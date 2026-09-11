# 设计：打包服务（管理端触发，打包机自持签名密钥）

状态：设计（阶段 2a = 服务端数据模型与接口；阶段 2b = 打包机代理；阶段 2c = 管理端页面）

## 要解决的问题

今天出一个租户的包要人做四件事：改 `tenants/<slug>/tenant.json` 的版本号、准备证书文件、拼对一串构建环境变量、在一台装了 keystore 的机器上跑 `pnpm android:release`。每一步都靠记性，而 2026-09-11 已经在同类链路上翻过一次车：OTA 密钥轮换时 `mv` 跑了两次，`curl --data-binary @` 指向一个不存在的文件，操作者以为换完了，线上其实没换。

目标是：管理端发一个构建请求，打包机把包出出来，产物和 sha256 回到服务端。人只决定"给哪个租户、哪个提交、什么版本号"。

## 不做什么（这条比做什么重要）

**服务端不向打包机分发签名密钥，也不在打包机上执行任意命令。**

原始提案是"管理端把 keystore 分发到打包机，服务端直接调打包机的命令"。这两件都不能做，理由是同一条：

- Android 用（包名 + 签名证书）认身份。keystore 泄露意味着对方能签一个同签名的 APK，在用户设备上原地覆盖安装、数据目录（含钱包）完整保留。direct 分发没有 Play App Signing 那套轮换，补救办法只有换包名，也就是让每个用户手动卸载重装。
- 让 wallet 后端能在打包机上执行任意命令，等于把上面那条风险换个方式又走一遍：后端一个 RCE 就拿到执行权，而执行权所在的机器正好握着 keystore。

所以接口只有一个语义：**为租户 X 在提交 Y 上出一个包**。不是 shell，不是命令字符串。密钥由打包机自己持有或自己去密钥管理服务取，服务端知道的是产物指纹，不是钥匙。

## 什么该进数据库，什么不该

规则一句话：**数据库可以提供构建参数，不能提供构建身份，更不能提供检查身份的那道闸。**

| 字段 | 去处 | 理由 |
| --- | --- | --- |
| OTA 签名证书 | **数据库**（`app_configs` 的 `ota.signing`，已经在那里） | 它本来就存在服务端，而且是公开材料。让打包机自己去取，"包里的证书"与"服务端当前用来签的密钥"就永远一致——今天这个一致性靠人拷文件维持，而不一致的症状是所有设备静默停在内置 bundle |
| version / androidVersionCode | **数据库**（构建任务行上的参数） | 它是发布协调数据，不是身份。服务端本来就知道每个租户发过哪些 build_number，把它放进来还顺手解决了一件今天没人管的事：**versionCode 单调递增**由服务端校验，而不是靠两个人不撞号 |
| gitRef（分支或提交） | **数据库**（构建任务行上的参数） | 同上。产物身份 = (提交, version, versionCode)，三者一起记在任务行上并与产物 sha256 绑定 |
| `EXPO_REQUIRE_OTA_SIGNING` | **哪儿都不去，直接删掉** | 它不是配置，是闸。做成按租户的数据库开关意味着谁都能远程把"这个包必须带信任根"的检查关掉。打包机自己去取证书之后，"带证书"是必然而不是选项，这个开关就没有存在理由了 |
| applicationId / 包名 / 权限清单 / keystore 别名 | **留在提交里** | 这些定义了产物**是什么**。服务端能在构建时改它们，等于一次数据库注入就能让打包机产出一个身份不同、却用你的密钥签名的 APK。产物身份门禁必须拿提交里的值去比对，不能拿下发请求的同一个数据库里的值 |

## 复用映射表

| 初稿里的表 | 结论 | 理由 |
| --- | --- | --- |
| `build_jobs` | **新建** | 新实体。`app_releases` 描述的是一个**已经存在的产物**，而构建任务可以失败、可以重试、可以在没有任何产物的情况下结束。用 `app_releases` 承载会把"失败的构建"写成"坏掉的发布记录" |
| `build_agents`（打包机登记表） | **取消** | 会变成"哪些机器存在"的第二个事实来源，而这个事实本来就由运维持有。代理用共享令牌认领任务，机器标识记在任务行的 `claimed_by` 上 |
| `build_logs` | **取消** | 高写入、没有查询需求。尾部日志放任务行的 JSON 列（够定位失败），完整日志写租户自己的对象存储，与产物同一套凭据 |
| 租户构建配置（仓库地址、默认分支） | **合并进 `app_configs`** | 一键一行，自带 version / updated_by，与品牌、灰度、OTA 密钥同一套。键名 `build.android` |
| 构建审计 | **合并进 `audit_events`** | `build_job_create` / `build_job_complete` / `build_job_fail`，与其它管理动作同一条历史 |

## 数据模型（迁移 40）

```sql
CREATE TABLE build_jobs (
  id           VARCHAR(80)  NOT NULL COMMENT '主键，bld_ 前缀',
  tenant_id    BIGINT UNSIGNED NOT NULL COMMENT '所属租户；构建参数与产物都只属于这个租户',
  platform     ENUM('android','ios') NOT NULL COMMENT '目标平台',
  git_ref      VARCHAR(200) NOT NULL COMMENT '要构建的分支名或提交 sha；代理解析成确切提交后回写 commit_sha',
  commit_sha   VARCHAR(64)  NULL COMMENT '代理实际检出的提交；NULL=还没认领或还没解析出来',
  version      VARCHAR(40)  NOT NULL COMMENT '语义版本，写进产物；与 app_releases.version 同义',
  build_number INT UNSIGNED NOT NULL COMMENT 'Android versionCode / iOS build；服务端保证同租户同平台严格递增',
  status       ENUM('queued','claimed','running','succeeded','failed','canceled') NOT NULL COMMENT '任务状态',
  claimed_by   VARCHAR(120) NULL COMMENT '认领这个任务的打包机自报标识，只用于排查；NULL=还没被认领',
  claimed_at   DATETIME(3)  NULL COMMENT '认领时间 UTC；NULL=还没被认领',
  heartbeat_at DATETIME(3)  NULL COMMENT '代理最近一次心跳 UTC；用于判定卡死的任务',
  release_id   VARCHAR(80)  NULL COMMENT '构建成功后落到 app_releases 的那条记录；NULL=还没产物',
  artifact_sha256 CHAR(64)  NULL COMMENT '产物 sha256，由代理计算、服务端接收后与上传的文件复核',
  log_tail     JSON         NULL COMMENT '失败定位用的日志尾部，字符串数组，最多 200 行；完整日志在对象存储',
  log_object_key VARCHAR(512) NULL COMMENT '完整日志在租户对象存储里的键；NULL=没有上传日志',
  failure_reason VARCHAR(500) NULL COMMENT '失败原因一句话；NULL=没失败',
  reason       VARCHAR(500) NOT NULL COMMENT '发起这次构建的原因，管理端必填，写进审计',
  created_by   VARCHAR(120) NOT NULL COMMENT '发起人',
  created_at   DATETIME(3)  NOT NULL COMMENT '创建时间 UTC',
  updated_at   DATETIME(3)  NOT NULL COMMENT '更新时间 UTC',
  PRIMARY KEY (id),
  KEY ix_build_jobs_queue (status, created_at),
  KEY ix_build_jobs_tenant (tenant_id, platform, created_at),
  UNIQUE KEY ux_build_jobs_build_number (tenant_id, platform, build_number)
) ENGINE=InnoDB COMMENT='打包任务：管理端写入，打包机代理认领与回报，服务端只记参数与结果，不记命令';
```

`ux_build_jobs_build_number` 是有意的：同一个租户、同一个平台的同一个 build 号不能被排两次队。今天这件事没人管，两个人各自出一个 build 34 的包，装到设备上哪个赢取决于谁后装。

## 接口

**管理端**（`x-admin-key` 或浏览器会话）

- `POST /v1/admin/builds` — `{platform, gitRef, version, buildNumber, reason, confirm}`。校验 `buildNumber` 严格大于该租户该平台已有的最大值（`app_releases` 与 `build_jobs` 取大者），否则 409。
- `GET /v1/admin/builds` — 列表，带状态与产物指纹。
- `GET /v1/admin/builds/{id}` — 详情，含 `logTail`。
- `POST /v1/admin/builds/{id}/cancel` — 只能取消 `queued` / `claimed`。

**打包机代理**（`x-build-agent-token`，与管理端凭据分开；管理端密钥不能调这组接口，反之亦然）

- `POST /v1/build-agent/claim` — `{agent, platforms}`，原子地把一条 `queued` 变成 `claimed` 并返回参数（含该租户的 OTA 证书 PEM）。没有任务返回 204。
- `POST /v1/build-agent/jobs/{id}/heartbeat` — `{logTail}`，顺便把状态推进到 `running`。
- `POST /v1/build-agent/jobs/{id}/complete` — `{commitSha, artifactSha256, uploadToken}`。
- `POST /v1/build-agent/jobs/{id}/fail` — `{failureReason, logTail}`。

代理拿到的**只有参数**，没有命令。它自己决定怎么构建，自己持有 keystore。

## 代理侧要做的检查（阶段 2b）

1. 检出 `gitRef`，记下确切提交。
2. 从任务里拿到 OTA 证书 PEM，写进工作区，作为 `EXPO_UPDATES_CODE_SIGNING_CERTIFICATE`。
3. 跑 `pnpm android:release <slug>`（现成的产物身份门禁照跑：权限清单、applicationId、签名指纹）。
4. **复核产物里内嵌的证书指纹等于任务里那张**。这一条是新增的，它把"包里的证书"与"服务端当前的签名密钥"焊在一起——今天这个一致性靠人拷文件。
5. 算 sha256，走现成的 `POST /v1/admin/release-artifacts/uploads` 上传，把 token 回报给 `complete`。

## 未决

- iOS 的构建机与签名身份（`release.ios` 已经有存储位置，构建链路还没有）。
- 卡死任务的回收策略：先只在列表里标出 `heartbeat_at` 超时，不自动重排——自动重排会在代理其实还活着的时候产生两个同号的包。
