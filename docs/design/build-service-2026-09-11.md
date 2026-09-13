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
- `GET /v1/admin/builds` — 列表，服务端按 `kind`（apk/ota）、`platform`、`status`、`version` 和 `q` 筛选，并用 `cursor` + `limit` 返回分页结果，带状态与产物指纹。
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

---

# 阶段 2b：打包机代理（独立程序，独立机器）

## 它必须是一个单独的程序，而且必须部署在另一台机器上

"单独部署"在这里不是工程洁癖，是这套设计成立的前提。

- **它持有 Android keystore。** 阶段 2a 全部的安全论证——服务端不下发密钥、不执行命令——在代理和 wallet 后端同机运行的那一刻全部作废：后端的一个 RCE 直接读到磁盘上的 keystore。分开部署才是那条论证的物理基础。
- **工具链完全不同。** JDK、Android SDK、Gradle、Node/pnpm，十几个 GB。服务端镜像是 alpine 加一个静态二进制，不该为了打包长成这样。
- **负载形状不同。** 一次 Android release 构建是约三分钟的满 CPU。跑在 API 进程里，接口延迟就跟着构建波动。
- **生命周期不同。** 重启 API 不该打断一个正在跑的构建；升级代理不该碰 API。

所以：`cmd/build-agent`，与 server 同仓库、同 go.mod（共用请求体定义，契约不会飘），编译成一个静态二进制，**不进容器**——它要用宿主机上的 Android SDK、keystore 和 pnpm 缓存。用 systemd 常驻。

## 只出不进

代理**轮询**服务端，服务端从不连代理。

这台机器因此可以完全不开放任何入站端口，蹲在 NAT 后面也能工作。反过来做（服务端推任务给代理）就要在那台握着签名密钥的机器上开一个监听端口，并给它一套鉴权——而那个端口的每一个 bug 都直接通向 keystore。

轮询的代价是一点延迟：空闲时每 10 秒问一次，认领到任务后立刻再问一次（队列里可能还有）。

## 配置（全部来自构建机本地，不来自服务端）

| 变量 | 含义 |
| --- | --- |
| `BUILD_AGENT_SERVER` | 服务端地址，例如 `https://api.anyfun.win` |
| `BUILD_AGENT_TOKEN` | 与管理端分开的那条凭据 |
| `BUILD_AGENT_NAME` | 自报标识，只用于排查，不作为鉴权依据 |
| `BUILD_AGENT_REPO` | RN-App 仓库地址或本地裸库路径 |
| `BUILD_AGENT_WORKSPACE` | 工作区根目录，每个任务一个临时 worktree |
| `BUILD_AGENT_PLATFORMS` | 这台机器能构建的平台，默认 android |
| `BUILD_AGENT_TIMEOUT_MINUTES` | 单次构建上限，默认 45 |
| `ANDROID_RELEASE_KEYSTORE_PATH` 等 | 现成的那套。**代理只是把它们传给构建脚本，自己不读内容** |

服务端下发的只有：租户 slug、git ref、version、buildNumber、OTA 证书 PEM。

## 一个任务的一生

1. `claim` 拿到任务。拿不到（204）就睡一轮。
2. `git fetch` 后 `git worktree add <workspace>/<jobId> <gitRef>`，记下解析出的确切提交。**每个任务一个全新 worktree**：共用检出会让另一个人未提交的改动混进产物——这件事 2026-09-10 真的发生过，当时的绕法就是手工开 worktree。
3. 把任务里的 `version` 与 `buildNumber` 写进 worktree 里的 `tenants/<slug>/tenant.json`，然后**校验这个文件只有这两个字段变了**。改到第三个字段就是服务端在试图改产物身份，当场判失败。
4. 把 OTA 证书 PEM 写进 worktree，设 `EXPO_UPDATES_CODE_SIGNING_CERTIFICATE` 指向它。
5. `pnpm install --frozen-lockfile` 然后 `pnpm android:release <slug>`。现成的产物身份门禁（权限清单、applicationId、签名指纹、Gradle 依赖校验）照跑，代理不复制其中任何一条。
6. **复核产物里内嵌的证书指纹等于任务里那张。** 这一条是新增的，它把"包里的证书"与"服务端当前的签名密钥"焊死。
7. 算 sha256，走现成的发布产物上传接口，把 `commitSha` / `artifactSha256` / `releaseId` 回报给 `complete`。
8. 无论成败，删掉 worktree。

心跳每 30 秒一次，带最近的日志尾部。超时就杀掉进程树并 `fail`。

## 日志里不能出现的东西

keystore 口令、`BUILD_AGENT_TOKEN`、任何 `*_PASSWORD` / `*_SECRET` / `*_TOKEN` 环境变量的值。日志尾部是要进数据库、进管理端界面的，Gradle 在失败时很乐意把整个命令行打出来。代理在上报前逐行过一遍脱敏。

## 并发

默认 1。Gradle 在同一个 `GRADLE_USER_HOME` 下并发构建不安全，而 buildNumber 的唯一性已经由服务端保证，并发在这里买不到什么。需要更快就多加一台机器——它们各自轮询，`SKIP LOCKED` 保证不会拿到同一条。

## 部署

```
/opt/rn-build-agent/build-agent          # 静态二进制，scp 上去
/etc/rn-build-agent.env                  # 0600，root 所有
/etc/systemd/system/rn-build-agent.service
```

服务单元以专用用户运行，`ProtectSystem=strict`，只对工作区与 keystore 目录可写。**这台机器不跑任何对外服务**。

## 未决

- 完整日志上传到对象存储（现在只有尾部进库）。
- iOS：需要 macOS 构建机与签名身份，另排。

## 升级顺序：先服务端，后代理

服务端的请求体解码用 `DisallowUnknownFields`。代理比服务端新时，它多送的一个字段会让整条请求 400——2026-09-11 的冒烟测试里就撞上了一次：代理开始上报 `commitSha`，而旧服务端不认识这个字段，结果失败上报全部被拒，任务永远停在 `claimed`。

所以升级顺序是**先服务端后代理**，不能反。这条严格性本身是对的（它让"多塞一个 command 字段"这种事必然失败），代价就是这个顺序约束。

## 部署文件

`deploy/build-agent/` 下有 systemd 单元与环境变量样例。要点：专用用户、`ProtectSystem=strict`、只对工作区和构建缓存可写、不监听任何端口。
