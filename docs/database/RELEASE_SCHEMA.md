# 发布与 OTA 相关列的 JSON 键（app_releases / ota_releases）

表结构本身以 `internal/store/migrations.go` 为准；本文只记录两个 JSON 列里由代码读写、影响下发决策的键，避免"列有 COMMENT 但键无处可查"。

## app_releases.file_metadata（JSON）

| 键 | 来源 | 含义 / 取值 | 缺失或非法的处理 |
| --- | --- | --- | --- |
| `fileName`、`size`、`sha256` | 入库校验（`createReleaseFromArtifact`） | 文件名、字节数、内容 SHA-256（小写 hex） | 入库必写 |
| `objectEtag` | 入库时 `objectstore.Stat` | 对象存储 ETag，去引号；分段上传形如 `<md5>-<n>` | **键不存在**：2026-09-10 前的旧记录，下载只比大小并 warning 一次；**键存在但为空/非字串**：500 `RELEASE_METADATA_INVALID`。入库时 ETag 为空直接拒绝（`RELEASE_OBJECT_ETAG_MISSING`） |
| `packageName`、`versionName`、`versionCode`、`minSdk`、`signerSha256`、`signingScheme`、`runtimeVersion` | `apkinspect`（仅 Android） | 包身份；`signerSha256` 小写 hex | 入库必写（Android） |
| `applicationId` | `apkinspect` 读内嵌 `extra.applicationId`（仅 Android） | App 身份（`X-Application-ID`），OTA 的 `extra.applicationId` 必须与之相等 | 旧记录缺失时由 OTA 创建路径回填（先核对对象 sha256/大小，见 OPERATIONS §5） |

## ota_releases.object_metadata（JSON，迁移 37）

`{ "<相对路径>": { "size": <字节数>, "etag": "<对象 ETag>" } }`，每个资源对象一条，不含 `manifest.json`（manifest 由 `manifest_sha256` 全文校验）。

| 状态 | 判定 | 下发行为 |
| --- | --- | --- |
| 列为 NULL | 迁移 37 之前的记录 | 放行并 warning 一次 |
| 有该路径且 `size` 为非负数、`etag` 为非空字串 | 正常记录 | `Stat` 比对大小与 ETag，不符 502 `OTA_OBJECT_CHANGED` |
| 列有内容但不是合法 JSON，或条目缺 `size` / `etag` | 数据事故 | 500 `OTA_OBJECT_METADATA_INVALID` |
| 列合法但没有该路径 | 包里没有这个文件 | 404 |

## app_releases.canary_installations / ota_releases.canary_installations（JSON，迁移 39）

灰度设备白名单，`installation_id` 字符串数组：`["inst_…", "inst_…"]`。设计见 `RN-App/docs/design/canary-release-allowlist-2026-09-11.md`。

| 状态 | 判定 | 读路径行为 |
| --- | --- | --- |
| `status <> 'canary'` | 这一列只在灰度状态下有意义 | 忽略；管理端接口也不返回它 |
| NULL 或 `[]` | 没有名单 | `JSON_CONTAINS` 不成立，该灰度行**对所有设备不可见** |
| 不是字符串数组（手工写成 `{}` / `"x"`） | 数据事故 | `JSON_CONTAINS` 不成立，只会少发不会多发；管理端读到时当空名单 |
| 含请求方已验明的 `installation_id` | 命中 | 与 active 一同参与 `ORDER BY build_number DESC`（OTA 按 `revision`），大的胜出 |

写入只走状态机（`canary` / `set-canary-audience`）：名单不能为空，ID 必须在 `app_installations` 里存在，上限 200 条（超过这个规模改为关联表，查询形状不变）。离开灰度（`promote` / `cancel-canary`）时清空。

## build_jobs（迁移 40）

打包任务。管理端写入，打包机代理认领与回报。设计见 `docs/design/build-service-2026-09-11.md`。

**表里没有命令字段，这是有意的。** 任务带的是参数（租户、提交、版本号），不是 shell。让服务端能在打包机上执行任意命令，等于 wallet 后端的任何一个 RCE 都拿到了那台握着 Android keystore 的机器的执行权，而 keystore 泄露在 direct 分发下没有补救办法：Android 用（包名 + 签名证书）认身份，对方能签一个同签名的 APK 在用户设备上原地覆盖安装、数据目录（含钱包）完整保留，补救只能换包名。

### 为什么不复用 app_releases

`app_releases` 描述的是一个**已经存在的产物**。构建任务可以失败、可以重试、可以在没有任何产物的情况下结束，塞进去会把"失败的构建"写成"坏掉的发布记录"。构建成功后产物仍然落 `app_releases`，任务行用 `release_id` 指过去。

### 不变量

- `ux_build_jobs_live_build_number (tenant_id, platform, live_build_number)`（迁移 41）：同租户同平台**同时**只能有一个用着这个 build 号的活任务。`live_build_number` 是生成列，`failed` / `canceled` 时取 NULL，而 MySQL 的唯一索引不比较 NULL——所以「构建失败 → 改一行 → 用同一个号重来」这条最常见的路径走得通。迁移 40 把唯一键直接建在 `build_number` 上，把它堵死了：失败的构建没有产物，那个号根本没被用掉。创建时还会把 `app_releases` 里已用的最大值算进去，要求严格递增——装到设备上的 APK 靠 versionCode 决定谁覆盖谁，重号意味着"哪个赢"取决于谁后装。
- 状态只前进：`queued → claimed → running → succeeded|failed`，`canceled` 只能从 `queued|claimed` 进入。已经出了包的构建不能被取消，否则状态会骗人。
- `log_tail` 最多 200 行、每行最多 2000 字节。日志由代理送来，不设上限的话一次失败就能把这一行撑到几十兆，而这张表是管理端列表要扫的。
- 认领是**跨租户**的，取最早那条。解析不出租户的任务当场判 failed 而不是报错留在队列里——否则一条脏数据会把整个队列堵死。
