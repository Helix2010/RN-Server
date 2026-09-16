# ADR-0019：Android 正式包由独立的签名闸签名，服务端只做登记、路由与复核

状态：Accepted（2026-09-16）

完整设计：`docs/design/android-signing-gate-2026-09-16.md`；表与配置结构：`docs/database/RELEASE_SCHEMA.md`（`build_jobs`）、`docs/database/SIGNING_GATE_SCHEMA.md`（`build.machines` / `build.keystore` / `build.keystore.check`）；接口：`contracts/openapi.json`（2026.09.22）。本 ADR 取代 ADR-0016 里"服务端生成签名密钥"与"打包机持有密钥口令"两部分，控制台里签名密钥与发布身份同一事务写入的做法保留。

## 背景

原来的打包机既跑 Gradle 又持有签名密钥：`BUILD_KEYSTORE_PASSPHRASE` 在打包机环境里，构建进程与解密密钥的代码同一个 uid。任何能影响构建的东西（依赖、Gradle 插件、仓库里的脚本）都能读到明文 keystore。服务端这一侧，一个全局 `BUILD_AGENT_TOKEN` 同时授权领任务、取密钥、上传产物、拿备份口令；服务端被攻破等于可以给任意包签正式名。

## 决策

### 1. 构建与签名拆成两台机器、两段状态

安装包任务：`queued → claimed → running → built → signing → succeeded`，进行中的任一状态都可以到 `failed`；可取消 `queued / claimed / built`；`signing` 只能由管理员带原因强制判失败（`POST /builds/:id/force-fail`）。热更新任务不变（`queued → claimed → running → succeeded`）。

- 转移规则写成一张表（`internal/api/build_job_states.go`），每个写状态的 SQL 用同一张表导出的状态集合拼条件，测试逐项断言非法转移返回 409。
- 构建机（`/v1/build-agent`）只拿到构建参数，**领取结果里没有任何密钥密文或口令**；它交付未签名包、CycloneDX SBOM 与 Ed25519 出处声明（`signing/provenance`），服务端验签并逐项比对声明与任务行后置为 `built`。
- 签名闸（`/v1/signer`）领 `built` 的任务、下载未签名包、自己签名、上传已签名包，再调 `complete`。服务端在 `complete` 里用 `internal/apkinspect` 复核已签名包（签名者 = 登记证书 = 请求值、包名、版本、非 debug、非作废指纹），然后**一个事务**：锁任务行 → 校验状态、`sign_attempt`、签名机器 → 核对复核过的对象键没被重传替换、签名闸没被吊销、带共享锁重读 `release.android` 与 `build.keystore` 仍与复核时一致（否则 409 `RELEASE_IDENTITY_CHANGED`）→ 版本递增校验 → 写 `app_releases` → 任务 `succeeded`。复核开始前先刷新签名心跳，大包复核期间不会被回收。已经 `succeeded` 且是同一台签名闸、同一个签名编号交回的同一个包，按幂等返回同一个 `releaseId`；别的签名闸或编号 409。崩溃点注入测试覆盖事务内三处与提交后一处。
- 签名认领只派同租户同平台在途任务里 build 号最小的那条，只派给登记为 `primary` 且 `active` 的签名闸，且该租户就绪（见 5）、签名闸报的就绪项与服务端当前值完全一致。候选按租户各取一条（该租户在途 build 号最小且已构建完的那条），不截前 N 条：长期不就绪的租户不会饿死后面的租户。

### 2. 编号防护与独立回收

- 每次构建认领 `attempt+1`，每次签名认领 `sign_attempt+1`；机器的所有任务级请求带 `x-build-attempt` / `x-sign-attempt`，写入 SQL 条件带编号与机器 id，不匹配 409 `BUILD_ATTEMPT_STALE` / `SIGN_ATTEMPT_STALE`。未签名包、SBOM、已签名包的对象键含编号与每次上传一个的随机段，写键与校验编号在锁住任务行的同一个事务里；迟到或过期的上传只删自己写的对象，碰不到已被任务行或发布记录引用的键。`complete` 只从任务行记下的键取包，事务里再核对键没被重传替换、签名闸没在复核期间被吊销。
- 回收是服务端独立定时器（每分钟，`RunBuildJobReaper`，随进程退出），不再挂在打包机认领上：`claimed/running` 10 分钟无心跳，安装包回 `queued`（`attempt` 到 3 判失败），热更新判失败；`signing` 5 分钟无心跳回 `built` 并 `sign_failures+1`。
- `sign_failures` 单独一列：签名闸"暂不能签"（`release`，例如本机还没确认）不计数；心跳超时与"临时错误放弃"（`reject transient`）各加一，到 2 判失败；"违规"（`reject violation`）直接失败。三种结论都写进 `sign_outcome`（只保留最近一次）；**审计只写判失败的那一次**（违规 `build_job_sign_rejected`，临时错误或心跳超时到上限 `build_job_sign_failed`，actor `system-signer`）。暂不能签与没到上限的临时错误不写审计：签名闸每一轮轮询都可能报一次，写审计会刷屏，而 `sign_outcome` 已经说清楚最近一次为什么没签成。这里改的是文档（原先写成"三种结论都写审计"与实现不符），没有改实现。签名闸报"暂不能签"之后有 60 秒冷却（`signDeferralCooldown`）：`sign_outcome` 是本机在冷却期内说的 `deferred` 时，这条任务不再派给同一台签名闸，别的签名闸不受影响——否则认领、退回、再认领会空转（端到端实测每秒一百多次）。
- `live_build_number` 生成列把 `built`、`signing` 算作占号，签名期间同一个 build 号不能再排一条。
- 手工上传 Android 发布记录时，该租户该平台有 `built`/`signing` 任务就 409 `RELEASE_SIGNING_IN_FLIGHT`，免得手工包抢走签名闸正要用的版本号。任务还在排队或构建时手工上传照常放行；签名认领在同一把发布序列锁里比对已有发布，被超过的任务当场判失败、不派（签名闸会在本机记录里占掉派出去的 versionCode）。

### 3. 机器登记取代全局令牌

- 平台级 `app_configs` 键 `build.machines`：每台机器一个令牌（`rnm_` + 32 字节 base64url，只存 sha256，原文只在新建响应里出现一次）、角色、主备、公钥与状态。`BUILD_AGENT_TOKEN` 删除。
- 鉴权中间件按令牌 sha256 找机器，校验角色（构建机令牌调签名闸接口 403，反之亦然），`revoked` 401 `MACHINE_REVOKED`（令牌查无是 401 `MACHINE_AUTH_REQUIRED`；分开说，机器认出吊销就退出而不是一直重连）。每个请求主键查一次 `version, updated_at`，没变用缓存——吊销即时生效，又不必每次解析整份 JSON。只带旧头 `x-build-agent-token` 返回 426 `MACHINE_AUTH_UPGRADE_REQUIRED`，旧打包机升级前看到的是"要升级"而不是"令牌错"。
- 公钥由机器自己上报为待接受，平台管理员核对完整 64 位指纹后接受；接受签名闸时**必须**同时带从本机抄来的 Ed25519 指纹（缺了 400 `INVALID_MACHINE`，对不上 409 `MACHINE_KEY_MISMATCH`），否则偷到令牌的人能在待接受期间把真机的 X25519 与自己的 Ed25519 配成一对，此后的换钥证明就归他（安全评审 R2）。已 active 的机器换钥必须带当前私钥对 `machinekey.RotationMessage` 的签名，否则 403——偷到令牌不等于能换掉出处密钥。
- 签名闸有两把钥：X25519 解密钥密文（其 sha256 是收件人指纹），Ed25519 签本机记录与换钥证明。构建机一把 Ed25519 出处密钥。
- **主备只影响路由**。签名闸与离线工具不采信这份登记：签名闸只信本机记录，离线工具只加密给离线 pin 文件里的签名闸。服务端被攻破能做到的是"不派活、派给错的机器"，做不到"让签名闸签一个它不认的包"。

### 4. 签名密钥 v3

- `build.keystore` 只收离线工具产出的 v3 上传文件（`signing/keystorebox`）：每台签名闸一份 X25519 密文，明文绑定租户、包名、证书指纹、别名与收件人列表。外层仍用 `STORAGE_MASTER_KEY` 加密。服务端打不开内层。
- 收件人必须都是已登记、未吊销签名闸已接受的公钥，多余的拒收（`BUILD_KEYSTORE_RECIPIENT_UNKNOWN`），缺的只提示（`missingSigners`，只列 active 的签名闸）；与 `release.android` 在同一事务里各自带乐观锁写入。
- 删除：服务端生成密钥（`/build-keystore/generate`）、v1 口令封装与 v2 打包机公钥封装的全部读写点、`internal/buildkeystore`、`cmd/build-keystore`、打包机公钥登记（`/platform/build-agent/public-key*`）、打包机的 `/keystore-checks`。库里的旧格式记录读出来是 `legacy=true`、不就绪，等租户上传 v3 时覆盖。
- `build.keystore` 是 v3 但用不了（记录损坏、外层解不开、索引字段与密文文件对不上）时不是读库错误：控制台照常返回（`configured=true`、`ready=false`），就绪问题 `KEYSTORE_RECORD_INVALID`，排队 409 `SIGNER_NOT_READY`，签名闸检查接口不下发这个租户。
- `build.keystore.check` 改为按机器 id 分键，`JSON_SET` 只改自己那一项——主备并发上报整行覆盖会丢掉对方的结论。

### 5. 就绪判断

排队与签名认领用同一个函数：有 v3 密钥且与发布身份一致；有 active primary 签名闸且密钥发给了它；服务端算得出信任根；primary 对当前密钥版本报告了试解成功、本机确认、确认时的信任根摘要等于服务端当前摘要、试签成功。不满足时排队 409 `SIGNER_NOT_READY`，detail 逐条列出缺什么，问题体里另带 `readinessProblems`；控制台签名密钥页 `GET /v1/admin/build-keystore` 带同样的 `readinessProblems`（就绪时为空数组）。每条原因有固定 code（OpenAPI `SignerReadinessProblem`，测试保证服务端全集与契约枚举一致）：`KEYSTORE_NOT_CONFIGURED`、`KEYSTORE_LEGACY_FORMAT`、`KEYSTORE_RECORD_INVALID`、`RELEASE_IDENTITY_NOT_CONFIGURED`、`RELEASE_IDENTITY_MISMATCH`、`PRIMARY_SIGNER_MISSING`、`PRIMARY_SIGNER_NOT_RECIPIENT`、`APP_IDENTITY_INCOMPLETE`、`OTA_CERTIFICATE_NOT_CONFIGURED`、`API_BASE_URL_INVALID`、`TRUST_ROOTS_INVALID`、`PRIMARY_SIGNER_NOT_CHECKED`、`PRIMARY_SIGNER_DECRYPT_FAILED`、`PRIMARY_SIGNER_NOT_CONFIRMED`、`TRUST_ROOTS_CHANGED`、`PRIMARY_SIGNER_TRIAL_SIGN_PENDING`、`PRIMARY_SIGNER_TRIAL_SIGN_FAILED`。

信任根摘要由 `signing/trustroots` 计算，服务端与签名闸共用：租户改了 `apiBaseUrl` 或 OTA 证书，摘要就变，在主签名闸重新 `confirm` 之前不能排队。App Links host 按 RN-App `app.config.ts` 的规则（`new URL(apiBaseUrl).host`）派生，有测试钉住。`apiBaseUrl` 在**保存打包配置时**就用 `trustroots.ValidateAPIBaseURL` 校验（去掉首尾空白与结尾 `/` 之后）：显式写默认端口 `:443`、大写域名、IP、带路径一律 400——WHATWG URL 会去掉 `:443`，同一个源两种写法会让服务端与签名闸对 host 与摘要得出不同结论，所以要求配置本身是唯一写法，而不是存进去再判不就绪。校验收紧之前存下的旧值在就绪判断里报 `API_BASE_URL_INVALID`。

### 6. 作废指纹永久拒绝

2026-09 重置作废的两张证书（anyfun `1a5d9fb4…e694`、predict-kim `9ab5fbe6…cf37`）写成服务端常量，在登记发布身份、登记签名密钥、上传门禁、签名闸完成四处拒绝（`RELEASE_SIGNER_RETIRED`）。只挡写入与入库路径，不影响读出历史发布记录。

### 7. 交付对象的清理

未签名包、SBOM、已签名包每次上传一个带随机段的新键，任务行只记最新那一个。任务被放弃（构建机报失败、回收、取消、强制判失败、签名闸拒签）或者被重新认领（构建、签名）时，行上不再有人引用的键在同一个事务里置空，**提交之后**删对象；删不掉只记日志，不挡状态变化。退回待签名（暂不能签、没到上限的临时错误、签名心跳超时）只删已签名包，未签名包与 SBOM 留给下一次签名。签成的任务，未签名包与 SBOM 随发布记录一起删（`DELETE /v1/admin/releases/{id}`，`keepObjects` 时保留）。

### 8. 原生指纹的来源

真实的已签名包里没有 `assets/fingerprint`，签名闸读不出原生指纹（设计「签名前检查」第 16 条的前提不成立，负责人决定）。发布记录的 `file_metadata.nativeFingerprint` 取任务行上构建机上报、经出处声明核对过的值，并记 `nativeFingerprintSource: "builder-provenance"`；签名闸 `complete` 带来的 `nativeFingerprint` 必须与它相等，否则 422 `SIGN_RESULT_MISMATCH`。热更新基线闸（`baseNativeFingerprint`）照旧用这个值。

### 9. 手工上传也要经过签名闸确认过的证书

签名闸只管它自己签的包；手工上传（`POST /v1/admin/releases`）原来只和登记的发布身份比对。安全评审 R2 证明这是一条绕过签名闸的路：租户管理员（或拿到 `x-admin-key` 的人）可以把 `release.android` 的证书改成自己的，或者用签名闸公开的 X25519 公钥封一份自己的 v3 密文上传（服务端打不开内层，只能照收），然后手工上传自签的包。现在：

- 租户有 v3 `build.keystore` 时，`PUT /v1/admin/release-identity/android` 的包名与证书必须就是密钥记录里的（409 `RELEASE_IDENTITY_KEYSTORE_MISMATCH`），身份只能随 `PUT /v1/admin/build-keystore` 一起换；v3 记录用不了（`KEYSTORE_RECORD_INVALID`，例如库里外层证书被改过）时不拿外层字段当依据，单独改身份 409 `BUILD_KEYSTORE_RECORD_INVALID`，手工上传闸按 `RELEASE_KEYSTORE_NOT_CONFIGURED` 拒绝。
- Android 手工上传在发布序列锁的事务里再过一道闸（签名闸 `complete` 不走这里），任何一条不满足都是 409 并写审计 `release_rejected`：租户有 v3 密钥（`RELEASE_KEYSTORE_NOT_CONFIGURED`）；包的签名证书就是密钥记录里的证书（`RELEASE_SIGNER_KEYSTORE_MISMATCH`）；**主签名闸**对当前密钥版本报告 `decrypt=ok` 且 `confirmed=true`（`RELEASE_SIGNER_NOT_CONFIRMED`）。确认是运维在签名闸本机对照离线指纹做的，服务端改不了它。

**结论：租户管理员账号被攻破时，手工上传只能发"签名闸本机确认过的证书"签的包。** 这是相对设计的一处收紧（设计里手工上传只受在途门禁约束），代价是没迁到签名闸的租户不能再手工上传 Android 包。

### 10. 热更新包只能来自构建任务

管理端直接上传热更新包的接口（`/ota/artifacts/uploads`、`/ota/artifacts/upload`、`/ota/releases`）与 upload-sessions 的 `uploadType=ota` 删除。热更新包的代理上传（`PUT /v1/build-agent/jobs/:id/ota-artifact`）与签名闸完成按路由模板精确豁免 10 秒数据库超时。

## 复用映射（先复用再建表）

| 拟新增 | 结论 |
| --- | --- |
| 机器登记 | 复用 `app_configs` 平台级 `build.machines`：条目少、只在人工操作时变，自带 `version / updated_by / updated_at` |
| 构建编号、未签名包、SBOM、出处、签名段认领与心跳、签名结论 | 合并进 `build_jobs` 新列（迁移 54）：同一个打包任务的运行状态，写方明确 |
| 受信构建机、确认过的证书与信任根、签过的版本号 | 不进服务端库，签名闸本机记录——它们防的就是服务端被攻破 |
| 签名、拒签、检查状态变化的历史 | 复用 `audit_events`（`system-signer`） |
| 签名密钥密文 | 复用 `build.keystore`，换成 v3 结构 |
| 每台签名闸的检查状态 | 复用 `build.keystore.check`，按机器 id 分键 |
| 打包机单一公钥 `build.agent.recipient` | 取消，被 `build.machines` 取代 |
| `platform_backups` 与备份配置 | 删除（备份方案整体移除） |

## 实现约定里拍板的几项（设计没写死的）

- `internal/apkinspect` 不挪进 `signing/`（它依赖 `avast/apkverifier`，`signing/` 只许依赖标准库与 `x/crypto`）；服务端继续用它复核签名闸交回的包。
- 编号走请求头，不改热更新那几条复用管理端处理函数的请求体。
- 公钥指纹一律按 base64 解码后的 32 字节原始公钥算完整 sha256。
- 构建机认领响应带 `claimedMachineId`，两个 public-key 接口的响应带 `machineId`（构建机用作出处声明的 `builderId`）。

## 两次发布

- **第一次**（本分支）：只含迁移 54，与删备份代码、本 ADR 的全部接口改动同发，无破坏性表变更。合并即部署，失败自动回滚到旧二进制时，旧代码面对的表和配置行都还在。
- **第二次**（新链路稳定之后，对应设计「落地顺序」第 8 步，另开分支单独发布）：一条新迁移删除 `platform_backups` 表，`app_configs` 的 `backup.bucket`、`backup.recipients`、`build.agent.backup-sign`、`build.agent.recipient`，以及旧格式（不是 format 2）的 `build.keystore.check` 行。**不在本分支里**：放进来的话合并即部署会把 54 和它一起跑掉，第一次发布就没有回滚余地。

## 代价

- 发一个正式包多一台机器、多一次人工确认。主签名闸挂了要人工把备用提升为 primary（`signer-role`），期间排队 409。
- 服务端不再能自己生成签名密钥：密钥生成与加密只在离线工具里做，丢了离线原件没有补救（ADR-0016 里"服务端生成"那条推论不再成立）。
- 所有现存租户要用离线工具重新生成密钥并上传 v3；在此之前 Android 安装包任务排不了队。
- `apiBaseUrl`、OTA 证书的任何改动都要在主签名闸上重新确认一次。
