# 发布与 OTA 相关列的 JSON 键（app_releases / ota_releases）

表结构本身以 `internal/store/migrations.go` 为准；本文只记录两个 JSON 列里由代码读写、影响下发决策的键，避免"列有 COMMENT 但键无处可查"。

## app_releases.file_metadata（JSON）

| 键 | 来源 | 含义 / 取值 | 缺失或非法的处理 |
| --- | --- | --- | --- |
| `fileName`、`size`、`sha256` | 入库校验（`createReleaseFromArtifact`） | 文件名、字节数、内容 SHA-256（小写 hex） | 入库必写 |
| `objectEtag` | 入库时 `objectstore.Stat` | 对象存储 ETag，去引号；分段上传形如 `<md5>-<n>` | **键不存在**：2026-09-10 前的旧记录，下载只比大小并 warning 一次；**键存在但为空/非字串**：500 `RELEASE_METADATA_INVALID`。入库时 ETag 为空直接拒绝（`RELEASE_OBJECT_ETAG_MISSING`） |
| `packageName`、`versionName`、`versionCode`、`minSdk`、`signerSha256`、`signingScheme`、`runtimeVersion` | `apkinspect`（仅 Android） | 包身份；`signerSha256` 小写 hex | 入库必写（Android） |
| `applicationId` | `apkinspect` 读内嵌 `extra.applicationId`（仅 Android） | App 身份（`X-Application-ID`），OTA 的 `extra.applicationId` 必须与之相等 | 旧记录缺失时由 OTA 创建路径回填（先核对对象 sha256/大小，见 OPERATIONS §5） |
| `nativeFingerprint` | 签名闸交回时为任务行上构建机上报、经出处声明核对过的值（包里读不出来），签名闸 `complete` 带的值必须与它相等；手工上传时为请求里带的值 | 原生面指纹，热更新能不能挂在这个包上靠它判 | 键不存在 = 不能做热更新基线 |
| `unsignedSha256` | 签名闸完成（`POST /v1/signer/jobs/:id/complete`） | 构建机交付的未签名包 sha256；已签名包的 sha256 就是上面的 `sha256` | 手工上传的记录没有这个键 |
| `sbom` | 签名闸完成：`{"fileName","objectKey","size","sha256","format":"cyclonedx-json"}`；手工上传带 `sbomToken` 时：`{"fileName","objectKey","size","format"}` | 这个包的依赖清单在对象存储里的位置 | 键不存在 = 没有 SBOM |
| `commitSha`、`commitSelfReported` | 签名闸完成 | 构建机检出的提交；`commitSelfReported` 恒为 `true`——提交由构建机自报，服务端没有 GitHub 凭据去核对 | 手工上传的记录没有 |
| `buildJobId`、`builderId`、`signerMachineId` | 签名闸完成 | 打包任务 id、交付未签名包的构建机 id、签名的签名闸 id（`build.machines`） | 手工上传的记录没有 |

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

## build_jobs（迁移 40、41、42、45、54）

打包任务。管理端写入；构建机认领、交付未签名包与出处签名；签名闸认领、签名、在一个事务里落发布记录并完成任务。设计见 `docs/design/build-service-2026-09-11.md`、`docs/design/android-signing-gate-2026-09-16.md`，决策见 ADR-0019。

**表里没有命令字段，这是有意的。** 任务带的是参数（租户、提交、版本号），不是 shell。让服务端能在构建机上执行任意命令，等于 wallet 后端的任何一个 RCE 都拿到了构建机的执行权。

**构建机没有签名能力。** 签名密钥只以加密给签名闸的密文存在 `app_configs.build.keystore`（见 `SIGNING_GATE_SCHEMA.md`），构建机领取任务时拿不到任何密文字段。

### 为什么不复用 app_releases

`app_releases` 描述的是一个**已经存在的产物**。构建任务可以失败、可以重试、可以在没有任何产物的情况下结束，塞进去会把"失败的构建"写成"坏掉的发布记录"。签名成功后产物落 `app_releases`，任务行用 `release_id` 指过去。签名阶段（认领编号、心跳、拒签原因）是同一个打包任务的后半程，合并在同一行上而不是另建签名任务表（设计「复用映射表」）。

### 状态（迁移 54）

```text
apk：queued → claimed → running → built（待签名）→ signing（签名中）→ succeeded
ota：queued → claimed → running → succeeded
进行中的状态都可以到 failed；可取消：queued、claimed、built；signing 只能强制判失败
```

状态集合与转移表在 `internal/api/build_job_states.go`，所有按状态判断的 SQL 从那里取。

| 转移 | 谁 | 条件 |
| --- | --- | --- |
| queued → claimed | 构建机认领 | `attempt+1`；本机没有 claimed/running 的任务 |
| claimed/running → running | 构建机心跳 | `attempt`、`claimed_machine_id` 对得上 |
| claimed/running → built | 构建机 `/built`（仅 apk） | 未签名包与 SBOM 已在本次认领下上传；出处签名用登记公钥验过、逐项一致 |
| claimed/running → succeeded | 构建机 `/complete`（仅 ota） | 编号对得上 |
| claimed/running → failed | 构建机 `/fail`；认领时缺配置 | 编号对得上 |
| claimed/running → queued / failed | 回收定时器：10 分钟无构建心跳 | apk 且 `attempt < 3` 退回排队，否则判失败；ota 直接判失败 |
| built → signing | 签名闸认领 | 只派 active 主签名闸；同租户同平台在途任务里 build 号最小；租户就绪且就绪项完全一致；`sign_attempt+1`、清空 `signed_object_key`。在发布序列锁里做 |
| built → failed | 签名认领时发现被已有发布超过 | 构建期间手工上传了不低于它的版本：签出来也入不了库，不派，写 `failure_reason` 与审计 `build_job_sign_overtaken` |
| signing → built | 签名闸 `/release`（暂不能签） | 不计 `sign_failures`；60 秒内不再派给同一台签名闸 |
| signing → built / failed | 签名闸 `/reject` transient；回收定时器：5 分钟无签名心跳 | `sign_failures+1`，到 2 判失败 |
| signing → failed | 签名闸 `/reject` violation；管理端 force-fail | — |
| signing → succeeded | 签名闸 `/complete` | 先刷新签名心跳再复核；与写 `app_releases` 同一事务，事务里带共享锁重读发布身份与签名密钥，变了 409 `RELEASE_IDENTITY_CHANGED`；已 succeeded 且同一签名闸、同一签名编号、同一 sha256 按幂等返回 |
| queued/claimed/built → canceled | 管理端取消 | built 只对 apk |

### 列（迁移 54 新增）

| 列 | 类型 | 含义 |
| --- | --- | --- |
| `attempt` | INT NOT NULL DEFAULT 0 | 构建认领编号，每次认领 +1；构建机所有上报带 `x-build-attempt`，对不上 409 `BUILD_ATTEMPT_STALE` |
| `claimed_machine_id` | VARCHAR(40) NULL | 认领的构建机 id（`build.machines`），由令牌鉴权得出；退回排队后保留为最近一次认领者。NULL = 从未被机器令牌认领 |
| `unsigned_object_key` / `unsigned_size` / `unsigned_sha256` | VARCHAR(512) / BIGINT / CHAR(64) NULL | 未签名包：`<prefix>/tenants/<tenant>/build-jobs/<job>/a<attempt>/<随机段>/app-release-unsigned.apk`，每次上传一个新键；大小与 sha256 由服务端收流时计算。写键与校验编号在锁住本行的同一个事务里；同一次认领重传时替换本列、提交后删旧对象；每次认领清空 |
| `sbom_object_key` / `sbom_size` / `sbom_sha256` | 同上 | CycloneDX SBOM：`…/a<attempt>/<随机段>/sbom.cdx.json`，写入规则同上 |
| `native_fingerprint` | VARCHAR(128) NULL | 构建机交付时上报的原生指纹，与出处声明一致，签名闸复核 |
| `provenance` | JSON NULL | `{"statement","signature","builderId","builderPublicKey","builderPublicKeySha256"}`：出处声明原始字节与 Ed25519 签名（base64），以及验签用的登记公钥 |
| `sign_attempt` | INT NOT NULL DEFAULT 0 | 签名认领编号，每次签名认领 +1；签名闸所有上报带 `x-sign-attempt` 且机器一致，否则 409 `SIGN_ATTEMPT_STALE` |
| `sign_failures` | INT NOT NULL DEFAULT 0 | 签名心跳超时与临时错误各 +1，到 2 判失败；暂不能签不计 |
| `signing_machine_id` | VARCHAR(40) NULL | 当前或最近一次认领签名的签名闸 |
| `signing_claimed_at` / `signing_heartbeat_at` | DATETIME(3) NULL | 签名认领时间与签名心跳 UTC |
| `sign_outcome` | JSON NULL | 最近一次没签成的原因：`{"kind":"deferred|violation|transient","code","detail","machineId","at"}`；签成之后保留作历史 |
| `signed_object_key` | VARCHAR(512) NULL | 签名闸交回的已签名包：`…/build-jobs/<job>/s<signAttempt>/<随机段>/app-release.apk`，写入规则同 `unsigned_object_key`（校验签名编号与签名闸）。`complete` 只从这个键取包复核，事务里再核对键没变（变了 409 `SIGNED_ARTIFACT_REPLACED`），发布记录的 `object_key` 就是它。每次签名认领清空 |

**为什么每次上传一个新键**：键只由编号决定时，同一次认领里一个在反向代理那里超时、被客户端重传顶替的请求，会在任务已经往前走（`/built`、`complete`）之后才写完——覆盖已被引用的对象，又因为状态变了、改不到行而把它删掉，发布记录指向一个不存在的包。每次一个新键之后，迟到或过期的上传只能删掉自己写的那个对象。

### 不变量

- `ux_build_jobs_live_build_number (tenant_id, platform, live_build_number)`：同租户同平台**同时**只能有一个用着这个 build 号的活 apk 任务。生成列在 `queued/claimed/running/built/signing/succeeded` 时取 `build_number`（迁移 54 把 built、signing 加进来：否则签名期间同一个号能再排一条），`failed/canceled` 与全部 ota 任务取 NULL。迁移 54 把状态枚举、表达式与索引放在**同一条 ALTER** 里改：分两步删列重建时索引会短暂退化成 `UNIQUE(tenant_id, platform)`。
- `ux_build_jobs_live_ota`：同租户同平台同时只允许一条在跑的 OTA 任务。
- `ix_build_jobs_claimed_machine (claimed_machine_id, status)`：每台构建机同时只派一条。
- 排队时就要求严格递增（`app_releases` 与在途任务一起算），android apk 还要求主签名闸就绪（409 `SIGNER_NOT_READY`）。
- 手工上传 Android 发布记录还要求：v3 签名密钥存在、包的签名证书就是密钥记录里的证书、主签名闸对当前密钥版本 `decrypt=ok` 且 `confirmed=true`（ADR-0019 第 9 节），与在途检查一起在发布序列锁的事务里判。
- 手工上传 Android 发布记录时，该租户该平台有 `built`/`signing` 任务就 409 `RELEASE_SIGNING_IN_FLIGHT`：手工那条会抢走签名闸要用的版本号。
- 交付对象随任务放弃或重新认领删除：状态变化与键列置空同一个事务，提交后删对象，删不掉只记日志。退回待签名只删已签名包；签成的任务的未签名包与 SBOM 随发布记录删除。
- `log_tail` 最多 200 行、每行最多 2000 字节。机器上报的自由文本（`log_tail`、构建机的 `failure_reason`、签名闸的 `sign_outcome.detail` 与检查 `error`）入库前去掉 C0/C1 控制字符（保留 \t）与 Unicode 双向覆盖/隔离字符（U+202A–U+202E、U+2066–U+2069、U+200E/U+200F）。
- 认领是**跨租户**的，取最早那条。解析不出租户、`git_ref` 不是固定分支的任务当场判 failed 而不是报错留在队列里——否则一条脏数据会把整个队列堵死。
- 回收是服务端独立的定时器（每分钟），条件更新，多实例并发安全。
