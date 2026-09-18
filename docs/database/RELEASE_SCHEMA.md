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
| `hosted`、`bundleId`、`appleTeamId`、`installUrl`、`ipaSha256`、`ipaSize`、`ipaSelfReported`、`uploadedToAppStoreConnect` | iOS 构建机交付（`POST /v1/build-agent/jobs/:id/ios-release`） | `hosted="testflight"` 表示产物不在我们手里（Apple 重新签名、瘦身，用户装的不是我们这一份），下载与产物校验据它跳过；`ipaSha256` 只是"构建机交付了什么"的自报凭证，不是分发凭证 | 只有 iOS 记录有 |
| `uploadedByEarlierAttempt` | 同上（设计 `ios-mac-builders-home-network-2026-09-18.md` §6.3） | 这次没传，因为 App Store Connect 上已经有同一个 build 号了。任务被回收重排后 build 号不变，上一次尝试可能已经把 `.ipa` 传上去、只是没报上来——**这时 Apple 那份对应的是上一次检出的提交**，与本条记录里自报的 `commitSha` / `ipaSha256` 可能不是一回事 | 旧代理不报，键不存在按 false 读 |
| `toolchain` | 同上 | 这台 Mac 的 `xcodebuild -version` 那一行。几台 Mac 装同一个 Xcode 是人工维护的约定，版本漂移只有记下来才看得见 | 没报就不写这个键：写空串等于说"这台机器的 Xcode 是空的" |

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
- iOS 认领还有两条（迁移 55、设计 `docs/design/ios-mac-builders-home-network-2026-09-18.md` §5.2、§5.3）：**同租户同时只有一条 iOS 安装包任务在途**（两条并行跑完，低号那条的 `/ios-release` 会被拒，而它的 `.ipa` 已经进了 App Store Connect，撤不回来）；任务租户 `release.ios` 的 `appleTeamId` + `bundleId` 必须在这台机器**本次认领自报**的盘点里（`build_machine_liveness.apple_teams`）。两条都写成子查询并用 `FOR UPDATE OF j SKIP LOCKED` 限定锁的范围——不限定的话每次认领都会锁住各租户 `app_configs` 的 `release.ios` 那几行。Android 不加第一条：那会把两台构建机同时打同一个租户的两条任务也串起来。

## build_machine_liveness（迁移 55）

构建机最近一次露面与它自报的签名材料盘点。认领与心跳时写，60 秒节流，不进审计。设计见 `docs/design/ios-mac-builders-home-network-2026-09-18.md` §5.2、§5.4。

**为什么不合并进 `app_configs` 的 `build.machines`**：那是一份带版本号的 JSON 文档，写入走乐观锁（`writeMachineRegistry`）。N 台机器每 10 秒认领一次、每 30 秒心跳一次，把"最近在线"写回那份文档，机器之间会互相把版本号顶掉，写失败还会污染认领这条主路径。按"先复用再建表"的判据，这是一个新实体（高频、单写方、按机器一行的运行状态），不是配置。

**这张表不做任何授权判断。** `apple_teams` 是机器自己说的：持有机器令牌的人可以谎报手里有全部 Team 的材料，领走任一租户的任务再让它失败。这不是新增攻击面（持令牌本来就能认领并失败任意任务），但因此它只用来决定"派不派这条任务给这台机器"和控制台显示什么——**是运维仪表，不是安全边界**。

| 列 | 类型 | 含义 |
| --- | --- | --- |
| `machine_id` | VARCHAR(40) PK | 构建机 id（`build.machines`，`mch_` 前缀），由机器令牌鉴权得出。没有外键：登记在 JSON 文档里，指不过去；机器删掉后留下的孤儿行比一条会在认领路径上失败的外键便宜 |
| `last_seen_at` | DATETIME(3) NOT NULL | 最近一次认领或心跳 UTC。写入按 60 秒节流：`ON DUPLICATE KEY UPDATE` 没有 WHERE，用 `IF(last_seen_at < VALUES(last_seen_at) - INTERVAL 60 SECOND, …)` 让窗口内的新值等于旧值，整条语句变成空转 |
| `agent_commit` | VARCHAR(64) NULL | 这台机器上跑的 `build-agent` 提交（`-ldflags` 注入）。与平台级 `approvedAgentCommit` 不一致时控制台标出。NULL=旧版代理没报 |
| `os` | VARCHAR(16) NULL | `runtime.GOOS`：`darwin`=Mac 打包机，`linux`=机房构建机。装机脚本与自升级归档按它分 |
| `platforms` | JSON NULL | 本次认领自报的平台，如 `["ios"]`。记的是**自报的**、不是被登记收窄之后的：收窄掉的恰恰是"它想干但干不了"，而那正是要在控制台上看见的 |
| `apple_teams` | JSON NULL | 自报盘点：`[{"teamId":"ABCDE12345","bundleIds":["com.x.y"],"expiresAt":"2027-01-01T00:00:00Z","uploadProbe":"ok"}]`（`uploadProbe`：`ok`/`forbidden`/`error`，启动时对上传 Key 做的只读探测，让"角色不够传不上去"在**第一次构建之前**就看得见）。服务端据它路由 iOS 任务；控制台拿它与全部租户的 `release.ios` 求差集，标出"这台缺哪个租户的签名材料"。NULL=不是 iOS 打包机或旧版代理没报 |
| `signing_expires_at` | DATETIME(3) NULL | 本机最早到期的证书或描述文件，30 天内控制台标黄 |
| `free_gb` | INT UNSIGNED NULL | 构建盘剩余空间 GiB，认领时自报 |
| `upgrade_error` | VARCHAR(300) NULL | 上一次自升级失败的原因（升级程序写 `state/upgrade-failed.json`，代理启动后读出来随认领报上来）。**为什么要报上来**：升级是 root 的那个程序做的，它失败时代理还在跑旧版，控制台上看到的只是"版本一直追不上审批值"，不说原因就只能上机器看日志 |
| `paused_reason` | VARCHAR(200) NULL | 这台机器自己暂停认领的原因（空闲空间低于 `BUILD_AGENT_MIN_FREE_GB` 等）。它仍然每 10 秒来问一次（仍然算在线），只是请求里带着 `paused`，服务端记下这一行就回 204 不派活。**为什么不让它干脆别来问**：那样控制台只能看到"离线"，而磁盘满和关机需要的处理完全不同 |
| `updated_at` | DATETIME(3) NOT NULL | 本行最近一次被写入 UTC |

### 不变量

- 写入点只有两个：`claim`（在 `GET_LOCK` 与事务**之外**、在"队列空回 204"**之前**——认领路径上绝大多数请求都是空转，而在线状态只有那些空转能证明）与 `heartbeat`（只动 `last_seen_at`：心跳的请求体里没有盘点，用认领那条写入会把 `apple_teams` 抹成 NULL，控制台上机器会在构建期间突然"什么材料都没有"）。
- 写失败只记日志，不影响认领与心跳：在线状态是仪表，认领是主路径。
- **`hasLiveBuilderFor` 不看这张表**：任务能不能排进队列仍然只看登记里有没有 active 的构建机。家里的 Mac 掉线时 iOS 任务照常排队等它回来（已定的决策）；"一台都不在线"只进排队响应的 `warnings`（`no_ios_builder_online`）与控制台提示。挡住排队的只有"**从来没有**任何一台报过这个 Team"（409 `NO_BUILDER_FOR_TEAM`），那种情况排进去永远没人领。
- 掉线判据 5 分钟（代理每 10 秒认领、每 30 秒心跳，写入 60 秒节流），控制台卡片超过 30 分钟标黄。
