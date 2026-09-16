# 签名闸相关的 app_configs 键（build.machines / build.recovery.recipients / build.keystore / build.keystore.request / build.keystore.check）

设计：`docs/design/android-signing-gate-2026-09-16.md`、`docs/design/android-signing-gate-automation-2026-09-16.md`；决策：ADR-0019、ADR-0020；接口 JSON 见 `contracts/openapi.json`。两期都**不新建表**：机器登记、签名密钥密文、每台签名闸的检查状态都放在 `app_configs`，打包任务的构建段与签名段合并进 `build_jobs`（见 `RELEASE_SCHEMA.md`），签名与拒签的历史进 `audit_events`（`actor_id='system-signer'`）。

签名闸与离线工具**不采信**这里的任何一项：签名闸只信本机记录（受信构建机、确认过的证书与信任根、签过的版本号），离线工具只加密给离线 pin 文件里的签名闸。这些键只用于服务端鉴权、路由与控制台展示。

## 表职责

| 键 | 作用域 | 作用 | 谁写 | 谁读 |
| --- | --- | --- | --- | --- |
| `build.machines` | 平台级（`tenant_id=0`），明文 | 构建机与签名闸登记：注册码 sha256、令牌 sha256、公钥、状态、主备、签名闸上报的本机角色与信任 | 平台管理员（新建、重发注册码、吊销、接受公钥、切换主备）；机器自己（注册、登记待接受的公钥、上报本机角色与信任） | 机器鉴权中间件（按 `version` 缓存）、签名认领、签名密钥上传校验、控制台 |
| `build.keystore` | 租户级，外层 `STORAGE_MASTER_KEY` secretbox | v3 上传文件（多份加密给签名闸与恢复公钥的密文）、索引字段与生成者 | 租户管理员经控制台导入；主签名闸交回生成的密钥（ADR-0020）。两条路都与 `release.android` 同一事务 | 签名闸（只取发给本机的那份；有生成者时附整份文件与签名）、就绪判断、控制台、导出 |
| `build.keystore.check` | 租户级，明文 | 每台签名闸对当前密钥版本的试解、本机确认、试签状态 | 签名闸（按机器 id `JSON_SET` 单键） | 就绪判断、控制台 |
| `build.recovery.recipients` | 平台级（`tenant_id=0`），明文 | 平台离线恢复公钥（ADR-0020）：生成的密钥必须也加密给其中至少一把 | 平台管理员（登记、吊销） | 新建签名闸前提、machine-setup `describe`、`/v1/signer/peers`、交回密钥的收件人校验、控制台 |
| `build.keystore.request` | 租户级，明文 | 这个租户最近一次"在主签名闸上生成签名密钥"的请求与结果（ADR-0020） | 租户管理员（发起）；主签名闸（交回或报失败时改状态） | 主签名闸（`keystore-checks` 的 `generationRequest`）、就绪判断、控制台 |

## build.machines

```json
{"machines":[{
  "id":"mch_…","role":"builder|signer","signerRole":"primary|standby|null","name":"amos-signer-a",
  "status":"pending_enrollment|pending_key|active|revoked","tokenSha256":"<64hex|空串>",
  "publicKey":"<base64|null>","publicKeySha256":"<64hex|null>",
  "ed25519PublicKey":"<base64|null>","ed25519PublicKeySha256":"<64hex|null>",
  "pending":{"publicKey","publicKeySha256","ed25519PublicKey","ed25519PublicKeySha256","reportedAt"} | null,
  "acceptedBy":null,"acceptedAt":null,"createdBy":"…","createdAt":"…","revokedBy":null,"revokedAt":null,"revokeReason":null,
  "reportedLocalRole":"primary|standby|null","reportedLocalRoleAt":"…|null",
  "enrollment":{"codeSha256":"<64hex>","expiresAt":"…","issuedBy":"…","issuedAt":"…","usedAt":"…|null"} | null,
  "reportedTrust":{"signers":[{"name","x25519Sha256","ed25519Sha256"}],"builders":[{"builderId","ed25519Sha256"}],"recoveryKeys":["<64hex>"]} | null,
  "reportedTrustAt":"…|null"
}]}
```

`enrollment`、`reportedTrust`、`reportedTrustAt` 是 ADR-0020 加的；手工流程登记的机器（amos 上线时的三台）没有这些字段，读出来按 null，不需要迁移。

| 字段 | 含义 |
| --- | --- |
| `role` | `builder` = 构建机；`signer` = 签名闸 |
| `signerRole` | 仅签名闸：`primary` 领签名任务，`standby` 不领；构建机为 null |
| `status` | `pending_enrollment` = 控制台新建之后、机器用注册码注册之前（没有令牌、没有公钥）；`pending_key` = 已注册（或 ADR-0020 之前手工新建）、公钥还没被接受，只能调各自的 public-key 接口；`active`；`revoked` = 吊销，令牌下一次请求就 401 `MACHINE_REVOKED`（查无令牌是 `MACHINE_AUTH_REQUIRED`），签名闸的 `signerRole` 同时置为 null |
| `tokenSha256` | 机器令牌（`rnm_` + 32 字节 base64url）的 sha256。令牌原文只出现在 `POST /v1/machine-setup/enroll` 的响应里（ADR-0020 之前是新建接口的响应），不进审计、不进日志。还没注册过的机器（`pending_enrollment`，或没注册就被吊销）为空串 |
| `enrollment` | 一次性注册码：`codeSha256` 是注册码（`rne_` + 32 字节 base64url）的 sha256，原文只出现在新建与重发的响应里；`expiresAt` = 签发后 60 分钟（UTC）；`issuedBy`/`issuedAt` 签发人与时间；`usedAt` = 注册成功的时间，null = 未用。重发整体替换（旧码作废）。null = 手工流程登记的机器 |
| `reportedTrust` / `reportedTrustAt` | 仅签名闸：它在 `POST /v1/signer/keystore-checks` 的 `trust` 里报的本机信任列表（信任的签名闸含本机、构建机、恢复公钥 sha256，排序后存）与最近一次变化的时间；只在变化时写（审计 `build_machine_trust_report`）。只给控制台提示用，签名闸不采信。null = 从未上报 |
| `publicKey` / `publicKeySha256` | 已接受的主公钥。构建机：Ed25519 出处公钥；签名闸：X25519 收件人公钥（sha256 就是密文的 `recipientSha256`） |
| `ed25519PublicKey` / `ed25519PublicKeySha256` | 仅签名闸：记录签名与换钥证明用的 Ed25519 公钥 |
| `reportedLocalRole` / `reportedLocalRoleAt` | 仅签名闸：它在 `POST /v1/signer/keystore-checks` 里报的本机角色（本机记录说了算）与这个值最近一次变化的时间；只在值变化时写（写审计 `build_machine_local_role_report`）。null = 从未上报。控制台的 `signerRole` 是 primary 而这里不是 primary 时，就绪问题 `PRIMARY_SIGNER_LOCAL_ROLE_MISMATCH` |
| `pending` | 机器报上来、等平台管理员核对完整指纹后接受的公钥（签名闸的 accept-key 可同时带 `ed25519PublicKeySha256`，带了就必须一致）。已 active 的机器换钥必须带用当前私钥对 `machinekey.RotationMessage` 的签名；旧公钥在接受之前一直有效 |

所有 sha256 都按 base64 解码后的 32 字节原始公钥计算，完整 64 位小写十六进制。

不变量（写入时校验，读到不满足的值鉴权直接失败）：

- id 唯一、令牌 sha256 唯一；非吊销机器名称唯一（`^[a-z0-9][a-z0-9-]{1,39}$`）。新建签名闸时名称另外限制在 22 个字符以内（`^[a-z0-9][a-z0-9-]{1,21}$`）：签名闸在机器上以系统用户 `rn-signer-<机器名>` 运行，Linux 用户名最多 32 个字符；只在新建时检查，已登记的机器不受影响。
- 非吊销的 `signerRole=primary` 最多一台；切换主签名闸时原 primary 同一次写降为 standby。
- `active` 的机器必须有已接受的公钥（签名闸两把都要有）。
- 同一把公钥（当前或待接受）不能出现在两台非吊销机器上。
- 写入带乐观锁（`expectedVersion` = 这一行的 `version`，不符 409 `MACHINES_VERSION_CONFLICT`），管理端写都要 `reason` + `confirm` 并写审计（`build_machine_create/revoke/key_accept/signer_role/enrollment_reissue`，机器自报公钥为 `build_machine_key_report`，机器注册为 `machine_enrolled`，actor `system-machine-setup`）。
- `pending_enrollment` 必须有未用的 `enrollment`、没有令牌与公钥；非空的令牌 sha256 唯一；注册码 sha256 唯一。
- 注册（`enroll`）在带 `FOR UPDATE` 读这一行的事务里核对并消耗注册码：同一个码并发注册只有一个成功。
- 鉴权每个请求先主键查 `version, updated_at`，没变用内存缓存，变了重读：吊销即时生效。

## build.recovery.recipients

```json
{"keys":[{"id":"rck_…","name":"platform-2026","x25519PublicKey":"<base64>","x25519PublicKeySha256":"<64hex>",
  "createdBy":"…","createdAt":"…","revokedBy":null,"revokedAt":null,"revokeReason":null}]}
```

| 字段 | 含义 |
| --- | --- |
| `id` | 服务端生成，`rck_` + 随机串 |
| `name` | 离线工具写进 `recovery-public.json` 的名字（`^[a-z0-9][a-z0-9-]{1,39}$`） |
| `x25519PublicKey` / `x25519PublicKeySha256` | 恢复公钥（32 字节 X25519，base64 std）与它原始字节的完整 sha256；作为 v3 密文收件人时 `recipientSha256` 就是它。登记时严格解析文件并核对两者一致（`signing/recovery.ParsePublic`） |
| `createdBy` / `createdAt` | 登记人与时间（UTC） |
| `revokedBy` / `revokedAt` / `revokeReason` | 吊销；三者同时为 null = 未吊销。吊销的公钥不再满足"至少一把恢复收件人"、不再下发给签名闸与新机器；已经加密给它的密文不变 |

- 公钥不是机密，明文存。**签名闸不采信这份登记**：本机 pin 的恢复公钥指纹由运维从密码管理器粘贴（安装命令 `--recovery-sha256`、`signer trust-recovery`）。
- 至多 16 把（含吊销的）；同一个 sha256 只能登记一次（吊销后也不能再登记，409 `RECOVERY_KEY_EXISTS`）。
- 写入带乐观锁（不符 409 `RECOVERY_KEYS_VERSION_CONFLICT`），要 `reason` + `confirm`，审计 `build_recovery_key_create/revoke`（`tenant_id=0`）。

## build.keystore（format 3）

```json
{"format":3,"sealed":"<base64 secretbox(Upload JSON)>","keyAlias":"release","certificateSha256":"<64hex>",
 "packageName":"com.example.app","tenantSlug":"Example","recipients":["<64hex>", "…"],
 "generator":{"machineId":"mch_…","name":"amos-signer-a","ed25519PublicKey":"<base64>","ed25519PublicKeySha256":"<64hex>"},
 "generationSignature":"<base64>","generationRequestId":"kgr_…"}
```

- `generator`、`generationSignature`、`generationRequestId`（ADR-0020）只在密钥由主签名闸生成并交回时有，三者同时出现或同时没有；离线导入的记录没有这三个键。`generator` 是交回那一刻登记里的主签名闸与它的 Ed25519 公钥；`generationSignature` 是它对 `keystorebox.GenerationMessage(generationRequestId, Upload)` 的签名。服务端交回时验过，签名闸（备签名闸）自己再验，并且只认本机信任的生成者。
- `recipients` 里除了签名闸的 X25519 公钥 sha256，还可以有登记过的恢复公钥 sha256（控制台视图的 `recoveryRecipients`）。
- `sealed` 外层用 `STORAGE_MASTER_KEY` 加密（关联数据 `build-keystore/v3:<tenantId>`），里面是离线工具产出的 `rn-android-keystore-upload/v3` 文件（`signing/keystorebox.Upload`）：每个收件人一份 `x25519-hkdf-sha256-aes256gcm` 密文，明文绑定租户、包名、证书指纹、别名与收件人列表。服务端打不开内层。
- `keyAlias`、`certificateSha256`、`packageName`、`tenantSlug`、`recipients`（排序）是从文件里抄出来的索引，读取时与文件逐项比对，不一致是数据事故。
- v3 记录用不了（记录损坏、外层解不开、索引字段与文件对不上）时，读出来不报错，就绪问题 `KEYSTORE_RECORD_INVALID`，签名闸检查接口不下发；重新上传覆盖即可。
- 写入有两条路：导入（`PUT /v1/admin/build-keystore`）与主签名闸交回（`POST /v1/signer/keystore-generations/:requestId`，见下一节）。只收 v3：收件人必须都是已登记、非吊销签名闸已接受的 X25519 公钥或登记过、未吊销的恢复公钥（多余的拒收，缺的签名闸只提示；交回的密钥还必须至少含一把恢复公钥，导入不强制）；`tenantSlug` 等于本租户；请求里的 `packageName`、`signerSha256` 与文件一致；证书不是作废的旧指纹。与 `release.android` 在同一事务里各自带乐观锁写入（ADR-0016）。有 v3 记录时，单独改 `release.android`（`PUT /v1/admin/release-identity/android`）只能写成与本记录相同的包名与证书（409 `RELEASE_IDENTITY_KEYSTORE_MISMATCH`）；v3 记录用不了时一律不许单独改（409 `BUILD_KEYSTORE_RECORD_INVALID`），手工上传按没有可用密钥拒绝。
- **没有 `format:3` 的旧记录**（v1 口令封 `{"sealed","keyAlias","keystoreSha256"}`、v2 加密给打包机公钥）读出来当作"没有可用的签名密钥"：控制台显示 `legacy=true`，排队与签名认领一律不就绪，上传 v3 时带这一行的 `version` 覆盖。

## build.keystore.request

```json
{"requestId":"kgr_…","packageName":"com.example.app","alias":"example-release","requestedBy":"…","requestedAt":"…",
 "keystoreVersion":3,"releaseIdentityVersion":5,"status":"pending|done|failed","error":{"code":"…","detail":"…"}|null,"completedAt":"…|null"}
```

| 字段 | 含义 |
| --- | --- |
| `requestId` | 服务端生成，`kgr_` + 随机串；进交回接口的路径，也签进生成签名 |
| `packageName` | 要生成的包名：租户已有 `release.android` 时必须等于它；第一次生成的租户取请求里的，交回时写进 `release.android` |
| `alias` | keystore 别名，`<slug 小写>-release`（规范成 `^[A-Za-z0-9._-]{1,64}$`） |
| `requestedBy` / `requestedAt` | 发起人与时间（UTC） |
| `keystoreVersion` / `releaseIdentityVersion` | 发起时 `build.keystore` 与 `release.android` 两行的 `version`（没有那一行为 0）。交回时两个都必须没变 |
| `status` | `pending` 等主签名闸；`done` 已交回并落库；`failed` 签名闸报失败或交回时发现版本已变 |
| `error` | `failed` 时有：签名闸报的 `code`（`TRUST_ROOTS_CHANGED`、`RECOVERY_KEY_NOT_PINNED`、`NOT_LOCAL_PRIMARY`、`GENERATION_FAILED`……）与清洗过的 `detail`（≤500 字符），或服务端判的 `KEYSTORE_GENERATION_STALE` |
| `completedAt` | 变成 `done`/`failed` 的时间；`pending` 为 null |

- 每个租户一行、只保留最近一次；同时最多一条 `pending`（409 `KEYSTORE_GENERATION_IN_PROGRESS`）。
- **读取时推导过期**：`pending` 而两个版本任一已变（有人导入了密钥或改了发布身份）按 `failed` + `KEYSTORE_GENERATION_STALE` 处理——不再下发给主签名闸、不挡新的请求、控制台与就绪都这么显示。交回这种请求时 409 并把 `failed` 写回库。
- 读路径上这一行读不出来（记录被改坏）：记日志、按"没有请求"处理，不挡这个租户已有密钥的检查、就绪与签名；再次发起时覆盖它。
- 交回在一个事务里按 `build.keystore` → `release.android` → `build.keystore.request` 的顺序带 `FOR UPDATE` 读（与发起、导入同序），写密钥、发布身份，请求标 `done`；审计 `build_keystore_generated` 与 `release_identity_update`（`system-signer`）。发起审计 `build_keystore_generation_request`，失败审计 `build_keystore_generation_failed`。同一请求、同一签名的重试按成功返回。

## build.keystore.check（format 2）

```json
{"format":2,"machines":{"mch_…":{"keystoreVersion":3,"decrypt":"ok|failed","confirmed":true,
  "confirmedTrustRootsDigest":"<64hex|null>","trialSign":"pending|ok|failed","checkedAt":"…","error":null}}}
```

| 字段 | 含义 |
| --- | --- |
| `keystoreVersion` | 检查的是 `build.keystore` 哪一版（那一行的 `version`）。密钥重新上传后旧结论自然失效 |
| `decrypt` | 签名闸用本机私钥试解发给它的密文 |
| `confirmed` / `confirmedTrustRootsDigest` | 运维在签名闸上 `signer confirm` 过，以及确认时的包内信任根摘要（`signing/trustroots.Digest`） |
| `trialSign` | 主签名闸试签一个测试包并复核指纹 |
| `error` | 签名闸给的一句说明，截断到 300 字符、去掉控制字符 |

- 按机器 id 用 `JSON_SET` 只改自己那个键，主备并发上报互不覆盖；只收当前密钥版本、且密钥加密给了上报者的结论（主签名闸为领生成请求拿到的"没有密文的项"不算检查）。结论（`keystoreVersion`、`decrypt`、`confirmed`、`confirmedTrustRootsDigest`、`trialSign`、`error`）没变的项**不写库**：不加 `version`、不动 `checkedAt`（它是"结论最近一次变化的时间"）；变了才写库并写审计 `build_keystore_check_update`。
- 没有 `format:2` 的旧行（打包机时代的单机记录 `{"version","ok","agent",…}`）读出来当作空，第一次上报时整行覆盖成 format 2。

## 就绪（排队门禁与签名认领共用 `signerReadinessFor`）

该租户有 v3 `build.keystore` 且与 `release.android` 一致；登记里有 active 的 primary 签名闸且密钥加密给了它；服务端算得出信任根（合成的 tenant manifest + 当前 OTA 证书；App Links host 按 RN-App `new URL(apiBaseUrl).host`）；primary 的检查记录 `keystoreVersion` 等于当前版本、`decrypt=ok`、`confirmed`、`confirmedTrustRootsDigest` 等于服务端当前摘要、`trialSign=ok`。任何一项不满足：排队 409 `SIGNER_NOT_READY`（detail 逐条列出），签名认领不派。

不就绪原因带固定 code，排队 409 的问题体与 `GET /v1/admin/build-keystore` 都以 `readinessProblems: [{"code","detail"}]` 给出（就绪时为空数组），枚举见 OpenAPI `SignerReadinessProblem` 与 ADR-0019 第 5 节。

ADR-0020 在枚举末尾追加三条，**只在租户没有可用的 v3 密钥时出现**（说明"为什么还没有密钥"；已有可用密钥的租户换密钥期间照常用旧密钥签，生成状态看视图里的 `generationRequest`）：`RECOVERY_KEY_NOT_CONFIGURED`（平台没有未吊销的恢复公钥）、`KEYSTORE_GENERATION_PENDING`（最近一次生成请求在等主签名闸）、`KEYSTORE_GENERATION_FAILED`（最近一次生成失败，detail 带签名闸报的 code）。
