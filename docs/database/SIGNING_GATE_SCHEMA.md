# 签名闸相关的 app_configs 键（build.machines / build.keystore / build.keystore.check）

设计：`docs/design/android-signing-gate-2026-09-16.md`；决策：ADR-0019；接口 JSON 见 `contracts/openapi.json`。本期**不新建表**：机器登记、签名密钥密文、每台签名闸的检查状态都放在 `app_configs`，打包任务的构建段与签名段合并进 `build_jobs`（见 `RELEASE_SCHEMA.md`），签名与拒签的历史进 `audit_events`（`actor_id='system-signer'`）。

签名闸与离线工具**不采信**这里的任何一项：签名闸只信本机记录（受信构建机、确认过的证书与信任根、签过的版本号），离线工具只加密给离线 pin 文件里的签名闸。这些键只用于服务端鉴权、路由与控制台展示。

## 表职责

| 键 | 作用域 | 作用 | 谁写 | 谁读 |
| --- | --- | --- | --- | --- |
| `build.machines` | 平台级（`tenant_id=0`），明文 | 构建机与签名闸登记：令牌 sha256、公钥、状态、主备 | 平台管理员（新建、吊销、接受公钥、切换主备）；机器自己（登记待接受的公钥） | 机器鉴权中间件（按 `version` 缓存）、签名认领、签名密钥上传校验、控制台 |
| `build.keystore` | 租户级，外层 `STORAGE_MASTER_KEY` secretbox | 离线工具产出的 v3 上传文件（多份加密给签名闸的密文）与索引字段 | 租户管理员经控制台上传（与 `release.android` 同一事务） | 签名闸（只取发给本机的那份）、就绪判断、控制台 |
| `build.keystore.check` | 租户级，明文 | 每台签名闸对当前密钥版本的试解、本机确认、试签状态 | 签名闸（按机器 id `JSON_SET` 单键） | 就绪判断、控制台 |

## build.machines

```json
{"machines":[{
  "id":"mch_…","role":"builder|signer","signerRole":"primary|standby|null","name":"amos-signer-a",
  "status":"pending_key|active|revoked","tokenSha256":"<64hex>",
  "publicKey":"<base64|null>","publicKeySha256":"<64hex|null>",
  "ed25519PublicKey":"<base64|null>","ed25519PublicKeySha256":"<64hex|null>",
  "pending":{"publicKey","publicKeySha256","ed25519PublicKey","ed25519PublicKeySha256","reportedAt"} | null,
  "acceptedBy":null,"acceptedAt":null,"createdBy":"…","createdAt":"…","revokedBy":null,"revokedAt":null,"revokeReason":null
}]}
```

| 字段 | 含义 |
| --- | --- |
| `role` | `builder` = 构建机；`signer` = 签名闸 |
| `signerRole` | 仅签名闸：`primary` 领签名任务，`standby` 不领；构建机为 null |
| `status` | `pending_key` = 新建后还没有被接受的公钥，只能调各自的 public-key 接口；`active`；`revoked` = 吊销，令牌下一次请求就 401 |
| `tokenSha256` | 机器令牌（`rnm_` + 32 字节 base64url）的 sha256。令牌原文只出现在新建接口的响应里，不进审计、不进日志 |
| `publicKey` / `publicKeySha256` | 已接受的主公钥。构建机：Ed25519 出处公钥；签名闸：X25519 收件人公钥（sha256 就是密文的 `recipientSha256`） |
| `ed25519PublicKey` / `ed25519PublicKeySha256` | 仅签名闸：记录签名与换钥证明用的 Ed25519 公钥 |
| `pending` | 机器报上来、等平台管理员核对完整指纹后接受的公钥。已 active 的机器换钥必须带用当前私钥对 `machinekey.RotationMessage` 的签名；旧公钥在接受之前一直有效 |

所有 sha256 都按 base64 解码后的 32 字节原始公钥计算，完整 64 位小写十六进制。

不变量（写入时校验，读到不满足的值鉴权直接失败）：

- id 唯一、令牌 sha256 唯一；非吊销机器名称唯一（`^[a-z0-9][a-z0-9-]{1,39}$`）。
- 非吊销的 `signerRole=primary` 最多一台；切换主签名闸时原 primary 同一次写降为 standby。
- `active` 的机器必须有已接受的公钥（签名闸两把都要有）。
- 同一把公钥（当前或待接受）不能出现在两台非吊销机器上。
- 写入带乐观锁（`expectedVersion` = 这一行的 `version`，不符 409 `MACHINES_VERSION_CONFLICT`），管理端写都要 `reason` + `confirm` 并写审计（`build_machine_create/revoke/key_accept/signer_role`，机器自报公钥为 `build_machine_key_report`）。
- 鉴权每个请求先主键查 `version, updated_at`，没变用内存缓存，变了重读：吊销即时生效。

## build.keystore（format 3）

```json
{"format":3,"sealed":"<base64 secretbox(Upload JSON)>","keyAlias":"release","certificateSha256":"<64hex>",
 "packageName":"com.example.app","tenantSlug":"Example","recipients":["<64hex>", "…"]}
```

- `sealed` 外层用 `STORAGE_MASTER_KEY` 加密（关联数据 `build-keystore/v3:<tenantId>`），里面是离线工具产出的 `rn-android-keystore-upload/v3` 文件（`signing/keystorebox.Upload`）：每个收件人一份 `x25519-hkdf-sha256-aes256gcm` 密文，明文绑定租户、包名、证书指纹、别名与收件人列表。服务端打不开内层。
- `keyAlias`、`certificateSha256`、`packageName`、`tenantSlug`、`recipients`（排序）是从文件里抄出来的索引，读取时与文件逐项比对，不一致是数据事故。
- 写入（`PUT /v1/admin/build-keystore`）只收 v3：收件人必须都是已登记、非吊销签名闸已接受的 X25519 公钥（多余的拒收，缺的只提示）；`tenantSlug` 等于本租户；请求里的 `packageName`、`signerSha256` 与文件一致；证书不是作废的旧指纹。与 `release.android` 在同一事务里各自带乐观锁写入（ADR-0016）。
- **没有 `format:3` 的旧记录**（v1 口令封 `{"sealed","keyAlias","keystoreSha256"}`、v2 加密给打包机公钥）读出来当作"没有可用的签名密钥"：控制台显示 `legacy=true`，排队与签名认领一律不就绪，上传 v3 时带这一行的 `version` 覆盖。

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

- 按机器 id 用 `JSON_SET` 只改自己那个键，主备并发上报互不覆盖；只收当前密钥版本的结论。状态真的变了才写审计 `build_keystore_check_update`。
- 没有 `format:2` 的旧行（打包机时代的单机记录 `{"version","ok","agent",…}`）读出来当作空，第一次上报时整行覆盖成 format 2。

## 就绪（排队门禁与签名认领共用 `signerReadinessFor`）

该租户有 v3 `build.keystore` 且与 `release.android` 一致；登记里有 active 的 primary 签名闸且密钥加密给了它；服务端算得出信任根（合成的 tenant manifest + 当前 OTA 证书；App Links host 按 RN-App `new URL(apiBaseUrl).host`）；primary 的检查记录 `keystoreVersion` 等于当前版本、`decrypt=ok`、`confirmed`、`confirmedTrustRootsDigest` 等于服务端当前摘要、`trialSign=ok`。任何一项不满足：排队 409 `SIGNER_NOT_READY`（detail 逐条列出），签名认领不派。
