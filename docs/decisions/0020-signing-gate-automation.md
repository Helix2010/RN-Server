# ADR-0020：签名闸部署与换密钥自动化（半自动）

状态：Accepted（2026-09-16）

完整设计：`docs/design/android-signing-gate-automation-2026-09-16.md`（下称"设计"）；表与配置结构：`docs/database/SIGNING_GATE_SCHEMA.md`；接口：`contracts/openapi.json`（2026.09.23）。本 ADR 在 ADR-0019 之上修改两件事：新机器怎么进来、租户签名密钥在哪里生成。ADR-0019 的其余决策（构建与签名拆机、编号防护、就绪判断、作废指纹、手工上传闸）不变。

## 背景

ADR-0019 上线 amos 时每一步都靠人：每台新机器要传部署包、跑脚本、手抄令牌、在控制台手抄两个指纹；每个租户换密钥要在离线机器上生成、gpg 打包进两个 U 盘、带回上传、两台签名闸各 `confirm` 一次。运维成本太高，而且前提是能从本地 ssh 到服务器，实际并不具备。

用户决定降到"半自动"：新机器 = 服务器本机一条命令 + 控制台点一次接受；换密钥 = 控制台点一次，由主签名闸本机生成；全平台只做一次离线操作（生成离线恢复密钥）；信任新的构建机、签名闸与信任根变化仍在签名闸本机确认。

## 安全模型的变化

这是本 ADR 最重要的部分。下表照抄设计「本设计保证什么，不保证什么」：

| 服务端或数据库被攻破后，攻击者能不能… | ADR-0019 | 本 ADR | 为什么 |
| --- | --- | --- | --- |
| 解开或偷走已有租户的签名密钥 | 不能 | 不能 | 密钥只加密给签名闸本机信任的签名闸与离线恢复公钥；新增收件人要在签名闸本机确认 |
| 让签名闸改用别的密钥签已有租户 | 不能 | 不能 | 本机记录按包名记着证书；新证书只接受本机或本机信任的签名闸生成的 |
| 让签名闸签指向攻击者服务端的包（已有租户） | 不能 | 不能 | 信任根变化要在签名闸本机重新确认 |
| 让签名闸签伪造构建机交付的包 | 不能 | 不能 | 构建机信任仍在签名闸本机确认 |
| 版本号乱签、同一 versionCode 签两个包 | 不能 | 不能 | 本机记录，不变 |
| **新租户第一次生成密钥时，写入错误的信任根** | 不能 | **能** | 新租户的信任根在第一次生成时直接取服务端的值（首次信任） |
| **让签名闸无意义地换一把新密钥（老用户升不上去）** | 不能 | **能** | 控制台一键换密钥；新密钥仍由签名闸生成、攻击者拿不到，后果是拒绝服务 |
| **在新机器安装时下发篡改过的程序** | 不适用 | **能** | 安装包从服务端下载；只影响此后新装的机器，已在运行的签名闸不受影响 |

服务端这一侧据此做的取舍：

- **服务端给签名闸的一切仍然只作对照或首次信任的输入**：`generationRequest.trustRoots`（首次信任）、`describe.primarySigner`（备签名闸首次信任主签名闸）、`/v1/signer/peers`（本机命令显示用，运维粘贴指纹比对）、`reportedTrust`（只显示）。服务端校验这些，是为了让错误尽早暴露，不是安全边界。
- **服务端仍然打不开任何密钥**。交回的密文服务端照样只校验形状与归属；它额外验证生成签名（用登记的主签名闸 Ed25519 公钥）并要求至少一把恢复收件人，但真正的防线在签名闸本机：备签名闸只认本机信任的生成者，主签名闸只加密给本机信任的签名闸与恢复公钥。
- **长期机器令牌不再经过控制台与屏幕**：控制台只发一次性注册码（60 分钟、一次、只存 sha256）；令牌由机器在本机注册时换回并直接写进 env 文件。注册码泄露的后果是"别人抢先用它注册了一台机器"——那台机器的公钥还要在控制台接受、要在签名闸本机 `trust-builder`/`trust-peer`，而真机注册会失败（码已用），运维会发现。
- **新增的拒绝服务面**（控制台一键换密钥、篡改安装包）在控制台权限与部署流水线上约束：换密钥要 `reason` + `confirm` 并审计，已有可用密钥的租户换密钥期间照常用旧密钥签；签名闸安装包的 sha256 在生产要与 CI 构建日志核对（`install.sh --expect-sha256`）。

## 决策

### 1. 新机器：注册码与 machine-setup

- `POST /v1/admin/platform/machines` 不再返回令牌，返回 `enrollment: {code, expiresAt, installCommand}`；机器状态新增 `pending_enrollment`。安装命令由服务端按请求的外部源拼好（`https` 只在 TLS、生产环境、或 `TRUSTED_PROXIES` 里的代理说 `X-Forwarded-Proto: https` 时成立），签名闸的命令末尾带 `--recovery-sha256 <从密码管理器粘贴恢复公钥指纹>` 占位——**恢复公钥指纹不取控制台的值**。
- 新建签名闸要求平台已登记未吊销的恢复公钥（409 `RECOVERY_KEY_NOT_CONFIGURED`）：没有恢复公钥的签名闸什么密钥都生成不了。
- `POST /v1/admin/platform/machines/:id/enrollment` 重发注册码（旧码作废），只对 `pending_enrollment`。
- `/v1/machine-setup`（不走机器令牌）：`GET /install.sh`（`internal/machinesetup` 嵌入的脚本）、`POST /describe`（不消耗注册码；机器身份、安装包清单、签名闸的恢复公钥、备签名闸的当前主签名闸公钥）、`GET /bundle/{role}.tar.gz`（头 `x-enrollment-code`，只给注册码所属角色，流式，按路由模板精确豁免数据库超时）、`POST /enroll`。三条按来源 IP 每分钟 20 次限速（429 `MACHINE_SETUP_RATE_LIMITED`）。注册码无效、过期、已用一律 404 `ENROLLMENT_CODE_INVALID`，同一句话。
- `enroll` 在**一个写事务**里 `FOR UPDATE` 读 `build.machines`、核对并消耗注册码、挂上待接受的公钥（`pending_key`）、签发令牌、写审计 `machine_enrolled`（不含令牌与注册码）。同一个码并发注册恰好一个成功（有测试）。
- 注册码合并进机器项的 `enrollment` 字段（同一实体的一次性状态，写方只有服务端），不建表。
- 安装包放在服务器本地 `/opt/rn-foundation/machine-bundles/current/`（`manifest.json` 格式 `rn-machine-bundles/v1`），由部署脚本原子切换 `current` 软链；服务端每次请求先解析软链再读清单与归档，避免切换时拿到"新清单 + 旧归档"。**不是配置项**，env 不新增键（它是和服务端二进制一起部署的产物，路径是部署约定）；目录或清单不在、归档大小与清单不符时 503 `MACHINE_BUNDLE_UNAVAILABLE`。
- 接受公钥（`accept-key`）请求体不变，控制台从视图的 `pendingPublicKeySha256` / `pendingEd25519PublicKeySha256` 填入。

### 2. 平台离线恢复公钥

- `app_configs` 平台级 `build.recovery.recipients`（公钥非机密，明文），平台管理员经 `/v1/admin/platform/recovery-keys` 登记（严格解析 `recovery-public.json`，`signing/recovery.ParsePublic`）与吊销；同一 sha256 只能登记一次，吊销后也不能再登记。
- 用途：新建签名闸的前提；`describe` 与 `/v1/signer/peers` 给本机命令取公钥原文；交回密钥时"至少一把恢复收件人"的判据；控制台展示。

### 3. 控制台一键生成签名密钥

- `POST /v1/admin/build-keystore/generate` 只记一条生成请求：租户级 `app_configs` `build.keystore.request`（每个租户同时最多一条未完成，写方明确），记下发起时 `build.keystore` 与 `release.android` 的版本。前提逐条检查：包名等于 `release.android` 的包名（没有发布身份的新租户取请求里的包名）、平台有恢复公钥、有 active 主签名闸、信任根算得出来（否则 409 `KEYSTORE_TRUST_ROOTS_UNAVAILABLE`，detail 说缺什么）。别名 `<slug 小写>-release`。
- `GET /v1/signer/keystore-checks` 只给 active 的路由主签名闸下发 `generationRequest`（带首次信任要用的信任根与摘要、`publishedMaxBuildNumber`）。租户这时可能还没有发给这台主签名闸的密文（新租户、旧格式记录），这种项 `box`/`packageName`/`certificateSha256`/`keyAlias` 为 null，只用来领生成请求；服务端也不收签名闸对这种项上报的"检查结论"（只收密钥加密给了上报者的结论）。
- 新租户还没有 `release.android` 时，信任根照样算：合成 tenant manifest 时包名取生成请求里的、签名证书指纹留空（信任根不含这两项，摘要与之后登记了身份时相同，有测试）。
- `POST /v1/signer/keystore-generations/:requestId` 一个事务，按 `build.keystore` → `release.android` → `build.keystore.request` 的顺序加锁（与发起、导入同序，避免交叉死锁）：
  1. 请求仍是当前 `pending`，两个版本都没变——否则 409 `KEYSTORE_GENERATION_STALE`，版本变了的把请求写成 `failed`；
  2. 调用者此刻是 active 的路由主签名闸，`generator` 就是它自己（403 `KEYSTORE_GENERATOR_NOT_PRIMARY`）；
  3. 用它登记的 Ed25519 公钥验 `keystorebox.GenerationMessage(requestId, upload)` 的签名（422 `KEYSTORE_GENERATION_SIGNATURE_INVALID`）；
  4. 上传文件按导入的全部规则校验（格式、租户、包名与别名等于请求、作废与公开 debug 证书、收件人），收件人可以是未吊销签名闸已接受的公钥或未吊销的恢复公钥，**至少一把恢复公钥**（422 `KEYSTORE_RECOVERY_RECIPIENT_MISSING`）；
  5. 写 `build.keystore`（新增 `generator`、`generationSignature`、`generationRequestId`）与 `release.android`（ADR-0016 同事务），请求标 `done`，审计 `build_keystore_generated`。
  签名闸没收到响应而重试：同一请求、同一签名已落库的按成功返回。1–4 的拒绝不改请求状态（主签名闸可以修正后再交，或调 `/fail`）。
- `POST /v1/signer/keystore-generations/:requestId/fail {code, detail}`：主签名闸报告做不了（`TRUST_ROOTS_CHANGED`、`RECOVERY_KEY_NOT_PINNED`、`NOT_LOCAL_PRIMARY`、`GENERATION_FAILED`……），请求标 `failed`。
- 当前密钥由签名闸生成时，`keystore-checks` 每项带 `generator`、`generationSignature`、`generationRequestId` 与整份 `upload`：备签名闸验证生成者是本机信任的签名闸、签名有效之后自动确认；离线导入的密钥这几项为 null，仍走 `signer confirm`。
- **过期在读取时推导**：`pending` 而两个版本任一已变（导入了密钥、改了发布身份）按 `failed` + `KEYSTORE_GENERATION_STALE` 处理——不下发、不挡新的请求、控制台与就绪都这样显示；交回时才写回库。不引入定时器，也不在导入、改身份的写路径里顺带改请求（那会让三个写路径都依赖这张记录）。
- `build.keystore.request` 这一行读不出来（被改坏）时，读路径记日志、按没有请求处理：它不能挡住这个租户已有密钥的检查、就绪与签名；再次发起时覆盖。

### 4. 导入与导出

- `PUT /v1/admin/build-keystore` 降级为"导入已有密钥（高级）"：收件人范围同样放宽到恢复公钥，但**不强制**恢复收件人——离线导入意味着运维手里有原件，而离线工具 `seal` 目前只按签名闸 pin 文件加密。
- `GET /v1/admin/build-keystore/export`：下载当前密钥的上传文件（纯密文）给离线工具 `recover`，审计 `build_keystore_exported`。租户管理员可以导出：文件只有收件人签名闸与恢复私钥持有人打得开。

### 5. 签名闸上报本机信任

- `POST /v1/signer/keystore-checks` 顶层新增必填 `trust`（本机信任的签名闸含本机、构建机、恢复公钥 sha256），服务端排序后记进机器项 `reportedTrust`/`reportedTrustAt`，只在变化时写（与 `reportedLocalRole` 合成一次写，审计 `build_machine_trust_report`）。只给控制台提示（主签名闸没信任备签名闸、签名闸没信任构建机或恢复公钥），不参与任何判断。
- `GET /v1/signer/peers`：active 的签名闸、构建机公钥与未吊销的恢复公钥，给 `trust-peer`、`trust-builder --builder`、`trust-recovery` 显示；签名闸比对运维粘贴的完整指纹后才写本机记录。

### 6. 就绪问题码

枚举末尾追加 `RECOVERY_KEY_NOT_CONFIGURED`、`KEYSTORE_GENERATION_PENDING`、`KEYSTORE_GENERATION_FAILED`，**只在租户没有可用的 v3 密钥时出现**。理由：就绪问题回答的是"现在为什么不能签"。已有可用密钥的租户在换密钥期间照常用旧密钥签——把"生成中""生成失败"算成不就绪，会让一次没成功（或主签名闸离线、还没升级）的换密钥把正在工作的租户卡死，而且没有取消入口；控制台从 `GET /v1/admin/build-keystore` 的 `generationRequest` 显示生成状态。交回之后密钥版本变了，主签名闸检查之前本来就不就绪（`PRIMARY_SIGNER_NOT_CHECKED`）。

## 复用映射（先复用再建表）

| 拟新增 | 结论 | 理由 |
| --- | --- | --- |
| 注册码（sha256、有效期、是否已用） | 合并进 `build.machines` 机器项 `enrollment` | 同一实体的一次性状态，写方只有服务端 |
| 恢复公钥 | 复用 `app_configs` 平台级 `build.recovery.recipients` | 平台级配置，条目少 |
| 生成请求 | 复用 `app_configs` 租户级 `build.keystore.request` | 每个租户同时最多一个，写方明确 |
| 生成者与签名 | 合并进 `build.keystore` 记录 | 属于这份密文的元数据 |
| 签名闸上报的本机信任 | 合并进 `build.machines` 机器项 `reportedTrust`，只在变化时写 | 同 `reportedLocalRole` |
| 安装包 | 不进库，服务器文件系统 | 部署产物 |
| 生成、注册、登记恢复公钥、导出的历史 | 复用 `audit_events` | — |

## 兼容与发布

- **线上已有数据**：amos 的 `build.machines` 三台 `active` 机器没有 `enrollment`、`reportedTrust` 字段，按 null 读，鉴权与路由照常（有测试用手写的旧 JSON 验证）；已有 `build.keystore`（离线导入或旧格式）没有生成者字段，照常读；`build.keystore.check` 不变。没有迁移。
- **发布顺序**：`trust` 与 `localRole` 一样是必填——旧签名闸二进制对新服务端的检查上报会 400（它的检查与就绪在升级前不再更新）。服务端与签名闸同一窗口升级（设计第 6 节第 1 步）。旧构建机与旧签名闸的其它接口不受影响。
- **回滚**：回滚到本 ADR 之前的服务端时，由签名闸生成的 `build.keystore` 记录带新字段，旧代码严格解析会判 `KEYSTORE_RECORD_INVALID`（不就绪、不下发），需要重新前滚或导入。登记里只要有一台**从没注册过**的机器（`pending_enrollment`，或没注册就被吊销、令牌 sha256 为空串），旧代码的不变量校验就不过，整份 `build.machines` 读不出来（所有机器鉴权 503）——回滚前先确认没有这样的机器项，有就直接从 JSON 里删掉那几项。注册过的机器与手工登记的机器项旧代码照常读（`enrollment`、`reportedTrust` 是它不认识的键，登记用宽松解析，旧代码再写登记时会丢掉这些键）。

## 代价

- 服务端被攻破时多了三种后果（见上表加粗三行）：新租户首次信任、无意义换密钥（拒绝服务）、给新装机器下发篡改的安装包。
- 生成失败或过期的请求只能靠再次发起覆盖，没有单独的取消接口。
- 新机器注册多了一组不走机器令牌的公开接口，靠一次性注册码与按 IP 限速约束。
