# ADR-0020：签名闸部署与换密钥自动化（半自动）

状态：Accepted（2026-09-16）

完整设计：`docs/design/android-signing-gate-automation-2026-09-16.md`（下称"设计"）；表与配置结构：`docs/database/SIGNING_GATE_SCHEMA.md`；接口：`contracts/openapi.json`（2026.09.24）。本 ADR 在 ADR-0019 之上修改两件事：新机器怎么进来、租户签名密钥在哪里生成。ADR-0019 的其余决策（构建与签名拆机、编号防护、就绪判断、作废指纹、手工上传闸）不变。

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
- 新建签名闸要求平台已登记未吊销的恢复公钥（409 `RECOVERY_KEY_NOT_CONFIGURED`）：没有恢复公钥的签名闸什么密钥都生成不了。签名闸的机器名最多 22 个字符（400 `INVALID_MACHINE`）：install.sh 按机器名建系统用户 `rn-signer-<机器名>`，Linux 用户名上限 32 个字符；构建机仍按通用规则（40 个字符）。
- `POST /v1/admin/platform/machines/:id/enrollment` 重发注册码（旧码作废），只对 `pending_enrollment`（已注册 409 `MACHINE_ALREADY_ENROLLED`，已吊销 409 `MACHINE_REVOKED`）。签名闸与新建同一条前提：平台没有未吊销的恢复公钥时 409 `RECOVERY_KEY_NOT_CONFIGURED`，旧码不作废。
- `/v1/machine-setup`（不走机器令牌）：`GET /install.sh`（`internal/machinesetup` 嵌入的脚本）、`POST /describe`（不消耗注册码；机器身份、安装包清单、签名闸的恢复公钥、备签名闸的当前主签名闸公钥）、`GET /bundle/{role}.tar.gz`（头 `x-enrollment-code`，只给注册码所属角色，流式，按路由模板精确豁免数据库超时）、`POST /enroll`。三条按来源 IP 每分钟 20 次限速（429 `MACHINE_SETUP_RATE_LIMITED`）。注册码无效、过期、已用一律 404 `ENROLLMENT_CODE_INVALID`，同一句话。
- `enroll` 在**一个写事务**里 `FOR UPDATE` 读 `build.machines`、核对并消耗注册码、挂上待接受的公钥（`pending_key`）、签发令牌、写审计 `machine_enrolled`（不含令牌与注册码）。同一个码并发注册恰好一个成功（有测试）。
- 注册码合并进机器项的 `enrollment` 字段（同一实体的一次性状态，写方只有服务端），不建表。
- 安装包放在服务器本地 `/opt/rn-foundation/machine-bundles/current/`（`manifest.json` 格式 `rn-machine-bundles/v1`），由部署脚本原子切换 `current` 软链；服务端每次请求先解析软链再读清单与归档，避免切换时拿到"新清单 + 旧归档"。**不是配置项**，env 不新增键（它是和服务端二进制一起部署的产物，路径是部署约定）；目录或清单不在、归档大小与清单不符时 503 `MACHINE_BUNDLE_UNAVAILABLE`。
- 接受公钥（`accept-key`）请求体不变，控制台从视图的 `pendingPublicKeySha256` / `pendingEd25519PublicKeySha256` 填入。

### 2. 平台离线恢复公钥

- `app_configs` 平台级 `build.recovery.recipients`（公钥非机密，明文），平台管理员经 `/v1/admin/platform/recovery-keys` 登记（严格解析 `recovery-public.json`，`signing/recovery.ParsePublic`）与吊销；同一 sha256 只能登记一次，吊销后也不能再登记。
- 用途：新建签名闸的前提；`describe` 与 `/v1/signer/peers` 给本机命令取公钥原文；交回密钥时"至少一把恢复收件人"的判据；控制台展示。

### 3. 控制台一键生成签名密钥

- `POST /v1/admin/build-keystore/generate` 只记一条生成请求：租户级 `app_configs` `build.keystore.request`（每个租户同时最多一条未完成，写方明确），记下发起时 `build.keystore` 与 `release.android` 的版本。前提逐条检查：包名等于 `release.android` 的包名（没有发布身份的新租户取请求里的包名）、包名不是别的租户 `release.android` 或 `build.keystore` 在用的（409 `ANDROID_PACKAGE_IN_USE`，不说是哪个租户；签名闸本机按包名把关本来也会拒，这里只是免得白白生成）、平台有恢复公钥、有 active 主签名闸、信任根算得出来（否则 409 `KEYSTORE_TRUST_ROOTS_UNAVAILABLE`，detail 说缺什么）。别名 `<slug 小写>-release`。
- `GET /v1/signer/keystore-checks` 只给 active 的路由主签名闸下发 `generationRequest`（带首次信任要用的信任根与摘要、`publishedMaxBuildNumber`）。租户这时可能还没有发给这台主签名闸的密文（新租户、旧格式记录），这种项 `box`/`packageName`/`certificateSha256`/`keyAlias` 为 null，只用来领生成请求；服务端也不收签名闸对这种项上报的"检查结论"（只收密钥加密给了上报者的结论）。
- 新租户还没有 `release.android` 时，信任根照样算：合成 tenant manifest 时包名取生成请求里的、签名证书指纹留空（信任根不含这两项，摘要与之后登记了身份时相同，有测试）。
- `POST /v1/signer/keystore-generations/:requestId` 一个事务，按 `build.keystore` → `release.android` → `build.keystore.request` 的顺序加锁（与发起、导入同序，避免交叉死锁）：
  1. 请求仍是当前 `pending`，两个版本都没变、发起不超过 30 分钟——否则 409 `KEYSTORE_GENERATION_STALE`（签名闸据此丢弃生成的密钥），版本变了或超时的把请求写成 `failed`（`KEYSTORE_GENERATION_STALE` / `KEYSTORE_GENERATION_TIMED_OUT`）；
  2. 调用者此刻是 active 的路由主签名闸，`generator` 就是它自己（403 `KEYSTORE_GENERATOR_NOT_PRIMARY`）；
  3. 用它登记的 Ed25519 公钥验 `keystorebox.GenerationMessage(requestId, upload)` 的签名（422 `KEYSTORE_GENERATION_SIGNATURE_INVALID`）；
  4. 上传文件按导入的全部规则校验（格式、租户、包名与别名等于请求、作废与公开 debug 证书、收件人），收件人可以是未吊销签名闸已接受的公钥或未吊销的恢复公钥，**至少一把恢复公钥**（422 `KEYSTORE_RECOVERY_RECIPIENT_MISSING`），**并且必须有发给主签名闸自己（生成者当前接受的 X25519 公钥）的密文**（422 `KEYSTORE_PRIMARY_RECIPIENT_MISSING`——否则发布身份换成新证书，主签名闸却再也解不开这个租户，就绪永远 `PRIMARY_SIGNER_NOT_RECIPIENT`）；
  5. 写 `build.keystore`（新增 `generator`、`generationSignature`、`generationRequestId`）与 `release.android`（ADR-0016 同事务），请求标 `done`，审计 `build_keystore_generated`。
  签名闸没收到响应而重试：同一请求、同一签名已落库的按成功返回。1–4 的拒绝不改请求状态（主签名闸可以修正后再交，或调 `/fail`）。
- `POST /v1/signer/keystore-generations/:requestId/fail {code, detail}`：主签名闸报告做不了（`TRUST_ROOTS_CHANGED`、`RECOVERY_KEY_NOT_PINNED`、`NOT_LOCAL_PRIMARY`、`GENERATION_FAILED`……），请求标 `failed`。与交回同一个判断：已经过期或超时的请求不收签名闸报的原因，409 并把推导出的失败写回。
- 当前密钥由签名闸生成时，`keystore-checks` 每项带 `generator`、`generationSignature`、`generationRequestId` 与整份 `upload`：备签名闸验证生成者是本机信任的签名闸、签名有效之后自动确认；离线导入的密钥这几项为 null，仍走 `signer confirm`。
- **过期与超时在读取时推导**（服务端时钟，可注入）：`pending` 而两个版本任一已变（导入了密钥、改了发布身份）按 `failed` + `KEYSTORE_GENERATION_STALE` 处理；`pending` 超过 30 分钟（主签名闸离线、没升级、信任根算不出来所以没下发）按 `failed` + `KEYSTORE_GENERATION_TIMED_OUT` 处理，两者都成立时报前者。都是不下发、不挡新的请求、控制台与就绪都这样显示；交回或失败报告时才写回库。不引入定时器，也不在导入、改身份的写路径里顺带改请求（那会让三个写路径都依赖这张记录）。
- `build.keystore.request` 这一行读不出来（被改坏）时，读路径记日志、按没有请求处理：它不能挡住这个租户已有密钥的检查、就绪与签名；再次发起时覆盖。

### 4. 导入与导出

- `PUT /v1/admin/build-keystore` 降级为"导入已有密钥（高级）"：收件人范围同样放宽到恢复公钥，但**不强制**恢复收件人——离线导入意味着运维手里有原件，而离线工具 `seal` 目前只按签名闸 pin 文件加密。包名同样不能是别的租户在用的（409 `ANDROID_PACKAGE_IN_USE`）。
- `GET /v1/admin/build-keystore/export`：下载当前密钥的上传文件给离线工具 `recover`，**只带发给未吊销恢复公钥的密文**，发给签名闸的不带；一个都没有 409 `BUILD_KEYSTORE_EXPORT_NO_RECOVERY_RECIPIENT`。理由：租户管理员可以导出，而带上签名闸的密文时，一台被吊销但没擦盘的签名闸私钥加上任何一次导出就能解开密钥；`recover` 本来只需要发给恢复公钥的那份（它只校验形状、核对明文与外层字段，不校验生成签名），恢复路径是 导出 → `recover` → `seal` → 导入，不是把导出文件直接导入。读密钥与写审计 `build_keystore_exported`（记实际导出的收件人）在同一个事务里，审计写不进去就 500 `BUILD_KEYSTORE_EXPORT_FAILED`、不给文件。
- `GET /v1/admin/build-keystore` 的 `recoveryRecipients` 列出当前密钥加密给了哪几把恢复公钥（含已吊销的：密文已经发给它了），`revokedRecoveryRecipients` 是其中已吊销的子集。两者相等时这把密钥已经没有可用的离线恢复，控制台提示登记新恢复公钥后重新生成。

### 5. 签名闸上报本机信任

- `POST /v1/signer/keystore-checks` 顶层新增 `trust`（本机信任的签名闸含本机、构建机、恢复公钥 sha256），新版本签名闸每轮都带，服务端排序后记进机器项 `reportedTrust`/`reportedTrustAt`，只在变化时写（与 `reportedLocalRole` 合成一次写，审计 `build_machine_trust_report`）。只给控制台提示（主签名闸没信任备签名闸、签名闸没信任构建机或恢复公钥），不参与任何判断。`trust` 可以缺（或为 null）：自动化之前的签名闸不认识这个字段，上报照常收下 `localRole` 与检查结论，`reportedTrust`/`reportedTrustAt` 记成 null（"这个版本不上报信任"，不保留旧值），控制台显示为未上报、不出信任提示。
- `GET /v1/signer/peers`：active 的签名闸、构建机公钥与未吊销的恢复公钥，给 `trust-peer`、`trust-builder --builder`、`trust-recovery` 显示；签名闸比对运维粘贴的完整指纹后才写本机记录。

### 6. 就绪问题码

枚举末尾追加 `RECOVERY_KEY_NOT_CONFIGURED`、`KEYSTORE_GENERATION_PENDING`、`KEYSTORE_GENERATION_FAILED`，**只在租户没有可用的 v3 密钥时出现**。理由：就绪问题回答的是"现在为什么不能签"。已有可用密钥的租户在换密钥期间照常用旧密钥签——把"生成中""生成失败"算成不就绪，会让一次没成功（或主签名闸离线、还没升级）的换密钥把正在工作的租户卡死，而且没有取消入口；控制台从 `GET /v1/admin/build-keystore` 的 `generationRequest` 显示生成状态。交回之后密钥版本变了，主签名闸检查之前本来就不就绪（`PRIMARY_SIGNER_NOT_CHECKED`）。

## 同证书重新封装（第二轮）

**问题**：密钥只在生成或导入时封装给当时的收件人。后加或替换的签名闸即使做完 `trust-peer` 也拿不到已有租户的密钥；
重新生成会换证书，已安装的 App 升不上去。剩下的路是离线 `recover` + `seal` + 导入 + 各自 `confirm`——正是这次要去掉的仪式。

**决定**：主签名闸把已确认的同一张证书重新封装给本机决定的收件人，交回新接口 `POST /v1/signer/keystore-reseals`。

| 选项 | 取舍 |
| --- | --- |
| 控制台加「重新封装」按钮 | 不要：收件人由签名闸本机决定，控制台按不按都不影响结果，多一个会误解成"服务端说了算" |
| 复用交回生成的接口与签名 | 不要：生成会换证书、要写发布身份、要有请求；重新封装两样都不做。签名另起 `rn-keystore-reseal/v1` 域，两种签名不能互相冒充，id 前缀也不重叠（`kgr_` / `rsl_`） |
| 服务端决定收件人 | 不要：那等于服务端能把密钥加密给它挑的公钥。服务端只下发 `recipients`（当前收件人）与机器状态，交集由签名闸本机算 |
| 缺收件人就立即封装 | 加 10 分钟节流：服务端乱报状态时不至于每分钟改写一次密钥记录 |
| 与生成并发 | 有待处理的生成请求时不封装（409）：生成本来就会换掉收件人 |

**确认参数**：明文里绑定的 `Generation` 换成本机对这张证书的当前确认（`kind=reseal`，被取代的证书就是它自己）。
新备签名闸本机没有确认时按它首次信任（`auto:peer-resealed:<主签名闸名>`），与自动接受生成时同一套规则。

**发布顺序**：服务端先上线；主签名闸升级后才会重新封装，旧签名闸不会调这个接口。`sealKind` 字段旧记录读成 `generation`，
旧服务端遇到 `sealKind` 会判记录非法——与其它新字段一样，只能前滚。

## 复用映射（先复用再建表）

| 拟新增 | 结论 | 理由 |
| --- | --- | --- |
| 注册码（sha256、有效期、是否已用） | 合并进 `build.machines` 机器项 `enrollment` | 同一实体的一次性状态，写方只有服务端 |
| 恢复公钥 | 复用 `app_configs` 平台级 `build.recovery.recipients` | 平台级配置，条目少 |
| 生成请求 | 复用 `app_configs` 租户级 `build.keystore.request` | 每个租户同时最多一个，写方明确 |
| 生成者与签名 | 合并进 `build.keystore` 记录（重新封装复用同样的字段，另加 `sealKind`） | 属于这份密文的元数据 |
| 签名闸上报的本机信任 | 合并进 `build.machines` 机器项 `reportedTrust`，只在变化时写 | 同 `reportedLocalRole` |
| 安装包 | 不进库，服务器文件系统 | 部署产物 |
| 生成、注册、登记恢复公钥、导出的历史 | 复用 `audit_events` | — |

## 兼容与发布

- **线上已有数据**：amos 的 `build.machines` 三台 `active` 机器没有 `enrollment`、`reportedTrust` 字段，按 null 读，鉴权与路由照常（有测试用手写的旧 JSON 验证）；已有 `build.keystore`（离线导入或旧格式）没有生成者字段，照常读；`build.keystore.check` 不变。没有迁移。
- **发布顺序**：服务端先上线（CI），签名闸二进制人工升级（设计第 6 节第 1 步），中间可能隔几个小时。`localRole` 必填（自动化之前的签名闸已经带它）；`trust` 可缺——**迁移窗口内旧签名闸不上报信任**，它的检查结论与就绪照常更新，控制台显示为未上报（`reportedTrust` null）。旧构建机与旧签名闸的其它接口不受影响。
- **回滚**：回滚到本 ADR 之前的服务端时，由签名闸生成的 `build.keystore` 记录带新字段，旧代码严格解析会判 `KEYSTORE_RECORD_INVALID`（不就绪、不下发），需要重新前滚或导入。登记里只要有一台**从没注册过**的机器（`pending_enrollment`，或没注册就被吊销、令牌 sha256 为空串），旧代码的不变量校验就不过，整份 `build.machines` 读不出来（所有机器鉴权 503）——回滚前先确认没有这样的机器项，有就直接从 JSON 里删掉那几项。注册过的机器与手工登记的机器项旧代码照常读（`enrollment`、`reportedTrust` 是它不认识的键，登记用宽松解析，旧代码再写登记时会丢掉这些键）。
- **服务端回滚而签名闸已经升级**：旧服务端的 `decode` 拒绝未知字段，新签名闸的检查上报带着 `trust`，一律 400——检查结论与就绪不再更新（之后再导入或换密钥，就一直停在 `PRIMARY_SIGNER_NOT_CHECKED`）；`GET /v1/signer/peers` 与 `/v1/signer/keystore-generations/*` 在旧服务端上 404（`trust-peer`、`trust-builder --builder`、`trust-recovery` 做不了，生成请求也不再有）。**结论：服务端不能回滚到自动化之前的版本，除非签名闸先回滚**；而签名闸一旦在本机记录里写入了新的记录类型（`trust-peer`、`trust-recovery`、自动确认），旧签名闸二进制加载记录链时遇到不认识的记录类型直接报错（`unknown trust record type`），签名闸不可回滚——实际上就是只能前滚修复。

## 代价

- 服务端被攻破时多了三种后果（见上表加粗三行）：新租户首次信任、无意义换密钥（拒绝服务）、给新装机器下发篡改的安装包。
- 生成失败或过期的请求只能靠再次发起覆盖，没有单独的取消接口。
- 新机器注册多了一组不走机器令牌的公开接口，靠一次性注册码与按 IP 限速约束。
