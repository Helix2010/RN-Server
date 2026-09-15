# 设计：平台级备份与异地恢复

状态：Revised Draft（2026-09-15，经三路对抗性评审后重写）。目标是「amos 整机损毁后，能在另一台机器上把打包与发布能力完整恢复」。

初稿提出一套服务端自动备份子系统（管理端入口 + 定时任务 + 代理侧封装 + 独立 CLI + 下载接口）。**评审后撤回**，理由见 §8。本稿的主张是：**先修三个让恢复走不通的阻断，再用离线信封 + 一个数据库备份脚本覆盖全部三个灾难场景**——那覆盖面严格更大、代码量是零头，而且不引入初稿那些新的攻击面。

## 1. 灾难场景

| 场景 | 丢了什么 | 还剩什么 | 今天能不能恢复 |
|---|---|---|---|
| A 整机损毁 | `/etc/rn-foundation.env`、`/etc/rn-build-agent.env`、`agent-key`、本地仓库与缓存 | 数据库（远端）、对象存储（远端） | 能，但**无法证明**恢复成功（§4.3） |
| B 机器 + `agent-key` 一起丢 | 同上，且 `agent-key` 无副本 | 同上 | **不能**（§4.1、§4.2） |
| C 数据库损毁 | `app_configs` 等全部表 | 对象存储、机器 | **不能——今天没有任何数据库备份** |

**场景 C 是最大的洞，而初稿把它列在「本次不做」。** 已核实：数据库是**自建在另一台机器上**的（不是托管服务，没有自带的自动备份与时间点恢复），而全仓 `mysqldump` / `binlog` 的命中只有 `docs/OPERATIONS_AND_RELEASE.md:225-226` 的要求本身，**零实现**。机器坏了库还在；库没了全都没了。

**产物文件不在任何一档里。** APK 与 OTA 包在远端对象存储，amos 上没有对象存储服务，生产强制 https endpoint（`OPERATIONS_AND_RELEASE.md:195`）。所以本方案不备份产物：它们不是机密，加密封装没有安全收益只有成本。桶本身丢失是另一个故障模式，对应的工具是对象存储的 versioning 与生命周期策略。

## 2. 机密盘点

两个域：

- **服务端域**，由 `STORAGE_MASTER_KEY`（`/etc/rn-foundation.env`，0600 root）解锁：OTA 签名私钥（`app_configs.ota.signing`）、bootstrap 签名私钥、对象存储凭据、FCM 服务账号、扫链端点、以及 Android keystore 的**外层**。
- **打包机域**，由 `agent-key`（`<StateDir>/agent-key`，0600，服务端零副本）解锁：keystore 的**内层**，也就是真正的 Android 签名密钥。

补两条初稿漏掉的：

- `DEVICE_IDENTITY_HMAC_KEY` 未显式配置时**回落到 `STORAGE_MASTER_KEY`**（`internal/config/config.go:213-214`），它是 `device_clients.device_key_hash` 的 HMAC 密钥。主密钥泄露时设备再识别哈希从「不可逆」退化成「可枚举比对」。**生产 env 里应该显式设一个不同的值**，让这个回落永远不生效。
- **`BUILD_AGENT_TOKEN` 是第三把能通向签名密钥的钥匙。** `GET /v1/build-agent/keystore-checks` 返回各租户的 sealed keystore，而 `sealedBuildKeystoreFor`（`internal/api/build_keystore.go:61-79`）**在返回前替你剥掉了外层 secretbox**。所以「拿到 Android 签名密钥必须有主密钥」是错的：**`agent-key` + `BUILD_AGENT_TOKEN` 就够，不需要主密钥**。`deploy/build-agent/README.md:45` 写着那把令牌「能做的事只有领构建任务这一件」——这句话不准确，应当改掉。

`app_configs` 的 secretbox 密文 **AAD 绑了 `tenant_id`**（`ota_signing.go:145`、`build_keystore.go:40`、`release_storage.go:245`），而 `tenants.id` 是 `AUTO_INCREMENT`（`migrations.go:1013`）。**恢复时 `tenant_id` 必须逐字不变**——通过管理端重建租户必然拿到新 id，所有密文当场作废，没有兼容路径。

## 3. 三个阻断（不修，恢复走不通）

### 3.1 keystore 装不回去：上传校验只认 v1

`PUT /v1/admin/build-keystore` 要求 `KDF=="scrypt"` 且 `Salt!=""`（`internal/api/build_keystore.go:167-174`），而 `cmd/build-keystore` 产出的 v2 盒子这两个字段是 `omitempty` 的空值（`internal/buildkeystore/seal.go:57-67`）。CLI 却在成功输出里指示用户去 `curl -X PUT .../v1/admin/build-keystore`（`cmd/build-keystore/main.go:250-252`）——**一条已发布、面向用户、必然 400 的操作指引。**

唯一能把密钥装进库的路径是 `POST /build-keystore/generate`，而它每次生成**新**密钥。

**修法**：校验按版本分支。v2 要求 `Version==2 && Algorithm=="x25519-hkdf-sha256-aes256gcm" && EphemeralPublicKey!="" && RecipientKeyID!="" && Nonce!="" && Ciphertext!=""`，并拒绝 `Version==2 && KDF!=""` 这种混合体（防止绕分支）；同时校验 `RecipientKeyID` 等于当前登记的打包机公钥指纹。

### 3.2 打包机公钥的 base64 值，全系统没有任何出口

`build-keystore seal` 必须给 `--agent-key <X25519 公钥 base64>`（`cmd/build-keystore/main.go:175,198-202`），CLI 提示去 `GET /v1/admin/platform/build-agent/public-key`——但那个接口**只回指纹**（`internal/api/build_agent_key.go:141-155`）。代理启动也只打印指纹（`cmd/build-agent/main.go:57-59`），且 `build-agent` 没有任何子命令。

所以修好 3.1 之后场景 B 照样卡住，除非人肉进 MySQL 抠 JSON。

**修法**：`getBuildAgentKey` 的响应加 `publicKey`（公钥不是秘密，`recipient.go:41-44` 注释自己说的），并给 `build-agent` 加一个 `print-key` 子命令。两处都做——场景 B 里两边都可能是唯一可达的一侧。

### 3.3 恢复路径上的四颗地雷

| # | 地雷 | 证据 | 修法 |
|---|---|---|---|
| a | **恢复后 keystore 不会重验**。`pendingKeystoreChecks` 跳过 `check.Version == keystore.version` 的租户，而场景 A 里数据库一个字没动，所以一条都不下发。管理端显示的 ok 是**灾难前那台机器写的** | `internal/api/build_keystore_check.go:117-122` | 恢复流程里插一步 `DELETE FROM app_configs WHERE config_key='build.keystore.check'`（`acceptBuildAgentKey` 已经在用同一条语句，`build_agent_key.go:197-198`）。判据改成「每个已配密钥的租户都出现一条 `checkedAt` **晚于恢复时刻**的 ok」 |
| b | **主密钥探针是假的**。`GET /v1/admin/ota/signing-key` 只读明文证书字段，从不解密；换一把完全错误的主密钥它照样 200 | `ota_signing.go:113-127,260-278`；解密只在 `:130-143`，仅由 `otaSignerFor` 调用 | 换成 `POST /v1/admin/release-storage/test`（走 `storageClientForTenant` → `secrets.Decrypt`，`release_storage.go:221,245`），或直接拉一次带 `expo-expect-signature` 的 manifest |
| c | **迁移会 DROP 掉刚恢复的数据**。`finalMigration`（v5）无条件 `DROP TABLE IF EXISTS app_releases, audit_events, app_configs, admin_sessions, ...` | `internal/store/migrations.go:1006-1011` | 顺序写死：**跑迁移 → 停服务 → 写回数据 → 再起服务**。`schema_migrations` **不进备份包**（连它一起恢复进空库，所有版本都算"已应用"，一张表都不会建）。恢复工具启动先查 `SELECT COUNT(*) FROM schema_migrations`，为空就拒绝执行 |
| d | **迁移种子会撞主键**。`INSERT INTO app_configs(0,'release.platforms',...)` **无任何 NOT EXISTS 保护**；`resetRNAppLocalizationMigration` 再写一行 `(0,'languages')` | `migrations.go:1019-1021`、`:938` | 恢复一律用 `INSERT ... ON DUPLICATE KEY UPDATE`，**备份里的行赢**，并把 `version` 一起写回（否则管理端所有乐观锁写操作会 409） |

顺带一个既有 bug，恢复是最容易触发它的场景：`pendingKeystoreChecks` 的 `LIMIT 20` 在 SQL 里，而「已验过就跳过」的过滤在 Go 里（`build_keystore_check.go:96-122`）。前 20 个租户验完之后列表永久为空，第 21 个租户的 ok 永远等不到。修法是把过滤下推进 SQL。

## 4. 方案

### 4.1 离线信封（人工，一次性，覆盖场景 A 与 B）

`agent-key` 和 `STORAGE_MASTER_KEY` 都是**永不变化**的（`cmd/build-agent/agentkey.go:25-40` 只在文件缺失时生成）。变化的只有 `app_configs` 的内容——那由 §4.2 的数据库备份覆盖。所以这两样根本不需要自动化，抄一次就够。

**两个信封，两个人，不同物理位置。** 不是一个信封放两处——初稿把恢复私钥、主密钥、桶凭据放进同一个信封，那等于把「两个互不相交的域」在运维上合并回一个，密码学性质只剩纸面。

| 信封 | 内容 | 持有人 |
|---|---|---|
| 甲 | `STORAGE_MASTER_KEY`；`MYSQL_DSN`（或至少「库在哪、哪个账号」） | 点名 |
| 乙 | `agent-key`；逐租户的明文 `.p12` + `storePassword`；备份桶只读凭据 | 另一个人，点名 |

**点名，不是点数。** 无主的「两个物理位置」是「文档上有备份」最经典的生成方式。

关于逐租户 `.p12`：它只在 `generate` 的那一次响应里出现（`internal/api/build_keystore_generate.go:207-220`，代码注释自己写着「管理员现在不备份，以后就再也拿不到这个文件了」）。**今天的实际状态**：`deploy/amos/rotate-keystore-passphrase.sh:36-42` 的 `RESEAL` 表只有 anyfun（有明文），`REGENERATE` 表是 predict.kim（没有明文，但也没有已发布的包，可以直接重新生成）。**所以今天把 `agent-key` 抄进信封，场景 A 和 B 就全覆盖了。** 以后每新建一个租户密钥，当场存进信封——这是流程纪律，不是代码。

### 4.2 数据库备份脚本（覆盖场景 C）

照 `deploy/amos/rotate-keystore-passphrase.sh` 的形态写 `deploy/amos/backup-db.sh`，amos 上挂 cron：

```
mysqldump（全库） | gzip | openssl smime -encrypt -binary -aes-256-cbc -outform DER -out <file> <recovery-cert.pem>
→ 上传到备份桶
```

几条要点：

- **`openssl smime -encrypt` 同样满足那条硬约束**：收件人是一张公钥证书，脚本侧没有对应私钥，**产出者打不开自己的产出**。而且恢复时用的是标准 `openssl smime -decrypt`，不需要任何项目专有工具——初稿用 `buildkeystore.SealTo` 封装，却又在恢复流程里承诺「必要时能用标准工具手工解开」，这两条互相矛盾（那是 X25519 + 自定 info 串的 HKDF + 塞进自定 JSON，没有任何标准工具能打开它）。
- **全库 dump 是初稿那五张表的严格超集**，还顺带覆盖钱包、用户、设备、审计、构建任务——初稿场景 C 末尾自己承认这些「不在本方案范围」。
- **必须补进 dump 范围的两张表**（初稿的五张表清单漏了，都是明文小表，没有任何不装的理由）：
  - `chain_token_catalog` —— 缺了会让 bootstrap 对**每一个**客户端返回 **503**，不是降级是硬失败（`internal/api/server.go:1723-1726`，判据在 `tokens.go:147-152`）。迁移种子只覆盖预置的五条链，之后通过管理端加的链的原生币行、以及所有租户自定义代币，全部永久丢失——而「哪些链 enabled」随 `app_configs` 恢复回来了，于是配置说要七条链、目录里只有五条 → 全站 503。
  - `language_document` —— App 的文案是 bootstrap 里**现算**的（`internal/api/server.go:1820,1841` → `compiledMessages`，`localization.go:916-971`，回退链尽头是 `result[key] = key`）。启动种子只补 `tenant_id=0` 的 zh-CN / en-US，所以恢复后**租户级覆盖文案静默丢失**（显示平台默认而不是这个租户定制的，比显示键名更难发现），其它语言直接显示键名。另有一个反向发现：已发布的整包文案读的是**对象存储里的快照**，这条路没断——**直到有人点一次「发布」**，那一刻 `publishLocalization`（`localization.go:737`）会用残缺的表重新编译并覆盖桶里的好快照。
- **`schema_migrations` 排除**（§3.3c）。
- **恢复私钥**（对应那张证书）进信封甲，与主密钥同处——它们都是「解开服务端域」这一类。
- **保留策略交给桶的生命周期规则**，脚本不删。
- **验证方式就是演练**：把 dump 恢复进一个 scratch schema，见 §6。

### 4.3 恢复流程

#### 场景 A（整机损毁，托管完好）

```
0) 新机器：工具链（Android SDK / JDK17 / node+pnpm / git）
   + nginx / TLS 证书 / DNS 指向原域名
   —— 这一步不做，后面每一步都是 404：tenantResolver 要求域名 active、
      租户未软删、且 CURRENT_DATE 在 start_date..expiry_date 之间
      （internal/api/tenant_resolver.go:64-78）
1) 写回 /etc/rn-foundation.env（信封甲），STORAGE_MASTER_KEY 必须是原来那一把
2) 起 rn-server
3) 验证主密钥：POST /v1/admin/release-storage/test（会真的解密凭据）
   —— 不要用 GET /ota/signing-key，那个不解密（§3.3b）
4) 验证租户解析与配置可读：GET /v1/mobile/bootstrap 返回 200
   —— 它同时验证 Host→tenant、app_configs 可读、代币目录完整
5) 放回 agent-key（信封乙，0600），写 /etc/rn-build-agent.env
   —— 必须**显式写死 BUILD_AGENT_STATE_DIR**。它默认从 workspace 推导
      （cmd/build-agent/config.go:89-92），路径差一点就找不到恢复的私钥，
      代理会静默生成一把新的（agentkey.go:42-55），而日志里区分不出来
   —— 先放私钥再起 agent：代理用 O_EXCL 写私钥（agentkey.go:47）
6) DELETE FROM app_configs WHERE config_key='build.keystore.check'
   —— 不删这一步，第 7 步看的是灾难前的旧记录（§3.3a）
7) 起 build-agent，等每个已配密钥的租户出现 checkedAt 晚于恢复时刻的 ok
8) 人工核对打包机公钥指纹等于离线记录的那一个
   —— registerBuildAgentKey 对无记录的首次登记零确认直接固定
      （build_agent_key.go:97-107）
9) 跑通一条真实 **APK** 构建并入库，才算恢复完成
```

#### 场景 B（连 `agent-key` 一起丢）

已有的 v2 盒子全部永久打不开，逐租户重建：

```
1) 新机器起 build-agent，生成新私钥、登记新公钥
   → 平台管理员核对指纹后 accept
   （accept 会 DELETE 全部 check 行，所以重验会真的发生）
2) 取新公钥的 base64 —— 依赖 §3.2 的修复
3) 用信封乙里的明文 .p12 + storePassword，本地跑 build-keystore seal 封给新公钥
4) PUT /v1/admin/build-keystore —— 依赖 §3.1 的修复
5) 代理重验，全 ok
```

**没有离线 `.p12` 的租户在这一档里无法恢复。** 换签名证书 = Android 认作另一个 App，已装用户全部升不上去。今天只有 anyfun 有明文（§4.1）。

#### 场景 C（数据库损毁）

```
1) 空库跑迁移（建表）
2) 停 rn-server
3) openssl smime -decrypt 解开 dump，恢复（不含 schema_migrations，一律 upsert）
4) 起 rn-server，之后同场景 A 第 3 步
```

**顺序不能换。** 先恢复数据再跑迁移，第一次启动会把刚写回去的 `app_configs` 和 `app_releases` 整表删掉（§3.3c）。

#### 一条运维约束

**恢复到新机器等于永久扩大签名密钥的信任边界。** 旧机器若并非物理损毁，必须按已泄露处理并销毁介质。这条与 `build-concurrency-2026-09-15.md` §8 同源。

## 5. 控制台：打包材料备份

### 5.1 和整库备份的分工

两个备份，两套机制，受众不同：

| | 整库备份（§4.2） | 打包材料备份（本节） |
|---|---|---|
| 产出者 | amos 上的 cron 脚本 | rn-server（控制台按钮 / 定时） |
| 范围 | 全库 | 打包与发布所需的那几张表，**排除图标 blob** |
| 体积 | 几十 MB 起 | 几百 KB |
| 用途 | 灾难恢复底座，覆盖场景 C | 可下载、可手工归档、可放进离线信封 |
| 控制台 | 不进 | 有配置、状态、按钮、下载 |

**后者不是前者的替代，也不是纯粹的重复。** 它填的是离线信封的一个真实缺口：信封里的内容会**随新租户、新密钥漂移**，而「每建一个租户密钥就去更新信封」是纯流程纪律，没人会记得。一个小到能下载、能随手归档的包正好覆盖这段漂移。但要清楚：**必须先有整库备份**，只有这个包不构成灾难恢复。

范围（对照 §4.2，去掉图标、加上两张必需表）：

`app_configs`（**排除 `build.icons` 那些行**）、`tenants`、`tenant_domain`、`app_releases`、`ota_releases`、`chain_token_catalog`、`language_document`。不含 `schema_migrations`（§3.3c）。

排除 `build.icons` 的理由：图标不是机密（`internal/api/build_icons.go:31-33` 自己说的，它原样编进每个 APK），丢了重传即可，而它单租户就能占 32MB（§8）。整库备份里有它。

### 5.2 产出

服务端内部产出 `tar.gz`（Go 代码，不 shell out），外层用现有的 X25519 原语封给**恢复公钥**。

**恢复公钥放 env（`BACKUP_RECOVERY_RECIPIENT`），与 `STORAGE_MASTER_KEY` 同一个文件、同一种保护。管理端只读显示指纹，不能写。** 它写进 `app_configs` 就意味着任何能写配置的路径都能改收件人。

`manifest.json` 必须有：格式版本、**实例 id + 序号 + 生成时间**（同时进 AEAD 的 AAD，见 §5.5）、每个成员的 sha256、逐租户的 keystore 校验**三态**（`ok` / `failed` / `pending`——`pending` 和 `failed` 一样危险，它意味着从来没验过）、`build.agent.recipient` 的当前指纹、以及外层的 `RecipientKeyID`。

**fail-closed**：`BACKUP_RECOVERY_RECIPIENT` 缺失或不是合法 X25519 公钥（用现成的 `Recipient.Fingerprint()` 返回 `""` 做判据，`internal/buildkeystore/recipient.go:50-57`）时，**拒绝产出**并说清缺什么，而不是产出一个少了东西却看起来正常的包。那种失败只会在灾难当天暴露。

### 5.3 两套凭据，职责分离

| 凭据 | 存放 | 权限 | 用途 |
|---|---|---|---|
| `platform.backup.storage` | `app_configs(0,...)`，管理端可配 | **只给 `PutObject`** | 产出备份时上传 |
| `BACKUP_READ_ACCESS_KEY_ID` / `..._SECRET` | **env**，不进数据库 | 只给 `GetObject` | 下载接口 |

**为什么分开**：写凭据在 `app_configs` 里，因而随备份包一起走；读凭据在 env 里，不进包。一个只拿到数据库或只拿到备份包的攻击者，**读不到桶**。

**要诚实说明它挡不住什么**：服务端 RCE 能读 env，所以它仍然能拉走全部历史备份。这是「要控制台下载按钮」必然付的代价——没有任何办法让服务端既能提供下载又不能自己下载。缓解是：包**封给恢复公钥**，服务端没有那把私钥，所以拉走的是**打不开的密文**；下载逐次记审计；服务端**没有 Delete 权限**，销毁不了备份。

**「测试连接」不能用现成的 `objectstore.Test()`**：它 Put 一个**固定键** `.rn-foundation-storage-check` 然后 Head（`internal/objectstore/s3.go:319-336`）——既要求 Get/Head 权限（和只给 Put 冲突），固定键在开了 versioning 的桶上还会永久留存。备份桶要单独写一个只 Put 到 `<objectPrefix>/.probe/<随机>` 的版本。

### 5.4 接口

全部挂 `platform.*`（`requirePlatformAdmin()`，按 `PLATFORM_ADMIN_USERNAMES` 白名单；列表为空时整组 403，fail-closed）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET / PUT | `/platform/backup/storage` | 备份桶配置，凭据只回 hint |
| POST | `/platform/backup/storage/test` | 只 Put 到随机探针键（§5.3） |
| GET | `/platform/backup` | 状态 + 恢复公钥指纹 + 最近 N 次清单 |
| POST | `/platform/backup/run` | 立即备份，返回序号与 sha256 |
| GET | `/platform/backup/download/:seq` | **按序号**下载 |

两条硬性约束：

- **清单从 `platform.backup.state` 的本地记录读，不 List 桶。** 服务端不需要 `ListBucket`，少一项权限。
- **下载只接受序号，不接受对象键。** 服务端用 `objectPrefix` + 记录里的键自己拼。初稿写的 `:key` 在 gin 默认设置下只匹配一个路径段（对象键必然含 `/`），那条路由写出来是 404；而「修好」的自然写法 `*key` 会把同桶任意对象读打开——`s3Client.Get` 把 key 原样交给 `GetObject`，没有任何前缀约束（`internal/objectstore/s3.go:178-184`）。
- **下载只认会话 cookie，不认 `x-admin-key`。** 备份下载不该是自动化能力，而 `x-admin-key` 的 actor 是一个固定值（`ADMIN_API_ACTOR`，默认 `api-key-automation`）——只要有人把它写进 `PLATFORM_ADMIN_USERNAMES`，一把长期有效的 API key 就能拉备份。

### 5.5 真实性：光加密不够

`SealTo` 是匿名 sealed box，没有发送方认证（`internal/buildkeystore/recipient.go:96-146`）。**知道恢复公钥的人**（公钥不是秘密，还要显示在管理端上）加上任意一条往桶里写对象的路径，就能伪造一个密码学上无法与真备份区分的包。恢复流程会把它写进新系统的配置根——`tenant_domain`（Host→租户映射）和 `build.android.identity.apiBaseUrl`（重建出来的 App 此后跟谁说话）都在里面，而 `apiBaseUrl` 只校验是个 https origin（`internal/api/build_config.go:85-98`）。

两条一起做：

1. **身份进 AAD**。`SealTo` 现在只把临时公钥放进 AAD（`recipient.go:131`）。把 `(实例 id, 序号, 生成时间)` 也放进去，伪造者就无法复用同一条身份。
2. **sha256 在包外。** 每次产出把 sealed 对象自身的 sha256 写进 `platform.backup.state` **和** `audit_events`，控制台显示它；恢复工具强制 `--expect-sha256`，值来自控制台或审计，**不来自包本身**。`manifest.json` 里的摘要只覆盖内层成员，对「这是哪一份备份」零贡献。

顺带：`audit_events` 不在打包材料备份的范围里，所以「曾经做过哪些备份」这段历史要同时写进 `platform.backup.state`（那一行在包里）。

### 5.6 定时

`cmd/server` 起一个 ticker，抄 push dispatcher 的形态（`cmd/server/main.go:88` 的 `go dispatcher.Run(workerCtx)`）。

- 跨实例互斥用 `platform.backup.state` 的 `version` 做 CAS。**注意现成的 `upsertAppConfig` 绑死在 `*gin.Context` 上**（`internal/api/build_keystore_generate.go:225-231`，内部用 `tenantID(c)` / `actor(c)` / `c.Request.Context()`），定时任务里复用不了，要另写一个 ctx 版本。今天是单实例部署，但不写这一条，将来加实例时会静默地每天备份 N 份。
- **服务端永不删除备份**，保留交给桶的生命周期规则。一个被拿下的服务端销毁不了你的备份。
- 连续失败要有声音：写 `audit_events`，并在页面上把「上次成功：N 天前」做成醒目状态。平台没有告警基建，这是最低限度。

### 5.7 管理端页面

放**平台维护**（`RN-Admin/src/modules/build-config/plugin.ts:68-75`，今天只有「管理员口令」一项）。

顺带订正初稿写错的事实：打包机公钥的 UI 在 `keystore-section.tsx`、由 `android-build-page.tsx:283` 渲染，属于**租户级**的「打包与签名」页——而后端那条路由是平台级的（`internal/api/server.go:177-178`）。这是个独立的 UI 归位小修，可以和本节一起做。

页面元素：

- 备份桶配置表单 + 「测试连接」
- 恢复公钥指纹（**只读**，来自 env），旁边一句「核对它和你手上那把离线私钥是同一对」
- 上次成功时间 / 序号 / sha256、连续失败计数
- 「立即备份」按钮
- 最近 N 次清单 + 逐条下载
- 打包机公钥（`publicKey` 字段，§3.2 加上之后）

**页面上必须写死两段文字**，不能只写在文档里：

1. **备份桶的只读凭据必须离线抄一份。** 凭据本身在备份包里，机器全丢时你需要凭据才能取到那个装着凭据的包——这是循环依赖，靠人记住不行。
2. **信封甲 / 乙的内容清单**（§4.1），以及「每新建一个租户签名密钥，当场把 `.p12` 和口令存进信封乙」。

全部文案、`aria-label`、`title`、placeholder 要过 `src/core/admin-i18n.tsx` 并双语，新页面配 `.spec.tsx`（`RN-Admin/docs/ADMIN_ENGINEERING_STANDARD.md:206-221`）。

## 6. 演练

没有演练的备份不是备份。而且判据要选对：

- **初稿的判据（跑通一条 OTA 构建）验不到任何被备份的东西。** OTA 构建不需要签名密钥（`cmd/build-agent/ota.go:13-16`，不调 `unsealKeystore`），也不碰 OTA 签名私钥（那把私钥是下发 manifest 那一刻才解的，`ota_signing.go:205-222`）。
- **正确的判据**：① 跑通一条真实 **APK** 构建并入库（强制解 keystore → 用 `agent-key` 开 v2 盒子 → 入库还要过 `signerSha256` 比对）；② 带 `expo-expect-signature` 头拉一次 manifest 并验签（这才验到 OTA 签名私钥）；③ 数据库 dump 恢复进 scratch schema 并通过 §4.3 场景 A 第 3、4 步的两个探针。
- **频率**：数据库 dump 的恢复验证跟着每次备份做（恢复进 scratch schema，脚本里就能做）；整机演练每季度一次。**演练通过之前，不要对外说「已经有备份了」。**

## 7. 落地顺序

1. **§3.1 + §3.2 两个阻断**。独立收益，不依赖本方案其余部分；不修则场景 B 无解。
2. **§4.1 离线信封**（今天就能做完，覆盖场景 A 与 B 的全部），写进 `deploy/amos/README.md` 里 `agent-key` 那段旁边，**点名责任人**。
3. **§4.2 `deploy/amos/backup-db.sh` + cron**（覆盖场景 C，这是今天最大的洞）。**必须排在 §5 之前**——只有打包材料备份不构成灾难恢复，先上控制台会给人「已经有备份了」的错觉。
4. **§3.3 四颗地雷 + LIMIT 20**（大部分是文档，两处是小代码改动）。
5. **§5 控制台**，内部顺序不能换：
   1. §5.3 的两套凭据（决定配置形状，做在后面就是返工）
   2. §5.5 的真实性（决定 manifest 结构与恢复工具入口校验，后补会让已产出的包全部作废）
   3. §5.2 产出 + §5.4 的 `run` 与 `download`
   4. §5.7 页面
   5. §5.6 定时（最后上，先用手动按钮跑几天）
6. **§6 一次真实演练**，包含那条负面用例。

### 7.1 演练的负面用例

**给恢复工具喂一个伪造包，它必须拒绝。** 做法：用恢复**公钥**自己封一个内容任意的包，放进桶里，然后按正常流程走恢复——它应该在 `--expect-sha256` 这一步停住。这条通不过，说明 §5.5 还没真正生效。

## 8. 初稿被撤回的部分

初稿提出：管理端配置入口 + 每日定时任务 + **代理侧把 `agent-key` 封给恢复公钥上报** + 服务端产出加密包上传 + **清单与按对象键下载的接口** + 独立 `cmd/rn-backup`。

其中**管理端入口、定时、产出与上传、按序号下载**保留，见 §5——但要满足评审给出的前置条件（两套凭据、真实性、fail-closed、排除图标 blob）。

**撤回的是代理侧封装 `agent-key` 这一整块**，以及初稿据以论证它安全的那些判断。记在这里是为了让下一个想到这个主意的人不用再走一遍。

**它自动化的是一个永不变化的文件。** `agent-key` 只在缺失时生成、不轮换、不过期。而信封里本来就要放主密钥和桶凭据——**多写一行的边际成本是零**。为了省掉这一行，初稿新增了：代理 env 变量、一条新接口、三个新配置键、一对恢复密钥及其轮换流程、`SealBytes`、以及「代理必须忽略服务端下发收件人」的专门用例。

**它保护的东西价值更低。** `agent-key` 打开的盒子里装的就是 `.p12` + 口令。只要明文 `.p12` 在信封里，丢 `agent-key` 的代价是逐租户重封（今天 1–2 个租户，约十五分钟手工活），不是能力丧失。

**它与整库备份严格重叠。** 初稿备的五张表是 `mysqldump` 的真子集。整库备份一旦做了，它 100% 被覆盖，只剩下「第二套要跑、要监控、要演练、要维护凭据的东西」。

**包不是 KB 级，是几十 MB。** 初稿在 §4.2 写「可能几十 MB」、在 §7 和 §8 写「KB 级」，自相矛盾；真实答案是后者错——`build.icons` 把启动图标以 base64 存在 `app_configs` 里，单张上限 6 MiB、四个槽位，代码注释自己算过「四张满打满算 24MB，base64 之后 32MB」，**每租户**（`internal/api/build_icons.go:48-57`；anyfun 线上那两张就是 2048×2048 / 2.6MB）。这拆掉三条依赖「KB 级」的结论：「永不删除堆着不心疼」、「代理返回」（经 API 进程转发几十 MB，而这个进程同机跑 wallet 后端）、以及 `aead.Seal(nil, ...)` 一次性全量进内存（50 MB 明文峰值约 280 MB 常驻，因为还要再 base64 一遍再 JSON 序列化一遍）。

**它引入了三个初稿没有推理到的新问题**：

1. **备份包只有机密性、没有真实性。** `SealTo` 是匿名 sealed box，没有发送方认证（`internal/buildkeystore/recipient.go:96-146`）。**知道恢复公钥的人**（公钥不是秘密，还要显示在管理端上）加上任意一条往桶里写对象的路径，就能伪造一个密码学上无法与真备份区分的包。灾难当天它会被写进一套全新生产系统的配置根——`tenant_domain`（Host→租户映射）和 `build.android.identity.apiBaseUrl`（重建出来的 App 此后跟谁说话）都在里面，而 `apiBaseUrl` 只校验是个 https origin（`build_config.go:85-98`）。初稿整章只在推理「谁能解开」，没有推理「谁能写进去」。
2. **服务端因此获得对全部历史状态的读权限。** §8 的清单与下载接口要求服务端同时有 `ListBucket` 和 `GetObject`；一次 rn-server RCE 就能读 `/etc/rn-foundation.env` 拿主密钥 → 解桶凭据 → 拉走每一份历史备份。初稿写「服务端永不删除备份——一个被拿下的服务端销毁不了你的备份」，这话对**销毁**成立，但同一套凭据让它能**读**：今天一次 RCE 拿到的是「当前数据库」，改完之后拿到的是「这套系统有史以来每一天的完整状态」。而且因为永不删除，**任何一次密钥轮换都不会生效**——昨天的备份里那把旧私钥连同能解它的主密钥依然在桶里。
3. **§4.4 那条「两项独立机密都失效才泄露」是错的。** `agent-key`（从备份里解出）**+ `BUILD_AGENT_TOKEN`** 就能拿到全部租户的 Android 签名密钥明文，**不需要主密钥**——因为 `/keystore-checks` 在返回前替你剥掉了外层 secretbox（§2）。初稿那套「两个域」的论证在这条路径上不成立。

**而它声称堵死的那条攻击其实没堵死。** 初稿 §4.3 把恢复公钥固定在代理 env 里，论证是「服务端改不了收件人」。但服务端 RCE 根本不需要改收件人：`build_jobs.git_ref` 是从库里读出来下发的（`build_jobs.go:713` → `buildJobView` 的 `"gitRef"`，`:111`），代理拿到就直接 `git worktree add --detach <worktree> <job.GitRef>`，**对它没有任何校验**（`cmd/build-agent/build.go:130`；同一个函数对 `TenantDirectory` 是校验了的，`:121-123`），而仓库是 `--mirror` 克隆、上游每个分支和 tag 都在本地可达。改掉 ref → 代理以 `builder` 身份执行那个提交的代码 → 直接读走 `agent-key`（属主就是 `builder`）。**「服务端能选检出哪个提交」就等于「服务端能在打包机上执行命令」**，只是叫构建。这条应当单独修：**把 main 的固定挪到代理侧**，代理忽略 `job.GitRef`、硬编码只从 `refs/heads/main` 检出，服务端下发的 ref 只用于日志核对。这和 `tenantfile.go` 顶部「两端分属不同信任域，各自把住自己那一侧」是同一条原则，只是这一项漏了。

### 8.1 控制台版本据此加的护栏

§5 保留了控制台，但每一条都对应上面的一个发现：

| 发现 | §5 里的护栏 |
|---|---|
| 备份可伪造 | §5.5：身份进 AAD + sha256 在包外 + 恢复工具 `--expect-sha256` |
| 服务端能读全部历史 | §5.3：写凭据只给 Put 且在库里，读凭据只给 Get 且在 env 里；包封给恢复公钥，拉走的是打不开的密文；服务端无 Delete |
| 按对象键下载 = 任意对象读 | §5.4：只接受序号，服务端自己拼键；清单从本地状态读，不 List 桶 |
| 包是几十 MB | §5.1：排除 `build.icons`，回到几百 KB |
| 产出一个缺东西却看起来正常的包 | §5.2：恢复公钥缺失或非法就拒绝产出 |
| 恢复公钥轮换会产出分裂包 | §5.2：`RecipientKeyID` 进 manifest 与状态行 |
| 解包路径遍历 | §5 之外：恢复工具必须校验每个成员名（禁绝对路径、禁 `..`、禁符号链接、白名单），手工路径写 `tar --no-absolute-names -C <空目录>` |

**代理侧封装仍然不做。** `agent-key` 永不变化，抄进信封乙一次就够（§4.1、§8 开头）；而上面那条 `git_ref` 的缝说明「把收件人固定在代理 env」这个保护本来就绕得开。控制台备份的范围里**不含 `agent-key`**——它只备份数据库里的东西。

## 9. 顺带修的既有问题

这些不是本方案引入的，但恢复流程依赖它们，应当同期修：

- `acceptBuildAgentKey` 的 `DELETE FROM app_configs WHERE config_key=?` **缺租户维度**（`build_agent_key.go:197-198`），一次接受清空全部租户的校验结果。
- `pendingKeystoreChecks` 的 `LIMIT 20` 语义（§3.3 末）。
- `putTo` 把 `x-build-agent-token` 附加到**服务端指定的任意 URL** 上并 PUT 整个产物（`cmd/build-agent/client.go:283-295`）——服务端 RCE 可以把产物导向外部主机并顺带泄露令牌，而 §2 显示那把令牌的价值远高于 README 的说法。
- `deploy/build-agent/rn-build-agent.env.example` 没有 `BUILD_AGENT_STATE_DIR` 这一项、也没提 `agent-key`，还停留在 `BUILD_KEYSTORE_PASSPHRASE` 时代。

## 10. 已知遗留

- **`STORAGE_MASTER_KEY` 无轮换**（`OPERATIONS_AND_RELEASE.md:311` 要求「轮换前必须实现逐版本解密、重加密和核对」，即尚未实现）。本方案不解决。
- **产物归档**。若将来要防桶本身丢失，应是独立的、**不加密**的归档任务，选择规则按「还在服务中」而不是固定条数：每租户每平台当前 `active` 的 APK + 上一个，每条运行时线的 `active`/`canary` 修订 + 前一个。
- **告警**。平台没有告警基建；备份连续失败、演练过期目前只能靠人去看。
- **`app_installations` 的吊销状态**：整库 dump 覆盖了它，但如果将来退回部分表备份，要知道不恢复这张表会让 `revoked` 的安装回到 `active`（`installations.go:31`），那是安全状态倒退。
