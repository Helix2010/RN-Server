# 设计：平台级备份与异地恢复

状态：Revised Draft v3（2026-09-15，经两轮共六路对抗性评审后重写）。目标是「amos 整机损毁后，能在另一台机器上把打包与发布能力完整恢复」。

v1 提出一套服务端自动备份子系统，评审后撤回其中的代理侧封装部分。v2 补回控制台并加了护栏，第二轮评审推翻了其中几条关键判断。本稿的改动集中在四处，全部有实测依据：**恢复密钥统一成一套**（v2 有两套互不相通的）、**全库 dump 必须包含 `schema_migrations`**（v2 的规则会让恢复成果被下一次部署删光）、**换 `openssl cms` 并补上工具链**（amos 上根本没有 `mysqldump`）、**把 `git_ref` 那条提出来单独立项**（v2 把系统里最严重的发现埋在历史记录一节里，没有任何一步会去执行它）。

评审记录见 §12。

## 1. 灾难场景与目标

| 场景 | 丢了什么 | 还剩什么 | 今天能不能恢复 |
|---|---|---|---|
| A 整机损毁 | `/etc/rn-foundation.env`、`/etc/rn-build-agent.env`、`agent-key`、本地仓库与缓存 | 数据库（远端）、对象存储（远端） | 能，但**无法证明**恢复成功（§3.3a） |
| B 机器 + `agent-key` 一起丢 | 同上，且 `agent-key` 无副本 | 同上 | **不能**（§3.1、§3.2） |
| C 数据库损毁 | 全部表 | 对象存储、机器 | **不能——今天没有任何数据库备份** |

**场景 C 是最大的洞。** 已实测：数据库**不在 amos 上**（amos 无 mysqld、不监听 3306），是自建在另一台机器上的，不是托管服务；而全仓 `mysqldump` / `binlog` 的命中只有 `docs/OPERATIONS_AND_RELEASE.md:225-226` 的要求本身，**零实现**。机器坏了库还在；库没了全都没了。

**产物文件不在任何一档里。** APK 与 OTA 包在远端对象存储，amos 上没有对象存储服务，生产强制 https endpoint（`OPERATIONS_AND_RELEASE.md:195`）。它们也不是机密，加密封装没有安全收益只有成本。桶本身丢失是另一个故障模式，对应的工具是对象存储的 versioning 与生命周期策略。

## 2. 机密盘点

两个域：

- **服务端域**，由 `STORAGE_MASTER_KEY`（`/etc/rn-foundation.env`，0600 root）解锁：OTA 签名私钥（`app_configs.ota.signing`）、bootstrap 签名私钥、对象存储凭据、FCM 服务账号、扫链端点、以及 Android keystore 的**外层**。
- **打包机域**，由 `agent-key`（`<StateDir>/agent-key`，0600，服务端零副本）解锁：keystore 的**内层**，也就是真正的 Android 签名密钥。

三条补充：

- `DEVICE_IDENTITY_HMAC_KEY` 未显式配置时**回落到 `STORAGE_MASTER_KEY`**（`internal/config/config.go:213-214`），它是 `device_clients.device_key_hash` 的 HMAC 密钥。主密钥泄露时设备再识别哈希从「不可逆」退化成「可枚举比对」。**生产 env 里应该显式设一个不同的值**——那样它就成为第四把永不变化的机密，必须进信封（§5）。
- **`BUILD_AGENT_TOKEN` 是第三把能通向签名密钥的钥匙。** `GET /v1/build-agent/keystore-checks` 返回各租户的 sealed keystore，而 `sealedBuildKeystoreFor`（`internal/api/build_keystore.go:61-79`）**在返回前替你剥掉了外层 secretbox**。所以「拿到 Android 签名密钥必须有主密钥」是错的：**`agent-key` + `BUILD_AGENT_TOKEN` 就够**。`deploy/build-agent/README.md:45` 写着那把令牌「能做的事只有领构建任务这一件」——这句话不准确，应当改掉。
- `app_configs` 的 secretbox 密文 **AAD 绑了 `tenant_id`**（`ota_signing.go:145`、`build_keystore.go:40`、`release_storage.go:245`），而 `tenants.id` 是 `AUTO_INCREMENT`（`migrations.go:1013`）。**恢复时 `tenant_id` 必须逐字不变**——通过管理端重建租户必然拿到新 id，所有密文当场作废，没有兼容路径。mysqldump 天然满足这一点（实测 `INSERT INTO tenants VALUES (100000001,...)`，`AUTO_INCREMENT=` 也保留）。

## 3. 三个阻断（不修，恢复走不通）

### 3.1 keystore 装不回去：上传校验只认 v1

`PUT /v1/admin/build-keystore` 要求 `KDF=="scrypt"` 且 `Salt!=""`（`internal/api/build_keystore.go:167-174`），而 `cmd/build-keystore` 产出的 v2 盒子这两个字段是 `omitempty` 的空值（`internal/buildkeystore/seal.go:57-67`）。CLI 却在失败提示里指示用户去上传（`cmd/build-keystore/main.go:196-201`）——**一条已发布、面向用户、必然 400 的操作指引。**

唯一能把密钥装进库的路径是 `POST /build-keystore/generate`，而它每次生成**新**密钥。

**修法**：校验按版本分支。v2 要求 `Version==2 && Algorithm=="x25519-hkdf-sha256-aes256gcm" && EphemeralPublicKey!="" && RecipientKeyID!="" && Nonce!="" && Ciphertext!=""`，并拒绝 `Version==2 && KDF!=""` 这种混合体（防止绕分支）；同时校验 `RecipientKeyID` 等于当前登记的打包机公钥指纹。

### 3.2 打包机公钥的 base64 值，全系统没有任何出口

`build-keystore seal` 必须给 `--agent-key <X25519 公钥 base64>`（`cmd/build-keystore/main.go:175,198-202`），但 `GET /v1/admin/platform/build-agent/public-key` **只回指纹**（`internal/api/build_agent_key.go:141-155`）。代理启动也只打印指纹（`cmd/build-agent/main.go:57-59`），且 `build-agent` 没有任何子命令。

CLI 的屏幕提示还错了第二次：它指向「平台维护 → 打包机公钥」，而那个 UI 实际在**租户级**的「打包与签名」页（§7.6）。

**修法**：`getBuildAgentKey` 的响应加 `publicKey`（公钥不是秘密，`recipient.go:41-44` 注释自己说的）；给 `build-agent` 加 `print-key` 子命令；订正 CLI 的提示文字。三处都要——场景 B 里每一侧都可能是唯一可达的。

### 3.3 恢复路径上的地雷

| # | 地雷 | 证据 | 修法 |
|---|---|---|---|
| a | **恢复后 keystore 不会重验**。`pendingKeystoreChecks` 跳过 `check.Version == keystore.version` 的租户，而场景 A 里数据库一个字没动，所以一条都不下发。管理端显示的 ok 是**灾难前那台机器写的** | `internal/api/build_keystore_check.go:95-122` | 恢复流程里插一步 `DELETE FROM app_configs WHERE config_key='build.keystore.check'`（`acceptBuildAgentKey` 已经在用同一条语句，`build_agent_key.go:197-198`）。判据改成「每个已配密钥的租户都出现一条 `checkedAt` **晚于恢复时刻**的 ok」，恢复时刻用恢复前记下的 `date -u` |
| b | **主密钥探针是假的**。`GET /v1/admin/ota/signing-key` 只读明文证书字段，从不解密；换一把完全错误的主密钥它照样 200 | `ota_signing.go:113-127,260-278`；解密只在 `:129-143`，仅由 `otaSignerFor` 调用 | 换成 `POST /v1/admin/release-storage/test`（走 `storageClientForTenant` → `secrets.Decrypt`，`release_storage.go:221,245`） |
| c | **迁移会 DROP 掉数据**。`finalMigration`（v5）无条件 `DROP TABLE IF EXISTS app_releases, audit_events, app_configs, admin_sessions, ...` | `internal/store/migrations.go:1006-1011` | **触发路径不是启动，是部署**：迁移只由 `rn-foundation-server migrate` 子命令跑（`cmd/server/main.go:46-53`），而 `deploy/amos/rn-foundation-apply:76` **每一次 push 到 main 都会 `systemctl start rn-foundation-migrate`**。见 §6.4 的处理 |
| d | **迁移种子会撞主键**。`INSERT INTO app_configs(0,'release.platforms',...)` **无 NOT EXISTS 保护**（`:1019`、`:1020` 有，`:1021` 没有）；`resetRNAppLocalizationMigration` 再写一行 `(0,'languages')` | `migrations.go:1021`、`:938` | 只影响 §7 的数据级恢复（见 §7.3）。全库 dump 不受影响，它自带 DROP+CREATE |

既有 bug，恢复最容易触发：`pendingKeystoreChecks` 的 `LIMIT 20` 作用在 **keystore 行按 `updated_at` 倒序**上（`build_keystore_check.go:95-101`），而「已验过就跳过」的过滤在 Go 里。真实行为是「只有最近更新的 20 把密钥有机会被验」——排在第 21 位之后的租户永远拿不到校验，除非它那行 keystore 被重写。修法是把过滤下推进 SQL。

## 4. 恢复密钥：一套，不是两套

v2 有两套互不相通的恢复密钥（脚本用 X.509/RSA、控制台用 X25519），而 X25519 那把私钥没有任何信封收留它——灾难当天会发现控制台那份备份没人能解。本稿统一成**一对 RSA 恢复密钥**：

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 7300 \
  -keyout recovery.key -out recovery.pem -subj "/CN=rn-foundation-backup-recovery"
openssl x509 -in recovery.pem -noout -fingerprint -sha256    # 指纹抄进信封
```

- `recovery.pem`（公钥证书）：进仓库 `deploy/amos/`、进 amos 的 `/etc/rn-foundation-backup/`、指纹显示在控制台上。
- `recovery.key`（私钥）：**进信封乙**，和 `agent-key` 同处，**绝不与 `STORAGE_MASTER_KEY` 同封**（§5）。

实测要点：

- **加密端完全不检查证书有效期**，过期证书照样能加密。所以「证书过期导致备份中断」不存在；真正的风险是反过来——换掉或过期都没有任何信号。**脚本与服务端都必须核对证书指纹等于硬编码的那一个**，否则「谁能换掉收件人」这条攻击在脚本版本上完全没设防。
- **PKCS#7/CMS 只支持 RSA**。P-256 证书直接失败（`encryption not supported for this key type`），X25519 连自签证书都签不出来。这也是统一成 RSA 的原因。
- `openssl cms -decrypt` 单收件人时只要私钥，不需要 `-recip`。信封里两个都放（多收件人时 `-recip` 必需）。

**`buildkeystore.SealTo` 一个字都不动。** v2 提议给它的 AAD 加备份身份——那是现役函数，唯一的服务端调用点就是封租户签名密钥（`build_keystore_generate.go:129`），改它的 AAD 会让库里已有的 v2 盒子全部打不开，而今天只有 anyfun 有离线明文 `.p12`。而且那条护栏本来就是空的：`SealTo` 是匿名 sealed box，谁知道收件人公钥谁就能封、也就能自己选 AAD，而实例 id / 序号 / 生成时间全是控制台上公开显示的值。

## 5. 离线信封（人工，一次性）

`agent-key`、`STORAGE_MASTER_KEY`、`recovery.key` 都是**永不变化**的（`cmd/build-agent/agentkey.go:25-40` 只在文件缺失时生成）。变化的只有数据库内容——那由 §6 覆盖。所以这些根本不需要自动化，抄一次就够。

**两个信封，两个人，不同物理位置。点名，不是点数。** 无主的「两个物理位置」是「文档上有备份」最经典的生成方式。

| 信封 | 内容 |
|---|---|
| **甲** | `STORAGE_MASTER_KEY`；`DEVICE_IDENTITY_HMAC_KEY`（若已显式配置）；`MYSQL_DSN`；备份签名的**验证证书**（§6.3）；`recovery.pem` 的 sha256 指纹 |
| **乙** | `recovery.key`（恢复私钥）；`agent-key`；逐租户的明文 `.p12` + `storePassword`；`BUILD_AGENT_TOKEN`；备份桶的读写凭据 |

**分法的原则**：甲是「解开服务端域」那一类，乙是「解开备份与打包机域」那一类。任何一个信封单独拿到都不足以还原全部机密；两个合起来才是全部，这正是要分两人的原因。

`recovery.key` 必须在乙、不能在甲：否则「主密钥 + 一份任何人都被鼓励随手归档的备份包」= 全平台服务端域机密的离线明文，不需要网络、不需要数据库、不需要那台机器还活着。

关于逐租户 `.p12`：它只在 `generate` 的那一次响应里出现（`build_keystore_generate.go:207-220`，代码注释自己写着「管理员现在不备份，以后就再也拿不到这个文件了」）。**今天的实际状态**：`deploy/amos/rotate-keystore-passphrase.sh:35-40` 的 `RESEAL` 表只有 anyfun（有明文），`REGENERATE` 表是 predict.kim（没有明文，但也没有已发布的包，可以直接重新生成）。**所以今天把 `agent-key` 抄进信封乙，场景 A 和 B 就全覆盖了。** 以后每新建一个租户密钥，当场存进去——这是流程纪律，不是代码。

**抄 `agent-key` 之后必须验证**：它是 44 字符的 base64，一个字符抄错就是全租户的盒子打不开，而代理会**静默生成一把新的**（`agentkey.go:42-55`），日志里区分不出来。恢复时用 §3.2 的 `build-agent print-key` 比对，**在启动代理之前**。

## 6. 全库备份脚本（覆盖场景 C）

### 6.1 先补工具链

amos 上实测**没有** `mysqldump`、`mysql`、`aws`、`s3cmd`、`rclone`、`mc`、`age`；**有** openssl 3.0.2、gpg、python3 3.10.12、curl、jq、zstd 1.4.8、gzip。`deploy/amos/install.sh` 不装任何这类包。

所以第一步是：

- `install.sh` 里加 `mysql-client-core-8.0`，脚本开头硬校验 `mysqldump --version | grep -q 'Distrib 8\.0\.'`。**必须是 MySQL 8.0 系**——Ubuntu 22.04 上 `mariadb-client` 也提供同名命令，装错包会在生成列和 `utf8mb4_0900_ai_ci` 上出问题，而且要到恢复那天才发现。
- 上传工具二选一：装 `awscli`，或者给 `rn-server` 加一个 `backup put <file>` 子命令（`aws-sdk-go-v2/service/s3` 已经在 `go.mod` 里，几十行，且能复用 `EnvironmentFile` 让凭据不进命令行）。**不要手搓 SigV4**——`deploy/amos/README.md:266-279` 已经记录过这个桶的行为和标准 S3 有出入，在一个已知脾气古怪的端点上手搓签名是在给灾难当天埋雷。

「恢复时不依赖项目专有代码」这条约束只管**解密**，不管**上传**。

### 6.2 dump 的参数与凭据

```bash
#!/usr/bin/env bash
set -euo pipefail    # pipefail 不能少，理由见下
```

**不带 `pipefail` 时失败的备份退出码是 0。** 实测：`mysqldump nosuchdb | gzip | openssl ...` 整条管道退出 0，产出一个 780 字节、能解密、能解压、**内容为空**的「备份」。

**凭据用 `--defaults-extra-file=<(...)`**，口令只经过 `/dev/fd`，不落盘、不进 argv、不进 history（实测 `ps` 里只看得到 `/dev/fd/63`）。`-p<password>` 虽然 mysqldump 自己会擦 argv，但擦除发生在 exec 之后，那个窗口里 `/proc/<pid>/cmdline` 是真值；`MYSQL_PWD` 被 MySQL 官方标为 insecure。

`MYSQL_DSN` 是 go-sql-driver 格式，口令里可能有 `( ) & $`——`AGENTS.md:49` 记着「`MYSQL_DSN` 就是这么泄的」。**绝不要用 shell 展开去拆**，用 python3 在同一个进程里读 env、正则拆、直接 print 成 my.cnf 片段；`password=` 的值要加双引号（`#` 会被当注释、空格会被吃掉），引号内的 `"` 和 `\` 要转义。库名单独从 DSN 取，my.cnf 的 `database=` 对 mysqldump 不生效。

**用一个只读账号，不要复用 `MYSQL_DSN` 里那个能写的。** 实测 `--single-transaction` 的全量 dump 只要 `GRANT SELECT ON *.*` 就够，不需要 `LOCK TABLES` / `PROCESS` / `RELOAD`。这条是「amos 被拿下时备份凭据能干什么」的分界线。加 `--no-tablespaces` 保险。

参数就这些：`--single-transaction --no-tablespaces`。**不要加 `--routines` / `--events` / `--triggers`**：实测这个 schema 里 VIEW / TRIGGER / EVENT / ROUTINE 一个都没有，而 `--routines` 会带出 `DEFINER=` 子句，恢复到新库时那个用户不存在就失败。脚本里留一条注释记下这个结论和它的失效条件（哪天有人加了 VIEW/TRIGGER，这个脚本要同步改）。

**生成列不需要任何参数。** 实测 mysqldump 8.0 对含 STORED 生成列的表自动切换成带列名的 INSERT 并把生成列排除在外，恢复后 `live_build_number` / `live_ota_slot` 按新表达式重算正确，唯一索引原样保留。**脚本里要写一条注释说明「为什么不用管生成列」**，否则下一个人会去加 `--complete-insert` 反而出事。

### 6.3 加密：`cms` 不是 `smime`，而且要先签后加密

```bash
openssl cms -sign   -binary -signer /etc/rn-foundation-backup/signer.pem \
                    -inkey /etc/rn-foundation-backup/signer.key -outform DER -stream \
| openssl cms -encrypt -binary -aes-256-gcm -stream -outform DER \
                    -out "$OUT" /etc/rn-foundation-backup/recovery.pem
```

实测对比（OpenSSL 3.0.2，峰值 RSS）：

| 命令 | 输入 | 峰值 RSS |
|---|---|---|
| `smime -encrypt -aes-256-cbc -outform DER`（v2 的写法） | 1 GB | **1,960 MB** |
| `cms -encrypt -aes-256-gcm -stream -outform DER` | 500 MB | **7 MB** |

`smime -encrypt` 全量进内存、约 2× 输入。今天的量级还撑得住，但**解密端更危险**：灾难当天在一台临时机器上解一个大备份会 OOM，而那是最不该出意外的时刻。

更要命的是 **CBC 没有完整性**。实测把密文翻一位：`smime -decrypt` 吐出**大部分正确、中间一段是垃圾**的明文——那会被 `mysql <` 直接写进库。`cms -aes-256-gcm` 则报 `Error decrypting CMS structure`。

两种写法双向兼容（`cms -decrypt` 能读 `smime` 的产出，反之亦然），`cms` 和 `smime` 同属 openssl 基础包，「恢复端用标准工具」的诉求完全不受影响。

**先签后加密解决真实性。** `cms -encrypt` 是匿名的：恢复证书是公钥，**任何拿到它 + 有一条往桶里写对象的路径的人，都能伪造一个密码学上无法与真 dump 区分的全库备份**——而全库 dump 里有 `tenant_domain`（Host→租户映射）和 `build.android.identity.apiBaseUrl`（重建出来的 App 此后跟谁说话，只校验是个 https origin，`internal/api/build_config.go:85-98`）。

签名私钥放 amos（它不是对偶机密，泄露只意味着能伪造，和上传凭据同级），**验证证书进信封甲**。恢复时 `openssl cms -verify -certfile signer.pem` 是一条标准命令，不破坏「不依赖专有代码」。

### 6.4 `schema_migrations` 必须包含 —— 这是 v2 最危险的一条错误

v2 写「`schema_migrations` 不进备份包」。那条规则是从「只有数据的打包材料包」搬过来的，**对 mysqldump 是反的**：

- 全库 dump **自带 `DROP TABLE IF EXISTS` + `CREATE TABLE`**（实测 25 条 DROP）。所以「连它一起恢复进空库，所有版本都算已应用，一张表都不会建」在 mysqldump 路径上不成立——dump 自己建表。
- 而 `schema_migrations` 为空时，下一次 CI 部署会跑 `rn-foundation-migrate`（`rn-foundation-apply:76`，**每一次 push 到 main**），v5 重放，`app_configs`（含全部 OTA 签名私钥、keystore 盒子、桶凭据）、`app_releases`、`audit_events` 全没。

**恢复成功过，然后被一次正常部署删掉。**

反方向同样坏：先跑迁移（代码版本 N）再恢复一个 schema 版本 M<N 的 dump，表结构退回 M、账本说 N，中间那些迁移永不再跑，静默漂移。

所以：**全库 dump 包含 `schema_migrations`，恢复时不跑迁移**（§8 场景 C）。

### 6.5 体积与压缩

实测（schema 同源的库）：全库 dump **244 MB**，其中 `app_configs` **241 MB（98.9%）**，全部来自 `build.icons`（104 行 / 平均 2.3 MB）。**gzip 只压到 1.34×**——base64-of-PNG，PNG 本来就 deflate 过，base64 涨的 4/3 最多被收回来。

所以 §6.2 管道里的 `gzip` 基本没收益，换 `zstd -3`（amos 有 1.4.8）或直接去掉。

生产量级：每租户上限 4 张 × 6 MiB → base64 后 32 MB；anyfun 实际两张 2.6 MB → ~7 MB。今天 3–4 个租户 → **20–60 MB，上限约 130 MB**。

真正会无界增长的是没有保留期的流水表：`app_diagnostic_reports`（表注释自己写着「不设保留期」，`migrations.go:1580`）、`audit_events`、`wallet_transfer_index`、`app_push_deliveries`。到 GB 级时这套管道（尤其解密端的内存）要换掉。

**两张表建议 `--ignore-table` 掉**：`admin_sessions`（恢复它等于把灾难前的活会话搬进新系统，是安全倒退）和 `wallet_auth_nonce`（一次性挑战，恢复无意义）。

### 6.6 调度：systemd timer，不是 cron，不用 root

amos 上现有的定时任务实测只有 acme.sh 的 root crontab 一条，**没有 MTA、没有告警基建**——cron 失败默认发本地 mail，没人看。

用 systemd timer 的三个理由在这台机器上都已成立：`EnvironmentFile=` 让数据库口令不进命令行（和 `rn-foundation-migrate.service` 同一个理由）；`OnFailure=` 能挂通知；同一个 unit 天然不并发（cron 要 `flock -n`）。

**别以 root 跑。** `/etc/rn-foundation.env` 是 0600 root，照字面做只能上 root cron——那等于在这台放着 Android keystore 的机器上再开一条 root 定时执行路径。备份只需要「只读 DB 账号 + 只 Put 的桶凭据」，单开一个 0600 `rnfoundation` 的 `/etc/rn-foundation-backup.env`。

桶凭据**必须是 env 里独立的一对**，不能是 §7 那个存在 `app_configs` 里的——脚本读不到库里的配置，也不该给它解密 `STORAGE_MASTER_KEY` 的能力。

`--single-transaction` 撞上迁移会 abort（实测：改字段数的 DDL → 退出码 3、那张表 0 行；而 `CREATE INDEX` 这类不改字段数的 DDL **不会** abort、数据完整，所以不能靠「迁移期间一定会失败」自我安慰）。备份窗口选在没人部署的时段，失败自动重试三次、间隔 5 分钟。

### 6.7 每次备份的自检（不需要私钥）

**v2 说「验证方式就是演练，脚本里就能做」——那和「产出者打不开自己的产出」互斥**：要在脚本里验证被上传的那个密文，amos 上就必须有恢复私钥。两条不能同时为真。

拆成两级：

**每次备份做（几秒，不需要私钥、不需要写权限）**：

1. dump 先落临时文件（`trap cleanup EXIT` + `shred`，抄 `rotate-keystore-passphrase.sh:103-109`），开始前检查可用空间 ≥ 5 GB（打包机的缓存会突然涨）。
2. 校验尾标 `-- Dump completed on` 存在——**pipefail 挡不住「dump 成功却被截断」**（实测：掐到 8 MB 的 dump 走完整条管道，解密成功、解压成功、合法 SQL，唯一少的就是这一行）。
3. `grep -c '^CREATE TABLE'` 等于预期表数，且 `app_configs` / `tenants` / `tenant_domain` / `chain_token_catalog` / `language_document` 的 INSERT 段各自非空——恰好是「缺了就全站 503 / 文案静默退化」的那几张（§7.2）。
4. 记录未压缩字节数与 sha256，和上一次比对，异常跌落报警。
5. 上传后**从桶 GET 回来重算 sha256**——这一步同时验证桶凭据、网络和对象完整性。
6. 成功时 `touch /var/lib/rn-foundation/backup-last-success`（mtime 即状态），并 PUT 一份状态到桶里的固定键（脚本没有 DB 写权限，写不了 `audit_events`）。

**每月做（真演练）**：完整解密 + scratch schema 恢复，在**另一台持有恢复私钥的机器**上。实测这一步本身很便宜（244 MB dump 恢复耗时 5.0 s、客户端峰值 RSS 52 MB，生成列重算正确、排序规则不漂、逐表行数一致），真正的代价是它要求一个能建库的账号——那个账号的权限必须精确落在 scratch 库上，**绝不给 `*.*`**，恢复完立刻 `DROP DATABASE`。

## 7. 控制台：打包材料备份

### 7.1 和全库备份的分工

| | 全库备份（§6） | 打包材料备份（本节） |
|---|---|---|
| 产出者 | amos 上的 systemd timer | rn-server（控制台按钮 / 定时） |
| 范围 | 全库（除两张会话表） | 打包与发布所需的那几张表，**排除图标 blob** |
| 体积 | 今天 20–60 MB | 今天几百 KB |
| 格式 | CMS，`openssl cms -decrypt` 可开 | 项目容器，主用 `cmd/rn-backup`（§7.5） |
| 用途 | **灾难恢复底座**，覆盖场景 C | 可下载、可手工归档、抵消离线信封的漂移 |

**后者不是前者的替代。** 它填的是离线信封的一个真实缺口：信封里的内容会随新租户、新密钥漂移，而「每建一个租户密钥就去更新信封」是纯流程纪律。**但必须先有全库备份**——只有这个包不构成灾难恢复。

范围：`app_configs`（**排除 `build.icons` 那些行**）、`tenants`、`tenant_domain`、`app_releases`、`ota_releases`、`chain_token_catalog`、`language_document`、`audit_events`。**不含 `schema_migrations`**——这一份是纯数据，恢复时要先跑迁移建表（和 §6 相反，§8 场景 C 与 §8.4 分别说明）。

排除 `build.icons` 的理由：图标不是机密（`internal/api/build_icons.go:31-33` 自己说的，它原样编进每个 APK），而它单租户就能占 32 MB（§6.5）。全库备份里有它。**代价要写在页面上**：只从这一份恢复的话，**构建会直接失败**在 `ENOENT: ./assets/tenants/<x>/icon.png`（`build_icons.go:26-30`），必须先重传图标。

**体积不是常数。** 今天 tar 之后约 300 KB–1 MB；`app_releases` / `ota_releases` / `language_document` 都是只增不减的行，两年后未压缩 5–15 MB。状态页要显示**最近一次包体**，越过阈值（8 MB）告警。产出走流式或先落临时文件再上传，不要一次性全量进内存。

**这一份不含 `app_installations`**：只从它恢复的话，被吊销的安装会回到 `active`（`installations.go:31`），那是安全状态倒退。同样写在页面上。

### 7.2 产出

服务端内部产出 `tar.gz`（Go 代码，不 shell out），封给 §4 那**同一把** RSA 恢复公钥：随机 32 字节数据密钥 → AES-256-GCM 加密载荷 → 数据密钥用 RSA-OAEP（`crypto/rsa.EncryptOAEP`，stdlib）封给 `recovery.pem` 的公钥。容器是一个明文 JSON 头（格式版本、证书指纹、封装后的数据密钥、nonce）+ 密文。

**不碰 `SealTo`，也不新增密码学原语**——RSA-OAEP 和 AES-GCM 都在 stdlib。头部字段与解包步骤要写进 `deploy/amos/README.md`，使得必要时能用 `openssl pkeyutl -decrypt` + 一段 python 手工解开。

`manifest.json`（在密文内，是清单不是警报）：格式版本、实例 id、序号、生成时间、每个成员的 sha256、逐租户的 keystore 校验**三态**（`ok` / `failed` / `pending`——`pending` 和 `failed` 一样危险，它意味着从来没验过）、`build.agent.recipient` 的当前指纹。

**fail-closed，而且在启动时。** 判据不能用 `Recipient.Fingerprint()`：它只在「不是 base64」或「0 字节」时返回空，**不检查长度**（`recipient.go:50-57`），一个 5 字节的值会通过、指纹显示得像模像样、到第一次备份才失败。改成解析 `recovery.pem` 成功且指纹等于配置里的那一个，和 `production` 下那批必填项一起在启动时校验（`internal/config/config.go:179-189`）。

**另外一条一行就能堵的**：如果恢复证书的公钥恰好等于 `app_configs(0,'build.agent.recipient')` 里那把，**拒绝启动**。这是运维最可能犯的粘错——两把公钥都在同一个页面上并排显示指纹，而粘错的后果是打包机能解开每一份平台备份。

### 7.3 真实性：sha256 必须真的在带外

v2 说「值来自控制台或审计」——可那两个值分别存在 `platform.backup.state` 和 `audit_events`，**都在同一个数据库里，都由同一个进程写**。一次 RCE 可以同时伪造包和期望值，而 v2 设计的负面用例**会通过**，因为演练里那个伪造包没有配套改 state 行。

三条一起上：

1. **桶必须开 versioning + Object Lock**（compliance 模式，保留期 ≥ 保留策略）。这是**唯一一条不依赖人的控制**：伪造包只能成为一个新版本，恢复工具按最早的版本取。**这也顺带修正 v2 的一个错误论断**——「服务端没有 Delete 权限所以销毁不了备份」是错的：`Put` 对已存在的键是**覆盖**（`internal/objectstore/s3.go:131-143`），在没开 versioning 的桶上覆盖等于删除。
2. **写凭据额外授 `s3:GetBucketVersioning`**（不给对象读权限），「测试连接」在 versioning 未开启时**直接失败**。零成本可验的判据，不验就等于把核心安全论证建在一个没人检查的桶属性上。
3. **产出成功时把 `(序号, 生成时间, sha256, 证书指纹)` 弹一个「抄走并存档」的模态框**，写进信封那张纸。恢复工具的 `--expect-sha256` 只接受人从纸上抄来的值；控制台显示的那个值**只用来当天核对，不是恢复依据**。

**服务端产出的包本质上无法自证真实性**——这句话要直接写进文档，取代 v2 那套说法。

### 7.4 凭据、endpoint 与对象键

新配置键 `platform.backup.storage`（`app_configs(tenant_id=0)`），字段照 `release.storage` 的形状但**去掉 `publicBaseUrl`**，生产强制 https。

**加密的 AAD 必须是 `"0:platform.backup.storage:" + field`**，不能复用 `release.storage` 的串（`release_storage.go:270-272`，两边 tenant 都是 `"0"`）。复用意味着能写库的人可以把产物桶凭据的密文**原样搬进来**——解密照样成功，于是备份被带着有 Get 和 Delete 权限的产物桶凭据传到产物桶。

**读路径的 `endpoint / region / bucket / objectPrefix` 全部进 env**，和读凭据放一起。原因：`AWSFactory.New` 接受任意绝对 http(s) endpoint（`objectstore/s3.go:99-105`），而 `validateReleaseStorageWrite` 对 endpoint 主机名不做任何校验（`release_storage.go:302-308`）。endpoint 在库里 = 能写配置的人可以让服务端**带着 env 里的读凭据**去签名请求打向任意主机（SSRF + AccessKeyId 外泄），或者把 bucket 换成别的桶。服务端启动时校验两边的 bucket/prefix 一致，不一致 fail-closed。

**写凭据其实也该进 env。** v2 把它放数据库的理由是「随备份包一起走」，可恢复当天需要的是**读**凭据，写凭据在包里对恢复毫无用处；放 env 则「能写库的人能改收件桶」这条路直接消失。管理端那个配置页因此只维护**非机密**字段与状态显示。

**对象键必须是受校验输入的纯函数，记录里不存键**：

```
key = objectPrefix + "/" + instanceID + "/" + fmt.Sprintf("%08d", seq) + ".rnbk"
```

`seq` 用 `strconv.Atoi` 解析、要求 > 0 且在 state 列出的序号集合里；`objectPrefix` 加正则 `^[a-z0-9][a-z0-9._/-]{0,127}$` 并拒绝任何 `..` 段（`validateReleaseStorageWrite` 今天**完全没有校验它**）；拼完再断言 `strings.HasPrefix(key, objectPrefix+"/")`。这样即使 state 行被污染，`Get` 的目标也偏不出去。

**实例 id** 是这套键的一部分，必须现在定义：启动时若 `platform.backup.state` 里没有就生成一个随机 8 字节 hex 并写进去，此后随库走。它**不进任何 AAD**（§4 已说明 AAD 那条不做），所以换机器不会导致解不开。

### 7.5 恢复工具

`cmd/rn-backup`：`open`（解密 + 校验 tar 成员名 + 比对 `--expect-sha256`）、`restore`（写回数据库）。

**解包必须校验每个成员名**：禁绝对路径、禁 `..`、禁符号链接、白名单文件名。手工路径要写 `tar --no-absolute-names -C <空目录>`，不能只说「用标准工具解开」。

`restore` 的语义（和 §6 的 mysqldump 路径不同，这一份是纯数据）：

- 前置检查 `SELECT COUNT(*) FROM schema_migrations`，为空就**拒绝执行**并说明必须先跑迁移。
- 一律 `INSERT ... ON DUPLICATE KEY UPDATE`，**备份里的行赢**，并把 `version` 一起写回（否则管理端所有乐观锁写操作会 409）。会撞的是 `(0,'release.platforms')` 和 `(0,'languages')` 两行（§3.3d）。
- 它需要 `MYSQL_DSN`——那在信封甲里。

**二进制怎么到恢复现场**：每次备份成功时，把 `rn-backup` 的静态编译二进制 + sha256 一起放进同一个桶前缀（它几 MB，包是几百 KB，这个成本可以接受），并在状态里记下摘要。

### 7.6 只有平台管理员可见、可下载

三道门：

- **前端**：插件声明 `platformOnly: true`，`RN-Admin/src/app/App.tsx:206-208` 按 `session.platformAdmin` 过滤掉整个插件。直敲路由也进不去：`activePlugin` 用的是**已过滤**的列表（`App.tsx:299-301`），落回 fallback；`session` 为 null 时同样被过滤，fail-closed。
- **后端**：路由挂 `platform.*` 组，`requirePlatformAdmin()` 按 `PLATFORM_ADMIN_USERNAMES` 白名单（`internal/api/chain_scan_admin.go:26-40`）；**白名单为空时整组 403**。
- **下载接口只认会话 cookie，不认 `x-admin-key`**（那把密钥还另受 `ADMIN_API_ALLOWED_IPS` 约束，`server.go:510-515`，但它是长期有效的自动化凭据，备份下载不该是自动化能力）。

**必须补的一道**：`GET` **不过 Origin 检查**。`authenticate()` 的 Origin 闸只对非安全方法生效（`server.go:492`，`safeMethod` 含 GET，`:2017`），而 `originAllowed` 会**回落去查 `tenant_domain` 表**（`server.go:448-467`）并回显 `Access-Control-Allow-Credentials: true`。部署上 `console.*` 与 `api.*` 同注册域，SameSite=Strict 放行。于是「谁能读平台备份」实际由 `tenant_domain` 表的内容决定，而往那张表加行的人不会意识到自己在扩大备份的读取来源。

修法（三选一，建议前两条都做）：平台组**关掉 CORS 的 tenant_domain 回退**，只接受 `CORS_ORIGINS` 里显式列出的控制台来源；下载 handler 里显式要求 `Origin` 为空或在白名单内，并检查 `Sec-Fetch-Site`；或者改成两步——`POST .../download-tickets/:seq`（POST 会过 Origin 闸）发一张 60 秒一次性票，再 `GET .../download?ticket=`。响应要显式 `Cache-Control: no-store`。

**这道门今天挡不住谁。** 控制台只有**一个**登录账号（`server.go:543` 比对唯一的 `ADMIN_USERNAME`），会话 `actor_id` 永远是这一个值；**「租户管理员」这个身份不存在**——租户是靠打开哪个域名（Host 头）区分的。所以白名单要么包含那个唯一账号（凡是能登录的人都看得见备份），要么不包含（平台路由整组 403）。`OPERATIONS_AND_RELEASE.md:233` 记录了这个阶段性决定：「当前阶段不加入 RBAC」。

`platformOnly` 仍然是正确的门（多账号落地时它已经是关好的）。今天便宜的补偿控制是**步进式再认证**：`run` 和 `download` 各要求重新输入一次管理员口令（`verifyPassword` 现成），并共用登录限速（`s.rateLimited`）。会话 TTL 默认 8 小时，一个被偷走的 cookie 否则能在 8 小时内拉走全部历史备份。

### 7.7 接口与定时

| 方法 | 路径 | 说明 |
|---|---|---|
| GET / PUT | `/platform/backup/storage` | 非机密字段 + 状态；机密在 env |
| POST | `/platform/backup/storage/test` | 只 Put 到 `<prefix>/.probe/<随机>`，并校验 versioning 已开 |
| GET | `/platform/backup` | 状态 + 证书指纹 + 最近 N 次清单（**从本地状态读，不 List 桶**） |
| POST | `/platform/backup/run` | 立即备份；走和定时**同一把** CAS 锁，最小间隔 60 秒 |
| GET | `/platform/backup/download/:seq` | 按序号下载（§7.4） |

**「测试连接」不能用现成的 `objectstore.Test()`**：它 Put 一个**固定键** `.rn-foundation-storage-check` 然后 `HeadObject`（`s3.go:319-336`），既要求 Get/Head 权限（和只给 Put 冲突），固定键在开了 versioning 的桶上还会永久留存。

**`POST /platform/backup/run` 必须加进数据库超时的豁免列表。** `r.Use(..., s.databaseTimeout(), ...)`（`server.go:136`）给每个请求的 context 上 `MYSQL_QUERY_TIMEOUT_SECONDS`（默认 10 秒）的限制，只豁免以 `/upload`、`/finalize`、`/release-storage/test`、`/download` 结尾的路径（`:363-368`）。读 8 张表 + tar + gzip + 加密 + 上传不可能在 10 秒内完成。`/platform/backup/download/:seq` 以序号结尾、也不在豁免里。

定时：`cmd/server` 起 ticker，抄 push dispatcher 的形态（`cmd/server/main.go:88`）。跨实例互斥用 `platform.backup.state` 的 `version` 做 CAS——**注意 `upsertAppConfig` 绑死在 `*gin.Context` 上**（`build_keystore_generate.go:225-231`，用了 `tenantID(c)` / `actor(c)` / `c.Request.Context()`），ctx 版本要把三样都显式传进去，租户一律写 `platformTenantID`（平台路由上 `tenantID(c)` 是字符串 `"<nil>"`，`server.go:1972`，直接插 `audit_events` 会 1366 报错）。

`platform.backup.state` 的字段：实例 id、序号、上次成功时间、上次 sha256、上次包体、连续失败次数、最近 N 条（N 默认 30）记录、CAS `version`。**完整历史进 `audit_events`**（`actor_id='system-backup'`），state 行只留最近 N 条——它是 `app_configs` 的一个 JSON 单元格，每次备份读改写一整行，无界增长会让每个包里都嵌着到那一刻为止的全部历史。

**服务端永不删除备份**，保留交给桶的生命周期规则。但要写清楚这**不等于**旧机密会消失：只要历史包还在，过去的 OTA 签名私钥和存储凭据就还在里面，**密钥轮换的语义因此从「旧的作废」退化成「多了一把新的」**。生命周期规则的保留期就是这个退化的时间上限，必须显式设一个数（建议 90 天），不能留空。

### 7.8 管理端页面

放**平台维护**（`RN-Admin/src/modules/build-config/plugin.ts:68-75`，今天只有「管理员口令」一项）。现有平台级菜单共三个：平台运维（扫链管理）、平台账号（账号查询）、平台维护（管理员口令）。备份和管理员口令并排。

顺带一个独立的 UI 归位小修：打包机公钥的 UI 在 `keystore-section.tsx`、由 `android-build-page.tsx:283` 渲染，属于**租户级**的「打包与签名」页，而后端那条路由是平台级的（`server.go:177-178`）。

页面元素：备份桶非机密配置 + 「测试连接」；恢复证书指纹（只读）+ 「核对它和信封乙里那把私钥是同一对」；上次成功时间 / 序号 / sha256 / 包体 / 连续失败计数；「立即备份」；最近 N 次清单 + 逐条下载；打包机公钥（§3.2 加上之后）。

**页面上必须写死四段文字**：

1. 备份桶的读写凭据必须离线抄一份（凭据本身在备份里，机器全丢时你需要凭据才能取到那个装着凭据的包）。
2. 信封甲 / 乙的内容清单（§5），以及「每新建一个租户签名密钥，当场把 `.p12` 和口令存进信封乙」。
3. **下载下来的包与那份只读凭据必须分开存放**，否则 §7.4 的凭据分离在运维侧被抵消。
4. **这一份不含图标与设备表**：只从它恢复会让构建失败在缺图标上，且被吊销的安装会回到 active（§7.1）。

全部文案、`aria-label`、`title`、placeholder 要过 `src/core/admin-i18n.tsx` 并双语（`RN-Admin/docs/ADMIN_ENGINEERING_STANDARD.md:206-222`），新页面配 `.spec.tsx`（同文件 §9，`:245` 起）。

**写操作要带 reason + 二次确认**（`AGENTS.md:35`）：`PUT /platform/backup/storage` 写桶配置、`POST /run` 产出含全部租户密文的包、`download` 取出它，三条都要。现成的形状是 `otaSigningWrite` 的 `Reason` / `Confirm`（`ota_signing.go:229-230`）。

## 8. 恢复流程

### 8.1 场景 A（整机损毁，托管完好）

```
0) 新机器：工具链（Android SDK / JDK17 / node+pnpm / git / mysql-client-core-8.0）
   + nginx / TLS 证书 / DNS 指向原域名
   —— deploy/amos/install-origin-cert.sh、setup-tls.sh、nginx-rn-foundation.conf
   —— 不做这一步后面每一步都是 404：tenantResolver 要求域名 active、租户未软删、
      且 CURRENT_DATE 在 start_date..expiry_date 之间（tenant_resolver.go:64-78）
   —— 演练时特别注意 expiry_date：历史备份很容易撞上
1) 记下恢复时刻：date -u
2) 写回 /etc/rn-foundation.env（信封甲 + 乙的桶凭据），
   STORAGE_MASTER_KEY 必须是原来那一把
3) 起 rn-server（用 x-admin-key 打 127.0.0.1:<PORT>，此时控制台还没部署）
4) 验证主密钥：POST /v1/admin/release-storage/test（会真的解密凭据）
   —— 不要用 GET /ota/signing-key，那个不解密（§3.3b）
5) 验证租户解析与配置可读：GET /v1/mobile/bootstrap 返回 200
6) 放回 agent-key（信封乙，0600），写 /etc/rn-build-agent.env
   —— 必须显式写死 BUILD_AGENT_STATE_DIR。它默认从 workspace 推导
      （cmd/build-agent/config.go:89-92），路径差一点就找不到恢复的私钥，
      代理会静默生成一把新的（agentkey.go:42-55），日志里区分不出来
   —— 起代理之前先跑 build-agent print-key（§3.2）核对，别抄错
7) DELETE FROM app_configs WHERE config_key='build.keystore.check'
   —— 不删这一步，第 8 步看的是灾难前的旧记录（§3.3a）
8) 起 build-agent，等每个已配密钥的租户出现 checkedAt 晚于第 1 步时刻的 ok
   —— 长期停在 pending 的租户要查 LIMIT 20 那个 bug（§3.3 末）
9) 人工核对打包机公钥指纹等于信封记录的那一个
   —— registerBuildAgentKey 对无记录的首次登记零确认直接固定（build_agent_key.go:96-107）
10) 跑通一条真实 APK 构建并入库，才算恢复完成
```

数据库和对象存储没动过，所以这一档不需要恢复任何表。

### 8.2 场景 B（连 `agent-key` 一起丢）

已有的 v2 盒子全部永久打不开，逐租户重建：

```
0) 先清点：确认每个有已发布包的租户，信封乙里都有明文 .p12 + storePassword
   —— 这一步必须在 accept 之前。accept 会覆盖旧公钥记录（build_agent_key.go:190），
      到第 3 步才发现清点不全就没有退路了
1) 新机器起 build-agent，生成新私钥、登记新公钥
   → 平台管理员核对指纹后 accept（accept 会 DELETE 全部 check 行，重验会真的发生）
2) 取新公钥的 base64 —— 依赖 §3.2 的修复
3) 用明文 .p12 + storePassword，本地跑 build-keystore seal 封给新公钥
4) PUT /v1/admin/build-keystore —— 依赖 §3.1 的修复
5) 代理重验，全 ok
```

**没有离线 `.p12` 的租户在这一档里无法恢复。** 换签名证书 = Android 认作另一个 App，已装用户全部升不上去。今天只有 anyfun 有明文（§5）。

### 8.3 场景 C（数据库损毁，用 §6 的全库备份）

```
1) 建库：CREATE DATABASE <db> CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci
   —— 目标必须是 MySQL 8.0.x。utf8mb4_0900_ai_ci 是 8.0 独有的，
      灾难当天随手 apt install mariadb-server 就恢复不回去了
   —— dump 不含 CREATE DATABASE / USE（实测），必须先建库并在命令行指定库名
2) 确认 rn-server 与 indexer 都没在跑
3) openssl cms -verify -certfile signer.pem（信封甲）→ cms -decrypt -inkey recovery.key（信封乙）
   → zstd -d → mysql <db> < dump.sql
   —— dump 自带 DROP+CREATE+INSERT，也含 schema_migrations（§6.4）
   —— **不要跑迁移**
4) 起 rn-server，之后走 §8.1 的第 4 步起（含第 7、8 步的 keystore 重验——
   §3.3a 的旧 ok 记录就在你刚恢复的 app_configs 里）
5) **恢复验证通过之前，不要跑 rn-foundation-apply**（§3.3c）
```

### 8.4 只丢了打包能力（用 §7 的控制台包）

这是 §7 那份包唯一的恢复场景：数据库在、机器在，但某些打包配置被误删或误改。

```
1) rn-backup open --expect-sha256 <信封那张纸上的值>
2) rn-backup restore（upsert，备份里的行赢，见 §7.5）
3) 重传被排除的图标（否则构建失败在 ENOENT）
4) 走 §8.1 的第 7、8 步重验 keystore
```

### 8.5 一条运维约束

**恢复到新机器等于永久扩大签名密钥的信任边界。** 旧机器若并非物理损毁，必须按已泄露处理并销毁介质。这条与 `build-concurrency-2026-09-15.md` §8 同源。

## 9. 验证与演练

服务端能自检的只有结构——而 v2 说「`SealTo` 本来就会自解一次做 sanity check」是**错的**：`recipient.go:142` 传 `private=nil`，`OpenWith` 在 AEAD 之前就返回 `errNeedPrivateKey`（`:168-173`），只做了三个长度断言，**从不解密**。

所以三级：

1. **每次备份的自检**（§6.7）：尾标、表数、关键表非空、字节数趋势、回拉 sha256。不需要私钥。
2. **每月的真演练**：完整解密 + scratch schema 恢复，在另一台持有恢复私钥的机器上。
3. **每季度的整机演练**：走完 §8.1，判据是 ① 跑通一条真实 **APK** 构建并入库（强制解 keystore → 用 `agent-key` 开 v2 盒子 → 入库还要过 `signerSha256` 比对）；② 带 `expo-expect-signature` 头拉一次 manifest 并验签（这才验到 OTA 签名私钥）。

**v2 的判据（跑通一条 OTA 构建）验不到任何被备份的东西**：OTA 构建不需要签名密钥（`cmd/build-agent/ota.go:13-16`，不调 `unsealKeystore`），也不碰 OTA 签名私钥（那把私钥是下发 manifest 那一刻才解的，`ota_signing.go:205-222`）。

**每一级都要有一个负面用例**：给恢复工具喂一个伪造包，它必须拒绝。注意这条只在 §7.3 的三项护栏都到位时才有意义——伪造者如果同时能改 state 行，单靠 `--expect-sha256` 是过不了关的。

**演练通过之前，不要对外说「已经有备份了」。**

## 10. 落地顺序

1. **§3.1 + §3.2 两个阻断**。独立收益，不依赖本方案其余部分；不修则场景 B 无解。
2. **§5 离线信封**（今天就能做完，覆盖场景 A 与 B 的全部），写进 `deploy/amos/README.md` 里 `agent-key` 那段旁边，**点名责任人**。
3. **§4 生成恢复密钥对 + 签名密钥对**，指纹抄进信封。
4. **§6 全库备份**：先 §6.1 补工具链与桶（桶、只 Put 的凭据、versioning + Object Lock + 90 天生命周期规则，这三样手工做完），再写脚本与 systemd timer，再补 §6.7 的自检。**必须排在 §7 之前**——只有打包材料备份不构成灾难恢复。
5. **§3.3 的地雷 + `LIMIT 20`**（大部分是文档，两处是小代码改动）。
6. **§11 的既有问题**，其中 `git_ref` 那条优先。
7. **§7 控制台**，内部顺序不能换：
   1. §7.3 桶属性（versioning/Object Lock）+ §7.2 的启动时 fail-closed —— 决定桶怎么建、env 怎么填，建完再改要迁移数据
   2. §7.4 凭据与对象键形状
   3. §7.3 的真实性三件套（决定状态字段与恢复工具入口校验，后补会让已产出的包全部作废）
   4. §7.2 产出 + §7.7 的 `run`（含超时豁免）与 `download`
   5. §7.6 权限门（含 Origin 修法）+ §7.8 页面
   6. §7.7 定时（最后上，先用手动按钮跑几天）
8. **§9 的三级验证各跑一次**，含负面用例。

门禁（`AGENTS.md:105-116`）：

```bash
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -race ./...
go build ./cmd/server ./cmd/build-agent ./cmd/rn-backup
```

新增 env 键（`BACKUP_*`、`DEVICE_IDENTITY_HMAC_KEY` 若显式设）必须同时改三处：`internal/config/config.go`（读取 + 逐键校验，错误里带上出错的值）、`docs/CONFIGURATION.md`、`deploy/amos/rn-foundation.env.example`。`AGENTS.md:14`：「少了第二处，这个键对运维就不存在」——而这些正是灾难当天运维要用的键。

回滚：§3.1 改的是已发布接口的校验（放宽，不影响既有调用方）；§7.5 的 `restore` 改变数据语义，回滚前要确认没有人用它写过库；其余都是新增，revert 即可。**§6 的脚本没有数据库状态，随时可停。**

## 11. 顺带修的既有问题

这些不是本方案引入的，但恢复流程依赖它们。**第一条是这份文档里最严重的发现**，v2 把它埋在历史记录一节里，没有任何一步会去执行它。

- **`git_ref` 未校验 = 服务端能在打包机上执行命令。** `build_jobs.git_ref` 是从库里读出来下发的（`build_jobs.go:713` → `buildJobView` 的 `"gitRef"`，`:111`），代理拿到直接 `git worktree add --detach <worktree> <job.GitRef>`，**零校验**（`cmd/build-agent/build.go:130`；同一个函数对 `TenantDirectory` 是校验了的，`:121-123`），而仓库是 `--mirror` 克隆、上游每个分支和 tag 都在本地可达。服务端 RCE 改掉 ref → 代理以 `builder` 身份执行那个提交的代码 → 直接读走 `agent-key`（属主就是 `builder`）。**「服务端能选检出哪个提交」就等于「服务端能在打包机上执行命令」**，只是叫构建。**修法**：把 main 的固定挪到代理侧——代理忽略 `job.GitRef`、硬编码只从 `refs/heads/main` 检出，服务端下发的 ref 只用于日志核对。这和 `tenantfile.go` 顶部「两端分属不同信任域，各自把住自己那一侧」是同一条原则，只是这一项漏了。
- **`putTo` 把 `x-build-agent-token` 附加到服务端指定的任意 URL 上**并 PUT 整个产物（`cmd/build-agent/client.go:283-295`）——服务端 RCE 可以把产物导向外部主机并顺带泄露令牌，而 §2 显示那把令牌的价值远高于 README 的说法。
- **`acceptBuildAgentKey` 的 `DELETE FROM app_configs WHERE config_key=?` 缺租户维度**（`build_agent_key.go:197-198`）。注意这条和 §8.2 场景 B 第 1 步互相依赖：那一步依赖「accept 会清空全部租户的 check」这个行为。真要加租户维度，场景 B 必须同时补一条显式的清空步骤。
- `pendingKeystoreChecks` 的 `LIMIT 20` 语义（§3.3 末）。
- `deploy/build-agent/rn-build-agent.env.example` 没有 `BUILD_AGENT_STATE_DIR` 这一项、也没提 `agent-key`，还停留在 `BUILD_KEYSTORE_PASSPHRASE` 时代。
- `deploy/build-agent/README.md:45` 关于 `BUILD_AGENT_TOKEN` 能力范围的描述不准确（§2）。

## 12. 评审记录

### 12.1 撤回：代理侧把 `agent-key` 封给恢复公钥上报

v1 提议代理把自己的私钥封给恢复公钥、上报给服务端存进 `app_configs`。撤回，理由三条：

- **它自动化的是一个永不变化的文件**，而信封里本来就要放主密钥和桶凭据，多写一行的边际成本是零。为省这一行，v1 新增了代理 env 变量、一条接口、一个配置键、一对独立密钥及其轮换流程、`SealBytes`，以及「代理必须忽略服务端下发收件人」的专门用例。
- **它保护的东西价值更低**：`agent-key` 打开的盒子里装的就是 `.p12` + 口令。只要明文 `.p12` 在信封里，丢 `agent-key` 的代价是逐租户重封（今天 1–2 个租户），不是能力丧失。
- **它声称堵死的攻击没堵死**：`git_ref` 那条缝（§11）说明服务端根本不需要改收件人。

### 12.2 否决：由打包机「转封」存量密钥给新收件人

谁能把一把公钥放进收件人集合，谁就拿到明文 keystore 封给自己的密文。而今天收件人的写入口之一是 `registerBuildAgentKey` 在无记录时用**代理令牌、零确认**直接固定（`build_agent_key.go:96-107`）。转封会把 build-service 那条承重论证从「服务端读不到签名密钥」变成「服务端读不到签名密钥，**除非**它往收件人列表里写一行，然后请那台读得到的机器把密钥交出来」。它**就是**一条命令，只是叫转封。人工重新上传原始 `.p12` 严格更安全。

### 12.3 v2 被推翻的判断

| v2 的说法 | 实际 |
|---|---|
| 「排除 `schema_migrations`」 | 对 mysqldump 是反的，会让恢复成果被下一次部署删光（§6.4） |
| 「身份进 AAD 解决伪造」 | 会封死全平台签名密钥，而且对知道公钥的攻击者是空的（§4） |
| 「sha256 在包外」 | 它在同一个数据库里；负面用例会假性通过（§7.3） |
| 「服务端没有 Delete 权限所以销毁不了备份」 | `Put` 覆盖已有键 = 销毁（§7.3） |
| 「包是 KB 级」/「几十 MB」 | 全库实测 244 MB（98.9% 是图标）；控制台包今天几百 KB 但线性增长（§6.5、§7.1） |
| 「`SealTo` 会自解一次做 sanity check」 | 只做三个长度断言，从不解密（§9） |
| 「验证方式就是演练，脚本里就能做」 | 与「产出者打不开自己的产出」互斥（§6.7） |
| 「演练判据：跑通一条 OTA 构建」 | OTA 构建不碰 keystore 也不碰 OTA 签名私钥（§9） |
| 两套恢复密钥 | 统一成一对 RSA（§4） |

## 13. 已知遗留

- **`STORAGE_MASTER_KEY` 无轮换**（`OPERATIONS_AND_RELEASE.md:311` 要求「轮换前必须实现逐版本解密、重加密和核对」，即尚未实现）。本方案不解决，但 §7.7 的保留期上限至少给了它一个边界。
- **产物归档**。若将来要防桶本身丢失，应是独立的、**不加密**的归档任务，选择规则按「还在服务中」而不是固定条数：每租户每平台当前 `active` 的 APK + 上一个，每条运行时线的 `active`/`canary` 修订 + 前一个。若和备份共桶，前缀命名（`db/`、`pack/`、`artifacts/`）现在就要定，生命周期规则按前缀配。
- **告警**。平台没有告警基建；§6.6 的 `OnFailure=` 与 §7.8 的状态显示是最低限度。
- **多账号管理员登录**。§7.6 的权限门在它落地之前形同虚设。
- **流水表无保留期**：`app_diagnostic_reports`（表注释自己写着「不设保留期」）、`audit_events`、`wallet_transfer_index`、`app_push_deliveries`。它们是全库备份体积的长期风险。
