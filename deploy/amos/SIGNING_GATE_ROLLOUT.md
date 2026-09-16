# 签名闸上线手册（amos，开发环境）

2026-09-16。对应设计 `docs/design/android-signing-gate-2026-09-16.md`「落地顺序」与 ADR-0019。
这份手册把一次上线从头到尾按顺序写成可照做的步骤；每个组件的细节以各自的 README 为准：
`deploy/signer/README.md`、`deploy/build-agent/README.md`、本目录 `README.md`。

脚本在 `deploy/amos/signing-gate-rollout/`：

| 脚本 | 在哪跑 | 身份 | 做什么 |
| --- | --- | --- | --- |
| `0-bundle.sh <输出目录>` | 开发机，干净工作区 | 普通用户 | 编 `build-agent`、`build-runner`、`signer`、`signer-check`，连同部署文件打成部署包，打印 sha256 |
| `1-install.sh <部署包目录>` | amos | root | 停旧构建机、留存旧配置与密钥、建用户与目录、装构建机与签名闸、装 CI 收口脚本。不涉及令牌，可重复执行 |
| `2-configure.sh` | amos，**你自己的终端** | root | 提示输入三台机器令牌（不回显）、写三份 env、启动、打印三台机器的公钥指纹 |
| `3-server-units.sh <部署包目录>` | amos | root | 换服务端三个 unit 并重启（必须在签名闸启动之后） |

## 0. 开始前要知道的

- **安装包冻结窗口**：从第 2 步服务端上线开始，到第 9 步第一个新签名的包发出为止，出不了安装包。热更新不受影响。
- **回滚点**：第 2–7 步都可以回滚到旧二进制（见第 11 节）。第 8 步上传新密钥之后不回退旧密钥，旧指纹已经写死永久拒绝，出问题只修复向前。
- **机密纪律**（`AGENTS.md`「机密的操作纪律」）：机器令牌、加密口令、密钥原件只在你自己的终端和离线机器上出现。不要用 Claude Code 的 `!` 前缀执行取密或输入令牌的命令，不要截图、不要贴进聊天。可以贴出来的只有公钥、指纹、证书 sha256。
- **需要人亲手做、不能交给自动化会话的步骤**：离线生成密钥（第 8 步）、控制台接受公钥时核对指纹（第 6 步）、签名闸上的 `promote`、`trust-builder`、`confirm`（第 6、8 步）。这些步骤就是设计要防“服务端或自动化被攻破”的那道人工确认，替人做等于没做。

### 本次涉及的租户

| 控制台域名 | 租户 slug（`--tenant`） | 包名（`--package`） | 旧签名指纹（已作废） |
| --- | --- | --- | --- |
| `console.anyfun.win` / `api.anyfun.win` | `AnyFun` | `com.anyfun.foundation` | `1a5d9fb4…e694` |
| `console.predict.kim` / `api.predict.kim` | `Predict` | `com.predict.kim` | `9ab5fbe6…cf37` |

any123 没有配置 Android 发布身份，本次不涉及。

### `signer confirm` 的对照值

下面的值取自**线上正在分发的安装包**（anyfun 1.3.16 build 46、predict 1.0.6 build 7，从公开下载接口取回后解包读出），
OTA 证书 sha256 另与服务端当前登记值核对一致。它们是改造之前构建的包，可作为独立于新服务端的参照。
`confirm` 时逐项由你输入；若服务端显示的值与这里不同（`DIFFERS`），先停下查清楚。

| 项 | AnyFun | Predict |
| --- | --- | --- |
| API origin | `https://api.anyfun.win` | `https://api.predict.kim` |
| OTA 证书 sha256 | `4fabae3ce4b4768de8ab69e3e22270eb7b408429f769f6524698e683cf3b1e5a` | `cd0c52ca7c3f30af89a15779f3745eb452451e67fb21ffd06019cabda2da1768` |
| bootstrap 签名地址 | `0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17` | `0x3294C48f71841558814a71B936EA8D9Aa07718Df` |
| App Links host | `api.anyfun.win` | `api.predict.kim` |
| scheme | `anyfun` | `predict` |
| 渠道 | `direct` | `direct` |
| applicationId | `dex-mobile` | `dex-mobile` |
| minSdk / targetSdk 下限 | 24 / 36 | 24 / 36 |
| 首签 versionCode 上限 | 取当前线上 build 号加一个余量，例如 `60` | 例如 `20` |

首签上限的作用：新密钥第一次签名时，versionCode 不能超过这个数。它要大于你打算发的第一个新包的 build 号（线上 AnyFun 是 46、Predict 是 7），又不要大太多。

## 1. 上线前（一次性）

1. **旧备份记录**：已导出到开发机 `UI/.secrets/backup-objects-export-2026-09-16/`（0600）。记录里 4 次运行全部失败、没有登记任何对象。桶所有者按 `backup.bucket` 的前缀检查并删除失败运行可能留下的半截对象，保留删除记录。
2. **GitHub**：RN-Server 仓库 Variables 里 `AMOS_DEPLOY_BUILD_AGENT` 删除或设为非 `true`（签名闸与 amos 同机期间构建机只人工部署；CI 那条路只换 `build-agent` 不换 `build-runner`）。
3. **确认没有在途安装包任务**：三个租户控制台「发布中心 → 打包任务」里没有排队中、已领取、构建中的安装包任务。
4. **离线工具**：在开发机 `signing/` 下为离线机器的平台编 `build-keystore`（或用已经打好的离线工具包，核对 `SHA256SUMS`），拷到离线机器。

## 2. 服务端上线

1. 把 `feat/signing-gate` 快进推到 RN-Server main（推之前 `git fetch` 核对领先/落后）。CI 跑完门禁后自动部署服务端并跑迁移 54（没有 55）。
2. 在 amos 上核对（CI 页面在本机 `gh` 看不到时以这里为准）：
   ```bash
   ssh amos 'stat -c "%y" /opt/rn-foundation/rn-server; systemctl show rn-foundation-server -p ActiveEnterTimestamp;
             curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:13080/health/ready'
   ```
   二进制时间晚于推送时间、`/health/ready` 为 200 即部署完成。CI 超过 15 分钟没部署，去 GitHub Actions 看失败原因；需要手工部署时用 `deploy/amos/deploy.sh server`。
3. 这时旧构建机会收到 426，打不出安装包（冻结窗口开始）。

## 3. 控制台上线（紧跟服务端）

把 RN-Admin `feat/signing-gate` 快进推到 main，CI 部署各租户控制台。核对：

- 「平台维护」里有「打包机与签名闸」，没有「备份与恢复」。
- 「打包任务」页正常打开；「打包配置」的签名密钥区显示“旧格式，需要重置”一类的不就绪原因（这是预期）。

新控制台要求新服务端，所以**不要先于服务端推**；旧控制台面对新服务端时签名密钥区会报错，这个窗口越短越好。

RN-App `feat/signing-gate` 同时推 main（不触发部署）。

## 4. 安装构建机与签名闸（第 1 步脚本）

```bash
# 开发机，RN-Server 仓库根目录，已切到刚推上去的那个提交
deploy/amos/signing-gate-rollout/0-bundle.sh /tmp/sg-deploy
scp -r /tmp/sg-deploy amos:/tmp/
ssh amos 'sudo bash /tmp/sg-deploy/rollout/1-install.sh /tmp/sg-deploy'
```

脚本最后打印各二进制与 apksigner 副本的 sha256（抄进离线记录），以及冒烟结果：`build-agent` 空环境、`build-runner` 无参数都应以 2 退出。

旧构建机的配置、二进制、`agent-key`、`backup-signing.key` 留存在 `/root/rn-build-agent-legacy-<日期>/`（root 0700），新链路稳定后按第 12 节销毁。

## 5. 新建机器、写令牌、启动（第 2 步脚本）

1. 控制台（平台管理员）「平台维护 → 打包机与签名闸 → 新建机器」，依次新建：

   | 名称 | 角色 | 主备 |
   | --- | --- | --- |
   | `amos-builder` | 构建机 | — |
   | `amos-signer-a` | 签名闸 | 主 |
   | `amos-signer-b` | 签名闸 | 备 |

   每台的令牌只在新建成功的弹层里显示一次。**先别关弹层**，或者把令牌暂存在你自己的密码管理器里，第 2 步要用。
2. 在**你自己的终端**登上 amos 执行：
   ```bash
   ssh -t amos 'sudo bash /tmp/sg-deploy/rollout/2-configure.sh'
   ```
   按提示依次粘贴 `amos-builder`、`amos-signer-a`、`amos-signer-b` 的令牌（不回显）。脚本写好 `/etc/rn-build-agent.env`（root 0600）、`/etc/rn-signer-a.env`、`/etc/rn-signer-b.env`（root:rn-signer-x 0640），启动两台签名闸（含检查进程 socket）与构建机，最后打印三台机器的 `show-key` 输出。
3. 令牌用完从暂存处删除；控制台弹层确认“已保存”后关闭。

## 6. 接受公钥、设定主签名闸、信任构建机

1. **pin 文件**：把 `amos-signer-a`、`amos-signer-b` 的 `show-key` 最后一行 JSON 抄进离线机器上的 pin 文件：
   ```json
   {"format":"rn-signer-pins/v1","signers":[ <amos-signer-a 那一行>, <amos-signer-b 那一行> ]}
   ```
   完整 64 个十六进制字符逐位核对。**离线工具只认这个文件。**
2. **控制台接受公钥**：「打包机与签名闸」里三台机器都在“待接受公钥”。逐台打开接受面板，手抄 `show-key` 输出里的完整指纹（签名闸要抄 X25519 与 Ed25519 两个），填原因，确认。
3. **主签名闸**：签名闸本机角色与控制台路由两处都要是主（`deploy/signer/README.md` 第 5 节）：
   ```bash
   ssh -t amos 'sudo systemctl stop rn-signer-a.service &&
                sudo -u rn-signer-a /opt/rn-signer/bin/signer promote --first --env-file /etc/rn-signer-a.env;
                sudo systemctl start rn-signer-a.service'
   ```
   控制台里 `amos-signer-a` 已经是主（新建时选的）。一分钟后机器卡片的“本机角色（上报）”应显示主。
4. **信任构建机**（两台都做）：从控制台抄 `amos-builder` 的机器 id（`mch_…`），粘贴 `build-agent show-key` 输出的完整 sha256：
   ```bash
   ssh -t amos 'sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-builder --builder-id mch_… --name amos-builder --env-file /etc/rn-signer-a.env'
   ssh -t amos 'sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-builder --builder-id mch_… --name amos-builder --env-file /etc/rn-signer-b.env'
   ```
5. 核对 `build-agent show-key` 里 `build runner:` 一行是 `separate user builder via sudo`。

## 7. 换服务端 unit（第 3 步脚本）

```bash
ssh amos 'sudo bash /tmp/sg-deploy/rollout/3-server-units.sh /tmp/sg-deploy'
```

去掉原备份方案的 `LoadCredential`，给服务端、扫链、迁移加上挡签名闸路径的 `InaccessiblePaths`，重启服务端（几秒钟不可用）与扫链。旧 unit 留存在 `/root/rn-foundation-units-previous-<日期>/`。

## 8. 逐个租户重置签名密钥（离线 + 控制台 + 签名闸）

每个租户做一遍（先 AnyFun，再 Predict）。

1. **离线机器**（不联网）：
   ```bash
   build-keystore create --pins pins.json --tenant AnyFun --package com.anyfun.foundation --alias anyfun-release --out-dir anyfun
   ```
   工具打印证书完整 sha256 与每个收件人指纹；口令写进 0600 文件、不打印。把**证书 sha256 记进密码管理器**。产出：`anyfun/keystore-upload.json`（上传用）、`.p12` 原件与口令文件。
2. **两个配置机密**（只做一次，在你自己的、没有自动化会话的终端里）：
   ```bash
   ssh amos "sudo grep -E '^(STORAGE_MASTER_KEY|DEVICE_IDENTITY_HMAC_KEY)=' /etc/rn-foundation.env" \
     | gpg --symmetric --no-symkey-cache --cipher-algo AES256 -o config-secrets.gpg
   gpgconf --kill gpg-agent
   ```
   把 `config-secrets.gpg` 拷到离线机器。
3. **打包保管**（全部租户都生成完再做一次）：离线机器上把各租户原件目录、`pins.json`、`config-secrets.gpg` 放进一个目录：
   ```bash
   tar -c vault | gpg --symmetric --no-symkey-cache --cipher-algo AES256 -o rn-signing-vault-2026-09-16.tar.gpg
   gpgconf --kill gpg-agent
   ```
   加密口令用密码管理器生成、只存密码管理器；加密包只放两个离线 U 盘，分开保管。两个 U 盘各取一份解开验证（证书指纹与密码管理器一致、pin 文件与 `show-key` 一致、两个配置机密的键都在），验证完擦除明文并 `gpgconf --kill gpg-agent`。
4. **控制台上传**：该租户控制台「配置中心 → 打包与签名 → 打包配置」签名密钥区上传 `keystore-upload.json`，核对页面显示的包名、证书完整指纹与密码管理器一致，填原因确认。页面会提示“换证书，老用户不能覆盖升级”——这是预期。
5. **两台签名闸确认**（交互终端，逐项输入第 0 节对照表里的值）：
   ```bash
   ssh -t amos 'sudo -u rn-signer-a /opt/rn-signer/bin/signer confirm --tenant AnyFun --env-file /etc/rn-signer-a.env'
   ssh -t amos 'sudo -u rn-signer-b /opt/rn-signer/bin/signer confirm --tenant AnyFun --env-file /etc/rn-signer-b.env'
   ```
   证书指纹**粘贴密码管理器里的值**，不接受 `yes`。
6. **就绪**：一两分钟内主签名闸自动试签。签名密钥区显示“就绪”、不就绪原因为空，主、备两行的试解、本机确认、信任根、试签都是通过。

## 9. 发第一个新签名的安装包

1. 该租户控制台「发布中心 → 打包任务」排一个安装包任务，版本号与 build 号都大于线上（AnyFun > 1.3.16 / 46，Predict > 1.0.6 / 7），且 build 号不超过第 8 步设的首签上限。控制台会弹“签名身份变更”确认层——证书确实换了，填原因确认。
2. 任务依次经过：排队中 → 已领取 → 构建中 → 待签名 → 签名中 → 成功。卡在“待签名”时看任务详情里列出的不就绪原因。
3. 下载产物核对：
   ```bash
   apksigner verify --print-certs <下载的 apk>   # 恰好 1 个签名者，证书 SHA-256 等于密码管理器里的值
   ```
4. 模拟器：卸载旧包 → 安装新包 → 用助记词恢复钱包 → App Links、热更新拉取正常。
5. 控制台「发布管理」发布这个版本（填原因）。**冻结窗口在第一个租户发出新包时结束**。通知现有用户卸载旧版、安装新版、用助记词恢复。
6. 仓库 `RN-App/tenants/<目录>/tenant.json` 的 `signerSha256` 改成新证书指纹（只用于本地 `android:verify`）。

## 10. 部署后核对清单

- [ ] `ssh amos 'sudo -u builder cat /var/lib/rn-signer-a/trust.jsonl'` 被拒（Permission denied）；`sudo -u builder ls /var/lib/rn-build-agent` 被拒
- [ ] `systemctl is-active rn-signer-a rn-signer-b rn-build-agent rn-foundation-server rn-foundation-indexer` 全部 active
- [ ] 控制台三台机器状态“已接受”，`amos-signer-a` 路由主、本机角色主；`amos-signer-b` 备
- [ ] 两个租户签名密钥区“就绪”
- [ ] 各签名闸 `signer list` 的记录行数与末行哈希抄进离线记录（`deploy/signer/README.md` 第 8 节）
- [ ] 第一个新包 `apksigner verify` 证书正确，模拟器安装与钱包恢复通过

## 11. 回滚

| 到了哪一步 | 怎么退 |
| --- | --- |
| 第 2、3 步（服务端 / 控制台已上线，构建机未动） | 推回上一版提交或 `deploy/amos/deploy.sh` 部署旧二进制；迁移 54 只加列、放宽状态值，旧代码能跑 |
| 第 4–7 步（构建机已迁移、签名闸已装） | 除上面外：`systemctl disable --now rn-signer-a rn-signer-b rn-signer-a-check.socket rn-signer-b-check.socket`；把 `/root/rn-build-agent-legacy-<日期>/` 里的 `rn-build-agent.env`、`rn-build-agent.service`、`build-agent.previous`、`agent-key` 放回原位（`agent-key` 回 `/var/lib/rn-build-agent/`，属 builder），`chown -R builder:builder /var/lib/rn-build-agent`，`daemon-reload` 后启动旧构建机；服务端 unit 从 `/root/rn-foundation-units-previous-<日期>/` 放回 |
| 第 8 步之后（新密钥已上传或已发包） | 不回退旧密钥（旧指纹永久拒绝）。只修复向前 |

## 12. 之后

- **第二次发布（迁移 55）**：新链路稳定运行后，把 `feat/signing-gate-release2` rebase 到当时的 main 单独发布。删除 `platform_backups` 表与退役配置行。
- **清理**：销毁 `/root/rn-build-agent-legacy-<日期>/`（含旧 `agent-key`、`BUILD_KEYSTORE_PASSPHRASE`）；`/etc/rn-foundation.env` 删掉 `BUILD_AGENT_TOKEN` 与全部 `BACKUP_*` 键（新服务端不读它们）；GitHub RN-App 的 4 个 `ANDROID_RELEASE_*` secret；开发机上旧密钥原件。
- **日常**：签名闸记录行数与末行哈希按 `deploy/signer/README.md` 第 8 节定期抄录；签名闸二进制只人工部署。

## 常见不就绪原因

控制台签名密钥区与排队被拒时列出的原因码，处理办法：

| 原因码 | 处理 |
| --- | --- |
| `KEYSTORE_NOT_CONFIGURED` / `KEYSTORE_LEGACY_FORMAT` | 按第 8 步上传离线工具产出的密钥文件 |
| `KEYSTORE_RECORD_INVALID` | 重新上传密钥文件；反复出现说明库被改过，查审计 |
| `RELEASE_IDENTITY_MISMATCH` | 发布身份与密钥不一致：重新上传密钥文件（会同时登记身份） |
| `PRIMARY_SIGNER_MISSING` | 控制台没有已接受的主签名闸：第 5、6 步 |
| `PRIMARY_SIGNER_NOT_RECIPIENT` | 密钥没有加密给主签名闸：pin 文件漏了它，离线 `build-keystore seal` 重新加密后上传 |
| `PRIMARY_SIGNER_LOCAL_ROLE_MISMATCH` | 控制台是主、签名闸本机不是主：在那台签名闸上 `signer promote`，或把路由切回 |
| `OTA_CERTIFICATE_NOT_CONFIGURED` / `APP_IDENTITY_INCOMPLETE` / `API_BASE_URL_INVALID` / `TRUST_ROOTS_INVALID` | 补齐 / 改正租户的 OTA 签名密钥与打包配置 |
| `PRIMARY_SIGNER_NOT_CHECKED` / `PRIMARY_SIGNER_TRIAL_SIGN_PENDING` | 等主签名闸下一轮检查（约一分钟）；一直不变看 `journalctl -u rn-signer-a` |
| `PRIMARY_SIGNER_DECRYPT_FAILED` | 密文不是加密给这台签名闸的当前公钥，或文件被改：核对 pin 文件后重新生成上传 |
| `PRIMARY_SIGNER_NOT_CONFIRMED` | 在主签名闸上 `signer confirm --tenant <slug>` |
| `TRUST_ROOTS_CHANGED` | 租户改了 API 地址、scheme 或 OTA 证书：核对无误后两台签名闸重新 `confirm` |
| `PRIMARY_SIGNER_TRIAL_SIGN_FAILED` | 看 `journalctl -u rn-signer-a`：多半是 JDK、apksigner 路径或权限检查 |
