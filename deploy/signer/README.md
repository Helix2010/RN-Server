# 签名闸部署与运维

设计：`docs/design/android-signing-gate-2026-09-16.md`（原设计）、`docs/design/android-signing-gate-automation-2026-09-16.md`
（部署与换密钥自动化，下称“自动化设计”）。

两种装法并存：

- **新机器：一条命令 + 控制台接受**（第 A–D 节）。安装包由服务端下发，`install.sh` 按实例名渲染
  `templates/` 里的 unit 与 env，`signer enroll` 用一次性注册码换令牌。unit 名 `rn-signer-<实例>.service`。
- **手工流程**（第 1–11 节）：amos 上已经在跑的 `amos-signer-a`、`amos-signer-b` 按它装好，unit 名
  `rn-signer-a/b.service`、`/etc/rn-signer-a/b.env` 不改；迁移到新流程只补信任记录（第 E 节）。

不管哪种装法，签名闸信什么（角色、受信签名闸与构建机、恢复公钥、确认过的租户与信任根、签过的版本号）
都只在它自己的本机记录里；服务端被攻破也改不了。**主备角色、信任哪台签名闸与构建机、信任根变更，都在签名闸本机确认**：
控制台登记的主备只决定服务端把任务派给谁；`signer enroll` 一律把新机器写成本机备、不信任任何签名闸。`rn-foundation-apply`、CI 部署账号 `rndeploy`
不得触及已安装的 `/opt/rn-signer`、`/etc/rn-signer-*`、`/var/lib/rn-signer-*`：已经在运行的签名闸不从服务端自动升级。

下面的命令都在**你自己的终端**里执行。令牌、口令、注册码不要经过 Claude Code 的 `!`、聊天、工单或截图。

## 文件

| 文件 | 安装到 | 属主 / 权限 |
| --- | --- | --- |
| `signer`、`signer-check`（构建产物） | `/opt/rn-signer/bin/` | root:root 0755 |
| `templates/rn-signer-@INSTANCE@.service`、`…-check.socket`、`…-check@.service` | `/etc/systemd/system/`（`@INSTANCE@` 换成实例名） | root:root 0644 |
| `templates/rn-signer-@INSTANCE@.env` | `/etc/rn-signer-<实例>.env` | root:rn-signer-<实例> 0640 |
| `rn-signer-a.service`、`rn-signer-b.service`（手工流程） | `/etc/systemd/system/` | root:root 0644 |
| `rn-signer-a-check.socket`、`rn-signer-a-check@.service`（b 同理，手工流程） | `/etc/systemd/system/` | root:root 0644 |
| `rn-signer.env.example` → `rn-signer-a.env`、`rn-signer-b.env`（手工流程） | `/etc/` | root:rn-signer-a 0640（b 同理） |
| apksigner.jar 副本 | `/opt/rn-signer/build-tools/35.0.0/lib/apksigner.jar` | root:root 0644，上级目录 0755 |
| 本 README | `/opt/rn-signer/README.md` | root:root 0644 |

状态目录 `/var/lib/rn-signer-<实例>`（本机私钥、`trust.jsonl`、`signed.jsonl`）与运行时目录 `/run/rn-signer-<实例>`
（tmpfs，明文 keystore 只出现在这里，签完即删）0700，属于 `rn-signer-<实例>`。

## A. 新机器：一条命令 + 控制台接受

前提：平台已经登记了离线恢复公钥（第 C 节）；没有登记时控制台不允许新建签名闸。

1. 控制台「平台维护 → 打包机与签名闸」新建签名闸（名字、主或备；这里的主备只决定路由，本机角色见第 4 步），
   得到一次性安装命令（60 分钟有效，只能用一次，过期在控制台重发）：

   ```bash
   curl -fsSL https://api.anyfun.win/v1/machine-setup/install.sh | sudo bash -s -- \
     --server https://api.anyfun.win --code rne_… --recovery-sha256 <从密码管理器粘贴恢复公钥指纹>
   ```

   `--recovery-sha256` 从密码管理器粘贴，**不取控制台显示的值**。生产环境再加 `--expect-sha256 <安装包清单 sha256>`，
   先与 CI 构建日志核对。

2. 在服务器本机执行这条命令。`install.sh` 检查前提（systemd、JDK 17、tmpfs 的 `/run`）、下载并核对安装包、
   建系统用户 `rn-signer-<实例>`（实例名默认取机器名，用户名最长 32 字符）、渲染 `templates/` 里的 unit 与 env，
   然后以 root 执行：

   ```bash
   RN_ENROLLMENT_CODE=<注册码> /opt/rn-signer/bin/signer enroll --server https://api.anyfun.win \
     --env-file /etc/rn-signer-<实例>.env --recovery-sha256 <指纹> [--name-check <机器名>]
   ```

   注册码经环境变量 `RN_ENROLLMENT_CODE` 传入，不进进程参数（`ps` 看不到）；程序读完就从自己的环境里删掉，降权执行的
   子进程拿不到。`--code rne_…` 仍然可用，两者都给且不同会拒绝。

   `signer enroll` 做这几件事：

   - 核对 env 文件是 root 所有、属组是签名闸用户组、组不可写；状态目录不存在就以签名闸用户建 0700；
   - 查询注册码（不消耗），核对 `--recovery-sha256` 是服务端登记的一把恢复公钥、机器名；
   - **以签名闸用户身份**生成本机两把私钥与本机记录，写入初始角色**备**（`mode enroll`；控制台登记成主也一样）、
     受信恢复公钥（`mode enroll`）。**不信任任何签名闸**：服务端给的主备与当前主签名闸只用来打印下一步提示（机器名），
     不写进本机记录，它的指纹也不显示；
   - 用注册码换长期机器令牌，**直接原子替换 env 文件**写进 `SIGNER_SERVER_URL`、`SIGNER_NAME`、`SIGNER_MACHINE_TOKEN`
     （令牌不经过屏幕，env 里其余行原样保留）；
   - 打印机器名、X25519 与 Ed25519 完整指纹，以及按控制台登记的主备给出的下一步命令。

   重复执行是安全的：已经注册过（env 有令牌、本机记录已初始化）直接退出 0；换令牌之前中断会留下
   `enroll.incomplete`，这时 `signer run` 拒绝启动，在控制台重发注册码后重跑即可（那套没换到令牌的密钥会被清掉重来）。
   状态目录里已经有本机记录、env 却没有令牌（例如手工装过的机器）时拒绝，按新机器处理。

3. 控制台机器卡片显示待接受的完整指纹：与安装输出**逐位**核对后点「接受」。接受只影响服务端路由。

4. 在签名闸本机定角色、补信任（交互终端；下面的 `signer …` 都是
   `sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer … --env-file /etc/rn-signer-<实例>.env`，细节见第 B 节）：

   - **平台第一台主签名闸**：先停服务，在本机 `signer promote --first`，再启动（第 5 节）。只在控制台登记成主、
     本机没 promote 时，控制台显示主签名闸不就绪（`PRIMARY_SIGNER_LOCAL_ROLE_MISMATCH`），任务停在待签名。
     **替换已有的主不要用 `--first`**：按第 9 节 `promote --import` 或 `--manual`（`--first` 会丢掉旧主的签名记录）。
   - **新备签名闸**：在备本机 `signer trust-peer --peer <主>`，粘贴**主签名闸本机** `signer show-key`（或它的安装输出）
     里的两个指纹；在主签名闸本机 `signer trust-peer --peer <新备>`，粘贴新备安装输出里的两个指纹。
     安装输出提示“服务端还没有主”时，先装主，再回到这一步。备信任主之前不接受任何生成的密钥。
   - **构建机**：每台签名闸本机 `signer trust-builder --builder <构建机>`。
   - 新备拿不到已有租户的密钥，见第 B 节「已知限制」。

出站地址：模板不写死 `IPAddressDeny/Allow`。上线后按 API 与 DNS 解析器地址加 drop-in
`/etc/systemd/system/rn-signer-<实例>.service.d/network.conf` 收紧（与服务端同机走回环时写 `IPAddressAllow=localhost`）。

## B. 签名闸之间的信任、构建机信任

签名闸之间的信任只由本机 `trust-peer` 写入（`enroll` 不写）。它在两个方向上各有用途：

- 主签名闸生成的新密钥**只加密给本机信任的签名闸**（本机默认信任自己）和本机信任的恢复公钥。服务端多登记一台签名闸，
  新密钥也不会加密给它。
- 备签名闸只自动接受**本机信任的签名闸**签过生成签名的密钥。
- **本机是主时只自动接受本机自己生成的密钥**：主为了加密给备而信任备，备（或另一台自认为是主的机器）生成的密钥
  在主上一律要 `signer confirm`。

**主签名闸信任新备**（在主签名闸本机，交互终端）：

```bash
sudo -u rn-signer-<主实例> /opt/rn-signer/bin/signer trust-peer --peer <新备机器名> --env-file /etc/rn-signer-<主实例>.env
```

程序从服务端取这台签名闸已接受的公钥，先只显示机器 id 与主备；粘贴**新机器安装输出里**的 X25519 与 Ed25519 完整指纹，
与服务端已接受的一致才写入。已有租户的密钥不会自动补加密给新备，见下面「已知限制」。

**备签名闸信任主**（在备本机）：

```bash
sudo -u rn-signer-<备实例> /opt/rn-signer/bin/signer trust-peer --peer <主机器名> --env-file /etc/rn-signer-<备实例>.env
```

指纹取**主签名闸本机** `signer show-key` 的输出（或主的安装输出），不取控制台。以后换了主签名闸（第 9 节），在每台剩下的备上
先 `signer trust-peer --revoke --peer <旧主>`，再 `signer trust-peer --peer <新主>`。

**撤销**：`signer trust-peer --revoke --peer <机器名> --reason "…"`。`promote` 会自动撤销被取代的旧主（第 9 节）。
被撤销的机器要重新当签名闸用，只能按新机器重装（新密钥），再在各签名闸上 `trust-peer`；不要对它的旧密钥重新 `trust-peer`。

**信任构建机**（每台签名闸本机都要做）：

```bash
sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer trust-builder --builder <构建机机器名> --env-file /etc/rn-signer-<实例>.env
```

机器 id 与出处公钥从服务端取，粘贴构建机安装输出里的出处公钥 sha256，一致才写入。旧写法
`--builder-id mch_… --name …`（粘贴两次）照常可用。

两台签名闸在同一台机器上（开发阶段 amos）时，分别以两个用户各执行一次（主信任备、备信任主）。

`trust-peer`、`trust-recovery`、`trust-builder`、`confirm` 可以与正在运行的 `signer run` 同时执行；
`signer list` 显示本机的全部信任。每次执行（含 `--revoke`）之后按第 8 节抄录记录文件的行数与末行哈希。

### 已知限制：后加或替换的签名闸拿不到已有租户的密钥

密钥只在**生成时**封装给当时本机信任的签名闸与恢复公钥。之后新加的备、提升后补的备、重装的机器，服务端的密文里都
没有发给它的那一份：它对这些租户一直显示没有密钥，主签名闸出事时它接不了手。（提升上来的主不受影响：它原来就是收件人。）

现状下的临时办法（证书不变，已安装的 App 照常升级）：

1. 离线机器上 `build-keystore recover … --expect-certificate-sha256 <已发布 App 的证书>` 解出原件（第 C 节）；
2. `build-keystore seal --pins <pin 文件> --p12 … --password-file …` 加密给**所有**签名闸（新旧都写进 pin 文件，
   指纹取各机器本机 `signer show-key`，不取控制台）；
3. 控制台「导入已有密钥（高级）」上传；
4. 每台签名闸本机 `signer confirm --tenant …`（粘贴已发布 App 的证书 sha256，信任根按离线记录输入）。

`seal` 只加密给 pin 文件里的签名闸：导入之后服务端的密文里没有恢复公钥那一份。第 1 步用过的导出文件（同一张证书）
留着，以后恢复仍用它。**不要为此点「生成签名密钥」**：那会换证书，已安装的 App 覆盖升级不了。

由主签名闸在本机把已确认的同一张证书重新封装给新信任的签名闸（“同证书重新封装”）会在下一轮实现。

## C. 离线恢复密钥（整个平台一次）

取代“每个租户的原件进 U 盘”：签名闸生成的每把租户密钥都加密给恢复公钥，签名闸全部丢失时用恢复私钥解开。

**生成**（离线机器，交互终端；口令手输两遍、不回显，非终端拒绝）：

```bash
build-keystore recovery-key create --out /media/usb1/rn-recovery --name platform-recovery-2026
```

- 写出 `recovery-private.key`（口令加密，scrypt N=2^17 + AES-256-GCM，0600）与 `recovery-public.json`，打印完整 sha256。
- 口令与恢复公钥 sha256 记进密码管理器；`recovery-private.key` 放两个离线 U 盘（与 `STORAGE_MASTER_KEY` 的加密包一起）。

**登记**：控制台「平台维护 → 签名闸恢复密钥」粘贴 `recovery-public.json` 的内容。

**签名闸信任**：新机器由安装命令的 `--recovery-sha256` 写入；已经在运行的签名闸在本机：

```bash
sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer trust-recovery --env-file /etc/rn-signer-<实例>.env
```

粘贴密码管理器里的恢复公钥 sha256，服务端有这把公钥、未吊销、公钥与指纹一致才写入。更换恢复密钥：先登记新的、
每台签名闸 `trust-recovery` 新的，再 `signer trust-recovery --revoke --recovery-sha256 <旧指纹> --reason "…"`
（撤销时再粘贴一次旧指纹确认）。

**恢复**（签名闸全部丢失，或给后加的签名闸补密钥）：

1. 控制台租户「打包与签名 → 导出密文文件」，把导出的 JSON 拷到离线机器（导出文件可能只含发给恢复公钥的那一份密文，照样能用）。
2. 取**已发布 App 的签名证书 sha256**，这是唯一的离线锚点：恢复公钥是公开的，谁都能把自己的密钥封给它、冒充导出文件，
   文件本身证明不了来源。取值来源（**不取控制台**）：
   - RN-App 仓库 `tenants/<slug>/tenant.json` 的 `signerSha256`，取 git 历史里提交过的值（`git log -p -- tenants/<slug>/tenant.json`
     核对是谁、何时改的）；
   - 或已发布的 APK / 已安装设备上导出的 APK：`apksigner verify --print-certs <apk>` 的 `certificate SHA-256 digest`。
3. 离线机器：

   ```bash
   build-keystore recover --recovery-key /media/usb1/rn-recovery/recovery-private.key \
     --upload AnyFun-keystore-export.json --out-dir ./anyfun-recovered \
     --expect-certificate-sha256 <已发布 App 的证书 sha256>
   ```

   密文文件记录的证书不是它：不问口令直接拒绝。输入恢复口令后，解出的 PKCS#12 里的证书不是它：拒绝。两种情况都不写任何文件。
   通过后解出 `<别名>.p12`、`<别名>.password`、`certificate.pem`（目录 0700、文件 0600）；程序还核对明文与密文文件的
   租户、包名、别名、证书一致，PKCS#12 用口令与别名打得开。
4. 按第 7 节 `build-keystore seal --pins <新 pin 文件> …` 加密给新签名闸，控制台「导入已有密钥（高级）」上传，
   新签名闸 `signer confirm`。

## D. 换密钥：控制台一键

控制台租户「打包与签名」点「生成签名密钥」。主签名闸（本机记录是主）在下一轮 `keystore-checks`（一分钟内）处理：

- **租户在本机从没确认过（任何包名，含已被取代的确认）**：首次信任服务端的信任根，minSdk/targetSdk 下限 24/28；
- **包名已确认且服务端信任根摘要与记录相同**：沿用本机确认的信任根与 SDK 下限，只换证书；
- **租户确认过、包名没确认过**（控制台换了包名）：不生成，回报 `TRUST_ROOTS_CHANGED`。新包名的密钥走「导入已有密钥」
  并在每台签名闸 `signer confirm`；
- 首签 versionCode 上限：本机对这个包名签过就取历史最大值 + 100，否则取服务端已发布的最大 build 号
  （`publishedMaxBuildNumber`）+ 100。后者是服务端的值：服务端可以把它压低或抬高，让新证书的首个安装包签不了，
  或让一个 versionCode 很大的包签出去、此后的版本号空间用完而发不了版。这是**拒绝服务，不是越权**：换了证书老用户
  本来就升不上去，本机的绝对上限（`SIGNER_MAX_VERSION_CODE`）与跳号上限照样生效。发现不对就在主签名闸 `signer confirm`
  按离线发布记录输入首签上限；
- 生成 RSA 4096，只加密给本机、本机信任且服务端 active 的签名闸、本机信任且服务端未吊销的恢复公钥，签生成签名交回；
  服务端接受后本机写自动确认（`signer list` 里 `confirmedBy` 为 `auto:first-generation` 或 `auto:regenerated`）。
- 主签名闸这次确认用的信任根摘要、SDK 下限、首签上限，以及被替换的证书（首次生成为空）写进每份密文的明文里。
  密文被生成签名覆盖，服务端改不了。
- 生成之后若要更新 RN-App `tenants/<slug>/tenant.json` 的 `signerSha256`，证书 sha256 取**主签名闸本机 `signer list`**
  （`confirmed tenants` 里这个包名的 `certificate`，`confirmedBy auto:…`）的输出，不取控制台。这个值以后就是恢复时的
  `--expect-certificate-sha256`（第 C 节）。
- 自动确认会往 `trust.jsonl` 追加一行：生成或自动接受之后按第 8 节抄录。

生成失败时控制台显示签名闸报回的原因：

| 原因 | 怎么办 |
| --- | --- |
| `TRUST_ROOTS_CHANGED` | 租户改了 API 地址、scheme、OTA 证书等（或包名换了租户）：先在主签名闸 `signer confirm --tenant …`，再点生成。已确认的租户换了包名：新包名不首次信任，导入密钥后各签名闸 `signer confirm` |
| `RECOVERY_KEY_NOT_PINNED` | 主签名闸没有信任恢复公钥，或它信任的恢复公钥在服务端被吊销：`signer trust-recovery` |
| `NOT_LOCAL_PRIMARY` | 控制台路由的主签名闸本机记录不是主：`signer promote`，或在控制台切回 |
| `GENERATION_FAILED` | 看 detail（服务端拒收、信任根格式不对等）与主签名闸 journal |

**备签名闸**在 `keystore-checks` 里拿到新密文时自动接受（本机是主时只接受本机自己生成的，见第 B 节）。条件：

- 生成者是本机信任的签名闸（`trust-peer`），生成签名验证通过；
- 签名覆盖的上传文件里，正是发给本机的这一份；
- 这张证书没为这个包名确认过；
- 按密文里主签名闸写下的参数核对：
  - 本机已有确认时，被替换的证书必须是本机当前的证书，信任根摘要必须与本机相同。这样可以挡住服务端重放更早的一次生成，
    也挡住主备信任根不一致的情况。确认沿用本机的信任根与 SDK 下限。
  - 本机没有这个包名的确认时（新加的备），租户在本机也必须从没确认过，服务端给的信任根摘要必须等于主签名闸确认的摘要。
    确认采用主签名闸的 SDK 下限与首签上限。

写入的确认记为 `auto:peer-generated:<主签名闸机器名>`。不满足时，控制台检查项显示原因，仍可在本机 `signer confirm`。

以下情况需要人工处理：
- 备签名闸离线期间主签名闸换了两次密钥：服务端只保留最新一份，它替换的不是备本机的证书，所以不会自动接受，
  要在备上 `signer confirm`。
- **新备只按收到的第一份生成首次信任**（已知限制）：新备本机没有确认，没法判断收到的是不是主签名闸最新的一份。服务端扣住
  后续的生成、或给新备一份已被取代的旧生成，新备就确认在旧证书上；之后主签名闸再换密钥，替换的不是新备本机的证书，新备不再
  自动接受。后果是主备证书不一致、备接不了手（**拒绝服务**），不会签错：主签的包照常，新备本来就不认领任务。
  现象：新备的检查项确认的证书与主不同，或报 `replaces certificate … run signer confirm`。处理：对照主签名闸本机
  `signer list` 的证书，在新备本机 `signer confirm --tenant …`。
- 离线导入的密钥（没有生成签名）：照旧 `signer confirm`。
- 主签名闸上出现别的签名闸生成的密钥（报 `only accepts keystores it generated itself`）：先查清是谁生成的；确实要用就在主上
  `signer confirm`。

## E. amos 现有部署迁移

`amos-signer-a`（主）、`amos-signer-b`（备）不重装，unit 名与 `/etc/rn-signer-a/b.env` 不改：

1. **先部署服务端**（`keystore-checks` 接受 `trust`、有 `/v1/signer/peers` 与生成接口的版本）：新签名闸每轮上报都带
   `trust`，旧服务端按严格解码会拒收，控制台就收不到检查结果。然后按第 1、2 节构建并替换 `/opt/rn-signer/bin/signer`、
   `signer-check`（新版本能读现有本机记录），`systemctl restart rn-signer-a rn-signer-b`，journal 里 `local records verified` 正常、
   没有 `keystore checks failed`。
2. 离线生成恢复密钥（第 C 节），控制台登记。
3. 两台都信任恢复公钥：

   ```bash
   sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-recovery --env-file /etc/rn-signer-a.env
   sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-recovery --env-file /etc/rn-signer-b.env
   ```

4. 互相信任（指纹取各自 `signer show-key` 的输出，不取控制台）：

   ```bash
   sudo -u rn-signer-b /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-b.env   # 记下 B 的两个指纹
   sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-peer --peer amos-signer-b --env-file /etc/rn-signer-a.env
   sudo -u rn-signer-a /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-a.env   # 记下 A 的两个指纹
   sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-peer --peer amos-signer-a --env-file /etc/rn-signer-b.env
   ```

5. `signer list` 核对两台的 `trusted signing gates`、`trusted recovery keys`，抄录记录文件行数与末行哈希（第 8 节）。
   注意：本机记录写入新类型（受信签名闸、恢复公钥、自动确认、promote 自动撤销旧主）之后，旧版 `signer` 会以
   unknown record type 或记录校验失败拒绝启动，**二进制不能再退回旧版本**；要退只能连同状态目录一起按新机器重装。
   控制台机器卡片的 `reportedTrust` 不再提示缺信任。
6. 控制台对 AnyFun、Predict 各点一次「生成签名密钥」；两台检查项都显示已确认、主试签通过后，排第一个新签名的安装包，
   按上线手册验证并发布。

## 1. 构建（离线记录二进制 sha256）

以下第 1–11 节是手工流程；第 1 节的构建、第 7–11 节的日常与故障两种装法通用。

```bash
git fetch --tags && git checkout <审阅过的 tag>
cd signing
GOTOOLCHAIN=go1.24.6 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/rn-signer/ ./cmd/signer ./cmd/signer-check
GOTOOLCHAIN=go1.24.6 go vet ./... && GOTOOLCHAIN=go1.24.6 go test -race ./...
sha256sum /tmp/rn-signer/signer /tmp/rn-signer/signer-check   # 抄进离线记录
```

固定 Go 版本（上面的 `go1.24.6` 换成当次审阅确定的版本，写进离线记录）；同一 tag、同一工具链、`-trimpath`
构建出的 sha256 应当一致，换人构建一次核对。

离线工具 `build-keystore` 在离线机器上用同样方式构建：`go build -trimpath -buildvcs=false ./cmd/build-keystore`。

## 2. 安装（amos，root）

```bash
# 系统用户：没有登录 shell，没有家目录
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rn-signer-a
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin rn-signer-b

install -d -o root -g root -m 0755 /opt/rn-signer /opt/rn-signer/bin /opt/rn-signer/build-tools/35.0.0/lib
install -o root -g root -m 0755 /tmp/rn-signer/signer /tmp/rn-signer/signer-check /opt/rn-signer/bin/
sha256sum /opt/rn-signer/bin/*   # 与离线记录核对

# apksigner.jar：从 Google 的 build-tools 35.0.0 包里取，复制成 root 拥有的副本。
# 不要把 SIGNER_BUILD_TOOLS_DIR 指向构建机那份 SDK：构建机用户能改的 jar 等于能在签名闸里执行代码。
# 签名闸启动时检查 JAVA_HOME 整棵目录树（含符号链接目标）、apksigner.jar（及 signer-check）与每一级上级目录
# 只能由 root 或签名闸用户修改；运行时目录必须在 tmpfs 上。
install -o root -g root -m 0644 <sdk>/build-tools/35.0.0/lib/apksigner.jar /opt/rn-signer/build-tools/35.0.0/lib/
sha256sum /opt/rn-signer/build-tools/35.0.0/lib/apksigner.jar   # 记进离线记录
# JDK 用系统包（root 拥有）：apt install openjdk-17-jre-headless

cd deploy/signer
install -o root -g root -m 0644 rn-signer-a.service rn-signer-b.service \
  rn-signer-a-check.socket rn-signer-b-check.socket \
  'rn-signer-a-check@.service' 'rn-signer-b-check@.service' /etc/systemd/system/
install -o root -g root -m 0644 README.md /opt/rn-signer/README.md
systemd-analyze verify /etc/systemd/system/rn-signer-a.service /etc/systemd/system/rn-signer-b.service \
  /etc/systemd/system/rn-signer-a-check.socket /etc/systemd/system/rn-signer-b-check.socket
```

## 3. 登记机器、写配置

> 控制台现在新建机器时给一次性安装命令，不再显示长期令牌：新机器按第 A 节装。本节保留为 amos 现有两台的装法记录。

1. 平台管理员在控制台「平台维护 → 打包机与签名闸」新建两台签名闸：`amos-signer-a`（primary）、
   `amos-signer-b`（standby）。令牌只显示一次。
2. 在你自己的终端写 env（令牌不进命令行参数，不回显）：

   ```bash
   install -o root -g rn-signer-a -m 0640 rn-signer.env.example /etc/rn-signer-a.env
   read -rsp 'amos-signer-a token: ' TOKEN; echo
   sed -i "s|^SIGNER_MACHINE_TOKEN=.*|SIGNER_MACHINE_TOKEN=\"$TOKEN\"|" /etc/rn-signer-a.env; unset TOKEN
   vi /etc/rn-signer-a.env   # 其余键：SIGNER_NAME、目录、SIGNER_CHECK_SOCKET=/run/rn-signer-a-check.sock
   ```

   B 同理（`/etc/rn-signer-b.env`，`root:rn-signer-b`，`/var/lib/rn-signer-b`、`/run/rn-signer-b`、`/run/rn-signer-b-check.sock`）。
   开发阶段与服务端同机：`SIGNER_SERVER_URL="http://127.0.0.1:13080"`，unit 里 `IPAddressAllow=localhost`。
   独立虚拟机上用 drop-in 把 `IPAddressAllow=` 改成 API 地址与 DNS 解析器地址，`SIGNER_SERVER_URL` 用 https。

## 4. 首次启动、show-key、pin 文件、控制台接受

```bash
systemctl daemon-reload
systemctl enable --now rn-signer-a-check.socket rn-signer-a.service
systemctl enable --now rn-signer-b-check.socket rn-signer-b.service
journalctl -u rn-signer-a -n 20   # "generated this signing gate's machine keys"、"waiting for a platform admin"
```

首次启动生成两把本机私钥（X25519 解密钥密文，Ed25519 给本机记录签名）并登记公钥，状态 `pending_key`。

```bash
sudo -u rn-signer-a /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-a.env
```

- 把最后一行 JSON 手抄/拷贝进离线机器上的 pin 文件 `{"format":"rn-signer-pins/v1","signers":[…]}`，
  **完整 64 位指纹**逐位核对。离线工具只认 pin 文件。
- 控制台「接受公钥」时核对 `X25519 sha256` 与 `Ed25519 sha256` 与这里一致。控制台接受只影响路由。

## 5. 设定主签名闸

角色有两处，**两处都要做、而且要一致**：

- **签名闸本机记录**（`signer promote`）：决定这台机器会不会去认领任务。本机记录是备的机器从不认领。
- **控制台的主备路由**（「平台维护 → 打包机与签名闸」切换主备）：决定服务端把任务派给谁。

签名闸每轮上报 `keystore-checks` 时带上本机记录里的角色（`localRole`：`primary` 或 `standby`）。控制台切了主、
本机还没 `promote`（或反过来）时，控制台显示这台签名闸**不就绪**并写明原因（本机记录不是主），任务不会被当作
"等它来领取"。只做一边，任务会一直停在已构建。

新机器默认是备（按第 A 节 `signer enroll` 装的机器不管控制台登记成什么也是备），第一台主在 A 上执行（交互终端），
然后在控制台把 A 设为主：

```bash
sudo -u rn-signer-a /opt/rn-signer/bin/signer promote --first --env-file /etc/rn-signer-a.env
```

B 保持备：它照样试解、确认、试签并上报，但从不认领任务。

`promote` 与 `abandon` 会和正在处理任务的 `signer run` 竞争本机记录，必须先停服务（`systemctl stop rn-signer-a.service`），
程序拿不到运行锁会直接拒绝；做完再 `systemctl start`。第一次 `promote --first` 时服务已经在跑，同样先停再起。
`confirm`、`trust-builder`、`list`、`show-key` 不用停。

## 6. 信任构建机（两台都要做）

在构建机上 `build-agent show-key` 读出出处公钥的完整 sha256；控制台里查到那台构建机的机器 id。

```bash
sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-builder --builder-id mch_… --name amos-builder --env-file /etc/rn-signer-a.env
sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-builder --builder-id mch_… --name amos-builder --env-file /etc/rn-signer-b.env
```

指纹要粘贴两次。撤销：`signer trust-builder --revoke --builder-id mch_… --reason "…"`，此后它交付的包一律拒签。

## 7. 租户密钥：离线生成 → 上传 → confirm → 试签

1. 离线机器：`build-keystore create --pins pins.json --tenant AnyFun --package com.anyfun.foundation --alias anyfun-release`，
   证书 SHA-256 记进密码管理器，原件按设计「原件与配置机密的保管」打包。已有原件（例如之前在 Android Studio 里生成的）
   用 `build-keystore seal`，先看下面「已有原件的格式要求」。
2. 控制台上传 `keystore-upload.json`，登记包名与证书指纹。
3. 分别在 A、B 上确认（交互终端，stdin 必须是 TTY）：

   ```bash
   sudo -u rn-signer-a /opt/rn-signer/bin/signer confirm --tenant AnyFun --env-file /etc/rn-signer-a.env
   ```

   - 程序用本机私钥解开发给本机的密文、自己算证书指纹；**粘贴密码管理器里的证书 SHA-256**（不接受 yes）。
   - 信任根逐项**由你输入/粘贴离线记录里的值**：API origin、OTA 证书 SHA-256、bootstrap 签名地址、
     App Links host、scheme、渠道、applicationId、minSdk/targetSdk 下限、首签 versionCode 上限。
     服务端的值只作对照，与你输入不同的会标 `DIFFERS`。
   - API origin 不写默认端口：`https://api.example.com`，不是 `https://api.example.com:443`（RN-App 按 WHATWG URL
     派生 App Links host 时会去掉 `:443`，两种写法会得出不同的 host 与摘要，所以一律拒绝显式 `:443`）。
   - minSdk 下限至少 24（签名闸只签 v2/v3），targetSdk 下限至少 28（明文流量缺省关闭）。
   - 同一包名只有一份有效确认：重新 confirm（例如换证书、改信任根）会取代旧的，程序会显示被取代的那份；
     换了证书后旧证书不再能签。
   - 服务端发来的字符串格式不对时程序直接退出、不显示原文（防终端控制字符伪造屏幕）。
4. `signer run` 一分钟内对确认过的密钥做试签（现场合成最小 APK，签完 verify 比对证书，文件只在
   `/run/rn-signer-a` 里、用完即删）。控制台显示「主、备均已确认，主试签通过」后这把密钥才算上线。

租户改了 `apiBaseUrl` 或 OTA 证书后，主签名闸会对该租户的任务报「暂不能签」（`TRUST_ROOTS_NOT_CONFIRMED`），
直到重新 `confirm`。

### 已有原件的格式要求（seal 之前）

`build-keystore` 与签名闸用的 PKCS#12 实现只依赖 Go 标准库，**只接受**：

- 文件是 PKCS#12（不是 JKS）；恰好一把私钥，带别名（friendlyName），别名匹配 `^[A-Za-z0-9._-]{1,64}$`；
- 私钥与证书的加密是 PBES2（PBKDF2-HMAC-SHA1/SHA-2 + AES-128/192/256-CBC）；
- 有 MAC（HMAC-SHA1/SHA-256/384/512，PKCS#12 KDF），不接受 PBMAC1；
- 仓库口令与私钥口令相同（PKCS#12 在 Java 里只有一个口令）。

JDK 12 及以上的 keytool、OpenSSL 3 的默认输出满足这些。**JDK 11 及更早的 keytool、OpenSSL 1.x、老版本 Android Studio**
生成的 `.p12` 用 RC2-40 / 3DES（`pbeWithSHAAnd40BitRC2-CBC`、`pbeWithSHAAnd3-KeyTripleDES-CBC`），`seal` 会报
「原件用的是老式加密」；`.jks` 更是直接读不了。这两种都在离线机器上**重新导出**一份 AES 的 PKCS#12，原件保持不动。

口令一律放在文件里（第一行是口令），不进命令行参数、不进 shell 历史。文件放在 tmpfs 上，用完删除：

```bash
umask 077
d=$(mktemp -d /dev/shm/rekey.XXXXXX)
( read -rsp '原件口令: ' P; echo; printf '%s\n' "$P" > "$d/src.pass" )        # printf 是 shell 内建，不产生进程参数
( read -rsp '新文件口令: ' P; echo; printf '%s\n' "$P" > "$d/dest.pass" )
```

用 keytool（JDK 17，原件是 `.jks` 或老式 `.p12` 都行；JKS 的私钥口令与仓库口令不同时再加一个 `-srckeypass:file`）：

```bash
keytool -importkeystore \
  -srckeystore anyfun-release-old.jks -srcstoretype JKS -srcstorepass:file "$d/src.pass" \
  -srcalias anyfun-release \
  -destkeystore anyfun-release-aes.p12 -deststoretype PKCS12 -deststorepass:file "$d/dest.pass" \
  -destalias anyfun-release \
  -J-Dkeystore.pkcs12.keyProtectionAlgorithm=PBEWithHmacSHA256AndAES_256 \
  -J-Dkeystore.pkcs12.certProtectionAlgorithm=PBEWithHmacSHA256AndAES_256 \
  -J-Dkeystore.pkcs12.macAlgorithm=HmacPBESHA256
```

（原件是 `.p12` 时把 `-srcstoretype JKS` 换成 `PKCS12`。三个 `-J-D` 在 JDK 12+ 上本来就是默认值，写出来是为了防止
`java.security` 被改过。）

或者用 OpenSSL 3（只适用于原件是 `.p12`；私钥经管道传递，不落盘）：

```bash
openssl pkcs12 -legacy -in anyfun-release-old.p12 -passin "file:$d/src.pass" -nodes \
  | openssl pkcs12 -export -name anyfun-release \
      -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256 -iter 210000 \
      -passout "file:$d/dest.pass" -out anyfun-release-aes.p12
```

`-name` 必须给：它就是别名，签名闸按别名找条目。然后核对证书没变、加密上传：

```bash
keytool -list -v -storetype PKCS12 -keystore anyfun-release-aes.p12 -storepass:file "$d/dest.pass" | grep 'SHA256:'
# 与密码管理器里记的证书 SHA-256 逐位核对（keytool 的写法带冒号、大写）
build-keystore seal --pins pins.json --p12 anyfun-release-aes.p12 --password-file "$d/dest.pass" \
  --tenant AnyFun --package com.anyfun.foundation --alias anyfun-release
rm -rf "$d"
```

`seal` 打印的证书 SHA-256 也要与离线记录一致。新导出的 `anyfun-release-aes.p12` 与它的口令按「原件与配置机密的保管」
和原件一起保管。

## 8. 日常

```bash
sudo -u rn-signer-a /opt/rn-signer/bin/signer list --env-file /etc/rn-signer-a.env   # 角色、受信构建机、确认、签名记录
journalctl -u rn-signer-a -u 'rn-signer-a-check@*'
```

拒签结果在控制台任务详情里：

- **暂不能签**（release，不计次）：`SIGNER_NOT_PRIMARY`、`SIGNER_NOT_READY`、`CERTIFICATE_NOT_CONFIRMED`、`TRUST_ROOTS_NOT_CONFIRMED`、`SIGNER_SHUTTING_DOWN`
- **违规**（reject violation，终态失败并审计）：策略码（`TRUST_ROOT_MISMATCH`、`PERMISSION_NOT_ALLOWED`、`MANIFEST_ELEMENT_NOT_ALLOWED`、
  `OTA_CONFIGURATION_NOT_ALLOWED`、`VERSION_CODE_*`、`BUILDER_NOT_TRUSTED`…）、`KEYSTORE_IDENTITY_MISMATCH`、
  `VERSION_CODE_ALREADY_RESERVED`、`VERSION_CODE_OUT_OF_BOUNDS`、`RESERVATION_CONFLICT`、`JOB_ALREADY_COMPLETED`、`SERVER_REJECTED_SIGNED_PACKAGE`
- **临时错误**（reject transient，签名编号到 2 判失败）：`CHECKER_FAILED`、`DOWNLOAD_FAILED`、`UNSIGNED_CHANGED_BEFORE_SIGNING`、
  `RUNTIME_FILES_FAILED`、`APKSIGNER_FAILED`、`SIGNED_VERIFY_FAILED`、`UPLOAD_FAILED`、`UPLOAD_MISMATCH`、`COMPLETE_FAILED`

生成与自动接受（第 D 节）的日志：`generating a keystore`、`generated keystore accepted by the server and confirmed locally`、
`keystore generation refused`（带 code）、`accepted a keystore generated by a trusted signing gate`、
`a generated keystore was not accepted automatically`（带原因）、`a trusted signing gate is not active on the server …`
（受信的签名闸在服务端不是 active，这次新密钥没加密给它）。

服务端的几个错误码由签名闸自己处理：`SIGNED_ARTIFACT_REPLACED` 原地重新 complete；`SIGNED_ARTIFACT_MISSING`
重新上传（最多 3 轮）；`UPLOAD_STORAGE_FAILED`、`UPLOAD_INTERRUPTED` 原地重试上传。

**令牌被拒**：任何接口（包括公钥登记）收到 `401 MACHINE_REVOKED` 或 `401 MACHINE_AUTH_REQUIRED`，签名闸记一条错误日志、
不再上报任何东西；正在签的任务立即放弃（还没记下签名包的预留自动释放），进程以**退出码 78** 结束。unit 里
`RestartPreventExitStatus=78` 阻止 systemd 重启，`systemctl status rn-signer-a` 显示 failed。按「登记机器」换新令牌后再启动。
其它致命错误（记录校验失败、文件不可信等）退出码是 1，仍按 `RestartSec=60s` 重启。

**认领退避**：签完交付一条之后立即认领下一条；其余结果（暂不能签、临时错误、违规、编号过期）之后至少等一个轮询间隔
（15 秒）才再认领，同一任务连续没签完时间隔翻倍：15 秒、30 秒、1、2、4、8 分钟，封顶 10 分钟；这个任务签完交付后清零。
退避期间试解、上报照常进行。服务端另有 60 秒冷却，两边独立。

### 预留的状态与释放

`signer list` 的 signed 一节里每条预留是下面之一：

| 状态 | 含义 | 能否释放 |
| --- | --- | --- |
| `reserved` | 解密前落盘；签名包还没记下，没有任何签名包离开过本机 | 能 |
| `signed` | 签名包 sha256 已落盘，随后才上传；服务端可能已经拿到它 | 不能 |
| `completed` | 服务端确认完成，记下发布 id | 不能 |
| `abandoned` | 已释放，versionCode 可以给别的包用 | — |

签名闸在记下签名包之前失败（解密不对、apksigner 失败、复核失败、被打断）会**自动释放**预留；所以正常情况下
不需要人工 `abandon`。只有进程在那之间被杀掉、留下 `reserved` 时才需要：

```bash
systemctl stop rn-signer-a.service
sudo -u rn-signer-a /opt/rn-signer/bin/signer abandon --job bld_… --reason "…" --env-file /etc/rn-signer-a.env
systemctl start rn-signer-a.service
```

`signed` 的预留永远占着那个 versionCode：同一任务再派下来会续签续传；换一个包就用更高的 versionCode 重新构建。

### 离线记录：记录文件的行数与末行哈希

> **重要：哈希链与每行的 Ed25519 签名发现不了两种回滚——记录文件被整齐截断到某个完整行，或整个状态目录被换回
> 旧快照。** 这两种情况下每一行照样验链、验签通过，签名闸照常启动（安全评审 R2 已复核）。被回滚的 `signed.jsonl`
> 会"忘掉"已经签过的 versionCode，同一个 versionCode 就可能再签一个不同的包。**离线抄录的行数与末行哈希是唯一防线**：
> `promote --import` 之前必须按下面的步骤比对，日常巡检必须抄录并与上一条比对，不能省。

哈希链只能证明"每一行都没被改、没被插入"，证明不了"文件末尾没被整行截掉"或"整个状态目录被换回了旧快照"。
签名闸自己发现不了这件事，所以靠离线记录。

**何时抄**（主、备都抄；备没有签名记录，只有 `trust.jsonl` 会变）：

1. 首次 `promote --first` 并重新启动服务之后；
2. **每次发布完成之后**（控制台任务变成已签名，`signer list` 里对应预留是 `completed`）；
3. 每次 `confirm`、`trust-builder`、`trust-peer`、`trust-recovery`（三者都含 `--revoke`）、`abandon`、`promote` 之后；
   以及每次「生成签名密钥」完成、备签名闸自动接受新密钥之后——**自动确认会自己往 `trust.jsonl` 追加一行**
   （`signer list` 里 `confirmedBy auto:…`），这时 `trust.jsonl` 的行数会在没有人工操作的情况下增加，抄录时在备注里写明；
4. 计划停机、迁移、提升备用演练之前；
5. **日常巡检**：没有发布也至少每周一次，另外每次重启服务后看一眼启动日志里的 `signedLines`、`signedLastLineSha256`。

每次抄录都先和离线记录里这台机器的上一条比（规则同下面的「怎么比对」）：行数变少、或者上一条的第 M 行哈希对不上，
就是被回滚了——立刻停服务（`systemctl stop rn-signer-a.service`），不要再签，按「故障」一节当作状态目录被改过处理。

> **不要用旧快照回滚 `trust.jsonl`**（包括“撤销错了想退回去”）。旧快照里没有之后的 `peer-revoke`、`recovery-revoke`、
> `builder-revoke` 与新的确认：回滚等于把已撤销的签名闸、恢复公钥、构建机重新变成受信，把换掉的证书重新变成有效。
> 撤销错了就重新 `trust-peer` / `trust-recovery` / `trust-builder`（追加新行）。

**抄什么**：执行 `signer list`（不用停服务），抄开头五行：

```bash
sudo -u rn-signer-a /opt/rn-signer/bin/signer list --env-file /etc/rn-signer-a.env | head -5
# machine amos-signer-a
#   x25519 sha256  <64 hex>
#   ed25519 sha256 <64 hex>
#   trust.jsonl  12 lines, last line sha256 <64 hex>
#   signed.jsonl 57 lines, last line sha256 <64 hex>
```

离线发布记录里每次追加一条（只追加，不改旧条目）：UTC 时间、机器名、`ed25519 sha256`、两个文件各自的**行数与完整
64 位末行 sha256**、这次对应的操作（发布就写任务 id、versionCode、发布 id）、抄录人。

**怎么比对**（`promote --import` 导入旧主记录时必做；怀疑状态目录被恢复过时也做）：

取离线记录里这台机器**最近一条**的 `signed.jsonl` 行数 M 与末行哈希 H，和程序显示的导入文件行数 N、末行 sha256 比：

1. 机器名与 `ed25519 sha256` 必须与记录一致（程序已经按 pin 文件验过公钥，这里再对一眼）。
2. **N < M**：文件被截短或是旧快照。不要导入，改用 `promote --manual`，按离线发布记录逐包输入最大 versionCode。
3. **N = M**：程序显示的末行 sha256 必须等于 H，否则同上处理。
4. **N > M**（最后一次抄录之后还有操作）：第 M 行的哈希必须等于 H——

   ```bash
   head -n M /run/rn-signer-b-import-a.jsonl | tail -n 1 | tr -d '\n' | sha256sum   # M 换成记录里的行数
   ```

   行哈希是那一行完整字节（不含换行）的 sha256。相等之后，再把多出来的 N−M 行对应的发布在控制台发布记录里逐条找到；
   找不到的说明记录来路不明，停下来查。
5. 程序显示的每个包的最大 versionCode 不能低于离线发布记录里该包已发布的最大 versionCode。

权限允许列表（`signing/policy/permissions.json`）与 RN-App `ALLOWED_PERMISSIONS` 必须在同一次变更里一起改；
改了要重新构建并按本文人工部署。RN-App 提高 compileSdk 时同时重新生成 `signing/apk/axml/framework_attrs.txt`。

## 9. 提升备用（演练与实操）

1. 停旧主：`systemctl disable --now rn-signer-a.service rn-signer-a-check.socket`；在控制台吊销 `amos-signer-a`。
2. 导入旧主的签名记录（状态目录还在时）。promote 需要运行锁，先停 B 的服务：

   ```bash
   systemctl stop rn-signer-b.service
   install -o rn-signer-b -g rn-signer-b -m 0600 /var/lib/rn-signer-a/signed.jsonl /run/rn-signer-b-import-a.jsonl
   sudo -u rn-signer-b /opt/rn-signer/bin/signer promote --import /run/rn-signer-b-import-a.jsonl --env-file /etc/rn-signer-b.env
   rm /run/rn-signer-b-import-a.jsonl
   systemctl start rn-signer-b.service
   ```

   粘贴 pin 文件里（或 B 本机 `signer list` 的 `trusted signing gates` 里）**旧主的 Ed25519 sha256**，程序逐行验链与签名，显示文件的行数、最后一行 sha256、每个包的预留数
   （其中未完成的条数）与最大 versionCode。**按第 8 节「离线记录：记录文件的行数与末行哈希」的比对步骤核对**，
   通过后原样输入本机机器名写入；对不上就不导入，改用 `--manual`。

   旧主的状态目录也没了：同样先停 B 的服务，`promote --manual`，逐包输入离线发布记录或已安装设备上的最大 versionCode
   （不取服务端的值）；程序最后问旧主的 Ed25519 sha256 时照样粘贴（B 本机 `signer list` 的 `trusted signing gates` 里有）。

   **旧主的信任随提升一并撤销**：B 本机受信签名闸里用旧主 Ed25519 的那台，与角色记录在同一次写入里追加 `peer-revoke`
   （原因「被本机提升取代」），程序在输入机器名之前会列出。此后新密钥不再加密给旧主，它签的生成也不再被接受——旧主以后
   被攻破、服务端把它报成 active 也没用。`--manual` 没给旧主指纹时不自动撤销，程序列出受信签名闸与撤销命令，按提示手动
   `signer trust-peer --revoke`。
3. 控制台把 `amos-signer-b` 切成 primary。**控制台切换路由与 B 上的 `signer promote` 两步都必须做**：B 启动后一分钟内
   上报 `localRole: primary`，控制台显示主签名闸就绪；只切了控制台、B 本机仍是备时，控制台显示不就绪原因
   （本机记录不是主），此时回到第 2 步补做 promote。
4. 其余每台备：`signer trust-peer --revoke --peer <旧主>`，再 `signer trust-peer --peer <新主>`（指纹取新主本机 `signer show-key`）。
5. 补一台新的备：按第 A 节装新机器（新实例、新密钥），新备本机 `trust-peer --peer <新主>`，新主本机 `trust-peer --peer <新备>`。
   新备拿不到已有租户的密钥：按第 B 节「已知限制」恢复原件、`seal` 给所有签名闸、导入、各自 `confirm`。

**旧主不能原地改当备**：它的状态目录里还是主的记录，其它签名闸上对它旧密钥的信任也已撤销。要把那台机器重新用作签名闸，
按新机器重装（新实例名、新状态目录、新密钥、控制台新建机器），再在各签名闸上 `trust-peer`；不要对它的旧密钥重新 `trust-peer`，
也不要复用它的令牌与状态目录。演练同理。

## 10. 故障

- **启动报 `enrollment did not finish (enroll.incomplete)`**：`signer enroll` 在换到令牌之前中断。在控制台重发注册码，
  重跑安装命令。
- **`signer enroll` 报 `already holds machine keys and local records`**：状态目录已经有本机记录（手工装过、或复用了目录），
  不会重新初始化；确认这台机器的记录不再需要之后按新机器处理（新实例名、新状态目录）。
- **启动报 `records: the last line of a record file is incomplete`**：断电或崩溃截断了最后一行。先
  `tail -c 2000 /var/lib/rn-signer-a/signed.jsonl` 看清是哪一条；预留在解密之前落盘，一条没写完的预留意味着
  那次签名没有发生。确认后把**只含那半行**的尾部截掉（`truncate -s <最后一个完整换行之后的字节数>`），其余行一个字节都不要改，
  改了整条链校验不过。
- **启动报记录校验失败（断链、签名不对、genesis 不是本机）**：不要修。状态目录被改过，按设计「签名闸状态目录丢了」
  当作新机器处理；是主就先提升备（第 9 节，旧主的信任随提升撤销）。这台机器以后要当签名闸用，只能按新机器重装（新密钥），
  再在各签名闸上重新 `trust-peer`；其它签名闸上对它旧密钥的信任要撤销（`trust-peer --revoke`）。
- **启动报 `mode must be operator` 或 `an enrollment role record must be standby`**：修复前的开发版 `signer enroll` 写过
  「首次信任服务端给的主」或「注册即为主」，这种记录现在不认。按新机器重装（生产环境没有出现过这种记录）。
- **启动报 `refusing to execute an untrusted file` / `refusing to run an untrusted JAVA_HOME`**：java、JDK 目录树里的某个文件
  或符号链接目标、apksigner.jar、signer-check 或它们的某级目录能被别的用户改，按第 2 步重装成 root 拥有。
- **启动报 `not on tmpfs`**：`SIGNER_RUNTIME_DIR` 不在 tmpfs 上，改回 unit 的 `RuntimeDirectory`（`/run/rn-signer-a`）。
- **检查进程 socket 报 `served by uid …`**：`SIGNER_CHECK_SOCKET` 指向的 socket 不是 systemd 创建的（签名闸要求对端是 uid 0），
  核对 `rn-signer-a-check.socket` 是否在跑、路径是否一致。
- **服务 failed、退出码 78（`MACHINE_REVOKED` / `MACHINE_AUTH_REQUIRED`）**：令牌已在控制台吊销或失效，签名闸不再工作，
  systemd 也不会重启它。按新机器登记、写新令牌，再 `systemctl start`；不要改 unit 去掉 `RestartPreventExitStatus`。
- **试签失败**（控制台 `trialSign=failed`，journal 里有 apksigner 的输出）：先确认 `ProcSubset=pid`、
  `SystemCallFilter=@system-service`、`MemorySwapMax=0` 下 JVM 能正常运行（首次部署必须核对一次，本仓库的测试环境无法在完整的
  systemd 沙箱里跑 JVM）。
- **检查进程反复崩溃**：同一任务两次后判失败；`journalctl -u 'rn-signer-a-check@*'`。

## 11. 部署后核对

```bash
sudo -u builder ls /var/lib/rn-signer-a /run/rn-signer-a        # 必须 Permission denied
sudo -u rn-signer-b cat /var/lib/rn-signer-a/trust.jsonl        # 必须 Permission denied
systemd-analyze security rn-signer-a.service 'rn-signer-a-check@x.service'
```

服务端、扫链、迁移三个 unit 的 `InaccessiblePaths` 加上 `/var/lib/rn-signer-*`、`/run/rn-signer-*`、`/etc/rn-signer-*.env`
（纵深防御，由服务端部署负责）。
