# 签名闸部署与运维（人工）

设计：`docs/design/android-signing-gate-2026-09-16.md`「签名闸」「密钥生成与上传」「部署与运维」。

签名闸**只人工部署**：从审阅过的 tag 用固定工具链构建，二进制 sha256 记进离线记录，root 手工安装。
`rn-foundation-apply`、CI 部署账号 `rndeploy` 不得触及 `/opt/rn-signer`、`/etc/rn-signer-*`、
`/var/lib/rn-signer-*` 任何路径。开发阶段主（A）备（B）都在 amos 上，各用独立系统用户；这挡得住同机
非 root 用户，挡不住 root（取舍见设计「开发阶段的部署」）。

下面的命令都在**你自己的终端**里执行。令牌、口令不要经过 Claude Code 的 `!`、聊天、工单或截图。

## 文件

| 文件 | 安装到 | 属主 / 权限 |
| --- | --- | --- |
| `signer`、`signer-check`（构建产物） | `/opt/rn-signer/bin/` | root:root 0755 |
| `rn-signer-a.service`、`rn-signer-b.service` | `/etc/systemd/system/` | root:root 0644 |
| `rn-signer-a-check.socket`、`rn-signer-a-check@.service`（b 同理） | `/etc/systemd/system/` | root:root 0644 |
| `rn-signer.env.example` → `rn-signer-a.env`、`rn-signer-b.env` | `/etc/` | root:rn-signer-a 0640（b 同理） |
| apksigner.jar 副本 | `/opt/rn-signer/build-tools/35.0.0/lib/apksigner.jar` | root:root 0644，上级目录 0755 |
| 本 README | `/opt/rn-signer/README.md` | root:root 0644 |

状态目录 `/var/lib/rn-signer-a`（本机私钥、`trust.jsonl`、`signed.jsonl`）与运行时目录 `/run/rn-signer-a`
（tmpfs，明文 keystore 只出现在这里，签完即删）由 systemd 按 unit 创建，0700，属于 `rn-signer-a`。

## 1. 构建（离线记录二进制 sha256）

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

角色只在本机记录里。新机器默认是备，第一台主在 A 上执行（交互终端）：

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
   证书 SHA-256 记进密码管理器，原件按设计「原件与配置机密的保管」打包。
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

服务端的几个错误码由签名闸自己处理：`SIGNED_ARTIFACT_REPLACED` 原地重新 complete；`SIGNED_ARTIFACT_MISSING`
重新上传（最多 3 轮）；`UPLOAD_STORAGE_FAILED`、`UPLOAD_INTERRUPTED` 原地重试上传；`401 MACHINE_REVOKED` 时签名闸
不再上报任何东西、直接退出（systemd 每 60 秒重启一次，每次都会因为同样的原因退出，按「登记机器」换新机器）。

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

### 记录文件的行数与末行哈希

`signer list` 开头打印 `trust.jsonl`、`signed.jsonl` 的行数与最后一行的 sha256（启动日志里也有）。每次发布后把
`signed.jsonl` 这两项抄进离线发布记录：哈希链只能证明"每一行都没被改"，证明不了"文件末尾没被整行截掉"，
提升备用导入旧主记录时要拿它来核对。

权限允许列表（`signing/policy/permissions.json`）与 RN-App `ALLOWED_PERMISSIONS` 必须在同一次变更里一起改；
改了要重新构建并按本文人工部署。RN-App 提高 compileSdk 时同时重新生成 `signing/apk/axml/framework_attrs.txt`。

## 9. 提升备用（演练与实操）

1. 停旧主：`systemctl disable --now rn-signer-a.service rn-signer-a-check.socket`；在控制台吊销 `amos-signer-a`。
2. 导入旧主的签名记录（状态目录还在时）：

   ```bash
   install -o rn-signer-b -g rn-signer-b -m 0600 /var/lib/rn-signer-a/signed.jsonl /run/rn-signer-b-import-a.jsonl
   sudo -u rn-signer-b /opt/rn-signer/bin/signer promote --import /run/rn-signer-b-import-a.jsonl --env-file /etc/rn-signer-b.env
   rm /run/rn-signer-b-import-a.jsonl
   ```

   先停 B 的服务（`systemctl stop rn-signer-b.service`，promote 需要运行锁）。粘贴 pin 文件里**旧主的 Ed25519 sha256**，
   程序逐行验链与签名，显示文件的行数、最后一行 sha256、每个包的预留数（其中未完成的条数）与最大 versionCode——
   **与离线发布记录里抄下的行数与末行哈希、最大 versionCode 核对**，对不上就说明文件被截短，改用 `--manual`。
   原样输入本机机器名后写入，再 `systemctl start rn-signer-b.service`。旧主的状态目录也没了：`promote --manual`，逐包输入离线发布记录或已安装设备上的
   最大 versionCode（不取服务端的值）。
3. 控制台把 `amos-signer-b` 切成 primary。之后按「密钥生成与上传」补一台新的备（新机器、新 id、加进 pin 文件、
   用原件 `build-keystore seal` 重新加密上传、两台重新 confirm）。

演练时旧主被吊销后按新机器处理，不要复用它的令牌与状态目录。

## 10. 故障

- **启动报 `records: the last line of a record file is incomplete`**：断电或崩溃截断了最后一行。先
  `tail -c 2000 /var/lib/rn-signer-a/signed.jsonl` 看清是哪一条；预留在解密之前落盘，一条没写完的预留意味着
  那次签名没有发生。确认后把**只含那半行**的尾部截掉（`truncate -s <最后一个完整换行之后的字节数>`），其余行一个字节都不要改，
  改了整条链校验不过。
- **启动报记录校验失败（断链、签名不对、genesis 不是本机）**：不要修。状态目录被改过，按设计「签名闸状态目录丢了」
  当作新机器处理；是主就先提升备。
- **启动报 `refusing to execute an untrusted file` / `refusing to run an untrusted JAVA_HOME`**：java、JDK 目录树里的某个文件
  或符号链接目标、apksigner.jar、signer-check 或它们的某级目录能被别的用户改，按第 2 步重装成 root 拥有。
- **启动报 `not on tmpfs`**：`SIGNER_RUNTIME_DIR` 不在 tmpfs 上，改回 unit 的 `RuntimeDirectory`（`/run/rn-signer-a`）。
- **检查进程 socket 报 `served by uid …`**：`SIGNER_CHECK_SOCKET` 指向的 socket 不是 systemd 创建的（签名闸要求对端是 uid 0），
  核对 `rn-signer-a-check.socket` 是否在跑、路径是否一致。
- **启动或运行中报 `MACHINE_REVOKED`**：令牌已在控制台吊销，签名闸不再工作。
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
