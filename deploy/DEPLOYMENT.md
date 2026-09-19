# 部署总览：各服务怎么上线、新机器怎么进、旧机器怎么退

这份文档回答四个问题：**平时发版哪些是自动的、哪些要人工做**；**加一台新机器要做什么**；**下掉一台旧机器要做什么**；
**出了问题怎么退**。每一节末尾都有「怎么确认成功」。逐条命令级的细节在各自的手册里，这里只给流程与顺序：

- 签名闸与构建机（新机器、换密钥、amos 迁移）：[`amos/SIGNING_GATE_ROLLOUT.md`](amos/SIGNING_GATE_ROLLOUT.md)
- 签名闸本机操作（确认、信任、提升、恢复）：[`signer/README.md`](signer/README.md)
- 构建机细节（目录、权限、镜像、deploy key）：[`build-agent/README.md`](build-agent/README.md)
- amos 这台机器本身（nginx、TLS 证书、env、租户域名、CI 授权）：[`amos/README.md`](amos/README.md)
- 服务端搬到 Rancher 时 Mac 打包机要的那几条：[`rancher/README.md`](rancher/README.md)
- iOS 签名材料、上传 Key、发布密钥与 `allowed_signers` 的制作、分发、续期与销毁：[`build-agent-macos/SIGNING_MATERIAL.md`](build-agent-macos/SIGNING_MATERIAL.md)
- 配置项含义：[`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md)

控制台里的位置按菜单写，例如「平台维护 → 打包机与签名闸」。`<API>` 指该租户的 API 地址（amos 上是 `https://api.anyfun.win`）。

## 0. 有哪些东西要部署

| 组件 | 跑在哪 | 谁部署 | 改了什么会重新部署 |
| --- | --- | --- | --- |
| API 服务端 `rn-foundation-server` | amos | **CI 自动**（push main） | RN-Server 代码、迁移 |
| 扫链 `rn-foundation-indexer` | amos | **CI 自动**（同一个二进制） | 同上 |
| 控制台（两个租户域名） | amos 的 nginx 静态目录 | **CI 自动**（RN-Admin push main） | RN-Admin 代码 |
| 构建机控制进程 `rn-build-agent` + 执行进程 | amos | **CI 自动**（开关 `AMOS_DEPLOY_BUILD_AGENT=true`，见下面的提醒） | `cmd/build-agent/**` |
| **签名闸 `signer` / `signer-check`** | amos（`rn-signer-a`、`rn-signer-b`） | **人工**（有意为之） | `signing/**` |
| 新机器安装包 `signer.tar.gz` / `builder.tar.gz` | amos `/opt/rn-foundation/machine-bundles/current` | **CI 自动**（随服务端发布） | 上面任何一个程序 |
| 特权收口脚本 `rn-foundation-apply` | amos `/usr/local/sbin` | **人工**（CI 不能改自己的 root 入口） | `deploy/amos/rn-foundation-apply` |
| App 安装包（APK） | 用户设备 | 控制台排任务 → 构建机 → 签名闸 → 控制台发布 | RN-App 代码、租户配置 |
| App 热更新（OTA） | 用户设备 | 控制台排任务 → 构建机 → **服务端用租户自己的 OTA 密钥签** | RN-App 的纯 JS / 样式 / 随包资源改动 |

两个开关都在 GitHub 仓库 Settings → Secrets and variables → Actions → Variables，**仓库里改代码关不掉它们**：

- `AMOS_DEPLOY_ENABLED`：不是 `true` 就只跑门禁、不部署。
- `AMOS_DEPLOY_BUILD_AGENT`：只有 RN-Server 用；是 `true` 时 CI 会连构建机程序一起换。

**为什么签名闸不自动部署**：能往 main 推代码的人，不该因此获得改签名闸的能力——它持有解开签名密钥的私钥。

> **现状提醒（amos，2026-09-17）**：签名闸与构建机、后端同在 amos 上。
> [`amos/README.md`](amos/README.md)「签名闸同机期间，打包机不走 CI」要求这期间把 `AMOS_DEPLOY_BUILD_AGENT` 关掉，
> 而这一轮部署里 CI 确实换上了新的构建机程序——也就是说它现在是 `true`。含义是：能往 main 推代码、
> 或者拿到 `AMOS_SSH_KEY` 的人，就能换掉持有机器令牌与出处私钥的那个进程，以受信构建机的名义交付任意包，
> 并在签名闸所在的机器上跑代码。要么明确接受这个取舍并记进风险台账，要么去 GitHub 关掉它、构建机改回手工部署
> （[`build-agent/README.md`](build-agent/README.md)）。签名闸挪到独立机器之后这条自然消失。

## 1. 平时发版（服务端 / 控制台 / 构建机）

1. 代码合进 main。
2. CI（`.github/workflows/deploy-amos.yml`）跑门禁：gofmt、vet、带 MySQL 的 `go test -race -p 1`、`signing/` 模块、
   shellcheck（`install.sh`、`build-bundles.sh`、`rn-foundation-apply`）、OpenAPI JSON。
3. 门禁过了、且 `AMOS_DEPLOY_ENABLED=true` 才部署，顺序固定：
   **服务端二进制 → 迁移 → 健康检查（失败自动回滚）→ 新机器安装包 → 构建机程序**。
4. 控制台是 RN-Admin 仓库自己的流水线，同样一套 secret 与 `AMOS_DEPLOY_ENABLED`，落地也走同一个特权脚本
   （`rn-foundation-apply admin <租户>`）——所以那个脚本没更新时，控制台这一路同样会受影响。

**要人工的只有两种情况：**

- 改了 `deploy/amos/rn-foundation-apply`：CI 只会**警告**两边 sha256 不一致（amos 上**没装**它、或那份还不认 `bundles`
  子命令时才直接失败）。在 amos 上检出本次发布的提交，核对后装上：
  ```bash
  sha256sum deploy/amos/rn-foundation-apply   # 与仓库里这个提交的一致
  sudo install -m 0755 -o root -g root deploy/amos/rn-foundation-apply /usr/local/sbin/rn-foundation-apply
  ```
  sudoers 不变，然后在 GitHub Actions 重跑一次部署。细节见 [`amos/README.md`](amos/README.md)「CI 是怎么授权的」。
- 改了 `signing/**`：签名闸要人工升级（见下一节）。

**回滚是怎么做的**：迁移失败或健康检查没过，`rn-foundation-apply` 会把二进制换回上一版再起。
**迁移不会退回去**——所以迁移只能是加法、旧代码要能在新表结构上跑；哪天写了破坏性迁移，这条回滚就不成立了。

**怎么确认成功**：`ls -l /opt/rn-foundation/rn-server` 的时间；`curl -s http://127.0.0.1:13080/health/ready`；
`readlink /opt/rn-foundation/machine-bundles/current` 等于本次提交。

## 2. 升级签名闸（人工，改了 `signing/**` 时）

前提：服务端已经上线到同一个提交（**服务端必须先走**，新签名闸的上报格式旧服务端不认）。

```bash
B=/opt/rn-foundation/machine-bundles/current
d=$(sudo mktemp -d); sudo mkdir "$d/signer"
sudo tar -xzf "$B/signer.tar.gz" -C "$d/signer"
(cd "$d/signer" && sha256sum bin/signer bin/signer-check)   # 与 CI 日志「Build machine bundles」核对
sudo systemctl stop rn-signer-a rn-signer-b                  # 手上的任务会退回服务端重排
sudo cp -a /opt/rn-signer/bin/signer /root/signer.prev       # 留一份好回滚
sudo install -o root -g root -m 0755 "$d/signer/bin/signer" "$d/signer/bin/signer-check" /opt/rn-signer/bin/
sudo systemctl start rn-signer-a rn-signer-b
sudo rm -rf "$d"
```

两台（主、备）一起换，别只换一台。`signer-check` 是 socket 激活的，换掉文件之后下一次连接就用新的，不用重启 socket。

**不可回退的那条线**：签名闸一旦在本机记录里写下新类型的记录（信任签名闸、信任恢复公钥、自动确认），
旧版二进制加载记录链会直接报错。所以只能前滚修复，回滚要连状态目录一起按新机器重装。

**怎么确认成功**：`systemctl is-active rn-signer-a rn-signer-b`；
`journalctl -u rn-signer-a -n 20` 里有 `local records verified`，没有校验错误；
控制台机器卡片上两台仍是 active、本机角色分别是主/备。

## 3. 上一台新机器

控制台新建机器 → 那台机器上执行一条命令 → 控制台点接受 → 在签名闸本机建立信任。**注册码只在机器上执行时真正消耗**。

### 3.1 先把前置条件装好

安装脚本会逐项检查，缺什么**一次列全再退出，注册码不会被用掉**。两种角色要求不同：

| | 签名闸 | 构建机 |
| --- | --- | --- |
| 通用 | x86_64、systemd、`/run` 是 tmpfs，`git` `sudo` `awk` `sed` 等 | 同左，另加 `visudo` `setpriv` `ssh` `ssh-keygen` `zip` `pgrep` `pkill` |
| Java | JDK 17（`apt install openjdk-17-jre-headless`） | JDK 17（`JAVA_HOME`，默认 `/usr/lib/jvm/java-17-openjdk-amd64`） |
| 还要有 | Android build-tools 35.0.0 的 `apksigner.jar`（sha256 钉死在脚本里，用 `--apksigner-jar <绝对路径>` 指定） | Android SDK（root 所有、全局可读、NDK 预装齐）、git ≥ 2.30、Node.js 22、pnpm、syft（固定版本，见 [`amos/install-syft.sh`](amos/install-syft.sh)） |
| 前置动作 | 平台已登记离线恢复公钥（第 5 节）；`--recovery-sha256` 的值从**密码管理器**取 | GitHub 只读 deploy key（脚本生成，第 3 步加到 GitHub 后重跑） |

签名闸的机器名最多 22 个字符（它会变成系统用户 `rn-signer-<实例>`，Linux 用户名上限 32 个字符）；
机器名更长时用 `--instance <2–22 个字符的短名>` 另起一个实例名。

### 3.2 步骤

1. **控制台**「平台维护 → 打包机与签名闸」→ 新建机器，选角色（构建机 / 签名闸主 / 签名闸备）与机器名。
   得到一条**一次性安装命令**（注册码 60 分钟有效，可重发）。
   - 平台还没有登记离线恢复公钥时，新建签名闸会被拒（先做第 5 节）。
2. **在新机器上**（root，能访问 API 即可，不需要从你的电脑 ssh 过去）：把控制台给的命令粘上去执行。
   生产上建议两段式，先看脚本再执行，并带上 CI 日志里的安装包 sha256：
   ```bash
   curl -fsSLo install.sh <API>/v1/machine-setup/install.sh
   less install.sh
   # 签名闸必须带 --recovery-sha256；apksigner.jar 不在默认位置时再带 --apksigner-jar；
   # 机器名超过 22 个字符时带 --instance <短名>。构建机这三个都不用。
   sudo bash install.sh --server <API> --code <注册码> --expect-sha256 <CI 日志里的值> \
        --recovery-sha256 <密码管理器里的恢复公钥指纹> \
        --apksigner-jar /path/to/apksigner.jar
   ```
   脚本做的事：核对前提 → 下载并逐文件核对安装包 → 建用户、目录、sudoers、unit → 生成本机密钥 →
   用注册码换长期机器令牌（令牌不上屏）→ 启动服务 → 打印**本机公钥指纹**与下一步命令。
   重复执行是幂等的，注册码也不会被二次消耗。
3. **只有构建机有这一步**：脚本会打印它生成的 deploy key 公钥。把它加到 GitHub 仓库
   `Helix2010/RN-App` → Settings → Deploy keys（**只读**，不勾 write access），然后**重新执行同一条安装命令**——
   这一次才会克隆仓库镜像，其余步骤跳过。
4. **控制台**点「接受」，核对指纹与安装输出一致。接受只影响服务端路由，**不代表任何一台签名闸信任它**。
5. **在签名闸本机建立信任**（服务端不能代劳）：
   - 新构建机：每台签名闸上 `signer trust-builder --builder <构建机名>`，粘贴构建机安装输出里的出处公钥指纹。
     **macOS / iOS 打包机跳过这一条**：签名闸只签 Android 的 APK，iOS 的包在 Mac 本机用钥匙串里的
     Distribution 证书签完，不经过签名闸——装机流程见
     [`build-agent-macos/MAC_SETUP_RUNBOOK.md`](build-agent-macos/MAC_SETUP_RUNBOOK.md)。
   - 新签名闸（备）：主签名闸上 `signer trust-peer --peer <新机器名>`；新机器上 `signer trust-peer --peer <主机器名>`，
     指纹取**对方本机** `signer show-key` 或它的安装输出，不取控制台。
   - 平台第一台主签名闸：`sudo systemctl stop rn-signer-<实例>` → `signer promote --first` → 再启动。
     注册一律写成本机备，主只能在本机产生。
6. **已有租户的密钥怎么到新签名闸**：两个方向的 `trust-peer` 都做完之后，主签名闸下一轮检查会把**同一张证书**
   重新封装给它（每个租户 10 分钟最多一次），证书不变、老用户照常升级。
   控制台「配置中心 → 打包与签名」的签名密钥卡片里，它那一行会从「缺」变成有密文，随后自动确认。

### 3.3 命令怎么敲

签名闸的运维命令都由**运维在那台机器的交互终端里**执行（不是脚本、不是 CI），以签名闸用户的身份、指明 env 文件：

```bash
sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer <子命令> --env-file /etc/rn-signer-<实例>.env
```

实例名默认就是签名闸的机器名；amos 上手工部署的两台是 `rn-signer-a`、`rn-signer-b`。
`promote`、`abandon` 会和正在跑的服务抢运行锁，**执行前先 `systemctl stop`**；`confirm`、`trust-*`、`list`、`show-key`
可以在服务运行时执行。所有指纹都从**对方本机**取，不从控制台复制——控制台是被校验的一方。

### 3.4 怎么确认成功

- 控制台机器状态 active，本机角色与登记一致，卡片上没有「还要在本机执行」的提示。
- 签名闸：`signer list` 里有对方与恢复公钥；控制台签名密钥卡片里它有密文、试解与确认都通过。
- 构建机：排一个安装包任务，它能领取并交付。

## 4. 下一台旧机器

**顺序很重要：先在签名闸本机撤销信任，再在控制台吊销，最后清机器。** 反过来做会留下一台「服务端已吊销、
但签名闸本机仍然信任」的机器——真正的边界在签名闸本机记录里。

### 4.1 下一台构建机

1. 等它手上的任务跑完（控制台「发布中心 → 打包任务」里没有它领取中的任务）。
2. 每台签名闸本机：`signer trust-builder --revoke --builder-id <机器 id> --reason "<原因>"`。
3. 控制台吊销这台机器（令牌立即失效）。
4. 机器上：`sudo systemctl disable --now rn-build-agent`，销毁状态目录 `/var/lib/rn-build-agent`
   （出处私钥、机器令牌、仓库镜像都在里面）与 `/etc/rn-build-agent.env`；GitHub 上删掉它的 deploy key。
5. 确认：控制台里它是 revoked；新任务不会派给它；其余构建机照常出包。

### 4.2 下一台备签名闸

1. 其余签名闸本机：`signer trust-peer --revoke --peer <机器名> --reason "<原因>"`。
2. 控制台吊销这台机器。
3. 机器上：`sudo systemctl disable --now rn-signer-<实例> rn-signer-<实例>-check.socket`，
   销毁状态目录 `/var/lib/rn-signer-<实例>`（私钥与本机记录）与 `/etc/rn-signer-<实例>.env`。
4. **已经发给它的那份密文不会自动消失。** 重新封装只在「本机信任的收件人里有谁还没有密文」时才触发，
   **少一个收件人不会触发**。要真正收回只有两条路：等下一次因为**新增**收件人而重新封装（那一次按当前信任重算收件人），
   或者给这个租户**重新生成密钥**（会换证书，老用户必须卸载重装）。在那之前，就当那台机器上的私钥仍然解得开这份密钥：
   如果它是**因为被攻陷才下线**的，别等重新封装，直接按「密钥已泄露」换密钥（第 6 节）。
5. 确认：控制台里它是 revoked；其余签名闸 `signer list` 里没有它；主签名闸日志里不再有「信任的签名闸不在服务端 active 列表」告警。

### 4.3 换掉主签名闸（旧主故障或被攻陷）

1. 控制台把路由主切到备（或先吊销旧主）。
2. 在新主本机（先 `systemctl stop`）：`signer promote --import <旧主的 signed.jsonl>`（旧主状态目录还在），
   或 `--manual`（目录也没了：逐个包名输入已签过的最大 versionCode，取离线记录或设备上的版本，**不取服务端**）。
   `promote --import` 会自动撤销本机对旧主的信任。
3. 其余每台备：`signer trust-peer --revoke --peer <旧主>`，再 `signer trust-peer --peer <新主>`。
4. 旧主那台机器按 4.2 清掉。**它不能原地改当备**：状态目录里还是主的记录，别人也已经撤销了对它的信任。
   要重新用作签名闸，按新机器重装。
5. 确认：控制台签名密钥就绪；新主 `signer list` 里没有旧主；排一个包能签出来。

## 5. 离线恢复密钥（整个平台一次，新平台必做）

### 5.1 生成与登记

1. 离线机器上：`build-keystore recovery-key create --out <目录> --name <名字>`，口令手输两遍。
2. 口令进密码管理器；`recovery-private.key` 进两个离线 U 盘；公钥指纹也记进密码管理器。
3. 控制台「平台维护 → 签名闸恢复密钥」粘贴 `recovery-public.json`。
4. 每台签名闸本机 `signer trust-recovery`，粘贴密码管理器里的指纹（不取控制台的值）。
5. 确认：控制台机器卡片的信任列表里有恢复公钥；之后生成的密钥收件人里能看到它。

**没有它就不能新建签名闸，也不能生成密钥**——签名闸全丢时它是唯一的救命绳。

### 5.2 真的要用它的时候（签名闸全丢）

1. 控制台「配置中心 → 打包与签名」导出当前密钥的密文（只会导出发给**恢复公钥**的那几份，发给签名闸的不带，
   服务端自己也解不开），这一步写进审计。
2. 拿到离线机器上：
   ```bash
   build-keystore recover --recovery-key recovery-private.key --upload <导出的文件> --out-dir <目录> \
                          --expect-certificate-sha256 <已发布 App 的证书 sha256>
   ```
   证书指纹取**设备上装着的那个包**或离线记录，**不取控制台**——控制台是这次要救的那一方。
3. 拿回 p12 与口令之后，按 [`amos/SIGNING_GATE_ROLLOUT.md`](amos/SIGNING_GATE_ROLLOUT.md) 第 4 节重新封装给新装的签名闸。

## 6. 换租户签名密钥（控制台一键）

前提：主签名闸本机为主、备已被主信任、两台都信任恢复公钥、当前密钥的收件人都确认过当前版本
（否则返回 409 `KEYSTORE_SIGNERS_NOT_IN_SYNC`，要么等它们跟上，要么明确勾选「仍然生成」）。

1. 该租户控制台「配置中心 → 打包与签名」→「生成签名密钥」，填原因。
2. 主签名闸在本机生成，只加密给**本机信任**的签名闸与恢复公钥，交回服务端；备自动接受。
   30 分钟没交回，这次生成作废。
3. **已有密钥的租户会换证书：老用户不能覆盖升级，必须卸载重装。** 确认弹层会写明。
4. 生成后：把证书 sha256 记进密码管理器；RN-App `tenants/<租户>/tenant.json` 的 `signerSha256` 改成新值
   （取**主签名闸本机** `signer list`，不取控制台），提交并发版。
5. 确认：控制台签名密钥就绪；排一个新包，`apksigner verify --print-certs` 的证书等于控制台显示的值。

## 7. 发一个安装包（APK）

1. 控制台「发布中心 → 打包任务」排任务，版本号与 build 号都要大于线上。
   证书或包名要变时服务端会回 409 `APP_IDENTITY_DRIFT`，要带上「改变 App 身份」的确认再发一次
   （接口上是 `acknowledgeIdentityChange: true`）。
2. 任务流转：排队中 → 已领取 → 构建中 → 待签名 → 签名中 → 成功。卡在待签名时看任务详情里的不就绪原因
   （[`amos/SIGNING_GATE_ROLLOUT.md`](amos/SIGNING_GATE_ROLLOUT.md) 第 7 节列了常见的几种）。
3. 下载产物核对：`apksigner verify --print-certs <apk>`，恰好 1 个签名者、证书等于控制台显示的值。
4. 控制台「发布中心 → 发布管理 → 全量版本」发布这个版本。发布前的产物只有管理员能取，公开下载会被挡（404）。
   **这一版换过证书时**（第 6 节）：发布之前先通知用户——备份助记词 → 装新包 → 卸载旧版。发布之后旧版用户
   只会看到"安装失败"，因为换了证书的包不能覆盖安装。

**依赖校验**：RN-App 的 `gradle/verification-metadata.xml` 记着每个 Android 依赖的 sha256。
改依赖、升 Expo、或者构建机缓存被清空之后，可能出现清单里没有的坐标 → 构建直接失败（这是设计如此）。
按 RN-App 手册重新生成清单（`pnpm android:verification-metadata <slug>`，冷缓存下跑真实构建）。

**怎么确认成功**：`curl -s "<API>/v1/public/releases/latest?platform=android"` 是这一版；
公开下载到的 apk sha256 与控制台记录一致，`apksigner verify --print-certs` 的证书也一致。

## 8. 发一次热更新（OTA）

热更新**不经签名闸**：构建机出包，**服务端用该租户自己的 OTA 签名密钥**签清单。它推的是 JS 与随包资源，
换不了原生代码，也换不了 App 身份。

1. 前提：该租户有 OTA 签名密钥（「配置中心 → 打包与签名 → OTA 签名」）。没有就直接 409 `OTA_SIGNING_KEY_MISSING`——
   设备验不过签会静默停在内置 bundle，现场完全看不出发生了什么，所以宁可在排队这一刻就挡住。
2. 控制台「发布中心 → 打包任务」→「构建 OTA」：选基线安装包（状态是**已校验 / 在分发 / 灰度**都行，不必已发布）、
   生效策略（`next_launch` 下次启动生效，或 `immediate`）。
3. 服务端在入库前逐项校验：包名、`apiBaseUrl` 与内置签名地址（应用身份不能被热更新改掉）、
   以及**原生指纹必须与基线一致**。动了原生的东西（依赖、原生模块、内置证书指纹这类）会 422 `OTA_NATIVE_CHANGED`
   ——这时候只能重新出安装包发全量更新，热更新这条路走不通。
4. 「发布中心 → 发布管理 → OTA 热更新」里发布。**只有装着基线那一版的设备会收到**；
   灰度就先 `canary` 并填安装 id 名单，验过再 `promote`。

**怎么确认成功**（照 App 的请求来，四个头一个都不能少）：
```bash
curl -si "<API>/v1/ota/manifest?platform=android&runtimeVersion=<基线 runtimeVersion>" \
     -H 'expo-platform: android'  -H 'expo-runtime-version: <基线 runtimeVersion>' \
     -H 'x-app-version: <基线 version>' -H 'x-build-number: <基线 buildNumber>' | head -20
```
200 且响应里有 `expo-signature`、清单 `id` 等于控制台那条记录的 updateId；没有已发布的更新时是 204。

> **别少带 `x-app-version` / `x-build-number`**：少了任何一个，服务端一律回 204，连查都不查。
> 用少了头的命令去"确认没发布"会得到一个永远成立的假阴性——要判断有没有发出去，看控制台那条记录的状态
> （`active` 才是发出去了），或者用上面这条完整的命令。

## 9. 出问题怎么退

| 出了什么事 | 怎么退 |
| --- | --- |
| 服务端新版本起不来 | CI 已经自动把二进制换回上一版（**迁移不回退**）。看 `journalctl -u rn-foundation-server -n 50` 定位，前滚修复 |
| 安装包发出去发现有问题 | 「发布管理 → 全量版本」对它 `pause`：新设备立刻拿不到它，**已经装上的不会被收回**。修好发新版本 |
| 想回到上一版安装包 | 对上一条记录再点一次发布（`paused → active` 也走发布）。只有「已校验」「已暂停」的记录能发布；版本号只能往前，别改旧记录 |
| 热更新推错了 | 「OTA 热更新」对它 `rollback`：会新写一条不可变的「回到内置 bundle」指令并置为 active，**连已经缓存了旧更新的设备也能退回来**。`pause` 只挡住还没拉到的设备 |
| 签名闸升级之后起不来 | **不能把二进制换回旧版**（第 2 节）。前滚修复；实在不行按新机器重装这台，再等主重新封装 |
| 构建机的出处私钥或机器令牌可能泄露 | 控制台吊销 → 每台签名闸 `trust-builder --revoke` → 按第 3 节重装。已交付的包不受影响，签名闸记录里留着是谁交的 |
| 签名密钥可能泄露 | 换密钥（第 6 节）：会换证书，老用户必须卸载重装；同时把旧证书那条分发 `pause` |

## 10. 离线要抄的东西

放密码管理器或离线记录，不要只留在服务器上：

- 恢复密钥口令、恢复公钥指纹。
- 每台签名闸的机器名与两个公钥指纹（`signer show-key`）。
- 每个租户的签名证书 sha256（取签名闸本机 `signer list`）。
- 每次 `confirm`、`trust-*`、`promote` 之后：`signer list` 的记录行数与末行哈希。
- 每次发布的安装包 sha256 与它的证书。
- 每次热更新的 updateId 与它的基线安装包（要回退时得知道退到哪一版）。
