# 签名闸部署与换密钥手册

2026-09-16。对应设计 `docs/design/android-signing-gate-automation-2026-09-16.md`（下称“自动化设计”）、
`docs/design/android-signing-gate-2026-09-16.md`（下称“原设计”）与 ADR-0019。组件细节以各自的 README 为准：
`deploy/signer/README.md`、`deploy/build-agent/README.md`、本目录 `README.md`。

一句话：

> 各服务的部署分工（谁自动、谁人工）与下旧机器的顺序：[`../DEPLOYMENT.md`](../DEPLOYMENT.md)。

- **新机器**：控制台新建 → 服务器本机执行一条安装命令 → 控制台点「接受」→ 在签名闸本机 `trust-peer` 或 `trust-builder`。
- **换密钥**：控制台点「生成签名密钥」。
- **离线恢复密钥**：整个平台只生成一次。

amos 上已经按旧手工流程装好的部署，迁移步骤见第 5 节。

## 0. 开始前要知道的

- **所有命令都在服务器本机的终端里执行**（不假设能从本地 ssh 过去）。注册码、口令只出现在控制台和这个终端里。
- **机密纪律**（`AGENTS.md`「机密的操作纪律」）：
  - 机器令牌不再经人手：`signer enroll` / `build-agent enroll` 直接写进 env 文件，屏幕上看不到。
  - 注册码 60 分钟有效、只能用一次，也不要贴进聊天、工单、截图。
  - 恢复密钥口令只放密码管理器。
  - 不要用 Claude Code 的 `!` 前缀执行这些命令。
  - 可以贴出来的只有公钥、指纹、证书 sha256。
- **注册码与本机其他用户**：安装命令最外层 `curl … | sudo bash -s -- … --code rne_…` 里的注册码会出现在
  这台机器的 `/proc/<pid>/cmdline` 与 sudo 日志里，本机其他登录用户读得到（`install.sh` 往下调
  `signer enroll` / `build-agent enroll` 时已改走环境变量 `RN_ENROLLMENT_CODE`，不再进进程参数，但最外层这一次避不开）。
  所以**只在没有其他不受信本机用户的机器上执行安装命令**。后果有限：注册码被抢注只会让这次注册失败
  （接受公钥仍要人工比对指纹，抢注者拿不到信任）。发现注册失败或注册码疑似泄漏，就在控制台机器卡片上
  「重发注册码」，旧码随即作废，再重跑安装命令。
- **必须由人亲手做、不能交给自动化会话的步骤**（设计要防“服务端或自动化被攻破”的那几道确认，替人做等于没做）：
  - 离线生成恢复密钥；
  - 装签名闸时粘贴 `--recovery-sha256`，并核对安装包 sha256；
  - 控制台接受时核对指纹；
  - 签名闸本机的 `trust-peer`、`trust-builder`、`trust-recovery`、`confirm`。
- **自动化设计写明不保证的几件事**（服务端被攻破时能做到）：
  - 给新租户第一次生成密钥时写入错误的信任根；
  - 无意义地换一把新密钥（老用户升不上去）；
  - 给**新装**的机器下发篡改过的安装包。

  所以第一次生成前要核对信任根（第 3 节），生产上装签名闸要核对安装包 sha256（第 2.3 节）。

### 涉及的租户与信任根对照值

第一次生成密钥时，签名闸直接取服务端当时的信任根（首次信任）。**点「生成签名密钥」之前**，先在控制台「打包配置」里
核对下面这些值；不一致就先查清楚，不要生成。表里的值取自改造前构建、线上正在分发的安装包（anyfun 1.3.16 build 46、
predict 1.0.6 build 7），与新服务端相互独立。

| 项 | AnyFun | Predict |
| --- | --- | --- |
| 控制台 / API 域名 | `console.anyfun.win` / `api.anyfun.win` | `console.predict.kim` / `api.predict.kim` |
| 包名 | `com.anyfun.foundation` | `com.predict.kim` |
| API origin | `https://api.anyfun.win` | `https://api.predict.kim` |
| OTA 证书 sha256 | `4fabae3ce4b4768de8ab69e3e22270eb7b408429f769f6524698e683cf3b1e5a` | `cd0c52ca7c3f30af89a15779f3745eb452451e67fb21ffd06019cabda2da1768` |
| bootstrap 签名地址 | `0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17` | `0x3294C48f71841558814a71B936EA8D9Aa07718Df` |
| App Links host | `api.anyfun.win` | `api.predict.kim` |
| scheme | `anyfun` | `predict` |
| 渠道 / applicationId | `direct` / `dex-mobile` | `direct` / `dex-mobile` |
| 线上最大 build 号 | 46 | 7 |

旧签名指纹（`1a5d9fb4…e694`、`9ab5fbe6…cf37`）已作废。any123 没有配置 Android 发布身份，不涉及。

## 1. 离线恢复密钥（整个平台一次）

签名闸生成的每一把租户密钥都会额外加密给这把恢复公钥：签名闸全丢了，也能用它在离线机器上解出原件。
它取代了原设计里“每个租户的原件打包进两个 U 盘”。

1. **构建离线工具**（开发机，审阅过的提交，固定工具链）：
   ```bash
   cd signing
   GOTOOLCHAIN=go1.24.6 CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /tmp/offline/ ./cmd/build-keystore
   sha256sum /tmp/offline/build-keystore   # 记进离线记录，拷到离线机器后再核对一次
   ```
2. **离线机器**（不联网）上生成：
   ```bash
   build-keystore recovery-key create --out recovery-2026 --name platform-recovery-2026
   ```
   - 口令输两遍，不回显，只放密码管理器。
   - 产出 `recovery-private.key`（0600，口令加密）和 `recovery-public.json`，并打印公钥完整 sha256。
3. **保管**：
   - 公钥 sha256 记进密码管理器。以后装签名闸、`trust-recovery` 都从这里粘贴。
   - `recovery-private.key` 放两个离线 U 盘，分开保管。
   - `STORAGE_MASTER_KEY` 与 `DEVICE_IDENTITY_HMAC_KEY` 的加密包也放进这两个 U 盘（原设计「原件与配置机密的保管」第 1 步）。取法：在 amos 本机你自己的终端里执行
     ```bash
     sudo grep -E '^(STORAGE_MASTER_KEY|DEVICE_IDENTITY_HMAC_KEY)=' /etc/rn-foundation.env \
       | gpg --symmetric --no-symkey-cache --cipher-algo AES256 -o config-secrets.gpg
     gpgconf --kill gpg-agent
     ```
4. **登记**：平台管理员在控制台「平台维护 → 签名闸恢复密钥」粘贴 `recovery-public.json` 的全文。
   页面显示的 sha256 必须与密码管理器里的一致。
5. **每台签名闸信任它**：
   - 新装的签名闸：安装命令带 `--recovery-sha256` 时自动完成；
   - 已有的签名闸：见第 5 节第 3 步。

**更换或新增恢复公钥**：

1. 按上面生成新的一把并在控制台登记。
2. 每台签名闸本机执行 `signer trust-recovery`，粘贴新的 sha256。
3. 在控制台对每个租户重新「生成签名密钥」，新密钥才会加密给它。
4. 旧的一把在控制台吊销，并在每台签名闸上执行：
   ```bash
   signer trust-recovery --revoke --recovery-sha256 <旧指纹> --reason "…" --env-file …
   ```

## 2. 新机器

### 2.1 前提（安装命令会逐项检查，缺什么一次列全后退出，注册码不会被用掉）

| 角色 | 需要（以 `install.sh` 的 `need_commands` 为准） |
| --- | --- |
| 全部 | x86_64；systemd（`/run/systemd/system` 存在、`/run` 在 tmpfs 上）；`curl`、`python3`、`sha256sum`、`tar`、`gzip`、`install`（coreutils）、`sudo`、`git`、`systemctl`、`useradd`、`groupadd`、`usermod`、`getent`、`cmp`、`awk`、`sed` |
| 签名闸 | JDK 17（`/usr/lib/jvm/java-17-openjdk-amd64`，`apt install openjdk-17-jre-headless`）；Android build-tools 35.0.0 的 `apksigner.jar`（见下） |
| 构建机 | JDK 17；`/opt/android-sdk`（root 所有、NDK 预装齐）；`/usr/local/bin:/usr/bin:/bin` 里的 Node.js 22、pnpm、syft（`deploy/amos/install-syft.sh`）；`visudo`、`setpriv`、`ssh`、`ssh-keygen`、`zip`、`pgrep`、`pkill`、git ≥ 2.30、openssh-client。旧结构迁移时若 `builder` 有 crontab，用 `crontab` 撤掉（缺 `crontab` 时跳过） |

`visudo` 在 `sudo` 包里、`setpriv`/`pkill`/`pgrep` 在 `util-linux`/`procps` 里、`ssh`/`ssh-keygen` 在 `openssh-client` 里，Ubuntu server 一般已装齐。

`apksigner.jar` 按 sha256 `00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7` 固定（官方
build-tools 35.0.0）。安装脚本先找已装的副本与 `/opt/android-sdk/build-tools/35.0.0/lib/`，都没有时自己取：

```bash
curl -fsSLO https://dl.google.com/android/repository/build-tools_r35_linux.zip
sha1sum build-tools_r35_linux.zip   # 2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc（Google 仓库清单里的值）
unzip -j build-tools_r35_linux.zip android-15/lib/apksigner.jar -d /root/
# 安装命令加 --apksigner-jar /root/apksigner.jar
```

### 2.2 控制台新建机器

平台管理员在控制台「平台维护 → 打包机与签名闸 → 新建机器」，填机器名、角色、主备（签名闸），填原因确认。

- 机器名规则：小写字母、数字、`-`，2–40 个字符。
- 签名闸机器名最多 22 个字符：系统用户 `rn-signer-<机器名>` 受 Linux 用户名 32 字符上限。系统用户、env 文件、unit、状态目录都按它命名：
  `rn-signer-<机器名>`、`/etc/rn-signer-<机器名>.env`、`rn-signer-<机器名>.service`、`/var/lib/rn-signer-<机器名>`，控制台给出的本机命令也按这个写。
  安装命令的 `--instance <2–22 个字符>` 可以换一个实例名，但那样控制台上的命令要自己替换路径，不建议用。
- 平台还没登记恢复公钥时，控制台不允许新建签名闸（先做第 1 节）。

弹层显示**一次性安装命令**，状态“待注册”：

```
curl -fsSL https://api.anyfun.win/v1/machine-setup/install.sh | sudo bash -s -- --server https://api.anyfun.win --code rne_…
```

- 签名闸的命令末尾还有 ` --recovery-sha256 <从密码管理器粘贴恢复公钥指纹>`：**把尖括号连同里面的字换成密码管理器里的值**，不要取控制台上的。
- 注册码 60 分钟后过期，过期了在机器卡片上「重发注册码」，旧码随即作废。

### 2.3 服务器本机执行

**开发环境**：直接粘贴执行控制台给的命令。

**生产环境装签名闸**：先核对再执行。安装脚本与安装包都来自服务端，服务端被攻破时能给新机器下发篡改过的程序：

```bash
curl -fsSLo install.sh https://api.anyfun.win/v1/machine-setup/install.sh
sha256sum install.sh
sudo bash install.sh --server https://api.anyfun.win --code rne_… \
  --recovery-sha256 <恢复公钥指纹> --expect-sha256 <signer.tar.gz 的 sha256>
```

- `install.sh` 的 sha256 要与 CI 部署日志「Build machine bundles」一步打印的 `install.sh` 一致。
- `--expect-sha256` 取同一步打印的 `signer.tar.gz` 的值（也在 run 页面的 notice 里）。
- 两者都要与离线记录的审阅提交对上。
- 归档可复现：同一提交、同一 Go 版本在别处跑 `deploy/setup/build-bundles.sh` 应得到相同的 sha256。

安装命令依次做这些事（也写在脚本开头的注释里）：

1. 检查前提。
2. 按注册码查询机器名、角色、主备与安装包清单（不消耗注册码）。
3. 下载安装包，核对归档与其中每个文件的 sha256。
4. 按角色安装：

   | | 签名闸 | 构建机 |
   | --- | --- | --- |
   | 系统用户 | `rn-signer-<实例>` | `rn-build-agent`、`builder`（`builder` 进 cron/at deny） |
   | 程序 | `/opt/rn-signer/bin/signer`、`signer-check`（root 0755） | `/opt/rn-build-agent/build-agent`、`build-runner`（root 0755），冒烟两个都以 2 退出 |
   | 配置 | 按模板渲染 `/etc/rn-signer-<实例>.env`（root:rn-signer-<实例> 0640，还没有令牌） | `/etc/sudoers.d/rn-build-agent`（visudo 校验）；env 由 enroll 写 |
   | unit | `rn-signer-<实例>.service`、`rn-signer-<实例>-check.socket`、`rn-signer-<实例>-check@.service` | `rn-build-agent.service` |
   | 其它 | root 自有的 `apksigner.jar` 副本 | 目录（见 `deploy/build-agent/README.md`「目录与权限」）；GitHub 只读 deploy key；仓库镜像 |

   发现改造前的旧构建机结构时（env 里有 `BUILD_AGENT_TOKEN`、unit 以 `builder` 运行、家目录里有 `agent-key`），
   先停旧进程（含撤掉 `builder` 的 crontab），再迁移。**旧结构里 `builder` 的家目录就是 `/var/lib/rn-build-agent`，
   仓库镜像与 `~/.ssh` 曾归 `builder` 可写**，控制进程 `git fetch` 会读镜像本地配置、`ssh` 会读 `~/.ssh/config`
   与 `known_hosts`，`builder` 能借此提权为 `rn-build-agent`。所以迁移把**整个旧家目录**（仓库镜像、`~/.ssh`、
   点文件）移进 `/root/rn-build-agent-legacy-<日期>/home/`（root 0700），新家目录从空建起：仓库镜像以
   `rn-build-agent` 重新克隆；`~/.ssh` 只取回 deploy key 的 `id_ed25519`/`id_ed25519.pub` 两个文件（属主改
   `rn-build-agent`，校验非软链、非 root 属主、公私钥配对），`config` 等其余文件留在留存目录，`known_hosts`
   按脚本里固定的 GitHub 主机公钥重写；另装 root 所有的 `/opt/rn-build-agent/github_known_hosts`。旧 env、unit、
   二进制、`agent-key`、`backup-signing.key` 同样留存。**deploy key 私钥曾对 `builder` 可读，建议在 GitHub 上
   换一把只读 deploy key**（泄漏面仅限源码读取）。
5. 注册（`install.sh` 经环境变量 `RN_ENROLLMENT_CODE` 交注册码，不进进程参数）：
   - 签名闸：`signer enroll`。生成本机密钥；核对 `--recovery-sha256` 在服务端登记的恢复公钥里，写进本机记录；
     **本机初始角色一律是「备」**（不再按服务端下发的主备写、也不再自动首次信任服务端给的主：服务端被攻破时
     不能让新机器本机为主，也不能让备自动接受它指定的「主」）。已注册时重复执行也照样调一次 `signer enroll`，
     它是幂等的——不连服务端、只清掉可能残留的 `enroll.incomplete` 标记（否则 `signer run` 会因它拒绝启动）。
   - 构建机：`build-agent enroll`。生成出处密钥（以 `os.OpenRoot` 打开状态目录后在其中创建，不跟随逃逸的软链）。
   - 两者都换回机器令牌，直接写进 env 文件。**注册码在这一步才被消耗。**
6. 启动服务，打印本机身份（完整指纹）与下一步的完整命令。签名闸 unit 模板不写死出站地址：`--server` 是回环或
   IP 字面量时 `install.sh` 直接渲染 drop-in `/etc/systemd/system/rn-signer-<实例>.service.d/network.conf`
   （`IPAddressDeny=any` + 允许该地址）；**`--server` 是域名时不渲染，必须按「下一步」手工加 API 与 DNS 解析器地址**。

**构建机的仓库镜像**：deploy key 是这次新生成的，第一次执行不会去克隆。

1. 把输出里的公钥加到 GitHub 仓库 `Helix2010/RN-App` → Settings → Deploy keys（只读）。
2. 重新执行同一条安装命令：这次会克隆镜像，其余步骤跳过。

### 2.4 控制台接受

机器卡片显示待接受的完整指纹。与安装输出里的指纹逐位核对后点「接受」，填原因：

- 签名闸核对 X25519 与 Ed25519 两个；
- 构建机核对出处公钥 sha256。

接受只影响服务端路由。

### 2.5 本机信任

实例名默认是机器名。amos 上手工部署的两台是 `rn-signer-a`、`rn-signer-b`，env 文件是 `/etc/rn-signer-a.env`、`/etc/rn-signer-b.env`。

**签名闸的主/备只在本机确认。** `signer enroll` 一律把本机记录写成「备」；控制台登记的主/备只决定派活。
`signer enroll` 结束时已按控制台登记与服务端有没有主，打印了这台机器要执行的完整命令；下表是要点。

| 新装的是 | 要在哪里执行什么 |
| --- | --- |
| 平台第一台主签名闸 | 控制台接受、登记为主后，在这台机器上把它提升为主（`promote` 要运行锁，先停服务）：`systemctl stop rn-signer-<实例>` → `sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer promote --first --env-file /etc/rn-signer-<实例>.env` → `systemctl start rn-signer-<实例>` |
| 替换旧主的新主 | **不要用 `--first`**：按 `deploy/signer/README.md` 第 9 节用 `promote --import`（旧主状态目录还在）或 `--manual`；再让每台备 `trust-peer --peer <新主>`、新主 `trust-peer --peer <每台备>` |
| 备签名闸 | 在这台备本机信任主：`sudo -u rn-signer-<备实例> /opt/rn-signer/bin/signer trust-peer --peer <主机器名> --env-file /etc/rn-signer-<备实例>.env`（指纹取**主签名闸本机** `signer show-key` 或它的安装输出，不取控制台）；并在主签名闸本机 `trust-peer --peer <新备机器名>`，粘贴这台备的 X25519 与 Ed25519 完整指纹。两个方向都做完之后，已有租户的密钥由主签名闸在下一轮自动重新封装给它（同一张证书，不换证书、不用离线恢复），控制台「签名密钥」一节里它那一行会从「缺」变成有密文 |
| 任何签名闸 | 这台签名闸本机，对每台构建机：`sudo -u rn-signer-<实例> /opt/rn-signer/bin/signer trust-builder --builder <构建机机器名> --env-file /etc/rn-signer-<实例>.env`，粘贴构建机的出处公钥 sha256 |
| 构建机 | 每台签名闸本机：同上一行的 `trust-builder --builder <新构建机机器名>` |

这些命令读终端输入，`trust-*` 不用停服务；`promote` 要先停服务再起。
控制台的机器卡片会按签名闸上报的本机信任列表提示还缺哪一步，例如“主签名闸还没信任备签名闸”。

**出站地址（上线必做）**：签名闸 unit 模板不写死 `IPAddress*`。`--server` 是回环或 IP 字面量时 `install.sh`
已渲染好 `/etc/systemd/system/rn-signer-<实例>.service.d/network.conf`；**是域名（生产 `https://api.…`）时
`install.sh` 不替你写**，装完按安装输出「下一步」在该 drop-in 里写 `IPAddressDeny=any` +
`IPAddressAllow=<API 地址> <DNS 解析器地址>`，然后 `systemctl daemon-reload && systemctl restart rn-signer-<实例>`（见 `deploy/signer/README.md`）。

### 2.6 重复执行与出错

- **失败后修好原因，重新执行同一条命令即可。**
- **已经注册过的实例**（env 文件里有机器令牌）：
  - 不重新注册，不替换已装的程序、unit 与 env；
  - 与安装包不同的文件只报告；
  - 服务没在跑就启动。
- **注册码已经用过**：查询会失败。脚本改用第一次执行时留在 `/var/lib/rn-machine-setup/<注册码 sha256>/` 的查询结果与安装包（root 0700，没有机密，装好后可以删）。
- **脚本拒绝继续、注册码不会被用掉的情况**：
  - 注册码没用过，但目标实例（或这台主机上的构建机）已经注册过：那是另一台机器的码，一台主机只跑一个构建机。
  - 这台主机上已有注册过的签名闸，而共享的 `/opt/rn-signer/bin/*` 或 `apksigner.jar` 与这次要装的不同：先按第 5 节第 1 步升级本机程序，再装新实例。
- **注册成功、但服务起不来**：看脚本打出的日志。修好后重新执行，注册步骤会跳过。
- **注册请求发出去了、却没收到回答**（网络在那一刻断了）：注册码可能已被消耗，而令牌没有落盘。
  1. 在控制台吊销这台机器；
  2. 新建一台（换个机器名）；
  3. 签名闸删掉 `/etc/rn-signer-<实例>.env` 与 `/var/lib/rn-signer-<实例>/` 后重装；构建机把 env 里的 `BUILD_AGENT_MACHINE_TOKEN` 清空后重装。

## 3. 换密钥：控制台一键

每个租户一次，先 AnyFun 再 Predict。前提：主签名闸已接受并本机为主，备签名闸已被主信任，两台都信任恢复公钥。

1. **核对信任根**：控制台「打包配置」里的 API 地址、OTA 证书、scheme 与第 0 节对照表一致。
2. **生成**：该租户控制台「配置中心 → 打包与签名 → 打包配置」→「生成签名密钥」。
   - 确认弹层写明包名；已有密钥时写明“会换证书、老用户不能覆盖升级”。
   - 填原因确认。
3. **等主签名闸处理**（一两分钟）。主签名闸会：
   1. 生成 RSA 4096 证书；
   2. 首次信任时写入本机确认记录（取服务端信任根，首签 versionCode 上限按设计取值）；
   3. 加密给本机信任的签名闸与恢复公钥，签名后交回。

   备签名闸验证主签名闸的生成签名后自动接受。主签名闸试签通过后，签名密钥区显示“就绪”。
4. **失败时**，签名密钥区显示原因码：

   | 原因码 | 处理 |
   | --- | --- |
   | `TRUST_ROOTS_CHANGED` | 租户改过 API 地址、scheme 或 OTA 证书：核对无误后在主签名闸本机 `signer confirm --tenant <slug>`，再重新生成 |
   | `RECOVERY_KEY_NOT_PINNED` | 主签名闸没有信任恢复公钥：本机 `signer trust-recovery` |
   | `NOT_LOCAL_PRIMARY` | 控制台的主签名闸本机记录不是主：在那台签名闸上 `signer promote`，或把路由切回 |
   | `PEER_NOT_TRUSTED` | 主签名闸没有信任某台备签名闸：主签名闸本机 `trust-peer` |
   | `GENERATION_FAILED` | 看 `journalctl -u rn-signer-<主实例>` |

5. **发第一个新签名的安装包**：
   1. 「发布中心 → 打包任务」排一个安装包任务。版本号与 build 号都要大于线上（AnyFun > 1.3.16 / 46，Predict > 1.0.6 / 7）。
      控制台弹“签名身份变更”确认层，填原因确认。
   2. 任务依次经过：排队中 → 已领取 → 构建中 → 待签名 → 签名中 → 成功。卡在“待签名”时看任务详情里的不就绪原因。
   3. 下载产物核对：
      ```bash
      apksigner verify --print-certs <下载的 apk>   # 恰好 1 个签名者，证书 SHA-256 等于签名密钥区显示的值
      ```
   4. 模拟器上：卸载旧包 → 安装新包 → 用助记词恢复钱包 → App Links、热更新拉取正常。
   5. 控制台「发布管理」发布这个版本，填原因。通知现有用户卸载旧版、安装新版、用助记词恢复。
   6. 把证书 SHA-256 记进密码管理器；RN-App `tenants/<目录>/tenant.json` 的 `signerSha256` 改成新指纹（只用于本地 `android:verify`）。
6. 各签名闸 `signer list` 的记录行数与末行哈希抄进离线记录（`deploy/signer/README.md` 第 8 节）。

## 4. 用恢复密钥找回原件（签名闸全丢了时）

1. 控制台签名密钥区「导出密文文件」，把文件拷到离线机器。
2. 离线机器：
   ```bash
   build-keystore recover --recovery-key recovery-private.key --upload <导出的文件> --out-dir restored
   ```
   输入恢复密钥口令，得到 `.p12` 与口令文件（放 tmpfs，用完删除）。
3. 装好新签名闸（第 2 节），按原设计的 `build-keystore seal` 加密给它们。
4. 在控制台「导入已有密钥（高级）」上传，再在每台签名闸本机 `signer confirm --tenant <slug>`。

## 5. amos 现有部署的迁移

amos 上已经按旧手工流程装好 `amos-signer-a`、`amos-signer-b`（`rn-signer-a/b`）与 `amos-builder`，**不重装**，只补齐。
`/etc/rn-signer-a.env` 等文件名与 unit 名不改；以后新装的机器用按机器名实例化的名字，两种命名并存。

### 5.0 前提

1. **服务端与控制台已是新版本**：RN-Server、RN-Admin 的 `feat/signing-gate` 合并发布，CI 部署完成。
2. **更新 CI 收口脚本**：特权脚本不由 CI 自己更新。把刚发布那个提交里的 `deploy/amos/rn-foundation-apply` 放到 amos 上
   （例如在 amos 上检出该提交），核对 sha256 与仓库里的一致后装上：
   ```bash
   sha256sum rn-foundation-apply   # 与 git show <提交>:deploy/amos/rn-foundation-apply | sha256sum 一致
   sudo install -m 0755 -o root -g root rn-foundation-apply /usr/local/sbin/rn-foundation-apply
   ```
   这一步等同 `deploy/amos/setup-ci-deploy.sh` 里的“特权收口脚本”一节，sudoers 不变。
   然后在 GitHub Actions 重跑一次部署（没更新前，部署会在「Upload machine bundles」一步明确报错；服务端本身不受影响），
   确认安装包已经就位：
   ```bash
   readlink /opt/rn-foundation/machine-bundles/current
   sha256sum /opt/rn-foundation/machine-bundles/current/*.tar.gz   # 与 CI 日志「Build machine bundles」一致
   ```
3. **确认没有在途任务**：三个租户控制台「发布中心 → 打包任务」里没有排队中、已领取、构建中、签名中的安装包任务。
4. **迁移窗口（服务端与签名闸不同步的那一小段）**：CI 先上新服务端（第 1 步），随后才由人工换签名闸二进制（5.1、5.3）。
   窗口内旧签名闸还没上报本机信任（新的信任上报格式由新二进制产生），控制台机器卡片会显示「未上报」/本机信任提示
   未清空——这是预期的，**不影响已在分发的安装包与已生成的密钥**（服务端那一路已把 trust 上报改成可选）。换完
   签名闸二进制并做完 5.3 后，卡片提示会清空。窗口内不要「生成签名密钥」，等 5.4。

### 5.1 升级两台签名闸与构建机的程序

> **顺序要对**：新的构建机控制进程在每次 `git fetch` 前会校验仓库镜像的配置与目录结构，并要求 root 所有的固定
> `known_hosts`。所以换构建机二进制**之前或同批**，先做下面「重建构建机仓库镜像与 ~/.ssh」，否则新二进制会拒绝
> 构建并提示按本节重建。amos 我已只读核查过：镜像的 config、`branches/`、`info/`、`hooks/`、`objects/info/alternates`
> 与 `.ssh` 都干净、`known_hosts` 指纹是 GitHub 官方——但 2026-09-16 用旧的 `signing-gate-rollout/1-install.sh`
> 迁移时没清过镜像，升级到会校验镜像的新二进制时仍按下面重建一次，边界才落到「root 所有、rn-build-agent 只读」。

新版本兼容现有本机记录。程序取自 CI 放在本机的安装包（sha256 已在 5.0 核对）：

新版本兼容现有本机记录。程序取自 CI 放在本机的安装包（sha256 已在 5.0 核对）：

```bash
B=/opt/rn-foundation/machine-bundles/current
d=$(sudo mktemp -d)
sudo mkdir "$d/signer" "$d/builder"
sudo tar -xzf "$B/signer.tar.gz" -C "$d/signer"
sudo tar -xzf "$B/builder.tar.gz" -C "$d/builder"
(cd "$d/signer" && sha256sum bin/signer bin/signer-check)       # 与 CI 日志核对，记进离线记录
(cd "$d/builder" && sha256sum bin/build-agent bin/build-runner)

# 签名闸：先停（手上的任务会 release 回服务端），留一份旧程序以便回滚
sudo systemctl stop rn-signer-a.service rn-signer-b.service
sudo cp -a /opt/rn-signer/bin/signer /root/signer.prev
sudo cp -a /opt/rn-signer/bin/signer-check /root/signer-check.prev
sudo install -o root -g root -m 0755 "$d/signer/bin/signer" "$d/signer/bin/signer-check" /opt/rn-signer/bin/
sudo systemctl start rn-signer-a.service rn-signer-b.service
systemctl is-active rn-signer-a rn-signer-b
sudo journalctl -u rn-signer-a -u rn-signer-b -n 20 --no-pager   # 没有记录校验错误

# 构建机：先重建镜像与 ~/.ssh、装固定 known_hosts（新二进制会校验镜像），再换两个程序（协议版本要一致）
sudo systemctl stop rn-build-agent

# 1) 安装 root 所有的固定 GitHub known_hosts（新控制进程 fetch 时只认它，rn-build-agent 改不了）
sudo install -d -o root -g root -m 0755 /opt/rn-build-agent
printf 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n' \
  | sudo install -o root -g root -m 0644 /dev/stdin /opt/rn-build-agent/github_known_hosts

# 2) 把现有仓库镜像与 ~/.ssh 移进留存目录，以 rn-build-agent 重新克隆干净镜像、重建 ~/.ssh
L=/root/rn-build-agent-migrate-$(date -u +%Y-%m-%d)
sudo install -d -o root -g root -m 0700 "$L"
sudo mv /var/lib/rn-build-agent/repos "$L/repos"          # 旧镜像整棵留存（core.* 之外的键、branches/、alternates 若有都在这里）
sudo mv /var/lib/rn-build-agent/.ssh "$L/ssh"             # 旧 ~/.ssh 整个留存
sudo install -d -o rn-build-agent -g rn-build-agent -m 0700 /var/lib/rn-build-agent/repos /var/lib/rn-build-agent/.ssh
# deploy key：只取回私钥与公钥两个文件（校验非软链、非 root 属主、公私钥配对），config/known_hosts 不沿用
sudo install -o rn-build-agent -g rn-build-agent -m 0600 "$L/ssh/id_ed25519"     /var/lib/rn-build-agent/.ssh/id_ed25519
sudo install -o rn-build-agent -g rn-build-agent -m 0644 "$L/ssh/id_ed25519.pub" /var/lib/rn-build-agent/.ssh/id_ed25519.pub
sudo -u rn-build-agent sh -c 'ssh-keygen -y -f /var/lib/rn-build-agent/.ssh/id_ed25519 | awk "{print \$1,\$2}"' \
  | diff - <(awk '{print $1,$2}' /var/lib/rn-build-agent/.ssh/id_ed25519.pub) \
  || { echo "deploy key 公私钥对不上，换一把只读 deploy key 再继续"; exit 1; }
# ~/.ssh/known_hosts 按固定主机公钥重写（rn-build-agent 家目录内的这份仅供 install 时的 clone 用；控制进程用的是 /opt/... 那份）
printf 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n' \
  | sudo -u rn-build-agent tee /var/lib/rn-build-agent/.ssh/known_hosts >/dev/null
sudo -u rn-build-agent chmod 0600 /var/lib/rn-build-agent/.ssh/known_hosts
# 重新克隆镜像（deploy key 已在 GitHub；空模板、只许 ssh、不跑 hook）
sudo -u rn-build-agent env HOME=/var/lib/rn-build-agent \
  GIT_SSH_COMMAND='ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i /var/lib/rn-build-agent/.ssh/id_ed25519 -o UserKnownHostsFile=/opt/rn-build-agent/github_known_hosts -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15' \
  git -c core.hooksPath=/dev/null -c protocol.allow=never -c protocol.ssh.allow=always \
  clone --quiet --mirror --template= git@github.com:Helix2010/RN-App.git /var/lib/rn-build-agent/repos/rn-app.git.part
# git clone 按当前 umask 建文件：默认 umask 002 时 config 会是组可写，新控制进程据此判"镜像配置不可信"、拒绝 fetch
sudo -u rn-build-agent chmod 0700 /var/lib/rn-build-agent/repos/rn-app.git.part
sudo -u rn-build-agent chmod -R go-w /var/lib/rn-build-agent/repos/rn-app.git.part
sudo -u rn-build-agent mv -T /var/lib/rn-build-agent/repos/rn-app.git.part /var/lib/rn-build-agent/repos/rn-app.git
ls -l /var/lib/rn-build-agent/repos/rn-app.git/config   # 不能有 g+w / o+w

# 3) 换两个程序；重启会先做完手上的构建（这一步之前服务已停）
sudo cp -a /opt/rn-build-agent/build-agent /root/build-agent.prev
sudo cp -a /opt/rn-build-agent/build-runner /root/build-runner.prev
sudo install -o root -g root -m 0755 "$d/builder/bin/build-agent" "$d/builder/bin/build-runner" /opt/rn-build-agent/
sudo systemctl start rn-build-agent
systemctl is-active rn-build-agent
sudo journalctl -u rn-build-agent -n 20 --no-pager   # 没有“镜像配置不可信”“known_hosts 不可用”

sudo rm -rf "$d"
```

> 旧 deploy key 私钥在改造前对 `builder` 可读，**建议在 GitHub 上换一把只读 deploy key**：生成新的、
> 加到 `Helix2010/RN-App` → Deploy keys（只读）、把上面 `id_ed25519`/`.pub` 换成新的、删掉 GitHub 上的旧 key。
> 泄漏面仅限源码读取。留存目录 `$L` 里的旧镜像与旧 `~/.ssh` 在新链路稳定后按 5.6 销毁。

### 5.2 离线恢复密钥

按第 1 节生成并在控制台登记。

### 5.3 两台签名闸：信任恢复公钥、互相信任

```bash
# 恢复公钥：粘贴密码管理器里的 sha256，程序从服务端取公钥核对后写进本机记录
sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-recovery --env-file /etc/rn-signer-a.env
sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-recovery --env-file /etc/rn-signer-b.env

# 互相信任：先各自 show-key 得到完整指纹，再在另一台上粘贴
sudo -u rn-signer-a /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-a.env
sudo -u rn-signer-b /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-b.env
sudo -u rn-signer-a /opt/rn-signer/bin/signer trust-peer --peer amos-signer-b --env-file /etc/rn-signer-a.env
sudo -u rn-signer-b /opt/rn-signer/bin/signer trust-peer --peer amos-signer-a --env-file /etc/rn-signer-b.env
```

- 不用停服务。
- `trust-builder`（`amos-builder`）旧流程已经做过，不用重做。
- 一两分钟后，控制台机器卡片上的本机信任提示应当清空。

### 5.4 生成 AnyFun、Predict 的签名密钥

按第 3 节：核对信任根 → AnyFun「生成签名密钥」→ 就绪 → Predict 同样一遍。

### 5.5 发第一个包

按第 3 节第 5 步。

### 5.6 收尾

- 各签名闸 `signer list` 的记录行数与末行哈希抄进离线记录。
- 删除 `/root/*.prev`。
- 新链路稳定后销毁 5.1 的镜像/ssh 留存目录 `/root/rn-build-agent-migrate-<日期>/`（旧镜像与旧 `~/.ssh`，含曾对 builder 可读的旧 deploy key）。
- 按旧手册第 12 节销毁 `/root/rn-build-agent-legacy-<日期>/`，并清理 `/etc/rn-foundation.env` 里的 `BUILD_AGENT_TOKEN` 与 `BACKUP_*`。
- 删除仓库里的 `deploy/amos/signing-gate-rollout/`（已被 `install.sh` 取代，只为这次迁移保留）。
- 第二次发布（迁移 55）：`feat/signing-gate-release2` rebase 到当时的 main 单独发布。

### 5.7 回滚

| 到了哪一步 | 怎么退 |
| --- | --- |
| 5.1 之后、5.4 之前 | 停服务，把 `/root/*.prev` 装回原位，启动。本机记录里新增的信任记录，旧程序不认时启动会报错：此时不要回滚签名闸，只修复向前 |
| 5.4 之后（新密钥已生成或已发包） | 不回退旧密钥，只修复向前 |

## 6. 部署后核对清单

- [ ] `systemctl is-active` 签名闸、构建机、`rn-foundation-server`、`rn-foundation-indexer` 全部 active
- [ ] `sudo -u builder ls /var/lib/rn-signer-a` 被拒；`sudo -u builder ls /var/lib/rn-build-agent` 被拒
- [ ] 控制台所有机器“已接受”；主签名闸路由主、本机角色主；本机信任提示为空
- [ ] 两个租户签名密钥区“就绪”，恢复收件人里有恢复公钥
- [ ] 第一个新包 `apksigner verify` 证书正确，模拟器安装与钱包恢复通过
- [ ] 签名闸记录行数与末行哈希、程序与安装包 sha256 都已抄进离线记录

## 7. 常见不就绪原因

| 原因码 | 处理 |
| --- | --- |
| `RECOVERY_KEY_NOT_CONFIGURED` | 平台没有登记恢复公钥：第 1 节 |
| `KEYSTORE_NOT_CONFIGURED` / `KEYSTORE_LEGACY_FORMAT` | 「生成签名密钥」（第 3 节） |
| `KEYSTORE_GENERATION_PENDING` | 等主签名闸处理（一两分钟）；一直不变看 `journalctl -u rn-signer-<主实例>` |
| `KEYSTORE_GENERATION_FAILED` | 按第 3 节第 4 步的原因码处理 |
| `KEYSTORE_RECORD_INVALID` | 库里的记录被改过或损坏：先查审计。已经有用户装了这把证书签的包时，按第 4 节用恢复密钥找回原件后导入（保留证书）；还没发过包才可以直接重新生成 |
| `RELEASE_IDENTITY_MISMATCH` | 发布身份与密钥不一致：查审计弄清谁改了什么。不要为此换证书；按第 4 节导入同一把密钥会重新登记发布身份 |
| `PRIMARY_SIGNER_MISSING` | 控制台没有已接受的主签名闸：第 2 节 |
| `PRIMARY_SIGNER_NOT_RECIPIENT` | 密钥没有加密给当前主签名闸（例如换主之前旧主没有 `trust-peer` 它）：主签名闸自己解不开就重新封装不了，按第 4 节用恢复密钥找回原件、加密给新主后导入，证书不变。重新生成会换证书，老用户升不上去。备签名闸缺密文不用这样处理：两边 `trust-peer` 之后主会自动重新封装 |
| `PRIMARY_SIGNER_LOCAL_ROLE_MISMATCH` | 控制台是主、签名闸本机不是主：那台签名闸上 `signer promote`，或把路由切回 |
| `OTA_CERTIFICATE_NOT_CONFIGURED` / `APP_IDENTITY_INCOMPLETE` / `API_BASE_URL_INVALID` / `TRUST_ROOTS_INVALID` | 补齐或改正租户的 OTA 签名密钥与打包配置 |
| `PRIMARY_SIGNER_NOT_CHECKED` / `PRIMARY_SIGNER_TRIAL_SIGN_PENDING` | 等主签名闸下一轮检查（约一分钟） |
| `PRIMARY_SIGNER_DECRYPT_FAILED` | 密文不是加密给这台签名闸的当前公钥，或文件被改：同 `PRIMARY_SIGNER_NOT_RECIPIENT` |
| `PRIMARY_SIGNER_NOT_CONFIRMED` / `TRUST_ROOTS_CHANGED` | 核对无误后在签名闸本机 `signer confirm --tenant <slug>` |
| `PRIMARY_SIGNER_TRIAL_SIGN_FAILED` | 看 `journalctl -u rn-signer-<主实例>`：多半是 JDK、apksigner 路径或权限检查 |
