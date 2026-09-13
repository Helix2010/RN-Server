# 打包机部署

**这台机器不和 wallet 后端同机。** 它持有 Android keystore，而"服务端不下发密钥、不执行命令"那套论证在两者同机的那一刻就作废了：后端的一个 RCE 直接读到磁盘上的密钥。amos 现在两者同机，那是开发环境的临时状态，不是可以照抄的样板（见 `deploy/amos/README.md`）。

设计见 `docs/design/build-service-2026-09-11.md`。

## 一句话拓扑

```
打包机  ──出──→  API（领任务 / 回传产物）
        ──出──→  GitHub（拉代码）
        ──出──→  npm / Maven / Gradle（拉依赖）
        ←─入──   什么都没有，不监听任何端口
```

代理只出不进：轮询服务端要活，服务端从不连它。所以这台机器可以关掉全部入站端口（除了你自己要用的 SSH）。反过来做就要在握着签名密钥的机器上开一个监听端口，那个端口的每一个 bug 都直接通向 keystore。

## 依赖的软件

| 软件 | amos 上的版本 | 为什么要 | 装漏了会怎样 |
| --- | --- | --- | --- |
| JDK 17 | `openjdk 17.0.20` | Gradle / Android 构建 | Gradle 起不来 |
| Node.js 22 | `v22.23.2` | Expo prebuild、`pnpm android:release`、SBOM 脚本 | 第一步就失败 |
| pnpm 12 | `12.4.1` | 仓库用 pnpm lockfile | `--frozen-lockfile` 不认别的包管理器 |
| git ≥ 2.30 | `2.34.1` | 裸库 + 每任务一个 worktree | 需要 `worktree` 子命令 |
| Android SDK | platform-tools / platforms;android-36 / build-tools 36.0.0、35.0.0 / cmake 3.22.1 | 编译与签名 | 构建到一半才报缺组件 |
| Android NDK | `27.0.12077973`、`27.1.12297006` | RN 的原生模块 | 见下面那条"SDK 只读" |
| syft | `1.51.1`（固定版本+校验和） | 生成 SBOM，构建的必经步骤 | **构建直接失败**，不是警告 |
| zip | 系统包 | 打热更新包（`build-ota.mjs` 调它） | 热更新任务失败在 `spawnSync zip ENOENT`；APK 那条不受影响 |

syft 用 `deploy/amos/install-syft.sh` 装，版本和 sha256 都写死在脚本里：SBOM 是要被别人当证据读的东西，同一个 commit 在两台机器上扫出不同组件数的话，没人分得清是依赖变了还是工具变了。

**SDK 目录对构建用户只读是有意的**，所以 NDK 版本必须预装齐。Gradle 想自己补一个缺失的 NDK 时会失败在 "SDK directory is not writable"，而不是去装它。版本号以 expo-updates / react-native 当前要求的为准。

## 依赖的服务

| 出口 | 给谁 | 没有会怎样 |
| --- | --- | --- |
| `https://<API 域名>` | 领任务、取图标、报心跳、传产物 | 领不到活；日志里是 claim 报错 |
| `github.com:22`（SSH） | `git fetch` 拉代码 | 构建第一步失败 |
| npm registry | `pnpm install` | 同上 |
| Maven Central / Google Maven / `services.gradle.org` | Gradle 依赖与 wrapper | 同上 |
| 对象存储 | 只在 `ARTIFACT_UPLOAD_MODE=direct` 时需要；`proxy` 模式下产物经 API 转发 | direct 模式下传不上去 |

不需要数据库、不需要 Redis、不需要对象存储凭证——代理手上没有任何一个能直连数据面的凭据。它只有一个 `BUILD_AGENT_TOKEN`，那把令牌能做的事只有"领构建任务"这一件；管理端的 admin key 不在这台机器上。

## 权限

### 账号

```
builder:x:998:998::/var/lib/rn-build-agent:/bin/bash     系统账号
```

- **builder 没有任何 sudo 权限**（`sudo -l -U builder` → not allowed）。构建过程跑的是仓库里的 `pnpm android:release`，那条链路上的任何一步都不该能提权。
- 家目录就是状态目录：OpenSSH 按 passwd 里的 home 找 `~/.ssh`，不看 `$HOME`，两者必须一致。
- 服务以 `User=builder` 跑，配上 `NoNewPrivileges=true`、`ProtectSystem=strict`、`ProtectHome=true`，可写路径只有两条（见 unit 里的 `ReadWritePaths`）。

### 文件

| 路径 | 属主 | 模式 | 说明 |
| --- | --- | --- | --- |
| `/etc/rn-build-agent.env` | root:root | `0600` | 含 `BUILD_AGENT_TOKEN`。**builder 读不到**——systemd 以 root 读它再注入进程环境 |
| `/opt/rn-build-agent/build-agent` | root:root | `0755` | builder 不能改自己的程序 |
| `/var/lib/rn-build-agent/` | builder:builder | `0755` | 状态 |
| `/var/lib/rn-build-agent/.ssh/` | builder:builder | `0700` | GitHub 部署密钥（**只读权限的 deploy key**） |
| `/var/lib/rn-build-agent/agent-key` | builder:builder | `0600` | 本机私钥，服务端把签名密钥加密给它的那把 |
| `/var/cache/rn-build-agent/` | builder:builder | `0755` | Gradle 与 pnpm 缓存，可随便删 |
| `/opt/android-sdk` | root:root | `0755`（builder 只读） | 见上 |

### 外部凭据

| 凭据 | 放哪 | 权限范围 |
| --- | --- | --- |
| `BUILD_AGENT_TOKEN` | `/etc/rn-build-agent.env` | 只能访问 `/v1/build-agent/*`。丢了泄的是构建队列，不是管理端 |
| GitHub deploy key | `/var/lib/rn-build-agent/.ssh/` | **只读**，单仓库 |
| 本机 X25519 私钥 | `/var/lib/rn-build-agent/agent-key` | 服务端按公钥指纹加密 keystore；换机器要平台管理员核对指纹后接受 |
| `BUILD_KEYSTORE_PASSPHRASE` | `/etc/rn-build-agent.env` | **遗留项**。v2 的盒子加密给本机公钥，不需要任何口令；这一条只为还没重新生成的老租户留着，全部迁完就删掉 |

服务端**从不**给这台机器下发可执行的东西：任务里只有版本号、租户配置、证书和一个加密的 keystore 盒子。构建跑的是仓库里那份提交过的脚本。这条边界是整套设计的地基，加功能时不要跨过去。

## 目录约定

| 路径 | 内容 | 删了会怎样 |
| --- | --- | --- |
| `/opt/rn-build-agent/build-agent` | 程序本体 | 重新 scp 一个 |
| `/etc/rn-build-agent.env` | 配置，0600 root 所有 | 要重新填 |
| `/var/lib/rn-build-agent/` | 状态，同时是 builder 的 HOME | 要重新配部署密钥、重新拉仓库 |
| `/var/lib/rn-build-agent/repos/rn-app.git` | 仓库镜像（裸库） | 重新 clone |
| `/var/lib/rn-build-agent/workspace/` | 每个任务一份检出 | 无所谓，任务结束就删 |
| `/var/lib/rn-build-agent/agent-key` | 本机私钥 | **已存的盒子全部打不开**，每个租户都要重新生成签名密钥 |
| `/var/lib/rn-build-agent/.ssh/` | GitHub 部署密钥 | 要重新生成并加回仓库 |
| `/var/cache/rn-build-agent/` | Gradle 与 pnpm 的缓存 | 只是下一次构建慢一点 |
| `/opt/android-sdk` | Android SDK，root 所有、全局可读 | 重新装 |

状态与缓存分开不是形式：清理策略和备份策略完全不同。缓存整个删掉只会让下一次构建慢几分钟，`/var/lib` 下的东西删了要重新配密钥、重新拉仓库，而 `agent-key` 删了连已有的签名密钥都救不回来。

## 装一台新的

```bash
# 1. 工具链
sudo apt-get install -y openjdk-17-jdk-headless zip
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt-get install -y nodejs
sudo corepack enable && sudo corepack prepare pnpm@latest --activate

# 2. Android SDK 到 /opt，root 所有、全局可读（构建用户不需要写它）
sudo mkdir -p /opt/android-sdk/cmdline-tools && cd /tmp
curl -sSLo cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
sudo unzip -qo cmdline-tools.zip -d /opt/android-sdk/cmdline-tools
sudo mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest
yes | sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses
sudo /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --install \
  "platform-tools" "platforms;android-36" "build-tools;36.0.0" "build-tools;35.0.0" \
  "ndk;27.0.12077973" "ndk;27.1.12297006" "cmake;3.22.1"
sudo chmod -R a+rX /opt/android-sdk

# 3. SBOM 工具（固定版本 + 校验和，别用官网那条 curl | sh）
#    脚本在仓库的 deploy/amos/install-syft.sh，scp 上来再跑
sudo bash install-syft.sh

# 4. 用户与目录
sudo useradd --system --create-home --home-dir /var/lib/rn-build-agent --shell /bin/bash builder
sudo mkdir -p /var/lib/rn-build-agent/{repos,workspace} /var/cache/rn-build-agent/{gradle,pnpm-store} /opt/rn-build-agent
sudo chown -R builder:builder /var/lib/rn-build-agent /var/cache/rn-build-agent

# 5. 部署密钥，公钥加到仓库的 Deploy keys（**只读**）
sudo -u builder ssh-keygen -t ed25519 -N "" -C "rn-build-agent@$(hostname)" -f /var/lib/rn-build-agent/.ssh/id_ed25519
sudo -u builder ssh-keyscan -t ed25519 github.com | sudo -u builder tee /var/lib/rn-build-agent/.ssh/known_hosts
sudo cat /var/lib/rn-build-agent/.ssh/id_ed25519.pub

# 6. 仓库镜像
sudo -u builder git clone --mirror git@github.com:Helix2010/RN-App.git /var/lib/rn-build-agent/repos/rn-app.git

# 7. 程序、配置、服务
sudo install -m 0755 build-agent /opt/rn-build-agent/build-agent
sudo install -m 0600 rn-build-agent.env.example /etc/rn-build-agent.env   # 然后填
sudo install -m 0644 rn-build-agent.service /etc/systemd/system/
sudo systemctl enable --now rn-build-agent
```

启动后 journal 里会打出本机公钥指纹。**第一台**登记即固定；之后换机器或重装会变成 `pending_acceptance`，要平台管理员在管理端把指纹敲一遍才接受——不这样做的话，偷到令牌的人登记自己的公钥就能收下以后每一把新密钥。

## 换二进制 / 重启

```bash
scp build-agent amos:~/build-agent.new
ssh amos 'sudo install -m 0755 ~/build-agent.new /opt/rn-build-agent/build-agent && sudo systemctl restart rn-build-agent'
```

代理收到 SIGTERM 后**不再领新任务，但会把手上那一条做完**再退出，所以 `systemctl restart` 可能挂着等一轮构建（最长 `BUILD_AGENT_TIMEOUT_MINUTES`，默认 45 分钟；unit 里 `TimeoutStopSec=3600` 就是为它留的）。日志里会有一行 `stop requested: not claiming any more builds`。

急着换就 `sudo systemctl kill -s SIGKILL rn-build-agent`：那条任务会在服务端由心跳超时回收，**build 号会放出来，但不会自动续跑**，需要在管理端重新排一个。

## 异常恢复

| 情况 | 会发生什么 |
| --- | --- |
| 代理进程崩了 | systemd `Restart=always` / `RestartSec=10` 拉起来 |
| 构建中途被硬杀（OOM / 断电 / SIGKILL） | 下次启动时自动清掉遗留的检出、裸库里的登记，以及那个目录里解开的 keystore；任务由服务端心跳超时回收 |
| 服务端重启 | 构建照常跑；心跳失败只打 WARN；产物回传与结果上报都会退避重试 |
| 产物上传遇到 5xx / 网络抖动 | 分三步各自重试（传包 / 传 SBOM / 建发布记录），最多 6 次，退避到分钟级 |
| 服务端明确拒绝（4xx，比如版本号没涨） | **不重试**，直接判失败——重试一百次也是同一个答案 |
| 构建超过 `BUILD_AGENT_TIMEOUT_MINUTES` | 杀掉进程组，按超时上报失败 |
| 代理超过 10 分钟没报心跳 | 服务端把任务判失败、放出 build 号（心跳 30 秒一次，容得下 20 次连续失败） |

**中断的构建一律不续跑**，这是有意的：半截的依赖安装和编译状态续下去比重来更危险，而重来只要几分钟。

## 排查

```bash
sudo journalctl -u rn-build-agent -f
```

构建失败的原因和日志尾部也会回到服务端，在管理端的构建记录里能看到——不必登到这台机器上才知道出了什么事。日志里的机密会被脱敏：进程环境里的值自动登记，keystore 口令是运行时从盒子里开出来的，在 `build.go` 里显式登记进脱敏器（Gradle 失败时很乐意把命令行整行打出来）。
