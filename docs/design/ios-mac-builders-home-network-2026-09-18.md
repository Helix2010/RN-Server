# 设计：家用网络里的 Mac 打包机与机房里的管理端怎么配合出 iOS 包

状态：设计（2026-09-18）。在 `ios-testflight-distribution-2026-09-17.md` 已实现的阶段 0–1 之上，回答它 §4.8 末尾与 §6 第 13 条留下的问题：**服务端跑在机房（虚拟机或 Rancher），Mac 打包机是家里的电脑、没有公网地址、可能有好几台**，两边怎么配合把 iOS 包打出来、发出去。

不改动已定的安全论证（`build-service-2026-09-11.md`：服务端不下发命令、签名材料不经服务端、任务只带参数）。本文引用的代码以 `origin/main` 2026-09-18 为准。

## 0. 一句话结论

**现有的打包机模型就是为这种网络写的。** 打包机「只出不进」：本机令牌 + 轮询认领，服务端从不连它（`cmd/build-agent/main.go` 包注释、`agent.serve`）。家用 NAT、动态 IP、没有端口映射都不构成障碍——Mac 只需要能出站到服务端的 HTTPS 源、GitHub、npm/CocoaPods 与 Apple。**不需要 VPN，不需要固定 IP，不需要在路由器上开任何东西。**

真正要补的是五件事，全在「多台」「家用」「macOS」这三个词上：

| # | 缺什么 | 为什么现在不够 | 见 |
| --- | --- | --- | --- |
| 1 | **按 Apple Team 路由任务** | 认领只按平台求交集（`build_agent.go` `claimBuildJob`）。签名身份在 Mac 的钥匙串里、按租户的 Apple 团队分，一台没有租户 X 证书的 Mac 会领走 X 的任务、失败、退回、再领走——正是 §4.8 说的那个自愈不了的循环，只是换成了租户维度 | §5.2 |
| 2 | **Mac 的账户、钥匙串与 ASC 密钥布局** | 执行进程的 `HOME` 被换成任务目录（`jobspec.jobPathEnv`），而 codesign 找钥匙串、xcodebuild 找 Xcode 账号、altool 找 `.p8` 全靠 `HOME`。原文 §10.3 已预判会撞；这里把修法定下来，并把「上传」从第三方代码里挪出来 | §4 |
| 3 | **macOS 的安装与常驻** | `install.sh` 只认 x86_64 + systemd，安装包只编 linux/amd64（`build-bundles.sh`），unit、sudoers、用户都是 Linux 的 | §4.4、§8 |
| 4 | **机器在线状态** | 登记里没有「最近一次心跳」。排队闸 `hasLiveBuilderFor` 只看 `active`，注释自己写着「一台 active 但已经关机的机器同样领不到，那件事这里看不出来」。家里的电脑会休眠、断电、断网，这个盲区在机房里可以忍，在家里不行 | §5.4 |
| 5 | **家用网络的失效路径** | 心跳断 10 分钟任务被回收重排（`build_reaper.go`），重排后用**同一个 build 号**再传一次 App Store Connect 会被 Apple 拒；45 分钟默认超时对「archive + 家用上行传几百 MB」偏紧 | §6 |

## 1. 场景与约束

| | 服务端 | Mac 打包机 |
| --- | --- | --- |
| 在哪 | 机房：虚拟机，或 Rancher 里的 Pod | 家里：Mac mini / MacBook，家用宽带 |
| 网络 | 有公网 HTTPS 源（`https://api.<租户域名>`） | NAT 后面，动态出口 IP，可能是运营商级 NAT；没有入站 |
| 台数 | 1 个部署（Rancher 可多副本） | 1～N 台，可能属于不同的人 |
| 可用性 | 常开 | 会休眠、关机、断电、换网络 |
| 持有 | 数据库、对象存储、租户配置、机器登记 | 源码检出、Xcode、**签名身份**、ASC 密钥、本机令牌 |
| 不能持有 | 任何签名材料（既定原则） | 服务端配置、其它 Mac 的身份 |

租户可能不止一个，每个租户一个 Apple Team、一个 bundle id（原文 §4.3「多租户隔离」）。**不是每台 Mac 都必然持有每个 Team 的签名身份**——这是 §5.2 的出发点。

## 2. 拓扑与网络

### 2.1 谁连谁

```mermaid
flowchart LR
  subgraph home1["家 A（NAT，动态 IP）"]
    A1["build-agent<br/>(_rnbuildagent)"] -->|sudo -n -u| R1["build-runner<br/>(_rnbuilder)<br/>xcodebuild / pnpm / pod"]
  end
  subgraph home2["家 B"]
    A2["build-agent"] -->|sudo| R2["build-runner"]
  end
  subgraph dc["机房（VM 或 Rancher）"]
    ING["Ingress / nginx<br/>公网 HTTPS"] --> API["rn-foundation-server"]
    API --> DB[(MySQL)]
    API --> OBJ[(对象存储)]
  end
  A1 -->|"HTTPS 出站：领任务 / 心跳 / 交结果"| ING
  A2 -->|HTTPS 出站| ING
  A1 -->|"ssh 出站：fetch 仓库镜像（只读 deploy key）"| GH["GitHub"]
  R1 -->|"HTTPS 出站：npm、CocoaPods CDN"| REG["依赖源"]
  R1 -->|"HTTPS 出站：证书与描述文件"| DEV["developerservices.apple.com"]
  A1 -->|"HTTPS 出站：上传 .ipa（§4.3）"| ASC["App Store Connect"]
  API -.->|"只读同步（模式 A，可选）"| ASC
  ING x-.-x A1
  linkStyle 10 stroke:red,stroke-dasharray: 5 5
```

红色虚线是**不存在**的方向：服务端没有任何路径能连到 Mac。这不是限制，是设计（`build-service-2026-09-11.md`「不做什么」）。

### 2.2 Mac 需要的出站清单

| 目的地 | 谁发起 | 协议 | 干什么 | 断了会怎样 |
| --- | --- | --- | --- | --- |
| 服务端 API 源 | 控制进程 | HTTPS 443 | 登记公钥、认领（每 10 秒，`PollEvery`）、心跳（每 30 秒）、取图标、交 `/ios-release` | 领不到任务；构建中断 10 分钟没心跳被回收 |
| `github.com` | 控制进程 | ssh 22 | fetch 仓库镜像（deploy key + 固定 known_hosts，`checkout.go` `gitEnv`） | 任务在检出那一步失败 |
| npm registry、CocoaPods CDN | 执行进程 | HTTPS | `pnpm install`、`pod install`（prebuild 里） | 任务失败 |
| `developerservices2.apple.com` 等 | 执行进程 | HTTPS | `-allowProvisioningUpdates` 申请/续期证书与描述文件 | archive 失败 |
| App Store Connect 上传端点 | **控制进程**（§4.3） | HTTPS | 传 `.ipa` | 包出来了但没上去；任务按失败上报 |
| Apple NTP | 系统 | UDP 123 | ASC 的 JWT 对时钟敏感（`exp` ≤ 20 分钟） | 上传与同步报鉴权错 |

家用宽带上 22 端口出站偶尔被运营商拦；被拦时 GitHub 支持 `ssh://git@ssh.github.com:443`，镜像的 `remote.origin.url` 与固定 known_hosts 里的主机条目要一起改成那个（`checkMirror` 只核对配置键名，不核对 URL 值）。

### 2.3 服务端侧要满足的

| 要求 | 为什么 | VM（nginx） | Rancher（Ingress） |
| --- | --- | --- | --- |
| 打包机路径直接 200，**不重定向** | 客户端拒绝一切 3xx（`client.go` `refuseRedirects`）：跟随重定向会把令牌带到别处 | 别在 `/v1/build-agent/*`、`/v1/machine-setup/*` 上做 `www`/尾斜杠/http→https 之外的跳转 | 同左；`nginx.ingress.kubernetes.io/ssl-redirect` 对 https 直连无影响 |
| 透传 `x-machine-token`、`x-build-attempt`、`x-enrollment-code` 头 | 鉴权全靠它们 | 默认透传 | 默认透传；别配 header 白名单 |
| 读超时 ≥ 60 秒 | 单次请求 30 秒超时（`defaultHTTPRequestTimeout`） | 默认够 | `proxy-read-timeout` 默认 60 |
| 请求体上限 | iOS 任务**不上传产物**，最大的是 `logTail` JSON；Android 那侧的未签名包上传（PUT，30 分钟）仍要 ≥ 2 GiB | 已有 | `proxy-body-size` 要放大——这条是 Android 的，iOS 不需要 |
| `TRUSTED_PROXIES` 指向反代 | `externalOrigin` 据此判 https 并拼安装命令（`machine_setup.go`）；`machine-setup` 三条接口按 `ClientIP` 限速 20/分钟 | `127.0.0.1` | Ingress Pod 网段。不配的话所有 Mac 的注册请求都算同一个 IP，20/分钟共用 |
| 安装包目录 | `describe`/`bundle` 从 `/opt/rn-foundation/machine-bundles/current` 读（`defaultMachineBundleDir`，**不是配置项**） | `rn-foundation-apply bundles` 已经放好 | 要挂成卷，或在镜像构建时放进去；否则新 Mac 的 `describe` 回 503 `MACHINE_BUNDLE_UNAVAILABLE` |
| 多副本 | 认领用 MySQL 命名锁 + `FOR UPDATE SKIP LOCKED`（`claimBuildJob`），回收器按 `attempt` 守护（`build_reaper.go`） | 单实例 | 多副本安全，无需选主；回收器每副本各跑一轮是幂等的 |
| 出站到 `api.appstoreconnect.apple.com` | 只有模式 A 的只读同步要（`ios_asc.go` `syncIOSTestFlight`） | 确认出站策略 | NetworkPolicy 放行 |

**不需要做的**：给 Mac 的出口 IP 加白名单（做不到，也不该依赖）；给服务端加 mTLS（令牌 + TLS 已够，而且证书轮换会变成每台 Mac 的运维负担）；打 VPN。运维要远程维护 Mac 可以自己用 Tailscale / 屏幕共享，那与打包链路无关。

## 3. 一次 iOS 发布的完整动线

```mermaid
sequenceDiagram
  autonumber
  participant OP as 运营（控制台）
  participant S as 服务端（机房）
  participant M as Mac（家里）
  participant AP as Apple
  participant U as 用户

  OP->>S: 排 iOS 安装包任务（版本、build 号、原因）
  S->>S: 闸：build 号递增、release.ios 齐、有 active 且能建 ios 的机器、<br/>【新增】有机器持有这个租户的 Team（§5.2）
  loop 每 10 秒
    M->>S: POST /v1/build-agent/claim {platforms:[ios]}
  end
  S-->>M: 任务 + 合成的 tenant.json（含 appleTeamId、iosBundleId）
  M->>M: 控制进程：fetch 镜像、检出 main、写身份文件与图标
  M->>M: 执行进程：pnpm install → pnpm ios:release（prebuild、archive、门禁、export）
  M-->>S: 每 30 秒心跳 + 日志尾
  M->>M: 控制进程：核对 .ipa 身份（§4.3）
  M->>AP: 控制进程：上传 .ipa（本机该 Team 的 ASC 密钥）
  M->>S: POST /jobs/:id/ios-release {ipaSha256, bundleId, version, build, uploaded}
  S->>S: 与 release.ios、任务行再对一遍；落无产物发布记录；任务 succeeded
  AP->>AP: 处理 build（几分钟到几十分钟）
  OP->>AP: 出口合规答复；内部测试组装机验；提 Beta App Review；开外部组与公开链接
  alt 模式 A（服务端有 ASC Key）
    OP->>S: 「同步」→ installUrl、buildExpiresAt 回写 release.ios
  else 模式 B
    OP->>S: 手填 installUrl、过期日
  end
  OP->>S: 更新策略 latestVersion.ios
  U->>S: 扫码 GET /app/download（iOS UA）
  S-->>U: 跳 TestFlight 公开链接
  U->>AP: 装 TestFlight → 接受 → 安装
```

三点分工，写清楚免得混：

- **服务端只决定「给谁、出什么版本」**：它合成 `tenant.json`（`tenant_manifest.go`，`appleTeamId` 来自 `release.ios`），下发的是参数，不是命令。
- **Mac 决定「能不能签、要不要传」**：签名身份和 ASC 密钥都在 Mac 上；上传开关 `BUILD_AGENT_IOS_UPLOAD` 是机器级配置，由装机器的人打开（原文 §4.9）。
- **人决定「对外可见的事」**：提审、开公开链接、改测试员，平台不自动做（原文 §4.6.6）。

## 4. Mac 打包机的账户、钥匙串与密钥

### 4.1 沿用两进程两用户，换成 macOS 的写法

| Linux（现状） | macOS（本稿） | 说明 |
| --- | --- | --- |
| `rn-build-agent` 用户 | `_rnbuildagent`（`sysadminctl -addUser … -roleAccount`，uid 200–400 区间的隐藏服务账户） | 持令牌、出处密钥、仓库镜像、**上传用的 ASC 密钥** |
| `builder` 用户 | `_rnbuilder`（同上） | 跑 pnpm / pod / xcodebuild；持**签名钥匙串**与**申请描述文件用的 ASC 密钥** |
| `rn-build-jobs` 组 | `_rnbuildjobs`（`dseditgroup`） | 任务根目录 setgid，APFS 支持 |
| `/etc/sudoers.d/rn-build-agent` | 同路径同内容 | macOS 自带 sudo 与 visudo；规则不变：`_rnbuildagent ALL=(_rnbuilder) NOPASSWD:NOSETENV: /opt/rn-build-agent/build-runner` |
| systemd unit | `/Library/LaunchDaemons/win.anyfun.rn-build-agent.plist`，`UserName=_rnbuildagent`，`KeepAlive` | launchd 不读 env 文件：`ProgramArguments` 指向一个 root 0700 的包装脚本，它 `set -a; . /etc/rn-build-agent.env; exec /opt/rn-build-agent/build-agent`。令牌仍只在 env 文件（root 0600）里 |
| `RestartPreventExitStatus=77` | plist 用 `KeepAlive={SuccessfulExit:false}`；包装脚本把 77 翻成 0 并留一个 `revoked` 标记文件，成功退出 launchd 不重启 | 机器被吊销后别每 10 秒撞服务端 |
| `KillMode=mixed` | launchd 停服务只给主进程 SIGTERM，行为一致 | 排空而不是中止 |
| `/var/lib/rn-build-agent` | `/var/rn-build-agent`（macOS 没有 `/var/lib` 惯例） | 0700 |
| `/var/lib/rn-build-jobs` | `/var/rn-build-jobs` | 2750 |
| `ProtectSystem` / `InaccessiblePaths` 等 | 没有对应物 | 边界靠 uid 与文件权限，Linux 上也是这么说的（README「unit 硬化」末段） |

`build-runner` 的两处 Linux 假设要在真机上验：`reap` 清 `/tmp`、`/var/tmp`、`/dev/shm` 顶层属于构建用户的条目（`dirs.go`），macOS 没有 `/dev/shm`、每用户临时目录在 `/var/folders/…`；以及 `kill(-1)` 在 macOS 上的语义。两者都不是阻断，但要有结论再上生产。

### 4.2 钥匙串：固定路径 + 每任务重设搜索列表

问题（原文 §10.3 已预判）：执行进程的 `HOME` 是本任务的 `work/home`，而 macOS 把钥匙串搜索列表存在 `~/Library/Preferences/com.apple.security.plist`，登录钥匙串在 `~/Library/Keychains`。`HOME` 一换，`codesign` 什么证书都找不到。

做法：**钥匙串放固定路径，每个任务开始时在任务 HOME 里把它设成搜索列表并解锁。** 缓存隔离（pnpm、DerivedData、描述文件都在任务 HOME 下、用完即删）不受影响，签名材料也不在任务目录里。

```text
/var/rn-build-signing/                        _rnbuilder:_rnbuilder 0700   ← 机器装好时准备，不随任务删
  rn-signing.keychain-db                      0600  各租户 Team 的 Apple Distribution 证书 + 私钥
  rn-signing.password                         0600  钥匙串口令（随机生成，只有 _rnbuilder 读得到）
```

执行进程在 `buildIPA` 里、跑 `pnpm ios:release` 之前（Go 侧，不放进 RN-App 脚本，脚本要能在开发者自己的 Mac 上手工跑）：

```bash
security list-keychains -d user -s /var/rn-build-signing/rn-signing.keychain-db   # 写进任务 HOME 的 prefs
security unlock-keychain -p "$(cat /var/rn-build-signing/rn-signing.password)" /var/rn-build-signing/rn-signing.keychain-db
security set-keychain-settings /var/rn-build-signing/rn-signing.keychain-db       # 不自动上锁
```

装机时对每把导入的私钥做一次 `security set-key-partition-list -S apple-tool:,apple: -s -k <口令>`，否则 codesign 第一次用会弹 UI 授权——而这台机器没人盯着屏幕。

**要说清楚的一条**：`_rnbuilder` 跑的是 pnpm、CocoaPods、几千个依赖的代码，而它能解开这个钥匙串。也就是说**第三方构建代码能拿到该 Team 的 Distribution 证书私钥**。这是原文 §4.2 承认的 iOS 不对称——签名与构建分不开——本稿不假装解决了它，只把它缩到「这一把钥匙串、这几个 Team」，并靠 §7 的可撤销性兜底。

### 4.3 ASC 密钥分两层，上传挪到控制进程

现状：`pnpm ios:release --upload` 在**执行进程**里调 `xcrun altool`，`.p8` 按约定在 `~/.appstoreconnect/private_keys/` 找，`ASC_KEY_ID` / `ASC_ISSUER_ID` 是**机器级单值**环境变量（`jobspec.machineEnvKeys`）。在队列模式下这条路走不通，两个原因：

1. `~` 是任务 HOME，`.p8` 不在那里；`-allowProvisioningUpdates` 不带 `-authenticationKey*` 时用的是**当前用户在 Xcode 里登录的账号**，一个 role account 在任务 HOME 里没有这个东西。
2. 机器级单值只够一个 Team。多租户就是多 Team，一台 Mac 要给几个租户出包就要几把 Key。

改成：

| 用途 | 谁持有 | ASC 角色 | 存放 | 为什么 |
| --- | --- | --- | --- | --- |
| **申请证书与描述文件**（`-allowProvisioningUpdates`） | `_rnbuilder`（执行进程） | **Developer**，限制到本 App | `/var/rn-build-signing/provisioning/<TEAMID>/AuthKey_<KEYID>.p8` + `key.json{issuerId,keyId}` | xcodebuild 在执行进程里跑，只能它拿。Developer 是能干这件事的最小角色 |
| **上传 .ipa** | `_rnbuildagent`（控制进程） | Developer 或 App Manager，限制到本 App | `/var/rn-build-agent/asc/<TEAMID>/AuthKey_<KEYID>.p8` + `key.json` | 上传是对外可见、撤不回的动作，该由**不执行第三方代码**的那个进程做；控制进程还能在传之前独立核对 `.ipa` 的身份 |
| **只读同步**（模式 A） | 服务端（`ios.asc`） | App Manager | 数据库加密 | 已实现，不变 |

配套改动：

- `build-ios-release.mjs`：`--upload` 保留给手工路径；新增 `--provisioning-key-dir <目录>`，把 `-authenticationKeyPath / -authenticationKeyID / -authenticationKeyIssuerID` 传给两次 `xcodebuild`；目录按 `tenant.appleTeamId` 选子目录。**不再从 `.env.local` 读 `ASC_KEY_ID`**——它是 Team 级的，不是机器级的。
- `build-runner buildIPA`：不再传 `--upload`；把 `RN_IOS_SIGNING_DIR`（新增的机器级白名单键，只在 darwin 上接受）拼成上面的参数。
- `build-agent deliverIPA`：核对 `.ipa` 里 `Info.plist` 的 bundle id / 版本 / build 号（`unzip -p … | plutil -convert json`，控制进程自己做，不信执行进程的 `result.json`）→ `BUILD_AGENT_IOS_UPLOAD` 开着且本机有该 Team 的上传密钥 → `xcrun altool --upload-app --apiKey --apiIssuer`，`API_PRIVATE_KEYS_DIR` 指到控制进程自己的目录 → 传成功再报 `uploadedToAppStoreConnect: true`。
- `jobspec.machineEnvKeys` 里的 `ASC_KEY_ID` / `ASC_ISSUER_ID` 删掉。

密钥泄露的后果对照：执行进程那把（Developer）泄露，对方能给该 App 申请证书、注册设备、传 build；控制进程那把泄露，对方能传 build。两者都在 ASC 后台一点即废（原文 §4.6.1 的论证）。**每台 Mac 每个 Team 各自一把**，吊销一台 Mac 的密钥不影响别的 Mac——这也是 §5.5 下线一台 Mac 时要做的事。

### 4.4 装机清单（`install-macos.sh`，服务端下发）

复用 `install.sh` 的骨架与协议（describe → 下载核对安装包 → 安装 → enroll → 启动），但按角色只做构建机、按平台只做 macOS：

1. **前提**：Apple Silicon 或 x86_64；Xcode 已装并 `xcode-select`，`sudo xcodebuild -license accept` 与 `-runFirstLaunch` 已做；git ≥ 2.30、Node 22、pnpm、CocoaPods 在 `/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin` 里（这条 PATH 就是交给执行进程的那一条）；`LANG=en_US.UTF-8`（CocoaPods 在非 UTF-8 locale 下直接报错）。缺什么列全再退，注册码不消耗。
2. **用户与目录**：§4.1 那一列。`_rnbuilder` 的 home 设成 `/var/empty`，shell `/usr/bin/false`。
3. **程序**：`builder-darwin-arm64.tar.gz`（`build-bundles.sh` 多编一组 `GOOS=darwin GOARCH=arm64`，清单 `manifest.json` 里按 `role/os/arch` 多一项；`describe` 按脚本自报的 `uname` 选）。冒烟同 Linux：空环境跑 `build-agent` 必须以 2 退出。
4. **签名区**：建 `/var/rn-build-signing`，生成钥匙串与口令；**证书导入与 `.p8` 放置由人做**——脚本只建目录、打印放什么、什么权限，然后核对权限。密钥材料不经脚本、不经服务端。
5. **注册**：`build-agent enroll`（现有），注册码经 `RN_ENROLLMENT_CODE` 环境变量。
6. **仓库镜像**：生成 deploy key → 打印公钥 → 人加到 GitHub → **重跑同一条命令**克隆镜像（与 Linux 一致）。每台 Mac 一把 deploy key。
7. **常驻**：装 plist，`launchctl bootstrap system`，等 `runner-mode.json` 出现后打印 `show-key`。
8. **电源**：`pmset -c sleep 0 disksleep 0`，`systemsetup -setrestartpowerfailure on`；MacBook 要插电并合盖不休眠（`pmset -c disablesleep 1`）。这一步在 Linux 上不存在，在家里是第一位的故障源。

`env` 文件示例（`rn-build-agent-macos.env.example`，与 Linux 那份并排）：

```bash
BUILD_AGENT_SERVER=https://api.anyfun.win
BUILD_AGENT_MACHINE_TOKEN=            # enroll 写入
BUILD_AGENT_REPO=/var/rn-build-agent/repos/rn-app.git
BUILD_AGENT_WORKSPACE=/var/rn-build-jobs
BUILD_AGENT_STATE_DIR=/var/rn-build-agent/state
BUILD_AGENT_PLATFORMS=ios
BUILD_AGENT_TIMEOUT_MINUTES=120       # §6.2
BUILD_AGENT_RUNNER=/opt/rn-build-agent/build-runner
BUILD_AGENT_RUNNER_USER=_rnbuilder
BUILD_AGENT_IOS_UPLOAD=true           # 装机器的人决定
RN_IOS_SIGNING_DIR=/var/rn-build-signing    # 新增（§4.3）
LANG=en_US.UTF-8
```

## 5. 多台 Mac

### 5.1 一台 Mac 就是一台机器

每台 Mac 独立登记：自己的注册码、令牌、出处密钥、deploy key、ASC 密钥。**没有「Mac 池共用一个身份」这种东西**——吊销要能按台做。

出处密钥对 iOS 没有消费者（原文 §10.1 第 2 条），但注册与认领流程仍然要它：`enroll` 用它换令牌，`ensureKeyAccepted` 在控制台接受之前不领任务。所以控制台「接受」这一步对 Mac 照做，只是**不需要**在签名闸上 `trust-builder`——签名闸只签 Android，不认识 iOS 构建机。`DEPLOYMENT.md` §3.2 第 5 步对 iOS 机器跳过。

### 5.2 路由：平台之外再加 Apple Team

登记（`build.machines`）给构建机再加一个字段：

```jsonc
{ "id": "mch_…", "role": "builder", "platforms": ["ios"],
  "appleTeamIds": ["J4JDF12345", "ABCDE67890"] }   // 空 = 不限（沿用旧行为）
```

三处一起改，原则与 `platforms` 相同——**登记说了算，自报只能收窄**：

| 位置 | 规则 |
| --- | --- |
| 排队 `createBuildJob` | iOS 任务：没有一台 active、`platforms` 含 ios、且 `appleTeamIds` 为空或含该租户 `release.ios.appleTeamId` 的机器 → 409 `NO_BUILDER_FOR_TEAM`，提示去登记或去那台 Mac 上装这个 Team 的身份 |
| 认领 `claimBuildJob` | iOS 任务的 SQL 多一个条件：`platform<>'ios' OR tenant_id IN (<该机器 appleTeamIds 对应的租户>)`。租户 → Team 的映射从 `app_configs` 的 `release.ios` 读，认领时算一次 |
| 改登记 `POST /machines/:id/apple-teams` | `expectedVersion` + `reason` + `confirm`，进审计；照 `setMachinePlatforms` 抄 |
| 代理自己 | 领到任务后、动磁盘之前，`prepareWorktree` 加一条：`security find-identity -v -p codesigning <钥匙串>` 里有没有该 Team 的 Apple Distribution 证书。没有就 `refused`（走现有的 `Refused` 上报路径判失败），并在日志里说清是登记错了 |

为什么不用租户 slug 而用 Team ID 登记：Mac 上持有的是 Team 的证书，一个 Team 下可能有几个租户的 App（原文 §7.1 实测那把 Key 能看到 5 个 App）；按 Team 登记与机器上实际有的东西一一对应。

### 5.3 并发与公平

- **一机一活**：`claimBuildJob` 对每台机器同时只派一条（409 `BUILDER_HAS_ACTIVE_JOB`）。两台 Mac 就是两条并发的 iOS 构建，不需要别的调度。
- **FIFO 跨租户**：`ORDER BY created_at`。iOS 队列与 Android 队列在同一张表里，但 Mac 只领 `platform='ios'`，互不影响。
- **不做亲和**：不记「租户 X 上次在哪台 Mac 打的」。iOS 没有增量缓存可复用（每任务新 HOME），亲和买不到东西。
- **Xcode 版本**：几台 Mac 装同一个 Xcode 版本，`build-ios-release.mjs` 把 `xcodebuild -version` 打进日志，`result.json` 加 `toolchain` 字段，服务端记进 `file_metadata`。Apple 不接受过旧 SDK 打的包，出问题时得知道是哪台机器的哪个 Xcode。

### 5.4 在线状态：加一张心跳表

`build.machines` 是 `app_configs` 里一份带版本号的 JSON 文档，写入走乐观锁（`writeMachineRegistry`）。N 台机器每 10 秒认领一次，把「最近在线」写回它会互相冲突。**另开一张表**：

```sql
CREATE TABLE build_machine_liveness (
  machine_id   VARCHAR(64) PRIMARY KEY,
  last_seen_at DATETIME(3) NOT NULL,
  agent_commit VARCHAR(48),
  os           VARCHAR(16),          -- darwin / linux
  platforms    JSON,
  updated_at   DATETIME(3) NOT NULL
);
```

- `claim` 与 `heartbeat` 里 `INSERT … ON DUPLICATE KEY UPDATE`，每机器每分钟最多写一次（服务端按 `last_seen_at` 节流），不进审计。
- `hasLiveBuilderFor` 的判据加一条「`last_seen_at` 在 5 分钟内」，排队闸的错误文案区分「没登记」和「登记了但都不在线」。
- 控制台机器卡片显示「最近在线 x 分钟前」，超过 30 分钟标黄；有 iOS 任务排着、却没有一台 ios 机器在线时在打包任务列表顶部提示。
- 代理侧不用改：它本来就在发这两个请求。`agent_commit` / `os` 从 `claim` 请求体新增的可选字段带上。

### 5.5 上一台、下一台

**上**：控制台新建构建机（勾 ios、填 Team ID）→ 把一次性安装命令（60 分钟有效、一次性）通过安全渠道发给那台 Mac 的主人 → 对方按 §4.4 执行 → 加 deploy key、重跑 → 控制台接受出处公钥 → 主人把证书导进钥匙串、放两把 `.p8` → 排一条测试任务。机器主人**不需要**控制台账号。

**下**（顺序）：等它手上的任务结束 → 控制台吊销（令牌立即失效，代理以 77 退出）→ **ASC 后台吊销这台 Mac 的两把 Key** → Mac 上 `launchctl bootout`，销毁 `/var/rn-build-agent`（令牌、出处私钥、上传 Key、镜像）、`/var/rn-build-signing`（钥匙串、描述文件 Key）、`/etc/rn-build-agent.env` → GitHub 删它的 deploy key。Distribution 证书的私钥这台机器持有过，**要不要吊销证书**看它是不是因为被攻陷才下线：证书吊销会让别的 Mac 上同一张证书失效，得重新申请（自动签名会自己申请，代价是一次构建失败后重试）。

**换程序**：拉模型意味着服务端推不了升级。安装包接口要注册码，已注册的机器拿不到。加一条 `GET /v1/build-agent/bundle`（机器令牌鉴权，回本机 os/arch 的安装包与 sha256），Mac 上一条 `rn-build-agent-upgrade` 脚本下载、核对、替换两个二进制、重启——两个二进制协议版本要一致（`checkRunner --protocol`），所以一起换。在此之前按 README「换二进制」手工 scp。

## 6. 家用网络的失效路径

### 6.1 断网、休眠、断电

| 发生什么 | 现有行为 | 结果 | 要改的 |
| --- | --- | --- | --- |
| 构建中断网 < 10 分钟 | 心跳失败只记日志，构建继续；网络回来心跳恢复 | 没影响 | — |
| 断网 ≥ 10 分钟 | 服务端回收：任务退回 `queued`、`attempt+1`（`reapStaleBuilds`）；Mac 下一次心跳 409 `BUILD_ATTEMPT_STALE`，当场中止、清目录、不上报 | 任务被另一台（或同一台）重领重建 | 见 §6.3 的重复上传问题 |
| 构建中休眠 / 断电 | 同上被回收；Mac 醒来后认领撞 409 `BUILDER_HAS_ACTIVE_JOB`（若还没被回收）→ 上报失败 | 一条失败记录，任务要重排 | §4.4 第 8 步禁休眠；断电靠 `restartpowerfailure` |
| 服务端不可达（机房维护） | 认领失败只记日志，10 秒后再试；结果上报按退避重试到分钟级（`report`） | 自愈 | — |
| Mac 换了网络（IP 变） | 无感：没有任何按 IP 的绑定 | — | — |
| 出口被运营商拦 22 | 检出失败 | 任务失败 | §2.2 的 ssh 443 |

### 6.2 时长

一次 iOS 任务的时间构成：`pnpm install`（每任务独立 store，家用下行）+ `pod install`（CocoaPods CDN）+ `prebuild` + `archive`（Mac mini M 系列 10–20 分钟量级）+ `export` + **上传几百 MB 到 Apple（家用上行，可能十几分钟）**。默认 45 分钟偏紧，Mac 上写 `BUILD_AGENT_TIMEOUT_MINUTES=120`（上限 480）。心跳 goroutine 在整个 `buildAndDeliver` 期间都在跑（`runJob`），上传阶段不会因为没心跳被回收。

带宽是家用机的主要成本。每任务独立 pnpm store 是安全决定（`build-concurrency-2026-09-15.md` §7 的硬链接 TOCTOU），不为省带宽回退。可选的省法是家里放一个 npm 只读镜像（verdaccio 之类）并把它写进 `.npmrc`——那是机器主人的事，不进本稿。

### 6.3 重复上传：同一个 build 号传两次

任务被回收重排后**build 号不变**（任务行上的参数）。第一次尝试如果 `.ipa` 已经传进 ASC、只是 `/ios-release` 那一步没报上去，重建后再传，Apple 会拒：同一 `CFBundleVersion` 不能传两次。任务就此失败，而 ASC 上其实有这个 build。

处理：控制进程上传前先查一次（用它自己那把 Key，`GET /v1/builds?filter[app]=…&filter[version]=<build 号>`，`internal/ascapi` 已有 `LatestBuilds`，补一个按 version 过滤的调用）：

- 已有且 `processingState` 不是 `FAILED`/`INVALID` → 不再上传，按 `uploadedToAppStoreConnect: true` 上报，日志写明「ASC 上已有此 build，跳过上传」；
- 没有 → 上传。

服务端侧 `/ios-release` 的幂等已经有（同一认领、同一摘要回原记录；不同摘要 409 `IOS_RESULT_CONFLICT`）。跨认领的重复由上面这条挡。**如果本机没有上传 Key（`BUILD_AGENT_IOS_UPLOAD` 关）**，这条查询也做不了，那就是原文的手工路径：包留在机器上，人来传。

### 6.4 时钟

ASC 的 JWT `exp` ≤ 20 分钟，家用 Mac 时钟漂移几分钟就会 401。macOS 默认开 NTP（`systemsetup -getusingnetworktime`），装机脚本核对一次即可。

## 7. 安全边界：与 Android 侧不同的地方

沿用 `android-signing-gate-2026-09-16.md`「每个角色被攻破会怎样」的写法：

| 被攻破的 | 能做什么 | 挡它的 | 挡不住的 |
| --- | --- | --- | --- |
| **Mac 执行进程**（第三方依赖投毒） | 拿到本机钥匙串里的 Distribution 私钥与 Developer 角色 Key；能签**该 Team** 的任意包 | 只能签，**不能传**：上传 Key 在控制进程；传上去也要过 TestFlight 处理与 Beta 审核；证书与 Key 可在 Apple 后台吊销；用户装的是 Apple 重签的那份 | 它交付给控制进程的 `.ipa` 里的代码——控制进程核对身份，核不了内容（Android 侧同样承认这一点） |
| **Mac 控制进程**（令牌、上传 Key 泄露） | 以这台机器的名义交 `/ios-release`（无产物，服务端只核身份字段）；传任意 `.ipa` 进该 Team 的 ASC | 服务端要求 bundleId / 版本 / build 号与任务行和 `release.ios` 一致；控制台吊销机器令牌；ASC 吊销 Key | 已经落库的那条发布记录会成为 `latestVersion` 与 OTA 基线的依据——所以 `latestVersion.ios` 阶段一仍是**运营手填**（原文 §4.5.2），不跟随发布记录，是有意的 |
| **服务端 / 数据库** | 排任务、改 `release.ios`（Team ID、bundle id、installUrl）、改机器登记 | Mac 检出固定 `main`（`buildBranch`），身份文件里的 bundle id 要与 `tenants/<slug>/tenant.json` 一致（`tenantfile.go` 那道闸），Team 要在本机钥匙串里有证书（§5.2 代理自检）；改 `installUrl` 只能指向 `testflight.apple.com` / `apps.apple.com` | 改 `installUrl` 把用户导去另一个 TestFlight 链接——这是原文 §4.5.1 已知的面，靠审计与只允许两个 host 缩小 |
| **一台 Mac 的主人** | 上面两条的合集，对它持有的那几个 Team | `appleTeamIds` 登记让它领不到别的租户的任务；每台 Mac 各自的 Key，吊一台不牵连别的 | 它持有的 Team 的证书私钥——这就是「让谁家的 Mac 持有哪个租户的身份」是**业务决定**而不是技术决定的原因 |

与 Android 最大的不同：Android 侧「执行第三方代码的机器没有签名能力」在 iOS 上不成立。本稿做的是把这个必然的暴露面切细（按 Team、按机器、按用途分密钥）并让每一片都可撤销，不是消除它。

## 8. 改动清单

### 8.1 服务端（RN-Server）

| # | 改什么 | 位置 | 量级 |
| --- | --- | --- | --- |
| S1 | 机器登记加 `appleTeamIds`；排队与认领按它过滤；`POST /machines/:id/apple-teams` | `machines.go`、`build_jobs.go` `createBuildJob`、`build_agent.go` `claimBuildJob`、契约 | 中 |
| S2 | `build_machine_liveness` 表与迁移；`claim`/`heartbeat` 节流写入；`hasLiveBuilderFor` 加在线判据；机器视图带 `lastSeenAt` | `build_agent.go`、`build_reaper.go` 旁、`machines.go`、迁移 | 中 |
| S3 | `claim` 请求体接受可选 `agentCommit` / `os`；`/ios-release` 接受可选 `toolchain` 记进 `file_metadata` | `build_agent.go`、`ios_build_release.go`、`client.go` | 小 |
| S4 | 安装包多一组 darwin/arm64（可再加 amd64）；`manifest.json` 按 `role/os/arch`；`describe` 与 `bundle` 按脚本自报 os/arch 选 | `deploy/setup/build-bundles.sh`、`machine_setup.go`、CI `deploy-amos.yml` | 中 |
| S5 | `install-macos.sh`（服务端 `go:embed` 下发，`GET /v1/machine-setup/install-macos.sh`） | `internal/machinesetup/` | 大（脚本） |
| S6 | `GET /v1/build-agent/bundle`（机器令牌鉴权，给已注册机器自升级用） | `machine_setup.go` | 小 |
| S7 | `ascapi` 补按 build 号查询 | `internal/ascapi` | 小 |
| S8 | Rancher 部署：机器安装包目录挂卷；`TRUSTED_PROXIES`；出站到 ASC 的 NetworkPolicy；Ingress 不重定向打包机路径 | 部署清单，不是代码 | — |

### 8.2 打包机程序（`cmd/build-agent`，同仓）

| # | 改什么 | 位置 |
| --- | --- | --- |
| A1 | 机器级白名单键加 `RN_IOS_SIGNING_DIR`（仅 darwin 接受）；删 `ASC_KEY_ID` / `ASC_ISSUER_ID` | `jobspec.go`、`config.go` |
| A2 | `buildIPA`：设钥匙串搜索列表并解锁（§4.2）；把 Team 的 provisioning Key 参数交给脚本；不再传 `--upload` | `build-runner/build.go` |
| A3 | `deliverIPA`：控制进程读 `.ipa` 的 `Info.plist` 核身份；查 ASC 有没有同号 build；上传；`uploadedToAppStoreConnect` 以真实结果为准 | `agent.go`、新 `ios_upload.go` |
| A4 | `prepareWorktree`：iOS 任务先查本机钥匙串有没有该 Team 的证书，没有就 refused | `checkout.go` |
| A5 | `claim` 带 `agentCommit` / `os` | `client.go` |
| A6 | `reap` 与临时目录清理的 macOS 分支；`/dev/shm` 不存在时静默 | `build-runner/dirs.go` |
| A7 | 退出码 77 时的 launchd 处理放在包装脚本里，程序不改 | `deploy/build-agent-macos/` |

### 8.3 RN-App

| # | 改什么 |
| --- | --- |
| R1 | `build-ios-release.mjs`：`--provisioning-key-dir`，`-authenticationKeyPath/-authenticationKeyID/-authenticationKeyIssuerID` 传给两次 xcodebuild；打印 `xcodebuild -version`；`--upload` 只留手工路径 |
| R2 | `result.json` 的 `toolchain` 由脚本写到 stdout 一行、runner 解析（或 runner 自己跑 `xcodebuild -version`） |

### 8.4 RN-Admin

| # | 改什么 |
| --- | --- |
| C1 | 机器卡片：`appleTeamIds` 的显示与修改（照 `platforms` 抄）；「最近在线」；离线标黄 |
| C2 | 新建构建机时可选「macOS」，安装命令换成 `install-macos.sh` 那条 |
| C3 | 打包任务列表：有 iOS 任务排队而无在线 iOS 机器时的提示 |

## 9. 落地顺序与验证

**阶段 A：一台 Mac、一个租户，手工装（不改服务端）**
先用现有代码在第一台 Mac 上把原文 §6 第 9 条「真机跑一遍」做完——这一条没有替代品。手工建用户、目录、sudoers、launchd，`BUILD_AGENT_PLATFORMS=ios`，`BUILD_AGENT_IOS_UPLOAD` 关。预期第一个错就是钥匙串（§4.2），在这台机器上把 A2 的做法验出来。
验证：控制台排一条 iOS 任务 → Mac 领到 → 出 `.ipa` → `/ios-release` 落记录、任务 succeeded → 包用手工 `altool` 传上去 → 内部测试组装机 → 冷启动、bootstrap、深链、Face ID、OTA。

**阶段 B：上传挪到控制进程，密钥分层（A1–A3、R1）**
验证：`BUILD_AGENT_IOS_UPLOAD=true` 下整条链不需要人碰；拔网线 15 分钟再插回，任务被回收重排，第二次不重复上传（§6.3）。

**阶段 C：第二台 Mac、第二个 Team（S1、A4、C1）**
验证：两个租户各排一条，分别落到持有其 Team 的 Mac 上；把一台的 `appleTeamIds` 清空，它领到不该领的任务时当场 refused 而不是构建到一半失败。

**阶段 D：在线状态与装机脚本（S2–S6、C2、C3）**
验证：合上 MacBook 盖子，5 分钟后控制台标离线、排队被 409；打开后自愈。新 Mac 从控制台一条命令装到能领任务，中途不出现令牌、口令、`.p8` 内容。

**阶段 E：Rancher 上线（S8）**
验证：`describe` 从卷里读到安装包；`externalOrigin` 拼出的安装命令是 https 的外部域名；两个 API 副本同时在，两台 Mac 同时认领只各拿到一条。

## 10. 未决

1. **Mac 的主人是谁**决定了「哪些 Team 的证书放在哪台机器上」。一台 Mac 服务多个租户，等于那台机器的主人能签那几个租户的包（§7 最后一行）。这是运营决定，本稿只提供按 Team 隔离的工具。
2. iOS 的 OTA 构建（`expo export --platform ios`）不需要 Xcode，理论上可以在 Linux 构建机上做；现在执行进程写死 `--platform android`（`buildOTA`）。要不要让 amos 顺带出 iOS 的热更新包，与本稿无关，但会影响「Mac 要不要领 OTA 任务」的答案（现在是不领：`validateClaimedJob` 拒绝 iOS 的 OTA 任务）。
3. 已注册机器的自升级（S6）做不做。不做就是每台 Mac 手工 scp 两个二进制，台数多了以后会有人忘。
4. 钥匙串口令文件对 `_rnbuilder` 可读等于对第三方代码可读（§4.2）。替代是每次任务由人解锁——那与「无人值守」冲突。接受，记进风险台账。
