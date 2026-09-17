# 构建机部署

设计见 `docs/design/android-signing-gate-2026-09-16.md`「构建机」「部署与运维」，装机与注册见 `docs/design/android-signing-gate-automation-2026-09-16.md`「2. 新机器」。

**构建机没有签名能力。** 它执行 pnpm、Gradle 和几千个第三方依赖的代码，按不可信处理：手上没有任何签名密钥，只交付**未签名包**、SBOM 和一份用本机出处密钥签名的出处声明；正式签名由签名闸做，签名闸只认在它本机 pin 过的构建机公钥。

## 一句话拓扑

```
build-agent（rn-build-agent） ──出──→ API（领任务 / 心跳 / 传未签名包与 SBOM / 交出处声明）
                              ──出──→ GitHub（fetch 仓库镜像，只读 deploy key）
        │ sudo -n -u builder
        ▼
build-runner（builder）       ──出──→ npm / Maven / Gradle（拉依赖）
                               ←─入── 什么都没有，不监听任何端口
```

## 两个进程，两个用户

| 进程 | 用户 | 持有 | 碰不到 |
| --- | --- | --- | --- |
| 构建控制进程 `build-agent` | `rn-build-agent` | 本机令牌 `BUILD_AGENT_MACHINE_TOKEN`、Ed25519 出处签名密钥、仓库镜像、只读依赖缓存 | 不执行仓库与依赖里的任何代码；执行进程的产物只当字节读 |
| 构建执行进程 `build-runner` | `builder` | 只有当前任务的一次性目录 | 令牌、出处密钥、仓库镜像、控制进程的 `/proc/<pid>/environ` |

- 控制进程经一条收窄的 sudoers 规则启动执行进程（`rn-build-agent.sudoers`）：`rn-build-agent ALL=(builder) NOPASSWD:NOSETENV: /opt/rn-build-agent/build-runner`。规则不限参数，参数由 `build-runner` 自己校验。
- **生产环境禁止 `BUILD_AGENT_RUNNER_USER=-`。** 这个值让执行进程不经 sudo、与控制进程同一个用户运行，第三方构建代码读得到本机令牌和出处私钥，这台机器交付的出处声明就不可信。它是给开发机本地测试的显式配置，代码不拒绝它，但会让它无处藏身：启动日志与每个任务的日志告警，`show-key` 的 `build runner:` 一行标出 `SAME USER AS THE BUILD AGENT`（状态由常驻进程启动时写进状态目录的 `runner-mode.json`）。在签名闸上 `trust-builder` 之前必须确认这一行是 `separate user builder via sudo`。
- 执行进程的环境不继承任何东西：sudo 本来就重置环境，执行进程也不读自己的环境，给子进程的环境全部来自任务说明里的白名单。
- 控制进程负责 fetch 与检出，检出固定 `refs/heads/main`（任务里的 `gitRef` 只核对，不是 `main` 就拒绝），过程中不跑任何 hook、不读系统与全局 git 配置。
- 控制进程给出处声明签名：jobId、attempt、租户 slug、包名、versionCode、versionName、commit、未签名包 sha256 与大小、SBOM sha256、原生指纹、构建机 id、时间。commit 与原生指纹是构建机自报，签名闸复核原生指纹。

## 执行进程调用协议

```
sudo -n -u builder -- /opt/rn-build-agent/build-runner build      --jobs-root /var/lib/rn-build-jobs --job <jobId> --kind apk|ota
sudo -n -u builder -- /opt/rn-build-agent/build-runner cleanup    --jobs-root /var/lib/rn-build-jobs --job <jobId>
sudo -n -u builder -- /opt/rn-build-agent/build-runner self-check --jobs-root /var/lib/rn-build-jobs --protocol 1 --expect-separated
```

- 退出码：0 成功；1 构建失败；2 参数、身份或任务目录不合规。空参数退出 2。失败原因是标准输出最后一行 `build-runner: error: …`。
- 执行进程自己校验：以 root 运行一律拒绝；`--jobs-root` 是规范的绝对路径、没有 `..`；`--job` 按服务端 id 规则（天然不含 `/`、`..`）；`--kind` 只能 `apk`/`ota`；同一个参数不许出现两次、不许多余的位置参数。经 sudo 运行时，任务根目录、任务目录、`src/`、`spec.json` 必须属于调用 sudo 的用户且执行进程改不了，`spec.json` 不能是符号链接。
- `self-check` 在控制进程启动时跑一次：确认 sudo 规则装好了、执行进程确实是另一个 uid、两个二进制的任务协议版本一致（只换了其中一个就启动失败）。

任务目录 `<jobs-root>/<jobId>/`：

| 路径 | 谁写 | 内容 |
| --- | --- | --- |
| `spec.json` | 控制进程 | 任务说明：kind、租户目录、版本、build 号、commit、热更新参数、子进程环境。执行进程严格解析（未知字段拒收）并逐项校验环境白名单 |
| `src/` | 控制进程 | 从仓库镜像浅取的单提交仓库（`.git` 是自包含的真目录），加上服务端下发的 `tenant.json`、图标、`ota-certificate.pem`、`google-services.json` |
| `work/` | 执行进程 | `app/`（`src/` 的副本，全部属于 builder）、`home/`、`gradle-home/`、`pnpm-store/`、`tmp/` |
| `out/` | 执行进程 | 固定文件名交回：`app-release-unsigned.apk`、`sbom.cdx.json`、`ota.zip`、`result.json`（原生指纹） |

控制进程读 `out/` 时把内容当不可信数据：`O_NOFOLLOW` 打开，拒绝符号链接、硬链接、FIFO 与超限文件（未签名包、热更新包 2 GiB，SBOM 16 MiB，结果 64 KiB），先复制进自己状态目录里的 `spool/` 再算 sha256、上传、签出处，之后执行进程残留的进程再改原文件也影响不到。SBOM 只当 JSON 读，核对它绑定的是这个未签名包（`metadata.component` 的 SHA-256、属性 `rn-app:artifact` 与 `rn-app:artifact-signing=unsigned`）。

## 每个任务的隔离

- **子进程环境白名单**（`cmd/build-agent/internal/jobspec`，控制进程在 `prepareWorktree` 里构造，安装包与热更新共用，测试断言两边一致）：
  - 机器级：`PATH`（unit 里设）、`LANG`、`JAVA_HOME`、`ANDROID_HOME`、`ANDROID_SDK_ROOT`、`GRADLE_RO_DEP_CACHE`，取自控制进程环境
  - 每任务目录：`HOME`、`GRADLE_USER_HOME`、`npm_config_store_dir`、`TMPDIR`、`ANDROID_USER_HOME`，都在 `work/` 下、用完删除
  - 任务专用：`EXPO_PUBLIC_TENANT`、`EXPO_PUBLIC_API_BASE_URL`、`EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=./ota-certificate.pem`、`EXPO_REQUIRE_OTA_SIGNING=1`、`GOOGLE_SERVICES_JSON=./google-services.json`（相对路径：它们进 expo config，也就进原生指纹）
  - 不再有 `GRADLE_DEPENDENCY_VERIFICATION`（RN-App 的 release 构建强制依赖校验）与四个 `ANDROID_RELEASE_*` 签名变量
- **跨任务不留东西**：执行进程在每个任务开始时和清理时回收 builder 的一切——`kill(-1)` 杀掉 builder 的全部进程（Gradle daemon、自己 setsid 出去的后台进程），删掉 `/tmp`、`/var/tmp`、`/dev/shm` 顶层属于 builder 的条目（例如 Metro 缓存）。builder 在这台机器上只能给执行进程用。
- **builder 没有能落脚的家目录**：passwd 里的 home 是 `/nonexistent`、shell 是 `nologin`，放进 `/etc/cron.deny` 与 `/etc/at.deny`。Java 按 passwd 取 `user.home`，所以 `ANDROID_USER_HOME` 显式指到任务目录。
- 未签名包按 RN-App `scripts/build-android-release.mjs` 的产物名 `artifacts/<租户目录>-<版本>-build<号>-release-unsigned.apk` 查找；原生指纹算不出来安装包任务直接失败（出处声明要它）。

## 依赖缓存

### pnpm：每个任务一个独立 store（已实测，选定）

设计让先验证"只读 store 下 `pnpm install --frozen-lockfile --offline` 是否可行"。2026-09-16 在开发机上用 RN-App（1197 个包，store 736 MB）实测：

| 做法 | 结果 |
| --- | --- |
| `pnpm fetch` 填 store 后 `chmod -R a-w`，再 `--offline` 安装 | **失败**：pnpm 10.32.1 在 `getContext` 里无条件把项目登记进 `<store>/v10/projects/`（symlink），只读 store 直接 EACCES；`packageManager` 与已装版本不同时还会先往 `$HOME` 装另一个 pnpm 并同样登记进 store |
| 只放开 `v10/projects/` 可写，关掉版本切换 | 可行：离线 2–3 秒；以另一个 uid（`sudo -u nobody`）安装时硬链接被 `protected_hardlinks` 拒绝，pnpm 自动改为复制（链接数 1，属安装用户） |
| 每任务新 store、在线 `pnpm install --frozen-lockfile` | 可行：4.7 秒（含每任务把 `packageManager` 指定的 pnpm 10.28.1 装进任务 `HOME`），store 随任务删除 |

选**每任务独立 store**。只读 store 在技术上能凑出来，但维护它绕不开两件事：控制进程在仓库检出上跑 pnpm（`.pnpmfile.cjs`、`configDependencies`、`packageManager` 版本切换都会执行仓库指定的代码），或者由执行进程填充后交给控制进程——而 store 的 `index/` 文件把 tarball 完整性映射到文件哈希，没有原 tarball 就无法验证，被下过毒的 store 会在之后每个任务里被信任。两种做法换来的只是每个任务省几秒到几分钟。每任务独立 store 时，tarball 完整性由 lockfile 保证，任务之间不共享任何 pnpm 状态。代价：每个任务都要访问 npm registry，registry 不可用时构建失败。

### Gradle：只读依赖缓存 `GRADLE_RO_DEP_CACHE`（可选，方案）

控制进程只负责把 `GRADLE_RO_DEP_CACHE` 交给执行进程，并在启动时核对它是真实目录、属于 rn-build-agent、组与其他人不可写；unit 的 `ProtectSystem=strict` 让它在运行时对控制进程和执行进程都是只读的。不设就是每个任务在自己的 `GRADLE_USER_HOME` 里从零下载依赖（慢，另外每个任务还会下载一次 Gradle 发行包）。

维护方案（尚未实现，按这个顺序做，控制进程全程不执行第三方代码）：

1. **填充**：挑一条成功的安装包任务，由执行进程在交回产物时把 `gradle-home/caches/modules-2` 硬链接进 `out/gradle-cache/`（自己的文件，零拷贝）。
2. **复制并校验**：由 root 或控制进程把它**逐字节复制**（不是硬链接，硬链接保留 builder 的 inode）进 `/var/cache/rn-build-agent/gradle-ro.<时间>.tmp/`，只接受普通文件与目录，丢掉 `*.lock` 与 `gc.properties`；`files-2.1/<group>/<module>/<version>/<sha1>/<file>` 逐个核对文件 SHA-1 等于所在目录名，且 SHA-256 出现在**控制进程自己检出的** `main` 的 `gradle/verification-metadata.xml` 里——对不上整份作废。
3. **原子切换**：权限收成 rn-build-agent:rn-build-jobs 0750/0640，`rename` 成新版本目录，改 `GRADLE_RO_DEP_CACHE` 指向它，重启服务；旧版本保留一份以便回退。`verification-metadata.xml` 变了就重做一次。

残余风险：`metadata-2.*` 里是 Gradle 的二进制元数据缓存，无法独立校验，被下毒时能影响依赖解析结果（例如在清单里都登记过的版本之间替换）；但 RN-App 在 release 构建里强制 Gradle 依赖校验，**任何不在 `verification-metadata.xml` 里的产物都会让构建失败**，这是这道缓存真正的防线。清单本身在仓库 `main` 里，谁能改 `main` 谁就能改它——那已经在"能改代码"的威胁里。填充用的那个任务如果被攻破，它能放进缓存的也只有清单里登记过的产物。

## 目录与权限

| 路径 | 属主 | 模式 | 说明 |
| --- | --- | --- | --- |
| `/opt/rn-build-agent/build-agent` | root:root | 0755 | 控制进程 |
| `/opt/rn-build-agent/build-runner` | root:root | 0755 | 执行进程；控制进程启动时拒绝一个组或其他人可写、或不属于 root 的执行进程二进制 |
| `/etc/rn-build-agent.env` | root:root | 0600 | 含本机令牌（`build-agent enroll` 写入）；systemd 以 root 读 |
| `/var/lib/rn-machine-setup/` | root:root | 0700 | install.sh 按注册码留下的查询结果与安装包（重复执行用，没有机密，装好后可删） |
| `/etc/sudoers.d/rn-build-agent` | root:root | 0440 | 那一条规则 |
| `/var/lib/rn-build-agent/` | rn-build-agent:rn-build-agent | 0700 | rn-build-agent 的 HOME；builder 连进都进不去 |
| `/var/lib/rn-build-agent/.ssh/` | rn-build-agent | 0700 | GitHub 只读 deploy key |
| `/var/lib/rn-build-agent/state/` | rn-build-agent | 0700 | `provenance-ed25519.key`（0600）、`spool/`。权限不对控制进程拒绝启动 |
| `/var/lib/rn-build-agent/repos/rn-app.git` | rn-build-agent | 0700 | 仓库镜像 |
| `/var/lib/rn-build-jobs/` | rn-build-agent:rn-build-jobs | 2750 | 任务根目录。builder 在组里：进得去、读得到，**建不了东西** |
| `/var/lib/rn-build-jobs/<jobId>/work`、`out` | rn-build-agent:rn-build-jobs | 2770 | builder 可写；setgid 让它建的文件属 rn-build-jobs 组，控制进程读得回来 |
| `/var/cache/rn-build-agent/gradle-ro*/` | rn-build-agent:rn-build-jobs | 0750 / 文件 0640 | 可选的只读 Gradle 依赖缓存 |
| `/opt/android-sdk` | root:root | 0755 | builder 只读，所以 NDK 版本要预装齐 |

builder 能写的地方只有当前任务的 `work/`、`out/` 与 `/tmp` 一类公共临时目录（后者每个任务开始时清掉属于它的条目）。

## unit 硬化

`rn-build-agent.service`：`User=rn-build-agent`、`SupplementaryGroups=rn-build-jobs`、`UMask=0027`、`PrivateTmp`、`ProtectSystem=strict`（可写只有 `/var/lib/rn-build-agent`、`/var/lib/rn-build-jobs`）、`ProtectHome`、`ProtectControlGroups`、`ProtectProc=invisible`（同一个 unit 里的 builder 进程看不见 rn-build-agent 的进程）、`KillMode=mixed`（见「换二进制」）、`LimitCORE=0`，以及 `InaccessiblePaths` 挡住同机签名闸的 `/etc/rn-signer-{a,b}.env`、`/var/lib/rn-signer-{a,b}`、`/run/rn-signer-{a,b}`、两个检查进程 socket、`/opt/rn-signer`，和服务端的 `/etc/rn-foundation.env`（纵深防御，真正的边界是那些路径的属主与权限）。

**没有 `NoNewPrivileges`**，也没有任何会被 systemd 隐式换成 `NoNewPrivileges` 的选项（`SystemCallFilter`、`SystemCallArchitectures`、`RestrictAddressFamilies`、`PrivateDevices`、`ProtectKernel*`、`MemoryDenyWriteExecute`、`RestrictSUIDSGID`、`LockPersonality` 等）：执行进程靠 sudo 切用户，那些选项会让 sudo 直接失败。2026-09-16 在开发机上用 `systemd-run` 按这份 unit 的选项实测过：sudo 切到另一个用户可行，`build-runner` 在沙箱里完整跑通一次安装包构建，控制进程靠组权限读回产物，构建用户读不到控制进程状态目录、看不到控制进程的 `/proc`；加上 `PrivateDevices=yes` 或 `SystemCallArchitectures=native` 后 sudo 报 "no new privileges flag is set"。分用户这道边界靠 uid 与文件权限，不靠这些选项。

## 依赖的软件

| 软件 | 为什么要 | 装漏了会怎样 |
| --- | --- | --- |
| JDK 17 | Gradle / Android 构建 | Gradle 起不来 |
| Node.js 22 | Expo prebuild、`pnpm android:release`、SBOM 脚本 | 第一步就失败 |
| pnpm | 仓库用 pnpm lockfile；`packageManager` 指定的版本会被装进每个任务的 HOME | `--frozen-lockfile` 不认别的包管理器 |
| git ≥ 2.30 | 控制进程的仓库镜像与每任务检出；执行进程的副本里 `build-ota.mjs` 要用 | 检出失败 |
| sudo | 控制进程启动执行进程 | 启动自检失败，控制进程以 2 退出 |
| Android SDK / NDK | 编译 | 构建到一半才报缺组件 |
| syft（固定版本+校验和，`deploy/amos/install-syft.sh`） | 生成 SBOM，构建的必经步骤 | 安装包任务失败 |
| zip | `build-ota.mjs` 打热更新包 | 热更新任务失败 |

## 装一台新的

一条命令（自动化设计「2. 新机器」，完整步骤见 `deploy/amos/SIGNING_GATE_ROLLOUT.md` 第 2 节）：

1. 平台管理员在控制台「平台维护 → 打包机与签名闸 → 新建机器」选构建机，得到一次性安装命令（注册码 60 分钟有效、只能用一次）。
2. 在构建机本机执行：
   ```bash
   curl -fsSL https://api.anyfun.win/v1/machine-setup/install.sh | sudo bash -s -- --server https://api.anyfun.win --code rne_…
   ```
3. 按输出的“下一步”：把 deploy key 加到 GitHub（只读）后重新执行同一条命令克隆仓库镜像；在控制台核对出处公钥 sha256 后接受；在每台签名闸上 `trust-builder --builder <机器名>`。

安装脚本（`internal/machinesetup/install.sh`，服务端下发）对构建机做的事：

- **检查前提**：JDK 17、`/opt/android-sdk`、Node 22、pnpm、syft、zip、git ≥ 2.30、sudo、openssh-client。缺什么列出来退出，注册码不会被用掉。
- **下载安装包**：服务端的 `builder.tar.gz`，核对归档与每个文件的 sha256，内容是 `bin/build-agent`、`bin/build-runner`、unit、sudoers、env 示例、本 README。
- **安装**：
  - 建 `rn-build-jobs` 组、`rn-build-agent` 与 `builder` 用户（builder 家目录 `/nonexistent`、nologin、进 cron/at deny）；
  - 建「目录与权限」一节的目录；
  - 装两个程序、sudoers（visudo 校验）、unit；
  - 冒烟：以 builder、空环境跑两个程序，都必须以 2 退出。
- **仓库镜像**：
  - GitHub 只读 deploy key 没有就生成；固定 known_hosts 写到 `/opt/rn-build-agent/github_known_hosts`（root 所有、rn-build-agent 改不了，控制进程 fetch 时只认它），内容是 GitHub 公布的 ed25519 主机公钥（固定在脚本里，不用 ssh-keyscan）；
  - 已有 deploy key 且还没有镜像时，以 rn-build-agent 身份 `git clone --mirror`（空模板、只许 ssh、不跑 hook）。
  - 控制进程每次 fetch 前核对镜像：目录与 `config` 属于 rn-build-agent、组与其他人不可写，`config` 只允许 `git clone --mirror` 写出的键（`core.*`、`remote.origin.url/fetch/mirror/tagopt`），不允许 `branches/`、`remotes/`、`objects/info/alternates`、`info/attributes` 等；`GIT_SSH_COMMAND` 固定只用 deploy key 与固定 known_hosts，传输协议 fetch 远端只放行 ssh。不符就整个任务失败并提示按手册重建，不自动修。
- **注册**：`build-agent enroll`（见「身份登记」）。
- **启动**：`systemctl enable` 并重启 `rn-build-agent`，等常驻进程写出 `runner-mode.json` 后打印 `show-key`。

可以重复执行：已注册（env 里有机器令牌）的机器不重新注册、不替换已装的文件，只报告与安装包不同的地方、确保服务在跑。
一台主机只跑一个构建机：已注册的主机上拿另一台机器的注册码执行会被拒绝，注册码不会被用掉。

手工安装（没有服务端安装包时）按 `install.sh` 里 `install_builder` 的步骤做，env 文件从 `rn-build-agent.env.example` 抄，令牌仍用 `build-agent enroll` 写入。

## 身份登记

1. **注册**：`build-agent enroll --server <API 源> --env-file /etc/rn-build-agent.env --state-dir /var/lib/rn-build-agent/state`，由 install.sh 以 root 调用。注册码经环境变量 `RN_ENROLLMENT_CODE` 交给它（不进进程参数，本机其他用户读不到；`--code` 仍兼容，两者都给必须相同）。
   1. describe：注册码必须属于一台构建机，这一步不消耗注册码。
   2. 出处密钥：已有就复用（核对属主与权限），没有就生成。以 root 运行时密钥交给状态目录的属主 rn-build-agent；状态目录属于 root 时拒绝。
   3. 先在 `/etc` 建好临时文件。
   4. enroll：交出出处公钥，换回机器令牌。
   5. 令牌**直接写进 env 文件**（root 0600，原子替换），不经过屏幕、日志与报错。已有 env 文件的其它键原样保留，`BUILD_AGENT_SERVER` 与令牌换成这次的，缺的键按 `rn-build-agent.env.example` 的默认值补上（测试守着两边一致）。
   6. 打印机器名、机器 id 与出处公钥完整 sha256，机器状态变成 `pending_key`。
   - env 里已有令牌、状态目录里已有密钥时什么都不做，退出 0，不连服务端。
   - 改造前带机密的旧 env（`BUILD_AGENT_TOKEN`、`BUILD_KEYSTORE_PASSPHRASE`）拒绝合并。
   - 服务端回的机器 id 与 describe 不符、令牌形状不对时丢弃令牌、不写盘。
2. 控制进程启动后登记同一把公钥（`POST /v1/build-agent/public-key`）。**接受之前不领任务**，journal 里会反复提示在等什么。
3. 在构建机上只读查看身份（不会创建任何东西）：
   ```bash
   sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir /var/lib/rn-build-agent/state
   ```
   输出公钥 base64、**完整 sha256（64 个十六进制字符）**，以及 `build runner:` 一行——必须是 `separate user builder via sudo`；是 `SAME USER AS THE BUILD AGENT` 就不要继续，先改配置。
4. 平台管理员在控制台「平台维护 → 打包机与签名闸」核对完整 sha256 后点「接受」。控制台接受只影响服务端路由。
5. 运维分别登上每台签名闸执行 `signer trust-builder --builder <构建机机器名>`，粘贴第 3 步的完整 sha256。**签名闸只认这里 pin 过的构建机**；没做这一步，这台构建机交付的包会被拒签。

**换出处密钥**（旧私钥还在）：
1. `sudo -u rn-build-agent /opt/rn-build-agent/build-agent rotate-key --state-dir /var/lib/rn-build-agent/state` 生成下一把并打印 sha256。
2. 重启服务，控制进程用当前私钥签换钥证明登记它。
3. **先**在每台签名闸上 `trust-builder` 新 sha256。
4. **再**在控制台接受。
5. 控制进程发现服务端已接受（每次签出处声明之前都会先问一次），换上新密钥并删掉旧私钥。

顺序反过来的话，中间交付的包会被签名闸拒签。换钥证明要签机器 id，服务端的登记响应需要带 `machineId`。

**私钥丢了**（状态目录没了）：不恢复，按新机器处理。
1. 控制台吊销旧机器、新建一台；
2. 清空 `/etc/rn-build-agent.env` 里 `BUILD_AGENT_MACHINE_TOKEN` 的值，执行新的安装命令；
3. 签名闸上撤销旧构建机，`trust-builder` 新的。

## 换二进制

**签名闸与 amos 同机期间，`AMOS_DEPLOY_BUILD_AGENT` 必须关着，构建机手工换二进制**（`deploy/amos/README.md`「签名闸同机期间，打包机不走 CI」）。另外 CI 那条路（`rn-foundation-apply build-agent`）只换 `build-agent`，不换 `build-runner`；两个二进制必须同一个提交一起换，版本不一致时控制进程启动自检失败（`--protocol`）。

CI 部署服务端时会把同一提交构建的安装包放到服务端机器的 `/opt/rn-foundation/machine-bundles/current/builder.tar.gz`，归档与其中每个程序的 sha256 打印在 CI 日志「Build machine bundles」一步。可以从那里取（与 CI 日志核对后安装，步骤见 `deploy/amos/SIGNING_GATE_ROLLOUT.md` 5.1），也可以自己编：

```bash
GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build-agent  ./cmd/build-agent
GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build-runner ./cmd/build-agent/build-runner
sha256sum build-agent build-runner                        # 记下来
scp build-agent build-runner <构建机>:~/
ssh <构建机> 'sudo install -o root -g root -m 0755 ~/build-agent ~/build-runner /opt/rn-build-agent/ && sudo systemctl restart rn-build-agent'
```

冒烟：`env -i /opt/rn-build-agent/build-agent` 必须以 2 退出（配置不全），什么都不写；`build-runner` 不带参数也以 2 退出。退出码 77 专指"机器被吊销"，与 2 不混用。

**停机是排空，不是中止。** 控制进程收到 SIGTERM 后不再发起新的领取；手上那一条（包括 SIGTERM 到达时已经发出、服务端已经派出的那次领取）照常构建、上传、交付，或者按失败上报，然后以 0 退出。unit 用 `KillMode=mixed`：SIGTERM 只发给控制进程，执行进程与它的子进程不会收到（`control-group` 会把 SIGTERM 发给整个 cgroup，sudo 转给执行进程，构建当场被打断——2026-09-16 用 `systemd-run` 对照实测过两种模式）。所以 `systemctl restart` 可能等一轮构建（最长 `BUILD_AGENT_TIMEOUT_MINUTES`）；超过 `TimeoutStopSec=3600` systemd 对整个 cgroup 补 SIGKILL。

急着换就 `systemctl kill -s SIGKILL rn-build-agent`：构建被打断，不上报；服务端回收任务，或者新进程领取时收到 409 `BUILDER_HAS_ACTIVE_JOB` 把它判失败；残留任务目录与 builder 进程在新进程启动时清掉。

## 从旧结构迁移（旧打包机以 builder 跑 build-agent）

`install.sh` 发现下列任一迹象就先迁移，再照新机器安装：

- env 里有 `BUILD_AGENT_TOKEN` 或 `BUILD_KEYSTORE_PASSPHRASE`；
- unit 以 `User=builder` 运行；
- `/var/lib/rn-build-agent` 属于 builder；
- 家目录里有 `agent-key` 或 `backup-signing.key`。

迁移时依次做（逻辑沿用 `deploy/amos/signing-gate-rollout/1-install.sh`）：

1. 停 `rn-build-agent`，`pkill -KILL -u builder`，等 builder 的进程全部退出。
2. 在 `/root/rn-build-agent-legacy-<日期>/`（root 0700）留存旧东西，新链路稳定后按上线手册销毁：
   - 旧 env 整个**移进**去（含旧令牌，从此不再使用）；
   - 旧 unit、旧 `build-agent` 各复制一份；
   - `agent-key`、`backup-signing.key`、`.gitconfig` 移进去。
3. 删掉 builder 写过的缓存与工作区（按被下毒处理）：
   - 家目录里的 `.android`、`.cache`、`.expo`、`.kotlin`、`.local`、`.npm`、`workspace/`；
   - `/var/cache/rn-build-agent/{gradle,pnpm-store}`；
   - `/tmp`、`/var/tmp`、`/dev/shm` 顶层属于 builder 的条目。
4. 建 rn-build-agent 与 rn-build-jobs，builder 改成家目录 `/nonexistent`、nologin、加入 rn-build-jobs 组；`chown -R rn-build-agent:rn-build-agent /var/lib/rn-build-agent`，已有的仓库镜像与 deploy key 随之交给 rn-build-agent。
5. 装程序、sudoers、unit，`build-agent enroll` 写出新的 env，启动。

amos 上的构建机已经按 `1-install.sh` 迁移并注册过，不需要再执行安装命令。

## 异常恢复

| 情况 | 会发生什么 |
| --- | --- |
| 控制进程崩了 | systemd `Restart=always` 拉起；启动时先让执行进程清空残留任务目录、回收 builder 进程，再删 spool |
| 构建中途被硬杀 | 服务端还记着这台机器的任务，领取时回 409 `BUILDER_HAS_ACTIVE_JOB`：控制进程带那条任务的编号报失败（中断的构建不续跑），然后继续领 |
| 服务端回收、取消或重派了任务 | 心跳或任何上报收到 409 `BUILD_ATTEMPT_STALE`：立即中止执行进程、清理，**不再上报** |
| 执行进程留下的进程握着输出管道 | 执行进程退出后最多等 20 秒就强制关管道，残留进程由清理回收 |
| 领取结果里出现 `sealedKeystore`、`keyAlias`、口令一类字段 | 整条任务拒收并报失败，不写盘 |
| 服务端重启 / 5xx | 心跳失败只打 WARN；上传、交付、失败上报退避重试 |
| API 源或反代回 3xx 重定向 | 不跟随（否则令牌与包体会被带到重定向目标），按错误处理、不重试，任务判失败 |
| 服务端说"等会儿再来" | 409 `BUILDER_CLAIM_IN_PROGRESS`（上一次领取还在处理）下一轮再领；400 `UPLOAD_INTERRUPTED`、424 `UPLOAD_STORAGE_FAILED` 退避重传 |
| 服务端明确拒绝（其余 4xx） | 不重试，带错误码按失败上报：`UPLOAD_CONTENT_TYPE_INVALID`、`UPLOAD_TOO_LARGE`、`UPLOAD_EMPTY`、`INVALID_BUILD_ATTEMPT`、`BUILD_SBOM_INVALID`、`BUILD_KIND_MISMATCH`、`BUILD_PROVENANCE_INVALID` 等 |
| 构建超过 `BUILD_AGENT_TIMEOUT_MINUTES` | 中止执行进程，按超时上报 |
| 公钥未被接受 | 不领任务，journal 里说清楚在等什么 |
| 机器在控制台被吊销 | 任何一条请求收到 401 `MACHINE_REVOKED`，或者公钥登记成功过之后收到 401 `MACHINE_AUTH_REQUIRED`（令牌不再被认）：立刻停止领取，在跑的构建中止并清理、**不再上报**，记错误日志，以退出码 **77** 退出。unit 的 `RestartPreventExitStatus=77` 让 systemd 不再重启它（`systemctl status` 显示 failed）。要恢复就在控制台新建机器，清空 env 里 `BUILD_AGENT_MACHINE_TOKEN` 的值，执行新的安装命令（重新注册并启动），再按「身份登记」走完接受与 trust-builder。登记之前就收到 `MACHINE_AUTH_REQUIRED`（多半是令牌抄错）不算吊销：照常重试并报错 |
| 状态目录或密钥权限不对 | 控制进程以 2 退出，不把密钥留在别人读得到的地方 |

## 排查

```bash
sudo journalctl -u rn-build-agent -f
sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir /var/lib/rn-build-agent/state
```

构建失败的原因和执行进程输出的尾部会随心跳与失败上报回到服务端，管理端的构建记录里能看到。执行进程的输出按不可信文本处理：控制字符替换、超长行截断，控制进程环境里的机密值替换成 `***`。
