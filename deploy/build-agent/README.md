# 构建机部署

设计见 `docs/design/android-signing-gate-2026-09-16.md`「构建机」「部署与运维」。

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
| `/etc/rn-build-agent.env` | root:root | 0600 | 含本机令牌；systemd 以 root 读 |
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

```bash
# 1. 工具链、SDK、syft：同上一节，SDK 放 /opt/android-sdk，root 所有、全局可读

# 2. 用户、组
sudo groupadd --system rn-build-jobs
sudo useradd --system --home-dir /var/lib/rn-build-agent --create-home --shell /usr/sbin/nologin \
  --user-group --groups rn-build-jobs rn-build-agent
sudo useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin \
  --user-group --groups rn-build-jobs builder
echo builder | sudo tee -a /etc/cron.deny /etc/at.deny >/dev/null

# 3. 目录
sudo install -d -o rn-build-agent -g rn-build-agent -m 0700 /var/lib/rn-build-agent /var/lib/rn-build-agent/.ssh /var/lib/rn-build-agent/state /var/lib/rn-build-agent/repos
sudo install -d -o rn-build-agent -g rn-build-jobs -m 2750 /var/lib/rn-build-jobs
sudo install -d -o root -g root -m 0755 /opt/rn-build-agent

# 4. GitHub 只读 deploy key 与仓库镜像
sudo -u rn-build-agent ssh-keygen -t ed25519 -N "" -C "rn-build-agent@$(hostname)" -f /var/lib/rn-build-agent/.ssh/id_ed25519
sudo -u rn-build-agent sh -c 'ssh-keyscan -t ed25519 github.com > /var/lib/rn-build-agent/.ssh/known_hosts'
sudo cat /var/lib/rn-build-agent/.ssh/id_ed25519.pub   # 公钥加到仓库 Deploy keys（只读）
sudo -u rn-build-agent git clone --mirror git@github.com:Helix2010/RN-App.git /var/lib/rn-build-agent/repos/rn-app.git

# 5. 两个二进制（手工部署，见「换二进制」）、sudoers、配置、unit
sudo install -o root -g root -m 0755 build-agent build-runner /opt/rn-build-agent/
sudo visudo -cf rn-build-agent.sudoers && sudo install -o root -g root -m 0440 rn-build-agent.sudoers /etc/sudoers.d/rn-build-agent
sudo install -o root -g root -m 0600 rn-build-agent.env.example /etc/rn-build-agent.env   # 然后填，令牌手输
sudo install -o root -g root -m 0644 rn-build-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now rn-build-agent
```

## 身份登记

1. 控制进程第一次启动时在状态目录生成出处密钥并登记公钥（`POST /v1/build-agent/public-key`），状态 `pending_key`，**接受之前不领任务**，journal 里会反复提示在等什么。
2. 在构建机上只读查看身份（不会创建任何东西）：
   ```bash
   sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir /var/lib/rn-build-agent/state
   ```
   输出公钥 base64、**完整 sha256（64 个十六进制字符）**，以及 `build runner:` 一行——必须是 `separate user builder via sudo`；是 `SAME USER AS THE BUILD AGENT` 就不要继续，先改配置。
3. 平台管理员在控制台「平台维护 → 打包机与签名闸」核对完整 sha256 后接受。控制台接受只影响服务端路由。
4. 运维分别登上主、备签名闸执行 `signer trust-builder`，粘贴第 2 步的完整 sha256。**签名闸只认这里 pin 过的构建机**；没做这一步，这台构建机交付的包会被拒签。

**换出处密钥**（旧私钥还在）：`sudo -u rn-build-agent /opt/rn-build-agent/build-agent rotate-key --state-dir /var/lib/rn-build-agent/state` 生成下一把并打印 sha256 → 重启服务，控制进程用当前私钥签换钥证明登记它 → **先**在每台签名闸上 `trust-builder` 新 sha256 → **再**在控制台接受 → 控制进程发现服务端已接受（每次签出处声明之前都会先问一次），换上新密钥并删掉旧私钥。顺序反过来的话，中间交付的包会被签名闸拒签。换钥证明要签机器 id，服务端的登记响应需要带 `machineId`。

**私钥丢了**（状态目录没了）：不恢复，按新机器处理——控制台新建机器发新令牌、吊销旧机器，签名闸上撤销旧构建机、`trust-builder` 新的。

## 换二进制

**签名闸与 amos 同机期间，`AMOS_DEPLOY_BUILD_AGENT` 必须关着，构建机手工部署**（`deploy/amos/README.md`「签名闸同机期间，打包机不走 CI」）。另外 CI 那条路（`rn-foundation-apply build-agent`）只换 `build-agent`，不换 `build-runner`；两个二进制必须同一个提交一起换，版本不一致时控制进程启动自检失败（`--protocol`）。

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

1. `sudo systemctl stop rn-build-agent`，`sudo pkill -KILL -u builder`（Gradle daemon 等）。
2. 按「装一台新的」第 2、3 步建 rn-build-agent、rn-build-jobs 与目录；`sudo usermod -d /nonexistent -s /usr/sbin/nologin -aG rn-build-jobs builder`；builder 进 cron/at deny。
3. 仓库镜像与 deploy key 交给 rn-build-agent：`sudo mv /var/lib/rn-build-agent/repos/rn-app.git …` 后 `sudo chown -R rn-build-agent:rn-build-agent /var/lib/rn-build-agent && sudo chmod 0700 /var/lib/rn-build-agent`（`.ssh` 同理）。
4. **删掉旧状态与缓存**：旧 `workspace/`、`/var/cache/rn-build-agent/{gradle,pnpm-store}`（builder 可写过，按被下毒处理）、`/tmp` 里属于 builder 的文件；`agent-key`、`backup-signing.key` 按设计「清理」一步销毁。
5. `/etc/rn-build-agent.env` 按新示例重写：删 `BUILD_AGENT_TOKEN`、`BUILD_KEYSTORE_PASSPHRASE`、`BUILD_AGENT_RECOVERY_RECIPIENT_*`、`BUILD_AGENT_NAME`（这两个机密键留着控制进程会拒绝启动），填 `BUILD_AGENT_MACHINE_TOKEN`、`BUILD_AGENT_STATE_DIR`、`BUILD_AGENT_WORKSPACE=/var/lib/rn-build-jobs`。
6. 装两个二进制、sudoers、新 unit，启动，走「身份登记」。

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
| 机器在控制台被吊销 | 任何一条请求收到 401 `MACHINE_REVOKED`，或者公钥登记成功过之后收到 401 `MACHINE_AUTH_REQUIRED`（令牌不再被认）：立刻停止领取，在跑的构建中止并清理、**不再上报**，记错误日志，以退出码 **77** 退出。unit 的 `RestartPreventExitStatus=77` 让 systemd 不再重启它（`systemctl status` 显示 failed）。要恢复就在控制台新建机器、把新令牌写进 env 文件、按「身份登记」重新走一遍，再 `systemctl restart`。登记之前就收到 `MACHINE_AUTH_REQUIRED`（多半是令牌抄错）不算吊销：照常重试并报错 |
| 状态目录或密钥权限不对 | 控制进程以 2 退出，不把密钥留在别人读得到的地方 |

## 排查

```bash
sudo journalctl -u rn-build-agent -f
sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir /var/lib/rn-build-agent/state
```

构建失败的原因和执行进程输出的尾部会随心跳与失败上报回到服务端，管理端的构建记录里能看到。执行进程的输出按不可信文本处理：控制字符替换、超长行截断，控制进程环境里的机密值替换成 `***`。
