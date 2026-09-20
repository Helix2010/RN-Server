# 实施进度：家用网络里的 Mac 打包机

设计是 `ios-mac-builders-home-network-2026-09-18.md`，**它是唯一事实源**；这份只记"做到哪了、每一项落在哪个提交、验证跑过没有"。设计与实现不一致时改的是实现，除非在下面「与设计的偏离」里写清为什么。

## 约定

- 部署顺序：**服务端先发、代理后升**。`claim` / `heartbeat` / `ios-release` 的请求体都是 `DisallowUnknownFields`，新代理带新字段先上会 400。
- 每一项做完要能回答：跑了哪些验证、哪些没跑。CI 是 `gofmt -l cmd internal`、`go vet ./...`、`go test -race ./...`、`go build ./cmd/server`，**CI 上没有 `RN_TEST_MYSQL_DSN`**，所以库测在本机跑（`root:rn-test@tcp(127.0.0.1:33061)/rn_test?parseTime=true`）。
- 管理端（C1–C4）改动前先读 `RN-Admin/docs/ADMIN_ENGINEERING_STANDARD.md`：它是那一侧 UED、交互、国际化、测试与交付的唯一事实源；数据经 `src/core/api.ts` + Zod 严格校验，页面必须表达 loading/error/empty/content，完成前跑 `pnpm check`。

## 服务端（RN-Server）

| # | 状态 | 提交 | 备注 |
| --- | --- | --- | --- |
| S1 | 已完成 | 本分支 | `claim` 按自报盘点过滤 iOS 任务（子查询 + `FOR UPDATE OF j`）、同租户一条在途、排队 409 `NO_BUILDER_FOR_TEAM` 与 `warnings` |
| S2 | 已完成 | 本分支 | 迁移 55 `build_machine_liveness`；`claim` 在锁与事务外、204 之前写；`heartbeat` 只动 `last_seen_at`；`hasLiveBuilderFor` 未改 |
| S3 | 已完成 | 本分支 | `claim` 体加 `agentCommit`/`os`/`appleTeams`/`freeGb`；`/ios-release` 体加 `toolchain`、`uploadedByEarlierAttempt`，两者进 `file_metadata`；`ios-release` 补进 OpenAPI（之前整条路由没写） |
| S4 | 已完成 | 本分支 | `build-bundles.sh` 多出 `builder-darwin-arm64.tar.gz`（build-agent/build-runner/ios-upload + macOS env 示例），`builder.tar.gz` 仍指 linux/amd64；登记里加 `os`，`describe`/下载按它选那一组；`-X main.commit` 注入两处一致 |
| S5 | 已完成 | 本分支 | `install-macos.sh`（816 行，`go:embed`，`GET /v1/machine-setup/install-macos.sh`）：唯一那个带外核对值必填且真的用来比对（人给的指纹 → 认公钥 → `ssh-keygen -Y verify` 验清单 → 可信清单里的摘要），FileVault 没开就拒装，三个角色账户 + 目录、安装包逐文件核对、冒烟、钥匙串与随机口令、enroll、deploy key、两份 plist |
| S6 | 已完成 | 本分支 | `GET /v1/build-agent/bundle`（清单 base64 + 离线签名 + 归档地址）与 `/bundle/archive`（流式，豁免库超时）；平台级 `approvedAgentCommit` 与 `POST /v1/admin/platform/build-agent-version`；claim 在选任务**之前**比对，不等则 409 `AGENT_UPGRADE_REQUIRED`；没签名或 `-dirty` 一律 503 |
| S7 | 已完成 | 本分支 | `ascapi` 加 `Uploader`（**只有它能写 Apple 侧状态**，服务端只构造只读的 `Client`，有用例守着）、Build Uploads 三个端点、按 build 号查询、只读探测 |
| S8 | 已完成 | 本分支 | `deploy/rancher/README.md`：安装包目录挂卷（含 `manifest.sig` 必须一起放）、`TRUSTED_PROXIES`、Ingress 不重定向与不剥请求头、出站到 ASC、**限速按副本各算**（N 副本就是 N×20，写下来免得有人按 20 算容量）、多副本直接开的依据、阶段 E 的验证清单 |
| S11 | 已完成 | 本分支 | `GET /v1/admin/platform/build-agent-version`（C4 要的读接口）与 darwin 的四行装机命令。设计里没有编号，归在 S6/S5 名下 |
| S9 | 已完成 | 本分支 | `signing/bundlesig` + 离线 `bundle-sign`（key create / sign / verify）；签的是提交 + 单调序号 + 清单摘要的规范化字节，不签 JSON |
| S10 | 已完成 | 本分支 | 排队超 6 小时的 iOS 任务发一条告警（每条只发一次，靠审计去重），**不改状态**；告警分得清"没人在线"与"没人有这个 Team 的材料" |

## 打包机程序（`cmd/build-agent`）

| # | 状态 | 备注 |
| --- | --- | --- |
| A1 | 已完成 | `machineEnvKeys` 按 `runtime.GOOS` 组装（`RN_IOS_SIGNING_DIR` 只在 darwin 认），删 `ASC_KEY_ID`/`ASC_ISSUER_ID`；新配置 `BUILD_AGENT_IOS_UPLOAD{ER,_USER,_KEYS}`、`BUILD_AGENT_ALLOWED_SIGNERS`、`BUILD_AGENT_MIN_FREE_GB`；iOS 机器不配 `ALLOWED_SIGNERS` 或 `RN_IOS_SIGNING_DIR` 直接启动失败 |
| A5 | 已完成 | `ios_inventory.go`：钥匙串身份 + 描述文件（纯 Go 读 CMS 里的 XML plist）+ 上传 Key 目录；每次认领前盘一次；领到任务后在检出之前再核一次 |
| A7 | 已完成 | 认领带 `agentCommit`/`os`/`appleTeams`/`freeGb`/`paused`/`upgradeError`；收到 409 写 `state/halt`（`upgrade:<提交>`）以 75 退出，吊销（77）也写；启动时读 `state/upgrade-failed.json` 打日志并随认领上报 |
| A8 | 已完成 | `version` 子命令与 `main.commit` 注入点；`result.json` 加 `toolchain`（执行进程直接问 `xcodebuild -version`），随 `/ios-release` 进 `file_metadata` |
| A9 | 已完成 | 认领前查空闲空间；`reap` 在 darwin 上改扫每用户的 `/var/folders/<xx>/<yyyy>/{T,C}`（Xcode/CocoaPods/Metro 写的是它们，而它们不吃 `TMPDIR`），`/dev/shm` 只留给 Linux。按属主扫目录而不是问 `confstr`：后者只回当前进程那一个，执行进程在不同 launchd 会话里跑过会留下不止一个；副作用是这段在 Linux 上测得了 |
| A6 | 已完成 | 检出之后 `git verify-commit`（`gpg.format=ssh` + `allowedSignersFile`，都走命令行 `-c`）；allowed_signers 必须是 root 所有、组与其他人不可写的普通文件，所在目录同样（目录可写的话换掉文件只是一次 rename）；没配就是没开这道闸，启动时告警一次 |
| A2 | 已完成 | `buildIPA` 先备签名：`security -i` 设搜索列表 + 解锁 + 关自动上锁（口令走标准输入，不进命令行），描述文件复制进任务 HOME 的两个目录；`pnpm ios:release` 改带 `--signing-dir`，**不再传 `--upload`** |
| A3 | 已完成 | `deliverIPA` 用 `archive/zip` + 自带的二进制/XML plist 解析器读 `Payload/<App>.app/Info.plist`，与任务行比对之后才交给上传账户；`sudo -n -u _rnuploader ios-upload`，包走标准输入 |
| A4 | 已完成 | `cmd/build-agent/ios-upload`：`--probe`（只读探端点权限，永远以 0 退出）与上传两条路；先查同号再传，分块 PUT 可重试，"同号已存在"当成功；一行 JSON 到 stdout |
| A10 | 已完成 | `deploy/build-agent-macos/`：两份 launchd plist（`UserName`、`KeepAlive.PathState`、`ExitTimeOut=7500`；升级那份走 `WatchPaths`）、`run-agent`（加载 env 后 `exec`）、sudoers 两条（`NOSETENV`）、env 示例；新程序 `cmd/build-agent/upgrade`（验签→核序号→核提交→逐文件核 sha256→冒烟→原子替换→删标记），全部进 darwin 归档 |

下一步：§9 阶段 A–F 真机验证（剩下的都要一台真 Mac）。两把信任根已落地（见下表）；R3 的开发者侧已就绪，GitHub 侧的分支保护受 Free 版限制暂缺。

**装第一台 Mac 之前还差四步，前三步与 Mac 无关**（2026-09-18 查线上确认：`GET /v1/machine-setup/install-macos.sh` 与
`GET /v1/admin/platform/build-agent-version` 都是 404，已登记机器只有 `amos-builder`、`amos-signer-a`、`amos-signer-b`
——本方案一行都还没上线）：

1. 三个仓库推送，CI 构建；
2. CI 的 `build-bundles.sh` 产出传到 amos，`rn-foundation-apply bundles <提交>` 切 current；
3. 离线机器上 `bundle-sign sign --sequence 1`，`manifest.sig` 放回服务器同一目录——**没有它 `describe` 一律 503，装不了**；
4. 控制台新建 macOS 机器拿注册码，Mac 上跑那四行。

离线机器上那份旧格式的 `release-key.pub`（一行裸 base64）要先用 `bundle-sign key public` 重出一份，见 SIGNING_MATERIAL §3.0。

## RN-App

| # | 状态 | 提交 | 备注 |
| --- | --- | --- | --- |
| R1 | 已完成 | `23978e5` | `build-ios-release.mjs` 加 `--signing-dir`：按 `application-identifier` 在签名目录里找描述文件（过期的单独报出来），用 `IOSConfig.ProvisioningProfile.setProvisioningProfileForPbxproj` 写进工程而不是全局覆盖命令行，`OTHER_CODE_SIGN_FLAGS=--keychain …`；两处 `-allowProvisioningUpdates` 都删了（无人值守的机器上它会去找 Xcode 账户） |
| R2 | 已完成 | `23978e5` | `exportOptionsPlist` 给了 `profileName` 就切 `manual` 并写 `provisioningProfiles`（留着 `automatic` 会让导出去找账户）；新增 `plugins/with-ios-pods-unsigned.js`（Podfile `post_install` 关掉全部 Pods target 的签名），`app.config.ts` 注册 |
| R3 | 部分 | `f705f23` | **开发者侧已就绪**（2026-09-18）：第一个 principal `rn-app-signing-a@gmail.com` 的 SSH 签名密钥已配好并实测签得出、验得过；`deploy/build-agent-macos/allowed_signers` 已落地。**GitHub 侧的分支保护暂缺**——Free 版私有仓库没有 Rulesets，那一栏不显示。缺它时 A6 那道闸仍然 fail-closed（未签名的提交到了 Mac 上验签失败、任务失败），代价是失败发现得晚、少一层独立记录。**真正要守的纪律与分支保护无关**：不要用 GitHub 网页的三个合并按钮——那三种合并都由 GitHub 生成或重写提交，签名要么是 web-flow 的、要么被改写失效，到了 Mac 上一律验不过；合并在本地做、fast-forward 推 |

## RN-Admin

| # | 状态 | 提交 | 备注 |
| --- | --- | --- | --- |
| C1 | 已完成 | `fba909c` | 机器卡片加「运行状态」：最近在线 / 离线 / 从未上报、空闲空间、程序版本（与 `approvedAgentCommit` 不一致时标黄并说明它会自己升级）、自报的 Team 与上传 Key 探测结论、「缺 X 租户的签名材料」、证书 30 天内到期与已过期、机器自停领任务与上一次升级失败。整块写明"自报是运维仪表不是安全边界" |
| C2 | 已完成 | `fba909c` + `2f62b9b` | 新建构建机可选 macOS（自动勾上 iOS 且不能取消，与服务端 400 一致）；服务端给 darwin 拼四行装机命令，控制台把**每个**尖括号占位都标黄（原来只标第一个）并写明它为什么不是 `curl \| bash` |
| C3 | 已完成 | `fba909c` | 打包任务表加「排队」列（还在排队的那格自己走并标黄）；`buildJobSchema` 加 `warnings`，`no_ios_builder_online` 翻成一条留在页面上的提示；409 `NO_BUILDER_FOR_TEAM` 翻成"去哪儿导材料" |
| C4 | 已完成 | `fba909c` + `2f62b9b` | 新增 `GET /v1/admin/platform/build-agent-version` 与「批准打包机程序版本」卡片：先显示两组安装包各自的提交、签名序号、签名时间、发布公钥指纹、归档摘要，再谈批准；批准与取消钉版本都走 `reason` + `confirm`；列出"现在因为版本不一致领不到任务"的机器 |

管理端门禁（`format:check` / `lint` / `typecheck` / `test` / `build`）全绿，580 个用例。
服务端侧 `gofmt` / `go vet` / `go test -race -p 1 ./...`（带本机 MySQL）全绿。

## 两把信任根（2026-09-18 落地）

| 东西 | 值 | 装机时要人抄吗 |
| --- | --- | --- |
| 发布公钥（自升级、清单验签） | 公钥字节 sha256 `bac1ec56b4e11d8f33ce1b4dbbba34e8ae7fc43d43001f408ab95f3c4b5bb4f6` | **要**，`--release-key-sha256`，唯一的一个 |
| `allowed_signers`（提交验签） | 文件 sha256 `296a3753aedc51b632db6fc8a58d58e79c177bf06a16ed27409b0c293fd2c755` | 不要，由脚本从验过签的清单里核对 |

两者口径不同（一个算公钥字节、一个算文件），落地当天撞出一个必然导致装机失败的 bug，见提交 `b01a11d`。
`build-bundles.sh` 结尾现在会按正确口径各打印一行；零警告的完整构建已跑通。口径的一致性现在有
端到端测试兜着（`internal/machinesetup/install_macos_chain_test.go`：真密钥、真签名，把脚本里的
`parse_description` 拉出来跑正反面）——把指纹改回按文件算，那组测试当场转红，正是当初漏掉的那个 bug。

**两份文件现在是同一种格式**：`release-key.pub` 与 `allowed_signers` 都是 OpenSSH 的一行公钥。

上表里的发布公钥指纹在 2026-09-19 换过几次（`395937be…` → `5aebeaf4…` → 现值）：装第一台 Mac 之前重新生成了
密钥。那时既没有机器装过、也没有被任何机器接受过的清单，所以是直接替换。**第一台 Mac 装上之后
再换就得走 `SIGNING_MATERIAL.md` §3.4**，顺序反了所有机器会集体拒绝升级。

## 运维手册（设计 §10 第 5 条）

| 状态 | 提交 | 备注 |
| --- | --- | --- |
| 已完成 | 本分支 | `deploy/build-agent-macos/SIGNING_MATERIAL.md`：签名材料归档（CSR 流程、合成 `.p12`、分发到每台 Mac、年度续期的先换后 revoke、销毁）、上传 Key（每机一把、探测结果怎么读、吊销）、发布密钥（生成、每次发版签一份、序号只增、轮换时先换遍所有 Mac 的公钥再签）、`allowed_signers`（文件格式、权限与它的失败症状、加减人、配套的 GitHub 分支保护、它挡不住什么）、一台 Mac 退役的清单 |

## 已补的缺口

| 缺口 | 影响 | 怎么补的 |
| --- | --- | --- |
| **签清单必须有服务器 shell**（2026-09-19 已补） | `manifest.sig` 在服务端只被读（`build_agent_bundle.go:73`），没有下发未签名清单的接口，也没有接收签名的接口。取清单、放回签名只能 `scp`/`ssh`。生产环境运维通常没有服务器 shell；更要紧的是这让**持有发布私钥的人必须同时握着服务器 shell**，而这两个角色正是这套设计要分开的——攻破这个人两样一起拿到。另外 `build-agent-version` 在未签名时 `commit` 返回 `null`，连"现在该签哪个提交"都问不出来，只能 `readlink current` | 加了 `GET /v1/admin/platform/build-agent-version/manifest`（下发当前清单原始字节与提交号，不要求已签名）与 `POST …/signature`（接收 `manifest.sig`），控制台那张卡片上有「下载 manifest.json / 选择 manifest.sig」两个动作。签名**存数据库**而不是写回 `machine-bundles/`：那个目录 root 拥有、只有 `rn-foundation-apply` 能写，这个性质值得保住，而且存库之后同一提交重新部署签名还在。文件那条路保留：取签名时按**清单摘要**挑（库里那份不匹配就回退看文件），而不是"库里有就用库里的"——同一个提交理论上总该构建出同一份清单，但那是前提不是保证。<br><br>**这不削弱信任根**：签名的权威性来自离线私钥，不来自它怎么送达；服务端拿到一份签名也伪造不出有效的，而它本来就能对这条链路做 DoS（归档是它服务的）。多一个写入点只多了"把签名换成垃圾"这种拒绝服务。上传时服务端做形状与绑定检查（format、`manifestSha256`、commit），甚至可以拿 bundle 里的 `release-key.pub` 验一遍——但那**只帮运维查错，不是安全边界**，那把公钥与服务端同源。真正的判据始终是 Mac 上按人给的指纹 pin 的那一把 |
| **控制进程读不到它要盘点的东西**（2026-09-19 真机发现、已补） | 设计 §4.2 把 `/var/rn-build-signing` 定成 `_rnbuilder 0700`，§5.4 又要**控制进程**（`_rnbuildagent`）盘点"这台机器能签哪些 Team"并随每次认领报上去。两条都对，但中间缺一段：控制进程连那个目录都 `stat` 不了。实现照 §5.4 写成了直接 `os.ReadDir` 与直接跑 `security`，于是真机上每轮打一行 `cannot read /var/rn-build-signing/profiles: permission denied`，然后**一个 Team 都不报**——机器在线、控制台上永远"缺材料"、iOS 任务永远派不过来，而日志里只有那一行 INFO | 加 `build-runner ios-inventory --signing-dir <abs>`：由执行账户把**原文**交回来（两条 `security` 的标准输出、`profiles/` 下每份描述文件的字节），控制进程照旧解析、判过期、判"少了什么"。选 `build-runner` 是因为 sudoers 里本来就只有它这一条 `(_rnbuilder)` 规则——不必为盘点再开一条，也不必放宽签名区的权限。**判断不跟着搬过去**：跑第三方构建代码的是执行账户，"这台机器报上去的能力"不该由它说了算 |
| **升级程序坏了就没有第二条路**（2026-09-19 真机撞上；2026-09-20 修了一半） | 换版本只有版本闸这一条路：批准 → 409 → 停机标记 → 升级程序验签换二进制。升级程序自己有问题时它换不掉自己，而装机脚本只能装**注册时那一版**——`describe` 要注册码，注册码一次性，已注册的机器不能重发（`MACHINE_ALREADY_ENROLLED`），失败时脚本回退读缓存下来的那份 describe。于是一台机器被永久钉在它装机那天的提交上 | 暂时绕道：发一个新注册码，用它重跑装机命令（`env` 不覆盖、注册跳过、新码不消耗，机器身份不变），装完把那台占位机器吊销。写在运维手册 §5.5。**2026-09-20 补了一半**：升级程序现在也换自己（`upgradeBinaries` 里加了 `rn-build-agent-upgrade`，排最后，前面任何一步失败都不碰它）。于是它自己的 bug 从此能随版本发下去——但**机器上还是旧版的那一次仍然得有人跑一遍装机脚本**，因为旧的那个不会换自己。当天就是这样：冒烟那个 bug 修好了，却发不到 mac-01 上。**剩下该补的**是「按机器令牌取当前版本」的重装路径——机器手上有长期令牌，升级程序就是拿它取包的，装机脚本没有用上；补的时候要保住"这个脚本从不读令牌"这条性质（设计 §4.5），所以更合适的形状是让 `build-agent` 出一个取包子命令，脚本调它 |

| **自升级的冒烟用 root 的身份去验控制进程的目录**（2026-09-20 真机撞上、已修） | 换二进制之前 `smoke()` 以 root 跑 `sudo -n -u _rnbuilder <staging>/build-runner self-check --jobs-root <workspace> --protocol 1 --expect-separated`。`self-check` 里那条「任务根目录必须归控制进程」拿的是 **SUDO_UID**——root 来调时它等于 0，而真机上目录归控制账户（`_rnbuildagent`，uid 201），于是自检必然 exit 2。**这条路在任何一台真机上都没成功过**：先前一直被另一个 bug（staging 目录 0700，sudo 报 Permission denied）挡在前面，修掉那个之后才露出来。表现极具迷惑性——下载、验签、单调序号、逐文件 sha256 全过，只卡最后一步，然后标记被删、代理重启、十几秒后重来一遍，每轮重下一次整包 | 冒烟不再带 `--jobs-root`：它要验的是**新二进制**能不能以执行账户跑起来（协议版本、拒绝 root、确实换了 uid）。`--jobs-root` 变成可选参数，代理启动时那条调用照旧带着它，而那时调用者才真的是控制进程。两侧各加一条用例，变异验证过 |
| **材料装不上时原因被丢掉**（2026-09-20 真机撞上、已修） | 第一次真传材料，证书那一格装不上，日志上只有 `cannot install signing material slot=certificate/J4JDFC8LCC/ error="exit status 1: "`——冒号后面是空的。`build-runner` 按它文件头的约定把失败原因写在**标准输出**（`build-runner: error: …`），而 `installMaterial` 只取了标准错误；`ios-upload` 恰好写标准错误，所以上传 Key 那一格从来没暴露过这条。单元测试也没挡住：假的 build-runner 用 `echo … >&2`，与真的那个约定相反 | 抽出 `runnerFailureDetail(stdout, stderr)`：先找 `build-runner: error: ` 那一行，没有再退回标准错误、再退回标准输出；盘点那条路原本就有同样的回退，改成共用它。回归用例让假 runner 照真的那样写标准输出，变异验证过（去掉修复后错误退回 `exit status 1: `） |
| **装证书前没解锁钥匙串**（2026-09-20 真机撞上、已修） | 钥匙串 `create-keychain` 建出来时是解开的，但那个状态活不过一次重启，而装材料跑在 launchd 守护进程里，没有图形会话。往锁着的钥匙串里 `security import` 换来的是 `User interaction is not allowed.`、退出码 1。构建那条路签名前一直有 `unlock-keychain`（`iossigning.go`），装材料这条路漏了；运维手册 §1.3 与装机脚本打印的手工步骤也一样漏 | `importCertificate` 在 import 之前先 `unlock-keychain` + `set-keychain-settings`。解锁与 `set-key-partition-list` 都要钥匙串口令，两条一起改走 `security -i` 的标准输入——顺手去掉了原先把钥匙串口令放在命令行上的那一处（`ps` 看得见）。`.p12` 的口令仍走命令行参数：`security -i` 按空白切词，而那个口令是人定的，带空格会被切坏。两份文档同时补了解锁那一行 |
| **归档里只有叶子证书**（2026-09-20 真机撞上、已补文档与诊断） | 证书导进钥匙串了，盘点却说「有描述文件、钥匙串里没有 Apple Distribution 身份」。`find-identity -v` 的 `-v` 要求链验到受信任的根，而 §1.2 合成 `.p12` 时只放了叶子证书——Apple 的 WWDR 中间证书没进去，`find-identity` 不带 `-v` 列得出这个身份，带 `-v` 就是 0。那条错读起来像「证书没装上」，而人刚看着上一行打出 `signing material installed` | 运维手册 §1.2 第 4 步改成 `openssl pkcs12 -export -certfile <WWDR>.pem`，§1.3 加了补装中间证书的那一行，验收那段加了一条 `find-identity -v` 自检。盘点的错误信息分成两句：证书在钥匙串里（`find-certificate` 看得见，它不看私钥）却不是有效身份时，直接点名缺中间证书 |
| **盘点问身份时没设钥匙串搜索列表**（2026-09-20 真机撞上、已修） | 叶子证书、WWDR 中间证书、Apple Root CA 三张都在签名钥匙串里，`security verify-cert -p codeSign` 说链没问题，`find-identity` 不带 `-v` 也列得出这个身份——带 `-v` 就是 0，**而且不报错**。`-v` 要做一次信任评估，评估时中间证书是按**钥匙串搜索列表**去找的，而这个独立钥匙串不在任何搜索列表上（`_rnbuilder` 的家目录是 `/var/empty`，也存不住）。签名那条路一直是对的（`iossigning.go` 把 `list-keychains` 与签名放在同一个任务 HOME 里），盘点这条路从来没跟上 | `ios-inventory` 改成把 `list-keychains -s <钥匙串>` 与 `find-identity -v` 放进**同一个** `security -i` 进程（新的 `securityScript`）。只改这一个进程的搜索列表，账户上不留状态——只读的盘点本来也不该留。解锁不需要，真机上验过只加这一条就够。`checkSigningDir` 顺手补了路径字母表检查（它现在会被拼进 `security -i` 的一行命令） |

## 与设计的偏离

| 位置 | 设计怎么写 | 实现怎么做 | 为什么 |
| --- | --- | --- | --- |
| §5.3「同租户同平台只允许一条在途」 | 没写限定平台 | 只对 iOS 加这条认领条件 | 给 Android 加会改掉"两台构建机同时打同一个租户的两条任务"这个今天就成立、并且有用例（`TestDBBuildJobClaimHandsEachJobToExactlyOneBuilder`）盯着的行为。设计给出的理由（iOS 的 `.ipa` 传上去撤不回、Android 那侧有签名闸的 versionCode 记录兜着）本身就只适用于 iOS |
| §5.4 心跳表 DDL | `INSERT … ON DUPLICATE KEY UPDATE … IF(last_seen_at < NOW(3) - INTERVAL 60 SECOND, …)` | 把 `NOW(3)` 换成传进来的时间戳 `VALUES(last_seen_at)` | 服务端的时间统一走 `s.now()`（测试可替换）；语义不变 |
| §5.2 认领 SQL | "用子查询而不是 JOIN"（避免锁住 `app_configs`） | 子查询 + `FOR UPDATE OF j SKIP LOCKED` | 只写子查询不够：MySQL 的锁定读会把子查询里读到的行一起锁上，要 `OF j` 才真的把锁限定在 `build_jobs` 上 |
| §6.2「低于 `BUILD_AGENT_MIN_FREE_GB` 不认领并告警（进 claim 的自报）」 | 两句话合不拢：不认领就没有 claim，也就没有自报，控制台只会看到"离线" | 认领**照发**，但带 `paused` + `pausedReason`，服务端记一行在线与原因后回 204 不派活；请求体与心跳表各加一个字段 | 磁盘满和关机要做的处理完全不同，控制台得分得清。代价是契约多两个字段 |
| §4.4「`security cms -D -i` 读 `ExpirationDate`」 | 起子进程解描述文件 | 纯 Go 从 CMS 块里取出 XML plist 自己解析 | 与 §4.3 第 1 步对 `.ipa` 定的规矩一致（不对文件调 `unzip`/`plutil`），少一处子进程；副作用是盘点在 Linux 上也测得了，不需要一台 Mac |
| §4.5 装机要三个带外核对值 | `--expect-sha256`（CI 日志里的归档摘要）、`--release-key-sha256`、`--allowed-signers-sha256` | 只要 `--release-key-sha256` 一个。`describe` 对 darwin 额外下发清单原始字节、它的离线签名与发布公钥；脚本用人给的指纹认出公钥 → 验清单 → 从**已验签的清单**里取归档与每个文件的摘要 | 三个值里有两个是冗余的（归档摘要对了，包里的文件就都对了），而剩下那个"归档摘要"每次发版都变、要去翻 CI 日志找对应版本——它恰恰是最麻烦也最弱的一环：CI 日志能被改，离线签名不能。人工抄写从 3 处减到 1 处，抄错的机会少三分之二，而判据反而更强 |
| §5.6 清单签名的编码 | 只说"Ed25519 签 `manifest.json`" | 签名放进 `manifest.sig` 时用 **OpenSSH 的 `SSHSIG` 封装**（namespace `rn-machine-bundles`），被签的字节不变 | 算法没变，变的是外层封装。装机脚本要在**下载安装包之前**验这份签名，那时机器上除了脚本自己没有任何可信的东西——换成这个格式，验签就是 macOS 自带的 `ssh-keygen -Y verify` 一条命令，脚本里一行密码学都不用写。先前那一版为此内嵌了约 160 行纯 Python 的 ed25519 验签；它跑得通（RFC 8032 向量、与 Go 交叉验证、非 canonical 的 S 都验过），但运维在执行前要把这个脚本从头读一遍再比对 shasum，而一段椭圆曲线运算没人读得动——"比对摘要"就只剩比对、没有"我知道我在跑什么"。顺带把两个信任根的文件格式统一了：`release-key.pub` 与 `allowed_signers` 现在都是 OpenSSH 的一行公钥。**换格式不需要换密钥**：指纹口径仍是公钥那 32 字节的 sha256，当时那把（`395937be…`）原样沿用，只重新导出了一次 `.pub`。（它后来在 2026-09-19 因为另一件事换掉了，见上面的信任根表） |
| §9 阶段 A「手工装」 | 第一台 Mac 手工建三个账户、目录、sudoers、launchd，不走装机脚本（"先用现有代码"） | 直接跑 `install-macos.sh` | 设计这么写是因为当时脚本还不存在。它给的理由是"预期第一个错就是钥匙串（§4.2），脚本挡在中间分不清是脚本的锅还是 macOS 的锅"——这个顾虑成立，但现在脚本已经写完并且每一步都有 `step`/`note` 输出，卡住时看得见停在哪一步，钥匙串那一步尤其是单独一段。反过来，手工再做一遍等于把脚本里的账户、目录权限、sudoers 与两份 plist 用人再实现一次，出错面比脚本大。阶段 A 真正要验的东西（真机出一次包、钥匙串、§4.3b 的手工签名）一条不减 |
| §4.3 上传 Key 探测 | `uploadProbe` 只说"进材料盘点" | 在认领体的 `appleTeams[]` 里加 `uploadProbe` 字段，落进 `build_machine_liveness.apple_teams` | 服务端请求体是严格解析，不先加字段代理就报不上来 |
| A1「`machineEnvKeys` 按 `runtime.GOOS` 组装」 | Linux 上不接受 `RN_IOS_SIGNING_DIR` | 按**任务平台**组装：只有 iOS 任务的环境里才有它 | 是更强的那一条——同一台 Mac 上的 Android 任务同样不该看见签名目录；Linux 侧的保护不变（`BUILD_AGENT_PLATFORMS=ios` 在非 darwin 上启动就失败）。副作用是 iOS 那条链路在 Linux 上测得了，`go test` 覆盖到钥匙串准备、描述文件复制、身份核对与上传交接 |
| §4.2「`security unlock-keychain -p "$(cat …)"`」 | 口令作为命令行参数 | 三条命令走 `security -i` 的标准输入 | 命令行参数 `ps` 看得到（AGENTS.md「机密的操作纪律」）。口令的字母表在读入时校验，拼不出第二条命令 |
| §5.6「Mac 在状态目录记本机见过的最高序号」 | 水位线放在代理的状态目录 | 放在 root 拥有的 `/opt/rn-build-agent/upgrade-sequence` | 状态目录属于代理那个账户。把"防降级"的水位线放在被防的一方能写的地方，这道闸就不成立了 |
| §4.3 第 2 步「`--ipa <路径>`」 | 把包的路径交给上传账户 | 包走**标准输入**，上传程序自己落到它的临时文件 | 产物副本在控制进程的 spool 里，而 spool 在状态目录下（0700，同一棵树里放着出处私钥）。为了传一个不是机密的包，去放宽一个装着机密的目录，不划算 |
| C2 装机命令 | 设计 §4.5 只给了在 Mac 上敲的那几行 | 由服务端拼好整段（四行，含 `shasum` 那一行）随注册码一起下发，控制台原样显示并标出占位 | 与 Linux 那条一致：命令里有服务端才知道的外部源与注册码。`--release-key-sha256` 仍然是占位——控制台替人填等于让这台 Mac 把服务端说的话当成信任根 |
| C4 「显示当前安装包提交、清单签名与序号」 | 没说从哪儿读 | 新增一条平台级只读接口，两组安装包各自带 `error` 而不是整条 503 | darwin 那组可能还没编出来；这一页存在的理由就是让人看见现在部署的是什么，一组坏了就整页空白等于把要看的东西藏起来 |
| §5.3「`build-ios-release.mjs` 打印 `xcodebuild -version` 供 runner 解析」 | 从构建脚本的日志里捞一行 | 执行进程直接问 `xcodebuild -version` | 否则这个值的正确性取决于另一个仓库里某行日志的格式 |
