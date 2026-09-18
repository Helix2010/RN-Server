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
| S5 | 已完成 | 本分支 | `install-macos.sh`（674 行，`go:embed`，`GET /v1/machine-setup/install-macos.sh`）：三个带外核对值必填且真的用来比对，FileVault 没开就拒装，三个角色账户 + 目录、安装包逐文件核对、冒烟、钥匙串与随机口令、enroll、deploy key、两份 plist |
| S6 | 已完成 | 本分支 | `GET /v1/build-agent/bundle`（清单 base64 + 离线签名 + 归档地址）与 `/bundle/archive`（流式，豁免库超时）；平台级 `approvedAgentCommit` 与 `POST /v1/admin/platform/build-agent-version`；claim 在选任务**之前**比对，不等则 409 `AGENT_UPGRADE_REQUIRED`；没签名或 `-dirty` 一律 503 |
| S7 | 已完成 | 本分支 | `ascapi` 加 `Uploader`（**只有它能写 Apple 侧状态**，服务端只构造只读的 `Client`，有用例守着）、Build Uploads 三个端点、按 build 号查询、只读探测 |
| S8 | 已完成 | 本分支 | `deploy/rancher/README.md`：安装包目录挂卷（含 `manifest.sig` 必须一起放）、`TRUSTED_PROXIES`、Ingress 不重定向与不剥请求头、出站到 ASC、**限速按副本各算**（N 副本就是 N×20，写下来免得有人按 20 算容量）、多副本直接开的依据、阶段 E 的验证清单 |
| S11 | 已完成 | 本分支 | `GET /v1/admin/platform/build-agent-version`（C4 要的读接口）与 darwin 的六行装机命令。设计里没有编号，归在 S6/S5 名下 |
| S9 | 已完成 | 本分支 | `signing/bundlesig` + 离线 `bundle-sign`（key create / sign / verify）；签的是提交 + 单调序号 + 清单摘要的规范化字节，不签 JSON |
| S10 | 已完成 | 本分支 | 排队超 6 小时的 iOS 任务发一条告警（每条只发一次，靠审计去重），**不改状态**；告警分得清"没人在线"与"没人有这个 Team 的材料" |

## 打包机程序（`cmd/build-agent`）

| # | 状态 | 备注 |
| --- | --- | --- |
| A1 | 已完成 | `machineEnvKeys` 按 `runtime.GOOS` 组装（`RN_IOS_SIGNING_DIR` 只在 darwin 认），删 `ASC_KEY_ID`/`ASC_ISSUER_ID`；新配置 `BUILD_AGENT_IOS_UPLOAD{ER,_USER,_KEYS}`、`BUILD_AGENT_ALLOWED_SIGNERS`、`BUILD_AGENT_MIN_FREE_GB`；iOS 机器不配 `ALLOWED_SIGNERS` 或 `RN_IOS_SIGNING_DIR` 直接启动失败 |
| A5 | 已完成 | `ios_inventory.go`：钥匙串身份 + 描述文件（纯 Go 读 CMS 里的 XML plist）+ 上传 Key 目录；每次认领前盘一次；领到任务后在检出之前再核一次 |
| A7 | 已完成 | 认领带 `agentCommit`/`os`/`appleTeams`/`freeGb`/`paused`/`upgradeError`；收到 409 写 `state/halt`（`upgrade:<提交>`）以 75 退出，吊销（77）也写；启动时读 `state/upgrade-failed.json` 打日志并随认领上报 |
| A8 | 已完成 | `version` 子命令与 `main.commit` 注入点；`result.json` 加 `toolchain`（执行进程直接问 `xcodebuild -version`），随 `/ios-release` 进 `file_metadata` |
| A9 | 部分 | 认领前查空闲空间已做；`reap` 的 darwin 分支还没做 |
| A6 | 已完成 | 检出之后 `git verify-commit`（`gpg.format=ssh` + `allowedSignersFile`，都走命令行 `-c`）；allowed_signers 必须是 root 所有、组与其他人不可写的普通文件，所在目录同样（目录可写的话换掉文件只是一次 rename）；没配就是没开这道闸，启动时告警一次 |
| A2 | 已完成 | `buildIPA` 先备签名：`security -i` 设搜索列表 + 解锁 + 关自动上锁（口令走标准输入，不进命令行），描述文件复制进任务 HOME 的两个目录；`pnpm ios:release` 改带 `--signing-dir`，**不再传 `--upload`** |
| A3 | 已完成 | `deliverIPA` 用 `archive/zip` + 自带的二进制/XML plist 解析器读 `Payload/<App>.app/Info.plist`，与任务行比对之后才交给上传账户；`sudo -n -u _rnuploader ios-upload`，包走标准输入 |
| A4 | 已完成 | `cmd/build-agent/ios-upload`：`--probe`（只读探端点权限，永远以 0 退出）与上传两条路；先查同号再传，分块 PUT 可重试，"同号已存在"当成功；一行 JSON 到 stdout |
| A10 | 已完成 | `deploy/build-agent-macos/`：两份 launchd plist（`UserName`、`KeepAlive.PathState`、`ExitTimeOut=7500`；升级那份走 `WatchPaths`）、`run-agent`（加载 env 后 `exec`）、sudoers 两条（`NOSETENV`）、env 示例；新程序 `cmd/build-agent/upgrade`（验签→核序号→核提交→逐文件核 sha256→冒烟→原子替换→删标记），全部进 darwin 归档 |

下一步：§9 阶段 A–F 真机验证（剩下的都要一台真 Mac）；R3 是 GitHub 上的设置，随时可做。

## RN-App

| # | 状态 | 提交 | 备注 |
| --- | --- | --- | --- |
| R1 | 已完成 | `23978e5` | `build-ios-release.mjs` 加 `--signing-dir`：按 `application-identifier` 在签名目录里找描述文件（过期的单独报出来），用 `IOSConfig.ProvisioningProfile.setProvisioningProfileForPbxproj` 写进工程而不是全局覆盖命令行，`OTHER_CODE_SIGN_FLAGS=--keychain …`；两处 `-allowProvisioningUpdates` 都删了（无人值守的机器上它会去找 Xcode 账户） |
| R2 | 已完成 | `23978e5` | `exportOptionsPlist` 给了 `profileName` 就切 `manual` 并写 `provisioningProfiles`（留着 `automatic` 会让导出去找账户）；新增 `plugins/with-ios-pods-unsigned.js`（Podfile `post_install` 关掉全部 Pods target 的签名），`app.config.ts` 注册 |
| R3 | 未开始 | | 仓库 `main` 开「要求签名提交」分支保护、合并限 rebase/fast-forward。这是 GitHub 上的操作，不是代码改动；A6 那道验签闸已经在代理侧生效，缺这一条时它验的是"开发者有没有自己签"，不是"仓库强制签" |

## RN-Admin

| # | 状态 | 提交 | 备注 |
| --- | --- | --- | --- |
| C1 | 已完成 | `fba909c` | 机器卡片加「运行状态」：最近在线 / 离线 / 从未上报、空闲空间、程序版本（与 `approvedAgentCommit` 不一致时标黄并说明它会自己升级）、自报的 Team 与上传 Key 探测结论、「缺 X 租户的签名材料」、证书 30 天内到期与已过期、机器自停领任务与上一次升级失败。整块写明"自报是运维仪表不是安全边界" |
| C2 | 已完成 | `fba909c` + `2f62b9b` | 新建构建机可选 macOS（自动勾上 iOS 且不能取消，与服务端 400 一致）；服务端给 darwin 拼六行装机命令，控制台把**每个**尖括号占位都标黄（原来只标第一个）并写明它为什么不是 `curl \| bash` |
| C3 | 已完成 | `fba909c` | 打包任务表加「排队」列（还在排队的那格自己走并标黄）；`buildJobSchema` 加 `warnings`，`no_ios_builder_online` 翻成一条留在页面上的提示；409 `NO_BUILDER_FOR_TEAM` 翻成"去哪儿导材料" |
| C4 | 已完成 | `fba909c` + `2f62b9b` | 新增 `GET /v1/admin/platform/build-agent-version` 与「批准打包机程序版本」卡片：先显示两组安装包各自的提交、签名序号、签名时间、发布公钥指纹、归档摘要，再谈批准；批准与取消钉版本都走 `reason` + `confirm`；列出"现在因为版本不一致领不到任务"的机器 |

管理端门禁（`format:check` / `lint` / `typecheck` / `test` / `build`）全绿，580 个用例。

## 运维手册（设计 §10 第 5 条）

| 状态 | 提交 | 备注 |
| --- | --- | --- |
| 已完成 | 本分支 | `deploy/build-agent-macos/SIGNING_MATERIAL.md`：签名材料归档（CSR 流程、合成 `.p12`、分发到每台 Mac、年度续期的先换后 revoke、销毁）、上传 Key（每机一把、探测结果怎么读、吊销）、发布密钥（生成、每次发版签一份、序号只增、轮换时先换遍所有 Mac 的公钥再签）、`allowed_signers`（文件格式、权限与它的失败症状、加减人、配套的 GitHub 分支保护、它挡不住什么）、一台 Mac 退役的清单 |

## 与设计的偏离

| 位置 | 设计怎么写 | 实现怎么做 | 为什么 |
| --- | --- | --- | --- |
| §5.3「同租户同平台只允许一条在途」 | 没写限定平台 | 只对 iOS 加这条认领条件 | 给 Android 加会改掉"两台构建机同时打同一个租户的两条任务"这个今天就成立、并且有用例（`TestDBBuildJobClaimHandsEachJobToExactlyOneBuilder`）盯着的行为。设计给出的理由（iOS 的 `.ipa` 传上去撤不回、Android 那侧有签名闸的 versionCode 记录兜着）本身就只适用于 iOS |
| §5.4 心跳表 DDL | `INSERT … ON DUPLICATE KEY UPDATE … IF(last_seen_at < NOW(3) - INTERVAL 60 SECOND, …)` | 把 `NOW(3)` 换成传进来的时间戳 `VALUES(last_seen_at)` | 服务端的时间统一走 `s.now()`（测试可替换）；语义不变 |
| §5.2 认领 SQL | "用子查询而不是 JOIN"（避免锁住 `app_configs`） | 子查询 + `FOR UPDATE OF j SKIP LOCKED` | 只写子查询不够：MySQL 的锁定读会把子查询里读到的行一起锁上，要 `OF j` 才真的把锁限定在 `build_jobs` 上 |
| §6.2「低于 `BUILD_AGENT_MIN_FREE_GB` 不认领并告警（进 claim 的自报）」 | 两句话合不拢：不认领就没有 claim，也就没有自报，控制台只会看到"离线" | 认领**照发**，但带 `paused` + `pausedReason`，服务端记一行在线与原因后回 204 不派活；请求体与心跳表各加一个字段 | 磁盘满和关机要做的处理完全不同，控制台得分得清。代价是契约多两个字段 |
| §4.4「`security cms -D -i` 读 `ExpirationDate`」 | 起子进程解描述文件 | 纯 Go 从 CMS 块里取出 XML plist 自己解析 | 与 §4.3 第 1 步对 `.ipa` 定的规矩一致（不对文件调 `unzip`/`plutil`），少一处子进程；副作用是盘点在 Linux 上也测得了，不需要一台 Mac |
| §4.3 上传 Key 探测 | `uploadProbe` 只说"进材料盘点" | 在认领体的 `appleTeams[]` 里加 `uploadProbe` 字段，落进 `build_machine_liveness.apple_teams` | 服务端请求体是严格解析，不先加字段代理就报不上来 |
| A1「`machineEnvKeys` 按 `runtime.GOOS` 组装」 | Linux 上不接受 `RN_IOS_SIGNING_DIR` | 按**任务平台**组装：只有 iOS 任务的环境里才有它 | 是更强的那一条——同一台 Mac 上的 Android 任务同样不该看见签名目录；Linux 侧的保护不变（`BUILD_AGENT_PLATFORMS=ios` 在非 darwin 上启动就失败）。副作用是 iOS 那条链路在 Linux 上测得了，`go test` 覆盖到钥匙串准备、描述文件复制、身份核对与上传交接 |
| §4.2「`security unlock-keychain -p "$(cat …)"`」 | 口令作为命令行参数 | 三条命令走 `security -i` 的标准输入 | 命令行参数 `ps` 看得到（AGENTS.md「机密的操作纪律」）。口令的字母表在读入时校验，拼不出第二条命令 |
| §5.6「Mac 在状态目录记本机见过的最高序号」 | 水位线放在代理的状态目录 | 放在 root 拥有的 `/opt/rn-build-agent/upgrade-sequence` | 状态目录属于代理那个账户。把"防降级"的水位线放在被防的一方能写的地方，这道闸就不成立了 |
| §4.3 第 2 步「`--ipa <路径>`」 | 把包的路径交给上传账户 | 包走**标准输入**，上传程序自己落到它的临时文件 | 产物副本在控制进程的 spool 里，而 spool 在状态目录下（0700，同一棵树里放着出处私钥）。为了传一个不是机密的包，去放宽一个装着机密的目录，不划算 |
| C2 装机命令 | 设计 §4.5 只给了在 Mac 上敲的那几行 | 由服务端拼好整段（六行，含 `shasum` 那一行）随注册码一起下发，控制台原样显示并标出占位 | 与 Linux 那条一致：命令里有服务端才知道的外部源与注册码。三个 sha256 仍然是占位——控制台替人填等于让这台 Mac 把服务端说的话当成信任根 |
| C4 「显示当前安装包提交、清单签名与序号」 | 没说从哪儿读 | 新增一条平台级只读接口，两组安装包各自带 `error` 而不是整条 503 | darwin 那组可能还没编出来；这一页存在的理由就是让人看见现在部署的是什么，一组坏了就整页空白等于把要看的东西藏起来 |
| §5.3「`build-ios-release.mjs` 打印 `xcodebuild -version` 供 runner 解析」 | 从构建脚本的日志里捞一行 | 执行进程直接问 `xcodebuild -version` | 否则这个值的正确性取决于另一个仓库里某行日志的格式 |
