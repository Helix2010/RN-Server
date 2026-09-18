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
| S5 | 未开始 | | `install-macos.sh`（`go:embed` 下发） |
| S6 | 已完成 | 本分支 | `GET /v1/build-agent/bundle`（清单 base64 + 离线签名 + 归档地址）与 `/bundle/archive`（流式，豁免库超时）；平台级 `approvedAgentCommit` 与 `POST /v1/admin/platform/build-agent-version`；claim 在选任务**之前**比对，不等则 409 `AGENT_UPGRADE_REQUIRED`；没签名或 `-dirty` 一律 503 |
| S7 | 已完成 | 本分支 | `ascapi` 加 `Uploader`（**只有它能写 Apple 侧状态**，服务端只构造只读的 `Client`，有用例守着）、Build Uploads 三个端点、按 build 号查询、只读探测 |
| S8 | 未开始 | | Rancher 部署清单 |
| S9 | 已完成 | 本分支 | `signing/bundlesig` + 离线 `bundle-sign`（key create / sign / verify）；签的是提交 + 单调序号 + 清单摘要的规范化字节，不签 JSON |
| S10 | 已完成 | 本分支 | 排队超 6 小时的 iOS 任务发一条告警（每条只发一次，靠审计去重），**不改状态**；告警分得清"没人在线"与"没人有这个 Team 的材料" |

## 打包机程序（`cmd/build-agent`）

| # | 状态 | 备注 |
| --- | --- | --- |
| A1 | 已完成 | `machineEnvKeys` 按 `runtime.GOOS` 组装（`RN_IOS_SIGNING_DIR` 只在 darwin 认），删 `ASC_KEY_ID`/`ASC_ISSUER_ID`；新配置 `BUILD_AGENT_IOS_UPLOAD{ER,_USER,_KEYS}`、`BUILD_AGENT_ALLOWED_SIGNERS`、`BUILD_AGENT_MIN_FREE_GB`；iOS 机器不配 `ALLOWED_SIGNERS` 或 `RN_IOS_SIGNING_DIR` 直接启动失败 |
| A5 | 已完成 | `ios_inventory.go`：钥匙串身份 + 描述文件（纯 Go 读 CMS 里的 XML plist）+ 上传 Key 目录；每次认领前盘一次；领到任务后在检出之前再核一次 |
| A7 | 部分 | 认领带 `agentCommit`/`os`/`appleTeams`/`freeGb`/`paused`；**409 `AGENT_UPGRADE_REQUIRED` 的处理与 halt 标记还没做**（等 S6） |
| A8 | 已完成 | `version` 子命令与 `main.commit` 注入点；`result.json` 加 `toolchain`（执行进程直接问 `xcodebuild -version`），随 `/ios-release` 进 `file_metadata` |
| A9 | 部分 | 认领前查空闲空间已做；`reap` 的 darwin 分支还没做 |
| A6 | 已完成 | 检出之后 `git verify-commit`（`gpg.format=ssh` + `allowedSignersFile`，都走命令行 `-c`）；allowed_signers 必须是 root 所有、组与其他人不可写的普通文件，所在目录同样（目录可写的话换掉文件只是一次 rename）；没配就是没开这道闸，启动时告警一次 |
| A2 | 已完成 | `buildIPA` 先备签名：`security -i` 设搜索列表 + 解锁 + 关自动上锁（口令走标准输入，不进命令行），描述文件复制进任务 HOME 的两个目录；`pnpm ios:release` 改带 `--signing-dir`，**不再传 `--upload`** |
| A3 | 已完成 | `deliverIPA` 用 `archive/zip` + 自带的二进制/XML plist 解析器读 `Payload/<App>.app/Info.plist`，与任务行比对之后才交给上传账户；`sudo -n -u _rnuploader ios-upload`，包走标准输入 |
| A4 | 已完成 | `cmd/build-agent/ios-upload`：`--probe`（只读探端点权限，永远以 0 退出）与上传两条路；先查同号再传，分块 PUT 可重试，"同号已存在"当成功；一行 JSON 到 stdout |
| A10 | 未开始 | 下一步：S4（darwin 归档）→ S5/S6/S9（装机与自升级）→ A10（macOS 部署件）→ R1/R2（RN-App）→ C1–C4（管理端） |

## RN-App

R1、R2、R3 未开始。

## RN-Admin

C1–C4 未开始。

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
| §4.3 第 2 步「`--ipa <路径>`」 | 把包的路径交给上传账户 | 包走**标准输入**，上传程序自己落到它的临时文件 | 产物副本在控制进程的 spool 里，而 spool 在状态目录下（0700，同一棵树里放着出处私钥）。为了传一个不是机密的包，去放宽一个装着机密的目录，不划算 |
| §5.3「`build-ios-release.mjs` 打印 `xcodebuild -version` 供 runner 解析」 | 从构建脚本的日志里捞一行 | 执行进程直接问 `xcodebuild -version` | 否则这个值的正确性取决于另一个仓库里某行日志的格式 |
