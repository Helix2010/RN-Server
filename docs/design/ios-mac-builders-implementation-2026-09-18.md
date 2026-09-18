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
| S4 | 未开始 | | `builder-darwin-arm64.tar.gz`；`builder.tar.gz` 仍指 linux/amd64 |
| S5 | 未开始 | | `install-macos.sh`（`go:embed` 下发） |
| S6 | 未开始 | | 自升级接口、`approvedAgentCommit`、claim 前 409 `AGENT_UPGRADE_REQUIRED` |
| S7 | 未开始 | | `ascapi` 补 Build Uploads 三个端点与按 build 号查询 |
| S8 | 未开始 | | Rancher 部署清单 |
| S9 | 未开始 | | 离线 `bundle-sign`（Ed25519 + `sequence`） |
| S10 | 已完成 | 本分支 | 排队超 6 小时的 iOS 任务发一条告警（每条只发一次，靠审计去重），**不改状态**；告警分得清"没人在线"与"没人有这个 Team 的材料" |

## 打包机程序（`cmd/build-agent`）

| # | 状态 | 备注 |
| --- | --- | --- |
| A1 | 已完成 | `machineEnvKeys` 按 `runtime.GOOS` 组装（`RN_IOS_SIGNING_DIR` 只在 darwin 认），删 `ASC_KEY_ID`/`ASC_ISSUER_ID`；新配置 `BUILD_AGENT_IOS_UPLOAD{ER,_USER,_KEYS}`、`BUILD_AGENT_ALLOWED_SIGNERS`、`BUILD_AGENT_MIN_FREE_GB`；iOS 机器不配 `ALLOWED_SIGNERS` 或 `RN_IOS_SIGNING_DIR` 直接启动失败 |
| A5 | 已完成 | `ios_inventory.go`：钥匙串身份 + 描述文件（纯 Go 读 CMS 里的 XML plist）+ 上传 Key 目录；每次认领前盘一次；领到任务后在检出之前再核一次 |
| A7 | 部分 | 认领带 `agentCommit`/`os`/`appleTeams`/`freeGb`/`paused`；**409 `AGENT_UPGRADE_REQUIRED` 的处理与 halt 标记还没做**（等 S6） |
| A8 | 部分 | `version` 子命令与 `main.commit` 注入点已有；`result.json` 的 `toolchain` 还没做 |
| A9 | 部分 | 认领前查空闲空间已做；`reap` 的 darwin 分支还没做 |
| A2、A3、A4、A6、A10 | 未开始 | 顺序：A6（提交验签）→ A2/A3（构建与交付）→ A4（`ios-upload`）→ A10（macOS 部署件） |

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
