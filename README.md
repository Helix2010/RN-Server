# RN-Server

基于 Go + Gin + MySQL，为 RN-App 提供认证、移动端启动配置、版本/分发策略、Feature Flag、通用 API 和可观测性关联的服务端基座。默认形态是可拆分的模块化单体，优先保证契约稳定和运维可控，而不是预先拆微服务。

## 当前阶段

当前已进入可运行基座阶段，包含 `GET /v1/mobile/bootstrap`、基于请求域名的多租户上下文和统一安装包发布链路。发布记录、国际化、主题、Feature Flag、升级策略和租户对象存储配置均由 MySQL 持久化；管理端直传 S3/R2/MinIO，服务端计算 hash、解析 Android APK 身份后，统一写入 `app_releases` 并进入发布状态机。开发阶段已删除旧 Application、Artifact 和独立 Storage Config 模型。

## 本地运行

```bash
cp .env.example .env
set -a && source .env && set +a  # .env 里 MYSQL_DSN 要加单引号：值里的 ( ) & 都会被 shell 解释
go run ./cmd/server
```

- 健康检查：`http://localhost:3000/health/live`
- OpenAPI UI：`http://localhost:3000/docs`
- App 配置：`http://localhost:3000/v1/mobile/bootstrap?locale=zh-CN`
- 业务模块：`app_configs.mobile-bootstrap.modules` 管理 `predict` 与 `dex` 开关；Bootstrap 按租户域名下发，至少保留一个模块开启。历史配置由迁移 23 自动补齐为双模块。
- 多语言管理：管理端使用 `/v1/admin/localization` 读取全局与租户合并结果，语言设置和文案分别保存为租户差异；发布后生成 `/v1/mobile/languages/{languageCode}/document` 资源。语言编码只接受标准 BCP 47（如 `zh-CN`、`en-US`），不接受下划线格式。
- 多语言资源对象 Key：发布文件按 `localization/{tenantId}/{languageCode}/{version}.json` 存储，租户和语言已由目录表达，文件名只保留版本号。
- RN-App 正式文案：迁移 8 会重置 `type=14` 为 AnyFun 基座实际使用的 zh-CN/en-US 文案，并清空旧语言资源引用；迁移后需由管理端重新发布语言包。
- RN-App 文案持续同步：迁移 29 从 RN-App 的 `i18n/seed` 补齐当前完整 UI 文案到全局 `language_document`（现为 748 个 key × 2 种语言），只补缺失记录，不覆盖已有全局内容或租户自定义覆盖；变更 App 内置文案后先在 RN-App 执行 `pnpm i18n:seed`，再在本仓库执行 `node scripts/sync-rn-app-i18n-seed.mjs`。
- Admin 登录：`POST /v1/admin/auth/login` 创建 HttpOnly 会话；管理 API 默认拒绝未认证请求。`x-admin-key` 仅保留给受控自动化，不再进入 Web 构建。
- 配置：所有环境变量、默认值、必填项和排查办法见 **[配置参考](docs/CONFIGURATION.md)**。数据库是一行 `MYSQL_DSN`（go-sql-driver 标准写法）；`rn-server config` 打印这台机器上**实际生效**的配置并标出每一项来自 env 还是默认值，机密只显示长度。
- 推送凭据：按租户存在 `app_configs` 的 `push.fcm`（用 `STORAGE_MASTER_KEY` 加密），管理接口 `GET /v1/admin/push/credentials`、`PUT|DELETE /v1/admin/push/credentials/fcm`、`POST /v1/admin/push/credentials/fcm/test`，平台默认走 `/v1/admin/platform/push/credentials/fcm`。保存时会真去 Google 换一次访问令牌，换不到就不保存。它必须和该租户 `google-services.json` 的 `project_info.project_id` 是同一个 Firebase 项目，两边保存时互相校验。见 `docs/decisions/0017-per-tenant-push-credentials.md`。
- OTA（实验性）：迁移 10 增加租户级 `ota_releases`，基线 APK、Runtime、Channel、Manifest 和资产由 RN-Server/华为 OBS 管理；`/v1/ota/manifest` 实现 Expo Updates v1 基础协议。当前尚未接入 Manifest 签名密钥和客户端公钥验签，生产启用前必须完成签名链路与真机回退验证。
- OTA Manifest 身份：上传 ZIP 中的客户端字段只作为构建提示。保存发布记录时，服务端会按当前请求域名和所选基线 APK 重写 `extra.expoClient`、API Base URL、应用版本、Build、Runtime、平台、分发渠道与 OTA Channel，避免跨租户或跨版本复用时继承构建机写死值。
- 扫链进程：`./rn-server indexer`（迁移 33；设计见 RN-App `docs/design/wallet-receive-index-2026-09-06.md`，表结构见 `docs/database/CHAIN_SCAN_SCHEMA.md`）。按链读 `app_configs` 里 `chain-scan.<chain>`（tenant 0）的端点与节奏，把目录内 ERC-20 转账与原生币入账写进 `wallet_transfer_index`；游标与端点健康在 `chain_scan_state`。`INDEXER_ENABLED=false` 时进程空转；扫链端点独立于 App 端 RPC，由平台管理员在管理端维护并用 `STORAGE_MASTER_KEY` 加密落库。追平之后每轮最多花 20 秒执行 `chain_scan_state.jobs` 里的后台任务（`rescan` 重扫区间、`attribute` 补原生币归属），进度按行锁写回、管理端随时可取消，完成写 `audit_events`（`chain_scan.job_done`）。告警（端点全断、落后、重组、端点错链、任务失败）除写 `open_alerts` 与审计外，可选 POST 到 `INDEXER_ALERT_WEBHOOK`：JSON `{text, chain, kind, message, raisedAt, resolved}`，顶层 `text` 直接兼容 Slack / Discord incoming webhook；企业微信要求 `msgtype` 结构，需经一层中转。移动端记录接口 `GET /v1/mobile/wallet/transfers`（Wallet 会话鉴权）返回索引记录与每链进度。收款推送：钱包登录（`/v1/mobile/auth/verify`）可带 `X-Installation-ID` + `Authorization: Installation <credential>` 把会话关联到安装（`wallet_session.installation_id`）；索引器首次写入 `in` 行时给该地址有效会话所在的安装入队 `wallet.transfer.received`（`app_push_outbox.payload.targetInstallationIds`，dispatcher 只发这些安装；重扫 / 补归属不推），文案 `wallet.receivedTitle` / `wallet.receivedBody` / `wallet.receivedUnattributedBody`（迁移 34，占位符 `{amount} {symbol} {chain}`，租户可覆盖）。新链门禁：`supportedNetworks[].MinBuild{Android, IOS}` 是认识该链的最低 App 构建号（加链先出 App 构建再填），bootstrap 按 `x-platform` / `x-build-number` 只下发达到门槛的链（`chains / networks / tokens` 同步过滤，一条不剩返回 426 `APP_BUILD_TOO_OLD`）；管理端目录带 `minBuild`，扫链管理页对未启用的链显示接入向导（门槛、低于门槛的活跃安装数、目录条目、配置、监听地址），租户「钱包与链」页显示看不到该链的安装数。
- 数据迁移：`go run ./cmd/server migrate` 执行带数据库锁和 ledger 的只向前迁移；历史数据自动归入 `default` 租户。
- Release identity：租户 Android 正式包身份（包名 + 签名证书 SHA-256）写在 `app_configs.release.android`，管理接口 `GET/PUT /v1/admin/release-identity/android`；入库时 APK 必须匹配，生产环境未登记拒绝入库，React Native 公开 debug 密钥任何环境都拒绝。入库用 `objectstore.Stat` 记录对象 ETag，公开下载与 OTA 资源下发前再 `Stat` 比对，不符或存储不可达都不下发（详见 `docs/OPERATIONS_AND_RELEASE.md` §5）。管理端入口：RN-Admin「发布基础设施 → Android 发布身份」页；API 为 `GET/PUT /v1/admin/release-identity/android`（契约 2026.09.10）。生产环境（`APP_ENV=production`）的对象存储 endpoint / publicBaseUrl 必须是 https，否则保存被拒（`STORAGE_ENDPOINT_INSECURE`）、已存配置不可用（`STORAGE_UNAVAILABLE`）。
- Release storage：`STORAGE_MASTER_KEY` 必须是 32 字节随机值的 Base64，只用于加密数据库中的租户对象存储凭证；Endpoint、Region、Bucket、Prefix 与凭证通过管理端写入 `app_configs.release.storage`。`ARTIFACT_UPLOAD_MODE=direct` 使用浏览器预签名直传并要求 Bucket CORS，`proxy` 则由 RN-Server 流式中转到对象存储、不要求浏览器访问 Bucket；其余 `ARTIFACT_*` 控制安装包大小、上传/下载有效期和校验超时。
- Multipart 上传：`/v1/admin/upload-sessions` 为 APK/OTA 提供可恢复的 S3 Multipart 会话。当前 RN-Admin 走服务端 proxy 分片接口（不依赖 Bucket CORS）；另提供 presign 分片接口供后续直传接入。选择文件后创建会话，按 `partSize` 上传分片，完成后才返回临时 artifact token；临时会话存于 `upload_sessions`，不会写入 `app_releases` 或 OTA 发布记录。`ARTIFACT_MULTIPART_TTL_SECONDS` 控制会话有效期，过期会话通过 cleanup endpoint abort。

最低检查为 `gofmt`、`go vet ./...`、`go test -race ./...` 和 `go build ./cmd/server`。

管理员密码只保存 scrypt 哈希，明文不得进入仓库或日志。

## 私有依赖

统一登录的客户端是私有仓库 `github.com/Helix2010/authorization-go-sdk`（公司认证中心的 Go SDK）。**本仓库里任何 go 命令**都要能拉到它，不只是编 `cmd/server`：`go list`、打包机的 `build-bundles.sh`、`deploy/amos/deploy.sh` 都会读整个模块图。第一次拉取之前配一次：

```bash
go env -w GOPRIVATE=github.com/Helix2010/authorization-go-sdk   # 不去公共代理和校验和库，go.sum 照样核对
# 用你能读这个仓库的 SSH 身份；主机别名按自己的 ~/.ssh/config 改（比如本机用的是 amos.github.com）
git config --global url."git@github.com:Helix2010/authorization-go-sdk".insteadOf "https://github.com/Helix2010/authorization-go-sdk"
```

模块缓存里有了之后，平时编译不再联网。CI 用的是那个仓库的只读 deploy key：Actions Secret `AUTHORIZATION_SDK_DEPLOY_KEY`（建在仓库级 Secrets，不是某个 environment 下），由 `.github/actions/private-go-modules` 装上。`Dockerfile` 要用 `docker build --ssh default .`。

## 设计入口

- [总体架构](docs/ARCHITECTURE.md)
- [API、数据与安全规范](docs/API_STANDARD.md)
- [配置参考](docs/CONFIGURATION.md)
- [可观测、升级与运行规范](docs/OPERATIONS_AND_RELEASE.md)
- [独立管理前端与插件模块决策](docs/decisions/0002-independent-admin-and-plugin-modules.md)
- [MySQL 持久化决策](docs/decisions/0003-mysql-persistence.md)
- [管理端浏览器会话门禁决策](docs/decisions/0004-admin-browser-session.md)
- [Go 服务端运行时决策](docs/decisions/0005-go-server-runtime.md)
- [Caddy HTTPS 网关决策](docs/decisions/0006-caddy-tls-gateway.md)
- [域名租户与 Release-Centric 简化决策](docs/decisions/0008-domain-release-centric-simplification.md)

所有参与者在改代码前必须先阅读 [AGENTS.md](AGENTS.md)。
