# RN-Server

基于 Go + Gin + MySQL，为 RN-App 提供认证、移动端启动配置、版本/分发策略、Feature Flag、通用 API 和可观测性关联的服务端基座。默认形态是可拆分的模块化单体，优先保证契约稳定和运维可控，而不是预先拆微服务。

## 当前阶段

当前已进入可运行基座阶段，包含 `GET /v1/mobile/bootstrap`、基于请求域名的多租户上下文和统一安装包发布链路。发布记录、国际化、主题、Feature Flag、升级策略和租户对象存储配置均由 MySQL 持久化；管理端直传 S3/R2/MinIO，服务端计算 hash、解析 Android APK 身份后，统一写入 `app_releases` 并进入发布状态机。开发阶段已删除旧 Application、Artifact 和独立 Storage Config 模型。

## 本地运行

```bash
cp .env.example .env
set -a && source .env && set +a
go run ./cmd/server
```

- 健康检查：`http://localhost:3000/health/live`
- OpenAPI UI：`http://localhost:3000/docs`
- App 配置：`http://localhost:3000/v1/mobile/bootstrap?locale=zh-CN`
- 多语言管理：管理端使用 `/v1/admin/localization` 读取全局与租户合并结果，语言设置和文案分别保存为租户差异；发布后生成 `/v1/mobile/languages/{languageCode}/document` 资源。语言编码只接受标准 BCP 47（如 `zh-CN`、`en-US`），不接受下划线格式。
- Admin 登录：`POST /v1/admin/auth/login` 创建 HttpOnly 会话；管理 API 默认拒绝未认证请求。`x-admin-key` 仅保留给受控自动化，不再进入 Web 构建。
- MySQL：通过 `MYSQL_HOST`、`MYSQL_PORT`、`MYSQL_USER`、`MYSQL_PASSWORD`、`MYSQL_DATABASE` 配置；`MYSQL_CHARSET`、`MYSQL_TIMEZONE`、`MYSQL_PARSE_TIME` 控制字符集、日期时区和日期解析；测试使用 `<database>_test`
- MySQL 连接行为：最大/空闲连接数、连接生命周期、空闲回收、查询/读写/初始化超时与有限重试均由 `MYSQL_*` 配置。目标数据库必须预先创建；服务启动不会执行 `CREATE DATABASE`。生产环境保持 `MYSQL_AUTO_MIGRATE=false`，迁移作为独立发布步骤执行。
- 数据迁移：`go run ./cmd/server migrate` 执行带数据库锁和 ledger 的只向前迁移；历史数据自动归入 `default` 租户。
- Release storage：`STORAGE_MASTER_KEY` 必须是 32 字节随机值的 Base64，只用于加密数据库中的租户对象存储凭证；Endpoint、Region、Bucket、Prefix 与凭证通过管理端写入 `app_configs.release.storage`。`ARTIFACT_UPLOAD_MODE=direct` 使用浏览器预签名直传并要求 Bucket CORS，`proxy` 则由 RN-Server 流式中转到对象存储、不要求浏览器访问 Bucket；其余 `ARTIFACT_*` 控制安装包大小、上传/下载有效期和校验超时。

最低检查为 `gofmt`、`go vet ./...`、`go test -race ./...` 和 `go build ./cmd/server`。

管理员密码只保存 scrypt 哈希，明文不得进入仓库或日志。

## 设计入口

- [总体架构](docs/ARCHITECTURE.md)
- [API、数据与安全规范](docs/API_STANDARD.md)
- [可观测、升级与运行规范](docs/OPERATIONS_AND_RELEASE.md)
- [独立管理前端与插件模块决策](docs/decisions/0002-independent-admin-and-plugin-modules.md)
- [MySQL 持久化决策](docs/decisions/0003-mysql-persistence.md)
- [管理端浏览器会话门禁决策](docs/decisions/0004-admin-browser-session.md)
- [Go 服务端运行时决策](docs/decisions/0005-go-server-runtime.md)
- [Caddy HTTPS 网关决策](docs/decisions/0006-caddy-tls-gateway.md)
- [域名租户与 Release-Centric 简化决策](docs/decisions/0008-domain-release-centric-simplification.md)

所有参与者在改代码前必须先阅读 [AGENTS.md](AGENTS.md)。
