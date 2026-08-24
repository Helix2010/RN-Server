# RN-Server

基于 Go + Gin + MySQL，为 RN-App 提供认证、移动端启动配置、版本/分发策略、Feature Flag、通用 API 和可观测性关联的服务端基座。默认形态是可拆分的模块化单体，优先保证契约稳定和运维可控，而不是预先拆微服务。

## 当前阶段

当前已进入可运行基座阶段，包含 `GET /v1/mobile/bootstrap` 和一组发布管理 API。发布、审计、国际化、主题、Feature Flag 与升级策略由 MySQL 持久化；管理 API 提供发布状态机、灰度摘要、带版本冲突保护的配置编辑和审计查询，供独立的 RN-Admin 使用。

## 本地运行

```bash
cp .env.example .env
set -a && source .env && set +a
go run ./cmd/server
```

- 健康检查：`http://localhost:3000/health/live`
- OpenAPI UI：`http://localhost:3000/docs`
- App 配置：`http://localhost:3000/v1/mobile/bootstrap?locale=zh-CN`
- Admin 登录：`POST /v1/admin/auth/login` 创建 HttpOnly 会话；管理 API 默认拒绝未认证请求。`x-admin-key` 仅保留给受控自动化，不再进入 Web 构建。
- MySQL：通过 `MYSQL_HOST`、`MYSQL_PORT`、`MYSQL_USER`、`MYSQL_PASSWORD`、`MYSQL_DATABASE` 配置；`MYSQL_CHARSET`、`MYSQL_TIMEZONE`、`MYSQL_PARSE_TIME` 控制字符集、日期时区和日期解析；测试使用 `<database>_test`

最低检查为 `gofmt`、`go vet ./...`、`go test -race ./...` 和 `go build ./cmd/server`。

管理员密码只保存 scrypt 哈希，明文不得进入仓库或日志。

## 设计入口

- [总体架构](docs/ARCHITECTURE.md)
- [API、数据与安全规范](docs/API_STANDARD.md)
- [可观测、升级与运行规范](docs/OPERATIONS_AND_RELEASE.md)
- [首个架构决策](docs/decisions/0001-modular-monolith.md)
- [独立管理前端与插件模块决策](docs/decisions/0002-independent-admin-and-plugin-modules.md)
- [MySQL 持久化决策](docs/decisions/0003-mysql-persistence.md)
- [管理端浏览器会话门禁决策](docs/decisions/0004-admin-browser-session.md)
- [Go 服务端运行时决策](docs/decisions/0005-go-server-runtime.md)

所有参与者在改代码前必须先阅读 [AGENTS.md](AGENTS.md)。
