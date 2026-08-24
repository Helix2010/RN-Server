# ADR-0005：RN-Server 统一采用 Go

- 状态：Accepted
- 日期：2026-08-24

## 决策

RN-Server 的唯一生产实现采用 Go、Gin、`database/sql` 与 go-sql-driver/mysql。服务端仓库不保留 Node、NestJS、TypeScript 或 pnpm 构建链。RN-Admin 仍是独立 React/TypeScript Web 项目，二者通过 OpenAPI 契约协作。

## 原因

Go 单二进制适合基座服务的容器部署、启动和资源治理；静态类型、标准测试与 race detector 可形成稳定门禁。保持现有 HTTP JSON 和 MySQL schema，可在不迁移业务数据的情况下替换运行时。

## 影响

CI 使用 `gofmt`、`go vet`、`go test -race` 和 `go build`。Docker 采用多阶段 Go 构建，运行镜像不包含 Go 工具链或源码执行器。RN-Admin 的 TypeScript 不受该决策影响，因为它属于浏览器前端仓库。
