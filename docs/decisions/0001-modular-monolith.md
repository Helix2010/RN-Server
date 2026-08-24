# ADR-0001：采用 TypeScript/NestJS 模块化单体

- 状态：Proposed
- 日期：2026-08-21

## 背景

RN-Server 是空白仓库，需要同时承载移动端平台能力和早期业务。团队尚无流量、组织或故障隔离证据支持微服务，且 RN-App 需要稳定、可生成的契约和端到端可观测。

## 决策

采用 Node.js LTS、TypeScript strict、NestJS/Fastify 的模块化单体。数据库最初建议 PostgreSQL/Prisma，现已由 ADR-0003 更新为 MySQL/mysql2。模块通过公开 application API/domain/integration event 协作；使用 transactional outbox 处理可靠异步副作用。OpenAPI 为移动端版本化公共契约。

## 备选方案

- 立即微服务：增加部署、契约、事务和排障成本，当前收益无证据。
- 无结构 Express/Fastify：初始文件少，但跨 AI/团队接手更易产生第二套边界与横切逻辑。
- Go 模块化服务：运行效率和静态类型优秀；若团队 Go 能力、性能目标或现有基础设施明确偏向 Go，可在初始化前替换，本蓝图中的模块/契约/发布规则仍适用。

## 后果

- 需要 lint/测试强制模块边界，避免“单体”退化为任意耦合。
- Node 版本、依赖和数据库连接池必须由 CI/部署固定。
- 将来拆分模块前需用 ADR 证明数据所有权、调用图、容量和组织边界；outbox integration events 提供迁移接缝。
