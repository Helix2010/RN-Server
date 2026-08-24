# RN-Server 工程执行约束

本文件对人类开发者与 AI 同等生效。

## 开始任务前

1. 必须阅读 README、本文件和相关 `docs/`；检查当前分支及用户已有改动。
2. 必须从 controller/consumer 追踪到 application、domain、repository 和外部依赖，不能在框架异常包装处停止。
3. 缺陷先复现/失败测试；需求先明确验收条件、API、数据迁移、权限与发布影响。

## 架构与契约

- 按 `src/modules/<module>` 组织业务能力；模块的公开出口是唯一跨模块依赖入口。
- controller 只处理 transport/auth/validation/mapping，业务规则必须进入 application/domain。
- repository、队列、对象存储、邮件/短信、更新供应商均通过 port/adapter 隔离。
- OpenAPI 是移动端公共契约，route/DTO 改动必须重新生成并执行 breaking-change 检查。
- 返回错误必须使用统一 Problem Details；禁止把堆栈、SQL、供应商 message 或敏感数据返回客户端。
- 写操作必须明确事务边界；涉及外部系统时采用 outbox/幂等消费，不伪造分布式原子性。
- 数据库迁移只能向前新增；已部署迁移禁止改写。破坏性 schema 采用 expand/migrate/contract。
- 生成目录和生成的 OpenAPI 文件禁止手改。

## 安全与隐私

- 默认拒绝访问；认证、授权、资源归属必须分别验证。
- 客户端传来的 userId/tenantId/role 不可信，身份从已验证凭证和服务端授权上下文获取。
- 禁止记录密码、token、验证码、签名私钥、完整请求/响应体和受保护个人数据。
- 下载 artifact 必须校验权限，采用短时 URL；服务端记录 hash、签名证书指纹和不可变 build 身份。
- 管理端发布、强更、灰度、回滚、密钥/证书操作必须有 RBAC、二次确认和审计记录。

## 变更纪律

- 只做任务所需的最小改动，不清理/回滚任务外内容。
- 新生产依赖、跨模块共享抽象、数据库/缓存/队列替换、微服务拆分必须新增 ADR。
- 禁止空 `catch`、无依据重试、无说明 `any`、禁用校验、删除失败测试、依赖真实网络/时钟的非确定测试。
- 兼容窗口内不得删除/改义移动端字段或 endpoint；新字段默认 optional/additive。

## 完成门禁

脚手架落地后最低执行：

```bash
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -race ./...
go build ./cmd/server
```

数据迁移、队列、鉴权、版本发布还需运行对应集成/E2E 和回滚验证。交付必须列明实际验证、未验证项、API/数据兼容、发布与回滚，不得声称未运行的检查通过。
