# ADR-0004：管理端浏览器会话门禁

- 状态：Accepted
- 日期：2026-08-24

## 背景

早期管理页面把共享 `x-admin-key` 注入 Vite 构建。任何能下载静态资源的人都可以提取长期密钥并直接调用发布与配置接口，因此它不是有效的生产安全边界。本阶段明确暂不引入 RBAC 和双人审批，但仍需要最小的身份门禁。

## 决策

RN-Server 使用配置文件中的管理员账号和 scrypt 密码哈希校验登录。成功后只向浏览器写入随机、高熵、HttpOnly、SameSite 会话 Cookie；数据库仅保存会话 token 的 SHA-256 摘要和过期时间。所有 `/v1/admin` 管理 API 由服务端 Guard 默认拒绝，写操作同时校验可信 Origin。登录失败按客户端地址进行窗口限流。

`x-admin-key` 只作为受控脚本的兼容入口，不再注入 RN-Admin 构建。浏览器不使用 localStorage/sessionStorage 保存凭证。生产部署必须配置明确的 CORS 来源；启用 HTTPS 后必须打开 Secure Cookie。

## 替代方案

- HTTP Basic Auth：实现更少，但缺少可撤销会话、退出能力和后续身份扩展点。
- 立即接入 OIDC/RBAC：长期方向正确，但超过当前阶段范围和运维准备度。
- 仅增加前端登录页：无法保护直接 API 调用，拒绝采用。

## 影响与退出策略

会话表是向前新增结构，发布时自动创建，不改变移动端 API。单实例登录限流存于进程内；扩展到多副本前应迁移到 Redis/网关。接入 OIDC 后替换凭证验证与 session issuer，Guard 和管理员上下文保持稳定。当前 HTTP 地址只能用于受控测试，正式对公网使用必须先接入 HTTPS。
