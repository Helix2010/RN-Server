# ADR-0006：使用隔离的 Caddy 容器作为 HTTPS 网关

- 状态：Accepted
- 日期：2026-08-25

## 背景

web4 同时运行多个互不相关的项目，RN 基座部署在
`/home/ubuntu/fy/service`。管理端需要使用自有域名和可信 HTTPS，且不能安装或
改写可能影响其他项目的系统级反向代理。HTTPS 下浏览器会阻止管理页面调用
HTTP API，管理会话 Cookie 也必须启用 `Secure`。

## 决策

RN 基座在自己的 Compose 项目中运行固定版本的 Caddy，并固定安装
`caddy-dns/cloudflare` 插件。网关仅占用当前空闲的 80/443 端口，按明确的 host
映射将 `api.anyfun.win` 转发到 Go 服务、将 `console.anyfun.win` 转发到
RN-Admin，未知子域名返回 404。Caddy 通过最小权限 Cloudflare Token 完成 DNS-01
验证，使用持久化命名卷保存 ACME 账户与泛域名证书并自动续期；基域名与路由
分别通过 `PUBLIC_BASE_DOMAIN`、`PUBLIC_API_DOMAIN` 和
`PUBLIC_CONSOLE_DOMAIN` 配置。

生产管理页面和 API 使用同一 site 下的两个 HTTPS origin。`PUBLIC_SERVER_URL`
指向 API，`CORS_ORIGINS` 只允许管理端 origin，`ADMIN_COOKIE_SECURE=true`。
Cloudflare Token 仅保存在生产 `.env`，不进入镜像、仓库或日志。RN-Server 和
RN-Admin 的原有端口暂时保留用于兼容与回滚，后续确认没有旧客户端依赖后再收敛
为 loopback 绑定。

## 替代方案

- 系统级 Nginx + Certbot：成熟，但会引入宿主机级配置和包生命周期，隔离性较差。
- 仅使用 Cloudflare 边缘 TLS、源站 HTTP：配置更少，但源站链路未加密，拒绝采用。
- Cloudflare Origin Certificate：适合 Full (strict)，但证书只能由 Cloudflare 信任，
  增加供应商绑定。

## 影响与退出策略

Caddy 是新增生产依赖和唯一公网 TLS 入口；镜像固定版本并受 Compose 健康检查、
日志轮转和部署回滚保护。证书状态持久化在 `rn-foundation-caddy-data`，普通代码部署
不会清除。退出时可先部署等价的 Nginx/负载均衡配置并切流，再停止 gateway；不得
在未迁移证书与流量前删除命名卷。
