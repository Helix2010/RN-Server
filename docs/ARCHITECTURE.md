# RN-Server 总体架构蓝图

状态：Active
定位：移动应用平台基座 + 后续业务模块宿主。
默认部署：单区域、高可用、无状态 API；根据真实容量演进。

## 1. 设计原则

1. **契约优先**：已安装在用户设备上的旧客户端无法同步升级，服务端必须兼容支持窗口。
2. **模块化单体优先**：事务、调试、部署简单；通过边界和事件保持未来拆分可能。
3. **安全默认拒绝**：认证不等于授权，授权不等于资源归属。
4. **操作可审计**：版本发布、强更、权限和数据变更均可追踪、可撤销或有补偿。
5. **端到端可观测**：同一 requestId/trace 贯通 App、API、数据库、队列和外部服务。
6. **AI 可验证**：命令、schema、边界和不变量由自动化检查，不依赖隐性经验。

## 2. 推荐技术基线

| 领域 | 决策 |
| --- | --- |
| Runtime | 当前受支持的 Go 稳定版本，`go.mod` 固定最低版本 |
| Framework | Go + Gin，标准 `net/http` 服务生命周期 |
| Database | MySQL 8.x + `database/sql`/go-sql-driver（Repository 隔离 SQL） |
| Cache/coordination | Redis，只用于有明确一致性语义的缓存、限流和锁 |
| Background jobs | Go worker 进程 + 队列 adapter + transactional outbox |
| API contract | OpenAPI 3.x 生成与版本化 artifact，breaking diff 门禁 |
| Error | RFC 9457 `application/problem+json` 语义 |
| Observability | OpenTelemetry traces/metrics/log correlation + error tracker |
| Artifact storage | S3 兼容对象存储 + CDN/短时签名 URL |
| Test | 单元 + MySQL/Redis 集成 + HTTP/contract E2E |

版本不在蓝图中写死；初始化时选择经验证的兼容组合并锁定。框架/ORM 大版本升级独立于业务 PR。

## 3. 目录与模块边界

```text
cmd/server/               # composition root 和进程生命周期
internal/
  api/                    # Gin transport、认证、校验和 DTO mapping
  config/                 # 环境配置与安全校验
  store/                  # database/sql、MySQL 查询与事务边界
  modules/                # 复杂业务增长后按能力迁入此处
    <business-module>/
      domain/
      application/
      infrastructure/
      presentation/
contracts/openapi.json    # 移动端与管理端公共契约
deploy/web4/              # 隔离部署、Caddy 与 Compose
docs/                     # 当前规范和仍有效的 ADR
```

每个模块内部使用轻量的 domain/application/adapter 分层，但不要求每个 CRUD 都制造接口。只有外部依赖、复杂领域不变量或需要替换/测试的边界才抽象 port。

跨模块协作优先级：

1. 同进程公开 application API；
2. 本地 domain event；
3. transactional outbox 后的异步 integration event；
4. 只有独立扩缩、故障隔离、数据所有权和团队边界均有证据时才拆服务。

禁止跨模块直接查询对方表来绕过授权和不变量；只读报表需要显式 read model。

## 4. 平台模块

### 4.1 Auth

- OAuth 2.1/OIDC 能力优先交给成熟身份服务；本服务负责 token 验证、会话/设备会话策略和业务授权映射。
- 移动端使用 Authorization Code + PKCE；refresh token rotation 与重放检测。
- 访问 token 短时有效；注销/风险事件通过 session version 或 denylist 控制必要的即时失效。
- 当前管理端使用独立管理员身份适配器；正式认证和 RBAC 作为后续独立模块，不进入首期流程。

### 4.2 App Config / Bootstrap

`GET /v1/mobile/bootstrap` 返回启动所需的最小、可缓存、签名配置：

- 服务时间、配置版本、缓存期限；
- 当前 platform/appId/distribution 对应的升级策略；
- typed feature flags 和安全默认值；
- maintenance/degraded 能力声明；
- 必要的公开 endpoint/config，不含秘密。

响应支持 ETag，服务故障时 App 可以使用仍有效的签名缓存。配置发布采用草稿、校验、灰度、激活、回滚状态机。

### 4.3 App Release

核心事实源只有一张 `app_releases`：

```text
app_releases
  tenant_id, platform(android/ios/harmony), version, build_number,
  runtime_version, status, release_notes, object_key, file_name,
  expected_size, file_size, sha256, file_metadata, published_at
```

约束：

- `tenant + platform + buildNumber` 唯一且发布后不可变。
- 安装包上传后服务端计算 hash；客户端提供的 hash 不能成为事实源。
- 当前激活需显式确认、reason 和 audit event；RBAC 与双人审批暂缓。提升 `minSupported` 仍是独立高风险动作。
- 当前开发阶段只做全量 active，不实现灰度 assignment。
- OTA 资源必须与 runtimeVersion 匹配并有 manifest 签名。
- direct APK 下载用短时 URL；MDM/store 只返回已批准的 action URL。

### 4.4 Feature Flags

flag schema 包含 key、type、default、owner、expiresAt、target rule、kill-switch priority。客户端只接收自己的已求值结果，不能得到完整用户分群规则。安全关键授权绝不能只依赖客户端 flag。

### 4.5 Audit

记录 actor、action、target、before/after 摘要、requestId、reason、time；敏感值脱敏。审计存储追加写，普通管理员无删除权限。发布/强更/回滚/权限修改必须覆盖。

## 5. 数据一致性

- 单模块数据库写使用事务；事务内不调用外部网络。
- “写库 + 发消息”使用 transactional outbox，由 worker 至少一次投递；consumer 用 eventId/business key 幂等。
- 分布式锁不是事务替代品；唯一约束、版本号或 compare-and-swap 才是并发不变量的最后防线。
- 缓存只存可重建数据，key 带 schema/tenant/version；失效失败不能产生越权。
- 时间统一存 UTC，边界使用带时区格式；关键流程注入 Clock 便于测试。

## 6. 多租户与资源归属

基座保持 tenant-ready，但首期若没有多租户需求不强行引入：

- 一旦启用，tenant context 来自已验证身份/域名映射，不信任任意 header。
- repository 层必须带 tenant predicate，数据库唯一约束包含 tenantId。
- cache、object key、queue job 和 telemetry 均隔离 tenant。
- 平台管理员跨 tenant 操作使用单独 scope、显式目标与审计。

## 7. 后台任务

job payload 只放 ID/版本，不复制大量敏感快照。每个 job 定义幂等键、最大尝试、退避、超时、dead-letter、可观测指标和人工补偿方式。worker 与 API 可以同仓、独立进程部署。

## 8. 部署拓扑

```text
WAF / Load Balancer
  -> API replicas ---- MySQL HA
         |             Redis
         +-----------> object storage/CDN
         +-- outbox -> worker replicas -> external providers

OTel collector <- API / workers <- trace context from RN-App
```

- API 无状态，滚动发布；readiness 不等于 liveness。
- 数据迁移作为受控 release step，先 expand 后部署代码。
- artifact 在各环境 promotion，同一个生产构建不重复编译。
- secret 来自 secret manager，支持轮换，不写镜像与日志。

## 9. 容量与可靠性

在压测前不虚构 QPS 数字。首个真实业务上线前用容量模型冻结：峰值用户、启动风暴、版本检查、artifact 下载带宽、登录和关键 mutation。特别防护：

- bootstrap 使用 CDN/ETag/cache，避免发布时击穿数据库；
- APK/OTA 二进制流量不经过 API 进程；
- 限流按 endpoint + identity/IP 风险组合，不使用一个全局阈值；
- 外部依赖有 timeout、circuit/bulkhead 和降级，不无限重试；
- 数据库连接池与实例数协同限制。

## 10. 兼容策略

服务端支持窗口由活跃 App 版本数据决定，至少明确 N 个 full builds 或一段时间。变更采用 additive -> app migrate -> observe -> raise min supported -> remove 的顺序。已发布客户端读取的 enum 增加新值也可能是 breaking change，必须在客户端有 unknown fallback 后才能扩展。
