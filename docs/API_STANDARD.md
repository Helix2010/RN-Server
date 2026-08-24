# API、数据与安全规范

## 1. HTTP 约定

- 路径按稳定大版本：`/v1/...`；资源用复数名词，动作只用于无法表达为资源状态转换的场景。
- JSON 字段使用 camelCase；时间为 RFC 3339 UTC；ID 对客户端视为 opaque string。
- 成功响应直接返回资源/结果，不强制包一层无信息的 `{code,data,message}`。
- 错误使用 `Content-Type: application/problem+json`。
- GET/HEAD 安全，PUT/DELETE 语义幂等；POST 若支持重试必须声明 `Idempotency-Key`。
- 列表优先 cursor pagination，返回 `items`、`nextCursor`、`hasMore`；禁止 offset 用于高变动大表。

## 2. 统一错误

```json
{
  "type": "https://api.example.com/problems/validation-error",
  "title": "Request validation failed",
  "status": 422,
  "code": "VALIDATION_ERROR",
  "requestId": "req_...",
  "errors": [
    { "path": "email", "code": "INVALID_FORMAT" }
  ]
}
```

- `code` 是稳定机器语义；`title/detail` 不作为客户端核心分支条件。
- 400 表示语法/通用输入问题，401 未认证，403 无权限，404 不暴露或不存在，409 并发/状态冲突，422 字段/领域校验，429 限流，5xx 服务故障。
- 未知异常映射 500，详细 cause 仅在服务端脱敏日志中，并关联 requestId。
- 不把异常全部包装成 HTTP 200。

## 3. 请求上下文

服务端接受/生成 requestId，提取合法 W3C trace context，响应回传 `X-Request-Id`。同时记录 appVersion、build、platform、distribution、runtimeVersion，但这些客户端 header 只用于诊断/兼容，不能作为授权事实。

## 4. 幂等与并发

- 支持幂等的 endpoint 将 `(principal, endpoint, idempotencyKey)` 设唯一，并保存 request fingerprint 与最终响应摘要。
- 相同 key 不同 payload 返回 409；处理中请求返回一致状态；记录有业务规定的 TTL。
- 资源更新用 version/ETag + `If-Match` 或数据库 compare-and-swap，避免最后写入静默覆盖。
- 资金、配额、库存等不变量由数据库约束/事务保证，不能只靠客户端按钮禁用。

## 5. 运行时校验与 OpenAPI

- 所有 path/query/header/body 在 controller 边界校验、去除未知字段；输出 DTO 明确映射，禁止直接序列化 ORM entity。
- DTO/route/security/error 在 OpenAPI 中可见；每个 endpoint 至少有成功、校验、认证/授权错误定义。
- CI 生成 `contracts/openapi/openapi.json`，与主分支执行 breaking diff；生成无差异才允许通过。
- generated contract 作为版本化 CI artifact 供 RN-App 固定使用。
- 删除、重命名、required 新字段、收窄类型、改变 enum/格式/状态码均视为潜在 breaking change。

## 6. 认证、授权与滥用防护

请求依次经过：凭证验证 -> audience/scope -> route permission -> resource ownership -> domain invariant。任一层失败即拒绝。管理 API 与 mobile API 分开 scope 和网络/风控策略。

当前管理端最小门禁通过 `POST /v1/admin/auth/login` 建立服务端可撤销的 HttpOnly 会话；浏览器不得持有共享管理密钥。登录接口必须限流，基于会话的写操作必须校验可信 Origin。`x-admin-key` 仅用于受控自动化兼容，不作为 Web 登录方案。

- 密码采用当前批准的强哈希参数，验证码有过期、次数和防枚举策略。
- refresh rotation 检测 token family 重放并撤销会话。
- 登录、注册、找回、bootstrap、artifact download 分别限流。
- CORS 不是移动 App 安全控制；不能替代 token、签名和授权。

## 7. 输入、上传与下载

- 限制 body/file 大小、MIME、扩展名和解码后的真实格式；必要时隔离病毒扫描。
- 对象 key 由服务端生成，不能把用户路径直接拼接到文件系统/存储 key。
- 上传使用短时签名 URL + finalize 验证；私有下载鉴权后给短时 URL。
- APK/OTA artifact 只有 release pipeline 可写，普通业务上传路径无权覆盖。

## 8. 数据迁移

生产迁移必须：有唯一序号、事务能力说明、锁表/耗时评估、备份/恢复点、向前修复方案。大表回填使用可恢复批任务，不在应用启动或一个长事务中完成。

schema 变更顺序：

1. expand：新增 nullable/有安全默认值的结构；
2. deploy dual-compatible code；
3. backfill 并核对；
4. enforce：约束生效；
5. contract：支持窗口结束后清理旧结构。

## 9. API 测试

- DTO/schema：边界和非法输入；
- application/domain：授权、不变量、时钟与并发；
- repository：真实 MySQL 约束和事务；
- controller：状态码、Problem Details、header；
- contract：生成 OpenAPI 与 RN-App fixture；
- 安全：越权、IDOR、重放、限流、上传、敏感日志；
- compatibility：至少验证支持窗口内最老客户端 contract。
