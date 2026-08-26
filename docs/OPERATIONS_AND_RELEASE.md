# 可观测、升级与运行规范

## 1. 可观测性模型

三类信号共享 resource attributes：service、environment、version、region、instance，并用 traceId/requestId 关联。

### Logs

- 结构化 JSON，固定 level/time/service/event/requestId/traceId/module/duration/status。
- route 使用模板而非含 ID 的真实路径，避免高基数。
- 请求/响应 body 默认不记录；允许字段采用 allowlist，而不是事后 blacklist。
- error log 记录 root cause chain、稳定 error code 和相关实体 ID 的安全形式，不只记录框架包装异常。

### Metrics

基础 RED：request rate、error rate、duration；资源 USE：CPU、memory、event loop、DB pool、queue lag。业务基座至少有 bootstrap 成功率、auth 成功率、release check、artifact download token、rollout assignment、OTA adoption、强更阻断量。

metrics label 禁止 userId/requestId/完整 URL 等无限基数值。

### Traces

从 RN-App 传入合法 traceparent，API -> DB -> Redis -> queue producer -> worker -> external HTTP 继续传播。采样采用 head 基线 + error/slow tail 保留；安全敏感字段不进 span attribute。

## 2. SLO 与告警

首发前以压测/业务目标冻结数字，不在蓝图阶段假装已有基线。至少定义：

- API availability 与 p95/p99 latency；
- bootstrap/update-policy availability；
- 登录成功率；
- worker queue age 和 dead-letter；
- App crash-free/ANR（来自客户端平台）；
- 发布后错误率相对上一稳定版本的变化。

告警必须指向 runbook 和 owner，按用户影响而不是每个异常报警。发布系统的 stop rule 可因错误率、启动失败、crash-free 回归暂停发布。

## 3. Release 状态机

```text
uploaded -> verified -> active -> paused -> completed
                    \-> rejected
```

- uploaded：对象存在但未可信；服务端流式计算 size/hash，提取 Android/iOS/OTA 元数据。
- verified：签名、app identity、build/runtime、malware/策略检查通过。
- active：官网全量分发。
- paused：不再分配新设备，已下载设备行为由客户端策略决定。
- 全量安装包不提供“自动回滚”：需要停止当前版本时使用暂停；修复必须发布更高 build 的新安装包。

已 active 的 artifact 永不原地替换。修复必须产生新 artifact/build/update id。

## 4. 更新决策 API

bootstrap 根据以下输入求值：

- 服务端可信的 application identity 映射；
- platform、app version、build、runtimeVersion；
- distribution channel；
- installation rollout bucket；
- tenant/group/region（来自可信上下文）；
- 当前策略、artifact 状态、暂停/kill switch。

输出是结构化 decision：`none | optional | recommended | required`，以及唯一合法 action：`ota | store | direct | mdm`。客户端 header 可伪造，因此升级决策不能承担认证授权职责。

决策响应须签名或包含由可信 TLS endpoint 获取的签名 manifest，带 issuedAt/expiresAt/policyVersion，防止离线缓存永久强更。

## 5. 非商店 artifact 安全

### Android direct APK

- CI 使用受控 signing service 签名，构建节点不持有可导出的长期私钥。
- 上传后验证 applicationId、versionCode、signer certificate fingerprint、minSdk、SHA-256。
- 二进制放对象存储/CDN，API 只签发短时下载 URL，不代理大文件。
- 生产下载入口可要求已认证企业用户或一次性 enrollment token；公开分发时仍需防盗链、限速与合规审查。
- 记录下载/安装结果时使用最小化匿名标识；不能假设“已下载 = 已安装”。

### iOS MDM/企业内部分发

- artifact/manifest 必须与允许的 bundleId、team/certificate、profile、受众匹配。
- certificate/profile 到期前告警；轮换必须先在真实受管设备验证覆盖升级。
- MDM assignment 状态与 App 主动 check 状态分开记录；MDM 是安装控制面，App release service 是版本策略面。
- 企业 IPA/manifest 不下发给公共用户，访问日志和审计证明分发范围。

### OTA

- manifest 签名密钥与 native signing key 分离；私钥由 signing service 保管。
- runtimeVersion 必须严格匹配；资源 URL 内容寻址并不可变。
- 更新上传后跑静态检查、启动 smoke 和真机 staging；生产先 canary。

## 6. 灰度与暂停

- 当前开发阶段不实现灰度 bucket 和比例分配。
- feature flag 可关闭业务功能，但不能修复原生 ABI 不兼容；两者责任分开。
- OTA 可独立设计恢复上一稳定 update；当前全量安装包发布模块不提供回滚，必须发布更高 build 的修复包。
- 提升 minSupported 前先证明所有目标渠道可安装、覆盖率达标且客服/应急通道就绪。

## 7. 备份与灾难恢复

- MySQL 定期全量 + binlog PITR，恢复演练而不只检查备份任务成功。
- 对象存储启用 versioning/immutability；签名 artifact 与 manifest 跨故障域备份。
- Redis/队列不能成为唯一业务事实源；outbox 可从数据库恢复投递。
- 记录目标 RPO/RTO、DNS/CDN/identity provider 故障的降级策略。
- bootstrap 故障时已安装 App 使用有限期缓存，不应全部变砖。

## 8. 管理控制面

发布管理端必须提供：draft preview、artifact verification、受众/比例、兼容矩阵、minSupported 风险提示、暂停、审计查询。当前阶段不加入 RBAC 与双人审批；高风险操作仍必须显式确认并填写 reason，不提供无上下文的“立即全量强更”按钮。

## 9. Runbook 最小集合

- API 错误率/延迟升高；
- 数据库连接耗尽/慢查询；
- 队列积压/dead-letter；
- 登录供应商故障；
- 错误 OTA 导致启动崩溃；
- Android APK 签名/下载/安装失败；
- iOS 企业证书/profile 到期或撤销；
- 错误 minSupported 导致全量阻断；
- 凭证/签名密钥疑似泄露。

每份 runbook 包含影响确认、立即止损、诊断查询、恢复、数据核对、沟通和复盘责任。

## 10. 多租户对象存储上线检查

- 上传模式由 `ARTIFACT_UPLOAD_MODE` 控制：`direct` 使用浏览器预签名 PUT，吞吐更高但 Bucket 必须允许管理端 Origin；`proxy` 由 RN-Server 将请求体流式写入对象存储，适用于暂时无法配置 CORS 的环境。代理模式不会把完整安装包读入内存，但会占用 API 带宽和一条长连接。

- 每个租户使用独立 bucket 或至少由服务端强制生成的 `tenants/<tenantId>/` 前缀；IAM policy 同时限制 bucket、prefix、Get/Put/List 权限，禁止 ListAllMyBuckets 和删除生产 Artifact。
- bucket CORS 只允许 RN-Admin 的 HTTPS origin、`PUT`/`HEAD` 和 `content-type` header。AWS S3 示例：

```json
[
  {
    "AllowedOrigins": ["https://console.anyfun.win"],
    "AllowedMethods": ["PUT", "HEAD"],
    "AllowedHeaders": ["content-type"],
    "ExposeHeaders": ["etag"],
    "MaxAgeSeconds": 900
  }
]
```

- `STORAGE_MASTER_KEY` 用 `openssl rand -base64 32` 生成并放入部署 secret；备份后再写入生产，不能放 MySQL。轮换前必须实现逐版本解密、重加密和核对，禁止直接替换环境值。
- 先在管理端保存配置，再执行“测试连接”；随后用非生产签名 APK 验证直传、finalize、拒绝错误 signer、预发布、激活、公开 latest metadata、307 下载与覆盖安装。
- 激活前确认 public CDN base URL 指向同一不可变 object key；未配置 CDN 时验证 presigned GET 的 TTL、限速和日志不会泄露 query signature。
