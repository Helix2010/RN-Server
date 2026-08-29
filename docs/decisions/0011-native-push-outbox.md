# ADR-0011：原生推送与更新事件 Outbox

状态：Accepted（2026-08-29）

## 决策

- APK、OTA、品牌和多语言发布事务内写入 `app_push_outbox`，由独立 Go Worker 异步发送。
- FCM HTTP v1 与 APNs Token Authentication 通过 Provider Adapter 隔离；HMS 作为后续适配器。
- 推送 Payload 只包含事件类型和版本提示，客户端必须重新请求 Bootstrap/Manifest，推送不作为版本事实源。
- 推送目标始终限定为 `tenant_id + installation_id + provider + token`；`device_client_id` 只用于平台内部去重，不作为推送目标。

## 降级

未配置供应商凭证或 `PUSH_DISPATCH_ENABLED=false` 时不启动 Worker，Outbox 记录保留，App 继续通过冷启动、回前台和定时同步发现更新。

## 安全

FCM Service Account、APNs `.p8` 私钥只从服务端 Secret/环境注入，不写入数据库、日志或客户端包。失效 Token 标记 `invalid_at`，投递结果写入租户隔离的 delivery 表。
