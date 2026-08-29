# 设备与推送表结构（最终版）

最终字段由 migration 14 创建、migration 17/18/19/20 补齐、migration 21 统一字段备注。生产环境必须执行到 `schema_migrations.version=21`；仅部署二进制不会自动补齐数据库（web4 当前 `MYSQL_AUTO_MIGRATE=false`）。

## 表职责

| 表 | 作用 | 租户隔离 |
|---|---|---|
| `device_clients` | 平台内部设备归并，保存 HMAC 后的设备来源值 | 不对租户开放 |
| `app_installations` | 当前租户某个独立 App 的安装实例、版本、语言、品牌和安装凭证 | `tenant_id` |
| `app_push_tokens` | 安装实例对应的 FCM/APNs/HMS Token | `tenant_id + installation_id` |
| `app_push_outbox` | 发布事件异步发送队列 | `tenant_id` |
| `app_push_deliveries` | 每个安装实例的投递结果 | `tenant_id` |

## 重要字段关系

```text
device_clients.id
  ← app_installations.device_client_id

app_installations.(tenant_id, installation_id)
  ← app_push_tokens.(tenant_id, installation_id)

app_push_outbox.id
  ← app_push_deliveries.event_id
```

`deviceClientId` 只用于平台内部去重，不允许作为租户查询、授权或推送目标。租户管理端所有查询必须带当前域名解析出的 `tenant_id`。

## 凭证字段

`app_installations.credential_hash` 保存安装凭证 SHA-256，不保存明文。凭证 90 天有效，提前 14 天由心跳触发轮换；管理员撤销安装实例时同时将关联推送 Token 设置为失效。
