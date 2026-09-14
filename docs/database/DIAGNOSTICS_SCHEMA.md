# 诊断上报表结构

由 migration 46（`diagnostic_reports`）创建。生产环境必须执行到 `schema_migrations.version=46`；仅部署二进制不会自动补齐数据库（生产 `MYSQL_AUTO_MIGRATE=false`）。设计见 RN-App `docs/design/diagnostic-report-2026-09-14.md`。

## 表职责

| 表 | 作用 | 租户隔离 |
|---|---|---|
| `app_diagnostic_reports` | 一键上报与崩溃上报的元数据；日志正文不在库里，在对象存储 | `tenant_id` |

同一个迁移还把 `features.crashAutoReport=false` 显式补进所有 `mobile-bootstrap` 配置（只补缺的）。

## 复用映射

| 拟存的东西 | 决定 | 理由 |
|---|---|---|
| 报告本身 | **新建** `app_diagnostic_reports` | 新实体。不进 `audit_events`：那是管理操作与系统事件的历史，报告有自己的处理状态与筛选维度 |
| 日志正文 | **不进库**，放对象存储，表里只存 `object_key` | 放库里会把元数据表拖成 blob 表；日志大多数时候没人看 |
| 钱包地址 | **不复制**，读时 `wallet_user_id` 关联 `wallet_user` | 地址即账号，不会变；一个事实一个存放处 |
| 设备归并 ID | **不复制**，读时 `installation_id` 关联 `app_installations` | 同上；而且租户视图本来就不暴露它 |
| 版本、渠道、系统、语言 | **存快照** | 与 `app_installations` 不是同一个事实：那边是最新状态、每次心跳覆盖，这里是出问题那一刻 |
| `running_ota_revision` | **存快照** | `ota_releases` 的行可以被清理，上报时解析出的修订号是历史事实 |

## 重要字段关系

```text
app_installations.(tenant_id, installation_id)
  ← app_diagnostic_reports.(tenant_id, installation_id)

wallet_user.(tenant_id, id)
  ← app_diagnostic_reports.(tenant_id, wallet_user_id)      NULL = 上报时未登录

ota_releases.(tenant_id, update_id)
  → app_diagnostic_reports.running_ota_revision            写入时解析一次
```

## 身份与信任

- `tenant_id` 按请求域名解析；`installation_id` 必须与 `Authorization: Installation <credential>` 校验通过的那一条一致；`wallet_user_id` 取该安装实例上最近一次仍有效的 `wallet_session`。请求体里带任何身份字段直接 400。
- `redaction_hits > 0` 表示服务端二次脱敏命中——客户端那一遍没拦住。它是安全信号，不只是清洗统计。

## 对象存储

- 键：`<storagePrefix>/tenants/<tenantId>/diagnostics/<YYYY>/<MM>/<DD>/<reference>.ndjson.gz`，内容是服务端**重新序列化**并 gzip 的 NDJSON，不是客户端上传的原始字节。
- 读取（管理端查看、下载）一律经 `/v1/admin` 接口代理，并在读之前核对键在本租户诊断前缀下；不下发预签名 URL。
- 删除顺序固定为先删对象、再删行；对象删不掉的那条保留行。

## 保留

**不设保留期，不自动清理**（产品决定）。存储增长的唯一硬闸是每租户每 24 小时 200 MB 的字节预算（`byte_size` 求和）。管理端提供单条与批量删除，均需 `reason` + `confirm=true` 并写 `audit_events`。以后加保留期只需一个按 `created_at` 删除的任务，`ix_diag_tenant_time` 已能支撑。

## `log_status`

| 值 | 含义 |
|---|---|
| `awaiting` | 元数据已收，等日志。超过 30 分钟未到的，管理端**读取时**显示为 `missing`，不回写 |
| `stored` | 日志已落盘 |
| `storage_unavailable` | 收元数据时租户没有可用对象存储；报告成立，但没有日志 |
| `failed` | 收到了日志但写对象存储失败 |
