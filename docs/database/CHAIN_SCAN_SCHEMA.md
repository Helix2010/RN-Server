# 扫链模块表结构（迁移 33）

设计：RN-App `docs/design/wallet-receive-index-2026-09-06.md` §4.9；决策：ADR-0013。生产环境必须执行到 `schema_migrations.version=33`（web4 `MYSQL_AUTO_MIGRATE=false`，迁移由部署脚本单独执行）。

## 表职责

| 表 / 列 | 作用 | 谁写 | 谁读 |
|---|---|---|---|
| `app_configs`（`tenant_id=0`，`config_key='chain-scan.<chain>'`） | 每链扫链配置：端点（URL 用 `secretbox` 加密）、跨度、确认深度、轮询、原生币模式、起扫块 | 管理端"扫链管理" | indexer（每 30 秒按 `version` 热加载） |
| `chain_scan_state` | 每链一行：游标（`scanned_to_block/hash`）、链头、状态、租约、错误计数、`endpoint_health` / `jobs` / `open_alerts` 三个 JSON | 持租约的 indexer；管理端只改 `jobs`（建任务 / 取消） | 管理端、移动端 `index` 字段 |
| `wallet_transfer_index` | 扫链得到的转账记录，唯一正式来源 | indexer（`INSERT IGNORE`，唯一键幂等） | 移动端记录接口、管理端地址查询 |
| `wallet_user.scan_state` | `balance` 模式的每链原生币余额快照 `{"<chain>":{"balanceRaw","block"}}` | indexer | indexer |
| `wallet_session.installation_id` | 登录时的安装实例 ID，定向推送用 | `POST /v1/mobile/auth/verify` | 推送 |
| `audit_events`（actor `system-indexer`） | 告警触发 / 恢复、重组、任务生命周期 | indexer、管理端 | 管理端审计页 |

## 重要字段关系

```text
app_configs(0, 'chain-scan.<chain>')  ── version ──▶ indexer 重建该链 worker
chain_scan_state.chain                ── 1:1 ────▶ app_configs 'chain-scan.<chain>'
wallet_transfer_index.(tenant_id, address_key) ──▶ wallet_user.(tenant_id, address_key)
wallet_transfer_index.contract_address           ──▶ chain_token_catalog.contract_address（EIP-55；原生币 'native'）
```

## 不变量

- 游标只在写记录的同一事务里推进；`scanned_to_hash` 每轮核对，不符即回退 `confirmations` 块并把 `block_number >` 回退点的行标 `orphaned`。
- 唯一键 `uq_transfer(tenant_id, chain, tx_hash, log_index, address_key, direction, block_number)`：重扫不重复；`unattributed` 行 `tx_hash=''`、`log_index=-1`，同一区间只会有一条。
- 监听集合不落表：`wallet_user(status='active')` × 租户 `mobile-bootstrap.wallet`（`onchainSends=true` 且 `chains` 含该链）。
- 端点明文只在 `app_configs` 密文与 indexer 内存里；`endpoint_health.urlHash` 是 SHA-256。
