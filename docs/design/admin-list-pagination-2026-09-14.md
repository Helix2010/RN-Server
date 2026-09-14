# 设计：管理端列表页的服务端分页与查询条件

状态：Accepted（2026-09-14）。依据 `RN-Admin/docs/ADMIN_ENGINEERING_STANDARD.md` §3「服务端分页和筛选是唯一事实源，禁止前端拉全量再切数组」与 §8「筛选条件写入 URL、筛选变化时清理 cursor」。

## 1. 现状盘点

管理端所有渲染"记录列表"的页面，逐个对照服务端 handler：

| 页面 | 接口 | 服务端现状 | 管理端现状 | 结论 |
|---|---|---|---|---|
| 设备 | `GET /v1/admin/installations` | 键集分页 + total + 多条件 | 加载更多 + FilterToolbar | 已具备 |
| 账号 | `GET /v1/admin/wallet/users` | 键集分页 + total | 加载更多 + FilterToolbar | 已具备 |
| 诊断上报 | `GET /v1/admin/diagnostics/reports` | 键集分页 + total | 加载更多 + URL 筛选 | 已具备 |
| 构建任务 | `GET /v1/admin/builds` | 键集分页 | 上一页/下一页 | 已具备 |
| 审计日志 | `GET /v1/admin/audit-events` | 固定 `LIMIT 1000`，`nextCursor` 恒为 null | 无分页、无筛选 | **补** |
| 全量版本 | `GET /v1/admin/releases` | **无 LIMIT**；支持 platform/status 但管理端没传 | 两个下拉框只有"全部"一项，是摆设；前端排序 | **补** |
| OTA 热更新 | `GET /v1/admin/ota/releases` | `LIMIT 200` 静默截断 | 平台/状态/通道/基线四个筛选全在前端对数组做 | **补** |
| 通知记录 | `GET /v1/admin/push/outbox`、`/push/deliveries` | `LIMIT 200` / `LIMIT 500`，`total` 返回的是 `len(items)` | 指标卡"事件数""投递失败"是截断后的数 | **补** |
| 平台封禁 | `GET /v1/admin/platform/wallet/blocks` | `LIMIT 200` | 无分页、无筛选 | **补** |
| 扫链地址记录 | `GET /v1/admin/platform/scan/transfers` | `LIMIT 200` | 查一次显示前 200 条 | **补** |

不做分页的页面及理由：

- **代币目录**（`/tokens`）：配置集合，行数被平台链目录白名单约束；页面按链分组展示并用 `databaseVersion` 做乐观锁，是配置编辑器而不是记录流。服务端已有 `chain` 过滤。
- **多语言文案**（`/localization`）：整份文档编辑器——草稿是整份克隆、新增语言要给每个 key 补一格、导出 Excel 需要全量、保存时对整份求差。分页要先把编辑模型改成"服务端逐条保存 + 草稿覆盖层"，属于编辑器重做，单独立项（见 §8）。
- **链配置**（`/platform/scan/chains`）、**OTA 基线选择器**（`/ota/base-releases`，`LIMIT 100` 的下拉选项）、设备详情里的内嵌表、诊断日志（已是 offset 分页）：不是列表页或已分页。

## 2. 统一契约

本次补的六个接口统一为：

- 请求：`limit`（1–200，默认 50，越界 422）、`cursor`（不透明字符串，坏游标 422，不悄悄从头翻）；其余为各自的筛选参数，非法取值 422 并说明是哪个参数、期望什么。
- 响应：`{ items, total, nextCursor, hasMore, limit }`。`total` 是**当前筛选条件下**的真实计数（`COUNT(*)`，不是本页条数）；`nextCursor` 为 null 等价于 `hasMore=false`。扫链地址记录例外，不返回 `total`（见 §4.6）。
- 排序：键集分页，排序键末尾一定带主键做唯一决胜，保证翻页不重不漏。排序键只用**不会随状态变化**的列，避免翻页途中行"跳页"。
- 游标：`base64url(JSON 数组)`，数组元素是排序键的字符串形式。用 JSON 而不是 `a:b` 拼接，是因为推送投递的主键含 `installation_id` 这类任意字符串，拼接会有歧义。实现集中在 `internal/api/list_page.go`。
- 时间范围：`from`（含）/`to`（不含），RFC 3339，与诊断上报一致。

## 3. 数据库

不新增表、列与索引。逐表确认现有索引能支撑新查询：

| 表 | 查询形状 | 现有索引 | 判断 |
|---|---|---|---|
| `audit_events` | `tenant_id=? ORDER BY created_at DESC,id DESC` | `ix_audit_tenant_created(tenant_id,created_at)` | 命中 |
| `app_releases` | `tenant_id=? ORDER BY build_number DESC,id DESC` | `ix_release_platform_build(tenant_id,platform,build_number)` | 带 platform 时命中；不带时按租户扫，单租户行数为百级 |
| `ota_releases` | `tenant_id=? ORDER BY revision DESC,created_at DESC,id DESC` | `ix_ota_lookup(tenant_id,…)` 前缀 | 租户前缀命中，排序在租户内完成 |
| `app_push_outbox` | `tenant_id=? ORDER BY created_at DESC,id DESC` | `ix_push_outbox_tenant(tenant_id,created_at)` | 命中 |
| `app_push_deliveries` | `tenant_id=? ORDER BY created_at DESC,…` | `ix_push_delivery_tenant(tenant_id,created_at)` | 命中 |
| `platform_wallet_block` | `ORDER BY created_at DESC,id DESC` | 无 | 平台级人工封禁，行数极少，不为它加索引 |
| `wallet_transfer_index` | `chain=? AND address_key=?` | `ix_transfer_address(tenant_id,…)` 首列是 tenant | **现状就用不上索引**（跨租户查），本次不改变这一点，见 §8 |

## 4. 逐接口

### 4.1 审计日志 `GET /v1/admin/audit-events`

- 排序 `(created_at DESC, id DESC)`。
- 筛选：`action`（精确）、`targetType`（精确）、`actorId`（精确）、`q`（`target_id` 或 `request_id` 精确匹配——拿到手的就是这两样之一）、`from`/`to`。
- `queryAudits(tenant, target)`（发布详情里取某条发布的审计）保持不变。

### 4.2 全量版本 `GET /v1/admin/releases`

- 排序 `(build_number DESC, id DESC)`。原来中间还有 `updated_at DESC`，但 `updated_at` 随每次状态动作变化，做键集会让行在翻页途中移动；`build_number` 在同平台内唯一且不变，跨平台同号由 `id` 决胜。
- 筛选：`platform`、`status`（可逗号分隔多个，白名单校验）、`q`（版本号前缀）。
- 管理端"灰度已被更高正式版盖过"的提示原来对整份数组求值；分页后改为单独取 `status=active` 这一小集合比对，不依赖当前页。
- 新租户向导只需要"有没有可分发/已校验的版本"，改为 `status=…&limit=1` 看 `total`。
- `GET /v1/admin/overview` 的计数继续用内部全量查询，不受影响。

### 4.3 OTA 热更新 `GET /v1/admin/ota/releases`

- 排序保持 `(revision DESC, created_at DESC, id DESC)`，游标三段。
- 筛选：`platform`、`status`、`channel`、`baseReleaseId`（原来都在前端做）。
- 响应额外返回 `baseReleases`：本租户（按 `platform` 筛选时限定该平台）**有 OTA 记录的**基线 APK 去重列表，供"基线 APK"下拉框使用。原来下拉选项从当前数组去重得到，分页后当前页不代表全集。不用 `/ota/base-releases` 代替：那个接口只列 verified/active 基线，已暂停/已完成基线上的 OTA 记录会筛不出来。

### 4.4 通知记录

`GET /v1/admin/push/outbox`：
- 排序 `(created_at DESC, id DESC)`；筛选 `status`、`eventType`（精确）、`from`/`to`。

`GET /v1/admin/push/deliveries`：
- 排序 `(created_at DESC, event_id DESC, installation_id DESC, provider DESC)`（主键三列决胜）。
- 筛选 `status`、`provider`（fcm/apns/hms）、`installationId`（精确）、`eventId`（精确）、`from`/`to`。
- 指标卡"投递失败"改为 `status=failed&limit=1` 的 `total`，不再从当前页数。

### 4.5 平台封禁 `GET /v1/admin/platform/wallet/blocks`

- 排序 `(created_at DESC, id DESC)`。
- 筛选：`address`（完整地址，已有）、`status`（`active` / `revoked`，空=全部）。非法地址的错误码由 `INVALID_WALLET_ADDRESS` 并入 `INVALID_PLATFORM_BLOCK_FILTER`（422，detail 不变）。**`includeRevoked` 去掉**：它只有管理端一个调用方，与本次改动同步发布；保留两个语义重叠的参数只会让人纠结该传哪个。

### 4.6 扫链地址记录 `GET /v1/admin/platform/scan/transfers`

- 排序 `(block_number DESC, id DESC)`，游标用 §2 的统一格式（没有复用移动端转账接口的 `transferCursor`：管理端六个列表用同一套解析与校验，少一种格式要维护）。
- 新增筛选：`direction`（in/out）、`status`（confirmed/orphaned）。
- **不返回 `total`**：这条查询跨租户按 `(chain,address_key)` 查，现有索引首列是 `tenant_id` 用不上（§3），再加一次 `COUNT(*)` 等于把全表扫翻倍。页面显示"已显示 N 条"。

## 5. 管理端

- 列表统一 `useInfiniteQuery` + 底部"加载更多"（与设备/账号/诊断一致），抽出 `ListLoadMore` 组件；卡片标题下显示"共 N 条，已显示 M 条"。
- 筛选统一 `FilterToolbar`，条件写入 URL、刷新与前进后退恢复（抽出 `src/core/url-filter.ts`）。同一路由下有多个列表时参数加前缀避免互相覆盖：全量版本用 `apk*`，OTA 沿用已有的 `platform/status/channel/baseReleaseId`，通知用 `outbox*` / `delivery*`，平台封禁用 `block*`。
- 去掉前端排序和前端筛选：顺序与过滤只以服务端为准。
- OTA 列表"筛选后为空"时原来渲染一张**没有筛选工具栏**的空卡片，用户没法改回条件；改为工具栏常驻、空态放在表格区域。
- 扫链地址记录是一次性查询表单，不写 URL。

## 6. 测试

- 服务端单测：每个接口的参数校验（非法取值 422）、where 片段；游标编解码往返（含非法游标）。
- 服务端库测（`TestDB…`，需 `RN_TEST_MYSQL_DSN`）：每个接口造超过一页的数据，用小 `limit` 翻完，断言不重不漏、`total` 正确、筛选生效。
- 管理端：各页请求参数随筛选变化、筛选变化回到第一页、加载更多拼接、URL 恢复；原有用例里依赖前端排序/前端筛选的断言改为依赖服务端顺序。

## 7. 兼容、发布与回滚

- 全部是 `/v1/admin/*` 管理端接口，调用方只有 RN-Admin，两仓同步发布。移动端契约不变。
- 响应只增字段；`releases` 与 `ota/releases` 从"一次返回全部"变为默认 50 条——旧版管理端会只看到前 50 条，因此**服务端与管理端必须同一窗口发布**，先服务端后管理端，窗口内旧管理端最多少显示历史行，不影响任何写操作。
- 平台封禁的 `includeRevoked` 被移除：旧管理端传了也会被忽略，结果变为"全部"（原来就是传 true），行为一致。
- 无迁移，回滚两仓提交即可。

## 8. 已知遗留（本次不做）

- **多语言文案编辑器分页**：需要重做编辑模型（§1），建议单独立项。
- **扫链地址记录的索引**：`wallet_transfer_index` 缺 `(chain,address_key,block_number,id)` 索引，平台级查询全表扫。数据量上来前补一个向前迁移。
- **契约文档欠账**：`openapi.json` 里设备列表没有列参数、账号列表与平台封禁接口缺条目。本次只补动到的接口：平台封禁补了 `GET` 条目，它的 `POST`（封禁）与 `/revoke`（解除）仍缺，其余另行补。
- 设备、账号两页的筛选条件没有写入 URL（§8 要求），不在本次范围。
