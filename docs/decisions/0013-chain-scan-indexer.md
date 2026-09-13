# ADR-0013：独立扫链进程与钱包链上转账记录

状态：Accepted（2026-09-06）

## 背景

App 的钱包记录页只有本机发起的转出（RN-App `onchain-transfers.ts` 的本地账本）；打到地址上的入账、别的钱包软件发起的转出都没有来源。评审（RN-App `docs/design/review-2026-09-05.md` §4.1）实测五条链的平台默认 RPC 端点：BSC 完全不能 `eth_getLogs`，ETH 只能带合约地址且 ≤100 块，Monad 出块 0.3s 且 ≤100 块；浏览器 API 与 App 自扫都不满足推送与配额要求。用户拍板：独立扫链模块。完整设计在 RN-App `docs/design/wallet-receive-index-2026-09-06.md`。

## 决策

- **独立进程**：`./rn-server indexer`，同镜像不同命令（compose `indexer` 服务），不在 API 进程里跑；这个子命令默认就扫，显式写 `INDEXER_ENABLED=false` 时空转等信号（那条留给容器部署防反复重启，裸机上不启 unit 即可）。每条链一把租约（`chain_scan_state.lease_owner/lease_until`），多副本可分摊。
- **三类 RPC 端点互不读取**：App 端用租户 `wallet.networks[].rpcUrls`；服务端读代币元数据用 `supportedNetworks` 默认端点；扫链只用 `app_configs(tenant_id=0, config_key='chain-scan.<chain>')` 里的端点列表，URL 用 `secretbox`（`STORAGE_MASTER_KEY`）加密，关联数据绑定链 id。
- **先复用再建表**（AGENTS.md「数据库表设计原则」）：配置复用 `app_configs`，历史（告警触发 / 恢复、重组、任务）复用 `audit_events`（actor `system-indexer`），监听集合派生自 `wallet_user` × 租户 `mobile-bootstrap.wallet`（`onchainSends=true` 且 `chains` 含该链，规则就是 `normalizeWallet`，indexer 不复制），只新增 `chain_scan_state`（每链一行：游标、状态、端点健康 JSON、任务 JSON、未恢复告警 JSON）与 `wallet_transfer_index`（唯一的数据表），加 `wallet_user.scan_state`、`wallet_session.installation_id` 两列。
- **不遗漏**：记录与游标同一事务写入，唯一键幂等；任何中断从 `scanned_to_block+1` 追；每轮核对游标区块哈希，不符回退 `confirmations` 块并把区间行标 `orphaned`。
- **后台任务与写入幂等**：`jobs` 只在 `scan.MutateJobs`（`SELECT … FOR UPDATE` 读改写）里动，`SaveState` 不再整份写回，管理端取消与 worker 进度互不覆盖；任务只在追平后执行、每轮 20 秒预算、只扫已确认区间。记录写入用 `INSERT … ON DUPLICATE KEY UPDATE`（刷新 `status='confirmed'`、区块哈希、时间、金额）而不是 `INSERT IGNORE`：重组后同一笔交易回到同一区块号时 orphaned 行能变回 confirmed，重扫也因此幂等。`attribute` 任务逐全区块定位原生币入账，按每条 `unattributed` 行自己的区间与地址扣减"新定位到的金额"，扣完即删。
- **定向推送复用 outbox**：不加表、不加列——`app_push_outbox.payload.targetInstallationIds` 非空时 dispatcher 只投这些安装；安装来自 `wallet_session.installation_id`（登录时可选带安装凭证头，带了就必须有效，失效返回 401 让 App 丢弃凭证后重试）。入队在写记录的同一事务里，写入前先判断是否首次见到该 in 行，重扫 / 补归属不推；代币不在目录（没有符号与精度）不推。
- **新链门禁在服务端**：链目录条目带 `MinBuild{Android, IOS}`，bootstrap 按安装的平台与构建号过滤（harmony 按 Android 算，解析不出的构建号按 0），旧 App 永远收不到它不认识的链 id；过滤后一条不剩返回 426 而不是空钱包段。旧构建安装数从 `app_installations.build_number` 算，不加表。
- **原生币两种声明式模式**：`blocks` 逐块读全部交易（精确、双向）；`balance` 用 Multicall3 `aggregate3(getEthBalance)` 读余额差，只有增加才对本轮区间扫块定位交易，扫不到的差额记 `attribution='unattributed'`（金额正确、来源待定），缺口超过 `nativeGapCap` 直接记差额并建 `attribute` 任务后台归属。
- **端点策略**：按顺序取第一个健康端点、同一轮固定；连续 3 次失败进入冷却（30s × 2^n，上限 10 分钟）；`eth_chainId` 不符永久剔除；链头低于游标的落后节点跳过；每端点令牌桶限速；"跨度过大"不算失败，减半重试并计数。

## 替代方案

- Etherscan V2：五条链都覆盖、含内部交易，但免费配额按用户 × 链轮询不可持续、推送要靠轮询、数据以第三方为准。保留为将来"记录详情看内部交易"的可选增强。
- App 自扫：Monad 100 块上限，离线一天 2880 次请求；无推送。否决。
- 在 API 进程内跑 worker（推送 dispatcher 的做法）：RPC 轮询会占 HTTP 进程的连接与超时预算，且无法单独扩缩；否决。

## 安全边界

- 扫链端点只在 `app_configs` 密文与 indexer 内存里出现；管理端只返回脱敏 URL；`chain_scan_state.endpoint_health` 只存 URL 的 SHA-256。
- 租户配置的 RPC 不参与扫链（租户可控的节点能伪造记录）。
- 平台级管理路由要求 `PLATFORM_ADMIN_USERNAMES` 明确列出的账号；变量为空即 403。

## 未决

- 主网扫链端点由运营在管理端维护（用户决定），代码不内置。
- 指标暴露留给 OTel；本期只有结构化日志 + 状态表 + 审计。
