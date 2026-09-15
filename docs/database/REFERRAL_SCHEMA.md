# 邀请关系表结构

本期不新增表。邀请关系是 `wallet_user` 的一对一属性，落在该表的四个新列上；绑定事件进 `audit_events`，租户配置进 `app_configs` 的 `mobile-bootstrap`。为什么这么放见 `docs/decisions/0018-referral-graph.md`，完整设计见 RN-App `docs/design/referral-graph-2026-09-15.md`。

## 新增列

全部在 `wallet_user` 上。该表原有字段见 `internal/store/migrations.go` 的 `walletIdentityMigration`。

| 列 | 类型 | 含义 |
|---|---|---|
| `invite_code` | `CHAR(8) NULL` | 该账号的邀请码，注册事务内生成、永不更换。Crockford Base32 大写（`0-9A-Z` 去掉 `I L O U`），租户内唯一。**永久可空**，理由见下 |
| `inviter_user_id` | `BIGINT UNSIGNED NULL` | 直接邀请人的 `wallet_user.id`，必为同租户。NULL = 没有邀请人。一次性写入，写入后不可改、不可解除 |
| `invited_at` | `DATETIME(3) NULL` | 绑定邀请人的时刻（UTC） |
| `invite_source` | `ENUM('code','link','admin') NULL` | 绑定渠道，只用于运营统计，不参与任何判定 |

后三者同生共死：要么全为 NULL，要么全非 NULL。由 CHECK 约束强制，不只是应用层约定。

`invite_source` 取值由**提交路径**决定，不由客户端自由填：

| 值 | 来自 |
|---|---|
| `code` | 用户在邀请页输入框里手输或粘贴邀请码 |
| `link` | 邀请链接深链带来的邀请码（用相机扫二维码也走这条，二维码内容就是链接） |
| `admin` | 管理端补录 |

## 为什么 `invite_code` 永久可空

登录语句是 `INSERT ... ON DUPLICATE KEY UPDATE`（`internal/api/wallet_auth.go:248`）。MySQL 对**任意**唯一键冲突都会触发 ON DUPLICATE 分支。三条路都走不通，只剩可空：

| 方案 | 实测后果 |
|---|---|
| `NOT NULL` 且进登录 INSERT | 抽到的码撞上他人的码时，MySQL 去更新**那一行**（`address` 被改成新用户的地址，`ROW_COUNT()=2`），随后按 `address_key` 查不到自己 → 500。且 ODUP **不抛 1062**，"碰撞后重试"无从捕获。MySQL 官方还把多唯一键上的 ODUP 列为 statement-based 复制不安全 |
| `NOT NULL` 无 DEFAULT | 回滚到旧二进制后，旧 INSERT 不带该列，strict 模式 `ERROR 1364 Field 'invite_code' doesn't have a default value` → **老用户也登不上** |
| `NOT NULL DEFAULT ''` | 两个并发新用户都插 `''`，在唯一键上互撞，回到第一行的问题 |

**可空列上的多个 NULL 在唯一索引里不冲突**，这正是需要的。码由注册事务里一条独立语句赋予：

```sql
UPDATE wallet_user SET invite_code=? WHERE id=? AND invite_code IS NULL
```

它抛真正的 1062，可捕获后换码重试。候选码在 `BeginTx` **之前**预抽 3 个——该事务已持有 nonce 行的 `FOR UPDATE` 锁并跨越 `siwe.Verify`，不该再被生成逻辑延长。

"人人有码"这条不变量由注册事务保证：提交后不存在无码的行。读到无码行就是事故，按正式场景原则报错，不走"没有码时换个行为"的分支。

## 新增索引与约束

| 索引 | 用途 |
|---|---|
| `uq_wallet_user_invite_code (tenant_id, invite_code)` | 码租户内唯一。生成碰撞由该键抛 1062，应用层换码重试。跨租户同码互不影响 |
| `ix_wallet_user_inviter (tenant_id, inviter_user_id, invited_at, id)` | 移动端"我的下级"。实测 `range + Backward index scan`，无 filesort |
| `ix_wallet_user_invited_at (tenant_id, invited_at, id)` | **管理端关系列表**。它没有 `inviter_user_id` 等值条件，上一个索引第二列断开，实测走 filesort、rows≈9918 |

CHECK 约束（MySQL 8.0.16+ 强制）：`inviter_user_id`、`invited_at`、`invite_source` 三者要么全 NULL 要么全非 NULL。

不加它的后果是实测过的：补录漏写一列就产生 `inviter_user_id` 非空、`invited_at` 为 NULL 的行。键集分页的游标条件（`list_page.go:96` 的 `keysetBefore`）里 `NULL < ts` 不为真，这行会被**全部排除**，在自己上级的下级列表里永久不可见；而 `total` 仍把它算进去，末几页返回空却 `hasMore=true`，违反 `list_page.go:176` 的契约。

同理，所有关系查询都要显式带 `inviter_user_id IS NOT NULL`，否则 `total` 会把全部未绑定用户算进去。

不做冗余计数列：直接下级数由 `ix_wallet_user_inviter` 数出来，计数列要在每次绑定时维护，是第二份真相。

## 迁移：四个版本

**不能把加列与唯一键写在同一条语句里。** 实测 `ADD COLUMN invite_code CHAR(8) NOT NULL` 给已有行填 `''`，同语句里的唯一键随即报 `Duplicate entry '1-' for key 'uq_wallet_user_invite_code'`，`Migrate` 失败 → 服务起不来。而且不幂等：拆成"先 ALTER 后回填"时 ALTER 已自动提交，回填失败后重启报 `Duplicate column name`，**永久无法启动，必须人工改库**。

四个独立迁移版本，每步幂等，用既有的 `addColumnIfMissing`（`migrations.go:91`）与 `INFORMATION_SCHEMA.STATISTICS` 探测：

1. 加四列，`invite_code` 可空
2. 回填邀请码（只处理 `invite_code IS NULL` 的行，可重复执行；中断后重跑不会给已有码的行换码）
3. 加三个索引 + CHECK 约束
4. —— **没有第四步**。不把 `invite_code` 收紧为 `NOT NULL`（见上）

这是 expand/migrate/contract 的前两段，contract 这一段本设计明确不做。

回填规模与在线 DDL 的锁影响按实际行数评估。**"线上只有个位数用户"不能写进迁移**：任何测试库、任何租户长到 2 人，同一条语句换个环境就炸。

## 邀请码

- 字母表：`0123456789ABCDEFGHJKMNPQRSTVWXYZ`（Crockford Base32，去掉 `I L O U`）。去掉易混字符是为了让人能照着念、照着抄。
- 长度 8，空间 32⁸ = 1.0995×10¹²。
- `crypto/rand` 取随机。**入库次数 = 注册次数**：码不进登录那条 ON DUPLICATE KEY UPDATE，只有 `invite_code IS NULL` 的行才会被赋码。抽取次数则等于登录次数——候选码在 `BeginTx` 之前预抽（事务一开就持有 nonce 行的 `FOR UPDATE` 锁并跨越 `siwe.Verify`，不该再被随机数生成拉长），而"这一行有没有码"要进了事务才知道。没用上的候选不入库，所以对碰撞概率没有影响；代价是每次登录多做 3 次 8 字节的 `crypto/rand`，比为了省下它而在事务前多查一次库便宜。单次失败率 = N/1.1×10¹²，N = 10 万时 9.1×10⁻⁸；重试 3 次的连续失败概率 7.5×10⁻²²，足够。重试仍失败则整个注册失败并告警，不降级为"这个人暂时没有码"。
- 生日式"任意两码相撞 50%"出现在 k ≈ 1.25√(32⁸) ≈ 1.31×10⁶ 次抽取。

### 归一化（只在服务端做）

客户端把用户输入的原文原样提交，服务端一处归一化。各端各自 trim 就是第二份真相。

1. 全角转半角
2. 去掉所有非字母数字字符（空格、连字符、下划线等）
3. 转大写
4. Crockford 易混字符映射：`I` `L` → `1`，`O` → `0`
5. 结果必须恰好 8 位且每一位都在字母表内

第 4 步是 Crockford 去掉易混字符的**全部意义所在**——没有它，照着念的人输 `O` 会拿到 `CODE_UNKNOWN`，而正确行为是解码成 `0`。

`U` 不做映射：Crockford 把它排除在字母表外，出现 `U` 就是输错。

归一化失败返回 `REFERRAL_CODE_MALFORMED`（422），与"码不存在"的 `REFERRAL_CODE_UNKNOWN`（404）区分——前者是用户输错、提示重新输入，后者是码无效、提示向邀请人核对。合并成一个码会让文案只能说一句含糊的话。

表 collation 在测试库实测为 `utf8mb4_0900_ai_ci`，唯一键本身大小写不敏感，与归一化要求一致；DDL 未显式指定，**生产库真实 collation 需核对**。

### 展示格式

- 界面大字与分享文案里分段为 `XXXX-XXXX`，提高抄写正确率。
- 存储、URL、二维码内容一律不带分隔符（链接形如 `https://<租户 API 域名>/app/invite/ABCD1234`）。
- 归一化第 2 步会去掉连字符，所以用户把带横线的码粘进输入框也认。

## 租户配置

邀请的两个旋钮存在 `app_configs` 的 `mobile-bootstrap` 里，与 `modules` / `wallet` / `services` 并列：

```json
"referral": { "enabled": true, "bindWindowHours": 168 }
```

| 键 | 取值 | 未配置时（声明式默认） |
|---|---|---|
| `enabled` | 布尔 | `false`。它会在 App 上多出一个入口，该由运营明确打开 |
| `bindWindowHours` | 整数 1–8760 | `168`（7 天），从 `wallet_user.first_seen_at` 起算 |

越界值在**写入时**拒绝（400，报错说清是哪个键、填了什么、期望什么），读路径不修复。
除了"不修复坏数据"这条原则，还有一个具体后果：新版 App 的 bootstrap schema 会校验
`referral` 的取值范围，下发一个越界值会让新版 App 整份 `safeParse` 失败——未知字段被
zod strip 掉是安全的，已知字段的取值校验仍然严格。

bootstrap 另外下发一个 `inviteLinkBase`（`https://<租户 API 域名>/app/invite/`），由服务端
按请求 Host 算，不进库、不可配置：落地页是服务端的，路径规则只该有一个来源。

上溯上界是**服务端内部常量**（`internal/api/referral.go` 的 `referralMaxDepth`），不做租户
配置——本期没有任何功能按层级分叉，做成旋钮运营也无从判断该填几。

> 这一节没有放进 `docs/CONFIGURATION.md`：那份文档在 §1 明确把"按租户变化的"划在
> 范围之外（"租户数据……**不在这里**，在库里按租户存"）。设计稿原本写的是放进那里，
> 按它自己的分类应该落在本文档。

## 关系与账号状态

封禁不改变已有关系，只影响能否**新建**关系（绑定时校验邀请人未被封禁）。

| 情形 | 行为 |
|---|---|
| 邀请人事后被封（租户级 `wallet_user.status` 或平台级 `platform_wallet_block`） | 关系保留。被邀请人侧照常显示，**不显示对方的账号状态** |
| 被邀请人事后被封 | 关系保留。仍计入邀请人的下级列表与 `inviteeCount` |
| 解封 | 无需复原，关系从未改变 |
| 管理端 | 列表与详情标注双方的封禁状态 |

平台没有账号注销路径（`wallet_user.status` 只有 `active` / `blocked`），因此不存在"注销后关系怎么办"。

## 关系图不变量

1. 每个已提交的 `wallet_user` 有非空 `invite_code`，租户内唯一（由注册事务保证，不由列约束保证）。
2. `inviter_user_id` 一旦非空即不再变化。
3. 邀请图无环，且任意链路深度不超过上溯上界（服务端内部常量，个位数）。
4. 自己不能是自己的邀请人。
5. `inviter_user_id` 指向的行与本行 `tenant_id` 相同。
6. 三列同生共死（CHECK 约束）。

第 3 条**不能只靠事务内上溯**：默认 REPEATABLE READ 下事务内普通 SELECT 走快照，两个用户同时互绑时两边上溯都看不到对方的写入，最终改的是不相交的两行，零锁冲突地造出环。必须按租户 `GET_LOCK` 串行化绑定，细节见设计 §3.4。

第 5 条由查询恒带 `tenant_id` 保证：邀请码查找就限定在本租户内，跨租户的 id 拿不到。

## 审计

绑定成功写 `audit_events`：

| 字段 | 值 |
|---|---|
| `actor_id` | 自助绑定 `system-referral`；补录为管理员账号 |
| `action` | `referral_bind`（用户）/ `referral_bind_admin`（补录）/ `referral_enumeration_throttled`（限流命中） |
| `target_type` | `wallet-user` |
| `target_id` | 被邀请人的 `wallet_user.id` |
| `reason` | 自助绑定为渠道说明；补录为运营必填原因 |
| `summary` | 邀请码、渠道，以及**风控留证信号**：本次绑定的来源 IP、双方注册时间、双方注册间隔、installation 复用情况。**双方的注册 IP 与 ASN 没有采集**——库里从没有任何表存过客户端 IP，补上它是一项需要合规判断的个人数据采集决策，本期不做，缺口与后果记在 ADR 0018「滥用」一节 |

`summary` **不写完整地址**（`audit_events` 会在管理端列表里展示，且脱敏地址等同唯一键，见 ADR 0018 安全边界）。

留证信号是本期唯一还来得及做的滥用防线：关系不可解绑，返佣上线后无法追溯清理，只能靠绑定当时记下的事实来判定。等返佣立项再想采集，这批数据已经永久缺失。详见设计 §6。

## 相关表

```text
wallet_user.(tenant_id, id)
  ← wallet_user.inviter_user_id          同表自引用，同租户

wallet_user.(tenant_id, id)
  ← audit_events.target_id               target_type='wallet-user'

app_configs.(tenant_id, 'mobile-bootstrap').referral
  → 租户级开关与绑定窗口
```

`wallet_user` 的三个写方（决定了并发方案，见 ADR 0018）：

| 写方 | 语句 |
|---|---|
| 登录 | `INSERT ... ON DUPLICATE KEY UPDATE`（`wallet_auth.go:248`） |
| 绑定 | 本设计新增，按租户 `GET_LOCK` 串行 |
| 链上索引器 | 一个事务里按 Go map 随机顺序批量 UPDATE（`indexer/store.go:370-382`） |
