# ADR-0012：钱包身份与 Sign-In with Ethereum

状态：Accepted（2026-09-01）

## 背景

App 侧要做真实的自托管钱包（见 RN-App ADR-0003 与 `UI/docs/wallet-web3-base-plan-2026-09-01.md`）。此前 App 的登录是本地 Mock：客户端自己拼 SIWE 消息、自己生成 nonce、`verify()` 只检查签名以 `0x` 开头。服务端没有任何身份概念，"注册"无从发生。

## 决策

- **地址即账号**：无邮箱、无密码。首次 `POST /v1/mobile/auth/verify` 成功即在 `wallet_user` 建档（按 `tenant_id + 小写地址` 唯一），响应用 `registered` 区分注册与登录。
- **服务端构造整条 SIWE 消息**并与 nonce 一起下发（`POST /v1/mobile/auth/nonce`），客户端只负责签名。客户端因此无法编造 domain 或有效期，两端也不会因为拼接差异对不上。
- **nonce 服务端持有、一次性核销**：`wallet_auth_nonce` 绑定租户 + 地址 + 域名 + 消息全文，10 分钟有效；`SELECT … FOR UPDATE` 保证并发下只有一次核销成功；**验签失败也核销**，避免拿同一个挑战反复试签名。
- **服务端永不接触私钥**。只做 ecrecover：EIP-191 personal_sign 信封 + Keccak-256 + secp256k1 公钥恢复 → EIP-55 地址，并校验消息里声明的地址与恢复出的地址一致（防"消息写别人地址、签名用自己密钥"）。
- **会话令牌只存 SHA-256**（`wallet_session`），`Authorization: Wallet <token>`，7 天有效，可撤销；比较用常量时间。

## 依赖

新增生产依赖 `github.com/decred/dcrd/dcrec/secp256k1/v4`（公钥恢复）。

替代方案：`github.com/ethereum/go-ethereum/crypto` —— 功能足够但会拖进整条以太坊客户端依赖树（体积与维护面都大得多）。Keccak-256 用已有的 `golang.org/x/crypto/sha3`（`NewLegacyKeccak256`），不额外引依赖。自研 secp256k1 恢复被直接排除：签名相关代码只用审计过的实现。

退出策略：恢复逻辑集中在 `internal/siwe`，换库只改一个文件；已有真实签名向量的单测可直接复用。

## 安全边界

- nonce 一次性、绑定地址与域名、失败即作废 → 抗重放。
- 消息声明地址 ≠ 恢复地址即拒绝 → 抗地址冒用。
- `MaxAge` 独立于客户端声明的 `Expiration Time`，客户端拉长有效期无效。
- 令牌明文不落库、不进日志；撤销后立即失效。
- 多租户：nonce、用户、会话全部按 `tenant_id` 隔离，域名由 `domainTenantScope()` 解析。

## 未决

- 是否需要 refresh token（当前 7 天到期后重新签名登录）。
- 是否按地址做风控/制裁名单筛查（合规范围，本 ADR 不含）。
