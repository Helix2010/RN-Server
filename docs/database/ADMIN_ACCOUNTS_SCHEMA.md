# 租户控制台账号与统一登录（tenant_admin_accounts / admin_sessions / app_configs auth.cid）

设计：`docs/design/tenant-console-accounts-and-sso-2026-09-25.md`（§3.2 账号表、§3.3 会话、§4 接入统一认证、§4.9 自建认证中心）；决策：ADR-0021；接口 JSON 见 `contracts/openapi.json`。

## 复用映射

| 初稿里拟新增 | 处理 | 理由 |
| --- | --- | --- |
| `tenant_admin_accounts` | **新建**（迁移 60） | 「控制台上的人」是新实体：一个租户多个人，登录时要按 (租户, 登录名) 或 (租户, 统一认证账号) 查人，要唯一约束与状态；`app_configs` 一键一行的 JSON 承载不了 |
| `tenant_admin_identities` 外部身份表 | 取消，合并进账号表 | 一个账号只绑一个外部身份：`idp` + `idp_subject` 两列加唯一键即可 |
| 邀请表 | 取消 | 用「初始口令 + 待绑定」代替邀请链接：还没绑定的账号就是 `status=pending_bind` 的账号 |
| 登录流程临时状态（state、PKCE） | 取消，用加密 Cookie | 10 分钟、一次性、只有发起它的浏览器用；`secretbox` 加密后放进 Cookie，不落库 |
| 绑定确认前的「要绑哪个统一认证账号」 | 取消，用加密 Cookie | 5 分钟、一次性；同上 |
| 统一认证的客户端配置 | 复用 `app_configs`，`tenant_id=0`、键 `auth.cid` | 平台级一份；客户端密钥用 `secretbox` 加密 |
| 会话 | 复用 `admin_sessions`，加三列（迁移 61） | 见下 |
| 审计 | 复用 `audit_events` | 租户账号的 actor 是 `tenant:<租户 id>:<账号 id>` |

应急账号（不绑定、只用本地口令）与 TOTP 暂不做（用户 2026-09-26：TOTP 要先把设计说定再实施），到时候再加列。

## tenant_admin_accounts

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `id` | BIGINT UNSIGNED 自增 | 账号主键；会话与审计 actor 用它 |
| `tenant_id` | BIGINT UNSIGNED | 所属租户；只能在这个租户的域名上登录 |
| `display_name` | VARCHAR(120) | 显示名 |
| `login_name` | VARCHAR(64) | 本地登录名，租户内唯一，小写；绑定之后不再能用来登录 |
| `email` | VARCHAR(255) | 建号时填的邮箱，只用于界面与通知；不唯一、不作身份依据 |
| `idp` | VARCHAR(32) NULL | `chainup-cid`；NULL=还没绑定 |
| `idp_subject` | VARCHAR(120) NULL | 统一认证 userinfo 的 `username`（账号 uuid，小写）；NULL=还没绑定 |
| `idp_email` | VARCHAR(255) NULL | 绑定时统一认证返回的邮箱，只用于显示 |
| `status` | VARCHAR(16) | `pending_bind` / `active` / `disabled`，见下 |
| `password_hash` | VARCHAR(255) NULL | 初始口令的 scrypt 哈希；绑定、停用后置 NULL |
| `password_expires_at` | DATETIME(3) NULL | 初始口令过期时刻（建号或重置后 72 小时）|
| `created_by` / `created_at` / `updated_at` | | 建号人与时间 |
| `bound_at` | DATETIME(3) NULL | 最近一次完成绑定的时刻 |
| `last_login_at` | DATETIME(3) NULL | 最近一次登录成功的时刻 |

唯一键：`(tenant_id, login_name)`、`(tenant_id, idp, idp_subject)`。同一个统一认证账号可以分别是多个租户的成员，各算一个账号；同一租户里一个统一认证账号只能绑一个账号。

状态：

| 状态 | 能怎么登录 | 登录后能做什么 | 怎么进入 |
| --- | --- | --- | --- |
| `pending_bind` | 登录名 + 初始口令（没过期） | 只能查会话、登出、走绑定（其余 403 `BIND_REQUIRED`） | 建号；平台管理员「解绑并重置」 |
| `active` | 只能统一登录（口令登录 409 `ACCOUNT_BOUND_USE_CID`） | 本租户范围内都能操作（先不分角色） | 本人确认绑定 |
| `disabled` | 不能 | 会话立即失效 | 平台管理员停用 |

谁写：平台管理员（控制台成员页：建号、停用、解绑重置）；本人（确认绑定）；登录时更新 `last_login_at`。谁读：登录、每个请求的鉴权（回表查状态）、成员页。

## admin_sessions 新增的列（迁移 61）

| 列 | 说明 |
| --- | --- |
| `tenant_id` | 租户会话的租户；NULL=平台会话（环境变量里的管理员账号） |
| `account_id` | 租户会话的账号；NULL=平台会话。索引 `ix_session_account`：停用、重置时删掉这个账号的全部会话 |
| `login_method` | `password` / `cid`；NULL=迁移之前的会话，按 `password` 处理 |

鉴权：租户会话只在请求域名属于同一个租户时有效（否则当没登录）；每个请求回表查账号状态；租户会话永远不是平台管理员。

## app_configs：auth.cid（平台级，tenant_id=0）

```json
{"authorizeUrl":"https://login.dexfun.win/auth/v1/oauth/authorize","logoutUrl":"https://login.dexfun.win/auth/v1/logout",
 "tokenUrl":"http://172.17.19.2:9098/auth/v1/oauth/token","userinfoUrl":"http://172.17.19.2:9098/internal/v1/userinfo",
 "clientId":"…","clientSecretEncrypted":"<base64 secretbox，AAD auth-cid:client-secret>"}
```

- 授权与退出地址给浏览器，必须 https，可以带 `{baseHost}`（认证中心挂在应用域名下的部署方式）；
- 换令牌与 userinfo 由服务端直连，允许本机或内网的 http；
- 客户端密钥不经任何接口返回，界面只显示 `hasClientSecret`；
- 回调地址固定为 `https://<控制台域名>/client/v1/oauth/login`（认证中心不能自定义），每个租户的控制台域名都要在认证中心登记。

谁写：平台管理员（`PUT /v1/admin/platform/auth/cid`，带 `expectedVersion`，审计 `cid_config_update`）。谁读：统一登录的发起、回调、登出。
