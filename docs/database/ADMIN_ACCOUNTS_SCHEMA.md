# 控制台账号与统一登录（tenant_admin_accounts / admin_sessions / app_configs auth.cid、mail.smtp）

设计：`docs/design/tenant-console-accounts-and-sso-2026-09-25.md`（§3.3 会话、§4 接入统一认证、§4.9 自建认证中心）、
`docs/design/platform-accounts-and-console-login-2026-09-27.md`（平台管理员也进这张表，迁移 63）、
`docs/design/console-accounts-external-maintenance-2026-09-27.md`（账号改由外部系统写入，迁移 64）；决策：ADR-0021、ADR-0024；接口 JSON 见 `contracts/openapi.json`。

## 复用映射

| 初稿里拟新增 | 处理 | 理由 |
| --- | --- | --- |
| `tenant_admin_accounts` | **新建**（迁移 60） | 「控制台上的人」是新实体：一个租户多个人，登录时要按 (租户, 统一认证账号) 查人，要唯一约束与状态；`app_configs` 一键一行的 JSON 承载不了 |
| `tenant_admin_identities` 外部身份表 | 取消，合并进账号表 | 一个账号只对应一个外部身份：`idp_subject` 一列加唯一键即可（迁移 64 起只有统一认证一种，`idp` 列删掉） |
| 登录流程临时状态（state、PKCE） | 取消，用加密 Cookie | 10 分钟、一次性、只有发起它的浏览器用；`secretbox` 加密后放进 Cookie，不落库 |
| 二次验证码 | 取消，放进程内存 | 10 分钟、一次性、输错 5 次作废；RN-Server 单实例，重启后重发即可（`second_factor.go`） |
| 发信账号 | 复用 `app_configs`，`tenant_id=0`、键 `mail.smtp` | 平台级一份；口令用 `secretbox` 加密（ADR-0022） |
| 统一认证的客户端配置 | 复用 `app_configs`，`tenant_id=0`、键 `auth.cid` | 平台级一份；客户端密钥用 `secretbox` 加密 |
| 会话 | 复用 `admin_sessions`，加列（迁移 61、62、64） | 见下 |
| 审计 | 复用 `audit_events` | 租户账号的 actor 是 `tenant:<租户 id>:<账号 id>`；平台管理员账号是 `platform:<账号 id>`，审计记在平台（`tenant_id=0`），动作前缀 `platform_account_`。账号本身的增删改由外部系统审计，RN 不记 |
| 平台管理员账号 | 复用 `tenant_admin_accounts`，加 `scope` 列（迁移 63） | `tenant_id` 为 NULL，租户查询天然查不到它们 |

迁移 64 起账号由外部系统（统一登录的平台端）写入，RN 只读（设计 `console-accounts-external-maintenance-2026-09-27.md`、ADR-0024）。
之前的「初始口令 → 待绑定 → 本人绑定」、登录名、邀请与绑定验证码都已删掉。

## tenant_admin_accounts

| 列 | 类型 | 谁写 | 说明 |
| --- | --- | --- | --- |
| `id` | BIGINT UNSIGNED 自增 | 数据库 | 账号主键；会话与审计 actor 用它 |
| `scope` | VARCHAR(16) | 外部系统 | `tenant`=租户成员；`platform`=平台管理员 |
| `tenant_id` | BIGINT UNSIGNED NULL | 外部系统 | 租户成员的租户，只能在这个租户的域名上登录；平台管理员为 NULL（只能在平台控制台 `PLATFORM_CONSOLE_HOST` 上登录，设计 `docs/design/service-and-console-split-2026-09-27.md`）。CHECK `ck_tenant_admin_scope` 保证与 `scope` 一致 |
| `tenant_key` | BIGINT UNSIGNED 生成列 | 数据库 | `IFNULL(tenant_id, 0)`，只给唯一键用（MySQL 唯一索引不比较 NULL） |
| `display_name` | VARCHAR(120)，默认 `''` | 外部系统 | 显示名，也用在二次验证邮件里（空串时用邮箱） |
| `email` | VARCHAR(255) | 外部系统 | **二次验证码发到这里**，必须是本人能收信的邮箱；不唯一、不作身份依据。CHECK `ck_tenant_admin_email`（`LIKE '_%@_%._%'`） |
| `idp_subject` | VARCHAR(120) | 外部系统 | 统一认证 userinfo 的 `username`（账号 uuid，**小写**）。CHECK `ck_tenant_admin_subject`（区分大小写的 uuid 正则）。改了它就是换了人，旧会话随即失效 |
| `status` | VARCHAR(16)，默认 `active` | 外部系统 | `active` / `disabled`，CHECK `ck_tenant_admin_status` |
| `created_by` | VARCHAR(120)，默认 `''` | 外部系统（可不写） | 谁分配的，只用于显示 |
| `created_at` | DATETIME(3)，默认当前时间 | 外部系统（可不写） | 分配时刻，列表里显示 |
| `last_login_at` | DATETIME(3) NULL | RN | 最近一次统一登录成功的时刻 |

唯一键：`uq_tenant_admin_subject (idp_subject, tenant_key)`——同一个统一认证账号在一个租户里最多一条，平台管理员里最多一条；可以分别是多个租户的成员。账号 id 在前，回调按它查出全部记录也走这个索引。
索引：`ix_tenant_admin_tenant (tenant_id, status)`（成员列表）。迁移 64 删掉了 RN 不再读的列：`login_name`、`password_hash`、`password_expires_at`、`idp_email`、`bound_at`、`idp`（恒为 `chainup-cid`）、`updated_at`。

登录规则（`cid_login.go` `accountForLogin`）：同时有平台记录与任何租户记录 → 拒绝（`cidError=identity_conflict`，记日志）；
平台控制台只认平台记录（→ 平台会话），租户控制台只认当前域名租户的记录（→ 租户会话），其余 → `no_access`；选中的记录不是
`active` → `disabled`。不自动开户。

谁写：外部系统（建议给它一个只能读写这张表、只读 `tenants` 与 `tenant_domain` 几列的数据库账号，见设计 §3）；RN 只写 `last_login_at`。
谁读：统一登录回调、每个请求的鉴权（回表查状态、`scope`、租户与 `idp_subject`）、控制台的只读列表（`GET /v1/admin/tenant-accounts`、`GET /v1/admin/platform/accounts`，只给平台管理员）。

## admin_sessions 新增的列（迁移 61、62、64、65）

| 列 | 说明 |
| --- | --- |
| `tenant_id` | 租户会话的租户；NULL=平台会话（平台管理员账号） |
| `account_id` | 会话的账号（租户成员或平台管理员），迁移 65 起必填 |
| `idp_subject`（迁移 64） | 登录时账号的统一认证账号 id；每个请求核对账号当前的 `idp_subject`，对不上就当没登录。迁移时现有账号会话已回填；迁移 65 起必填 |
| `second_factor_at`（迁移 62） | 账号会话最近一次通过邮箱二次验证的时间；敏感操作要在 15 分钟内（ADR-0023），平台管理员账号的平台级写操作也要。NULL=这个会话还没验过；环境变量账号不用 |

迁移 64 删掉了 `login_method` 列与索引 `ix_session_account`（只给已删掉的停用、重置接口用）。迁移 65 删掉环境变量管理员账号留下的会话（`account_id` 为 NULL），会话从此只有统一登录一个来源。

鉴权：租户会话只在请求域名属于同一个租户时有效（否则当没登录）；平台管理员账号的会话只在平台控制台有效，拿到租户控制台上当没登录；每个请求回表，账号要是 `active`、按会话类型查得到、`idp_subject` 不变；租户会话永远不是平台管理员。

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

## app_configs：mail.smtp（平台级，tenant_id=0）

```json
{"host":"smtp.example.com","port":587,"username":"noreply@example.com",
 "passwordEncrypted":"<base64 secretbox，AAD mail-smtp:password；无 username 时为空>","fromAddress":"noreply@example.com","fromName":"RN 平台"}
```

- `host` 只写主机名；`port` 空 = 587。465 走隐式 TLS，其它端口必须 STARTTLS，只有本机地址允许明文（本地调试）；
- 口令不经任何接口返回，界面只显示 `hasPassword`；
- 账号会话的邮箱二次验证码靠它发：没配就过不了二次验证（503 `MAIL_NOT_CONFIGURED`），不退回不校验；有可用的平台管理员账号时不能删（409 `MAIL_REQUIRED_FOR_SECOND_FACTOR`）。

谁写：平台管理员（`PUT /v1/admin/platform/mail`，带 `expectedVersion`，审计 `mail_config_update`；`POST /v1/admin/platform/mail/test` 试发，审计 `mail_test_sent`）。
谁读：`POST /v1/admin/auth/second-factor/code`（审计 `tenant_account_second_factor_code_sent` / `platform_account_second_factor_code_sent`：收件人掩码，不含验证码）。
