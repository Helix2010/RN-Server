# 配置参考

服务端读 51 个环境变量。这份文档回答三个问题：**哪些必须配**、**每个键是什么**、**这台机器上现在到底生效了什么**。

最后一个问题不用查文档：

```bash
rn-server config
```

它打印实际生效的值，并标出每一项来自 `env` 还是代码 `default`；机密只显示长度，输出可以直接贴进工单。`config` 子命令**不连数据库**——配置有问题的时候多半正是连不上库的时候。

## 1. 原则：.env 只放"别处不可能知道"的东西

机密与这台机器的拓扑。有默认值的不写，能从库里推导的不填，按租户变化的进租户配置。

写一行等于默认值的配置，代价不是磁盘，是**以后没人能一眼看出哪些是特意设成这样的**。amos 上这份文件曾经有 61 行，其中 24 行复述默认值、7 行是空的或代码从不读取的；真正承载信息的不到 30 行。收缩之后是 18 行（见 §6）。

按"这个值由什么决定"分，51 个键落在五类里，只有前三类真的属于 .env：

| 类别 | 例子 | 该不该在 .env |
|---|---|---|
| 机密 | `STORAGE_MASTER_KEY`、`MYSQL_DSN`、`ADMIN_API_KEY` | **必须**，且只能在这里 |
| 部署拓扑 | `BIND_ADDRESS`、`PORT`、`TRUSTED_PROXIES` | **必须**，别处不可能知道 |
| 角色开关 | `PUSH_DISPATCH_ENABLED`、`MYSQL_AUTO_MIGRATE` | 要，决定这台机器跑什么 |
| 调优参数 | 超时、TTL、连接池 | **只写和默认不同的那几个**，并写上理由 |
| 租户数据 | 推送凭据、下载地址、对象存储凭据 | **不在这里**，在库里按租户存 |

## 2. 必须配的

| 键 | 说明 |
|---|---|
| `MYSQL_DSN` | 数据库连接，见 §3。生产不配拒绝启动；开发不配用本地默认 |
| `STORAGE_MASTER_KEY` | 32 字节随机值的 Base64。库里所有敏感配置都用它封：对象存储凭据、OTA 签名私钥、推送服务账号、签名密钥外层、扫链端点。**换掉它 = 那些配置全部解不开**。生产必填 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | 管理端登录。哈希用 `POST /v1/admin/platform/password-hash` 生成，明文不进仓库和日志。生产必填 |
| `APP_ENV` | `development`（默认）/ `test` / `production`。生产会额外强制上面几项；`test` 会给库名加 `_test` 后缀 |

生产环境额外拒绝的：`CORS_ORIGINS` 显式写 `*`（见 §4）。

## 3. 数据库：一行 DSN

```ini
MYSQL_DSN=user:password@tcp(host:port)/database?parseTime=true&loc=UTC&charset=utf8mb4&timeout=15s&readTimeout=15s&writeTimeout=15s
```

格式是 [go-sql-driver](https://github.com/go-sql-driver/mysql#dsn-data-source-name) 的标准写法，参数语义由驱动定义，我们不另发明。

### 3.1 三条会咬人的规则

**口令里的特殊字符不用转义。** 驱动取整串里最后一个 `/` 作库名分隔，再在其左侧取最后一个 `@` 作凭据分隔，口令是第一个 `:` 到那个 `@` 之间的全部内容。所以口令含 `@ / : ( ) & $` 都不会断。**唯一的约束是用户名不能含 `:`**。

**时区写 `loc=UTC`，不能写 `Z`。** `Z` 是 ISO-8601 的 UTC 记号，不是时区名；驱动用 `time.LoadLocation`，不认它。（旧的 `MYSQL_TIMEZONE` 示例里写的就是 `Z`，迁移时要改。）

**本地 `.env` 里这一行要加单引号。** 用 `set -a && source .env` 加载时，值里的 `(` `)` `&` 都会被 shell 解释，不加引号直接报 `syntax error near unexpected token '('`。systemd 的 `EnvironmentFile` 不做 shell 展开，所以 `/etc/rn-foundation.env` 里**不要**加引号。

### 3.2 服务端会替你补五项

驱动自己的默认值和我们要的**不一样**，而差异全都在启动之后才发作：

| 参数 | 驱动默认 | 我们的默认 | 漏掉的后果 |
|---|---|---|---|
| `parseTime` | **false** | `true` | 所有读 `DATETIME` 的接口 500，而启动是绿的 |
| `timeout` | **0（无限）** | `15s` | 库挂起时连不上也不返回 |
| `readTimeout` | **0** | `30s` | handler 永远等下去，连接池占满，健康检查跟着死 |
| `writeTimeout` | **0** | `30s` | 同上 |
| `charset` | 不发（用服务端默认） | `utf8mb4` | 库的服务端默认不是 utf8mb4 时中文变问号 |

DSN 里没写的，服务端补上并在 `rn-server config` 里逐项标出 `服务端补齐`。照着 MySQL 文档随手写一行最小 DSN 拿到的正是上面那几样，所以这一步不是锦上添花。

**显式写 `parseTime=false` 会被拒绝启动**：整套代码把 `DATETIME` 扫进 `time.Time`，关掉它不会报错，只会让每个读时间的接口 500。

`charset` 只在 `charset` 和 `collation` 都没写时才补——显式给了 `collation` 的人知道自己在做什么。

### 3.3 不在 DSN 里的数据库键

它们是 `database/sql` 和我们自己的事，驱动不认：

| 键 | 默认 | 说明 |
|---|---|---|
| `MYSQL_CONNECTION_LIMIT` | `10` | 连接池上限。和别的进程共用一个库时，几边加起来别超过库那边的上限 |
| `MYSQL_MAX_IDLE_CONNECTIONS` | `2` | 不能大于上一项，否则拒绝启动 |
| `MYSQL_CONNECTION_MAX_LIFETIME_SECONDS` | `1800` | |
| `MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS` | `300` | |
| `MYSQL_QUERY_TIMEOUT_SECONDS` | `10` | 管理接口的整体超时 |
| `MYSQL_INIT_TIMEOUT_SECONDS` | `30` | 启动时 ping 的超时 |
| `MYSQL_INIT_MAX_ATTEMPTS` | `3` | 启动重试次数，1–10 |
| `MYSQL_INIT_RETRY_DELAY_SECONDS` | `5` | |
| `MYSQL_AUTO_MIGRATE` | `true` | **生产要 `false`**：迁移由 `rn-foundation-migrate` 这个 oneshot unit 单独跑，两个写入方抢同一张 `schema_migrations` 是这里最不想要的东西 |

目标数据库必须预先存在；服务启动不会执行 `CREATE DATABASE`。

### 3.4 旧的十一个键已经不再被读取

`MYSQL_HOST`/`MYSQL_PORT`/`MYSQL_USER`/`MYSQL_PASSWORD`/`MYSQL_DATABASE`/`MYSQL_CHARSET`/`MYSQL_TIMEZONE`/`MYSQL_PARSE_TIME`/`MYSQL_CONNECT_TIMEOUT_SECONDS`/`MYSQL_READ_TIMEOUT_SECONDS`/`MYSQL_WRITE_TIMEOUT_SECONDS` 已于 2026-09-13 合并进 `MYSQL_DSN`。

env 里还留着它们而没有 `MYSQL_DSN` 时，**服务拒绝启动**并点名：

```
MYSQL_DSN is required: MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_DATABASE 已经不再被读取，
把它们合成一行 MYSQL_DSN=user:password@tcp(host:port)/database?parseTime=true&loc=UTC&...
```

不静默忽略是有意的：那样会落到开发默认连接（本机 3306 的 `rn_foundation`）上，报错只会说"连不上"，而真正的原因是这台机器的配置没迁移过——那是最难查的一类失败。

`deploy/amos/slim-env.py` 可以自动完成这次合并（先不加 `--apply` 看要动哪些键）。

## 4. 其余键

### 4.1 这台机器

| 键 | 默认 | 说明 |
|---|---|---|
| `BIND_ADDRESS` | 空（所有网卡） | 裸机部署**要显式填 `127.0.0.1`**，否则应用端口会绕过反向代理直接对外，TLS 和它上面的一切都白设。Docker 部署靠端口映射兜底 |
| `PORT` | `3000` | |
| `TRUSTED_PROXIES` | 空 | 允许设置 `X-Forwarded-For` 的上跳。**空 = 谁都不信**，`ClientIP` 取直连对端。不填时 `ADMIN_API_ALLOWED_IPS` 只是摆设（安全评审 N17） |
| `PLATFORM_ADMIN_USERNAMES` | 空 | 能进平台级页面（扫链管理、打包机公钥、平台推送默认）的管理员，逗号分隔。**空 = 平台路由一律 403** |
| `CORS_ORIGINS` | 开发 `*`，生产空 | **额外**放行的来源。租户自己的域名由 `tenant_domain` 表推导（见 `originAllowed`），通常不需要写。生产显式写 `*` 会拒绝启动 |
| `HTTP_READ_TIMEOUT_SECONDS` | `3600` | 大产物上传要靠它，别调小 |
| `HTTP_WRITE_TIMEOUT_SECONDS` | `3600` | |

### 4.2 管理端

| 键 | 默认 | 说明 |
|---|---|---|
| `ADMIN_API_KEY` | 空 | `x-admin-key` 自动化通道。空 = 该通道关闭。浏览器构建里没有它 |
| `ADMIN_API_ACTOR` | `api-key-automation` | `x-admin-key` 请求写进审计的身份。请求自报的 `x-admin-id` 一律忽略（N17 门禁项） |
| `ADMIN_API_ALLOWED_IPS` | 空 | 限制该通道的来源（CIDR 或裸 IP）。空 = 不限制。要它生效必须先配 `TRUSTED_PROXIES` |
| `ADMIN_SESSION_TTL_SECONDS` | `28800` | 最小 300 |
| `ADMIN_COOKIE_SECURE` | `true` | 会话 cookie 只走 TLS。本地用 http 调管理端才关掉 |
| `ADMIN_LOGIN_MAX_ATTEMPTS` | `5` | 最小 3 |
| `ADMIN_LOGIN_WINDOW_SECONDS` | `900` | 最小 60 |

### 4.3 打包与产物

| 键 | 默认 | 说明 |
|---|---|---|
| `BUILD_AGENT_TOKEN` | 空 | 打包机代理的凭据，与管理端密钥**完全分开**：管理端密钥能改配置、发版、读安装明细，打包机只需要领任务和回报结果。空 = `/v1/build-agent` 整条通道关闭 |
| `ARTIFACT_UPLOAD_MODE` | `direct` | `direct` 是浏览器直传对象存储，**要求桶上有 CORS 规则**；`proxy` 由服务端流式中转，不要求浏览器访问桶。桶配不了跨域就用 `proxy` |
| `ARTIFACT_MAX_SIZE_MB` | `512` | 1–2048 |
| `ARTIFACT_UPLOAD_TTL_SECONDS` | `900` | 60–3600 |
| `ARTIFACT_MULTIPART_TTL_SECONDS` | `7200` | 300–86400，分片会话的可恢复窗口 |
| `ARTIFACT_VERIFY_TIMEOUT_SECONDS` | `300` | 30–1800 |

对象存储的 endpoint / 桶 / 凭据**不在 env**：按租户存在 `app_configs.release.storage`，用 `STORAGE_MASTER_KEY` 加密，由管理端写入。

### 4.4 推送

| 键 | 默认 | 说明 |
|---|---|---|
| `PUSH_DISPATCH_ENABLED` | `false` | 这台机器跑不跑派发。出站队列的认领是 CAS，多实例安全 |
| `PUSH_POLL_INTERVAL_SECONDS` | `10` | 1–300 |
| `PUSH_CONCURRENCY` | `8` | 1–64 |

**FCM 凭据不在 env**：按租户存在 `app_configs.push.fcm`，用 `STORAGE_MASTER_KEY` 加密，在管理端「Android 打包与签名」页配置。见 [ADR-0017](decisions/0017-per-tenant-push-credentials.md)。

`FCM_PROJECT_ID` / `FCM_SERVICE_ACCOUNT_JSON` 是**弃用的过渡键**：库里一行 `push.fcm` 都没有时才兜底，且每次启动打 WARN。`rn-server push-credentials import-env` 把它们搬进库（存为平台默认 tenant 0，所有租户继承，行为零变化），搬完就该从 env 删掉。下一版会删除这两个键的读取。

APNs（`APNS_TEAM_ID` / `APNS_KEY_ID` / `APNS_PRIVATE_KEY` / `APNS_BUNDLE_ID` / `APNS_ENVIRONMENT`）和 HMS（`HMS_APP_ID` / `HMS_CLIENT_ID` / `HMS_CLIENT_SECRET`）目前**仍是全局的**，没有租户在用。谁把它们改成按租户，必须同时把 `Dispatcher.apns` 和 `Dispatcher.hmsToken` 这两个全局字段改成 `map[tenant]`，否则两个租户会互相拿到对方的令牌。

### 4.5 扫链

| 键 | 默认 | 说明 |
|---|---|---|
| `INDEXER_ENABLED` | `rn-server indexer` 下 `true`，其它入口 `false` | **跑这个子命令就是要扫链**，不必再写一行开关。显式写 `false` 时进程空转不退出——那条留给容器部署防反复重启，裸机上不启 unit 即可 |
| `INDEXER_ALLOW_PLAIN_HTTP` | `false` | 私网部署允许 `http://` 扫链端点 |
| `INDEXER_ALERT_WEBHOOK` | 空 | 告警 webhook。顶层 `text` 兼容 Slack / Discord；企业微信要 `msgtype` 结构，需一层中转 |

扫链端点按链存在 `app_configs.chain-scan.<chain>`（tenant 0），用 `STORAGE_MASTER_KEY` 加密，由平台管理员在管理端维护。

### 4.6 其它

| 键 | 默认 | 说明 |
|---|---|---|
| `DEVICE_IDENTITY_HMAC_KEY` | 空 | 跨 App 设备归并用的独立 HMAC 密钥。空时回落到 `STORAGE_MASTER_KEY`，一直是这么跑的 |

## 5. 报错怎么读

配置问题**一次报完**，逐键一句，带上你写的原值：

```
2 configuration problems:
  - MYSQL_QUERY_TIMEOUT_SECONDS must be a whole number, got "十秒"
  - ADMIN_COOKIE_SECURE must be true or false, got "yes-please"
```

在此之前，二十几个键共用一句 `invalid MySQL numeric configuration`，而解析失败会静默变成 `-1` 再被那句拦住——任何笔误得到的都是同一句话，看的人只能 ssh 上去一个一个键地试。

## 6. 一份真实的生产配置

amos 上 `/etc/rn-foundation.env` 的全部内容（值已抹去），**18 行**：

```ini
# ---- 机密 ----
STORAGE_MASTER_KEY=
MYSQL_DSN=user:password@tcp(host:13306)/db?parseTime=true&loc=UTC&charset=utf8mb4&timeout=15s&readTimeout=15s&writeTimeout=15s
ADMIN_USERNAME=
ADMIN_PASSWORD_HASH=
ADMIN_API_KEY=
BUILD_AGENT_TOKEN=

# ---- 这台机器 ----
APP_ENV=production
BIND_ADDRESS=127.0.0.1
PORT=13080
TRUSTED_PROXIES=127.0.0.1
PLATFORM_ADMIN_USERNAMES=

# ---- 角色 ----
PUSH_DISPATCH_ENABLED=true
MYSQL_AUTO_MIGRATE=false

# ---- 与默认不同的调优，每一条都有理由 ----
MYSQL_CONNECTION_LIMIT=3            # 和别的进程共用一个库
MYSQL_MAX_IDLE_CONNECTIONS=1
MYSQL_CONNECTION_MAX_LIFETIME_SECONDS=600
MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS=60
ARTIFACT_UPLOAD_MODE=proxy          # 桶没有跨域规则，见 deploy/amos/README.md
```

没出现在这里的 33 个键，要么用默认值，要么是按租户存在库里的。

模板：`deploy/amos/rn-foundation.env.example`（生产）、`.env.example`（本地）。

## 7. 常见问题

**"我改了 env，怎么没生效？"** — systemd 的 `EnvironmentFile` 在进程启动时读一次。`systemctl restart`，不是 `reload`。改完先 `rn-server config` 核对。

**"服务起不来，日志只说连不上数据库。"** — 先跑 `rn-server config`：它不连库，所以这时候还能用。看「来源」那一行是 `MYSQL_DSN` 还是 `开发默认连接`——后者意味着这台机器根本没配 DSN。

**"本地 `source .env` 报 `syntax error near unexpected token '('`。"** — `MYSQL_DSN` 那一行要加单引号，见 §3.1。

**"推送发不出去，`last_error` 是 `FCM_PROJECT_MISMATCH`。"** — 这个租户的 `google-services.json`（编进 APK）和服务端的服务账号不是同一个 Firebase 项目。管理端「Android 打包与签名」页上那两节紧挨着，红绿标记会指出来。

**"怎么知道某个键到底有没有被读？"** — `rn-server config` 会把 env 里看着像我们的、其实没人读的键单独列出来（`⚠ env 里有代码从不读取的键：…`）。生产示例里曾经躺着一个 `INDEXER_MYSQL_CONNECTION_LIMIT=4`，amos 上也照着填了，代码从来没读过它。

## 相关

- [ADR-0017：推送凭据按租户存进数据库](decisions/0017-per-tenant-push-credentials.md)
- [设计：服务端 .env 收缩](design/env-config-slimdown-2026-09-13.md) — 为什么这么改，以及上线过程
- [可观测、升级与运行规范](OPERATIONS_AND_RELEASE.md)
- `deploy/amos/README.md` — amos 这台机器的部署与运维
