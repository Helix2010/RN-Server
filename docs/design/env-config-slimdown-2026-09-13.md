# 设计：服务端 .env 收缩

状态：Proposed（2026-09-13）。分析基于 `internal/config/config.go`、两份示例文件和 amos 上 `/etc/rn-foundation.env` 的键名清单（未读取任何值）。两项决定已定：**推送凭据按租户进库**、**MySQL 十一个键合成一个 DSN**。第 5、6 节是这两项的设计，第 8 节是对它们的对抗性审查——审查改掉了设计初稿里的六处，逐条列在 8.3。

## 1. 现状：61 行里有多少是必须的

| 口径 | 数量 |
|---|---|
| 代码读取的环境变量 | **67** |
| amos 上实际写了的 | **61** |
| 其中值与代码默认值**完全相同**（写了等于没写） | **24** |
| 其中值与默认不同（真正的覆盖） | 18 |
| 其中代码里没有默认值、必须由人给 | 18，但里面 **6 个在 amos 上是空的** |
| 示例文件里有、代码**从不读取**的 | 1（`INDEXER_MYSQL_CONNECTION_LIMIT`） |
| 代码读进 `Config` 但**没有任何地方使用**的 | 1（`ARTIFACT_DOWNLOAD_TTL_SECONDS`） |

61 行里，24 行复述默认值、7 行是空的或死的，真正承载信息的不到 30 行——其中还有一批本质上不是"部署配置"。

## 2. 问题不只是"多"，是五类东西混在一个文件里

按"这个值由什么决定"分，67 个键落在五类里，只有前两类真的属于 .env：

### 2.1 机密——必须在 env，且只能在 env

`MYSQL_PASSWORD`、`STORAGE_MASTER_KEY`、`ADMIN_PASSWORD_HASH`、`ADMIN_API_KEY`、`BUILD_AGENT_TOKEN`。

`STORAGE_MASTER_KEY` 是信任根：库里所有敏感配置（对象存储凭据、OTA 签名私钥、bootstrap 签名密钥、签名 keystore 外层、chain-scan 端点）都用它封。它不能进库，这是结构性的。其余四个是"能进库但没必要"——数量少、改动少。`FCM_SERVICE_ACCOUNT_JSON` 原本也在这一类，第 5 节把它挪出去。

### 2.2 部署拓扑——每台机器不同，必须在 env

`APP_ENV`、`BIND_ADDRESS`、`PORT`、`TRUSTED_PROXIES`、数据库地址。这些回答的是"这台机器怎么接进来"，别处不可能知道。

### 2.3 角色开关——决定这台机器跑什么

`INDEXER_ENABLED`、`PUSH_DISPATCH_ENABLED`、`MYSQL_AUTO_MIGRATE`。

该在 env，但形态不对。`INDEXER_ENABLED` 在 systemd 部署下是多余的：扫链已经是 `rn-server indexer` 子命令，unit 就是它自己。不想跑就不启 unit，而不是启一个 unit 再让它空转——空转是给 Docker Compose 防容器反复重启设计的，裸机不需要。

### 2.4 调优参数（约 26 个）——有默认值，几乎不该出现

MySQL 连接池与超时 12 个、HTTP 超时 2 个、管理会话 3 个、产物 TTL 5 个、推送 2 个、`INDEXER_ALLOW_PLAIN_HTTP`、`ADMIN_API_ACTOR`。

amos 上这 26 个里 **18 个填的就是默认值**。剩下 8 个是真调过的（连接池 3/1/600/60、读写超时 15、`ARTIFACT_UPLOAD_MODE=proxy`），原因都写在注释里，应该留——但应该只留这 8 个。

### 2.5 放错地方的（约 15 个）——本质是租户数据或平台数据

- **`ANDROID_STORE_URL` / `ANDROID_DIRECT_URL` / `IOS_STORE_URL` / `IOS_MDM_URL`**：下载链接是**按租户**的，而这是四个租户共用的全局值——一个值不可能同时对四个租户都对。代码里它只是 `actionURL()` 的兜底，`server.go:1624` 一旦有可见发布就用按租户生成的 `/v1/public/releases/{id}/download` 覆盖掉它。amos 上四个全空。**删。**
- **`OTA_CHANNEL`**：只在 `updatePolicy.otaChannel` 缺失时兜底，而 `initialConfig` 模板里这个键有值 `production`。永远不会被读到的默认值的默认值。**删，代码里写死兜底。**
- **`CORS_ORIGINS`**：`b53a08a` 之后来源已从 `tenant_domain` 表推导（`originAllowed` 先看 env 再问表），env 只剩"额外放行"。但 `config.go` 的生产校验仍**强制它显式列出**——这条要求在推导落地那天就过时了。**改成可选。**
- **`DEVICE_IDENTITY_HMAC_KEY`**：可选、空时回落到主密钥、两份示例和 amos 上全是空的。代码保留能力，示例里删。
- **`ADMIN_API_ACTOR`**：审计标签，默认值就是它。示例里删。
- **`PLATFORM_ADMIN_USERNAMES`**：授权名单放 env 有争议，但它是"谁能进平台页"的引导，只有一个管理员账号的现状下留 env 合理。**留。**
- **`FCM_PROJECT_ID` / `FCM_SERVICE_ACCOUNT_JSON`**（及休眠的 8 个 APNs/HMS 键）：第 5 节。

## 3. 三份清单已经漂开了

- 生产示例写着"**不要放 `BUILD_AGENT_TOKEN`**，打包机连的是 web4"——打包机 2026-09-12 已搬到 amos，amos 上这个键是填了的。注释在指导人做错事。
- 生产示例有 `INDEXER_MYSQL_CONNECTION_LIMIT=4`，amos 上也填了，**代码从来没读过这个键**。
- 开发示例缺 8 个键，含 `BIND_ADDRESS`、`TRUSTED_PROXIES`、`ADMIN_API_ALLOWED_IPS` 三个安全相关的：本地照着它配，到生产才第一次见到这些概念。
- 生产示例缺 9 个键（APNs 5、HMS 3、`BUILD_AGENT_TOKEN`）。
- amos README 里"推送派发默认留给 web4"——web4 已按 ADR-0015 退役。
- 两个 systemd unit 共用一份 env，indexer 进程加载了全部管理端、推送、产物配置。无害，但让"这台机器到底配了什么"更难回答。

## 4. 报错质量

`config.go` 的校验只有 4 句话，二十几个键共用一句 `invalid MySQL numeric configuration`。`integer()` 解析失败**静默变成 -1**再被那句拦住——任何笔误得到的都是同一句话。

没有任何办法在不 ssh + grep 的情况下回答"服务端现在生效的配置是什么"。这次分析花在这上面的时间比花在设计上的多。

## 5. 设计 A：推送凭据按租户进库

### 5.1 为什么必须做，而不只是"更整洁"

`push.New(ctx, db, cfg)` 在启动时用**一份全局** `FCM_SERVICE_ACCOUNT_JSON` 建一个 OAuth 客户端，所有租户的消息都从 `fcm.googleapis.com/v1/projects/{FCM_PROJECT_ID}/messages:send` 发出去。而 `google-services.json` 自 2026-09-13 起是**按租户**存的（`build.android`）。

FCM 的设备注册 token 绑定它被签发时的 Firebase 项目。用项目 X 的服务账号去发一个属于项目 A 的 token，v1 接口回 `403 SENDER_ID_MISMATCH`。今天的 `sendFCM` 把它当成普通非 2xx 走 `retry`：1、4、9、16 分钟后第五次改 `failed`，`last_error` 是一句 `FCM status 403`。**没有任何配置校验会拦，也没有任何界面会说"这个租户的推送发不出去是因为项目不匹配"。**

**现状已核实（2026-09-13，在 amos 上用一次性只读工具查生产库，未打印任何机密）：** 库里四个租户（AnyFun、Predict、any123、tokenup.pro）全部启用；其中两个（AnyFun、Predict）上传了 `google-services.json`，**都属于 Firebase 项目 `anyfun`**（project_number 393818650719），与 env 里服务账号 `firebase-adminsdk-fbsvc@anyfun.iam.gserviceaccount.com` 的 `project_id` 相同；Predict 那份文件在同一个项目下注册了两个 Android 包（`com.anyfun.foundation`、`com.predict.kim`）。另两个租户还没有任何打包配置。`app_push_tokens` 里只有 AnyFun 的 1 个 FCM token，且已作废；`app_push_outbox` 里没有任何 `failed`，也没有 `FCM status 403` 的痕迹。

所以今天推送**没有坏**——但成立的方式是"所有租户共用一个 Firebase 项目，而且恰好和服务端那把钥匙是同一个"。这不是设计出来的，是巧合：Predict 的包被加进了 AnyFun 的 Firebase 项目里，而不是 Predict 自己的。下一个租户拿着自己的 Firebase 项目上传 `google-services.json` 那天，打包成功、安装成功、token 注册成功，只有推送发不出去，`last_error` 是一句 `FCM status 403`。结论不变：凭据必须和它服务的租户放在一起，并且和那个租户的 `google-services.json` 对得上。核实的另一个收获是 `import-env` 之后的第一眼一定是全绿——四个租户全部继承平台行，两份 `google-services.json` 的 `projectMatches` 都为 true。

### 5.2 存储

复用 `app_configs`，不建表。一个 provider 一个 key：`push.fcm`、`push.apns`、`push.hms`。分开存是为了轮换互不影响、审计一目了然，也因为三家的字段形状完全不同。

`push.fcm` 的 `config_value`：

```json
{
  "projectId": "anyfun-prod",
  "clientEmail": "firebase-adminsdk-xxx@anyfun-prod.iam.gserviceaccount.com",
  "privateKeyId": "3f9a…",
  "serviceAccountEncrypted": "<base64，STORAGE_MASTER_KEY + AES-GCM>",
  "verifiedAt": "2026-09-13T04:12:00Z"
}
```

- 明文只放**给人看的**三项：项目、账号、key id。它们本来就在 Firebase 控制台上公开显示，不是机密。
- 整份服务账号 JSON 加密存，AAD 为 `<tenant>:push.fcm:serviceAccount`，与 `storageAssociatedData` 同一套写法——AAD 里带租户 id，一个租户的密文搬到另一个租户下解不开。
- **服务端解得开它。** 这一点要说清楚：签 JWT 换令牌必须用私钥明文，所以它和 `ota.signing` 是同一类（服务端运行时要用，服务端能开），**不是** `build.keystore` 那一类（服务端运行时不用，服务端不能开）。ADR-0011 当时不让进库的理由是"不写入数据库、日志或客户端包"三个并列，其中"日志、客户端包"仍然成立并由本设计保证；"数据库"这一项被本设计推翻，理由是多租户下 env 里放不下 N 份，而放不下的代价是推送静默失效。这要写成 ADR-0017 supersede 0011 的那一段，不是悄悄违反。

### 5.3 平台级回落：让迁移零行为变化

读取用与 `release.storage` 相同的语句：`WHERE config_key='push.fcm' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`——**租户自己的行优先，没有就用平台（tenant 0）那一行**。

这给了一条不改变任何行为的迁移路径：把今天 env 里那份凭据导入到 tenant 0，四个租户全部继承，发出去的请求和今天逐字节相同；之后哪个租户有自己的 Firebase 项目，就在自己名下存一份覆盖掉。

回落必须**在界面上显眼**：视图带 `inherited: true`，控制台写"继承自平台默认，项目 X"。第 5.5 节的项目匹配检查作用在**生效的那一行**上，不管它来自租户还是平台——继承来的项目对不上自己的 `google-services.json`，同样报红。

### 5.4 派发器：按租户建客户端，按版本失效

`push.New(ctx, db, cfg, secrets *secretbox.Box)`——多传主密钥的盒子（`api.New` 里已经建了一个，`main.go` 里同一个传两处）。

```go
type tenantSender struct {
    version   int            // app_configs.version，生效那一行的
    projectID string
    client    *http.Client   // oauth2.Transport，TokenSource 自己缓存并刷新访问令牌
}
senders map[string]*tenantSender   // key = 生效行的 tenant_id（租户自己的或 "0"）
```

每处理一条 outbox 事件，先做一次 `SELECT tenant_id, version` 拿到生效行的身份和版本；命中缓存且版本相同就直接用，否则解密、`google.CredentialsFromJSON`、重建客户端。一次索引查询换来的是：**换密钥不用重启进程**（今天 `rotate-fcm-key.sh` 改完 env 必须重启），多实例部署下各实例最迟在下一条事件时看到新密钥，不需要广播。

缓存键是**生效行**的 tenant_id 而不是事件的 tenant_id：四个租户都继承平台那一行时只有一个客户端、一个令牌源，而不是四份相同的。

`sendFCM` 的错误分类补三条，这是今天缺的：

| 响应 | 今天 | 设计 |
|---|---|---|
| 404 / `UNREGISTERED` | token 作废 | 不变 |
| `403 SENDER_ID_MISMATCH` | 当普通失败重试 5 次 | **凭据错误**：整条事件立即 `failed`，`last_error=FCM_PROJECT_MISMATCH: token 属于别的 Firebase 项目`；**绝不**把 token 标作废——token 是好的，错的是凭据 |
| `401` / `403` 其它（密钥被吊销、权限被收） | 当普通失败重试 5 次 | **凭据错误**：同上，`last_error=FCM_CREDENTIAL_REJECTED` |
| 凭据行不存在 | 每个收件人一句 `FCM is not configured`，全失败后重试 5 次 | 事件立即 `failed`，`last_error=FCM_NOT_CONFIGURED` |

"凭据错误立即 failed 而不重试"的理由：重试解决的是瞬时故障，凭据错误在有人改配置之前不会自愈，把 30 分钟的退避花在它上面只是延迟发现。事件表里那一行 `failed` 加一句能看懂的 `last_error`，比五次 `FCM status 403` 有用。

APNs 与 HMS 本次**不**改成按租户，但结构要为它预留：`apns2.Client` 是按密钥建的、`hmsAccessToken` 的缓存是 `Dispatcher` 上**一个**全局字段（`d.hmsToken`）。谁把它们改成按租户，必须同时把这两处改成 `map[tenant]`，否则两个租户会互相拿到对方的令牌。写在这里是因为这是最容易被漏的那种边界。

### 5.5 与 `google-services.json` 的接缝：同一件事的两半

这是本设计里最重要的关联性调整。`google-services.json`（编进 APK，App 端半边）和服务账号（留在服务端，服务端半边）**必须属于同一个 Firebase 项目**——`project_info.project_id` 与服务账号里的 `project_id` 相等。对不上时构建成功、安装成功、token 注册成功，只有推送发不出去。

和包名一致性那次一样，三处校验：

1. **保存服务账号时**：如果该租户 `build.android` 里已有 `google-services.json`，比 `project_id`，不等回 `422 FCM_PROJECT_MISMATCH`，两个 id 都写进 detail。
2. **保存 `google-services.json` 时**（`build_config.go`，今天只解析 `client[].package_name`，要补 `project_info.project_id` 的解析）：如果该租户已有**生效的** `push.fcm`（自己的或继承的），比 `project_id`，不等回 `422 GOOGLE_SERVICES_PROJECT_MISMATCH`。继承来的对不上，detail 要说清"服务端凭据是平台默认的项目 X，这份文件是项目 Y；要么给本租户单独配一份凭据，要么换文件"。
3. **派发时**：`SENDER_ID_MISMATCH` 的分类见 5.4。它是最后一道，前两道漏过去的（例如两边都还没配、后来先配了一边）由它兜住并说清楚。

还有一条相反方向的形状校验，和现有那条对称：`build_config.go` 拒绝把服务账号（有 `private_key`）当 `google-services.json` 上传；这里要拒绝把 `google-services.json`（有 `project_info`、没有 `private_key`）当服务账号上传，并把人指回另一个入口。

### 5.6 保存即验证：把 `rotate-fcm-key.sh` 搬进服务端

`rotate-fcm-key.sh` 存在的理由是一段值得保留的洞察：`google.CredentialsFromJSON` **只在本地解析 JSON，不联网**。密钥被吊销了服务照样能起来，日志一行错都没有，直到第一次真发推送才炸。所以脚本在换密钥前后各做一次**真实的 OAuth 令牌交换**，那才是"这把密钥现在有效"的证据。

这段逻辑用 Go 重写（RS256 签 JWT，`aud=https://oauth2.googleapis.com/token`，`scope=firebase.messaging`，POST 换 access_token，15 秒超时），放在 `PUT` 的路径上：**换不到令牌就不保存**，回 `424 FCM_CREDENTIAL_REJECTED` 并带上 Google 的错误码。另有 `POST /push/credentials/fcm/test` 随时重验并刷新 `verifiedAt`，与 `release-storage/test` 同一个模式。

代价：保存这个配置依赖 amos 到 Google 的出网。它本来就依赖——派发器每条消息都要出去。不提供"跳过验证"的开关：那个开关存在的第一天就会有人在 Google 抽风时用它存进一把坏钥匙，然后忘了回来。

JWT 的 `iat` 往回退 60 秒：服务端和 Google 的时钟差超过几十秒时 `invalid_grant`，报错看不出是时钟问题。

### 5.7 管理接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/admin/push/credentials` | 三个 provider 各一段：`configured`、`inherited`、`projectId`、`clientEmail`、`privateKeyIdHint`（前 8 位）、`verifiedAt`、`version`；FCM 一段额外带 `googleServicesProjectId` 与 `projectMatches`，控制台不用自己再去比 |
| PUT | `/v1/admin/push/credentials/fcm` | `{serviceAccountJson, expectedVersion, reason, confirm}`，用 `decodeLimited` 上限 64 KiB（服务账号约 2.3 KB）；校验形状 → 比项目 → 换令牌 → 加密落库，同一事务写审计 |
| DELETE | `/v1/admin/push/credentials/fcm` | 删租户自己的行，回落到平台；响应里说明回落之后生效的是哪个项目 |
| POST | `/v1/admin/push/credentials/fcm/test` | 用生效凭据换一次令牌 |
| PUT/DELETE | `/v1/admin/platform/push/credentials/fcm` | 平台默认（tenant 0），仅 `PLATFORM_ADMIN_USERNAMES`，与 chain-scan 管理接口同一道门；DELETE 前回**正在继承它的租户数**，控制台确认框列出来——删掉平台那一行等于同时关掉所有继承者的推送 |

私钥**不经任何接口返回**。审计动作 `push_credentials_update` / `push_credentials_delete` / `push_credentials_test`，摘要记 `projectId`、`clientEmail`、`privateKeyId` 前 8 位、`verified`。

### 5.8 控制台落点

放在「Android 打包与签名」页 `google-services.json` 那一节的**紧下方**，标题写成"推送：服务端半边"。理由就是 5.5——它们是同一个 Firebase 项目的两半，一半编进 APK、一半留服务端，摆在一起，`projectMatches` 那个红绿标记才有地方站。放到别的页，跨页约束又没人校验了，这正是合并那两页时吃过的亏。

页面上：项目、账号、key id 前 8 位、`verifiedAt`、`inherited` 标记、与上方 `google-services.json` 的项目匹配状态；上传服务账号 JSON 的入口（选中文件那一秒就做形状校验和项目比对，和 google-services 那边对称）；「重新验证」按钮。APNs/HMS 不在这一页——它们属于将来的 iOS 页。

### 5.9 迁移与下线

1. `rn-server push-credentials import-env`：读 env 里的 `FCM_PROJECT_ID` / `FCM_SERVICE_ACCOUNT_JSON`（沿用 `decodeSecret` 接受 base64 或 `\n` 转义的两种形态），换一次令牌验证，写入 tenant 0，打印项目与账号。**tenant 0 已有行时拒绝**，不静默覆盖。在 amos 上跑一次。
2. 过渡一个版本：`push.New` 找不到任何 `push.fcm` 行、而 env 里有 `FCM_*` 时，用 env 并在日志里每次启动打一条 WARN"推送凭据仍在 env，运行 import-env"。下一版删掉 env 读取。
3. `rotate-fcm-key.sh` 删除，其功能由 PUT 的验证和 `/test` 接口承担。
4. ADR-0017：按租户的推送凭据；supersede ADR-0011「安全」一节里"不写入数据库"这一句，保留"不写入日志或客户端包"。
5. `deploy/amos/README.md` 删掉"派发留给 web4"和 FCM 两行；`deploy/web4/README.md` 已随 ADR-0015 退役，不再维护。

## 6. 设计 B：MySQL 十一个键合成一个 DSN

### 6.1 合什么、留什么

```ini
# 合成一行（原 11 个键）
MYSQL_DSN=app:口令@tcp(db.internal:13306)/rn_foundation?parseTime=true&loc=UTC&charset=utf8mb4&timeout=15s&readTimeout=15s&writeTimeout=15s
```

合进去的 11 个：`HOST` `PORT` `USER` `PASSWORD` `DATABASE` `CHARSET` `TIMEZONE` `PARSE_TIME` `CONNECT_TIMEOUT` `READ_TIMEOUT` `WRITE_TIMEOUT`——它们全都是 go-sql-driver DSN 的标准组成，合并不需要自己发明语法。

**不**合进去的 9 个，因为它们不是 DSN 的事：连接池 4 个（`CONNECTION_LIMIT` `MAX_IDLE` `MAX_LIFETIME` `MAX_IDLE_TIME`，`database/sql` 的池设置，驱动不认）、我们自己的 3 个启动重试（`INIT_*`）、`QUERY_TIMEOUT`、`AUTO_MIGRATE`。它们都有默认值，按第 7 节的原则不写就不出现。

### 6.2 服务端要替 DSN 补的默认——这是审查发现的主要风险

驱动 `NewConfig()` 的默认值和我们今天的默认值**不一样**。运维照着 MySQL 文档随手写一个 `user:pass@tcp(host)/db`，会拿到：

| 参数 | 驱动默认 | 今天的默认 | 漏掉的后果 |
|---|---|---|---|
| `parseTime` | **false** | true | 所有 `DATETIME` 列扫进 `time.Time` **全部失败**，每个读时间的接口 500，没有一处启动校验会拦 |
| `timeout` / `readTimeout` / `writeTimeout` | **0（无限）** | 15s / 30s / 30s | 数据库挂起时 handler 永远等，连接池被占满，健康检查跟着死 |
| `charset` | 不发（用服务端默认） | utf8mb4 | 服务端默认恰好是 utf8mb4 时无事；不是时中文变问号 |
| `loc` | UTC | UTC（`Z` 别名） | 一致；但 `loc=Z` 是**非法的**（驱动用 `time.LoadLocation`），今天写 `MYSQL_TIMEZONE=Z` 的地方要改成 `UTC` |
| `AllowNativePasswords` | true | true | 一致 |

所以 `config.Load` 解析 DSN 之后要**补四项**：`parseTime` 没写就置 true，三个 timeout 没写就置今天的默认。补了什么在 `rn-server config` 的输出里逐项标出 `(defaulted)`，让人看得见。**不允许显式写 `parseTime=false`**——直接拒绝启动并解释为什么。

### 6.3 解析、校验、错误信息

`config.Load` 里 `mysql.ParseDSN(os.Getenv("MYSQL_DSN"))`，`Config` 结构里 11 个字段换成一个 `MySQL *mysql.Config`。解析失败的报错点名：`MYSQL_DSN: invalid DSN: did you forget to escape a param value?`——驱动的错误信息本来就比我们那句"invalid MySQL numeric configuration"好。

补充校验：`Addr` 非空（漏写 `tcp(...)` 时驱动会默默连 `127.0.0.1:3306`，在生产这不是想要的默认）、`DBName` 非空、`Net` 只允许 `tcp`。

`APP_ENV=test` 给库名加 `_test` 后缀的规则保留：解析后改 `cfg.MySQL.DBName`，`FormatDSN` 会重新拼。

**口令里的特殊字符**（已按驱动源码核实）：`ParseDSN` 取整串里**最后一个** `/` 作为库名分隔，再在其左侧取**最后一个** `@` 作为凭据分隔，口令是第一个 `:` 到那个 `@` 之间的全部内容。所以口令里含 `@`、`/`、`:`、`(`、`)` 都不会断；**唯一的约束是用户名不能含 `:`**。`?` 之后的参数值要 URL 转义，但那部分是我们自己写的固定内容。systemd 的 `EnvironmentFile` 不做 `$` 展开，`merge-env.sh` 用 python 整行替换、不经 shell——DSN 值里的 `&`、`$` 在这条部署链路上都安全；只有 `README.md` 里本地开发那句 `set -a && source .env` 需要给值加单引号，文档里点一句。

### 6.4 分两步上线，避免出现"部署红了"的窗口

CI 在 push 到 main 时自动部署服务端，而 env 是人用 `merge-env.sh` 手工改的——两者没有先后保证。如果代码先到、只认 `MYSQL_DSN`，`rn-foundation-migrate` 会因为连不上库失败，`rn-foundation-apply` 回滚（这是对的），但那次部署是红的，而且直到有人改 env 之前每次部署都红。

1. **第一版**：同时接受 `MYSQL_DSN` 与旧的 11 个键，`MYSQL_DSN` 优先；只有旧键时用它们拼出 `mysql.Config`，并在启动日志打一条 WARN"MYSQL_* 已弃用，等价的 MYSQL_DSN 是 `<口令打码>`"。运维照着日志把一行加进 env，再用 `merge-env.sh` 删掉 11 行。`rn-server config` 在这个版本里就能用。
2. **第二版**：删掉 11 个旧键的读取。此时 amos 上已经只有 `MYSQL_DSN`。

`rn-foundation-migrate.service` 与两个 unit 共用同一份 `EnvironmentFile`，用的是同一个 `config.Load`，切换后自然一致，不需要单独处理。

### 6.5 要跟着改的地方

- `internal/store/store.go`：`driverConfig` 不再拼字段，直接用 `cfg.MySQL`；`pingWithRetry`、池设置不变。
- `internal/config/config_test.go` 的 `TestLoadUsesConfigurableMySQLOptions`、`internal/store/store_test.go` 的 `TestDriverConfigUsesConfiguredConnectionOptions` 改为围绕 DSN 断言，并**新增**"漏写 parseTime / timeout 时被补上"和"`parseTime=false` 被拒绝"两条。
- `internal/api/db_integration_test.go` 的 `openTestDB` 目前用 `RN_TEST_MYSQL_HOST` 等五个变量拼 `Config`，改为接受 `RN_TEST_MYSQL_DSN`（保留五个旧变量的拼装以免 CI 立刻要改）。
- 示例文件、`deploy/amos/install.sh:74`、`deploy/amos/README.md:103` 里"数据库四项照抄 web4"改成"`MYSQL_DSN` 一行"；`README.md` 本地开发说明加单引号提示。

## 7. 目标形态与实施顺序

原则一句话：**.env 只放"别处不可能知道"的东西**——机密与拓扑。有默认值的不写，能从库里推导的不填，按租户变化的进租户配置。

### 7.1 amos 的目标 env

```ini
# ---- 机密 ----
STORAGE_MASTER_KEY=
MYSQL_DSN=user:口令@tcp(host:13306)/db?parseTime=true&loc=UTC&charset=utf8mb4&timeout=15s&readTimeout=15s&writeTimeout=15s
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

# ---- 与默认不同的调优，每一条都要有理由 ----
MYSQL_CONNECTION_LIMIT=3            # 和别的进程共用一个库，加起来别超过库的上限
MYSQL_MAX_IDLE_CONNECTIONS=1
MYSQL_CONNECTION_MAX_LIFETIME_SECONDS=600
MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS=60
ARTIFACT_UPLOAD_MODE=proxy          # 桶没有跨域规则且我们改不了，见 deploy/amos/README.md
```

**61 行 → 18 行。** 推送凭据进库、11 个 MySQL 键合成 1 行、24 行默认值删掉、7 行空的或死的删掉。

### 7.2 顺序

前三步没有行为变化，可以立刻做；后两步各自独立。

1. **只动文件**：两份示例合并成一份按上面四段组织，开发差异用注释块；删 `INDEXER_MYSQL_CONNECTION_LIMIT`；改错掉的注释；附一张"全部可用键 / 默认值 / 何时需要改"的参考表。amos 上用 `merge-env.sh` 删掉与默认相同的 24 行（删行不改值）。
2. **小的代码改动，每条独立可回滚**：`rn-server config` 子命令（机密打 `<set, N chars>`，每键标 env / default / defaulted）；校验逐键报错、`integer()` 解析失败直接报错而不是 -1；删四个下载链接键、`OTA_CHANNEL`、`ARTIFACT_DOWNLOAD_TTL_SECONDS`、`ADMIN_API_ACTOR` 的读取（删 `OTA_CHANNEL` 前先查一遍没有租户的 `updatePolicy` 缺 `otaChannel`）；`CORS_ORIGINS` 生产改可选（`TestProductionRequiresLoginAndExplicitOrigin` 要跟着改）；`INDEXER_ENABLED` 在 `indexer` 子命令下默认 true。
3. **DSN 第一版**（6.4 第 1 步）——随第 2 步一起发也可以，它是纯增量。
4. **推送凭据进库**（第 5 节全部）+ ADR-0017 + `import-env` 在 amos 上跑一次 + 从 env 删两行。
5. **DSN 第二版**：确认 amos env 已只剩 `MYSQL_DSN` 后删旧键读取。

每一步都**不带 `-A` 提交**——这份收缩会和另一个会话的改动落在同一个工作区里。

## 8. 对抗性审查

审查方式：对第 5、6 节逐条问"怎么让它坏掉""坏了谁看得见""和哪个现有功能撞"。8.1 与 8.2 是问题和设计的回答，8.3 是审查**改掉了初稿哪里**——没改动过设计的审查等于没做。

### 8.1 设计 A：推送凭据

| 攻击 / 疑问 | 设计的回答 |
|---|---|
| 租户 A 上传了项目 X 的服务账号，`google-services.json` 是项目 Y | PUT 时 `422 FCM_PROJECT_MISMATCH`，两个 id 都在 detail 里（5.5-1） |
| 反过来：先配了凭据，后传一份别的项目的 `google-services.json` | `build_config.go` PUT 时 `422 GOOGLE_SERVICES_PROJECT_MISMATCH`（5.5-2）。这要求 `build_config.go` 新解析 `project_info.project_id`，今天它只解析 `client[].package_name` |
| 两边都还没配，先配一边，永远不配另一边 | 各自能保存（无可比对象）；派发时 `FCM_NOT_CONFIGURED` 立即 `failed` 并写明；控制台 GET 里 `projectMatches` 为 null 且 `configured=false`，两处都看得见 |
| 密钥在 Google 控制台被吊销，服务端浑然不知 | 保存时的令牌交换只能证明**当时**有效。派发时 `401/403` 归为凭据错误立即 `failed`，`last_error=FCM_CREDENTIAL_REJECTED`；`/test` 接口随时可重验。这比今天好——今天要等五次重试、然后是一句 `FCM status 403` |
| `SENDER_ID_MISMATCH` 被当成 token 作废，把好 token 标 `invalid_at` | 5.4 明确：403 类**绝不**动 token。这是初稿没写、审查加上的（8.3-①） |
| 平台那一行被删，四个继承它的租户同时失去推送 | 平台 DELETE 前服务端回继承者数量，控制台确认框列出来（5.7）。初稿没有这一条（8.3-②） |
| 多实例部署，一台换了密钥另一台还在用旧的 | 缓存以生效行的 `version` 为键，每条事件前查一次；旧实例最迟下一条事件切到新密钥。不需要广播、不需要重启 |
| 四个租户继承同一平台行，建四份客户端、拿四份令牌 | 缓存键是**生效行**的 tenant_id（"0"），四个租户共用一个客户端（5.4）。初稿按事件 tenant_id 缓存，审查改的（8.3-③） |
| 服务账号 JSON 和 `google-services.json` 拿混了 | 形状校验对称：`build_config.go` 已拒绝含 `private_key` 的；这边拒绝含 `project_info` 不含 `private_key` 的，并指回另一个入口（5.5 末） |
| 请求体上限 | `decodeLimited` 64 KiB，超限 413——图标那次的教训直接复用 |
| 私钥出现在日志或审计里 | 审计只记 `projectId`、`clientEmail`、`privateKeyId` 前 8 位；令牌交换的 assertion 不进任何日志；FCM 错误体最多 16 KB 已被 `LimitReader` 截断且本身不含机密 |
| `import-env` 在 tenant 0 已有行时跑第二次 | 拒绝，不覆盖（5.9-1） |
| 过渡期 env 与库同时有凭据，谁赢 | 库赢；env 只在库里一行都没有时用，且每次启动 WARN（5.9-2）。下一版删 env 读取，过渡态不会永久化 |
| 服务端时钟偏差导致换令牌 `invalid_grant` | `iat` 回退 60 秒（5.6）；报错里带 Google 原文，`invalid_grant` 加一句"检查服务器时钟" |
| Google 不可达时无法保存配置 | 接受这个代价，不给跳过开关（5.6）。派发本来就依赖同一条出网 |
| APNs / HMS 被人顺手改成按租户 | 5.4 末尾点名两个全局缓存字段必须同时改成 `map[tenant]`；`sendAPNs` 的 `topic` 兜底 `cfg.APNsBundleID` 应换成该租户 `release.ios` 的 `bundleId`。不在本次范围，但边界写下了 |
| 与 ADR-0011 冲突 | 不悄悄违反：ADR-0017 显式 supersede 其中"不写入数据库"一句，保留另外两句（5.2、5.9-4） |
| 谁能改平台默认 | 与 chain-scan 平台接口同一道门（`PLATFORM_ADMIN_USERNAMES`）；租户接口只能改自己的行 |

### 8.2 设计 B：DSN

| 攻击 / 疑问 | 设计的回答 |
|---|---|
| 运维写 `user:pass@tcp(host)/db`，漏 `parseTime` | 服务端补 true 并在 `rn-server config` 标 `(defaulted)`（6.2）。**初稿漏了这条**——没有它，所有读时间的接口会在部署后 500，而启动是绿的（8.3-④） |
| 漏三个 timeout | 同上补默认。驱动默认 0 = 永不超时（8.3-④） |
| 显式写 `parseTime=false` | 拒绝启动，说明整套代码假设 `time.Time` 扫描（6.2） |
| 照抄今天的 `MYSQL_TIMEZONE=Z` 写成 `loc=Z` | `time.LoadLocation("Z")` 失败，`ParseDSN` 报错点名 `loc`；文档写明改 `UTC`（6.2） |
| 口令含 `@` `/` `:` `&` `$` | 按驱动源码：口令段是第一个 `:` 到最后一个 `@`，含这些都不断；`&` `$` 在 systemd `EnvironmentFile` 和 `merge-env.sh` 两条链路上都不展开（6.3）。**用户名含 `:` 会断**，写进文档 |
| 漏写 `tcp(...)` | 驱动默默连 `127.0.0.1:3306`。补校验 `Addr` 非空（6.3）。初稿没有（8.3-⑤） |
| `AllowNativePasswords` 丢了 | 驱动默认就是 true，与今天一致，不需要补 |
| 代码先于 env 到达生产 | 6.4 两步走：第一版双读、日志里给出等价 DSN；第二版才删旧键。`rn-foundation-apply` 的回滚是最后一道 |
| `migrate.service` 用同一份 env | 同一个 `config.Load`，切换后自然一致 |
| `APP_ENV=test` 的 `_test` 后缀 | 解析后改 `DBName` 再 `FormatDSN`（6.3） |
| `rn-server config` 打印 DSN 泄露口令 | 从解析后的 `mysql.Config` 复制一份、`Passwd` 置 `***` 再 `FormatDSN`，**不用正则**在字符串上打码——口令里可能含 `@`，正则会打错位置（8.3-⑥） |
| 集成测试 `openTestDB` 用五个 `RN_TEST_MYSQL_*` 拼 `Config` | 改为优先 `RN_TEST_MYSQL_DSN`，保留五个旧变量的拼装（6.5）；CI 不需要同步改 |

### 8.3 审查改掉了初稿的六处

1. **403 类错误绝不作废 token。** 初稿只写了"归为凭据错误"，没写"不动 token"。`SENDER_ID_MISMATCH` 下 token 是好的，作废它等于让那台设备永久收不到推送——比发不出去更坏，因为下次注册才会恢复。
2. **平台行删除前回继承者数量。** 初稿的 DELETE 和租户行一样对待。删平台默认是"关掉所有没单独配的租户的推送"，确认框必须把这层意思说出来。
3. **按租户缓存改为按生效行缓存。** 初稿 `map[eventTenantID]`，四个继承者会建四个相同客户端、向 Google 换四份令牌。
4. **DSN 缺参补默认。** 初稿把 DSN 当成"用户说什么就是什么"，驱动的 `parseTime=false`、`timeout=0` 默认会在启动绿灯之后让整个服务坏掉。这是本次审查最重要的发现。
5. **`Addr` 非空校验。** 初稿只依赖 `ParseDSN` 的报错，而漏写地址不是错误，是默默连本机。
6. **配置打印时口令打码走结构体，不走正则。** 初稿写的是"正则替换 `:xxx@`"，口令含 `@` 时会把口令的一部分打印出来。

### 8.4 审查初稿留下的两件事，已闭合

初稿写这一节时两件事没有验证：各租户的 Firebase 项目是否相同，以及 outbox 里是否已有项目不匹配的失败。2026-09-13 在 amos 上查过生产库（结果见 5.1）：

- **相同。** 两个上传了 `google-services.json` 的租户都是项目 `anyfun`，与服务端凭据一致；另两个租户还没有打包配置。`import-env` 之后 GET 会看到两个 `projectMatches: true`、两个 `configured: false`（继承平台、但还没有 App 半边）。
- **没有历史失败。** outbox 里 78 条 `sent`、13 条 `cancelled`（2026-09-01 派发器未运行期间的），0 条 `failed`。第 5 节的错误分类改动没有需要回放的存量。

顺带看到的一件事，与本设计无关但值得记：`app_push_tokens` 里只有 1 个 token 且已作废，也就是说今天线上**没有任何一台设备能收到推送**。第 5 节上线后第一条真实推送才是它的第一次端到端验证——上线时要有人拿一台注册了 token 的设备在旁边。

## 9. 不做什么

- 不引入配置文件格式（YAML/TOML）。systemd `EnvironmentFile`、`merge-env.sh`、CI 的 `rn-foundation-apply` 全部围着 KEY=VALUE 建，换格式是为了"看起来整洁"付迁移成本。
- 不把调优参数搬进库。调优是"这台机器"的属性；而且数据库连不上的时候得靠它们连数据库。
- 不给 indexer 单独一份 env。两个进程读同一份文件多加载几个键无害，分两份就多一处会漂的东西。
- 不在本次把 APNs / HMS 改成按租户。没有租户在用；但 5.4 末尾的两个边界已经写下，谁做谁看。

## 10. 实施记录（2026-09-13）

设计的第 5、6 节和第 7.2 的前三步已经实现（`38f8475` 配置与 DSN、`f3e614e` 推送凭据、RN-Admin `f5e7486` 控制台）。下面记录**实现与设计不一致的六处**——每一处都是写代码时发现设计想错了或想漏了，留在这里是因为下次读设计的人会先读到设计。

1. **验证不再自己签 JWT（改掉 §5.6 的 iat 回退）。** 设计说手写 RS256 assertion 并把 `iat` 回退 60 秒防时钟偏差。实现改用 `google.CredentialsFromJSON` + `TokenSource.Token()`——它就是**真正发送时走的那条路**，而"验证通过"如果和发送走不同的路，它证明的就不是发送能成功。代价是 `iat` 不可控；时钟偏差改为在报错里点名（`invalid_grant` 追加一句"检查服务器时钟"）。这个交换值得：路径一致是强性质，时钟提示是弱补偿。

2. **DSN 要补的是五项不是四项（§6.2）。** 设计漏了 `charset`。驱动默认**不发** charset（用服务端默认），而我们今天总是发 `utf8mb4`；不补就不是"等价迁移"，是在库的服务端默认不是 utf8mb4 时让中文变问号。显式写了 `collation` 的不补——那种人知道自己在做什么，再塞一个 charset 会多发一条 `SET NAMES` 并可能打架。

3. **补默认值的做法是"接回 DSN 再解析一遍"，不是改解析结果。** 写的时候才发现 `charset` 根本不落在 `mysql.Config.Params` 里，它在驱动的私有字段 `charsets` 上——从外面写 `Params["charset"]` 会变成另一个同名参数。同理，旧的十一个键现在先拼成一条**等价 DSN**再走同一条解析路径，而不是各拼一份 `mysql.Config`：只有驱动自己知道每个参数的语义，自己拼第二份迟早和它对不上。附带好处是启动时那条弃用警告可以直接把等价 DSN 打出来，运维照抄一行就完成迁移。

4. **`Addr` 非空校验只能从原串上做（§8.3-⑤ 的修正的修正）。** `ParseDSN` 在漏写 `tcp(...)` 时**不报错也不留空**——它把 `Addr` 补成 `127.0.0.1:3306`。所以校验解析结果永远发现不了，只能按驱动自己的拆法（最后一个 `/` 之前、最后一个 `@` 之后）看原串里到底写没写。

5. **`ADMIN_API_ACTOR` 的读取保留了（推翻 §7.2 第 2 步的一项）。** §2.5 说"示例里删"是对的，§7.2 顺手写成了"删读取"。`TestLoadAdminSecurityDefaults` 里明确记着它是安全评审 N17 的门禁项：`x-admin-key` 通道写进审计的身份由配置绑定，请求自报的 `x-admin-id` 一律忽略。删掉读取等于把那个门禁的一半拆了。只从示例文件里删。

6. **服务端多了一个 `verifyFCM` 注入点。** 保存凭据这条路**必须**联网（那正是设计的重点），而测试不该联网。做成 `server` 上的一个字段，默认是 `pushcreds.Verify`。

### 还没做的

- **第 4 步的后半段**：`push-credentials import-env` 还没在 amos 上跑，env 里的 `FCM_*` 也还没删。要在部署之后做。
- ~~**第 5 步（DSN 第二版）**~~：已完成，见 §12。
- **amos env 的实际收缩**：新二进制部署之前不能动 env（旧二进制不认 `MYSQL_DSN`）。顺序是：部署 → `rn-server config` 核对 → 写 `MYSQL_DSN` → 删十一行和二十多行默认值 → `import-env` → 删 `FCM_*` → 重启。

## 11. 上线记录（2026-09-13 07:42–07:44 UTC）

CI 部署 → `import-env` → 收缩 env → 重启，全程 2 分钟，没有中断。

**env：60 个键 → 18 个**（`deploy/amos/slim-env.py`，备份在 `/etc/rn-foundation.env.bak-20260913-074333`）。删掉的 43 个分四类：11 个合进 `MYSQL_DSN`、7 个代码从不读取或键已删除、20 个值就是默认值、2 个推送凭据（已进库）、3 个空的。

**等价性是在重启之前验的**，这一步不能省：用 systemd 自己的 `EnvironmentFile` 加载新文件跑 `rn-server config`，得到的连接串和旧的十一个键拼出来的**逐字节相同**——

```
root:***@tcp(…:13306)/rn?charset=utf8mb4&parseTime=true&readTimeout=15s&timeout=15s&writeTimeout=15s
```

**推送凭据**：`import-env` 向 Google 真换了一次令牌（通过，说明生产这把钥匙是活的），存为 tenant 0。重启后逐租户查 `GET /v1/admin/push/credentials`：

| 租户 | configured | inherited | 项目 | google-services | projectMatches |
|---|---|---|---|---|---|
| anyfun | true | true (0) | anyfun | anyfun | **true** |
| predict.kim | true | true (0) | anyfun | anyfun | **true** |
| any123 | true | true (0) | anyfun | 未上传 | **null** |

和 §8.4 预测的一致：两个配齐的租户全绿，第三个是"待配置"而不是红叉。

**删掉 `CORS_ORIGINS` 之前核对过 §2.5 那个推断**，没有照它写的做。三个 `console.*` 域名确实都在 `tenant_domain` 里（`api.*` 也在），所以删得掉；删完预检仍然逐个回正确的 `Access-Control-Allow-Origin`，而 `https://evil.example` 不放行。**换一台机器之前要重新核对**——这个结论属于这份数据，不属于这套代码。

**`INDEXER_ENABLED` 删掉之后扫链照常起**（`chain worker started chain=op-sepolia`），子命令默认值生效。

**两条弃用警告在重启后消失**，说明 `MYSQL_DSN` 和库里的凭据都走通了。

### 顺带发现，与本次改动无关

`any123.top` 的 TLS 一直是坏的：`/etc/nginx/ssl/rn-foundation-le` 那张证书（2026-09-12 签）的 SAN 只有 `api.predict.kim` 和 `console.predict.kim`，而 `setup-tls.sh` 的默认 `DOMAINS` 里是带 any123 两个名字的。nginx 配置第 4 行自己写着"本机现存的 `console.any123.top` ⋯⋯一直没生效"。该租户的 API 在本机带 Host 头是通的（上面那张表就是这么查的），坏的只是公网 TLS。要修就重跑一次 `setup-tls.sh`。


## 12. DSN 第二版（2026-09-13）

删掉 `legacyDSN()` 与它的调用点、启动时那条弃用警告、`rn-server config` 里的迁移提示。发这一版之前核对过还有谁依赖旧键：代码里只有 `legacyDSN()` 一处，CI 跑测试根本不设 `MYSQL_*`（集成测试用的是 `RN_TEST_MYSQL_*`，另一套前缀），仓库里还写着旧键的只剩 `deploy/web4/.env.example` 和两处文档——都已改成 DSN 写法。

**关键不是删，是删完之后旧键要给出指路的报错。** 静默忽略它们会落到开发默认连接（本机 3306 的 `rn_foundation`）上，报错只会说"连不上"，而真正的原因是这台机器的配置没迁移过——那是最难查的一类失败。所以：

| env 的状态 | 行为 |
|---|---|
| 有 `MYSQL_DSN` | 用它（旧键即便还在也只是无人读取的噪声） |
| 没有 DSN，但旧键还在 | **拒绝启动**，点名是哪几个键、该写成什么样 |
| 都没有，生产 | 拒绝启动：`MYSQL_DSN is required in production` |
| 都没有，开发 / 测试 | 用本地默认 `root@tcp(127.0.0.1:3306)/rn_foundation`，并同样补齐那五项参数 |

最后一行是有意保留的：`go test` 和裸跑 `rn-server` 不该先要一行配置。生产不给这个默认——在生产上默默连本机 3306 不是一个可接受的猜测。

上一版说这一步"没有回退路径"是错的：`rn-foundation-apply` 把上一版二进制留成 `rn-server.prev`，迁移失败或健康检查不过都自动装回去（该脚本第 78、86 行）。真正的风险从来不是回不去，而是**看不到的机器**——别人笔记本上还写着旧键的 `.env`。那个由上面第二行的报错接住。
