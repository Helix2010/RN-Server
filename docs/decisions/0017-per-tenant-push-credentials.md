# ADR-0017：推送凭据按租户存进数据库

状态：Accepted（2026-09-13）。**Supersedes ADR-0011「安全」一节中"不写入数据库"这一句**；同一句里的"不写入日志或客户端包"继续有效，并由本决策的实现保证。

## 背景

ADR-0011 定下推送凭据只从环境注入。那时只有一个 Firebase 项目，这条约束没有代价。

之后两件事变了：

1. `google-services.json` 自 2026-09-13 起**按租户**存在 `build.android`（ADR-0016）。
2. 平台上现在有四个租户。

FCM 的设备注册 token 绑定它被签发时的 Firebase 项目。用项目 X 的服务账号去发一个属于项目 A 的 token，v1 接口回 `403 SENDER_ID_MISMATCH`。而 env 里只放得下一份服务账号——也就是说，只要有两个租户用不同的 Firebase 项目，其中一个的推送必然发不出去。

2026-09-13 查过生产库：四个租户里有两个传了 `google-services.json`，都属于项目 `anyfun`，与 env 里那把服务账号一致。所以**今天没有坏**，但它成立的方式是巧合——Predict 的包被加进了 AnyFun 的 Firebase 项目，而不是它自己的。下一个租户带着自己的项目接进来那天，构建成功、安装成功、token 注册成功，只有推送发不出去，日志里是一句 `FCM status 403`。

旧实现还有两处放大了这个问题：

- `sendFCM` 把 403 当成普通非 2xx 走重试：1、4、9、16 分钟后第五次判 `failed`，`last_error` 是一句 `FCM status 403`。没有任何配置校验会拦，也没有任何界面会说"这个租户的推送发不出去是因为项目不匹配"。
- `google.CredentialsFromJSON` 只在本地解析 JSON、**不联网**。密钥在 Firebase 控制台被吊销之后，服务照样能起来，日志一行错都没有，直到第一次真发推送才炸。`deploy/amos/rotate-fcm-key.sh` 就是为这件事写的：它在换密钥前后各做一次真实的 OAuth 令牌交换。

## 决策

**推送凭据按租户存进 `app_configs`**，键 `push.fcm` / `push.apns` / `push.hms`。整份服务账号 JSON 用 `STORAGE_MASTER_KEY` 加密（AAD `<tenant>:push.fcm:serviceAccount`），明文只留项目、账号邮箱、`private_key_id`——这三项在 Firebase 控制台上本来就公开显示，不是机密，而管理端要靠它们回答"现在用的是哪把钥匙"。

### 为什么这不违反"密钥不进库"的精神

要和 `build.keystore` 分清楚。签名密钥服务端**不需要也不能**解开：它加密给打包机的公钥，服务端运行时用不到它，所以"服务端能解开"本身就是一个多余的能力。服务账号私钥不同——每发一条推送都要用它签 JWT，服务端必须能解开。它属于 `ota.signing`、`release.storage` 那一类，而库里这一类已经有四种，都用同一把主密钥封着。

真正的约束是"不写入**日志或客户端包**"，这一条由实现保证：私钥不经任何接口返回，审计只记项目、账号和 `private_key_id` 前 8 位，令牌交换的 assertion 不进日志。

### 平台级回落

读取语句与 `release.storage` 相同：`WHERE config_key='push.fcm' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`——租户自己的行优先，没有就用平台（tenant 0）那一行。

这给了一条零行为变化的迁移路径：`rn-server push-credentials import-env` 把 env 里那份导进 tenant 0，四个租户全部继承，发出去的请求和今天逐字节相同。之后哪个租户有自己的 Firebase 项目，就在自己名下存一份覆盖掉。

回落在界面上必须显眼（`inherited: true`），并且**项目匹配检查作用在生效的那一行上**，不管它来自租户还是平台。

### 保存即验证

`PUT` 的路径上真去 Google 换一次访问令牌，换不到就不保存（`424 FCM_CREDENTIAL_REJECTED`）。走的是和真正发送**完全相同**的那条路（`google.CredentialsFromJSON` + `TokenSource.Token()`），所以"验证通过"证明的正是"这把钥匙现在能发推送"。另有 `POST /push/credentials/fcm/test` 随时重验并刷新 `verifiedAt`。

不提供"跳过验证"的开关：那个开关存在的第一天就会有人在 Google 抽风时用它存进一把坏钥匙，然后忘了回来。代价是保存这个配置依赖服务器到 Google 的出网——它本来就依赖，派发器每条消息都要出去。

`rotate-fcm-key.sh` 随之删除，它的价值已经搬进服务端。

### 项目一致性：同一件事的两半

`google-services.json`（编进 APK）和服务账号（留在服务端）必须属于同一个 Firebase 项目。三处校验：

1. 保存服务账号时比该租户已存的 `google-services.json` → `422 FCM_PROJECT_MISMATCH`
2. 保存 `google-services.json` 时比该租户生效的凭据（含继承来的）→ `422 GOOGLE_SERVICES_PROJECT_MISMATCH`
3. 派发时 `SENDER_ID_MISMATCH` → 见下

外加一条对称的形状校验：`build_config.go` 已经拒绝把服务账号（含 `private_key`）当 `google-services.json` 上传；现在也拒绝把 `google-services.json`（含 `project_info`、无 `private_key`）当服务账号上传，并把人指回另一个入口。

### 派发器的错误分类

| 响应 | 处理 |
|---|---|
| 404 / `UNREGISTERED` | token 作废（不变） |
| `403 SENDER_ID_MISMATCH` | 凭据错误：事件立即 `failed`，**绝不碰 token**——token 是好的，错的是凭据；作废它会让那台设备永久收不到推送 |
| 401 / 其它 403 | 凭据错误：`FCM_CREDENTIAL_REJECTED` |
| 没有任何凭据 | 凭据错误：`FCM_NOT_CONFIGURED` |
| 其它非 2xx | 照旧退避重试 |

凭据错误不重试的理由：重试解决的是瞬时故障，凭据错误在有人改配置之前不会自愈，把三十分钟的退避花在它上面只是延迟发现。

### 客户端缓存

派发器按**生效行**的 `tenant_id` 缓存 OAuth 客户端，版本跟着 `app_configs.version`。每条事件查一次（走主键索引），版本没变就复用。换来的是：换密钥不用重启进程，多实例部署下各实例最迟在下一条事件时看到新密钥。

键是生效行而不是事件的租户：四个租户都继承平台那一行时只有一个客户端、一个令牌源，而不是四份相同的。

## 后果

- `push.New` 多一个 `*secretbox.Box` 参数；`PUSH_DISPATCH_ENABLED=true` 现在要求 `STORAGE_MASTER_KEY`（生产上本来就是必填）。
- 每条事件多一次 `app_configs` 主键查询。
- `FCM_PROJECT_ID` / `FCM_SERVICE_ACCOUNT_JSON` 降为过渡键：库里一行都没有时兜底，每次启动打一条 WARN。下一版删除。
- APNs / HMS 本次**不**改成按租户（没有租户在用）。谁做，必须同时把 `Dispatcher.apns` 和 `Dispatcher.hmsToken` 这两个全局字段改成 `map[tenant]`，否则两个租户会互相拿到对方的令牌；`sendAPNs` 里 `cfg.APNsBundleID` 那个兜底也要换成该租户 `release.ios` 的 `bundleId`。
- 删平台那一行等于关掉所有继承者的推送，所以平台 DELETE 先数继承者、没有 `confirm=true` 就拒绝。

设计与对抗性审查见 `docs/design/env-config-slimdown-2026-09-13.md` §5、§8。
