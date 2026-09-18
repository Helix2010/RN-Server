# iOS 推送凭据按租户化，以及共通应用参数的归位

2026-09-18。两件事写在一份里，因为它们的根因是同一个：**控制台把"跨平台的东西"
挂在了 Android 那一页下面**。一件是推送（FCM 在 Android 页，APNs 压根没有），
一件是 App 参数（四个平台无关的字段挂在「Android 打包与签名」第 3 步）。

关联：ADR-0017（推送凭据按租户存进数据库）、ADR-0016（Android 签名控制台流程）、
`RN-Admin/docs/ADMIN_ENGINEERING_STANDARD.md` §2.3（二级 Tab）、§15（配置卡与表单）。

---

## 1. 现状核查

### 1.1 APNs：三处都停在半路

| 层 | 现状 | 位置 |
| --- | --- | --- |
| 存储键 | `push.apns` 常量**已定义**，没有任何写入 | `internal/pushcreds/pushcreds.go:39` |
| 管理接口 | 硬编码返回 `{configured:false, inherited:false, version:0}` | `internal/api/push_credentials.go:316` |
| 派发器 | **能发**，但读 env 的全局一份，不按租户 | `internal/push/dispatcher.go:100-111` |
| 控制台 | 无入口 | — |

派发器里已经留了一条给后来人的话（`dispatcher.go:36-38`）：

> apns 与 hms 仍是全局的一份：没有租户在用。谁把它们改成按租户，必须同时把
> 这两处改成 `map[tenant]`，否则两个租户会互相拿到对方的令牌；`sendAPNs` 里
> 那个 `cfg.APNsBundleID` 兜底也要换成该租户 `release.ios` 的 `bundleId`。

这份设计就是按那句话做的。

### 1.2 四个共通字段：服务端早就是对的，只有控制台放错了

`internal/api/tenant_manifest.go:23` 的注释已经把边界画清楚了：

> 只有这几个字段由租户在控制台维护：`appName` / `scheme` / `androidPackage` /
> `iosBundleId` / `apiBaseUrl` / `iconBackgroundColor`。

组装时的来源（`tenant_manifest.go:164-176`）：

| 字段 | 来源 | 平台 |
| --- | --- | --- |
| `appName` `scheme` `apiBaseUrl` `iconBackgroundColor` | `build.config`.identity | **跨平台** |
| `androidPackage` | `release.android`.packageName | Android |
| `iosBundleId` | `release.ios`.bundleId | iOS |

所以**用户的理解是对的，而且服务端的模型本来就长这样**：一份租户身份，
外加两个按平台的包标识。`tenantManifest` 同时带 `androidPackage` 和
`iosBundleId`、`androidVersionCode` 和 `iosBuildNumber`，它是发给两个平台打包机的
同一份清单。

错的只有控制台的归属。错得有多深，看服务端自己的报缺失文案就知道
（`tenant_manifest.go:98`）：

```go
add("appName", "Android 打包与签名 → App 参数")
add("scheme",  "Android 打包与签名 → App 参数")
add("apiBaseUrl", "Android 打包与签名 → App 参数")
```

iOS 构建同样要这三项，但指路只会把人送去 Android 那一页。

**这一半不需要改任何接口**，`build.config` 已经是租户级、平台无关的一条记录。

---

## 2. 决策一：APNs 照 FCM 的形状复制一份

不发明新形状。ADR-0017 为 FCM 定的那套（按租户存、平台级回落、保存即验证、
明文只留非机密的标识项）已经在生产上跑过，APNs 直接套用。

### 2.1 记录形状

键 `push.apns`，`config_value`：

```json
{
  "teamId":           "ABCDE12345",
  "keyId":            "XYZ9876543",
  "environment":      "production",
  "authKeyEncrypted": "<STORAGE_MASTER_KEY 封的 .p8>",
  "verifiedAt":       "2026-09-18T07:00:00Z"
}
```

- `teamId` / `keyId` 明文：和 FCM 的 projectId / clientEmail 同理，它们在 Apple
  开发者后台本来就公开显示，不是机密，而控制台要靠它们回答"现在用的是哪把钥匙"。
- `.p8` 私钥加密，AAD `<tenant>:push.apns:authKey`（对齐 FCM 的
  `<tenant>:push.fcm:serviceAccount`）。
- 和 FCM 服务账号同类：**服务端每发一条推送都要用它签 JWT**，必须能解开。
  这不违反"密钥不进库"——那条约束的实质是"不进日志、不进客户端包"，
  ADR-0017 已经论证过，这里沿用同一条论证。

### 2.2 topic（bundle id）不存在这条记录里

`sendAPNs` 的 topic 取该租户 `release.ios` 的 `bundleId`，不在 `push.apns` 里存
第二份。

理由：存两份必然漂移，而漂移的表现是**推送静默失效**——APNs 回 400
`DeviceTokenNotForTopic`，和 FCM 的 `SENDER_ID_MISMATCH` 是同一类"构建成功、
安装成功、注册成功，只有推送发不出去"。bundle id 变了意味着换了一个 App，
不是换了一份推送配置。

代价：iOS 身份没配时 APNs 无法验证也无法发送。这是对的——没有 bundle id 时
本来就没有能收推送的 App。界面按"待配置"处理，并指向 iOS 那一页。

### 2.3 保存即验证：用一次真实推送探活

FCM 的验证是去 Google 换一次访问令牌。APNs 没有等价的"验证凭据"接口，
但它的错误码把**鉴权失败**和**收件人无效**分得很干净：

| APNs 响应 | 含义 | 结论 |
| --- | --- | --- |
| 403 `InvalidProviderToken` / `ExpiredProviderToken` | JWT 签不对、key/team 不匹配 | **凭据坏**，拒绝保存 |
| 400 `TopicDisallowed` | 这把 key 的 team 管不着这个 bundle id | **凭据与身份不匹配**，拒绝保存 |
| 400 `BadDeviceToken` | 鉴权过了，只是收件人是假的 | **凭据好**，接受 |
| 其他 5xx / 网络错误 | Apple 侧异常 | 拒绝保存，原文回显 |

做法：拿一个明显无效的 device token（32 字节全 0 的十六进制）向该租户的
bundle id 发一条 `content-available` 静默推送。APNs **先验 provider token
再验 device token**，所以 `BadDeviceToken` 恰恰证明鉴权通过了。

常量在 `github.com/sideshow/apns2@v0.25.0/response.go` 里都有
（`ReasonInvalidProviderToken` / `ReasonTopicDisallowed` / `ReasonBadDeviceToken`），
不用自己拼字符串。

这和 FCM 遵守同一条原则：**验证要和真正发送走同一条路**，否则"验证通过"
证明不了任何事。失败码 `424 APNS_CREDENTIAL_REJECTED`，与
`FCM_CREDENTIAL_REJECTED` 对齐。

同样**不提供"跳过验证"开关**，理由见 ADR-0017。

### 2.4 environment：默认 production，但必须可选

这一项容易配错，且错了之后同样是静默失效：

- **TestFlight 装的包走 production**。它是 App Store 分发的构建，不是 sandbox。
- 只有 Xcode 直接连真机调试出来的包才注册 sandbox token。

默认 `production`。保留 sandbox 选项是因为开发机真机调试拿到的 token 只有
sandbox 认，两边的 token 互不通用（production 收到 sandbox token 回
`BadDeviceToken`——和凭据坏的表现一样，所以界面上要把这一项写清楚）。

### 2.5 平台级回落

读取语句与 FCM / `release.storage` 相同：

```sql
WHERE config_key='push.apns' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1
```

`rn-server push-credentials import-env` 扩展成一并把 `APNS_TEAM_ID` /
`APNS_KEY_ID` / `APNS_PRIVATE_KEY` / `APNS_ENVIRONMENT` 导进 tenant 0，
给一条零行为变化的迁移路径。

`APNS_BUNDLE_ID` **不导**：它被 §2.2 的 `release.ios.bundleId` 取代。导入时如果
env 里的 bundle id 与某租户的 `release.ios` 不一致，打一条 warn 列出来——这正是
今天可能已经错着的地方。

### 2.6 派发器

按 `dispatcher.go:36-38` 那条注释办：

- `apns *apns2.Client` → 按租户缓存的 `map[string]*apns2.Client`，键是**生效行的
  租户**（可能是 "0"），不是请求方租户——和 FCM 的 `SourceTenant` 语义一致。
- 配置改动要让缓存失效（沿用 FCM 现有的失效路径）。
- `sendAPNs` 的 `topic` 从 `cfg.APNsBundleID` 改成该租户 `release.ios.bundleId`。
- 403 不再当普通非 2xx 重试——和 ADR-0017 修 FCM 403 的理由相同：重试五次
  只会把一个配置错误拖成四十分钟后的一行 `APNs status 403`。

### 2.7 HMS 继续占位

`push.hms` 保持 `configured:false`，界面上画出来但标"未接入"。理由和当初一样：
没有租户在用，而 HMS 的字段形状与前两家不同，现在设计等于凭空猜。

---

## 3. 决策二：共通参数独立成 Tab，各平台身份只读汇总

### 3.1 目标信息架构

```
发布基础设施
├─ 应用身份            ← 新增。共通四项 + 各平台身份只读汇总
├─ Android 打包与签名   ① 签名密钥 ② 包身份 ③ Android 打包参数
├─ iOS 打包与分发       ASC 接入 / TestFlight 与扫码
├─ 推送凭据            ← 新增。FCM / APNs / HMS
├─ 发布存储            APK / iOS / HarmonyOS
└─ OTA 签名
```

### 3.2 「应用身份」Tab

两张卡，**按记录边界切**（标准 §15.1：一张卡 = 一次保存 = 一条记录）：

- **卡 1「共通参数」** — `build.config`.identity 那一条，一次保存。
  `appName` / `scheme` / `apiBaseUrl` / `iconBackgroundColor`。
  卡头说清楚："这四项两个平台共用，改了 Android 和 iOS 下一次构建都会变。"
- **卡 2「各平台包标识」** — **只读汇总**，用 `identity-details`。
  Android 包名 + 证书指纹（来自 `release.android`）、iOS Team ID + bundle id
  （来自 `release.ios`），每项带一个"去改"的链接跳到对应 Tab。

为什么平台身份是只读而不是搬过来：它们各自属于 `release.android` /
`release.ios`，**各带各的乐观锁**，而且和同一条记录里的证书指纹 / installUrl /
过期日是一起保存的。搬过来就得把一条记录拆成两次提交，"其中一条冲突"会变成
半保存——这正是 iOS 那一页当初拆成两张卡的原因。只读汇总既让人在一处看全，
又不动记录边界。

### 3.3 Android 那条编号链会短一节

第 3 步「App 与打包参数」拿掉四项之后剩下：仓库目录、构建分支、
`google-services.json`——**这三项确实只属于 Android**。

链条从 ①密钥 → ②包身份 → ③打包参数 变成同样的三步，编号不变，
只是第 3 步瘦了。页面顶上那张 ASCII 链条图要跟着改一行。

**这是这份方案里唯一会动到现有叙事的地方**，那条编号是那一页唯一的导航
（`.signing-step` 的 CSS 注释：四张卡片长得都像"又一组配置"）。

### 3.4 「推送凭据」Tab：为什么不按耦合分散放

有一个反对意见值得写下来：FCM 和 `google-services.json` 必须是**同一个 Firebase
项目**，APNs 的 topic 必须是**该租户的 bundle id**。按耦合放的话，FCM 该留在
Android 页挨着 google-services，APNs 该放 iOS 页挨着 bundle id。

不这么做，理由是**耦合可以在卡内表达，不必靠 Tab 相邻**：

- 服务端的 `GET /push/credentials` 本来就一次返回三家，而且 FCM 那份里已经带了
  `googleServicesProjectId` 和 `projectMatches`（服务端比出来的结论，控制台不自己
  再比一次）。把这两项直接画在 FCM 卡里，比"隔壁 Tab 有个文件"更能说明问题。
- APNs 卡同理回显该租户的 bundle id，没配时显示"待配置"并给跳转。

这样"推送"是一件事一个 Tab，而一致性校验就在人填的那张卡上——比隔着一个 Tab
更近，不是更远。

---

## 4. 分期与风险

| 期 | 内容 | 仓库 | 风险 |
| --- | --- | --- | --- |
| P1 | 共通参数独立 Tab + 各平台身份只读汇总 | RN-Admin | 低，**零接口改动**；只动那条编号链的第 3 步 |
| P2 | 「推送凭据」Tab：FCM 从 Android 页迁过来 | RN-Admin | 低，接口不变 |
| P3 | APNs 按租户：存储 + 保存即验证 + 管理接口 | RN-Server | 中，新密文字段与新外呼 |
| P4 | 派发器按租户化 + `import-env` 扩展 | RN-Server | **高，动生产推送链路** |
| P5 | 控制台 APNs 卡 | RN-Admin | 低 |

P4 是唯一会改变线上行为的一期。它的安全网是 §2.5 的平台级回落：导入 env 那份到
tenant 0 之后，所有租户继续继承同一套凭据，发出去的请求和今天逐字节相同；
只有某个租户自己存了一份，才会改变它的行为。

### 需要拍板的点

1. **P4 要不要做。** 不做 P4 的话，P3/P5 存下来的每租户 APNs 凭据不会被派发器使用
   （仍走 env 那份全局的）——界面会说"已配置"，实际发送用的却是另一把。
   **这种状态比没有更危险**，所以 P3–P5 要么一起上，要么都不上。
2. **environment 默认值**是否就定 production（§2.4）。
3. **§3.3 那条编号链**瘦一节能不能接受，还是希望第 3 步保持原样、
   四个共通字段在「应用身份」页只读镜像（代价：一份配置两个地方显示）。

---

## 5. 不在这一版里

- HMS 接入（§2.7）。
- iOS 构建参数（Xcode 版本、provisioning profile 等）：目前全在 Mac 上，
  管理端没有对应模型，硬塞进「应用身份」只会造出一堆填不了的框。
- 把 `androidPackage` / `iosBundleId` 真正搬进 `build.config`：会把两条各带锁的
  记录合成一条，收益不抵迁移成本（§3.2）。
