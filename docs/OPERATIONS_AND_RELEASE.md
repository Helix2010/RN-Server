# 可观测、升级与运行规范

## 1. 可观测性模型

三类信号共享 resource attributes：service、environment、version、region、instance，并用 traceId/requestId 关联。

### Logs

- 结构化 JSON，固定 level/time/service/event/requestId/traceId/module/duration/status。
- route 使用模板而非含 ID 的真实路径，避免高基数。
- 请求/响应 body 默认不记录；允许字段采用 allowlist，而不是事后 blacklist。
- error log 记录 root cause chain、稳定 error code 和相关实体 ID 的安全形式，不只记录框架包装异常。

### Metrics

基础 RED：request rate、error rate、duration；资源 USE：CPU、memory、event loop、DB pool、queue lag。业务基座至少有 bootstrap 成功率、auth 成功率、release check、artifact download token、rollout assignment、OTA adoption、强更阻断量。

metrics label 禁止 userId/requestId/完整 URL 等无限基数值。

### Traces

从 RN-App 传入合法 traceparent，API -> DB -> Redis -> queue producer -> worker -> external HTTP 继续传播。采样采用 head 基线 + error/slow tail 保留；安全敏感字段不进 span attribute。

## 2. SLO 与告警

首发前以压测/业务目标冻结数字，不在蓝图阶段假装已有基线。至少定义：

- API availability 与 p95/p99 latency；
- bootstrap/update-policy availability；
- 登录成功率；
- worker queue age 和 dead-letter；
- App crash-free/ANR（来自客户端平台）；
- 发布后错误率相对上一稳定版本的变化。

告警必须指向 runbook 和 owner，按用户影响而不是每个异常报警。发布系统的 stop rule 可因错误率、启动失败、crash-free 回归暂停发布。

## 3. Release 状态机

```text
uploaded -> verified -> active  -> paused -> completed
                    |          \-> completed（被更新的 active 收尾）
                    \-> canary -> active（promote）
                    |         \-> rejected（cancel-canary）
                    \-> rejected
```

- uploaded：对象存在但未可信；服务端流式计算 size/hash，提取 Android/iOS/OTA 元数据。
- verified：签名、app identity、build/runtime、malware/策略检查通过。
- active：官网全量分发。
- canary：只对 `canary_installations` 名单里的安装可见，与 active 平行。`publish` 的收尾语句只扫 `status='active'`，两条主干互不干涉。
- paused：不再分配新设备，已下载设备行为由客户端策略决定。
- 全量安装包不提供“自动回滚”：需要停止当前版本时使用暂停；修复必须发布更高 build 的新安装包。

已 active 的 artifact 永不原地替换。修复必须产生新 artifact/build/update id。

### 3.1 历史版本清理（删除，不是状态迁移）

状态机里没有"删除"：一个版本只会一路走到 completed，升级决策要看得见历史。但产物不
会跟着退场——一个安卓包约 37MB，几十个版本累计就是几个 G 的对象存储，而任何时刻真正
会被下发的只有 active 那一个。清理因此是**独立的破坏性动作**，两个接口，都要
`reason` + `confirm: true`，都写审计（`release_purge` / `ota_release_purge`）：

```text
DELETE /v1/admin/ota/releases/{id}
DELETE /v1/admin/releases/{id}
```

两条硬约束由服务端强制，不靠操作纪律：

| 拒绝 | 条件 | 怎么解 |
| --- | --- | --- |
| `OTA_RELEASE_IN_USE` | 这条 OTA 是 active / canary，且它的运行时版本正是当前 active 全量包的运行时版本 | 先发新版或回滚，再清 |
| `RELEASE_IN_USE` | 全量包处于 active / canary | 先暂停或发布替代版本 |
| `RELEASE_HAS_OTA` | 还有 OTA 记录以它为基线 | 先清掉那些 OTA |

更老运行时线上的 active OTA **可以**删：那条线上的设备收到的是全量升级，不是 OTA。

顺序永远是先 OTA 后基线包。OTA 的包身份（`applicationId`、签名证书指纹）是从基线 APK
读出来的，基线先消失，剩下的 OTA 行就永远校验不过去。

两个接口都收 `keepObjects`（默认 `false`）。置为 `true` 时只清数据库记录，桶里的文件
原样保留，服务端不发任何 List / Delete——**只读存储凭据下唯一走得通的清理方式**。
是有意保留还是删失败，审计里分得清：`summary.keptObjects` 记意图，响应的
`objectsFailed` 记删不掉的条数。批量脚本用 `KEEP_OBJECTS=1` 开这个模式，管理端的删除
面板里是一个默认不勾的"同时删除对象存储里的安装包"。

**如果要连文件一起清，存储凭据必须有 `DeleteObject` 和 `ListBucket`**，而且要覆盖 `tenants/<tenantId>/` 前缀。
不带 `keepObjects` 又用只读凭据会走成这样：数据库记录删掉了，桶里一个字节都没少
（2026-09-12 首次清理时就是这样，23 个安装包变成孤儿对象）。删不掉的对象条数会在响应的 `objectsFailed`
里报出来，对象键留在审计事件的 `summary.objectKey` / `summary.objectPrefix`，权限修好
之后照着扫：

```sql
SELECT JSON_UNQUOTE(JSON_EXTRACT(summary,'$.objectKey'))   FROM audit_events WHERE action='release_purge';
SELECT JSON_UNQUOTE(JSON_EXTRACT(summary,'$.objectPrefix')) FROM audit_events WHERE action='ota_release_purge';
```

OTA 那一侧是失败即中止（`STORAGE_LIST_FAILED`），记录不动——列不出来就不知道该删哪些
对象，先删了行等于把线索也扔了。

批量清理用 `deploy/web4/purge-history.sh`（在部署机上跑，管理密钥只在那台机器；
2026-09-12 起生产是 amos，脚本里的 `SERVICE_DIR` 要指向该机的配置目录）：
`DRY_RUN=1 ./purge-history.sh android` 先看清单，去掉 `DRY_RUN` 才真删。脚本对
"历史"的定义只有一条——build 号低于当前 active 全量包；比 active 更高的 verified
是待发布，不动。OTA 一律尝试删除，留哪一条由服务端的 409 决定，脚本不自己判断。

对象删除**先列后删**：2026-09-10 之前入库的 OTA 没有 `object_metadata`，只按数据库枚
举会把同目录的 bundle 和图片永久留在桶里，所以按 manifest 所在前缀 List 一遍再删。
数据库先提交、对象后删除：反过来一旦入库失败，留下的是一行指向空对象的记录，下发时
才炸；这个方向最坏只是桶里多几个孤儿对象，审计 summary 里记了前缀，可以再扫。

## 4. 更新决策 API

bootstrap 根据以下输入求值：

- 服务端可信的 application identity 映射；
- platform、app version、build、runtimeVersion；
- distribution channel；
- installation rollout bucket；
- tenant/group/region（来自可信上下文）；
- 当前策略、artifact 状态、暂停/kill switch。

输出是结构化 decision：`none | optional | recommended | required`，以及唯一合法 action：`ota | store | direct | mdm`。客户端 header 可伪造，因此升级决策不能承担认证授权职责。

决策响应须签名或包含由可信 TLS endpoint 获取的签名 manifest，带 issuedAt/expiresAt/policyVersion，防止离线缓存永久强更。

### 4.1 公开的三个下载入口

| 地址 | 返回 | 用途 |
| --- | --- | --- |
| `GET /v1/public/releases/latest?platform=android` | JSON（version、buildNumber、sha256、size、downloadUrl…） | 官网 / 脚本查当前版本 |
| `GET /v1/public/releases/latest/download?platform=android` | **302** 跳到下面那条 | **贴二维码、官网按钮、群公告用这条**：地址固定，发版不用换 |
| `GET /v1/public/releases/{id}/download` | APK 字节流（支持 Range） | 真实下载地址，带发布 ID，每发一版就变 |

三条共用同一套可见性判定，灰度也在内：匿名与名单外的调用方永远只会拿到 / 被跳到
active 版本；带有效安装凭证且在名单里的设备才会拿到它自己的灰度包（设计
`RN-App/docs/design/canary-release-allowlist-2026-09-11.md`）。

固定入口的跳转带 `Cache-Control: no-store`——它的意义就是"随时点都是最新的"，
被 CDN 或浏览器缓存住就失去意义。`platform` 缺省顺序是 query → `x-platform` 头 →
`android`（浏览器扫码打开时这两个都不会带）。

## 5. 非商店 artifact 安全

### Android direct APK

- CI 使用受控 signing service 签名，构建节点不持有可导出的长期私钥。
- 上传后验证 applicationId、versionCode、signer certificate fingerprint、minSdk、SHA-256。
- **签名者与包名按租户 pin（2026-09-10）**：每个租户在 `app_configs` 的 `release.android`（`GET/PUT /v1/admin/release-identity/android`，JSON `{"packageName":"com.anyfun.wallet","signerSha256":"<证书 SHA-256，64 位小写十六进制>","expectedVersion":0,"reason":"…","confirm":true}`）登记正式包身份。入库时 APK 的包名与签名者证书指纹必须与之相等（`RELEASE_PACKAGE_MISMATCH` / `RELEASE_SIGNER_MISMATCH`）；`APP_ENV=production` 下未登记即拒绝（`RELEASE_SIGNER_UNPINNED`）；React Native 模板公开 debug 密钥（`fac61745…1033b9c`）在任何环境都拒绝入库也不允许被 pin（`RELEASE_DEBUG_SIGNER`）。pin 只读租户自己那一行，不从平台级继承。每次拒绝写 `audit_events`（`release_rejected`）。 管理端入口：RN-Admin「发布基础设施 → Android 发布身份」页（查看、设置、乐观锁冲突提示；客户端把带冒号/大写的指纹规范化为 64 位小写十六进制，debug 指纹在客户端即被拒绝）。
- APK 必须内嵌 Expo 配置 `extra.applicationId`（RN-App 构建脚本已保证），入库记入 `file_metadata.applicationId`，缺失拒绝（`RELEASE_APPLICATION_ID_MISSING`）；内嵌配置存在但不是合法 JSON 拒绝（`RELEASE_EMBEDDED_CONFIG_INVALID`）。所有入库拒绝（身份、applicationId、版本不符）都写 `audit_events`（`release_rejected`）。
- **发布后对象校验**：入库时用 `objectstore.Stat` 记录对象存储 ETag（`file_metadata.objectEtag`，去引号；分段上传对象形如 `<md5>-<n>`，同一对象再次 Stat 值不变）；`GET /v1/public/releases/{id}/download` 每次先 `Stat` 对象，大小或 ETag 与入库值不符返回 502 `RELEASE_OBJECT_CHANGED`，error 日志与审计（`release_object_changed`，actor `system-release`）对同一 (租户, 发布, 维度) 每 10 分钟最多写一次，请求本身每次都拒绝。去重是**进程内**的：多副本部署时每个实例各写一次；审计写失败只记 error 日志，绝不会把拒绝变成放行（响应先于审计决定）。对象存储不可达返回 502 `RELEASE_DOWNLOAD_FAILED`，不放行；`file_metadata` 不是合法 JSON、或 `objectEtag` 键存在但为空 / 不是字串，返回 500 `RELEASE_METADATA_INVALID`（数据事故，用迁移修，不降级成只比大小）。入库时对象存储没有返回 ETag 则拒绝入库（502 `RELEASE_OBJECT_ETAG_MISSING`），从不持久化空 ETag。只有 2026-09-10 之前入库、`file_metadata` 里**没有** `objectEtag` 键的发布才按旧记录处理：只比大小并每条记一次 warning；要获得完整校验需重新入库。CopyObject、存储类变更或服务端重加密都会改变 ETag，做过这些操作的发布必须重新入库，否则会被当成被篡改而拒绝下发。
- **换签名密钥期间自动收掉应用内直装（2026-09-11，安全评审 N1 迁移窗口 / RN-App runbook §8.5）**：Android 不允许签名不同的 APK 覆盖安装。bootstrap 现在比对"设备现在装的那个 build"入库时记的 `file_metadata.signerSha256` 与"它该升到的那个包"的同一字段，两边都知道且不相等时 `features.directUpdateEnabled` 对这台设备返回 `false`，客户端退回打开下载页而不是在应用内下完再被系统安装器拒掉。任何一边取不到指纹（2026-09-10 之前入库的旧记录、或那个 build 从没上传过）都保持原行为，宁可多给一个可能失败的按钮也不挡住正常升级。**这只消除应用内的失败循环，不能让旧签名装机装上新包**——真正的出路仍是"备份助记词 → 卸载 → 重装"，那段话要写进 `releaseNotes`（强制更新弹层会渲染前 3 条）或旧 runtime 的迁移 OTA。
- 二进制放对象存储/CDN，API 只签发短时下载 URL，不代理大文件。
- 生产下载入口可要求已认证企业用户或一次性 enrollment token；公开分发时仍需防盗链、限速与合规审查。
- 记录下载/安装结果时使用最小化匿名标识；不能假设“已下载 = 已安装”。

### iOS MDM/企业内部分发

- **Apple Team ID 与 bundle id 按租户登记（2026-09-11）**：`app_configs` 的 `release.ios`（`GET/PUT /v1/admin/release-identity/ios`，JSON `{"appleTeamId":"ABCDE12345","bundleId":"com.anyfun.foundation","expectedVersion":0,"reason":"…","confirm":true}`，Team ID 大小写不敏感、入库规范化为大写）。目前唯一的消费方是通用链接归属声明：`GET /.well-known/apple-app-site-association` 按域名解析租户，从这条记录生成，未登记返回 404（`RELEASE_IDENTITY_NOT_CONFIGURED`），**从不猜一份授权发出去**。声明只覆盖 `/app/wc` 一条路径（WalletConnect 回跳），不是整域——整域声明会让任何一个 API 地址都试图拉起 App。该文件按 Apple 要求不带 `.json` 后缀、以 `application/json` 直出、不重定向。RN-Admin 暂无对应界面，目前用 `PUT` 接口登记。
- artifact/manifest 必须与允许的 bundleId、team/certificate、profile、受众匹配。
- certificate/profile 到期前告警；轮换必须先在真实受管设备验证覆盖升级。
- MDM assignment 状态与 App 主动 check 状态分开记录；MDM 是安装控制面，App release service 是版本策略面。
- 企业 IPA/manifest 不下发给公共用户，访问日志和审计证明分发范围。

### OTA

- **代码签名（2026-09-11，安全评审 N19）**：OTA 此前只有完整性没有真实性——manifest 的 sha256 存在我们自己的数据库里，能改数据库或能顶替这条响应的人，可以让客户端拿到一份它认为"完整"的恶意 bundle，而 OTA 能改的是整个 JS 层，包括钱包签名前的确认界面。

  现在每租户一把 RSA 私钥（`app_configs` 的 `ota.signing`，用 storage master key 认证加密后落库，**任何接口都不返回私钥**），经 `GET/PUT /v1/admin/ota/signing-key` 维护，`POST /v1/admin/ota/signing-key/generate` 直接在服务端生成密钥对（签每一份 manifest 时服务端本来就要把明文私钥解出来，让它在这里诞生不扩大暴露面，却省掉运维机上的明文文件与一次跨机器搬运；代价是没有离线备份，而丢了它的代价本来就等于主动轮换它的代价：发一个原生新版。**Android keystore 不适用这条推论**——服务端运行时根本不用它，它丢了没有任何补救）。下发时对**改写完成后的最终响应体**签名（对入库原文签名会把 `applyManifestStrategy` 那段改写留在签名覆盖范围之外），`rollBackToEmbedded` 指令同样签——它本身就是一条"把所有人退回内置版本"的指令。

  协议事实（读 expo-updates 57.0.22 源码确认）：`expo-signature` 是 RFC 8941 字典 `sig="<base64>", keyid="…", alg="rsa-v1_5-sha256"`，签的是 body 原始字节，`SHA256withRSA`；**plain 响应里它是 HTTP 响应头，multipart 里它是 part 的头**（manifest 与 directive 各签各的）。写错位置的表现是"签了但客户端说没签名"。

  几处必须知道的行为：ETag 把 keyid 算进去（否则装/换密钥时 manifest 字节没变，带 `if-none-match` 的客户端一直拿 304、永远收不到签名）；写入时校验证书与私钥是一对（不匹配的话服务端签得出来而客户端一定验不过，症状是所有设备静默停在内置 bundle）；租户没配密钥时照常下发未签名响应，要验签的客户端自己拒绝并回落内置 bundle，同时服务端按 (租户, 运行时) 去重记一条 warning——这个故障在设备上完全静默，只能从服务端看见。

  **上线顺序**：先装服务端密钥，再发带 `codeSigningCertificate` 的原生包。反过来的话，新包的所有设备都收不到 OTA。App 侧的 `EXPO_REQUIRE_OTA_SIGNING` 开关（RN-App runbook §3.2.1）用来保证带证书这件事不被忘记。
- manifest 签名密钥与 native signing key 分离；私钥由 signing service 保管。
- runtimeVersion 必须严格匹配；资源 URL 内容寻址并不可变。
- 更新上传后跑静态检查、启动 smoke 和真机 staging；生产先 canary。
- 应用身份（App 请求头 `X-Application-ID`，即租户配置的 `applicationId`）由 OTA 包自己带上（`extra.applicationId`），服务端只校验不改写；缺失即拒绝上传（`OTA_MANIFEST_INVALID`）。基线 APK 的包名是 `package_id`，不是应用身份，不能拿来顶替，否则装了 OTA 的设备会以另一个身份上报，`app_installations` 里出现同一台设备的两条记录，安装凭证也对不上。
- **应用身份绑定基线（2026-09-10）**：Android 基线的 OTA，其 `extra.applicationId` 必须等于基线 APK 内嵌的 `extra.applicationId`（`OTA_APPLICATION_ID_MISMATCH`）。基线在 `file_metadata` 里没有该值时，服务端从对象存储重新解析 APK 并回填（系统写入，审计 `release_applicationid_backfilled`，actor `system-ota`，在 OTA 事务之外，OTA 随后失败也不撤回）。回填前先核对下载到的对象与入库记录的 `sha256` / `file_size` 一致：不一致返回 502 `OTA_BASE_RELEASE_CHANGED` 并记审计（`ota_base_release_changed`），绝不把替换件的身份写进数据库；记录里没有 sha256 / 大小、对象读不到或超过 `ARTIFACT_MAX_SIZE_MB` 返回 502 `OTA_BASE_RELEASE_UNREADABLE`（不截断解析）；解析出来为空的基线不能再挂 OTA（`OTA_BASE_APPLICATION_ID_UNKNOWN`）。服务端没有租户级 applicationId 配置，所以只绑基线 APK，不与租户配置比对。**已知缺口**：iOS 基线（IPA）服务端不解析，iOS OTA 不做该绑定，只记 warning。
- **资源对象校验**：OTA 入库时用 `objectstore.Stat` 记录每个资源对象的大小与 ETag（`ota_releases.object_metadata`，迁移 37；不含 `manifest.json`，manifest 由 `manifest_sha256` 全文校验）；入库时任一资源对象没有 ETag 即拒绝（502 `OTA_OBJECT_ETAG_MISSING`）；`GET /v1/ota/assets/{id}/*` 下发前 `Stat` 比对，不符返回 502 `OTA_OBJECT_CHANGED` 并记审计（`ota_object_changed`，同一 (租户, OTA, 维度, 路径) 每 10 分钟最多一次，进程内去重）；对象表里的条目缺 ETag 视为损坏（500）；对象存储不可达返回 502 `OTA_ASSET_UNAVAILABLE`；对象表里没有这条路径返回 404（包里没有这个文件，不拿前缀下的其它对象顶上）；对象表损坏返回 500 `OTA_OBJECT_METADATA_INVALID`。迁移 37 之前的 OTA 记录为 NULL，只受 manifest 内容 hash（服务端）与资源 hash（expo-updates 客户端）保护。
- 生成给客户端的绝对地址（下载、OTA 资源、上传入口）在 `APP_ENV=production` 下一律 `https://`；代理缺 `x-forwarded-proto` 只记一次 warning，不再烘出 `http://` 地址。
- 对象存储配置在 `APP_ENV=production` 下必须使用 https 的 `endpoint` / `publicBaseUrl`：保存时拒绝 http（422 `STORAGE_ENDPOINT_INSECURE`），已存的 http 配置在使用时被拒并记 error（503 `STORAGE_UNAVAILABLE`）。原因：`direct` 上传模式的上传入口是对象存储的 presigned URL，不经 `absoluteURL`，协议只能由配置本身保证。

## 6. 灰度与暂停

**按设备名单的灰度（2026-09-11 起可用）**。设计与安全论证见 `RN-App/docs/design/canary-release-allowlist-2026-09-11.md`。

操作步骤（全量包与 OTA 同一套）：

1. 让目标设备先跑一次带身份上报的版本——灰度靠服务端签发的安装凭证识别身份，更早的客户端认不出，只会拿到正式版。
2. 管理端「发布记录」→ 待发布行 →「灰度发布」，从「安装与设备」勾选或粘贴安装 ID。名单不能为空，ID 必须已经上报过（拼错会当场被拒）。
3. 名单内设备下一次拉 bootstrap 就能看到；**OTA 要多等一次启动**——灰度令牌由 expo-updates 的 extra params 持久化，本次启动的 manifest 请求已经发出去了。
4. 验证通过 →「转为正式发布」（`promote`，同一条记录转正，不重新上传）；有问题 →「取消灰度」。
5. 取消后，已经装上灰度版的设备会停在高于 active 的版本上，直到出现更高的 active。不要指望客户端降级。

约束：

- 强制升级（mandatory）与灰度互斥，两个方向都拒。强制版本只由 active 记录决定——一台设备拿到灰度包不会让它身上的强制升级要求消失。
- 允许多条灰度并存（面向不同名单），设备按 `build_number`（OTA 按 `revision`）取最大的一条。
- 发布一个 build 不低于某条灰度的 active 之后，那条灰度对谁都不再可见。管理端会提示，但**不会自动改它的状态**——需要运营去点「取消灰度」。
- 名单规模上限 200 台；超过这个量级要把 JSON 列拆成关联表。
- 进入灰度、改名单、取消、转正四个动作都进审计，正文记设备数与名单哈希（完整名单在发布记录上随时可查）。
- 匿名请求与老客户端永远只看得到 active：`/v1/public/releases/latest` 不带凭证时看不到灰度，猜到发布 ID 直接下载也是 404。

- 当前开发阶段不实现灰度 bucket 和比例分配。
- feature flag 可关闭业务功能，但不能修复原生 ABI 不兼容；两者责任分开。
- OTA 可独立设计恢复上一稳定 update；当前全量安装包发布模块不提供回滚，必须发布更高 build 的修复包。
- 提升 minSupported 前先证明所有目标渠道可安装、覆盖率达标且客服/应急通道就绪。

## 7. 备份与灾难恢复

- MySQL 定期全量 + binlog PITR，恢复演练而不只检查备份任务成功。
- 对象存储启用 versioning/immutability；签名 artifact 与 manifest 跨故障域备份。
- Redis/队列不能成为唯一业务事实源；outbox 可从数据库恢复投递。
- 记录目标 RPO/RTO、DNS/CDN/identity provider 故障的降级策略。
- bootstrap 故障时已安装 App 使用有限期缓存，不应全部变砖。

## 8. 管理控制面

发布管理端必须提供：draft preview、artifact verification、受众/比例、兼容矩阵、minSupported 风险提示、暂停、审计查询。当前阶段不加入 RBAC 与双人审批；高风险操作仍必须显式确认并填写 reason，不提供无上下文的“立即全量强更”按钮。

**身份与会话（2026-09-11，安全评审 N17）**：

- `x-admin-key` 自动化通道写进 `audit_events` 的 actor 由 `ADMIN_API_ACTOR`（默认 `api-key-automation`）决定，**不再取请求自报的 `x-admin-id`**——那是持钥者可任意填写的字段，审计链等于没有依据。请求仍可带该头，只会被忽略并记一条 warning 日志；因此这条通道现在也不再要求带 `x-admin-id`。要区分多个自动化调用方，就给它们各自的部署配不同的 `ADMIN_API_ACTOR`（`ADMIN_API_KEY` 目前仍是单值）。
- `ADMIN_COOKIE_SECURE` 默认改为 `true`，管理会话 cookie 只走 TLS。本地用 http 调管理端时在 `.env` 里显式设 `false`。
- 旁路本身的存废（是否保留 `x-admin-key`）、按租户 RBAC 与发布双人分离仍是未决项，见钱包安全评审 N17。

## 9. Runbook 最小集合

- API 错误率/延迟升高；
- 数据库连接耗尽/慢查询；
- 队列积压/dead-letter；
- 登录供应商故障；
- 错误 OTA 导致启动崩溃；
- Android APK 签名/下载/安装失败；
- iOS 企业证书/profile 到期或撤销；
- 错误 minSupported 导致全量阻断；
- 凭证/签名密钥疑似泄露。

每份 runbook 包含影响确认、立即止损、诊断查询、恢复、数据核对、沟通和复盘责任。

### 安装记录去重（2026-09-07 OTA 应用身份修复后的一次性核对）

修复前上传的 OTA 包把应用身份改写成了 APK 包名，装过 OTA 的设备在 `app_installations` 里各有两条记录：`application_id` 等于 `package_id` 的那条是错误身份。设备装上修复后的 OTA 包会重新以租户配置的身份上报，那之后再删错误行；还没重新上报的设备（`good.last_active_at` 更旧）先留着，隔天再跑一次：

```sql
DELETE bad FROM app_installations bad
JOIN app_installations good
  ON good.tenant_id = bad.tenant_id AND good.installation_id = bad.installation_id
 AND good.application_id <> bad.application_id
WHERE bad.application_id = bad.package_id
  AND good.last_active_at >= bad.last_active_at;
```

推送 Token、钱包会话都只按 `installation_id` 关联，不受删除影响。

### 签名密钥切换日（测试阶段用的是公开 debug 密钥，正式包换密钥时执行）

设备归并靠 Android ID 的 HMAC，而 Android ID 按应用签名密钥区分：换密钥当天所有 Android 设备的归并 ID 都会变，`device_clients` 会出现一批新记录，旧记录不再有心跳。

1. 切换前：导出一份"账号 × 安装实例"汇总（`wallet_user_installation` 与 `app_installations` 按 `installation_id` 关联），切换前的设备维度历史只能从这份数据和安装实例记录回看。
2. 切换要求：所有租户的正式包共用同一把密钥，否则跨租户设备归并只能按地址聚合（设计 device-account-aggregation-2026-09-07 §4.4）。
3. 现有用户必须卸载重装（签名不同无法覆盖安装），重装后是新的安装实例、新的归并 ID；登录后账号历史照常累积。
4. 切换后核对：管理端"设备管理"里新安装实例的 `launch_source` 与运行 OTA 正常上报；账号详情里旧安装实例停留在切换前的最近活跃时间，属预期。
5. 归并从切换日重新开始，不做旧新 ID 的映射（没有可靠依据）。

### 数据库集成测试

`internal/api/db_integration_test.go` 覆盖会话替代、封禁结束会话、心跳解析运行修订号、租户接口不泄露归并 ID、平台级跨租户查询与封禁。需要一个可清空的 MySQL 8：

```bash
docker run -d --name rn-test-mysql -e MYSQL_ROOT_PASSWORD=rn-test -e MYSQL_DATABASE=rn_test -p 127.0.0.1:33061:3306 mysql:8.0
RN_TEST_MYSQL_DSN='root:rn-test@tcp(127.0.0.1:33061)/rn_test?parseTime=true&charset=utf8mb4' go test ./internal/api/ -run TestDB -v
```

没有设置 `RN_TEST_MYSQL_DSN`（或旧的 `RN_TEST_MYSQL_HOST` 那一组，仍然认）时这组测试跳过（CI 里显示 skip，不算通过）。

## 10. 多租户对象存储上线检查

- 上传模式由 `ARTIFACT_UPLOAD_MODE` 控制：`direct` 使用浏览器预签名 PUT，吞吐更高但 Bucket 必须允许管理端 Origin；`proxy` 由 RN-Server 将请求体流式写入对象存储，适用于暂时无法配置 CORS 的环境。代理模式不会把完整安装包读入内存，但会占用 API 带宽和一条长连接。

- 每个租户使用独立 bucket 或至少由服务端强制生成的 `tenants/<tenantId>/` 前缀；IAM policy 同时限制 bucket、prefix、Get/Put/List 权限，禁止 ListAllMyBuckets 和删除生产 Artifact。
- bucket CORS 只允许 RN-Admin 的 HTTPS origin、`PUT`/`HEAD` 和 `content-type` header。AWS S3 示例：

```json
[
  {
    "AllowedOrigins": ["https://console.anyfun.win"],
    "AllowedMethods": ["PUT", "HEAD"],
    "AllowedHeaders": ["content-type"],
    "ExposeHeaders": ["etag"],
    "MaxAgeSeconds": 900
  }
]
```

- `STORAGE_MASTER_KEY` 用 `openssl rand -base64 32` 生成并放入部署 secret；备份后再写入生产，不能放 MySQL。轮换前必须实现逐版本解密、重加密和核对，禁止直接替换环境值。
- 先在管理端保存配置，再执行“测试连接”；随后用非生产签名 APK 验证直传、finalize、拒绝错误 signer、预发布、激活、公开 latest metadata、307 下载与覆盖安装。
- 激活前确认 public CDN base URL 指向同一不可变 object key；未配置 CDN 时验证 presigned GET 的 TTL、限速和日志不会泄露 query signature。
