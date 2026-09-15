# 设计：打包服务的故障恢复备份

状态：Draft v5（2026-09-15）。前四版走了弯路，v5 换了方向：**由打包机自己产出一份自带恢复说明的加密备份包**，平台管理员在控制台手动或定时触发、可下载。人只需要保管两把离线私钥。

数据库备份不在本方案范围内。

## 1. 要防的是什么

App 的安装包必须用签名密钥签。这把钥匙丢了，就再也发不出能升级的新版本——老用户装不上去，只能卸载重装，钱包数据全没。

这把钥匙存在数据库里，但是加密的。**能解开它的只有打包机上的一个小文件**（`/var/lib/rn-build-agent/agent-key`，0600）。服务端故意读不到它——签名密钥能放进数据库，靠的就是这条。

所以：**打包机硬盘坏了，数据库里的密钥全在，但没有任何东西能打开它们。** 所有 App 从此发不出新版本，无法补救（换签名证书 = Android 认作另一个 App）。

这就是本方案唯一要防的事。

## 2. 一个绕不过去的前提

**任何机器能自动打开的备份，攻破那台机器的人也能打开。** 所以必须有东西存在所有机器之外。

就一样：**恢复私钥**。生成一次，存到机器之外，此后不再碰。

除此之外的一切都可以自动化——这是 v5 与前几版的根本差别：前几版让人抄八样东西进两个信封，v5 让打包机把那八样自己打包进去，人只保管钥匙。

### 2.1 两把钥匙，两个人，缺一不可

备份包**套两层加密**：里层封给甲的公钥，外层封给乙的公钥。要打开必须先用乙的私钥剥外层、再用甲的私钥解里层——**两个人都在场才能打开**。

这不增加任何日常操作：加密全自动，只是生成密钥时多一步、配置里多一行。

它挡住的是：一个人拿到备份就能拿到全平台签名密钥；一把私钥泄露就等于全部历史备份泄露。

**代价要说清楚——它把「丢失」的风险翻倍了。** 2-of-2 意味着任何一把丢了，全部备份就永远打不开，和没有备份一样。所以**每个持有人必须把自己那把再存两份，放在不同的物理位置**。不做这一步，这个方案挡住的安全风险会小于它引入的可用性风险。

如果初期只有一个人能负责，单把钥匙也能跑，但那是过渡状态，要在文档和控制台上标出来。

### 2.2 钥匙怎么到两个人手上

**私钥不分发。每个人在自己的机器上生成自己那一对，只把公钥交出来。** 公钥不是秘密，走任何渠道都行；私钥从生成那一刻起就没离开过本人的机器，所以「怎么安全地把私钥送过去」这个问题根本不存在。

甲、乙各自在自己电脑上跑（互相不用碰面）：

```bash
# 生成私钥，会提示设一个密码；私钥文件本身被这个密码保护
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -aes-256-cbc -out my-recovery.key

# 导出公钥——只有这个文件交出去
openssl rsa -in my-recovery.key -pubout -out my-recovery.pub

# 记下指纹，后面核对用
openssl rsa -in my-recovery.key -pubout -outform DER | openssl dgst -sha256
```

运维拿到两个公钥之后：甲的填进打包机的 `/etc/rn-build-agent.env`，乙的填进服务端的 `/etc/rn-foundation.env`。控制台会显示两把公钥的指纹，**甲乙各自核对一眼跟自己记下的那个一致**——防止填错、填串。

### 2.3 每个人怎么保管自己那把

**必须存两份，放两个不同的地方。** 两把钥匙缺一不可，任何一个人弄丢，全部备份就永远打不开。

推荐：两个加密 U 盘，分别放在两个物理位置；密码存在本人的密码管理器里。**私钥文件和它的密码不要放在同一个地方**——那就退化成一把钥匙了。

不要放的地方：公司共享盘、即时通讯的收藏、云笔记、两人共用的密码库。

### 2.4 配好之后必须马上验一次

**这一步不能跳。** 配完立刻手动跑一次备份，然后甲乙两人一起按包里的说明把它打开一次。

理由很实际：如果有人生成时弄错了、或者存错了地方，要在**今天**发现，而不是一年后真出事的时候。之后每月重复一次（几分钟），顺带确认两个人都还在、钥匙都还找得到（§12 第 2 级）。

### 2.5 人员变动与不可用

**人走了**：新人生成自己的一对，公钥换进配置，重新跑一次备份，然后**删掉旧备份**——旧备份用旧私钥还是能开的，离职的人手上那把不会自动失效。

**两个人同时联系不上**：这是 2-of-2 的固有代价。如果这个风险不能接受，可以再准备一份「破窗用」副本——两把私钥各一份封进信封放保险箱，规定两个人签字才能取。加不加这一层，取决于「找不到人」和「有人私自取走」哪个更让你担心。

## 3. 备份包里有什么

| 内容 | 谁能产出 |
|---|---|
| **打包机身份文件** `agent-key` | 只有打包机 |
| **每个租户的签名密钥明文**（`.p12` + 口令） | 只有打包机（它有 `agent-key`，能解开那些盒子） |
| 打包机配置 `/etc/rn-build-agent.env` | 只有打包机 |
| 服务端配置 `/etc/rn-foundation.env`（含 `STORAGE_MASTER_KEY`） | 服务端 |
| 打包必需的数据库配置：租户身份、图标、Firebase 配置、发布身份 | 服务端 |
| **`RECOVERY.md` 恢复说明** | 产出时生成，见 §5 |

前三项是关键——它们**不在数据库里**，数据库备份再完整也覆盖不到。

签名密钥明文由打包机现场解出来装进去，所以**不需要人去收集和保管 `.p12`**，也不会因为新加了租户而遗漏。今天三个租户里只有一个有离线明文，这个做法直接把那个缺口补上。

## 4. 谁产出、怎么加密

### 4.1 流程

```
1. 打包机读 agent-key、读自己的配置
2. 打包机向服务端要全部租户的密封盒子，逐个解开成明文 .p12 + 口令
3. 打包机把这些打成 tar，先封给甲的公钥
4. 打包机把密文上报给服务端（它只出不进，从不监听端口，这条不变）
5. 服务端把自己那部分也加进去，整体再封给乙的公钥，传到云存储
6. 控制台显示状态；平台管理员可以下载
```

服务端从头到尾**打不开**这个包：里层它没有甲的私钥，外层它只有乙的公钥。

### 4.2 两把恢复公钥都写死在配置里，服务端不能指定

- 甲的公钥写在 `/etc/rn-build-agent.env`（root 所有，0600）：`BUILD_AGENT_RECOVERY_RECIPIENT=<公钥>`
- 乙的公钥写在 `/etc/rn-foundation.env`：`BACKUP_RECOVERY_RECIPIENT_OUTER=<公钥>`

**打包机只封给配置里那一把，不接受服务端下发的收件人。** 否则服务端被攻破之后，攻击者只要改一下收件人，就能让打包机把全部签名密钥封给他自己——那等于把「服务端读不到签名密钥」这条论证直接作废。

代价是：换恢复密钥要有人上机器改配置。**这件事本来就应该需要一个人到场。**

启动时要校验：两把公钥都能解析、**且互不相同**（相同就是 2-of-2 退化成 1）。具体校验规则见 §8.3。

### 4.4 触发：打包机只出不进，所以「立即备份」是异步的

打包机每 10 秒轮询服务端要活干，**从不监听端口**（那台机器握着签名密钥，不开任何入站端口是设计的一部分）。所以服务端没有办法主动叫它干活，控制台那个按钮只能是：

```
控制台点「立即备份」 → 服务端建一条待办（状态 pending）
   → 打包机下一轮轮询看到 → 产出并上报（running）
   → 服务端封外层、上传、写结果（succeeded / failed）
   → 控制台刷新出结果
```

**定时备份走的是同一条路**：到点了服务端自己建一条同样的待办。一套机制，两个触发口。

三条必须写清楚的语义：

- **不并发**：已有 pending 或 running 的待办时，再点「立即备份」返回 409 并带上那条的编号，不排第二条。
- **认领超时**：pending 超过 15 分钟没被打包机取走 → 判 `failed`，原因写「打包机没有响应」。打包机挂了、或者 `BUILD_AGENT_RECOVERY_RECIPIENT` 没配（§8.2 要求它缺失时不领待办），都会落到这一条。
- **产出超时**：running 超过 30 分钟没上报 → 判 `failed`。打包机重启后不续做，下一条待办重新来过。

**不能挂在「空闲时顺带做」上。** 现有的密钥校验就是这么挂的——只在构建队列为空的那一轮才跑（`cmd/build-agent/main.go:84-91` 的 `if worked { continue }` 会跳过它）。照抄的话，只要有人连着排构建，备份就永远轮不上。

正确的位置是**每轮循环开头看一眼**，在领构建之前：

```go
for {
    if req, ok := api.pendingBackup(ctx); ok {
        runBackup(ctx, cfg, api, req)     // 有待办就先做完
    }
    worked := pollOnce(ctx, cfg, api)     // 再领构建
    ...
}
```

这样备份最多等一条构建（那条构建正在 `pollOnce` 里面跑），而且不受队列长度影响。

**这条路径顺带解掉一个坑**：`POST /platform/backup/run` 只是插一行待办，毫秒级返回，**不需要**加进数据库超时的豁免列表（全局中间件给每个请求 10 秒上限，`internal/api/server.go:136`）。真正耗时的活在打包机上，不占 HTTP 请求。

### 4.5 包内结构

云存储里并排两个对象：

```
<prefix>/<实例id>/<8位编号>.rnbk          备份包本体（加密）
<prefix>/<实例id>/<8位编号>.README.txt    怎么解开（不加密，见 §5.1）
```

**外层**（封给乙）解开后是一个 tar：

```
manifest.json          这次备份的元数据，见下
RECOVERY.md            恢复手册（明文，不含机密）
recover.sh             交互式恢复脚本（明文，不含机密）
agent.rnbk             打包机那部分，封给甲
server.rnbk            服务端那部分，封给甲
```

`agent.rnbk` 解开后：

```
agent-key                                   打包机身份文件，恢复时放回 <StateDir>/agent-key，0600 builder:builder
build-agent.env                             恢复时放回 /etc/rn-build-agent.env，0600 root:root
keystores/<租户slug>/keystore.p12           签名密钥明文
keystores/<租户slug>/store-password.txt     口令（单行，无换行）
keystores/<租户slug>/key-alias.txt          别名
keystores/<租户slug>/fingerprint.txt        证书 SHA-256，核对用
```

`server.rnbk` 解开后：

```
rn-foundation.env                           恢复时放回 /etc/rn-foundation.env，0600 root:root
db/tenants.json                             租户主表（含 id，必须逐字保留，见 §8.4）
db/tenant-domain.json                       域名映射
db/build-config/<租户slug>.json             打包配置：应用身份、Firebase 配置
db/build-icons/<租户slug>/<四张 png>        启动图标（缺了构建会失败在 ENOENT）
db/release-identity/<租户slug>.json         发布身份：包名、签名指纹
```

`manifest.json` 的字段：

| 字段 | 说明 |
|---|---|
| `format` | 容器格式版本，当前 `1` |
| `seq` | 编号，全局递增 |
| `instanceId` | 产出它的那套系统的标识 |
| `createdAt` | RFC 3339 |
| `serverVersion` / `agentVersion` | 两侧的构建版本，恢复时要装匹配的 |
| `schemaVersion` | 数据库迁移版本号 |
| `tenants[]` | 每个租户：slug、域名、有没有签名密钥、证书指纹 |
| `files[]` | 每个成员的路径、大小、sha256 |
| `innerRecipient` / `outerRecipient` | 两把公钥的 SHA-256 指纹 |

**服务端那部分也封给甲**（不是只封给乙）。否则只拿到乙的私钥就能读到 `rn-foundation.env` 里的 `STORAGE_MASTER_KEY`，2-of-2 就只剩一半。`RECOVERY.md` 与 `recover.sh` 不含机密，留在外层——只有乙的人能读到步骤但拿不到任何密钥，这是想要的。

### 4.6 容器格式：一个 tar，四个文件

每一层都是同样的结构，用 tar 装四个文件，**任何一台 Linux 机器用 `tar` + `openssl` 就能打开**：

```
meta.json      明文元数据
key.bin        RSA-OAEP(公钥, 80 字节密钥材料)
payload.enc    AES-256-CBC 密文
payload.mac    HMAC-SHA256(payload.enc)，32 字节
```

`key.bin` 解出来是固定 80 字节：**前 32 字节是 AES 密钥，中间 32 字节是 HMAC 密钥，最后 16 字节是 IV**。三样一起封，省掉一次 KDF——恢复端不需要 `openssl kdf`（老版本 openssl 没有这个子命令）。

`meta.json`：

```json
{
  "format": 1,
  "layer": "outer",
  "alg": "RSA-OAEP-SHA256+AES-256-CBC+HMAC-SHA256",
  "recipient": "<公钥 SHA-256 指纹>",
  "createdAt": "2026-09-15T08:00:00Z"
}
```

解开一层的完整命令（`README-FIRST.txt` 里会带着实际路径生成一遍）：

```bash
tar xf backup-00000042.rnbk                      # 得到 meta.json key.bin payload.enc payload.mac
openssl pkeyutl -decrypt -inkey 乙.key \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -in key.bin -out k.bin                         # 会提示输入私钥密码
ENC=$(dd if=k.bin bs=1 count=32 2>/dev/null | xxd -p -c64)
MAC=$(dd if=k.bin bs=1 skip=32 count=32 2>/dev/null | xxd -p -c64)
IV=$( dd if=k.bin bs=1 skip=64 count=16 2>/dev/null | xxd -p -c32)
openssl dgst -sha256 -mac HMAC -macopt hexkey:$MAC -binary payload.enc | cmp - payload.mac \
  || { echo "完整性校验失败，这个包被改过或损坏"; exit 1; }
openssl enc -d -aes-256-cbc -K $ENC -iv $IV -in payload.enc -out inner.tar
tar xf inner.tar
```

**先验 MAC 再解密**，顺序不能反——CBC 没有完整性，密文被改一位会解出「大部分正确、中间一段是垃圾」的内容，而那是会被照着执行的恢复步骤。

要求与约束：

- 公钥 **RSA ≥ 3072 位**（4096 推荐）。RSA-OAEP-SHA256 在 3072 位下能封 318 字节，80 字节远在范围内。
- `payload.enc` 走流式加密与流式上传，不要整包进内存。
- `xxd` 不是所有发行版都有，`README-FIRST.txt` 里同时给 `od -An -tx1 | tr -d ' \n'` 的写法。
- **不碰现有的 `buildkeystore.SealTo`**：那是给签名密钥封盒子用的现役函数，动它会让库里已有的盒子全部打不开。这里是另一套格式、另一个用途。

## 5. 恢复说明必须跟着包走

**拿到东西却不知道怎么用**是这类备份最常见的失败方式。所以包里带三样：外面一页纸告诉你怎么解开，里面一个脚本替你做，一份手册供脚本跑不通时人照着做。

说明分两层是为了解开「要先知道怎么解密，才能读到怎么解密」这个死循环：

### 5.1 密文外面：`README-FIRST.txt`

和备份包并排放在云存储里，**不加密**（里面没有任何机密）。内容是一页纸：

- 这是什么、什么时候产生的、对应哪个版本的服务端与打包机
- **你需要什么**：两把恢复私钥，以及各自由谁保管（这一句由运维填）
- **怎么解开**：先外层后里层，六条 openssl 命令，可以直接复制粘贴，参数值已经填好
- 解开之后先读 `RECOVERY.md`

### 5.2 密文里面：`RECOVERY.md`

**产出时生成，不是写死的模板**——模板会过期，生成的不会。里面带的是这次备份的真实值：

- **包里每个文件是什么、放到哪、什么权限、属主是谁**
- **按顺序的恢复步骤**，每步都是可以直接执行的命令，不是散文
- 这份备份对应的租户清单（几个租户、各自的域名、各自有没有签名密钥）
- 对应的服务端与打包机版本号、数据库 schema 版本
- 每个文件的 sha256
- **怎么验证恢复成功了**：跑哪条命令、看到什么算通过

`RECOVERY.md` 的骨架就是 §7 的恢复流程，但里面的 `<租户>`、`<域名>`、`<路径>` 全部替换成产出那一刻的实际值。

### 5.3 密文里面：`recover.sh`

照着手册一步步敲容易漏、容易错，所以包里再带一个**交互式恢复脚本**：

- 问清新机器的域名、安装路径这几个必须由人决定的东西，其余全部自动
- 把文件放到位并设好权限与属主
- 起服务，然后跑完 §7 的整套验证
- 结束时明确说**「恢复完成」**或者**「卡在第几步、因为什么、下一步该查哪里」**——不要静默失败

它和 `RECOVERY.md` 一样是**产出时生成**的，两者内容必须一致：脚本做的每一步，手册里都有对应的那条命令，供环境不一样、脚本跑不通时人接手。

脚本**只做恢复，不做破坏**：遇到目标路径已有文件就停下来问，不覆盖。

## 6. 控制台

平台管理员在**平台维护**下（和「管理员口令」并排）：

- 手动「立即备份」
- 定时开关与频率
- 上次成功时间、包的编号与 sha256、连续失败次数
- 最近若干次的清单，逐条下载
- 两把恢复公钥的指纹（只读），旁边注明各自由谁保管，以及一句「核对它和你手上那把私钥是同一对」
- 若当前只配了一把公钥，显著标出「**单钥模式，过渡状态**」

租户管理员看不到：插件声明 `platformOnly`，前端按会话里的 `platformAdmin` 过滤掉整个菜单；后端路由挂 `platform.*` 组，由 `requirePlatformAdmin()` 按 `PLATFORM_ADMIN_USERNAMES` 白名单卡住，白名单为空时整组 403。

**要知道这道门今天挡不住谁**：控制台只有一个登录账号（`internal/api/server.go:543` 比对唯一的 `ADMIN_USERNAME`），租户是靠打开哪个域名区分的，「租户管理员」这个身份不存在。所以白名单要么包含那个唯一账号（凡是能登录的人都看得见），要么不包含（整组关闭）。多账号登录是另一件事（`OPERATIONS_AND_RELEASE.md:233` 记录了「当前阶段不加入 RBAC」）。

今天便宜的补偿：`run` 和 `download` 各要求重新输入一次管理员口令，并共用登录限速——会话 TTL 默认 8 小时，一个被偷走的 cookie 否则能拉走全部历史备份。

### 6.1 桶

- 用**独立的桶和独立凭据**，不要复用产物桶——产物桶凭据泄露不该等于备份泄露。
- **必须开 versioning**。只给 `PutObject` 不等于安全：`Put` 对已存在的键是覆盖（`s3.go:131-143`），没开 versioning 时覆盖就是删除。「测试连接」要顺带校验 versioning 已开，否则这条论证建在一个没人检查的属性上。
- 保留期用桶的生命周期规则，显式设一个数（建议 90 天）。要知道它的含义：**只要历史包还在，过去的签名密钥就还在里面**——密钥轮换的语义因此是「多了一把新的」，不是「旧的作废」，而保留期就是这个的时间上限。

## 7. 恢复流程

这一节的内容会被生成进每个包里的 `RECOVERY.md`（§5.2），带上当时的实际值。

```
0) 新机器装好：Android SDK / JDK17 / node+pnpm / git / nginx
   域名 DNS 指回来、TLS 证书装好
   —— 不做这一步后面每一步都是 404：租户是按域名解析的，
      而且要求域名 active、租户未软删、当前日期在有效期内
      （internal/api/tenant_resolver.go:64-78，演练时特别容易撞有效期）
1) 记下此刻时间：date -u
2) 从云存储取备份包和 README-FIRST.txt
3) 两个持钥人到场：先用乙的私钥剥外层，再用甲的私钥解里层
   —— 然后跑 recover.sh（交互式），或照 RECOVERY.md 手动来
4) 写回 /etc/rn-foundation.env，起 rn-server
5) 验证主密钥对不对：POST /v1/admin/release-storage/test
   —— 这个接口会真的解密一次凭据。不要用 GET /ota/signing-key，
      那个只读明文证书字段、从不解密，钥匙错了它照样返回 200
6) 验证租户解析与配置可读：GET /v1/mobile/bootstrap 返回 200
7) 放回 agent-key（0600），写 /etc/rn-build-agent.env
   —— BUILD_AGENT_STATE_DIR 必须显式写死。它默认从 workspace 推导
      （cmd/build-agent/config.go:89-92），路径差一点就找不到恢复的私钥，
      打包机会静默生成一把新的（agentkey.go:42-55），日志里区分不出来
   —— 起打包机之前先跑 build-agent print-key 核对指纹
8) DELETE FROM app_configs WHERE config_key='build.keystore.check'
   —— 不删这一步，第 9 步看到的是灾难前写下的旧记录（见 §11）
9) 起 build-agent，等每个租户出现 checkedAt 晚于第 1 步时刻的 ok
10) 跑通一条真实的 APK 构建并入库，才算恢复完成
```

**如果两把恢复私钥丢了任意一把**，备份包就是一堆打不开的字节，和没有备份一样。这就是 §2.1 要求每人各存两份的原因。

## 8. 接口、数据与配置

### 8.1 打包机侧（`/v1/build-agent`，既有的共享令牌鉴权）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/backup-requests` | 有待办返回 `{id, seq, innerRecipient}`，没有返回 **204**。`innerRecipient` 只用于**核对**——打包机封给自己 env 里那一把，两者不一致就拒绝执行并上报原因（§4.2） |
| GET | `/backup-keystores` | 返回**全部**租户的密封盒子 `[{tenant, version, sealedKeystore, keyAlias}]`。**不能复用现有的 `/keystore-checks`**：它 `LIMIT 20` 且跳过「这一版已验过」的租户（`internal/api/build_keystore_check.go:95-122`），拿它做备份会静默漏租户 |
| POST | `/backup-requests/:id/payload` | 请求体是 `agent.rnbk` 的原始字节（`application/octet-stream`），上限 512 MiB。服务端只存不读。重复上传同一个 id → 409 |
| POST | `/backup-requests/:id/fail` | `{reason}`。打包机自己失败时主动上报，不要让服务端干等到超时 |

`/backup-keystores` 的值比现有接口更高（一次拿全量明文盒子），所以它要**单独记审计**（`actor_id='build-agent'`），并且只在有 pending 待办时才返回内容，其余时候返回 403。

### 8.2 控制台侧（`/v1/admin/platform`，`requirePlatformAdmin()`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/backup` | 状态：当前待办（如有）、最近 N 条记录、两把公钥指纹、是否单钥模式、桶是否开了 versioning |
| POST | `/backup/run` | 建一条待办。已有 pending/running → **409** 并带上那条的 seq。要 `{reason, confirm:true}`（`AGENTS.md:35`），并要求重新输入一次管理员口令（§6） |
| GET | `/backup/:seq/download` | 下载。**路径以 `/download` 结尾是有意的**——既有的数据库超时中间件正好豁免这个后缀（`server.go:363-368`），不用再改豁免列表 |
| GET / PUT | `/backup/storage` | 桶的**非机密**字段与状态；凭据和 endpoint 在 env，不落库（§8.3） |
| POST | `/backup/storage/test` | 只 Put 一个随机探针键，并校验 versioning 已开。**不能用现成的 `objectstore.Test()`**：它 Put 固定键再 `HeadObject`（`internal/objectstore/s3.go:319-336`），既要 Get 权限，固定键在开了 versioning 的桶上还会永久留存 |

`download` 用 `:seq` 而不是对象键：服务端按 §4.5 的规则自己拼键。`s3Client.Get` 把 key 原样交给 `GetObject`、没有任何前缀约束（`s3.go:178-184`），接受外部传键等于开一个任意对象读。

**`download` 这条 GET 要补 Origin 检查**：`authenticate()` 的 Origin 闸只对非安全方法生效（`server.go:492`，`safeMethod` 含 GET），而 `originAllowed` 会回落去查 `tenant_domain` 表（`:448-467`）并回显 `Access-Control-Allow-Credentials: true`。不补的话，「谁能读平台备份」实际由那张表的内容决定。修法：平台组关掉 tenant_domain 回退，只认 `CORS_ORIGINS` 里显式列出的控制台来源；响应带 `Cache-Control: no-store`。

### 8.3 新增配置

**服务端** `/etc/rn-foundation.env`：

| 键 | 校验 |
|---|---|
| `BACKUP_RECOVERY_RECIPIENT_INNER` | 甲的 RSA 公钥（PEM）。必须能解析、位数 ≥ 3072 |
| `BACKUP_RECOVERY_RECIPIENT_OUTER` | 乙的 RSA 公钥（PEM）。同上，且**必须与 INNER 不同**——相同就是 2-of-2 退化成 1，直接拒绝启动 |
| `BACKUP_BUCKET_ENDPOINT` / `_REGION` / `_BUCKET` / `_PREFIX` | 生产强制 https |
| `BACKUP_BUCKET_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | 只需要 `s3:PutObject` + `s3:GetObject` + `s3:GetBucketVersioning` |
| `BACKUP_INTERVAL_HOURS` | 0 = 关闭定时，只留手动。范围 1–168 |

**打包机** `/etc/rn-build-agent.env`：

| 键 | 校验 |
|---|---|
| `BUILD_AGENT_RECOVERY_RECIPIENT` | 甲的 RSA 公钥（PEM），≥ 3072 位 |

**失败方向**：打包机侧这个键**缺失或非法时不 fail-closed 启动**——把备份做成构建的单点故障是负收益，而且第一次配置往往正好发生在恢复当天。但它必须**拒绝领备份待办并上报原因**，让控制台上看得见「打包机没配恢复公钥」，而不是静默不备份。服务端侧相反：两把公钥缺失或非法就**拒绝启动**（和 `production` 下那批必填项一起校验，`internal/config/config.go:179-189`）。

三处联动一个都不能少（`AGENTS.md:14`：「少了第二处，这个键对运维就不存在」）：`internal/config/config.go` 读取与逐键校验、`docs/CONFIGURATION.md`、两边的 `.env.example`。**这些正是灾难当天要用的键。**

### 8.4 数据：新建一张 `platform_backups`

#### 复用映射表（`AGENTS.md:99-100`）

| 拟新增 | 结论 | 理由 |
|---|---|---|
| 备份运行记录 | **新建表 `platform_backups`** | 它是**新实体**：一次备份运行有生命周期（pending → running → succeeded/failed）、有多个写方（控制台建、打包机认领与上报、服务端收尾）、条数随时间无界增长。`app_configs` 的一行 JSON 装不下多写方 + 无界增长，`audit_events` 只能追加、没法表达在途状态 |
| 桶配置 | **进 `app_configs(tenant_id=0)`** | 平台级配置的既定去处，自带 `version` 乐观锁与 `updated_by`。只放非机密字段，凭据在 env |
| 备份历史的审计 | **进 `audit_events`** | 既定去处，`actor_id='system-backup'`。表里那份是运行状态，审计那份是不可篡改的流水，两者用途不同不算重复事实源 |

#### DDL

```sql
CREATE TABLE platform_backups (
  id          VARCHAR(80)  NOT NULL          COMMENT '主键，pbk_ 前缀',
  seq         INT UNSIGNED NOT NULL          COMMENT '编号，全局递增，对象键用它；下载接口按它取，不接受外部传对象键',
  status      ENUM('pending','running','succeeded','failed') NOT NULL
                                             COMMENT '状态：pending=已建待办等打包机认领，running=打包机已认领在产出，succeeded=已上传，failed=任一环节失败',
  trigger_by  ENUM('manual','schedule') NOT NULL
                                             COMMENT '触发来源：manual=控制台按钮，schedule=定时',
  requested_by VARCHAR(120) NOT NULL         COMMENT '发起人；定时触发时写 system-backup',
  reason      VARCHAR(500) NOT NULL          COMMENT '发起原因，手动触发必填，写进审计',
  claimed_by  VARCHAR(120) NULL              COMMENT '认领的打包机自报标识，只用于排查，不作为鉴权依据；NULL=还没被认领',
  claimed_at  DATETIME(3)  NULL              COMMENT '认领时间 UTC；NULL=还没被认领',
  object_key  VARCHAR(512) CHARACTER SET ascii NULL
                                             COMMENT '对象存储里的键；NULL=还没上传成功',
  sha256      CHAR(64)     NULL              COMMENT '最终对象的 SHA-256，下载后核对用；NULL=还没上传成功',
  size_bytes  BIGINT UNSIGNED NULL           COMMENT '最终对象字节数；NULL=还没上传成功',
  tenant_count INT UNSIGNED NULL             COMMENT '这次备了几个租户的签名密钥，突然变少要人看一眼；NULL=还没产出',
  failure_reason VARCHAR(500) NULL           COMMENT '失败原因一句话；NULL=没失败',
  created_at  DATETIME(3)  NOT NULL          COMMENT '创建时间 UTC',
  updated_at  DATETIME(3)  NOT NULL          COMMENT '更新时间 UTC',
  PRIMARY KEY (id),
  UNIQUE KEY ux_platform_backups_seq (seq),
  KEY ix_platform_backups_status (status, created_at)
) ENGINE=InnoDB COMMENT='平台备份运行记录：控制台或定时建待办，打包机认领并产出，服务端收尾。只记状态与结果，备份内容本身在对象存储里';
```

**「不并发」靠一条部分唯一索引不好写**（MySQL 没有 partial index），所以用生成列，和 `build_jobs.live_ota_slot` 同构：

```sql
ALTER TABLE platform_backups ADD COLUMN live_slot TINYINT UNSIGNED
  GENERATED ALWAYS AS (CASE WHEN status IN ('pending','running') THEN 1 ELSE NULL END) STORED
  COMMENT '未结束的备份占位：pending/running 时为 1，其余为 NULL。唯一索引建在它上面，保证同时只有一条在途；MySQL 唯一索引不比较 NULL，所以结束后可以立刻建下一条。由数据库生成，无人写入';
CREATE UNIQUE INDEX ux_platform_backups_live ON platform_backups (live_slot);
```

迁移要**幂等**（`addColumnIfMissing` + 查 `information_schema.STATISTICS` 再建索引，模板在 `internal/store/migrations.go:1503-1518`），并且注意 `COMMENT` 里不能出现单引号——集成测试在这上面挡过一次。

`seq` 取 `COALESCE(MAX(seq),0)+1`，和插入在同一个事务里，靠 `ux_platform_backups_seq` 兜并发。

## 9. 测试

**Go 侧**

- 容器格式往返：产出 → 用测试私钥解开 → 逐文件比对内容与 sha256；两层嵌套各验一次。
- **篡改必须被发现**：把 `payload.enc` 翻一位 → 解开时 MAC 校验失败并**在解密之前**中止。
- 只有外层私钥时，`server.rnbk` 与 `agent.rnbk` **都打不开**（守住 2-of-2，防止将来有人「顺手」把服务端那部分只封给乙）。
- `INNER` 与 `OUTER` 配成同一把 → **拒绝启动**。
- 打包机拿到的 `innerRecipient` 与自己 env 里的不一致 → 拒绝执行并上报，**不产出**。
- 打包机 env 缺 `BUILD_AGENT_RECOVERY_RECIPIENT` → 照常领构建，但拒绝领备份待办并上报原因。
- 并发建待办：两个请求同时打 `/backup/run`，只成功一条，另一条 409。
- 认领超时与产出超时各自把记录判 `failed`。
- `/backup-keystores` 在没有 pending 待办时返回 403；有待办时返回**全部**租户（造 25 个租户，断言不是 20 条）。
- `download` 用不存在的 `seq`、别人的 `seq`、带 `..` 的 `seq` → 400/404，且不产生任何对象读。
- 非平台管理员访问全部备份路由 → 403；`PLATFORM_ADMIN_USERNAMES` 为空 → 403。

**脚本与文档侧**

- `recover.sh` 在一台干净容器里跑通（目标路径已存在时停下来问，不覆盖）。
- `README-FIRST.txt` 里的命令**逐条复制粘贴能跑**——这条要在 CI 里跑，不能靠人看。

门禁：

```bash
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -race ./...
go build ./cmd/server ./cmd/build-agent
```

## 10. 兼容、发布与回滚

**升级顺序：先服务端，后打包机。** 打包机的请求体过服务端的 `DisallowUnknownFields`，反过来会让新打包机的上报被 400 顶回来（`build-service-2026-09-11.md` 记过一次同样的事故）。

**打包机不升级也不会坏**：它不认识 `/backup-requests` 就永远不会去调，备份待办会走认领超时判 `failed`，构建一切照常。所以服务端可以先上、观察几天。

**回滚**：

- 服务端回滚：待办停在 pending，超时后判 `failed`，无数据损坏。**但要先确认没有打包机已经上报了 payload 而服务端还没收尾**——那条记录会停在 `running`，回滚后没人处理它，需要人工置 `failed`。
- 打包机回滚：同上，新待办不再被认领。
- 迁移只增表、增列，没有 down migration（`AGENTS.md:26`：迁移只能向前新增）。真要退表，是手工 `DROP TABLE platform_backups` + `DELETE FROM schema_migrations WHERE version=<N>`，两步都做，漏了账本那一行会让服务端认为迁移已跑过、永远不再补。
- **已经产出的备份包不受任何回滚影响**——它在对象存储里，格式自描述，用 openssl 就能开。

## 11. 必须同时修的

**服务端能让打包机执行任意代码**——这条不修，§4.2 的「公钥写死在配置里」是绕得开的：攻击者不用改收件人，直接让打包机检出一个带后门的提交，以 `builder` 身份读走 `agent-key` 就行。

详情与修法记在 `build-concurrency-2026-09-15.md` §9（`git_ref` 从库里读出下发、代理零校验）。**本方案依赖它，必须一起做。**

另外三条阻断，不修则恢复走不通：

| 问题 | 后果 |
|---|---|
| 「上传签名密钥」接口只认旧格式（`internal/api/build_keystore.go:167-174` 要 scrypt + salt），而我们的 CLI 产出的是新格式（那两个字段为空） | 手上有明文 `.p12` 也装不回去。而且 CLI 的屏幕提示还在教用户去调这个接口（`cmd/build-keystore/main.go:196-201`），那是一条必然失败的指引 |
| 打包机公钥的 base64 值全系统没有出口（接口只回指纹，`build_agent_key.go:141-155`；`build-agent` 没有子命令） | 修好上面那条也还是卡住——重新封盒子需要这个值 |
| 恢复后签名密钥不会重新校验：待验清单跳过「这一版已经验过」的租户（`build_keystore_check.go:95-122`），而恢复场景里数据库一个字没动 | 控制台显示「正常」，看的是灾难前那台机器写下的记录 |

## 12. 怎么证明备份是有效的

**服务端永远无法证明「那两把恢复私钥真的能开」**——它一把都没有。它能做的只有结构自检，而且这个自检比看上去弱得多：现有 `SealTo` 封完调的那次自解（`recipient.go:142`）在真正解密之前就返回了，只做了三个长度断言。

所以分三级，**只有第二级算数**：

1. **每次产出**（自动）：文件 sha256 与清单一致、关键内容非空、包体相对上次没有异常跌落、上传后从桶取回来重算一次 sha256。
2. **每月**（人工，两个人各花几分钟）：两位持钥人按 `README-FIRST.txt` 一起开一次最新的包，核对里面的租户清单对不对。**这是唯一能证明那两把私钥能用的动作**，也顺带定期确认两个人都还在、钥匙都还找得到。
3. **每季度**：走完 §7 的完整流程，判据是跑通一条真实的 **APK** 构建。不能用 OTA 构建当判据——OTA 构建根本不碰签名密钥（`cmd/build-agent/ota.go:13-16`），拿它验等于什么都没验。

**演练通过之前，不要对外说「已经有备份了」。**

## 13. 落地顺序

1. **修 §11 的四条**（`git_ref`、上传格式、公钥出口、重验）。前三条不修，备份做出来也用不上。**这一步不依赖本方案其余任何部分，可以立刻开工。**
2. **生成两对恢复密钥**（§2.2），公钥进两边配置，两把私钥交给两个人、各自再存两份。**在此之前先手工抄一份 `agent-key` 存着**——这是过渡期的保险，十分钟的事。
3. **打包机侧产出**：轮询待办（§4.4）、拉全量密封盒子、解密、打 tar、封给甲的公钥、上报。接口契约见 §8.1。
4. **服务端侧**：合并自己那部分、封外层（§4.5/§4.6）、生成 `README-FIRST.txt` / `RECOVERY.md` / `recover.sh`、上传、状态落库。
5. **控制台**：配置页、手动按钮、下载、权限门。接口契约见 §8.2。
6. **定时**（`BACKUP_INTERVAL_HOURS`）：最后上，先用手动按钮跑几天。
7. **三级验证各跑一次**。

门禁与测试清单见 §9，兼容与回滚见 §10。

## 14. 不做什么

- **数据库备份**：不在范围内。
- **产物文件**（APK / OTA 包）：它们在远端对象存储，不随打包机一起死，而且不是机密。防桶丢失靠桶自己的 versioning 与跨区复制。
- **由打包机把密钥「转封」给服务端指定的新收件人**：谁能往收件人列表里写一行，谁就能让打包机把密钥交出来。这里的做法是把收件人写死在两边各自的 root 配置里（§4.2），不给服务端任何指定权。

## 15. 已知遗留

- **`STORAGE_MASTER_KEY` 没有轮换机制**（`OPERATIONS_AND_RELEASE.md:311` 明确要求先实现逐版本解密与重加密，至今未做）。它在备份包里，所以桶的保留期就是它历史影响范围的上限。
- **恢复密钥轮换**：换任意一把都要改对应机器的配置、重新产出一份备份、并删掉旧备份（旧备份仍然对旧私钥有效）。要写进运维手册。
- **多账号管理员登录**：§6 的权限门在它落地之前，实际上是「所有能登录的人都看得见」。
- **告警**：平台没有告警基建，连续失败目前只能靠人去看控制台状态。
