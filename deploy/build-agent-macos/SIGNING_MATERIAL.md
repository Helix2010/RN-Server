# iOS 签名材料与两把信任根：做出来、发下去、到期换、不要了怎么销

这份手册管三样东西，它们的共同点是**都不经服务端**，而且都由人一台台放到 Mac 上：

| 东西 | 是什么 | 放在哪台 Mac 的哪 | 谁能签发 | 有效期 |
| --- | --- | --- | --- | --- |
| **签名材料归档** | 每个 Team 一张 Apple Distribution 证书（含私钥）+ 每个 App 一份 App Store 描述文件 | `/var/rn-build-signing/`（`_rnbuilder` 0700） | 租户的 Account Holder / Admin | 1 年 |
| **上传 Key** | 每个 Team 一把 ASC Team Key（`.p8`），所有 Mac 共用 | `/var/rn-build-upload/<TEAMID>/`（`_rnuploader` 0700） | 租户的 Account Holder / Admin | 不过期，可吊销 |
| **发布密钥** | 签安装包清单的 Ed25519 密钥，自升级的信任根 | 公钥在每台 Mac 的 `/opt/rn-build-agent/release-key.pub`（root 0644）；私钥只在离线机器与密码管理器 | 平台管理员 | 不过期 |
| **`allowed_signers`** | 允许给 RN-App 的 `main` 出包的人的 SSH 签名公钥，提交验签的信任根 | 每台 Mac 的 `/opt/rn-build-agent/allowed_signers`（root 0644） | 平台管理员 | 随人员变动 |

设计来源：`docs/design/ios-mac-builders-home-network-2026-09-18.md` §4.2、§4.4、§4.6、§5.6，未决第 5 条。
形状照 [`../amos/SIGNING_GATE_ROLLOUT.md`](../amos/SIGNING_GATE_ROLLOUT.md)。装机本身看
[`install-macos.sh`](../../internal/machinesetup/install-macos.sh)；部署总览看
[`../DEPLOYMENT.md`](../DEPLOYMENT.md)。

**先读这一段**：Mac 是**池子**——每台都持有**全部租户**的签名材料，任务按机器自报的盘点路由。
所以少给一台机器导一个 Team 的材料，等于那个租户少一台可用的机器；一台都没有时那个租户
根本排不出任务（服务端 409 `NO_BUILDER_FOR_TEAM`）。控制台「平台维护 → 打包机与签名闸」的
机器卡片上直接写着每台缺哪个租户，每次动完材料都去看一眼。

---

## 1. 签名材料归档

### 1.1 为什么私钥是平台生成、一个 Team 只有一张证书

Apple 的原文是「Distribution certificates belong to the team and only one type of each
distribution certificate is allowed per team」，社区对 Apple Distribution 类型的上限说法在
1 到 3 张之间。**按最紧的理解做：一个 Team 一张。** 多台 Mac 各申请一张会把名额用光，之后
再也加不了机器，而建证书本来就要租户的 Admin 到场，不是自动化能做的事。

私钥由**平台在离线 Mac 上生成**，只把 CSR 交给租户去签发。这样私钥从不离开平台，租户那边
也不用在聊天工具里传一个 `.p12` 的口令。

### 1.2 做一个 Team 的归档（该 Team 第一次，或年度续期）

在**离线 Mac**（不联网、FileVault 开着的那一台，与签发布密钥的可以是同一台）上：

```bash
# 1) 生成私钥与 CSR。私钥从这一刻起就不该离开这台机器
openssl req -new -newkey rsa:2048 -nodes \
  -keyout  ios-dist-<TEAMID>-<年份>.key \
  -out     ios-dist-<TEAMID>-<年份>.csr \
  -subj "/emailAddress=<平台运维邮箱>/CN=<租户名> Distribution/C=CN"
chmod 600 ios-dist-<TEAMID>-<年份>.key
```

2. 把 **`.csr`** 交给租户的 Account Holder / Admin，请他们在 developer.apple.com →
   Certificates → `+` → **Apple Distribution** 上传它、下载签发出来的 `.cer` 回给平台。
   （App Manager 角色要额外勾了「Access to Certificates, Identifiers & Profiles」才做得了。）
3. 请同一个人为**每个 App** 生成 **App Store** 描述文件（选这张新证书 + 对应 App ID），下载
   `.mobileprovision` 回给平台。描述文件不是机密，但要和证书一起换。
4. 在离线 Mac 上合成 `.p12`：

```bash
openssl x509 -inform DER -in distribution.cer -out ios-dist-<TEAMID>-<年份>.pem
openssl pkcs12 -export -legacy \
  -inkey ios-dist-<TEAMID>-<年份>.key \
  -in    ios-dist-<TEAMID>-<年份>.pem \
  -out   ios-dist-<TEAMID>-<年份>.p12
# 口令：现场随机生成一段，立刻存进密码管理器，不要用能背下来的
```

`-legacy` 是为了让 macOS 的 `security import` 认得（OpenSSL 3 默认的 AES-256 加密方式，
较老的 Security.framework 读不了）。导入报「MAC verification failed」多半就是缺了它。

5. 打成归档，一个 Team 一个目录：

```text
ios-signing-<TEAMID>-<年份>/
  ios-dist-<TEAMID>-<年份>.p12          ← 证书 + 私钥，口令在密码管理器
  profiles/<bundle id>.mobileprovision  ← 每个 App 一份
  NOTES.txt                             ← 签发日期、到期日、是谁签发的、对应哪些 App
```

6. 进密码管理器：`.p12` 的口令、证书指纹、**到期日**。归档本身放加密卷或密码管理器的附件里。
   **私钥 `.key` 与 `.csr` 留在离线机器上**，不要跟着归档到处走——`.p12` 里已经有私钥了。

### 1.3 分发到每台 Mac

在**每一台** Mac 上（`<TEAMID>` 大写）：

```bash
K=/var/rn-build-signing/rn-signing.keychain-db
P=/var/rn-build-signing/rn-signing.password

# 先解锁。钥匙串建出来时是解开的，但那个状态活不过一次重启——往锁着的钥匙串里 import
# 只会得到 "User interaction is not allowed."
sudo -u _rnbuilder security unlock-keychain -p "$(sudo cat $P)" "$K"

sudo -u _rnbuilder security import ios-dist-<TEAMID>-<年份>.p12 -k "$K" -T /usr/bin/codesign
# 不做下面这一步，codesign 第一次用会弹 UI 授权，而这台机器没有图形会话
sudo -u _rnbuilder security set-key-partition-list -S apple-tool:,apple: -s -k "$(sudo cat $P)" "$K"

sudo install -d -o _rnbuilder -g _rnbuilder -m 0700 /var/rn-build-signing/profiles/<TEAMID>
sudo install -o _rnbuilder -g _rnbuilder -m 0600 \
     profiles/<bundle id>.mobileprovision /var/rn-build-signing/profiles/<TEAMID>/
```

然后**重启代理**——材料盘点在启动时做一次，不重启控制台上看不到变化：

```bash
sudo launchctl kickstart -k system/win.anyfun.rn-build-agent
```

`.p12` 用完从这台 Mac 上删掉（它已经进钥匙串了）。传输过去的那份也删。

怎么确认成功：控制台「平台维护 → 打包机与签名闸 → 构建机」，这台机器的「自报的签名材料」
里出现这个 Team，bundle id 数对得上，「缺 X 租户的签名材料」里不再有它。

### 1.4 年度续期

到期前**一个月**开始，不要等到期当天——控制台在证书还剩 30 天时就开始标黄，那是给这件事
留的时间，不是提醒你最后一周再动。

1. 按 §1.2 做一套新的（新 `.key`、新 CSR、新证书、**每个 App 都要新的描述文件**）。
2. 每台 Mac 按 §1.3 导入新证书、放新描述文件。**新旧并存**：钥匙串里两张证书都在，
   描述文件按 bundle id 同名覆盖（代理按 `application-identifier` 找，指向新的那份）。
3. 全部 Mac 都换完、并且各排一条任务验过之后，再删旧的：

```bash
sudo -u _rnbuilder security find-certificate -a -c "Apple Distribution: <租户>" -Z "$K" | grep SHA-1
sudo -u _rnbuilder security delete-certificate -Z <旧证书的 SHA-1> "$K"
```

4. 请租户在 developer.apple.com 上 Revoke 旧证书。**顺序不能反**：先 revoke 再换，中间所有
   Mac 都签不出包。

### 1.5 不要了怎么销

租户下线、或者证书疑似泄露时：

1. 请租户 **Revoke** 那张 Distribution 证书（developer.apple.com）。这一步让已经泄露的私钥
   再也签不出能被 Apple 接受的包，是唯一真正起作用的一步，先做。
2. 每台 Mac：`security delete-certificate -Z <SHA-1>`，删 `profiles/<TEAMID>/` 整个目录，
   删 `/var/rn-build-upload/<TEAMID>/`，重启代理。
3. 密码管理器里那条标成「已吊销 + 日期」，**不要直接删**——出事时要能回答「当时是哪一张」。
4. 离线机器上的 `.key`、`.csr`、`.p12`：`rm -P`（多次覆写）之后再删目录。
5. 控制台上确认没有任何一台机器还报着这个 Team。

**泄露的判定**：`_rnbuilder` 跑着 pnpm、CocoaPods 与几千个依赖的代码，而它能解开这个钥匙串——
也就是说**一次依赖投毒就等于全部 Team 的证书私钥泄露**。这是 iOS「签名与构建分不开」的结构性
问题，本方案没有解决它，只做到让这把私钥在这台机器上**没有出口**（执行进程一把 ASC Key 都拿不到，
建不了 Ad Hoc 描述文件，传不了 build）。真出了这种事，按上面五步全部租户走一遍。

---

## 2. 上传 Key

**每个 Team 一把**，所有 Mac 共用，角色 **Developer**（能上传 build 与管内部测试组的最低角色）。

> 2026-09-19 从「每台 Mac 一把」改成「每 Team 一把」。按机器分是想让丢一台只吊销一把，
> 但**证书私钥本来就是全机共用的**：丢一台 Mac 就得在 Apple 后台吊销证书、重签、全机重发，
> 那一刻所有 Mac 都停了，上传 Key 分不分机器省不下这次停机。而按机器分的代价是天天付的
> ——ASC Key 只能在租户自己的 Apple 账号里建，按机器分就要求租户知道平台有几台打包机。
> 理由记在设计 `ios-signing-material-distribution-2026-09-19.md` §5。

租户的 Account Holder / Admin 在 App Store Connect → Users and Access → Integrations →
App Store Connect API → Team Keys → `+`，角色选 Developer，**`.p8` 只能下载一次**。

> **2026-09-19 起有更省事的一条**：走完第 6 节那三步之后，这把 Key 可以在控制台上传——
> 租户的「iOS 打包与分发」页 → iOS 签名材料 → 上传 Key，填 issuer id 与 key id、选 `.p8`，
> 浏览器加密后上传，**所有 Mac** 下一轮认领时自己装。下面这段手工放的做法留着兜底
> （没登记平台密钥、或者机器还没换到含 D 期的版本时用它）。

放到那台 Mac：

```bash
sudo install -d -o _rnuploader -g _rnuploader -m 0700 /var/rn-build-upload/<TEAMID>
printf '{"issuerId":"%s","keyId":"%s"}\n' "<ISSUER>" "<KEYID>" \
  | sudo -u _rnuploader tee /var/rn-build-upload/<TEAMID>/key.json >/dev/null
sudo install -o _rnuploader -g _rnuploader -m 0600 \
     AuthKey_<KEYID>.p8 /var/rn-build-upload/<TEAMID>/
sudo launchctl kickstart -k system/win.anyfun.rn-build-agent
```

代理启动时会对每把上传 Key 做一次**只读探测**，结果显示在控制台的机器卡片上：

- **上传 Key 可用**：这把 Key 能用 Build Uploads 那套端点，第一次构建就能传。
- **上传 Key 权限不够**：Developer 角色在这套端点上不够用，把这个 Team 的 Key
  **换成 App Manager 角色的 Team Key**。换完重启代理再看。
- **上传 Key 探测失败**：网络不通，或者 `key.json` / `.p8` 写错了。

探测存在的意义是**在第一次构建之前**知道传不上去：上传是一次构建的最后一步，等到那时才发现
权限不够，已经烧掉一个 build 号和半小时。

**吊销**：ASC 后台 Revoke 那把 Key，然后删掉每台 Mac 上的 `/var/rn-build-upload/<TEAMID>/`。
一台 Mac 报废、被偷、或者要退役，要做的是一整套：控制台吊销机器令牌、Apple 后台吊销
**证书**（它在那台机器的钥匙串里）并重签重发、ASC 吊销上传 Key 并重新上传一把。
证书那一步本来就要全平台做，所以上传 Key 跟着一起换不额外多停一次机。

---

## 3. 发布密钥（自升级的信任根）

自升级是整个方案里**唯一一条「服务端能往 Mac 上放可执行代码」的路**，而每台 Mac 上放着全部
租户的签名材料。只校验 sha256 没有意义——那个 sha256 也是服务端给的。所以清单要由一把
**服务端手里没有**的私钥签过。

### 3.0 当前这一把

| 公钥字节 sha256 | 生成 | 备注 |
| --- | --- | --- |
| `5037b2f8337739f54335482ff64a31934fee2c7873e793beacc13081095d533d` | 2026-09-19 | 平台管理员一人持有；公钥在 `deploy/build-agent-macos/release-key.pub` |

> 这张表由 `TestReleaseKeyTableMatchesTheDeployedKey` 守着：表里那一行与仓库里
> `release-key.pub` 算出来的指纹对不上就编译不过。换密钥时两个文件要在**同一个提交**里改。

在它之前生成过四把并随即换掉（`b60f0ccf…`、`395937be…`、`5aebeaf4…`、`bac1ec56…`）。**四把都从未部署**：没有任何 Mac 装过
机，也没有一份被任何机器接受过的清单，所以每次都是直接替换而不是 §3.4 的轮换——没有序号水位线
要考虑，也不用去任何机器上换公钥。

**这个便利只在第一台 Mac 装机之前成立。** 一旦有机器装了，换密钥就必须走 §3.4：先跑遍每台机器
换掉 `/opt/rn-build-agent/release-key.pub`，再用新私钥签，顺序反了它们会集体拒绝升级。

> **公钥文件的格式换过一次（2026-09-18）。** `release-key.pub` 现在是 OpenSSH 的一行公钥
> （`ssh-ed25519 AAAA… rn-release-key`），与 `allowed_signers` 里的写法一致——这台机器上两个
> 信任根因此是同一种格式。`bundle-sign key create` 直接产出这个格式。
>
> 手上如果有旧格式的 `.pub`（一行裸 base64），`bundle-sign verify --pub` 会说"不是一行
> ssh-ed25519 公钥"。不用动私钥，重新导出一份即可：
>
> ```bash
> /tmp/bundle-sign key public --key <私钥目录>/release-key.ed25519 > <私钥目录>/release-key.pub
> ```
>
> 它同时把指纹打在 stderr 上，顺手和密码管理器里的值对一眼。

### 3.1 生成（全平台一次）

#### 先把 `bundle-sign` 弄到那台机器上

这一节和 §3.2 的每一条命令都要在**离线机器**上跑，而那台机器上未必有仓库，也未必装了 Go。
三条路，按那台机器的实际情况挑：

| 情况 | 做法 |
| --- | --- |
| 有仓库、有 Go | `cd signing && go build -o /tmp/bundle-sign ./cmd/bundle-sign`（`signing/` 是独立的 Go module，**必须在那个目录里**构建，仓库根目录构建会失败） |
| 没仓库但能联网取一次 | 克隆仓库再按上一条构建 |
| 真气隙（不联网、无 Go） | 在一台联网机器上交叉编译，用 U 盘拷过去：`cd signing && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o bundle-sign ./cmd/bundle-sign`（Intel Mac 用 `GOARCH=amd64`），**同时把它的 sha256 一起带过去，在离线机器上核一遍**再用 |

> **手里那份旧的 `bundle-sign` 不能继续用来签。** 2026-09-18 之后签名换成了 OpenSSH 的
> `SSHSIG` 封装（见 §3.2），旧二进制产出的是旧格式，服务端会以"不是一个 SSH 签名块"拒掉。
> 旧的也没有 `key public` 这个子命令。每次要签之前，确认手里这份是当前提交构建出来的。

#### 生成

```bash
/tmp/bundle-sign key create --out ~/rn-release-key
```

它会打印：

```
private key: ~/rn-release-key/release-key.ed25519 (0600, keep it offline and in the password manager)
public key:  ~/rn-release-key/release-key.pub
public key sha256: <64 位十六进制>
```

- **私钥**：留在这台离线机器上，同时把内容存进密码管理器（保管方式与离线恢复密钥相同）。
  离线机器坏了而密码管理器里没有备份，就再也签不出更高序号的清单——所有 Mac 停在当前版本。
- **`public key sha256`**：**记进密码管理器**。装机时 `install-macos.sh --release-key-sha256`
  要的就是它，每台 Mac 的每次装机都拿它做一次带外核对。

  > 这个值是**公钥字节**（base64 解码后那 32 字节）的摘要，**不是 `release-key.pub` 这个
  > 文件的摘要**——两者不同，别用 `shasum -a 256 release-key.pub` 去算。同一个值还出现在
  > 清单签名的 `publicKeySha256` 字段和控制台「批准打包机程序版本」那张卡片上，三处一致，
  > 你在控制台看到的就是密码管理器里记的那个。
  >
  > **装机只要这一个值。** 归档摘要与包内每个文件的摘要（含 `allowed_signers`）都由
  > `install-macos.sh` 从一份离线签名背书的清单里取：人给的指纹认出公钥 → 公钥验清单 →
  > 可信清单里的摘要核对归档与每个文件。让人抄三个值不比抄一个更安全，多两次抄写只是多
  > 两次抄错的机会，而其中归档摘要那一个还得每次发版去翻 CI 日志找对应的版本。
- **公钥文件**：OpenSSH 的一行（`ssh-ed25519 AAAA… rn-release-key`）。放进仓库的
  `deploy/build-agent-macos/release-key.pub`，`build-bundles.sh` 会把它打进 darwin 那组安装包
  （没有它只是警告，但 `install-macos.sh` 会拒绝安装）。丢了可以从私钥重新导出，不用碰密钥：

  ```bash
  /tmp/bundle-sign key public --key ~/rn-release-key/release-key.ed25519 > release-key.pub
  ```

**已定不做双人签名**（设计 §10 第 3 条）：由平台管理员一人持有。

### 3.2 每次发版：签一份清单

CI 产出 `manifest.json` 与三个归档、部署到服务器之后，在离线机器上：

`bundle-sign sign` 只读 `manifest.json`——三个归档不用拷过去。清单里已经是每个归档与每个
文件的 sha256，签了清单就等于签了它们。

> 想要更强的保证（"我签的不只是 CI 说的那串数字"），在离线机器上用**同一个提交**跑一遍
> `deploy/setup/build-bundles.sh`，再 `diff` 两份 `manifest.json`：一致说明 CI 没有夹带。
> 前提是 Go 版本与 CI 完全相同（`build-bundles.sh` 的可复现性建立在这上面），版本不同会
> 得到不同的二进制、对不上，别误判成被篡改。

```bash
# 只需要 manifest.json；签完把 manifest.sig 放回服务器同一个目录
/tmp/bundle-sign sign --key ~/rn-release-key/release-key.ed25519 \
                      --dir  ./machine-bundles/<提交> \
                      --sequence <比上一次大>
# 产出 ./machine-bundles/<提交>/manifest.sig，把它放回服务器同一个目录
/tmp/bundle-sign verify --pub ~/rn-release-key/release-key.pub \
                        --dir ./machine-bundles/<提交> \
                        --expect-commit <提交>
```

**序号只增不减，记在密码管理器里。** 每台 Mac 记住自己见过的最高值（root 拥有的
`/opt/rn-build-agent/upgrade-sequence`），低于它的清单一律拒绝——这是防「攻破服务端后把机器
降回一个有已知漏洞、但当初确实被签过的旧版本」的那道闸。

**要回滚**：用**更高的序号**再签一份指向旧提交的清单。回滚因此是一次显式的、有签名的动作，
不是在数据库里改一个值。

没有 `manifest.sig` 时，`GET /v1/build-agent/bundle` 一律回 503，什么都不给——免得一台机器在
「清单还没签」的窗口里下到一份没人背书的程序。

**签名放在 `manifest.sig` 的 `signature` 字段里，是一个 OpenSSH 签名块**（`SSHSIG`，就是
`ssh-keygen -Y sign` 那个格式，namespace 固定 `rn-machine-bundles`）。被签的字节没变，仍是
每字段一行的规范化内容，不是 JSON。

换成这个格式是为了**装机脚本里不必自带密码学**：新 Mac 要在下载安装包之前验这份签名，那时
机器上除了脚本自己没有任何可信的东西。用这个格式，验签就是系统自带的一条命令：

```bash
ssh-keygen -Y verify -f <当场生成的 allowed_signers> -I release-key \
           -n rn-machine-bundles -s manifest.sig < <被签的字节>
```

运维在执行前要把那个脚本从头读一遍、再与 CI 日志比对 shasum——那是整条链子的第一环，靠的是
"能读完"。一段椭圆曲线运算没人读得动，比对摘要就只剩比对、没有"我知道我在跑什么"。

### 3.3 放开升级

签完只是"可以升"，还要在控制台「平台维护 → 打包机与签名闸 → 构建机 → 批准打包机程序版本」
点一次批准。那张卡片先显示现在部署的提交、签名序号、签名时间与发布公钥指纹，核对无误再批。

可以先批、看一台 Mac 升上去没问题，再放开——批准与不批准都只决定**什么时候升**，挡住恶意
程序的始终是每台 Mac 自己验的那份离线签名。

### 3.4 轮换

私钥疑似泄露，或者保管人交接：

1. `bundle-sign key create --out <新目录>` 生成新的一把（**新目录**：`key create` 用 `O_EXCL`
   写私钥，不会盖掉旧的）。
2. 新公钥进仓库、进下一版安装包；新的 sha256 进密码管理器。
3. **每台 Mac 都要重装或手工换 `/opt/rn-build-agent/release-key.pub`**（root 0644），并按新的
   sha256 核对。这一步没有自动化——自动换信任根就等于没有信任根。
4. 换完之后用新私钥签一份序号更高的清单。旧私钥销毁（`rm -P`），密码管理器里那条标成
   「已轮换 + 日期」。

轮换期间新旧不能并存：Mac 只认它本机那一把公钥。所以顺序是"先换遍所有 Mac 的公钥，再用新私钥签"。

---

## 4. `allowed_signers`（提交验签的信任根）

Android 侧，构建机被喂了恶意代码，产物还要过签名闸。iOS 侧没有这一环：`.ipa` 在 Mac 上签完
直接进 App Store Connect。于是**谁能往 RN-App 的 `main` 推代码，谁就能在全部 Mac 上以
`_rnbuilder` 身份执行代码、拿到全部 Team 的证书私钥**。

这道闸在控制进程、检出之后、交给执行进程之前：

```bash
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/opt/rn-build-agent/allowed_signers \
    verify-commit <sha>
```

### 4.0 当前名单

| principal（= 那个人的 `git config user.email`） | 加入 | 备注 |
| --- | --- | --- |
| `rn-app-signing-a@gmail.com` | 2026-09-18 | 平台运维；密钥 `~/.ssh/rn-app-signing-A`，仅用于签提交 |

**现在只有一把。** 这把密钥所在的机器丢了、或者要换密钥时，在所有 Mac 的
`allowed_signers` 都换完之前**打不出 iOS 包**——队列会停在「排队中」，而不是报错。
第二个人(或同一个人在另一台机器上的第二把)什么时候加进来，决定这个单点什么时候消失。

### 4.1 文件长什么样

一行一个允许给 `main` 出包的人，格式是 OpenSSH 的 allowed_signers：

```
alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
bob@example.com   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…
```

邮箱要与那个人 `git config user.email` 的值一致，否则 `verify-commit` 认不出来。

权限要求：文件与**它所在的目录**都必须是 root 所有、组与其他人不可写。目录可写的话，换掉
这个文件只是一次 `rename`，这道闸就不成立了。

代理**启动时**核对一次，不合规只打一条 `builds will fail until this is fixed` 的错误日志，
不退出（新机器还没克隆镜像时也要能先把公钥登记上去）；**每条任务**在检出之后再核一次，不合规
那条任务失败。所以权限改坏了的症状是"每一条任务都在检出之后失败"，而日志里那句话在启动时就
已经写下了——出这种事先去看代理的启动日志。

`BUILD_AGENT_ALLOWED_SIGNERS` 这个键在 iOS 机器上是**必填**的（`loadConfig` 挡着，不填直接
启动失败）；Linux 构建机上不填只是告警。

```bash
sudo install -o root -g wheel -m 0644 allowed_signers /opt/rn-build-agent/allowed_signers
ls -ld /opt/rn-build-agent /opt/rn-build-agent/allowed_signers    # 都应该是 root、drwxr-xr-x / -rw-r--r--
```

### 4.2 加人、减人

`allowed_signers` **不从服务端取、不随任务下发**。轮换等于重新分发文件，与证书归档同一条运维
路径：改仓库里的 `deploy/build-agent-macos/allowed_signers` → 下一版安装包带上新的 → 每台 Mac
装机或手工 `install` 覆盖。

**它的摘要不用单独记**：装机时由 `install-macos.sh` 从验过签的清单里核对（§3 那条链子），
运维只带发布公钥的指纹。

**减人要当天做**：一个已经离开的人的公钥还在这个文件里，等于他推一个签过名的提交就能在所有 Mac 上
跑代码。

### 4.3 配套的仓库设置（R3，在 GitHub 上做）

- RN-App 的 `main` 开分支保护「**要求签名提交**」。
- 合并方式限 **rebase / fast-forward**，让落到 `main` 上的每个提交都是开发者本地签的。
- **不接受 GitHub 网页合并**：web-flow 的签名公钥不进允许列表，网页上点出来的合并提交在 Mac 上
  验签失败、任务失败。

没有这三条时这道闸验的是「开发者有没有自己签」，不是「仓库强制签」——有人直接推一个没签的提交
上去，任务会失败（这是对的），但它挡不住有人绕过分支保护。

### 4.4 它挡不住什么

挡「未经允许的人改了 `main`」。**挡不住**「允许的人被钓鱼」，也**挡不住依赖投毒**——后者直接
进入 `_rnbuilder`，§1.5 那一段已经如实写明。

---

## 6. 材料分发密钥（密文分发）

设计见 [`ios-signing-material-distribution-2026-09-19.md`](../../docs/design/ios-signing-material-distribution-2026-09-19.md)。
它把第 1、2 节那些"由人逐台放"的材料改成**控制台传一次、每台 Mac 自己取**，而服务端全程
只见密文。

**2026-09-19 全部上线**（A–D 期）。上手顺序是三步，缺一步后面那步没法做：

| 步 | 做什么 | 在哪 |
| --- | --- | --- |
| 1 | `ios-material keygen` 生成两把平台密钥，私钥进密码管理器 | A 机（§6.1） |
| 2 | 两个**公钥**登记到控制台「平台维护 → iOS 签名材料」 | 控制台（§6.2） |
| 3 | 两把**私钥**放到每台 Mac 上，核对指纹 | 每台 Mac（§6.3） |

三步走完，证书、描述文件、上传 Key 就在**租户的「iOS 打包与分发」页**上传一次、机器自己取
（平台的「iOS 签名材料」页只放两把平台公钥和一张只读总览——上传要 Apple Team ID，而那个值
写在租户页上）。第 1.3 节与第 2 节那套人工放材料的路留着兜底，没走完这三步时仍然按它做。

### 6.1 生成（全平台一次，在 A 机上）

#### 先把 `ios-material` 弄到那台机器上

和 `bundle-sign` 同一件事（§3.1），三条路挑一条。**注意它是 2026-09-19 才有的**，手里那份
旧检出里没有这个子命令，要先把仓库更到当前 main。

| 情况 | 做法 |
| --- | --- |
| 有仓库、有 Go | `cd <仓库>/signing && go build -o /tmp/ios-material ./cmd/ios-material`（`signing/` 是独立的 Go module，**必须在那个目录里**构建） |
| 没仓库但能联网取一次 | 克隆仓库再按上一条构建 |
| 真气隙 | 在联网机器上交叉编译，用 U 盘拷过去：`cd signing && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o ios-material ./cmd/ios-material`（Intel Mac 用 `GOARCH=amd64`），**把 sha256 一起带过去核一遍**再用 |

#### 生成

```bash
/tmp/ios-material keygen --out ~/rn-ios-material-keys
```

它会打印两块，每块三行（私钥路径、公钥、指纹）：

```
builder
  私钥   ~/rn-ios-material-keys/builder.x25519（0600，立刻进密码管理器）
  公钥   <base64>
  指纹   <64 位十六进制>
uploader
  …
```

**私钥不会被打印**，只写进那两个 0600 的文件——要存进密码管理器得自己 `cat` 它们。
再跑一次 `keygen` 不会覆盖已有私钥（覆盖等于把已经发出去的材料全部作废），要换密钥得先
自己把旧文件挪走，并且清楚代价：已存材料全部要重新加密上传，每台 Mac 都要重放新私钥。

产出两把，**按角色分开**：

| 文件 | 给谁 | 解什么 |
| --- | --- | --- |
| `builder.x25519` | 每台 Mac 的 `_rnbuilder` | Distribution 证书（`.p12` + 口令）、描述文件 |
| `uploader.x25519` | 每台 Mac 的 `_rnuploader` | App Store Connect 上传 Key（`.p8`） |

合成一把的话，拿到构建账户就同时拿到了上传能力——而那正是 Mac 上三个账户分开要挡的事。

### 6.2 立刻要做的三件事

1. 两把**私钥进密码管理器**，连同 `keygen` 打出来的指纹；
2. 两个公钥（`keygen` 打出来的那两行 base64）登记到控制台「平台维护 → iOS 签名材料 →
   平台密钥」，指纹与 `keygen` 打的对一遍；
3. 确认密码管理器里有了之后，删掉 A 机上的私钥文件（或者让它留在这台不联网的机器上——
   但**绝不能**进任何联网的机器、更不能进服务端）。

> **私钥一个字节都不要经过服务端。**服务端只转发它读不懂的密文，这是整套设计的前提：
> 它被攻破也变不出能用的签名材料。私钥要是从服务端下发，这条前提当场作废。

### 6.3 装机时把私钥放到 Mac 上

```bash
sudo bash install-macos.sh --server <API> --code rne_… \
     --release-key-sha256 <发布公钥指纹> \
     --material-key-builder  /path/to/builder.x25519 \
     --material-key-uploader /path/to/uploader.x25519
```

两个参数是**这台机器上的文件路径**，内容从密码管理器取（scp 过去、或者现场 `cat >` 一份，
装完删掉）。脚本会：

1. 查形状（一行 base64、解出来 32 字节）；
2. 各装各的账户：`builder` 那把归 `_rnbuilder`，`uploader` 那把归 `_rnuploader`，都是 0600；
3. **把两个公钥指纹打出来**，与控制台「平台维护 → iOS 签名材料」上登记的那两把核对。

> 对不上就是私钥放错了。不核对的话，表现是"材料下来了但解不开"——而那条错要等第一次下发
> 才出现，还容易被当成服务端的问题。

不给这两个参数照样装得完，只是这台机器不会自动收材料，证书与描述文件仍按第 1.3 节人工放。

#### 已经装好的机器怎么补

装机时没给这两个参数（mac-01 就是这样装的），不必重装——两把私钥各放一个文件、各归一个
账户就行。以 root 在那台 Mac 上：

```bash
sudo install -o _rnbuilder  -g _rnbuilder  -m 0600 builder.x25519  /var/rn-build-signing/material-key.x25519
sudo install -o _rnuploader -g _rnuploader -m 0600 uploader.x25519 /var/rn-build-upload/material-key.x25519
```

再照装机脚本那样核对指纹（这两条各自以对应账户跑，因为私钥只有它读得到）：

```bash
sudo -u _rnbuilder  /opt/rn-build-agent/build-runner material-key-fingerprint --signing-dir /var/rn-build-signing
sudo -u _rnuploader /opt/rn-build-agent/ios-upload --material-key-fingerprint --keys /var/rn-build-upload
```

两个值与控制台上登记的那两把对得上就成了：控制进程下一轮认领（最多两分钟）就会去取材料。
**放完把源文件删掉**——一把明文私钥留在 `/tmp` 或家目录里，比装到这台机器上那份还容易被顺走。

> 这两个子命令是 2026-09-19 随 D 期一起进的。机器上那版程序更早的话，先按运维手册 §5 把
> 版本换上去，否则会报"不认识的子命令"。

### 6.4 先试一把（可选）

工具现在就能用，可以拿一份假材料走一遍，确认你手上的密钥是对的：

```bash
printf 'a-fake-password' | /tmp/ios-material encrypt \
  --pub ~/rn-ios-material-keys/builder.x25519.pub \
  --team J4JDFC8LCC --kind certificate --p12 /path/to/some.p12 --out /tmp/cert.box.json

/tmp/ios-material verify --key ~/rn-ios-material-keys/builder.x25519 --in /tmp/cert.box.json
```

`verify` 只打印种类、Team、bundle id 这些**非机密**字段——口令与私钥它一个字都不会印。
拿 `uploader.x25519` 去解这份证书会失败，那是对的（§6.1 那条隔离）。

## 5. 一台 Mac 退役时的清单

按顺序做，每一步都要做完：

1. 控制台吊销这台机器（机器令牌立刻失效，它再也领不到任务）。
2. 每个 Team 的上传 Key 在 ASC 后台 **Revoke**。
3. GitHub 上删掉这台机器的 deploy key。
4. 机器本体：`fdesetup` 的恢复密钥仍在密码管理器里的话，抹盘重装最省事；不抹盘就至少
   `rm -P` 掉 `/var/rn-build-signing`、`/var/rn-build-upload`、`/var/rn-build-agent`。
5. 密码管理器里这台机器那条标成「已退役 + 日期」。
6. 控制台上确认剩下的机器里，每个租户都至少还有一台报着它的材料——**这一步最容易忘**，
   退掉最后一台持有某个 Team 材料的 Mac，那个租户就排不出任务了。
