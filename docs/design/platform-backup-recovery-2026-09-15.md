# 设计：打包服务的故障恢复备份

状态：Draft v7（2026-09-15）。方向自 v5 起没变——**由打包机自己产出一份自带恢复说明的加密备份包**，平台管理员在控制台手动或定时触发、可下载，人只保管离线私钥。

- **v6** 是三轮对抗性评审之后的修订，改动集中在三处：包里要装的东西不够（拿到包也装不回去）、容器只有保密性没有真实性（拿公钥就能伪造一个包）、状态机按 v5 的文字实现第一次跑就坏。
- **v7** 把门限从「两个人缺一不可」换成 **2-of-3（三个人，任意两个就能开）**，并补齐六处会让开发卡住的契约缺口——其中最要紧的是**打包机上报给服务端的元数据**（§4.7），外层清单和两份恢复说明都靠它生成。

逐条见 §16 的修订记录。本文档已具备开工条件，落地顺序见 §13。

数据库备份不在本方案范围内。

## 1. 要防的是什么

App 的安装包必须用签名密钥签。这把钥匙丢了，就再也发不出能升级的新版本——老用户装不上去，只能卸载重装，钱包数据全没。

这把钥匙存在数据库里，但是加密的。**能解开它的只有打包机上的一个小文件**（`/var/lib/rn-build-agent/agent-key`，0600）。服务端故意读不到它——签名密钥能放进数据库，靠的就是这条。

所以：**打包机硬盘坏了，数据库里的密钥全在，但没有任何东西能打开它们。** 所有 App 从此发不出新版本，无法补救（换签名证书 = Android 认作另一个 App）。

这就是本方案唯一要防的事。

## 2. 一个绕不过去的前提

**任何机器能自动打开的备份，攻破那台机器的人也能打开。** 所以必须有东西存在所有机器之外。

就一样：**恢复私钥**。生成一次，存到机器之外，此后不再碰。三个人各一把，任意两把能开（§2.1）。

除此之外的一切都可以自动化——这是与前几版的根本差别：前几版让人抄八样东西进两个信封，现在让打包机把那八样自己打包进去，人只保管钥匙。

### 2.1 三把钥匙，三个人，任意两把能开

备份要**三个人各拿一把钥匙，任意两个人凑到一起就能打开**（2-of-3）。一个人单独拿到包，什么都读不到。

做法很直白：三个人两两配对有三组——甲乙、甲丙、乙丙。**每一组产出一个包，桶里并排放三个。** 每个包还是「外层套内层」两层锁，外层用这一组里一个人的公钥、内层用另一个人的，所以开一个包必须这两个人都在。出事那天，看还剩哪两个人，就开对应那个包。

```
<seq>-AB.rnbk    外层封给 B，内层封给 A   —— 甲和乙一起开
<seq>-AC.rnbk    外层封给 C，内层封给 A   —— 甲和丙一起开
<seq>-BC.rnbk    外层封给 C，内层封给 B   —— 乙和丙一起开
```

**容器格式一个字都不用改**，只是同一份内容封三次。代价是三倍存储：整包约 50 MB（其中两个 Go 二进制占 35 MB），三份 150 MB，按天备份保留 90 天约 13 GB——可以忽略。打包机侧多做一次内层封装（约 15 MB），几秒钟的事。

**为什么是 2-of-3 而不是 2-of-2。** 设某个持有人在**需要用的那一刻**失效的概率为 `p`：

| 方案 | 打不开的概率 | `p = 15%` 时 | 一个人能单独拿到吗 |
|---|---|---|---|
| 1-of-1（一把钥匙） | `p` | 15% | 能 |
| 2-of-2（两把，都要） | `2p − p²` | 28% | 不能 |
| **2-of-3（三把，要两把）** | **`≈ 3p²`** | **6%** | **不能** |

2-of-2 在可用性上恒定比 1-of-1 差近一倍（比值 `2 − p`，没有交叉点）——它拿可用性换安全性。2-of-3 **同时优于另外两个**：比一把钥匙更不容易丢，又仍然一个人拿不到东西。这是这一版换过来的全部理由。

`p` 不只是「U 盘坏了」，它至少有三个分量：**介质丢失**、**口令丢失**、**人在那一刻联系不上**（离职、住院、在飞机上）。所以下面三条是配套要求，少一条上面那个 6% 就不成立：

1. **每人各存两份，放两个不同的物理位置**（压住介质丢失）。
2. **两份副本的口令不许共用同一条密码管理器记录**（压住口令丢失）。至少把口令另抄一份纸质的，和第二份介质放在一起、但不在同一个抽屉。
3. **每月演练的判据是每个人各自独立取出自己那份、独立输入口令成功**，不是「包最后开了」。少了这一条，口令丢失会静默到真出事那天。

**范围要说准**：双重保护只对**云存储里那三个对象**成立。产出过程中服务端手上必然经手过内层密文（§4.1 第 4 步），那个 blob 是**只封给一个人**的。所以「服务端被攻破 + 那个人的私钥泄露」这条路径上，另外两把钥匙贡献为零。不要读成「内层在任何地方都受双重保护」。

**降级模式**：只配两把公钥就退回 2-of-2（产出一个包），只配一把是**单钥过渡模式**（单层，控制台显著标出）。不支持四把以上——`C(4,2)=6` 个包，人的流程撑不住。

### 2.2 钥匙怎么到三个人手上

**私钥不分发。每个人在自己的机器上生成自己那一对，只把公钥交出来。** 公钥不是秘密，走任何渠道都行；私钥从生成那一刻起就没离开过本人的机器，所以「怎么安全地把私钥送过去」这个问题根本不存在。

三个人各自在自己电脑上跑（互相不用碰面）：

```bash
# 生成私钥，会提示设一个密码；私钥文件本身被这个密码保护
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -aes-256-cbc -out my-recovery.key

# 导出公钥——只有这个文件交出去
openssl rsa -in my-recovery.key -pubout -out my-recovery.pub

# 记下指纹，后面核对用（输出就是裸 hex，可以直接和控制台比对）
openssl rsa -in my-recovery.key -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

运维把三把公钥填进**两边**的配置，每把占一个固定槽位 **A / B / C**（§8.3）。槽位不是身份，只是给包命名用的记号；控制台上每个槽位显示指纹和「由谁保管」，那一行由运维填。三个人**各自核对一眼自己那个槽位的指纹跟手上记的一致**——防止填错、填串。

**槽位一旦分配就不要重排。** 包的名字（`<seq>-AB.rnbk`）和历史备份绑死在槽位上，重排会让「哪个包要谁的钥匙」这件事在历史记录上全部错位。换人是换某个槽位上的公钥（§2.5），不是挪槽位。

#### 四个指纹，四个定义，不能混

这套系统里有四种公钥，它们的指纹算法**不一样**，控制台上必须分区显示、各自带标题。混在一起是核对仪式假通过或假失败的直接原因——同一把私钥用三种自然写法（DER SPKI / DER PKCS#1 / 直接哈希 PEM 文件）会得到三个完全不同的值。

| 指纹 | 是什么 | 定义 | 谁核对 |
|---|---|---|---|
| **恢复公钥 A / B / C** | 三个持有人的 RSA 公钥 | **DER 编码的 SubjectPublicKeyInfo 的 SHA-256，小写 hex，64 字符**；服务端侧 `x509.MarshalPKIXPublicKey` + `sha256` | 三个持有人各自核对自己那把 |
| **备份签名公钥** | 打包机对备份包签名用的 Ed25519 公钥（§4.3） | 同上，DER SPKI 的 SHA-256，64 字符 | 三个持有人**都要抄一份**，见下 |
| **打包机公钥** | 既有的 X25519 公钥，用来封签名密钥盒子 | **既有实现不改**：原始公钥字节的 SHA-256 **截断到 16 字符**（`internal/buildkeystore/recipient.go:50-56`） | 上传签名密钥的人 |
| **`agent-key` 指纹** | 恢复后核对身份文件放对没有 | **就是上一行那个值**——`agent-key` 的公钥即打包机公钥。`manifest.agentKeyFingerprint` 与 `build-agent show-key` 的输出都用这个 16 字符形式 | 恢复的人（§7.2 第 4 步） |

最后两行是同一个值的两种用途，写在一起是为了让实现者不要再发明第三种算法。**`manifest.agentKeyFingerprint` 与 `show-key` 必须逐字节相同**，否则 §7.2 第 4 步的核对永远对不上——那一步是「身份文件放没放对」唯一的检查。

`manifest.recipients[]`、`meta.recipient`、控制台显示、上面那条 `openssl` 命令的输出，四处对恢复公钥必须是同一个值。

**三个人在同一次核对里还要各自抄下备份签名公钥的指纹。** 它是「这个包确实是我们那台机器产出的」在两台机器都没了之后唯一还站得住的锚点（§4.3）。一行 64 个字符，和自己那把的指纹记在同一张纸上。


### 2.3 每个人怎么保管自己那把

**必须存两份，放两个不同的地方。** 三把里丢掉两把，全部备份就永远打不开。

推荐：两个加密 U 盘，分别放在两个物理位置；**口令不要只存在密码管理器的一条记录里**（§2.1 第 2 条），另抄一份纸质的和第二份介质分开放。**私钥文件和它的口令不要放在同一个地方**——那就退化成一把钥匙了。

不要放的地方：公司共享盘、即时通讯的收藏、云笔记、几个人共用的密码库。

**三个人不要把自己那份放在同一栋楼里。** 2-of-3 防的是「失去一个人」，如果三份都在一个机房或一个办公室，一场火灾就同时带走三把，那这个方案退化成零。

### 2.4 配好之后必须马上验一次

**这一步不能跳。** 配完立刻手动跑一次备份，然后**三组配对全部各开一次**——不是只开一个包。

理由很实际：三个包是三次独立的封装，任何一个槽位填错、填串、公钥贴漏一段，都只会让**那一个包**打不开，而它恰恰是你真出事那天唯一能用的那个。三组都验过，才算这套东西配对了。

之后每月按 §12 第 2 级轮着来：这个月开 AB，下个月开 AC，再下个月开 BC。一个季度正好把三组和三个人都走一遍，顺带确认每个人都还在、钥匙都还找得到。

### 2.5 人员变动与不可用

**人走了**：新人生成自己的一对，公钥换进**原来那个槽位**（不要挪槽位，§2.2），重新跑一次备份，然后**删掉旧备份**——旧备份用旧私钥还是能开的，离职的人手上那把不会自动失效。

注意换一个人会同时作废**两个**包（他参与的那两组），所以换完必须立刻重跑一次备份，不能等下一次定时。

**三个人里失去一个**：不影响，剩下两个人的那个包照常能开。这正是换成 2-of-3 买到的东西。**但要立刻补上第三个人**——只剩两个人时你实际处在 2-of-2，可用性已经掉回去了。

**失去两个人**：备份包就是一堆打不开的字节。这是 2-of-3 的边界，没有别的兜底。

#### 从 2-of-2 升到 2-of-3

系统一开始可以只配两把跑（§8.3），第三把以后补。补的时候：

1. 第三个人在自己机器上生成一对，只交出公钥（§2.2），**同时抄下打包机备份签名公钥的指纹**——另外两个人早就抄过了，他不抄就没法独立验一个包是不是真的。
2. 公钥填进**两边**配置的槽位 C，两侧都重启。
3. **立刻手动跑一次备份。** 不跑的话桶里还是只有 AB 那一个包——`AC` 和 `BC` 要等到下一次产出才存在，而在那之前你名义上是 2-of-3、实际还是 2-of-2。这一条最容易漏，因为配置改完控制台就显示 `2-of-3` 了。
4. 按 §2.4 把**新出现的那两组**（AC、BC）各开一次验掉。AB 那一组之前验过，不用重来。

**历史备份不会变成三个包。** 补槽位之前产出的那些，桶里永远只有 AB 一个对象；控制台的记录里每一条展开几行，看的是那一次的 `objects`（§8.4），不是当前的门限模式。所以真出事时挑包要看那一条记录实际有哪几组，别按当前模式想当然。

v5 写过一条「破窗用信封：私钥各一份封进保险箱，签字才能取」——**那条自相矛盾，已删**。加了它，你付了门限方案的全部可用性代价，又把安全性退回成「能开保险箱的人就能开全部备份」的 1-of-1，净剩下操作摩擦。

## 3. 备份包里有什么

判据只有一条：**拿着这个包和一台干净的机器，不依赖任何别的东西，能把打包服务跑起来。** v5 只装了机密，没装「把机密装回去所需要的东西」，所以按 v5 的清单恢复会卡在第一步。

| 内容 | 谁能产出 | 为什么非它不可 |
|---|---|---|
| **打包机身份文件** `agent-key` | 只有打包机 | 不在数据库里；没有它，库里每个盒子都永远打不开 |
| **每个租户的签名密钥明文**（`.p12` + 口令 + 别名 + 证书指纹） | 只有打包机 | 同上 |
| 打包机配置 `/etc/rn-build-agent.env` | 只有打包机 | |
| **`build-agent` 二进制本体 + systemd unit** | 只有打包机 | `deploy/amos/deploy.sh` 是在开发机上交叉编译的，目标机器上**没有 Go 工具链**；不装它，恢复第一步就得先找一台能编译的机器 |
| **RN-App 的 git remote 地址、deploy key、ssh 配置** | 只有打包机 | 没有源码就不能构建。走 ssh host alias 的话那段 `~/.ssh/config` 也要一起收 |
| 服务端配置 `/etc/rn-foundation.env`（含 `STORAGE_MASTER_KEY`） | 服务端 | |
| **`rn-server` 二进制本体 + systemd unit + nginx 站点配置** | 服务端 | 同二进制那条理由 |
| **TLS 证书与私钥** | 服务端 | 租户是按域名解析的，没有证书后面每一步都是 404。见下 |
| 打包必需的数据库配置：租户身份、图标、Firebase 配置、发布身份 | 服务端 | 只在「数据库也没了」的场景 B 用得上（§7） |
| **`RECOVERY.md` 恢复说明 + `recover.sh`** | 产出时生成 | 见 §5 |

二进制不需要去仓库里找：**每一侧把自己正在跑的那个读出来就行**（`/proc/self/exe`），unit 文件和 nginx 配置是磁盘上已知路径的文件。两个 Go 二进制加起来几十 MB，对包体没有影响。

**TLS 这条不是第三个人质。** 挂在 Cloudflare 橙云后面的域名（`anyfun.win`）用的是 Cloudflare Origin CA 证书：15 年有效、不走 ACME、**不需要在这台机器上留任何能改 DNS 的凭据**——`deploy/amos/install-origin-cert.sh` 的开头把这个取舍写得很清楚，理由正是「这台机器同时持有 Android 签名密钥的封装口令，少放一个凭据就少一分风险」。所以把证书和私钥文件收进包就够了。走 ACME 的那些域名（`deploy/amos/setup-tls.sh`，TLS-ALPN-01）在新机器上重签一次即可，那条路不依赖任何长期凭据。

前五项是关键——它们**不在数据库里**，数据库备份再完整也覆盖不到。

签名密钥明文由打包机现场解出来装进去，所以**不需要人去收集和保管 `.p12`**，也不会因为新加了租户而遗漏。今天三个租户里只有一个有离线明文，这个做法直接把那个缺口补上。

**打包机上那份明文暂存必须有归宿。** 解出来的 `.p12` 和口令落在 `<StateDir>/backup-staging/`，0700，`defer os.RemoveAll`，并且**进程启动时先清理上一次的残留**（和检出目录同样的处理）。不能落在 `/tmp` 以外又不清理：`rn-build-agent.service:30-31` 明写「急着换就 `systemctl kill -s SIGKILL`」，而同一个文件 `:28` 已经点名过这条路径会「留下孤儿 worktree 和一份解开的 keystore」。

## 4. 谁产出、怎么加密

### 4.1 流程

```
1. 打包机读 agent-key、读自己的配置、读自己的二进制与 unit
2. 打包机向服务端要全部租户的密封盒子，逐个解开成明文 .p12 + 口令
3. 打包机把这些打成 tar，分别封给 A 和 B 两把公钥 —— 得到两份内层密文
   （AB 包和 AC 包共用封给 A 的那份，BC 包用封给 B 的那份）
   对每一份出一个 Ed25519 签名（§4.3）
4. 打包机把两份密文 + 两个签名 + 一份元数据上报给服务端
   （它只出不进，从不监听端口，这条不变）
5. 服务端把自己那部分也加进去，按三组配对封三个外层：
      AB 包 = 外层封给 B，里面放封给 A 的那份内层
      AC 包 = 外层封给 C，里面放封给 A 的那份内层
      BC 包 = 外层封给 C，里面放封给 B 的那份内层
   三个对象传到云存储
6. 服务端把三个对象各自的 sha256 写进数据库；控制台显示状态，平台管理员可以下载
```

服务端从头到尾**打不开**任何一个包：内层它没有 A 或 B 的私钥，外层它只有公钥。

**配对规则写成一条公式，两边各自推导。** 打包机要知道封几份内层、服务端要知道封几个外层，两边都从「配了哪几个槽位」推，不互相下发——下发就是又给了服务端一个指定收件人的口子（§4.2）：

> 取配好的槽位集合，按字母序两两组合。对每一组 `(X, Y)`（`X` 在前）：**内层封给 X，外层封给 Y，包名 `XY`。**

代进去：`{A,B,C}` → AB / AC / BC 三个包，内层收件人是 `{A, B}` 两种；`{A,B}` → 只有 AB 一个包，内层只封给 A；`{A}` → 单钥模式，单层单包。

**所以内层只做两份，不是三份**（AB 与 AC 共用封给 A 的那份），打包机解密和打包这件重活只做两遍。三份也能跑，但没必要多花一次。

第 4 步收到的密文会落到服务端本地一个 0600 的临时文件上（`defer os.Remove`），这是为了校验大小、流式封外层，不是设计缺口——它是**封给持有人的密文**，服务端读不懂。真正的边界问题是它**存在过**，见 §2.1 的范围说明。

**降级**：只配两把公钥时第 3 步只封一份、第 5 步只出一个包；只配一把时退化成单层单包（单钥过渡模式）。

### 4.2 恢复公钥全部写死在配置里，服务端不能指定

- 三把公钥都写在打包机的 `/etc/rn-build-agent.env`（root 所有，0600）：`BUILD_AGENT_RECOVERY_RECIPIENT_A` / `_B` / `_C`
- 服务端 `/etc/rn-foundation.env` 里也是同样三把：`BACKUP_RECOVERY_RECIPIENT_A` / `_B` / `_C`

打包机只需要 A 和 B 来封内层，但三把都要配——它要用 C 来**核对**服务端下发的组合是不是它认识的那三把。

**打包机只封给自己配置里那几把，不接受服务端下发的收件人。** 否则服务端被攻破之后，攻击者只要改一下收件人，就能让打包机把全部签名密钥封给他自己——那等于把「服务端读不到签名密钥」这条论证直接作废。

服务端下发待办时会带上三个指纹，打包机拿它和自己 env 里那三把**逐一比对**，任何一个对不上就拒绝执行并上报原因。比对的是指纹不是公钥本体，所以下发的内容没有被信任过。

代价是：换恢复密钥要有人上两台机器改配置。**这件事本来就应该需要一个人到场。**

### 4.3 包要能证明是我们产出的

**这是 v5 最大的洞。** v5 的容器只有保密性，没有真实性：RSA-OAEP 用的是**公钥**，而公钥不是秘密（指纹还印在控制台上）。所以任何拿到桶写权限的人，都能从零造一个新包——MAC 校验通过、两层都解得开、里面是他写的 `recover.sh`。而 `recover.sh` 是「把文件放到位、设属主、起服务」的脚本，**恢复时必然以 root 跑**，在平台最脆弱的那一天、由两位持有人亲手执行。他还能把 `RECOVERY.md` 一起改掉，让「人工照着手册做」这条兜底路径同时失效。

v5 里「完整性校验失败，这个包被改过或损坏」那句话因此是错的，已改：**MAC 通过只说明「没损坏、没被拼接」，不说明「没被替换」。**

两个锚点，各挡一类攻击者：

| 锚点 | 挡住谁 | 怎么用 |
|---|---|---|
| **最终对象的 sha256 记在数据库、显示在控制台、印在 `README-FIRST.txt` 里** | 只攻破了桶的人 | 下载后先算 sha256，和控制台上那一行比对。灾难主场景（打包机坏了）里数据库和控制台都还在，这条随时可用 |
| **打包机对每一份内层密文的签名** | 连服务端一起攻破的人 | 打包机持有一把长期 **Ed25519 备份签名私钥**，公钥登记在数据库、显示在控制台、并且由三位持有人在 §2.2 里各自抄了一份。验签公钥不来自包本身 |

为什么**只签里层、由打包机签**：服务端被攻破是本方案自己列出的威胁（§4.2、§11），服务端签的东西挡不住服务端。而内层是全部价值所在。外层（`manifest.json` / `RECOVERY.md` / `recover.sh`）靠 sha256 那条锚点，它足以挡住「只攻破桶」。

落到操作上，三条硬规则：

1. `README-FIRST.txt` 的**第一步**是核对 sha256，不是解包。
2. **验签通过之前不许跑 `recover.sh`。** `recover.sh` 自己开头也要验一次 `inner.rnbk.sig`，验不过就停——这是纵深，不是主防线（整包被伪造时脚本也是伪造的）。
3. 备份签名私钥**打包机第一次启动时自己生成**，此后不动；它跟着内层进包。恢复出来的机器生成一把新的并重新登记，旧公钥在数据库里留档（`build_agent_keys` 加一行，§8.4），这样历史包的签名仍然验得过。登记走 §8.1 的 `POST /backup-signing-key`，和既有的公钥登记同一套「首次自动接受、换钥要人核对指纹」的规则。
4. **场景 B（数据库也没了）下留档也没了**，这时验签公钥只剩三位持有人纸上抄的那一行——这正是 §2.2 要求他们抄的原因。

不用签名算法之外的花样：`openssl pkeyutl -verify` 对 Ed25519 在 OpenSSL ≥ 1.1.1 上直接可用，恢复端不需要装任何东西。

### 4.4 触发：打包机只出不进，所以「立即备份」是异步的

打包机每 10 秒轮询服务端要活干，**从不监听端口**（那台机器握着签名密钥，不开任何入站端口是设计的一部分）。所以服务端没有办法主动叫它干活，控制台那个按钮只能是：

```
控制台点「立即备份」 → 服务端建一条待办（状态 pending）
   → 打包机下一轮轮询认领（running）→ 产出并上报
   → 服务端封外层、上传、写结果（succeeded / failed）
   → 控制台刷新出结果
```

**定时备份走的是同一条路**：到点了服务端自己建一条同样的待办。一套机制，两个触发口。状态机的完整约束（谁写、怎么写、超时谁执行）见 §8.5——那一节是 v6 新增的，v5 只有语义没有写法，按 v5 实现第一次跑就坏。

**不能挂在「空闲时顺带做」上。** 现有的密钥校验就是这么挂的——只在构建队列为空的那一轮才跑（`cmd/build-agent/main.go:83-91` 的 `if worked { continue }` 会跳过它）。照抄的话，只要有人连着排构建，备份就永远轮不上。

正确的位置是**每轮循环开头看一眼**，在领构建之前：

```go
for {
    if req, ok := api.pendingBackup(ctx); ok {
        bctx, cancel := context.WithTimeout(ctx, backupTimeout)  // 25 分钟
        runBackup(bctx, cfg, api, req)
        cancel()
    }
    worked := pollOnce(ctx, cfg, api)     // 再领构建
    ...
}
```

插入点是 `cmd/build-agent/main.go:77` 的 `for {` 与 `:78` 的 `worked := pollOnce(...)` 之间；`:83-86` 的 `if worked { continue }` 和 `:87-90` 的 `verifyPendingKeystores` 一行都不要动。

**`runBackup` 必须自带超时，这条不是可选项。** 它跑在轮询循环里，卡住就等于打包机再也不领构建——而症状是「构建队列无限堆积，日志里什么都没有」。`backupTimeout` 取 **25 分钟**，小于服务端 30 分钟的产出超时（§8.5），让打包机来得及在服务端判死之前主动 `POST /fail`。同一个文件里已有先例：`registerPublicKey` 被显式包了 30 秒 ctx（`main.go:66-76`）。

`pendingBackup` 返回 error 时不要吞成 `ok=false`：连续 N 轮拿不到答案要出一条 WARN，否则「老服务端 + 新打包机」和「服务端挂了」在日志里长得一模一样。

这样备份最多等一条构建（那条构建正在 `pollOnce` 里面跑），而且不受队列长度影响。

### 4.5 包内结构

云存储里每次备份放 **三组 × 2 个**对象，**每组的写入顺序固定：先 `.rnbk` 后 `.README.txt`**，README 的存在就是「这一组上传完成了」的提交标记：

```
<prefix>/<instanceId>/<8位编号>-AB.rnbk          A 和 B 这一组的备份包
<prefix>/<instanceId>/<8位编号>-AB.README.txt    怎么解开（不加密，见 §5.1）
<prefix>/<instanceId>/<8位编号>-AC.rnbk
<prefix>/<instanceId>/<8位编号>-AC.README.txt
<prefix>/<instanceId>/<8位编号>-BC.rnbk
<prefix>/<instanceId>/<8位编号>-BC.README.txt
```

`instanceId` 来自配置（§8.3），**不许从主机名推导**——主机改名、或者恰好在新机器上恢复之后，键的前缀就换了。下载走数据库里存的 `objects` 那一列，不重新拼（§8.2）。

**外层**（封给这一组的第二个人）解开后是一个 tar，六个成员：

```
manifest.json          这次备份的元数据，见下
RECOVERY.md            恢复手册（明文，不含机密）
recover.sh             交互式恢复脚本（明文，不含机密）
inner.rnbk             打包机那部分，封给这一组的第一个人
inner.rnbk.sig         打包机对上一个文件的 Ed25519 签名（§4.3）
server.rnbk            服务端那部分，封给这一组的第一个人
```

三个包里 `inner.rnbk` 的**文件名一样，内容不一定一样**：AB 与 AC 里那份封给 A，BC 里那份封给 B。`manifest.pair` 写明这是哪一组、谁开外层谁开内层，`README-FIRST.txt` 上也印着。

`inner.rnbk` 解开后：

```
manifest.json                               内层自己的清单，见下
agent-key                                   打包机身份文件 → <StateDir>/agent-key，0600 builder:builder
backup-signing.key                          备份签名私钥 → <StateDir>，0600 builder:builder
build-agent.env                             → /etc/rn-build-agent.env，0600 root:root
bin/build-agent                             正在跑的那个二进制，0755 root:root
systemd/rn-build-agent.service              → /etc/systemd/system/
ssh/id_deploy + ssh/config                  RN-App 的 deploy key 与 host alias，0600 builder:builder
source-remote.txt                           RN-App 的 git remote 地址（一行）
keystores/<租户slug>/keystore.p12           签名密钥明文
keystores/<租户slug>/store-password.txt     口令（单行，无换行）
keystores/<租户slug>/key-alias.txt          别名
keystores/<租户slug>/fingerprint.txt        证书 SHA-256，核对用
```

`server.rnbk` 解开后：

```
manifest.json                               内层自己的清单
rn-foundation.env                           → /etc/rn-foundation.env，0600 root:root
bin/rn-server                               正在跑的那个二进制，0755 root:root
systemd/rn-foundation-server.service        → /etc/systemd/system/
nginx/rn-foundation.conf                    → nginx 站点目录
tls/<域名>.crt + tls/<域名>.key             证书与私钥（§3）
db/tenants.json                             租户主表（含 id，必须逐字保留）
db/tenant-domain.json                       域名映射
db/build-config/<租户slug>.json             打包配置：应用身份、Firebase 配置
db/build-icons/<租户slug>/<四张 png>        启动图标（缺了构建会失败在 ENOENT）
db/release-identity/<租户slug>.json         发布身份：包名、签名指纹
```

`db/*` 只在**场景 B**（数据库也没了）用得上，场景 A 一个字都不要碰。§7 把两个场景拆开了。

#### `db/*.json` 的格式

**就是表里的列，原样导出，不做任何加工。** 每个文件是一个 JSON 数组（`tenants.json`、`tenant-domain.json`）或一个 JSON 对象（每租户一个文件的那几个），键名用数据库列名的小驼峰形式，值按列的类型直出：`DATETIME` 用 RFC 3339 UTC 字符串，`TINYINT(1)` 用布尔，`JSON` 列直接嵌套。

三条约束：

- **`tenants.id` 必须逐字保留。** 它是 `AUTO_INCREMENT`，而 `app_configs` 的 secretbox 密文把 `tenant_id` 绑进了 AAD——id 变了，那些密文全部解不开。恢复时要显式插入 id，不能让数据库重新发号。
- **图标是 base64 直出**，它们本来就以 base64 存在 `app_configs` 里；解码成 `.png` 落盘是为了人能看一眼确认没错，恢复时用哪一种都行，`RECOVERY.md` 里写清楚。
- **不导出任何密文列。** 签名密钥的明文已经在 `inner.rnbk` 里了，密文再导一份只是扩大暴露面；`app_configs` 里其余的 secretbox 密文没有 `STORAGE_MASTER_KEY` 也没用，而那把钥匙在 `rn-foundation.env` 里——要恢复的是「打包服务」，不是整个库（§14）。

#### 两层的 `manifest.json`

**外层**（服务端写）：

| 字段 | 说明 | 来源 |
|---|---|---|
| `format` | 容器格式版本，当前 `1` | 服务端 |
| `seq` | 编号，全局递增 | 服务端 |
| `pair` | 这是哪一组：`"AB"` / `"AC"` / `"BC"`（单钥模式为 `"A"`） | 服务端 |
| `instanceId` | 产出它的那套系统的标识，来自配置 | 服务端 |
| `createdAt` | RFC 3339 | 服务端 |
| `serverVersion` | 服务端构建版本 | 服务端 |
| `agentVersion` | 打包机构建版本 | **打包机上报**（§4.7） |
| `schemaVersion` | 数据库迁移版本号 | 服务端 |
| `agentKeyFingerprint` | 包里那个 `agent-key` 的指纹，16 字符形式（§2.2） | **打包机上报** |
| `backupSigningFingerprint` | 打包机备份签名公钥的指纹，64 字符形式 | **打包机上报** |
| `tenants[]` | 每个租户：slug、域名、有没有签名密钥、证书指纹 | **打包机上报**（签名密钥那部分只有它知道） |
| `recipients[]` | 三把恢复公钥的槽位与指纹，并标明本包用的是哪两个 | 服务端 |
| `files[]` | 外层成员（`manifest.json` 自身除外）各自的路径、大小、sha256。**`inner.rnbk`、`inner.rnbk.sig`、`server.rnbk` 必须在内** | 服务端 |

**内层**（各自那一侧写，两个 `.rnbk` 各有一份）：

| 字段 | 说明 |
|---|---|
| `format` / `createdAt` | 同上 |
| `side` | `"agent"` 或 `"server"` |
| `files[]` | **本层**每个成员的路径、大小、sha256、目标路径、目标权限、目标属主 |

`files[]` 里的「目标路径 / 权限 / 属主」是 `recover.sh` 和 `RECOVERY.md` 真正照着做的那份数据——上面两个文件区里写的那些箭头，就是它渲染出来的，不是手写的散文。

**`files[]` 覆盖两个 `.rnbk` 本身，这条是防拼接的。** 不覆盖的话，攻击者可以把一个**旧**备份的 `inner.rnbk`（轮换前的签名密钥、旧的 `agent-key`）塞进新包、`manifest` 原样不动、重封外层——两层 MAC 全绿、两把私钥都用上了，恢复出来的却是旧密钥，或者 `agent-key` 和库里的盒子对不上、全部租户的签名密钥永久打不开。**而这正是本方案唯一要防的事。** `RECOVERY.md` 和 `recover.sh` 的第一步就是校验这两个 sha256。

**每一层的清单只列该层成员的 sha256，机密文件的哈希不得出现在外层。** 这正是内层要有自己那份 `manifest.json` 的原因。理由具体：系统生成的 keystore 口令是 16 字节随机 hex（`internal/androidkeystore/generate.go:62,135-139`），128 位爆不动；但**上传通道收的是管理员自带 `.p12` 的口令，可以是人选的弱口令**——它的 sha256 一旦出现在只需要一把钥匙就能读到的外层，就是一次离线爆破。

**服务端那部分也封给内层那个人**（不是只封给开外层的人）。否则只拿到外层那把私钥就能读到 `rn-foundation.env` 里的 `STORAGE_MASTER_KEY`，这一组的两把锁就只剩一把。`RECOVERY.md` 与 `recover.sh` 不含机密，留在外层。

**要知道只开了外层的人能读到什么**（这是既定泄露，不是缺陷，但别低估）：全部租户的 slug、域名、证书指纹；服务端与打包机的精确版本号和 schema 版本（可以直接对着已知 CVE 打）；全平台的文件布局、路径、权限、属主、恢复步骤；以及内层密文的准确长度。这些不是密钥，拼起来是一份写好的攻击计划书。

### 4.6 容器格式：一个 tar，四个文件

每一层都是同样的结构，用 tar 装，**任何一台 Linux 机器用 `tar` + `openssl` 就能打开**：

```
meta.json      明文元数据
key.bin        RSA-OAEP(公钥, 80 字节密钥材料)
payload.enc    AES-256-CBC 密文，PKCS#7 填充
payload.mac    HMAC-SHA256(meta.json ‖ key.bin ‖ payload.enc)，32 字节
```

`key.bin` 解出来是固定 80 字节：**前 32 字节是 AES 密钥，中间 32 字节是 HMAC 密钥，最后 16 字节是 IV**。三样一起封，省掉一次 KDF——恢复端不需要 `openssl kdf`（老版本 openssl 没有这个子命令）。80 字节由 `crypto/rand` 一次取出，均匀独立，Encrypt-then-MAC 要的就是两把独立均匀的键，这里加 KDF 不增加任何安全性。

规范里必须写死、否则会被静默写错的五条：

- **PKCS#7 填充。** tar 的长度永远是 512 的倍数，也就永远是 16 的倍数；`openssl enc` 默认加 PKCS#7，Go 的 `cipher.NewCBCEncrypter` 不加。生产端漏写填充时，Go↔Go 的往返测试**会绿**，只有 openssl 那条路径炸——而那正是灾难当天唯一走的路径。更糟的是它**不会干净地失败**：openssl 报 `bad decrypt`、退出码 1，但已经写出了一个少 16 字节的文件，而 `tar xf` 照样能读。所以 §9 必须有一条「Go 封、openssl 解」的跨实现测试。
- **MAC 覆盖 `meta.json ‖ key.bin ‖ payload.enc`，顺序固定，`cat` 的顺序就是规范的一部分。** v5 只覆盖 `payload.enc`，于是 `layer` / `recipient` / `createdAt` / `alg` 可以随意改而 MAC 照样通过：改 `recipient` 能骗持有人「这个包不是给我的」，改 `layer` 能诱导脚本把内层当外层处理，改 `alg` 是 format 2 出现之后现成的降级通道。
- **`meta.json` 带 `seq` + `instanceId` + `layer`**，配合上一条进 MAC 覆盖范围。不带的话，`inner.rnbk` 和 `server.rnbk` 可以直接对调——它们封给同一把公钥、同样的文件名、格式完全一致，内部没有任何东西区分二者。
- **每一层独立调用一次 CSPRNG 取 80 字节，禁止跨层复用。** 复用一旦发生，外层的 `key.bin`（开外层那个人能解）里就直接躺着内层的 AES 密钥，「要两个人」当场塌成「要一个人」——开外层那个人独自拿到全部签名密钥。而这个 bug **往返测试百分百通过**、MAC 全绿、人工检查看不出来。测试：外层与内层 `key.bin` 解出的 80 字节必须不相等。
- **payload 不压缩。** 内层 tar 里 `keystores/<租户slug>/` 的 slug **由服务端下发**，和 `agent-key`、`store-password.txt` 在同一个流里；而服务端手上有 `inner.rnbk`（§4.1 第 4 步），能看到它的大小。加了压缩就是一个标准的 BREACH 式预言机：造一个 slug = 对口令的猜测 → 触发一次备份 → 包小一点就猜对一个字符。触发次数也没有闸（§4.4 的定时和手动都只限并发不限总量），32 位 hex 口令一天之内跑得完。将来真要压缩，规则是「逐文件压缩，且服务端可控字符串不得与机密进入同一压缩上下文」。顺带给备份待办加个频率闸（每小时最多 N 条）。

`meta.json`：

```json
{
  "format": 1,
  "layer": "outer",
  "seq": 42,
  "instanceId": "prod-1",
  "alg": "RSA-OAEP-SHA256+AES-256-CBC-PKCS7+HMAC-SHA256",
  "recipient": "<公钥 SHA-256 指纹，定义见 §2.2>",
  "createdAt": "2026-09-15T08:00:00Z"
}
```

解开一层的完整命令。**它是一个脚本，不是给人粘的裸命令**——`README-FIRST.txt` 里会带着实际路径生成一遍：

```bash
#!/bin/bash
# 用法: bash open-layer.sh <包文件> <私钥> <解到哪个目录>
set -euo pipefail
umask 077

PKG="$1"; KEY="$2"; OUT="$3"
work=$(mktemp -d /dev/shm/rnbk.XXXXXX)      # 机密只落在 tmpfs 上
trap 'rm -rf "$work"' EXIT                   # 退出即清

tar xf "$PKG" -C "$work"
cd "$work"
cat meta.json; echo                          # 人工确认 recipient / seq / layer

openssl pkeyutl -decrypt -inkey "$KEY" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -pkeyopt rsa_mgf1_md:sha256 \
  -in key.bin -out k.bin                     # 会提示输入私钥密码
[ "$(stat -c%s k.bin)" = 80 ] || { echo "密钥材料长度不是 80，格式不对"; exit 1; }

ENC=$(dd if=k.bin bs=1 count=32         2>/dev/null | xxd -p -c64)
MAC=$(dd if=k.bin bs=1 skip=32 count=32 2>/dev/null | xxd -p -c64)
IV=$( dd if=k.bin bs=1 skip=64 count=16 2>/dev/null | xxd -p -c32)
# 没有 xxd 时：把 `xxd -p -cN` 换成 `od -An -tx1 | tr -d ' \n'`，输出逐字节相同

# 先验 MAC 再解密
cat meta.json key.bin payload.enc \
  | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$MAC" -binary > payload.mac.calc
cmp payload.mac.calc payload.mac             # set -e 会在不一致时直接停
# OpenSSL 3.0 的等价写法：openssl mac -digest SHA256 -macopt hexkey:"$MAC" -in <文件> HMAC

openssl enc -d -aes-256-cbc -K "$ENC" -iv "$IV" -in payload.enc -out plain.tar
mkdir -p "$OUT"
tar xf plain.tar -C "$OUT"                   # -C 必须有，见下
echo "OK -> $OUT"
```

三层依次开，**每层解到不同目录**。下面以 AC 这一组为例（外层是 C，内层是 A，`manifest.pair` 和 `README-FIRST.txt` 上都写着）：

```bash
bash open-layer.sh backup-00000042-AC.rnbk ~/C.key ./L1      # C 的私钥
bash open-layer.sh ./L1/inner.rnbk         ~/A.key ./L2-agent  # A 的私钥
bash open-layer.sh ./L1/server.rnbk        ~/A.key ./L2-server
```

`-C` 不是风格问题：两层用同样的四个文件名，不分目录的话 `inner.rnbk` 和 `server.rnbk` **无法在同一个目录里先后展开**，第二个会把第一个的中间文件全盖掉，而且没有任何提示。这个坑百分百在灾难当天、在压力下触发。

其余要求与约束：

- **先验 MAC 再解密，顺序不能反**——CBC 没有完整性，密文被改一位会解出「大部分正确、中间一段是垃圾」的内容，而那是会被照着执行的恢复步骤。但要记住 §4.3：MAC 通过只证明没损坏、没被拼接。
- 命令块用 `set -euo pipefail`，**不要写 `|| { echo ...; exit 1; }`**：那一段粘进交互式 shell 时，失败会直接关掉操作者的终端会话，他会以为是网络问题、重连后跳过这一步。
- 公钥 **RSA ≥ 3072 位**（4096 推荐）。RSA-OAEP-SHA256 在 3072 位下能封 318 字节，80 字节远在范围内。
- `rsa_mgf1_md:sha256` 显式写上。它的默认值确实跟随 `rsa_oaep_md`，但那是个隐式约定，而这段命令要在若干年后的未知 openssl 版本上跑。
- **流式加密可行，但必须先算长度再开始写**：tar 头要求先写成员长度，不能边写边算。好在 CBC+PKCS#7 的密文长度是确定的 `16 × (⌊n/16⌋ + 1)`，明文是个 tar 也可以先算出来。不写这一句，实现时会撞墙然后退化成「整包进内存」——而那正是要避免的。
- 租户 slug 必须匹配 `^[a-z0-9-]+$`，**打包机侧校验**，不要依赖 GNU tar 默认拒绝 `..` 这个行为。
- **永远不要做「在线验证备份」接口。** `openssl enc -d` 的退出码加 `bad decrypt` 就是现成的 padding oracle；今天恢复是离线一次性的，这条攻击不成立，一旦有个端点会解密并回错误码，它立刻成立。
- **不碰现有的 `buildkeystore.SealTo`**：那是给签名密钥封盒子用的现役函数，动它会让库里已有的盒子全部打不开。这里是另一套格式、另一个用途。

### 4.7 打包机上报的元数据

外层 `manifest.json`、`RECOVERY.md` 和 `recover.sh` 都由服务端生成，但它们有一半内容**只有打包机知道**——服务端打不开内层，拿不到租户清单、`agent-key` 指纹、内层每个文件该放到哪。所以上报不是「一段密文」，是**密文 + 签名 + 一份元数据**三样。

`POST /backup-requests/:id/payload` 走 `multipart/form-data`，三个部件：

| 部件 | 类型 | 内容 |
|---|---|---|
| `meta` | `application/json` | 下面这个对象，≤ 256 KiB |
| `payload` | `application/octet-stream` | 内层密文本体，≤ 512 MiB |
| `sig` | `application/octet-stream` | 对 `payload` 的 Ed25519 签名，64 字节 |

选 multipart 不选「密文走 body、元数据走头」是因为元数据里有租户清单和文件表，塞进 HTTP 头会撞上头长度上限，而且不好做大小限制。`meta` 必须**排在 `payload` 之前**，这样服务端可以先解析元数据、校验通过再决定要不要收那 512 MiB。

`meta` 的结构：

```json
{
  "recipientSlot": "A",
  "agentVersion": "2026-09-15-abc1234",
  "agentKeyFingerprint": "<16 字符，§2.2>",
  "backupSigningFingerprint": "<64 字符，§2.2>",
  "tenants": [
    {"slug": "acme", "domain": "api.acme.example",
     "hasKeystore": true, "signerSha256": "<证书 SHA-256>"}
  ],
  "innerFiles": [
    {"path": "agent-key", "size": 32, "sha256": "...",
     "target": "<StateDir>/agent-key", "mode": "0600", "owner": "builder:builder"}
  ]
}
```

- **`recipientSlot`** 说明这一份内层封给了哪个槽位。打包机一次备份要传两份（封给 A 的和封给 B 的），服务端靠它决定哪一份进哪个包。同一个 `:id` 下每个槽位只许传一次，重复传 409。
- **`innerFiles[]` 就是内层 `manifest.json` 的 `files[]`**，原样上来。服务端拿它渲染 `RECOVERY.md` 里「哪个文件放到哪、什么权限、属主是谁」那一段，以及 `recover.sh` 里对应的那几行。**服务端不解释它，只做转义和渲染**——路径里带引号或换行要当成非法输入拒掉，否则它就是一条往 `recover.sh` 里注入命令的路。
- **`tenants[]`** 进外层 `manifest.json`，控制台的 `tenant_count` 也从它来。
- 两个指纹进外层 `manifest.json`，`backupSigningFingerprint` 还要和数据库里登记的那一把**一致**，不一致服务端直接判这条待办失败——打包机换了签名密钥而没走登记流程，是个必须让人看见的信号。

**服务端对 `meta` 的信任边界**：它来自打包机，而「服务端能让打包机执行任意代码」这条洞修好之前（§11），打包机也不是完全可信的。所以 `meta` 的每一项都要当外部输入校验——slug 匹配 `^[a-z0-9-]+$`、路径不含 `..` 和引号、数组长度有上限、`mode` 匹配 `^0[0-7]{3}$`。这些校验便宜，且正好挡住「渲染进 `recover.sh`」那条注入路径。


## 5. 恢复说明必须跟着包走

**拿到东西却不知道怎么用**是这类备份最常见的失败方式。所以包里带三样：外面一页纸告诉你怎么解开，里面一个脚本替你做，一份手册供脚本跑不通时人照着做。

说明分两层是为了解开「要先知道怎么解密，才能读到怎么解密」这个死循环。

### 5.1 密文外面：`README-FIRST.txt`

和备份包并排放在云存储里，**不加密**（里面没有任何机密）。**每个包一份，三个包三份**，各自写着自己这一组要谁的钥匙。内容是一页纸：

- **第一步：核对 sha256。** 这个文件里印着对应 `.rnbk` 的 sha256，和控制台「平台维护 → 备份与恢复」那一行比对。对不上就停下来，不要解包。理由见 §4.3
- **这个包要谁**：`本包需要 A 和 C 两把钥匙。先用 C 的私钥剥外层，再用 A 的私钥解内层。` 后面跟着两个槽位的指纹和「由谁保管」——运维在配置时填的那一行
- **另外两个包是**：`<seq>-AB.rnbk`（要 A 和 B）、`<seq>-BC.rnbk`（要 B 和 C）。**手上这两个人开不了本包时，去看那两个**——这一句必须有，否则拿到包的人不知道还有别的选择
- 这是什么、什么时候产生的、`seq` 是多少、对应哪个版本的服务端与打包机
- **怎么解开**：`open-layer.sh` 那段脚本，参数值已经填好，三层的调用顺序也写好
- **验签**：打包机备份签名公钥的指纹，以及那条 `openssl pkeyutl -verify` 命令。**验签通过之前不要跑 `recover.sh`**
- 解开之后先读 `RECOVERY.md`

### 5.2 密文里面：`RECOVERY.md`

**产出时生成，不是写死的模板**——模板会过期，生成的不会。里面带的是这次备份的真实值：

- **包里每个文件是什么、放到哪、什么权限、属主是谁**
- **先判断是场景 A 还是场景 B**（§7），两条路的步骤不一样
- **按顺序的恢复步骤**，每步都是可以直接执行的命令，不是散文；凭据、端口、`Host` 头全部填好（§7）
- 这份备份对应的租户清单（几个租户、各自的域名、各自有没有签名密钥）
- 对应的服务端与打包机版本号、数据库 schema 版本、`agent-key` 指纹
- **本层成员**的 sha256（机密文件的哈希不出现在外层，§4.5）
- **怎么验证恢复成功了**：跑哪条命令、看到什么算通过

`RECOVERY.md` 的骨架就是 §7，但里面的 `<租户>`、`<域名>`、`<路径>` 全部替换成产出那一刻的实际值。

### 5.3 密文里面：`recover.sh`

照着手册一步步敲容易漏、容易错，所以包里再带一个**交互式恢复脚本**：

- **开头先验 `inner.rnbk.sig`**，验不过就停（§4.3 第 2 条）
- 开头强制 `umask 077`、工作目录建在 `/dev/shm` 或 tmpfs 上、`trap 'rm -rf "$work"' EXIT`。不做这三件事，全公司最集中的那份机密会以 `-rw-rw-r--` 解在某人主目录里，同机任何用户可读，之后没有任何清理步骤——而 SSD 上 `rm` 不等于擦除
- 问清新机器的域名、安装路径这几个必须由人决定的东西，其余全部自动
- 把文件放到位并设好权限与属主
- 起服务，然后跑完 §7 的整套验证
- 结束时明确说**「恢复完成」**或者**「卡在第几步、因为什么、下一步该查哪里」**——不要静默失败

它和 `RECOVERY.md` 一样是**产出时生成**的，两者内容必须一致：脚本做的每一步，手册里都有对应的那条命令，供环境不一样、脚本跑不通时人接手。

脚本**只做恢复，不做破坏**：遇到目标路径已有文件就停下来问，不覆盖。

## 6. 控制台

平台管理员在**平台维护**下（和「管理员口令」并排，实现见 §8.6）：

- 手动「立即备份」
- 定时开关与频率
- 上次成功时间、编号、**三个包各自的 sha256**（§4.3 的第一个锚点，要能一眼看到并逐个复制）、连续失败次数
- 最近若干次的清单，**每一次按它自己那一条 `objects` 里实际有几组就展开几行**（不是按当前门限模式——补槽位之前的老记录只有一组，§2.5），各自一个下载按钮；**已过保留期的要标出来**，否则真出事那天点到一条过期的，看到的是一句看不懂的 S3 `NoSuchKey`
- **三个恢复公钥槽位**：槽位字母、指纹（64 字符）、「由谁保管」那一行（可编辑）。哪个槽位没配要显著标出
- **当前门限模式**：`2-of-3`（三把都配了）/ `2-of-2`（配了两把）/ **`单钥模式，过渡状态`**（只配一把，显著标出）
- **打包机备份签名公钥的指纹**（§4.3），单独一个区块——它和上面三个、以及既有的「打包机公钥」指纹（16 字符）算法都不一样，混在一起显示会让核对仪式失效（§2.2 的四个指纹表）
- 一条**强制判失败**的按钮（§8.2），带 reason 与二次确认

租户管理员看不到：插件声明 `platformOnly`，前端按会话里的 `platformAdmin` 过滤掉整个菜单；后端路由挂 `platform.*` 组，由 `requirePlatformAdmin()` 按 `PLATFORM_ADMIN_USERNAMES` 白名单卡住，白名单为空时整组 403。

**要知道这道门今天挡不住谁**：控制台只有一个登录账号（`internal/api/server.go:543` 比对唯一的 `ADMIN_USERNAME`），租户是靠打开哪个域名区分的，「租户管理员」这个身份不存在。所以白名单要么包含那个唯一账号（凡是能登录的人都看得见），要么不包含（整组关闭）。多账号登录是另一件事（`OPERATIONS_AND_RELEASE.md:233` 记录了「当前阶段不加入 RBAC」）。

今天便宜的补偿：`run` 和 `download` 各要求重新输入一次管理员口令，并共用登录限速——会话 TTL 默认 8 小时，一个被偷走的 cookie 否则能拉走全部历史备份。

### 6.1 桶

- 用**独立的桶和独立凭据**，不要复用产物桶——产物桶凭据泄露不该等于备份泄露。
- **必须开 versioning，而且要开对象锁。** 只给 `PutObject` 不等于安全：`Put` 对已存在的键是覆盖（`s3.go:131-143`），没开 versioning 时覆盖就是删除；而 §4.3 那条伪造攻击的入口正是桶写权限，版本化 + Object Lock 让被覆盖的真包还能取回来。
- 「测试连接」要顺带校验 versioning 已开，**但状态页不要每次实时查**：那是一次真实的 S3 调用，跑在 10 秒 DB ctx 里，桶不可达时整个状态页 500——连「上次成功时间」都看不到，而那正是出事时最想看的一行。缓存或异步刷新。另外 `internal/objectstore/` 里今天没有任何 versioning 相关方法，这是要新增的 port 方法，不是免费的。
- 保留期用桶的生命周期规则，显式设一个数（建议 90 天）。要知道它的含义：**只要历史包还在，过去的签名密钥就还在里面**——密钥轮换的语义因此是「多了一把新的」，不是「旧的作废」，而保留期就是这个的时间上限。
- **2-of-3 把桶里的东西变成三份**（§2.1）。整包约 50 MB，三份 150 MB；按天备份、保留 90 天约 13 GB。生命周期规则要按**对象名前缀**统一设，不要只设某一组，否则三组的保留期会不一致，而人是按「还剩哪两个人」挑包的，挑到过期那一组才发现就晚了。
- `BACKUP_INTERVAL_HOURS` 的下界是 6（§8.3）：1 小时间隔 + 90 天保留 = 2160 次 × 3 份 = 6480 份全平台签名密钥副本躺在桶里。


## 7. 恢复流程

**先判断是哪个场景，两条路不一样。** v5 把它们混在一条流程里，是「拿到东西也不知道怎么用」的另一半原因。

| 场景 | 情况 | 要做什么 |
|---|---|---|
| **A** | 打包机没了，服务端和数据库还在 | §7.2。这是 §1 说的那件事，也是最常见的 |
| **B** | 服务端也没了 | §7.3 先把服务端立起来，再走 §7.2 |

数据库本身不在本方案范围内。包里的 `db/*.json` 只够把**打包相关的那部分配置**补回去，不是数据库备份。

### 7.1 两个场景共用的第 0 步：开包与验真

```
0.1) 看还剩哪两个持有人，决定开哪一组：
       A+B → <seq>-AB.rnbk    A+C → <seq>-AC.rnbk    B+C → <seq>-BC.rnbk
     从云存储取那个 .rnbk 和同名的 .README.txt
0.2) sha256sum <seq>-XY.rnbk —— 和控制台上那一行比对（服务端还在时）
     控制台也没了时，跳到 0.5 用签名验
0.3) 记下此刻时间：date -u    （后面第 6 步要用它判断记录是不是新写的）
0.4) 两个持有人到场，按 README-FIRST 里的 open-layer.sh 依次开三层，
     每层解到不同目录（-C，§4.6）。先用「外层那个人」的私钥，再用「内层那个人」的
     —— 谁是哪个，README-FIRST 第二行和 manifest.pair 都写着
0.5) 验签：openssl pkeyutl -verify -pubin -inkey <备份签名公钥> \
            -rawin -in L1/inner.rnbk -sigfile L1/inner.rnbk.sig
     公钥指纹和三位持有人手上抄的那一行（§2.2）比对
0.6) 校验 manifest.files[] 里 inner.rnbk / server.rnbk 的 sha256
     —— 这一步防的是拼接：旧包的内层塞进新包，两层 MAC 都会通过（§4.5）
0.7) 验签和 0.6 都通过之后，才可以跑 recover.sh
```

**这一组开不了就换一组。** 三个包内容相同，只是锁的组合不同——某一组的某把私钥忘了口令、介质坏了，直接去开另外两组里还能凑齐的那一个。这是 2-of-3 买到的东西，`README-FIRST.txt` 上印着另外两个包的名字就是为了这一刻。

### 7.2 场景 A：打包机没了

```
1) 新机器装好：Android SDK / JDK17 / node + pnpm / git
2) 放回打包机那一侧：
     bin/build-agent                → 安装路径，0755 root:root
     systemd/rn-build-agent.service → /etc/systemd/system/
     agent-key, backup-signing.key  → <StateDir>，0600 builder:builder
     build-agent.env                → /etc/rn-build-agent.env，0600 root:root
     ssh/id_deploy, ssh/config      → builder 的 ~/.ssh/，0600 builder:builder
   —— BUILD_AGENT_STATE_DIR 必须显式写死。它默认从 workspace 推导
      （cmd/build-agent/config.go:89-92），路径差一点就找不到恢复的私钥，
      打包机会静默生成一把新的（agentkey.go:42-55），日志里区分不出来
3) 按 source-remote.txt 把 RN-App 检出到 workspace（ssh/config 里的 host alias 要一起放好）
4) 起服务之前先核对身份：
     build-agent show-key            （这个子命令今天不存在，§11 要补）
   输出的指纹必须等于 manifest.agentKeyFingerprint。不等就是第 2 步放错了位置
5) 让下一轮校验重新跑一次（不做这步，第 6 步看到的是灾难前的旧记录，§11）：
     DELETE FROM app_configs WHERE config_key='build.keystore.check'
6) systemctl start rn-build-agent
   等每个租户出现 checkedAt 晚于第 0.3 步那个时刻的 ok
7) 跑通一条真实的 APK 构建并入库，才算恢复完成
```

第 5 步要连数据库。场景 A 下数据库还在，直连即可。

**如果决定不沿用旧的 `agent-key`**（比如怀疑那台机器被入侵过），路就不是上面这条：要生成一把新的、把包里的明文 `.p12` 重新封给它、再上传回数据库。**这条路今天走不通**，卡在 §11 的前两条——上传接口只认旧格式，而打包机公钥没有出口。

### 7.3 场景 B：服务端也没了

先做这一段，做完回到 §7.2。

```
1) 新机器：域名 DNS 指回来
2) 放回服务端那一侧：
     bin/rn-server                       → 安装路径，0755 root:root
     systemd/rn-foundation-server.service → /etc/systemd/system/
     nginx/rn-foundation.conf             → nginx 站点目录
     tls/<域名>.crt, tls/<域名>.key       → nginx 配置里写的路径
     rn-foundation.env                    → /etc/rn-foundation.env，0600 root:root
3) systemctl start rn-foundation-server && nginx -t && systemctl reload nginx
4) 验证主密钥对不对（这个接口会真的解密一次凭据）：
     export ADMIN_API_KEY=<从恢复出来的 rn-foundation.env 里取 ADMIN_API_KEY>
     curl -sS -X POST \
       -H "x-admin-key: $ADMIN_API_KEY" \
       -H "Host: <租户域名>" \
       http://127.0.0.1:13080/v1/admin/release-storage/test
   期望 {"ok":true,...}
   —— 不要用 GET /ota/signing-key 代替：那个只读明文证书字段、从不解密，
      钥匙错了它照样返回 200
   —— 三件必须填对的事：端口是 13080（amos 上应用只听 127.0.0.1，443 在 nginx），
      鉴权走 x-admin-key（server.go:504-507），Host 头决定解析到哪个租户
   —— 403 先查 ADMIN_API_ALLOWED_IPS：它限制这条自动化通道的来源
      （config.go:31-33，server.go:122），127.0.0.1 不在名单里就会被挡
   —— 不要指望用管理员口令登录控制台来做这一步：包里有 ADMIN_PASSWORD_HASH，
      没有明文口令，那是有意的
5) 验证租户解析与配置可读：
     curl -sS -H "Host: <租户域名>" http://127.0.0.1:13080/v1/mobile/bootstrap
   期望 200
   —— 租户必须域名 active、未软删、当前日期在有效期内
      （internal/api/tenant_resolver.go:64-78，演练时特别容易撞有效期）
6) 回到 §7.2
```

**数据库也没了的话，本方案覆盖不到。** `db/*.json` 能把租户身份、域名映射、打包配置、图标、发布身份补回去（`tenants.id` 必须逐字保留，见 §8.4），但签名密钥要重新封进库——那条路同样卡在 §11 的前两条。

**如果两把恢复私钥丢了任意一把**，备份包就是一堆打不开的字节，和没有备份一样。这就是 §2.1 那三条要求的原因。

## 8. 接口、数据与配置

### 8.1 打包机侧（`/v1/build-agent`，既有的共享令牌鉴权）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/backup-requests/claim` | 原子认领。有待办返回 `{id, seq, recipients:[{slot,fingerprint}...]}`，没有返回 **204**。`recipients` 只用于**核对**——打包机封给自己 env 里那三把，任何一个指纹对不上就拒绝执行并上报原因（§4.2） |
| GET | `/backup-keystores?request=<id>` | 返回**全部**租户的密封盒子 `[{tenant, version, sealedKeystore, keyAlias}]` |
| POST | `/backup-requests/:id/payload` | `multipart/form-data`，三个部件 `meta` / `payload` / `sig`，契约见 **§4.7**。一次备份要传两次（槽位 A 一份、槽位 B 一份），同一槽位重复传 409。服务端只存不读密文 |
| POST | `/backup-requests/:id/fail` | `{reason}`。打包机自己失败时主动上报，不要让服务端干等到超时 |
| POST | `/backup-signing-key` | 登记备份签名公钥 `{publicKey, fingerprint}`。打包机启动时调一次，和既有的 `/public-key` 登记同一套规则：**库里没有就自动接受，已有另一把就记成 `pending_acceptance` 等人核对指纹后接受**——自动接受等于偷到令牌的人换掉签名公钥，之后他伪造的包就验得过 |

**认领必须是 POST 而且必须原子。** v5 写的是 `GET /backup-requests`，两个问题：

- **原子性**：v5 没说怎么把 `pending` 翻成 `running`。两个进程同时读到同一条并各自 UPDATE，两边都会去解开全部租户的签名密钥、打完 tar、上传，第二个才在 `/payload` 吃 409——损害发生在 409 之前。而且第二个大概率把 409 当硬失败去调 `/fail`，把第一条**已经成功**的记录翻成 `failed`。现成做法在隔壁：`internal/api/build_jobs.go:697` 的 `SELECT ... WHERE status='pending' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED`，再 `UPDATE ... SET status='running', claimed_by=?, claimed_at=? WHERE id=? AND status='pending'`，检查 RowsAffected。
- **方法**：一个会改状态的 GET 在这套代码里特别危险——`safeMethod`（`server.go:2017`）含 GET，`authenticate()` 的 Origin 闸（`:492`）因此对它完全不生效；而任何 HTTP 客户端和代理都会对 GET 自动重试。既有的 `agent.POST("/claim", ...)`（`server.go:201`）就是对的样子。

**`/backup-keystores` 的门禁判据是「这个令牌名下有一条 `running` 的待办，且 id 匹配」。** v5 写的是「只在有 **pending** 待办时才返回内容」——那和状态机自相矛盾：认领那一刻状态就变 `running` 了，库里没有 pending，于是**每一次备份都拿不到盒子**。更糟的是 v5 的测试用例（「有待办时返回全部租户」）会直接造一条 `pending` 行再调接口、从不经过认领，**测试绿而生产必挂**。测试必须先走一遍 `claim`。

**不能复用现有的 `/keystore-checks`**：它 `LIMIT 20` 且跳过「这一版已验过」的租户（`internal/api/build_keystore_check.go:95-122`），拿它做备份会静默漏租户。

`/backup-keystores` 的值比现有接口更高（一次拿全量明文盒子），所以它要**单独记审计**（`actor_id='build-agent'`）。

**`/payload` 有两条实现约束，漏了就是必然失败：**

1. **它落在 10 秒数据库超时里。** 豁免名单（`internal/api/server.go:363-370`）是 `/upload` 后缀、multipart part、`/finalize`、`/release-storage/test`、`/download`、`readsTokenChain`——`…/payload` 一个都不沾。body 本身读得完（HTTP 读超时 3600 秒），但接完之后的**封外层 → 上传 S3 → `UPDATE status='succeeded'`** 全部用一个早就过期的 ctx，逐个 `context deadline exceeded`，记录停在 `running`，30 分钟后判 `failed`。**每一次都是。** 修法照 `internal/api/simplified_releases.go:173` 的现成先例：`context.WithTimeout(context.Background(), ...)` 另起一条 ctx 做 Put 和收尾，**不要去改豁免名单**（改名单会顺带放开 DB 超时，不是想要的）。
2. **先比 `ContentLength` 再收 body**，不符直接 411；落盘用 `os.CreateTemp` + `defer os.Remove` + `http.MaxBytesReader`（同一个文件 `:135`、`:153-159`）。这台机器同时跑着构建和 wallet 后端，磁盘被一次失控的上报写满，倒下的不止备份。

**备份签名公钥的登记为什么要单独一条路**：它和既有的打包机 X25519 公钥用途完全不同（一个签备份包、一个封签名密钥盒子），算法不同、指纹形式不同（§2.2 的四个指纹表），生命周期也不同——恢复出来的机器会生成一把**新的**签名密钥并登记，而旧的必须在库里留档，否则历史包再也验不了签（§4.3 第 3 条）。所以是新接口 + `build_agent_keys` 里的新一行，不是复用同一行改个值。

**迟到的请求不是重复请求**：`/payload` 打到一条已经 `failed` 的 id、`/fail` 打到一条已经 `succeeded` 的 id，都返回 409 且**不做任何写**，响应里要让打包机知道「不用重试，把本地明文暂存删掉」。

### 8.2 控制台侧（`/v1/admin/platform`，`requirePlatformAdmin()`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/backup` | 状态：当前待办（如有）、最近 N 条记录、三个指纹、是否单钥模式、桶是否开了 versioning（缓存值，§6.1） |
| POST | `/backup/run` | 建一条待办。已有 pending/running → **409** 并带上那条的 `seq` 与 `status`。要 `{reason, confirm:true}`（`AGENTS.md:35`），并要求重新输入一次管理员口令（§6） |
| POST | `/backup/:seq/force-fail` | `{reason, confirm:true}`。`UPDATE ... SET status='failed' WHERE seq=? AND status IN ('pending','running')`，写审计。**这条是逃生口，不是可选项**，见下 |
| GET | `/backup/:seq/:pair/download` | 下载某一组的包，`:pair` 是 `AB` / `AC` / `BC`（单钥模式为 `A`）。**路径以 `/download` 结尾是有意的**——既有的数据库超时中间件正好豁免这个后缀（`server.go:363-370`），不用再改豁免列表 |
| GET / PUT | `/backup/storage` | 桶的**非机密**字段与状态；凭据和 endpoint 在 env，不落库（§8.3） |
| POST | `/backup/storage/test` | 只 Put 一个随机探针键，并校验 versioning 已开。**不能用现成的 `objectstore.Test()`**：它 Put 固定键再 `HeadObject`（`internal/objectstore/s3.go:319-336`），既要 Get 权限，固定键在开了 versioning 的桶上还会永久留存 |

**为什么 `force-fail` 必须有**：`deploy/build-agent/rn-build-agent.service:30-31` 明写「急着换就 `systemctl kill -s SIGKILL rn-build-agent`」。运维照做之后，记录停在 `running`、`live_slot` 被占，控制台显示「备份进行中」但什么都没在跑，点「立即备份」一直 409——**30 分钟内一次备份都做不了，而运维手上没有任何动作能改变它**。`build-concurrency-2026-09-15.md` §3.5.4 论证过同一件事：在途闸上线的同时必须给 `running` 一条强制判失败的路。

**`download` 用 `:seq` + `:pair` 但对象键从行上读，不重新拼。** v5 写的是「服务端按 §4.5 的规则自己拼键」——那依赖 `instanceId`，而主机改名、或者恰好在新机器上恢复之后，前缀就换了，历史备份全部 404。`platform_backups.objects` 这一列就是答案：上传成功时把三组的键和 sha256 写进去，下载时按 `:pair` 从里面挑。`:pair` 只当**查表的键**用，匹配不到就 404，**绝不参与拼字符串**——「不接受外部传对象键」这条安全约束（`s3Client.Get` 把 key 原样交给 `GetObject`，`s3.go:178-184`）靠「键来自我们自己写的那一行」同样成立，而且更强。

**`download` 这条 GET 要补 Origin 检查**：`authenticate()` 的 Origin 闸只对非安全方法生效（`server.go:492`，`safeMethod` 含 GET），而 `originAllowed` 末尾会回落去查 `tenant_domain` 表（`:444` → `originIsTenantDomain` `:446-467`），`cors()` 对任何通过 `originAllowed` 的来源发 `Access-Control-Allow-Credentials: true`（`:412`）。不补的话，「谁能读平台备份」实际由那张表的内容决定。修法：平台组关掉 tenant_domain 回退，只认 `CORS_ORIGINS` 里显式列出的控制台来源；响应带 `Cache-Control: no-store`。

**行比对象活得久**：90 天生命周期删掉对象之后，表里那条 `succeeded` 还带着 sha256 和 object_key。按保留期在列表里标「已过保留期」，并把 S3 的 `NoSuchKey` 映射成明确文案。

### 8.3 新增配置

**服务端** `/etc/rn-foundation.env`：

| 键 | 校验 |
|---|---|
| `BACKUP_RECOVERY_RECIPIENT_A` | 槽位 A 的 RSA 公钥，**PEM 的 base64，单行**。必须能解析、位数 ≥ 3072 |
| `BACKUP_RECOVERY_RECIPIENT_B` | 槽位 B，同上 |
| `BACKUP_RECOVERY_RECIPIENT_C` | 槽位 C，同上。三把**必须两两不同**——任意两把相同就是门限退化，直接拒绝启动 |
| `BACKUP_INSTANCE_ID` | 对象键前缀用，`^[a-z0-9-]{1,32}$`。**显式配，不从主机名推导**（§4.5） |
| `BACKUP_BUCKET_ENDPOINT` / `_REGION` / `_BUCKET` / `_PREFIX` | 生产强制 https |
| `BACKUP_BUCKET_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` | 只需要 `s3:PutObject` + `s3:GetObject` + `s3:GetBucketVersioning` |
| `BACKUP_INTERVAL_HOURS` | 0 = 关闭定时，只留手动。范围 **6–168**，建议 24 |

**PEM 走 base64 单行是有理由的**：PEM 带换行，直接写进 systemd 的 `EnvironmentFile` 极易写坏，而**这个键要用的那一天正好是最不该出意外的那一天**。

`BACKUP_INTERVAL_HOURS` 的下界是 6 不是 1：1 小时间隔 + 90 天保留 = 2160 次备份 × 3 份 = 6480 份全平台签名密钥副本躺在桶里（§6.1），而且一条卡住的备份会连着吃掉好几次定时。

**打包机** `/etc/rn-build-agent.env`：

| 键 | 校验 |
|---|---|
| `BUILD_AGENT_RECOVERY_RECIPIENT_A` / `_B` / `_C` | 同样那三把，PEM 的 base64 单行，≥ 3072 位，两两不同。封内层只用 A 和 B，C 用来核对服务端下发的组合（§4.2） |

**槽位可以缺，但要连续从 A 开始。** 配了 A+B+C 是 2-of-3（三个包）；只配 A+B 是 2-of-2（一个包）；只配 A 是单钥过渡模式（单层、一个包）。配成 A+C 而跳过 B 直接拒绝启动——那是填错了，不是有意的降级，而「以为配了三把其实只有两把」正是这套东西最不能出的错。

**服务端与打包机两边的三把必须逐指纹一致**，不一致时打包机拒绝执行并上报（§4.2）。控制台上要能看出来是哪个槽位对不上。

**失败方向**：打包机侧这几个键**缺失或非法时不 fail-closed 启动**——把备份做成构建的单点故障是负收益，而且第一次配置往往正好发生在恢复当天。但它必须**拒绝认领备份待办并上报原因**，让控制台上看得见「打包机没配恢复公钥」或「槽位 B 的指纹和服务端对不上」，而不是静默不备份。

**服务端侧的校验不能挂在 `Environment == "production"` 下面。** `internal/config/config.go:179-189` 那个 block 的条件是 production，而 amos 上的 wallet 后端今天不是 production——挂在那里等于「配了就以为有」。正确的判据是**只要启用了备份（桶配置非空或 `BACKUP_INTERVAL_HOURS > 0`），槽位 A 缺失或任何一把非法、或存在两把相同、或槽位不连续，就拒绝启动**，和环境无关。另外 `rn-server config`（`cmd/server/config_dump.go`）要把当前门限模式和四个指纹（三个槽位 + 备份签名公钥）或「未配置」打出来。

反过来也要注意：把整个 wallet 后端的启动挂在备份配置上，意味着**部署新服务端之前必须先把 env 写好**。§10 的升级顺序和 §13 的落地顺序都标了这条前置。

三处联动一个都不能少（`AGENTS.md:14`：「少了第二处，这个键对运维就不存在」）：`internal/config/config.go` 读取与逐键校验、`docs/CONFIGURATION.md`、两边的 `.env.example`。**这些正是灾难当天要用的键。**

### 8.4 数据：新建一张 `platform_backups`

#### 复用映射表（`AGENTS.md:99-100`）

| 拟新增 | 结论 | 理由 |
|---|---|---|
| 备份运行记录 | **新建表 `platform_backups`** | 它是**新实体**：一次备份运行有生命周期、有多个写方（控制台建、打包机认领与上报、服务端收尾、超时扫描）、条数随时间无界增长。`app_configs` 的一行 JSON 装不下多写方 + 无界增长，`audit_events` 只能追加、没法表达在途状态 |
| 桶配置 | **进 `app_configs(tenant_id=0)`** | 平台级配置的既定去处，自带 `version` 乐观锁与 `updated_by`。只放非机密字段，凭据在 env |
| 备份历史的审计 | **进 `audit_events`** | 既定去处，`actor_id='system-backup'`。表里那份是运行状态，审计那份是不可篡改的流水 |
| 连续失败次数 | **不加列**，从 `ix_platform_backups_status` 倒查到上一条 `succeeded` 推导 | `AGENTS.md:102` 一个事实一处 |

#### DDL

```sql
CREATE TABLE IF NOT EXISTS platform_backups (
  id          VARCHAR(80)  NOT NULL          COMMENT '主键，pbk_ 前缀',
  seq         INT UNSIGNED NOT NULL AUTO_INCREMENT
                                             COMMENT '编号，全局递增，对象键用它；下载接口按它取，不接受外部传对象键。自增由数据库发号，回滚留下的号洞无害',
  status      ENUM('pending','running','succeeded','failed') NOT NULL
                                             COMMENT '状态：pending=已建待办等打包机认领，running=打包机已认领在产出，succeeded=已上传，failed=任一环节失败',
  trigger_by  ENUM('manual','schedule') NOT NULL
                                             COMMENT '触发来源：manual=控制台按钮，schedule=定时',
  requested_by VARCHAR(120) NOT NULL         COMMENT '发起人；定时触发时写 system-backup',
  reason      VARCHAR(500) NOT NULL          COMMENT '发起原因，手动触发由人填；定时触发写固定常量 scheduled backup',
  claimed_by  VARCHAR(120) NULL              COMMENT '认领的打包机自报标识，只用于排查，不作为鉴权依据；NULL=还没被认领',
  claimed_at  DATETIME(3)  NULL              COMMENT '认领时间 UTC；NULL=还没被认领',
  payload_received_at DATETIME(3) NULL       COMMENT '打包机上报密文到达的时间 UTC；NULL=还没上报。产出超时据它和 claimed_at 分段判断，卡住时才分得清该去哪台机器看',
  objects     JSON         NULL              COMMENT '这一次产出的每一组包：[{"pair":"AB","objectKey":"...","sha256":"...","sizeBytes":123}]。2-of-3 有三组，2-of-2 一组，单钥模式一组。下载按 pair 从这里查键，不重新拼；sha256 是恢复时判断包有没有被换过的第一个锚点，控制台要显示、README 要印。NULL=还没上传成功',
  tenant_count INT UNSIGNED NULL             COMMENT '这次备了几个租户的签名密钥，突然变少要人看一眼；NULL=还没产出',
  failure_reason VARCHAR(500) NULL           COMMENT '失败原因一句话；NULL=没失败',
  created_at  DATETIME(3)  NOT NULL          COMMENT '创建时间 UTC',
  updated_at  DATETIME(3)  NOT NULL          COMMENT '更新时间 UTC',
  live_slot   TINYINT UNSIGNED
              GENERATED ALWAYS AS (CASE WHEN status IN ('pending','running') THEN 1 ELSE NULL END) STORED
                                             COMMENT '未结束的备份占位：pending/running 时为 1，其余为 NULL。唯一索引建在它上面，保证同时只有一条在途；MySQL 唯一索引不比较 NULL，所以结束后可以立刻建下一条。由数据库生成，无人写入',
  PRIMARY KEY (id),
  UNIQUE KEY ux_platform_backups_seq (seq),
  UNIQUE KEY ux_platform_backups_live (live_slot),
  KEY ix_platform_backups_status (status, created_at)
) ENGINE=InnoDB COMMENT='平台备份运行记录：控制台或定时建待办，打包机认领并产出，服务端收尾。只记状态与结果，备份内容本身在对象存储里';
```

`objects` 用 JSON 列而不是子表：每次最多三行、形状固定、只整体读整体写，`AGENTS.md` 的复用原则下不值得为它开一张表。但**不要在它上面建索引也不要按它查**——要按对象键反查的时候，说明设计已经跑偏了。

四处和 v5 不一样，前三处是实测出来的：

- **`seq` 用 `AUTO_INCREMENT`，不用 `COALESCE(MAX(seq),0)+1`。** 后者在 `REPEATABLE READ` 下是一致性读，两个并发事务读到同一个值；实测（MySQL 8.0.46）第二个请求**阻塞整个第一个事务的时长**才拿到 1062，而且报的索引是 `ux_platform_backups_seq` 不是 `ux_platform_backups_live`——MySQL 对同时违反两个唯一索引的 INSERT 报**先建的那一个**。按 v5 的契约只匹配 `ux_platform_backups_live` 就翻 409 的话，并发那条会掉进 500，而 §9 那条「两个请求同时打 `/backup/run`，只成功一条，另一条 409」的测试在真 MySQL 上会红。自增锁不参与事务，换成它之后唯一能冲突的就剩 `live_slot` 一个，错误映射唯一。InnoDB 允许 `AUTO_INCREMENT` 列作为某个索引的第一列，主键仍是 `id`。
- **生成列直接写进 `CREATE TABLE`**，不再单独 `ALTER`。少一个可能半途失败的 DDL。
- **`payload_received_at` 是新列。** 没有它，「产出超时：running 超过 30 分钟没上报」在打包机已经上报完的情况下语义是空的。2-of-3 下打包机要传两份，这一列记的是**最后一份**到齐的时间；没到齐之前它保持 NULL，超时按 `claimed_at` 算。
- **`objects` 取代了 v5 的 `object_key` / `sha256` / `size_bytes` 三个单数列**，因为一次备份现在产出三个对象。

**备份签名公钥另有归宿**：它进既有的 `build_agent_keys`（`internal/api/build_agent_key.go` 那张表），加一个 `kind` 维度区分 `x25519-keystore`（既有那把）和 `ed25519-backup-sign`（新的），**旧行保留不删**——历史包的签名要靠它验（§4.3 第 3 条）。这是给既有表加列，不是新建表。

**迁移必须幂等，三步全要**：`CREATE TABLE IF NOT EXISTS`、（若分步）`addColumnIfMissing`、建索引前查 `information_schema.STATISTICS`。模板在 `internal/store/migrations.go:1503-1518`。v5 只说了后两条，漏了 `CREATE TABLE` ——那正是 `build-concurrency-2026-09-15.md:225-247` 逐字测过的红线：`CREATE TABLE` 成功、建索引失败 → `INSERT INTO schema_migrations` 那一行不执行（`migrations.go:990-993`）→ `Migrate` 返回 error → `store.Open` 失败 → 进程退出 → `MYSQL_AUTO_MIGRATE` 默认 true，下次启动重跑、撞 `ERROR 1050 Table already exists` → **永久启动失败循环，下线的不是备份功能，是整个 wallet 后端。**

`COMMENT` 里不能出现单引号——集成测试在这上面挡过一次。

`live_slot` 的唯一索引**不带 `tenant_id` 前缀是对的**：`build_jobs` 那道闸是按租户的，`platform_backups` 根本没有租户维度，闸就是平台全局一条。实测确认「任意多条已结束 + 至多一条在途」是它的语义，`failed` 不占槽。

**还有一条硬约束：封外层 + 上传绝对不能包在那个把状态翻成 `succeeded` 的事务里。** 实测：`UPDATE ... SET status='succeeded'`（`live_slot` 1→NULL）会让并发 INSERT 一直等到该事务提交（5 秒的事务就阻塞 5 秒）。「上传完再写 succeeded」的自然写法极容易变成 `BEGIN; UPDATE; <上传>; COMMIT`，那样整个平台的 `/backup/run` 会阻塞整个上传时长，再被 10 秒的 DB 超时砍掉返回 500。同理 `/backup/run` 那个事务里只许有「插一行 + 写一条审计」，不许有任何外部调用。

### 8.5 状态机：谁写、怎么写、超时谁执行

v5 只给了状态语义，没给写法。四个写方（控制台建、打包机认领、服务端收尾、超时扫描）都要动同一行，按 v5 的文字实现会互相覆盖。

**每一条转换都写成带状态条件的 UPDATE 并检查 RowsAffected**，先例是 `markBuildJobFailed` 的 `WHERE status IN (...)`（`build_jobs.go:950`）：

| 转换 | 谁 | 写法 |
|---|---|---|
| → `pending` | 控制台 / 定时 | 单条 INSERT，1062 撞 `ux_platform_backups_live` → 409 带 seq 与 status |
| `pending` → `running` | 打包机认领 | `FOR UPDATE SKIP LOCKED` + `WHERE id=? AND status='pending'` |
| 记一份 payload 到达 | 服务端收 payload | `WHERE id=? AND status='running'`；两份都到齐了才写 `payload_received_at` |
| `running` → `succeeded` | 服务端收尾 | `WHERE id=? AND status='running'`，0 行说明被别人收尾了，放弃并记日志 |
| `pending`/`running` → `failed` | 打包机上报 / 超时扫描 / force-fail | `WHERE id=? AND status IN ('pending','running')` |

不加 CAS 的具体后果：payload 第 2 分钟到达，服务端开始封外层+上传；第 30 分钟产出超时扫描判 `failed`；第 31 分钟上传完成，服务端无条件写 `succeeded`——一条本该 `failed` 的记录变成 `succeeded`，而 `failure_reason` 还留着。反过来也成立。

**两个超时都跑在服务端自己的定时器上。**

- **认领超时**：`pending` 超过 15 分钟没被认领 → `failed`，原因写「打包机没有响应」。
- **产出超时**：`running` 且 `COALESCE(payload_received_at, claimed_at)` 早于 30 分钟前 → `failed`。2-of-3 下「只传上来一份就断了」落在这一条里：`payload_received_at` 还是 NULL，按 `claimed_at` 判死，已经收到的那一份随记录一起作废。

**认领超时绝不能挂在打包机轮询路径上**，尽管这个仓库的既定做法正好会把它做错：`claimBuildJob` 的注释写着「发新活之前先把心跳停了的旧任务收掉。挂在这条路径上而不是另起一个后台循环」（`build_jobs.go:679-682`）。照抄就死——**认领超时的触发条件恰恰是「打包机不轮询了」**。完整时序：打包机挂了 → 定时建一条 `pending` 占住 `live_slot` → 没人认领也没人判它超时 → 这条 `pending` **永远**占着唯一索引 → 此后每次定时都撞 1062、每次点「立即备份」都 409 → 平台没有告警（§15），没人会发现备份三个月没跑过。后台 ticker 的先例：`internal/indexer/indexer.go:60`、`internal/push/dispatcher.go:126`。

**超时判据只许读行上的时间列，不许有任何内存状态。** 这样重启、部署、回滚、再滚回全部自愈（§10）。仓库里正好有一条同形状的先例：`internal/push/dispatcher.go:125` 在 `Run` 的第一行就跑一条纯时间列的 `UPDATE ... WHERE status='processing' AND locked_at<?` 把上一次进程留下的在途任务收回来。

**定时触发不要用 `time.NewTicker(interval)`。** ticker 的相位从进程启动算起：`BACKUP_INTERVAL_HOURS=24` + 每天有一次部署或重启 = **备份一次都不会跑**，而控制台上「上次成功时间」一直是空的，没人会把它和部署节奏联系起来。这是本方案最坏的一类失败：以为有备份，其实没有。

正确写法：ticker 只做 **1 分钟一次**的「到点了吗」轮询，到没到点由库决定——`SELECT MAX(created_at) FROM platform_backups WHERE trigger_by='schedule'`，`now - last >= interval` 才建。重启、多实例、中途改间隔全部自洽。多实例下第二个实例会吃 `ux_platform_backups_live` 的 1062，把它当「别人已经建过了」静默吞掉（每分钟一条 ERROR 日志会把人训练到无视它）。

### 8.6 控制台侧（RN-Admin）

**挂进已有的「平台维护」插件，不新开一个。** 用户要求这个功能和已有的平台级菜单放在一起，而 `src/modules/build-config/plugin.ts:67-74` 的 `adminPasswordPlugin` 正是那个插件（`label: "平台维护"`、`platformOnly: true`）。加第二个导航项即可：

```ts
export const adminPasswordPlugin: AdminPlugin = {
  id: "admin-password",
  label: "平台维护",
  icon: "shield",
  platformOnly: true,
  navigation: [
    { id: "admin-password", label: "管理员口令", icon: "key" },
    { id: "platform-backup", label: "备份与恢复", icon: "archive" },
  ],
  pages: {
    "admin-password": AdminPasswordPage,
    "platform-backup": PlatformBackupPage,
  },
};
```

`platformOnly: true` 由 `App.tsx:206-208` 按会话的 `platformAdmin` 过滤，**前端过滤只是不显示，真正把关的是服务端的 `requirePlatformAdmin()`**（§6）。不要在前端做任何「因为藏起来了所以安全」的假设。

新增文件，和 `platform-accounts` 模块同构（`plugin.ts` + 页面 + `.spec.tsx`）：

| 文件 | 内容 |
|---|---|
| `src/modules/build-config/platform-backup-page.tsx` | 页面本体 |
| `src/modules/build-config/platform-backup-page.spec.tsx` | 单测 |
| `src/modules/build-config/plugin.ts` | 上面那段改动 |
| `src/core/admin-i18n.tsx` | 新 key 的 zh / en 两张表，以及 zh→key 反查字典三处都要加 |
| `src/design-system/page-skeletons.tsx` | `PlatformBackupPageSkeleton`，照 `FormLayoutSkeleton` + 一张表的形状 |

**i18n key 一览**（zh / en 两张表 + zh→key 字典，三处联动，漏一处会在运行时掉回中文原文）：

`navPlatformBackup`（备份与恢复）、`backupRunNow`（立即备份）、`backupRunReason`（备份原因）、`backupSchedule`（定时备份）、`backupIntervalHours`（备份间隔（小时））、`backupLastSuccess`（上次成功）、`backupConsecutiveFailures`（连续失败）、`backupThresholdMode`（门限模式）、`backupSingleKeyWarning`（单钥模式，过渡状态）、`backupRecoverySlots`（恢复公钥槽位）、`backupSlotHolder`（由谁保管）、`backupSigningKey`（备份签名公钥）、`backupAgentKey`（打包机公钥）、`backupPairAB` / `backupPairAC` / `backupPairBC`、`backupDownload`（下载）、`backupExpired`（已过保留期）、`backupForceFail`（强制判失败）、`backupBucket`（备份桶）、`backupBucketTest`（测试连接）、`backupVersioningOff`（桶未开 versioning）。

**四个指纹分四个区块显示**，各自带标题和算法说明（§2.2 的表）。把它们排成一列不带标题，是这套东西唯一那个人工核对环节失效的最直接方式。

**下载按钮的行为**：每条记录按**那一条的 `objects`** 展开几行（老记录可能只有一组，别按当前门限模式渲染），每行一个按钮，点了先要求重新输入一次管理员口令（§6）。已过保留期的按钮置灰并显示原因，**不要让它发一个注定 404 的请求**。

**「立即备份」是异步的**（§4.4），点完不要转圈等结果：立刻刷新状态、显示「已排队，等打包机认领」，之后靠轮询更新。已有在途时按钮置灰，旁边显示那条的 `seq` 和状态——服务端返回 409 时也是同样的文案，两条路要一致。


## 9. 测试

**容器格式**

- 往返：产出 → 用测试私钥解开 → 逐文件比对内容与 sha256；两层嵌套各验一次。
- **跨实现**：Go 封、**openssl 解**。这一条是专门为 PKCS#7 填充设的——漏写填充时 Go↔Go 往返会绿，只有 openssl 那条路径炸，而那是灾难当天唯一走的路径（§4.6）。
- **每层密钥材料独立**：外层与内层 `key.bin` 解出的 80 字节必须不相等。
- **篡改被发现**：`payload.enc` 翻一位 → MAC 校验失败并**在解密之前**中止；单独改 `meta.json` 的 `layer` / `recipient` / `createdAt` → 同样失败（v5 的 MAC 覆盖范围下这条会漏）。
- **拼接被发现**：把另一次备份的 `inner.rnbk` 换进来 → `manifest.files[]` 的 sha256 比对失败。
- **伪造被发现**：用公钥自己封一个完整合法的包 → 两层 MAC 都通过，但 `inner.rnbk.sig` 验签失败、且整包 sha256 与库里那行不一致。**这条测试 v5 没有，而它对应的是唯一一条会导致恢复时执行攻击者代码的路径。**
- 只有外层那一把私钥时，`server.rnbk` 与 `inner.rnbk` **都打不开**（守住「要两个人」）。

**门限矩阵**（这一组是 2-of-3 的核心，缺了它「任意两把能开」只是一句话）

- 三把私钥的**三种两两组合各能开对应那个包**：A+B 开 AB，A+C 开 AC，B+C 开 BC。
- **任意单独一把都打不开任何一个包**——三把 × 三个包 = 九次断言，全部失败才算过。
- **配错的组合打不开**：拿 A+B 去开 AC 包，失败。
- 三个包解出来的**内容逐字节相同**（同一次备份的同一份内容，只是锁不同）。
- 只配两把公钥 → 产出一个包，`manifest.pair == "AB"`；只配一把 → 单层单包。
- **升级路径**：先配 A+B 跑一次备份（一个包），再补上 C 跑第二次 → 第二次产出三个包，**第一次那条记录仍然只有一组**，控制台按各自的 `objects` 渲染而不是按当前模式。
- 配对规则是从槽位集合推的，不是下发的：给服务端塞一个不在配置里的收件人 → 打包机拒绝执行并上报（§4.2）。
- 配成 A+C 跳过 B → **拒绝启动**（§8.3）。
- 三把里有两把相同 → 拒绝启动。

**元数据契约**（§4.7）

- `meta` 排在 `payload` 之前，服务端能在收 512 MiB 之前就拒掉非法元数据。
- `innerFiles[].path` 带 `..`、引号、换行 → 400，且**不落任何临时文件**。
- `innerFiles[].mode` 不匹配 `^0[0-7]{3}$` → 400。
- 租户 slug 不匹配 `^[a-z0-9-]+$` → 400。
- `backupSigningFingerprint` 和库里登记的那把不一致 → 这条待办直接判 `failed`，原因可读。
- 渲染出来的 `recover.sh` 里，`innerFiles[].path` 的内容被正确转义——用一个带 `$(...)`、反引号、单引号的路径做断言。
- 同一个 `:id` 同一个 `recipientSlot` 传两次 → 第二次 409，第一次的记录不受影响。
- 只传了槽位 A 那一份就断线 → 产出超时把记录判 `failed`（`payload_received_at` 仍为 NULL）。

**备份签名公钥登记**

- 库里没有 → 自动接受。
- 库里已有另一把 → `pending_acceptance`，**不自动替换**；此前的包仍然用旧公钥验得过。
- 旧行不被删除（历史包要验签）。

**配置与权限**

- 三把槽位里有两把配成同一把、或跳过 B 只配 A+C → 拒绝启动；非 production 环境同样拒绝（§8.3）。
- 打包机拿到的 `innerRecipient` 与自己 env 里的不一致 → 拒绝执行并上报，**不产出**。
- 打包机 env 缺 `BUILD_AGENT_RECOVERY_RECIPIENT` → 照常领构建，但拒绝认领备份待办并上报原因。
- 非平台管理员访问全部备份路由 → 403；`PLATFORM_ADMIN_USERNAMES` 为空 → 403。
- `download` 用不存在的 `seq`、别人的 `seq`、带 `..` 的 `seq` → 400/404，且不产生任何对象读。

**状态机**（跑在真 MySQL 上，不是 sqlite）

- 并发建待办：两个请求同时打 `/backup/run`，只成功一条，另一条 **409**（不是 500）。
- 认领并发：两个 claim 同时打，只有一个拿到待办。
- **`/backup-keystores` 必须先经过 `claim`**：直接造一条 `pending` 行再调接口 → 403。造 25 个租户，认领后断言返回 25 条不是 20 条。
- 认领超时与产出超时各自把记录判 `failed`；扫描器只读行上的时间列，重启后照样收拾。
- `force-fail` 把一条 `running` 判死，之后能立刻建下一条。
- 迟到的 `/payload`（记录已 `failed`）与迟到的 `/fail`（记录已 `succeeded`）→ 409 且不写任何一列。
- 收尾与超时扫描竞态：先判 `failed` 再收尾 → 收尾的 UPDATE 影响 0 行，记录保持 `failed`。
- 定时：`BACKUP_INTERVAL_HOURS=24`，模拟进程每小时重启一次 → 24 小时内仍然建了且只建了一条。

**脚本与文档**

- `recover.sh` 在一台干净容器里跑通，并断言落盘权限是 0600、工作目录在 tmpfs、退出后已清理。
- 目标路径已存在时 `recover.sh` 停下来问，不覆盖。
- `README-FIRST.txt` 与 `open-layer.sh` 里的命令**逐条复制粘贴能跑**——这条在 CI 里跑，不能靠人看。

门禁：

```bash
test -z "$(gofmt -l cmd internal)"
go vet ./...
go test -race ./...
go build ./cmd/server ./cmd/build-agent
```

## 10. 兼容、发布与回滚

**顺序：先写 env，再部署服务端，最后部署打包机。** 第一步不能省——服务端启动校验会因为两把公钥缺失而拒绝启动（§8.3），而 PEM 走 base64 单行正是为了让这一步不出意外。

**一条硬规则代替 v5 的升级顺序论证：备份功能不得向任何既有请求体新增字段。** v5 说「打包机的请求体过服务端的 `DisallowUnknownFields`」——那条论证张冠李戴：`DisallowUnknownFields` 在 `decodeLimited`（`server.go:1956`）里，对**新接口**根本不起作用，因为老服务端上压根没有 `/v1/build-agent/backup-requests` 这条路由，而这个 router 没注册 `NoRoute`/`NoMethod`（零命中），新打包机拿到的是 gin 默认的裸 404。

真正会出事的是另一条路：`claimBuildJob` 的 body 是 `{agent, platforms}`，解码失败直接 `400 INVALID_BUILD_CLAIM`（`build_jobs.go:661-664`）。**只要备份功能顺手往这个既有请求体里加一个字段**（`agentVersion`、`capabilities`、「我配了恢复公钥」之类——§8.3 要求控制台能看见「打包机没配恢复公钥」，实现者第一反应就是在 claim 里带上），新打包机 + 老服务端就**一条构建都领不到，全平台构建停摆**。所以那个信号走 `/backup-requests/:id/fail` 的 reason，不要挤进 `/claim`。规则比顺序可靠：顺序总有人搞反，规则能进 code review。

**打包机不升级也不会坏**：它不认识新路由就永远不会去调，备份待办走认领超时判 `failed`，构建一切照常。**但这条成立的前提是 §8.5 的认领超时真的有人执行**——不执行的话，「老打包机」就等于「备份功能永久自锁」。

**回滚**：

- 服务端回滚：待办停在 `pending`，超时后判 `failed`，无数据损坏。
- **回滚窗口**：服务端「收到 payload → 封外层 → 上传 → 写 succeeded」这一段，长度等于加密加上传的耗时（分钟级）。正好在窗口里重启，那条记录停在 `running`，而**超时扫描器本身也被回滚掉了**，于是没有任何东西会去动它，`live_slot` 被永久占住。滚回新版本后能不能自愈，取决于扫描判据——§8.5 要求它只读行上的时间列，就是为了这一刻。人工收尾用 `force-fail`，不要直接改库。排查 SQL：

  ```sql
  SELECT seq, status, claimed_by, claimed_at, payload_received_at, updated_at
    FROM platform_backups WHERE status IN ('pending','running');
  ```

- **桶里可能已经有对象而记录说 `failed`**——那是一份完整的全平台签名密钥孤儿对象，不在任何清单里、不会被 §12 第 1 级覆盖、只能等生命周期。§4.5 定死了写入顺序（先 `.rnbk` 后 `.README.txt`），README 的存在就是提交标记，恢复时也好判断。
- 迁移只增表，没有 down migration（`AGENTS.md:26`）。真要退表，是手工 `DROP TABLE platform_backups` + `DELETE FROM schema_migrations WHERE version=<N>`，两步都做，漏了账本那一行会让服务端认为迁移已跑过、永远不再补。
- **已经产出的备份包不受任何回滚影响**——它在对象存储里，格式自描述，用 openssl 就能开。

## 11. 必须同时修的

**服务端能让打包机执行任意代码**——这条不修，§4.2 的「公钥写死在配置里」是绕得开的：攻击者不用改收件人，直接让打包机检出一个带后门的提交，以 `builder` 身份读走 `agent-key` 就行。详情与修法记在 `build-concurrency-2026-09-15.md` §9（`git_ref` 从库里读出下发、代理零校验）。**本方案依赖它，必须一起做。**

另外三条阻断，不修则恢复走不通：

| 问题 | 后果 |
|---|---|
| 「上传签名密钥」接口只认旧格式（`internal/api/build_keystore.go:167-174` 要 scrypt + salt），而 CLI 产出的是新格式（那两个字段为空） | 手上有明文 `.p12` 也装不回去——§7.2 末尾和 §7.3 末尾那两条路都卡在这里。而且 CLI 的屏幕提示还在教用户去调这个接口（`cmd/build-keystore/main.go:156` 与 `:250` 两处 `curl -sS -X PUT`），那是一条必然失败的指引 |
| 打包机公钥的 base64 值全系统没有出口（接口只回指纹，`build_agent_key.go:141-155`；`build-agent` 没有任何子命令——`grep "os.Args\|flag\." cmd/build-agent/*.go` 零命中） | 修好上面那条也还是卡住——重新封盒子需要这个值。要补的子命令是 **`build-agent show-key`**：打印 `agent-key` 的指纹和公钥 base64。§7.2 第 4 步用的就是它，`manifest.agentKeyFingerprint`（§4.5）是它的比对对象 |
| 恢复后签名密钥不会重新校验：待验清单跳过「这一版已经验过」的租户（`build_keystore_check.go:95-122`），而恢复场景里数据库一个字没动 | 控制台显示「正常」，看的是灾难前那台机器写下的记录。§7.2 第 5 步的 `DELETE` 是绕过它的手段，但那是人工步骤，接口层面该有个正经的「重置校验状态」 |

## 12. 怎么证明备份是有效的

**服务端永远无法证明「那两把恢复私钥真的能开」**——它一把都没有。它能做的只有结构自检，而且这个自检比看上去弱得多：现有 `SealTo` 封完调的那次自解（`recipient.go:142`）在真正解密之前就返回了，只做了三个长度断言。

所以分四级，**只有第二级能证明那两把私钥还能用**：

1. **每次产出**（自动）：文件 sha256 与清单一致、关键内容非空、包体相对上次没有异常跌落、上传后从桶取回来重算一次 sha256 并落库。
2. **每月**（人工，两个人各花几分钟）：两位持有人按 `README-FIRST.txt` 开一次最新的包。判据有三条：**两个人各自独立取出自己那份介质、独立输入口令成功**（§2.1 第 3 条）；签名验得过；`manifest.tenants[]` 的租户清单对得上。
   **每月轮换一组**：这个月 AB，下个月 AC，再下个月 BC。一个季度正好把三组和三个人都走一遍——只盯着一组练，另外两组坏了你不会知道，而真出事那天你多半恰好用不上练过的那一组。
   **这一级用「轻模式」：验签 + 验 MAC + RSA 解封 + 只解出 `manifest.json`，不解 `keystores/`。** 理由具体：完整解包会把全平台所有租户的签名密钥明文落到某个人的笔记本上，一年 12 次；而这一级真正要证明的是「那两把私钥还能用、两个人还在」，那不需要看到密钥本身。
3. **每季度**：走完 §7 的完整流程，判据是跑通一条真实的 **APK** 构建。不能用 OTA 构建当判据——OTA 构建根本不碰签名密钥（`cmd/build-agent/ota.go:13-16`），拿它验等于什么都没验。这一级在一台用完就扔的机器上做，完整解包只在这里发生。
4. **另外每季度顺带一条离线核对**（不需要恢复整套）：把包里每个 `.p12` 算一次证书 SHA-256（`internal/androidkeystore` 已有 `CertificateSHA256`），和 `db/release-identity/<slug>.json` 里的 `signerSha256` 比对。这条能证明「包里那把确实是线上在用的那把」，成本几秒钟。

**演练通过之前，不要对外说「已经有备份了」。**

## 13. 落地顺序

1. **修 §11 的四条**（`git_ref`、上传格式、`build-agent show-key`、重验）。前三条不修，备份做出来也用不上。**这一步不依赖本方案其余任何部分，可以立刻开工。**
2. **持有人各自生成一对恢复密钥**（§2.2），公钥按槽位 A/B/C 进两边配置，私钥各自存两份，各自抄下打包机备份签名公钥的指纹。**在此之前先手工抄一份 `agent-key` 存着**——这是过渡期的保险，十分钟的事。
   **这一步不阻塞开发**：代码实现的是 2-of-3 的能力，谁持有哪把是运维决定的。人没凑齐就先配两把跑 2-of-2，补第三把只改配置、不改代码，升级路径见 §2.5。
3. **容器格式与签名**（§4.3、§4.6）先独立做出来并通过 §9 的容器格式那组测试，包括跨实现和伪造那两条。它是后面所有步骤的地基，且可以完全离线开发。
4. **数据与状态机**（§8.4、§8.5）：建表、四条转换的 CAS、两个超时扫描器、`force-fail`。在真 MySQL 上跑并发那组测试。
5. **打包机侧产出**：登记备份签名公钥、认领（§8.1）、拉全量密封盒子、解密、收集二进制与 unit 与 ssh 配置、打 tar、**分别封给 A 和 B**、各签一个名、按 §4.7 的 multipart 上报两次。别忘了 `runBackup` 的 25 分钟 ctx 和明文暂存的清理（§3、§4.4）。
6. **服务端侧**：收两份 payload 与元数据（§4.7、§8.1 的两条实现约束）、合并自己那部分、**按三组配对封三个外层**、为每一组生成 `README-FIRST.txt` / `RECOVERY.md` / `recover.sh`、上传六个对象、把三组的键与 sha256 落进 `objects`。
7. **控制台**（§8.6）：挂进「平台维护」插件、配置页、手动按钮、每条三行的下载、`force-fail`、权限门、**四个指纹分四个区块**、i18n 三处联动。
8. **定时**（`BACKUP_INTERVAL_HOURS`）：最后上，按 §8.5 的「1 分钟轮询 + 库里判到点」写，先用手动按钮跑几天。
9. **四级验证各跑一次**（§12），其中第 2 级要把**三组配对全部各开一次**（§2.4）。

配置三处联动见 §8.3，门禁与测试清单见 §9，兼容与回滚见 §10。

## 14. 不做什么

- **数据库备份**：不在范围内。
- **产物文件**（APK / OTA 包）：它们在远端对象存储，不随打包机一起死，而且不是机密。防桶丢失靠桶自己的 versioning 与跨区复制。
- **由打包机把密钥「转封」给服务端指定的新收件人**：谁能往收件人列表里写一行，谁就能让打包机把密钥交出来。收件人写死在两边各自的 root 配置里（§4.2），不给服务端任何指定权。
- **在线验证备份的接口**：那是一个现成的 padding oracle（§4.6）。
- **压缩 payload**：BREACH 式预言机，理由见 §4.6。
- **Shamir 分割 / 新的密码学工具**：卖点是「任何一台 Linux 机器 `tar` + `openssl` 就能开」，2-of-3 如果要上，走「三对各出一个包」这条路，格式一个字不改（§2.1）。

## 15. 已知遗留

- **`STORAGE_MASTER_KEY` 没有轮换机制**（`OPERATIONS_AND_RELEASE.md:311` 明确要求先实现逐版本解密与重加密，至今未做）。它在备份包里，所以桶的保留期就是它历史影响范围的上限。
- **恢复密钥轮换**：换任意一把都要改对应机器的配置、重新产出一份备份、并删掉旧备份（旧备份仍然对旧私钥有效）。要写进运维手册。
- **恢复密钥轮换会同时作废两个包**：换一个人的公钥，他参与的那两组立刻失效，必须当场重跑一次备份，不能等下一次定时（§2.5）。
- **第三个持有人还没定下来时**：先配两把跑 2-of-2，补第三把只改配置、不改代码（§8.3）。但要知道这期间可用性是 2-of-2 那一档（§2.1 的表），别以为已经是 2-of-3 了。
- **三份介质放在同一栋楼**会让 2-of-3 退化成零（§2.3）。这是流程约束，代码管不了，只能写进运维手册并在演练时抽查。
- **GitHub 不可达**：包里只有 RN-App 的 remote 地址和 deploy key，没有仓库本体。GitHub 长时间不可用时恢复会卡在检出那一步。要覆盖它就得把 bare 仓库也装进包，体积是另一个量级，先不做。
- **多账号管理员登录**：§6 的权限门在它落地之前，实际上是「所有能登录的人都看得见」。
- **告警**：平台没有告警基建，连续失败目前只能靠人去看控制台状态。这是 §8.5 那条「`pending` 永远占着闸没人发现」的真正兜底缺口。
- **产出超时的扫描用不上现有索引**：`ix_platform_backups_status (status, created_at)` 覆盖认领超时，产出超时按 `claimed_at` / `payload_received_at` 过滤。行数少，今天无所谓；写在这里免得以后有人纳闷。
- **`-macopt hexkey:` 的值在 `ps` 里可见**（OpenSSL 会主动擦掉 `enc -K` 的 argv，但不擦 `dgst -macopt`）。只泄露 HMAC 键不泄露 AES 键，而且能伪造 MAC 的人本来就能伪造整包，影响有限；在共享或装了 EDR 的机器上会被记进进程日志。

## 16. 修订记录

### v6 → v7：换成 2-of-3，并补齐六处开发缺口

门限从「两个人缺一不可」换成「三个人任意两个」。**容器格式一个字没改**——三个人两两配对成三组，同一份内容封三次，桶里并排放三个包（§2.1）。选这条路而不是「一份密文 + 每对一组拆半密钥」，是因为量过包体：整包约 50 MB（两个 Go 二进制占 35 MB），三份 150 MB、按天保留 90 天约 13 GB，省下的存储买不回后者增加的格式复杂度和出错面。

| 改动 | 落在哪 |
|---|---|
| 2-of-3 的可用性论证、三条配套要求、三组配对的包名与降级模式 | §2.1、§2.3–2.5 |
| 三个槽位 A/B/C、槽位不许重排、**四个指纹四种算法的定义表** | §2.2 |
| 打包机封两份内层、服务端封三个外层；下发三个指纹供核对 | §4.1、§4.2 |
| 六个对象的命名、外层六成员、**内层自己的 `manifest.json`**、`db/*.json` 的导出格式 | §4.5 |
| **新增 §4.7「打包机上报的元数据」**：multipart 三部件、`meta` 结构、服务端只渲染不解释、注入防护 | §4.7 |
| `README-FIRST.txt` 写明本包要谁、以及另外两个包的名字 | §5.1 |
| 控制台：三个槽位、门限模式、每条三行下载、四个指纹分区 | §6 |
| 恢复第一步先挑组；这一组开不了就换一组 | §7.1 |
| `POST /backup-signing-key` 登记接口；`payload` 改 multipart；`download` 加 `:pair` | §8.1、§8.2 |
| 配置键改 A/B/C；槽位必须从 A 连续；两边逐指纹一致 | §8.3 |
| `objects` JSON 列取代三个单数列；备份签名公钥进 `build_agent_keys` 加 `kind` | §8.4 |
| **新增 §8.6「控制台侧（RN-Admin）」**：挂进既有的「平台维护」插件、文件清单、i18n key 一览 | §8.6 |
| 门限矩阵（九次断言）、元数据契约、签名公钥登记三组测试 | §9 |
| 每月演练轮换配对 | §12 |

**六处开发缺口已关闭**：外层 manifest 的字段来源（§4.7）、`RECOVERY.md`/`recover.sh` 描述内层所需的数据（§4.7 的 `innerFiles[]`）、签名怎么随请求走（§4.7 multipart）、备份签名密钥的接口与存储（§8.1、§8.4）、内层清单文件（§4.5）、四个指纹的定义（§2.2）。另两处（`db/*.json` 格式、RN-Admin 契约）见 §4.5 与 §8.6。

### v5 → v6：三轮对抗性评审

三个方向各一轮（恢复可执行性 / 容器与密码学 / 状态机与并发）。下面每一条都自己复核过，未通过复核的意见没有采纳。

| 改动 | 起因 | 影响 |
|---|---|---|
| §3 包里补进两个二进制、systemd unit、nginx 配置、TLS 证书、RN-App 的 remote 与 deploy key | v5 只装了机密。目标机器没有 Go 工具链，`deploy.sh` 是在开发机上交叉编译的 | **拿到 v5 的包装不回去**。这是最严重的一条 |
| §4.3 新增：sha256 锚点 + 打包机对内层签名 | 容器只有保密性。公钥不是秘密，任何有桶写权限的人都能伪造一个 MAC 通过、能解开、里面是他写的 `recover.sh` 的包 | 恢复当天以 root 执行攻击者代码 |
| §4.6 MAC 覆盖扩到 `meta.json ‖ key.bin ‖ payload.enc` | v5 只覆盖 `payload.enc`，`layer` / `recipient` / `alg` 可随意改 | 降级通道、误导操作者 |
| §4.5 `manifest.files[]` 明确覆盖两个 `.rnbk` | v5 没说是哪一层的成员 | 旧包内层塞进新包，两层 MAC 全绿，恢复出旧密钥或对不上的 `agent-key` |
| §4.6 明写 PKCS#7、每层独立随机、不压缩、`-C`、`set -euo pipefail`、tmpfs + `umask 077` | 逐条实测：漏填充会静默丢 16 字节且 `tar` 照读；跨层复用密钥会让 2-of-2 塌成 1 而测试全绿；不分目录时第二层覆盖第一层的中间文件 | 灾难当天才会暴露 |
| §2.2 指纹定义写死为 DER SPKI 的 SHA-256 小写 hex | 三种自然写法给三个不同的值，v5 没定义 | 核对仪式假通过或假失败 |
| §2.1 可用性账重算；§2.5 删掉「破窗信封」 | `P₂/P₁ = 2 − p` 恒大于 1，「每人存两份」只作用在介质丢失那一个分量；破窗信封把 2-of-2 退回 1-of-1 | 按两人落地不变（这是既定决策），但三条前提补齐，2-of-3 作为切换点记进 §15 |
| §8.1 `/backup-keystores` 门禁从 pending 改成 running + 请求 id | 认领那一刻状态就变 `running`，v5 的判据**每次备份都拿不到盒子**，而 v5 的测试因为不经过认领会绿 | 测试绿、生产必挂 |
| §8.1 `/payload` 另起 ctx + ContentLength 前置校验 | `…/payload` 不在 10 秒 DB 超时的豁免名单里，封外层和上传全部 `context deadline exceeded` | 每一次备份都失败 |
| §8.4 `seq` 改 `AUTO_INCREMENT`；`CREATE TABLE IF NOT EXISTS`；新增 `payload_received_at` | 实测 MySQL 8.0.46：`COALESCE(MAX)+1` 并发时阻塞且报错的是 `seq` 索引不是 `live` 索引 → 500 而非 409；`CREATE TABLE` 不幂等会把整个 wallet 后端锁进启动失败循环 | 并发测试会红；迁移半途失败会下线全站 |
| §8.5 新增整节：四条转换的 CAS、超时跑在服务端 ticker、定时改成「1 分钟轮询 + 库里判到点」 | v5 只有语义没有写法；认领超时挂在轮询路径上永远不触发；`time.NewTicker(24h)` + 每天一次部署 = 一次都不跑 | 「以为有备份，其实没有」 |
| §8.2 新增 `force-fail`；`download` 改读 `object_key` | SIGKILL 是我们自己运维手册教的，之后 30 分钟一次备份都做不了；`instanceId` 全仓库零命中，拼键在改名或恢复后全部 404 | |
| §8.3 校验不再挂在 `Environment=="production"`；PEM 走 base64 单行；间隔下界抬到 6 | amos 不是 production；`EnvironmentFile` 写 PEM 换行极易写坏；1 小时 × 90 天 = 2160 份密钥副本 | |
| §7 拆成场景 A / 场景 B；命令补齐端口、`x-admin-key`、`Host`、`ADMIN_API_ALLOWED_IPS` 的坑 | v5 假设机器还在，却按「机器也没了」打包；步骤 5/6 没有凭据也没有 Host，照抄跑不通 | |
| §10 把升级顺序论证换成硬规则「不得向既有请求体新增字段」 | v5 的 `DisallowUnknownFields` 论证对新接口不成立（老服务端是裸 404，没注册 `NoRoute`）；真正的雷在 `/claim` 上，加一个字段就全平台构建停摆 | |
| §12 第 2 级改成轻模式，完整解包移到第 3 级 | 每月完整解包 = 一年 12 次把全平台签名密钥明文落到某人笔记本上 | |
| §11 修正引用 | `cmd/build-keystore/main.go:196-201` 是 `--agent-key` 的失败文案，真正教用户调接口的是 `:156` 与 `:250`；`main.go:84-91` 应为 `:83-91`；`server.go:448-467` 应为 `:444` 与 `:446-467` | |

**没有采纳的意见**（复核后不成立）：

- 「TLS 需要一个不在任何 env 和包里的 Cloudflare `CF_Token`，是第三个人质」——`deploy/amos/install-origin-cert.sh` 的存在理由正是**不在这台机器上放能改 DNS 的凭据**：Cloudflare Origin CA 证书 15 年有效、不走 ACME。把证书和私钥收进包就够了（§3）。
- 「服务端收到 `agent.rnbk` 后不许落盘」——它是**封给甲的密文**，服务端读不懂。落一个 0600 的临时文件是为了校验大小和流式封外层，这不改变安全边界。真正的问题是它**存在过**，已写进 §2.1 的范围说明。
- 「同一个随机源同时产 AES 键和 HMAC 键、不做 KDF 有问题」——不成立。80 字节均匀独立，Encrypt-then-MAC 要的就是两把独立均匀的键。v5「省掉一次 KDF」的理由站得住，保留。
- 「排除 `schema_migrations`」「身份进 AAD」「`SealTo` 会自解一次做 sanity check」——前几轮已经复核掉，不再重复。
