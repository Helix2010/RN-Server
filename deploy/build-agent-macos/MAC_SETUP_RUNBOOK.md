# Mac 打包机：从零装到能出包

照这份从上往下做。每一步给了命令和**合格线**——对不上就停，别往下走。

配套文档：签名材料的来龙去脉在 [`SIGNING_MATERIAL.md`](SIGNING_MATERIAL.md)，方案设计在
`docs/design/ios-mac-builders-home-network-2026-09-18.md`。

---

## 0. 两台机器

这件事需要**两台**机器，角色不能合并：

| | **A 机（签名机）** | **B 机（打包机）** |
| --- | --- | --- |
| 干什么 | 持有发布私钥，每次发版签一份清单 | 领任务、出 `.ipa`、传 App Store Connect |
| 上面有什么 | `release-key.ed25519`（0600） | 全部租户的 Distribution 私钥、上传 Key、机器令牌、deploy key |
| 要 Xcode 吗 | **不要** | 要，而且必须是 xip 装的 |
| 要多大磁盘 | 几百 MB | **60 GB 以上**空闲 |
| 要 Apple Silicon 吗 | 不要，什么机器都行（连 Mac 都不必） | **要**，安装包只编 darwin/arm64 |
| 要联网吗 | 签名时不需要；取仓库和 `manifest.json` 时需要一次 | 要 |
| FileVault | 要开（私钥在上面） | **必须开**，脚本查不到会拒装 |

### 一条铁律

> **发布私钥绝不能出现在 B 机上。**

自升级是整个方案里唯一一条「服务端能往打包机上放可执行代码」的路，而打包机上放着全部租户的
签名材料。这条路之所以安全，全靠"清单要由一把**服务端手里没有**的私钥签过"。私钥要是和打包机
同机，攻破打包机就同时拿到密钥和材料，这道闸等于不存在。

A 机不必是 Mac。`bundle-sign` 是纯 Go，`GOOS=linux` 一样构建，它只做一件事：读私钥、签几百字节。
一台旧笔记本、一台平时关机要签才开的小主机都行。

### 另外两把钥匙也别放 B 机

- **RN-App 的提交签名私钥**（`~/.ssh/rn-app-signing-*`）：它决定"谁能给 main 出包"。放在 B 机上，
  攻破 B 机的人就能伪造一个能过验签的提交。留在开发机上。
- **管理端的平台管理员口令**：同理。

---

## 1. A 机：签名机

### 1.1 装 Go 和仓库

```bash
git clone <RN-Server 远端> RN-Server
cd RN-Server
git checkout main && git pull --ff-only
git rev-parse HEAD            # 记下这个提交，第 3 步要用
```

> **macOS 上的坑**：`/usr/bin/git` 是 Xcode 的 shim。机器上装过 Xcode 但没接受许可，`git`、
> `clang`、`make` 会一律罢工，报的是「You have not agreed to the Xcode and Apple SDKs license」。
> 解法 `sudo xcodebuild -license accept`。

### 1.2 构建 bundle-sign

```bash
cd signing && CGO_ENABLED=0 go build -o /tmp/bundle-sign ./cmd/bundle-sign && cd ..
/tmp/bundle-sign
```

**合格线**：不带参数跑，用法里要有 `bundle-sign key public --key <private key file>` 这一行。

两个坑：

- `signing/` 是**独立的 Go module**。必须 `cd signing` 之后再 build，在仓库根目录跑会失败。
- `CGO_ENABLED=0` 是为了不依赖 clang（macOS 上 Go 默认开 cgo，会再撞一次 Xcode 许可那堵墙）。

> **手里那份旧的 `bundle-sign` 不能用。** 2026-09-18 之后签名换成了 OpenSSH 的 `SSHSIG` 封装，
> 旧二进制产出旧格式，服务端会拒，而报错说的是"签名格式不对"，不会告诉你是拿错了二进制。
> 每次要签之前，确认手里这份是当前提交构建出来的。

### 1.3 发布密钥

**已经有一把**（当前这把指纹 `395937be6513e23f0e293dbabb3fd110dd864bb53ef7b48cf47d35e2849b978a`）：

```bash
# 确认私钥还是那一把
openssl base64 -d -A < ~/rn-release-ios-key/release-key.ed25519 | tail -c 32 | shasum -a 256
# 公钥重出一份（旧格式是裸 base64，现在要 OpenSSH 的一行）
/tmp/bundle-sign key public --key ~/rn-release-ios-key/release-key.ed25519 > ~/rn-release-ios-key/release-key.pub
ssh-keygen -l -f ~/rn-release-ios-key/release-key.pub
```

**合格线**：前两条都打出 `395937be6513e23f0e293dbabb3fd110dd864bb53ef7b48cf47d35e2849b978a`。

**还没有**：

```bash
/tmp/bundle-sign key create --out ~/rn-release-ios-key
```

私钥内容**立刻存进密码管理器**（A 机坏了而密码管理器里没有备份，就再也签不出更高序号的清单，
所有 Mac 停在当前版本）。打印的 `public key sha256` 也记进密码管理器——装机时要人手抄的就是它，
**整条链子上唯一的外部输入**。

新密钥还要把公钥行放进仓库：

```bash
cat ~/rn-release-ios-key/release-key.pub > <仓库>/deploy/build-agent-macos/release-key.pub
```

### 1.4 确认 B 机上没有私钥副本

在 **B 机**上跑：

```bash
ls ~/rn-release-ios-key/ 2>/dev/null || echo "干净"
```

打出文件列表就说明私钥在 B 机上，`rm -P` 删掉再继续。A 机和 B 机各留一份 = 两倍的暴露面。

---

## 2. B 机：打包机体检

脚本的 `preflight` 会一次性把缺的全列出来再退出，**检查阶段失败不消耗注册码**。所以嫌麻烦
可以直接跳到第 4 步让它体检。提前对一眼省来回。

```bash
uname -m                                   # 必须 arm64
sw_vers
xcode-select -p                            # 必须在 /Applications/Xcode*.app/ 下
xcodebuild -version                        # 能打出版本号
df -g /                                    # 第 4 列 ≥ 60
fdesetup status                            # 必须含 "FileVault is On"
git --version                              # ≥ 2.30
node --version                             # ≥ 22
which node pnpm pod git                    # 必须在 /usr/local/bin、/opt/homebrew/bin、/usr/bin、/bin 之一
sudo systemsetup -getusingnetworktime      # 必须 On
```

### 每条为什么

| 检查 | 不满足会怎样 |
| --- | --- |
| `arm64` | 安装包只编 darwin/arm64；Intel Mac 也跑不了当前的 Xcode |
| Xcode 在 `/Applications/Xcode*.app/` | **App Store 装的会静默升级**，几台机器的 Xcode 版本一飘，同一个提交出不同的包。必须用 xip 装（[developer.apple.com/download](https://developer.apple.com/download/all/)） |
| 空闲 ≥ 60 G | 每任务 1–2 G 依赖 + 数 G DerivedData。注意**装机门槛 60 G，运行时低于 40 G 代理就暂停认领**——60 G 只是勉强过线 |
| FileVault On | 这台机器上放着全部租户的 Distribution 私钥；不开，任何拿到机器的人从恢复模式重置口令就能读走 |
| node ≥ 22、git ≥ 2.30 | RN-App 的构建要 |
| 工具在那四个目录里 | 那条 PATH 会写进 env 文件交给执行进程，装在别处到时候找不到 |
| 网络对时 On | App Store Connect 的 JWT 只有 20 分钟有效期，时钟漂几分钟就是 401——而那个 401 看着像密钥有问题，能查很久 |

### 常见的补法

```bash
# 空间用 df -g，不是 df -h：脚本读 df -g / 的第 4 列，按整数 GB 比。
# APFS 容器里所有卷共享同一个 Avail，df -h 列一大堆看着乱。
df -g /

# Xcode 装了但没选中
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
sudo xcodebuild -license accept
sudo xcodebuild -runFirstLaunch

# FileVault
sudo fdesetup enable          # 恢复密钥立刻存进密码管理器

# 网络对时
sudo systemsetup -setusingnetworktime on
```

FileVault 的代价要知道并接受：冷启动会停在预启动解锁屏，断电后得有人到机器前输口令，期间任务
在队列里等。计划内重启用 `sudo fdesetup authrestart` 可以免去到场。

---

## 3. 服务端：让安装包可用

### 3.1 确认部署到位

```bash
curl -s -o /dev/null -w '%{http_code}\n' <API>/v1/machine-setup/install-macos.sh
```

**合格线**：`200`。是 `404` 说明服务端还是旧版本，等 CI 部署完。

### 3.2 A 机签清单

CI 每次部署都会在服务器上产出一份新的安装包目录，**没签过的一律 503，装不了**。

**路径一律走 `current`，不要手抄提交号。** 服务器上每部署一次就多一个以提交号命名的目录，
`current` 这个软链指向当前那一份。手抄提交号每次都是一次抄错的机会，而且抄错的症状是
"签了一份没人要的清单"——服务端那边毫无变化，你会以为是别的地方出了问题。

```bash
mkdir -p ~/sign-bundle && cd ~/sign-bundle && rm -f manifest.json manifest.sig
scp <服务器>:/opt/rn-foundation/machine-bundles/current/manifest.json .

# 提交号从清单里读出来，不手抄
COMMIT=$(sed -n 's/.*"commit"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' manifest.json | head -1)
echo "$COMMIT"

/tmp/bundle-sign sign --key ~/rn-release-ios-key/release-key.ed25519 --dir . --sequence <比上次大 1>
/tmp/bundle-sign verify --pub ~/rn-release-ios-key/release-key.pub --dir . --expect-commit "$COMMIT"
```

**合格线**：`verify` 打出 `signature is valid: commit …, sequence N, release key sha256 395937be…`，
其中的 commit 与上面 `echo "$COMMIT"` 打出来的一致。

> `--expect-commit "$COMMIT"` 看着像自证（两个值都来自同一份清单），它挡的不是"清单被换"——那
> 由签名管。它挡的是**你签的和你以为的不是同一份**：`--dir` 指错目录、上一次的 `manifest.sig`
> 没删干净、`scp` 其实失败了而你用的是旧文件。所以上面第一条命令里的 `rm -f` 不是多余的。

只需要 `manifest.json`，三个 `.tar.gz` 不用拷——清单里已经是每个归档与每个文件的 sha256，
签了清单就等于签了它们。

**序号只增不减，记进密码管理器。** 每台 Mac 记住自己见过的最高值，低于它的清单一律拒——这是
防"攻破服务端后把机器降回一个有已知漏洞、但当初确实被签过的旧版本"那道闸。要回滚就用**更高的
序号**再签一份指向旧提交的清单：回滚是一次显式的、有签名的动作，不是数据库里改一个值。

### 3.3 放回服务器

`/opt/rn-foundation/machine-bundles/` 是 root 的，`rn-foundation-apply` 没有放签名的子命令：

```bash
scp manifest.sig <服务器>:/tmp/
ssh <服务器> "sudo install -o root -g root -m 0644 /tmp/manifest.sig \
  /opt/rn-foundation/machine-bundles/current/ && rm /tmp/manifest.sig"
```

在控制台「平台维护 → 打包机与签名闸 → 构建机 → 打包机程序版本」核对：提交、序号、签名时间、
发布公钥指纹都对，`error` 消失。**那个指纹就是你密码管理器里记的那个**——密码管理器、签名文件、
控制台三处一致，这是设计要的性质。

### 3.4 装机窗口期不要往 main 推东西

推 main 会触发 CI 重新构建，服务器上多一个**新提交**的安装包目录、`current` 跟着切过去。你刚签
的那一份就不是当前那份了，得重签。哪怕只改文档也一样。

---

## 4. B 机：装机

### 4.1 控制台建机器

平台维护 → 打包机与签名闸 → 构建机 → 新建，**类型选 macOS**（iOS 平台会自动勾上且不能取消）。
它会给出注册码和拼好的四行命令，尖括号占位标黄。

### 4.2 四行命令

```bash
curl -fsSLo install-macos.sh <API>/v1/machine-setup/install-macos.sh
shasum -a 256 install-macos.sh
sudo bash install-macos.sh --server <API> --code rne_… \
     --release-key-sha256 395937be6513e23f0e293dbabb3fd110dd864bb53ef7b48cf47d35e2849b978a
```

**第二行不能跳过。** 它的值要和 CI「Build machine bundles」那一步打印的比对——这是整条信任链的
第一环。脚本里的验签靠的是 macOS 自带的 `ssh-keygen -Y verify`，没有自带密码学，就是为了让这个
脚本**能被从头读完**；只比对摘要不读内容，等于只有比对、没有"我知道我在跑什么"。

`--release-key-sha256` 的值从**密码管理器**取，不要从控制台上复制——控制台替人填这个值，等于让
这台机器把服务端说的话当成信任根。

### 4.3 脚本会做什么

按顺序：前提检查 → 系统设置 → FileVault → 建三个角色账户与目录 → `describe` 与验签 → 下载核对
安装包 → 安装程序 → 钥匙串 → 写 env → **注册（注册码在这一步才消耗）** → deploy key → 克隆镜像
→ 装 launchd → 完成。

信任链在「`describe` 与验签」那一步闭合：

```
人给的指纹 → 认出发布公钥 → 验清单的离线签名 → 可信清单里的摘要
            → 核对归档 → 核对包内每个文件（含 allowed_signers）
```

可以重复执行：已注册的机器不重新注册、不覆盖已经放好的签名材料，只核对并确保服务在跑。

### 4.4 中途停在 deploy key

脚本会打印一个 deploy key 让你加到 GitHub 的 RN-App 仓库上，然后退出。加完**重新执行同一条命令**
即可，注册码已经用掉了但脚本认得出来。

---

## 5. 装完验证

1. 控制台看这台机器：在线、角色 builder、系统 macOS、报出它持有的 Apple Team 材料。
2. 「打包机程序版本」里点一次**批准**，机器的 `agentCommit` 才允许升到该提交。
3. 排一条 iOS 任务，看它被领走、出 `.ipa`、落记录。

第 3 条需要 anyfun 的 Account Holder / Admin 先签发第一张 Distribution 证书，并按
[`SIGNING_MATERIAL.md`](SIGNING_MATERIAL.md) §1 做好归档、分发到这台机器。

还有一条容易忘的前提：**打包机只构建签过名的提交**。它跑

```
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=/opt/rn-build-agent/allowed_signers verify-commit -- <sha>
```

验不过整条任务失败。所以目标提交必须是在开发机上、用 `allowed_signers` 里那把密钥、以名单上那个
邮箱提交的。在别处（比如 CI 或 Linux 开发箱）产生的提交一律过不了。

---

## 6. 重装 / 清理

B 机要从头再来时，按 [`SIGNING_MATERIAL.md`](SIGNING_MATERIAL.md) §5 的退役清单做，尤其是：

1. 控制台**吊销**这台机器（旧的机器令牌立刻失效）。
2. GitHub 上删掉这台机器的 deploy key。
3. 机器本体：抹盘重装最干净；不抹盘就 `rm -P` 掉 `/var/rn-build-signing`、`/var/rn-build-upload`、
   `/var/rn-build-agent`，再 `rm -rf /opt/rn-build-agent /var/rn-machine-setup /var/rn-build-jobs`，
   卸掉两个 launchd（`/Library/LaunchDaemons/win.anyfun.rn-build-agent*.plist`），删掉三个角色账户
   （`_rnbuildagent`、`_rnbuilder`、`_rnuploader`）。
4. 每个 Team 的上传 Key 在 ASC 后台 **Revoke**。

然后从第 2 步重新开始。注册码要在控制台重新发一个——用过的不能再用。

---

## 7. 报错的真实含义

| 看到 | 实际是什么 |
| --- | --- |
| `You have not agreed to the Xcode and Apple SDKs license` | macOS 的 `git`/`clang` 是 Xcode shim。`sudo xcodebuild -license accept` |
| `tool 'xcodebuild' requires Xcode, but active developer directory is a command line tools instance` | 只装了 Command Line Tools，没装 Xcode，或没 `xcode-select -s` |
| `fatal: unable to read tree` | 浅克隆或对象库不全。`git fetch --unshallow`，不行就重新克隆 |
| `describe 返回 503` | 安装包还没签。回第 3.2 步 |
| 签完了，控制台还是说 `no manifest.sig` | 多半签到了**别的目录**：往 main 推过东西之后 `current` 换了一份。用 `current` 走一遍第 3.2 步 |
| `服务端给的发布公钥指纹是 X，与 --release-key-sha256 Y 不符` | 手抄的值不对，或服务器上的 `release-key.pub` 不是你那把。**先怀疑抄错**，去密码管理器核 |
| `清单的离线签名验不过` | 签清单用的不是那把密钥，或者清单被改过。也可能是**用旧版 bundle-sign 签的**（旧格式） |
| `the signature is not an armoured SSH signature` | 确定是旧版 `bundle-sign` 签的。重新构建工具再签 |
| `commit X is not signed by an allowed signer` | 目标提交没签名，或提交者邮箱不在 `allowed_signers` 里。见第 5 节 |
| `No signature`（`git log --show-signature`） | **不一定是没签**。本地没配 `gpg.ssh.allowedSignersFile` 时 git 根本没法验，就用这个很误导的说法。判断签没签看 `git log -1 --format='%G?'`：`N` 才是没签 |

---

## 附：本次（2026-09-19）的实际值

| | |
| --- | --- |
| 服务端提交 | `9d73dfd37342255d64a94bcd49063545fea4de0c` |
| `install-macos.sh` sha256 | `ccd959b69e92d10c23e783cb048612843ee65a1e9c22dcc6bd4d2d875e967100` |
| 发布公钥指纹 | `395937be6513e23f0e293dbabb3fd110dd864bb53ef7b48cf47d35e2849b978a` |
| 清单签名序号 | `1`（下次签用 2） |
| `allowed_signers` 文件 sha256 | `296a3753aedc51b632db6fc8a58d58e79c177bf06a16ed27409b0c293fd2c755` |
