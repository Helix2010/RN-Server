# 部署总览：各服务怎么上线、新机器怎么进、旧机器怎么退

这份文档回答三个问题：**平时发版哪些是自动的、哪些要人工做**；**加一台新机器要做什么**；**下掉一台旧机器要做什么**。
每一节末尾都有「怎么确认成功」。逐条命令级的细节在各自的手册里，这里只给流程与顺序：

- 签名闸与构建机（新机器、换密钥、amos 迁移）：[`amos/SIGNING_GATE_ROLLOUT.md`](amos/SIGNING_GATE_ROLLOUT.md)
- 签名闸本机操作（确认、信任、提升、恢复）：[`signer/README.md`](signer/README.md)
- 构建机细节（目录、权限、镜像、deploy key）：[`build-agent/README.md`](build-agent/README.md)
- amos 这台机器本身（nginx、证书、env、备份）：[`amos/README.md`](amos/README.md)
- 配置项含义：[`../docs/CONFIGURATION.md`](../docs/CONFIGURATION.md)

## 0. 有哪些东西要部署

| 组件 | 跑在哪 | 谁部署 | 改了什么会重新部署 |
| --- | --- | --- | --- |
| API 服务端 `rn-foundation-server` | amos | **CI 自动**（push main） | RN-Server 代码、迁移 |
| 扫链 `rn-foundation-indexer` | amos | **CI 自动**（同一个二进制） | 同上 |
| 控制台（两个租户域名） | amos 的 nginx 静态目录 | **CI 自动**（RN-Admin push main） | RN-Admin 代码 |
| 构建机控制进程 `rn-build-agent` + 执行进程 | amos | **CI 自动**（开关 `AMOS_DEPLOY_BUILD_AGENT=true`） | `cmd/build-agent/**` |
| **签名闸 `signer` / `signer-check`** | amos（`rn-signer-a`、`rn-signer-b`） | **人工**（有意为之） | `signing/**` |
| 新机器安装包 `signer.tar.gz` / `builder.tar.gz` | amos `/opt/rn-foundation/machine-bundles/current` | **CI 自动**（随服务端发布） | 上面任何一个程序 |
| 特权收口脚本 `rn-foundation-apply` | amos `/usr/local/sbin` | **人工**（CI 不能改自己的 root 入口） | `deploy/amos/rn-foundation-apply` |
| App（RN-App） | 用户设备 | 排包任务 → 控制台发布 | RN-App 代码、租户配置 |

**为什么签名闸不自动部署**：能往 main 推代码的人，不该因此获得改签名闸的能力——它持有解开签名密钥的私钥。
构建机自动部署是可以接受的：它不持有签名密钥，且交付要经签名闸校验出处。

## 1. 平时发版（服务端 / 控制台 / 构建机）

1. 代码合进 main。
2. CI（`.github/workflows/deploy-amos.yml`）跑门禁：gofmt、vet、带 MySQL 的 `go test -race -p 1`、`signing/` 模块、shellcheck、OpenAPI JSON。
3. 门禁过了才部署，顺序固定：**服务端二进制 → 迁移 → 健康检查（失败自动回滚）→ 新机器安装包 → 构建机程序**。
4. 控制台是 RN-Admin 仓库自己的流水线。

**要人工的只有两种情况：**

- 改了 `deploy/amos/rn-foundation-apply`：CI 会先核对 amos 上那份的 sha256，不一致就报错。按手册 5.0 装上新版再重跑部署。
- 改了 `signing/**`：签名闸要人工升级（见下一节）。

**怎么确认成功**：`ls -l /opt/rn-foundation/rn-server` 的时间；`curl -s http://127.0.0.1:13080/health/ready`；
`readlink /opt/rn-foundation/machine-bundles/current` 等于本次提交。

## 2. 升级签名闸（人工，改了 `signing/**` 时）

前提：服务端已经上线到同一个提交（**服务端必须先走**，新签名闸的上报格式旧服务端不认）。

```bash
B=/opt/rn-foundation/machine-bundles/current
d=$(sudo mktemp -d); sudo mkdir "$d/signer"
sudo tar -xzf "$B/signer.tar.gz" -C "$d/signer"
(cd "$d/signer" && sha256sum bin/signer bin/signer-check)   # 与 CI 日志「Build machine bundles」核对
sudo systemctl stop rn-signer-a rn-signer-b                  # 手上的任务会退回服务端重排
sudo cp -a /opt/rn-signer/bin/signer /root/signer.prev       # 留一份好回滚
sudo install -o root -g root -m 0755 "$d/signer/bin/signer" "$d/signer/bin/signer-check" /opt/rn-signer/bin/
sudo systemctl start rn-signer-a rn-signer-b
sudo rm -rf "$d"
```

**不可回退的那条线**：签名闸一旦在本机记录里写下新类型的记录（信任签名闸、信任恢复公钥、自动确认），
旧版二进制加载记录链会直接报错。所以只能前滚修复，回滚要连状态目录一起按新机器重装。

**怎么确认成功**：`systemctl is-active rn-signer-a rn-signer-b`；
`journalctl -u rn-signer-a -n 20` 里有 `local records verified`，没有校验错误；
控制台机器卡片上两台仍是 active、本机角色分别是主/备。

## 3. 上一台新机器

控制台新建机器 → 那台机器上执行一条命令 → 控制台点接受 → 在签名闸本机建立信任。**注册码只在第 3 步真正消耗**。

### 3.1 通用步骤

1. **控制台**「打包机与签名闸」→ 新建机器，选角色（构建机 / 签名闸主 / 签名闸备）与机器名
   （签名闸的机器名最多 22 个字符，它会变成系统用户名 `rn-signer-<机器名>`）。
   得到一条**一次性安装命令**（注册码 60 分钟有效，可重发）。
   - 平台还没有登记离线恢复公钥时，新建签名闸会被拒（先做第 5 节）。
2. **在新机器上**（root，能访问 API 即可，不需要从你的电脑 ssh 过去）：把控制台给的命令粘上去执行。
   生产上建议用两段式，先看脚本再执行，并带上 CI 日志里的安装包 sha256：
   ```bash
   curl -fsSLo install.sh <API>/v1/machine-setup/install.sh
   less install.sh
   sudo bash install.sh --server <API> --code <注册码> --expect-sha256 <CI 日志里的值> \
        [--recovery-sha256 <密码管理器里的恢复公钥指纹>]      # 签名闸必填
   ```
   脚本做的事：核对前提 → 下载并逐文件核对安装包 → 建用户、目录、sudoers、unit → 生成本机密钥 →
   用注册码换长期机器令牌（令牌不上屏）→ 启动服务 → 打印**本机公钥指纹**与下一步命令。
   重复执行是幂等的。
3. **控制台**点「接受」，核对指纹与安装输出一致。接受只影响服务端路由。
4. **在签名闸本机建立信任**（服务端不能代劳）：
   - 新构建机：每台签名闸上 `signer trust-builder --builder <构建机名>`，粘贴构建机安装输出里的出处公钥指纹。
   - 新签名闸（备）：主签名闸上 `signer trust-peer --peer <新机器名>`；新机器上 `signer trust-peer --peer <主机器名>`，
     指纹取**对方本机** `signer show-key` 或它的安装输出，不取控制台。
   - 平台第一台主签名闸：`sudo systemctl stop rn-signer-<实例>` → `signer promote --first` → 再启动。
     注册一律写成本机备，主只能在本机产生。
5. **已有租户的密钥怎么到新签名闸**：两个方向的 `trust-peer` 都做完之后，主签名闸下一轮检查会把**同一张证书**
   重新封装给它（10 分钟最多一次），证书不变、老用户照常升级。控制台「签名密钥」里它那一行会从「缺」变成有密文。

### 3.2 怎么确认成功

- 控制台机器状态 active，本机角色与登记一致，卡片上没有「还要在本机执行」的提示。
- 签名闸：`signer list` 里有对方与恢复公钥；控制台「签名密钥」里它有密文、试解与确认都通过。
- 构建机：排一个安装包任务，它能领取并交付。

## 4. 下一台旧机器

**顺序很重要：先在签名闸本机撤销信任，再在控制台吊销，最后清机器。** 反过来做会留下一台"服务端已吊销、
但签名闸本机仍然信任"的机器——真正的边界在签名闸本机记录里。

### 4.1 下一台构建机

1. 等它手上的任务跑完（控制台「打包任务」里没有它领取中的任务）。
2. 每台签名闸本机：`signer trust-builder --revoke --builder-id <机器 id> --reason "<原因>"`。
3. 控制台吊销这台机器（令牌立即失效）。
4. 机器上：`sudo systemctl disable --now rn-build-agent`，销毁状态目录 `/var/lib/rn-build-agent`
   （出处私钥、机器令牌、仓库镜像都在里面）与 `/etc/rn-build-agent.env`；GitHub 上删掉它的 deploy key。
5. 确认：控制台里它是 revoked；新任务不会派给它；其余构建机照常出包。

### 4.2 下一台备签名闸

1. 其余签名闸本机：`signer trust-peer --revoke --peer <机器名> --reason "<原因>"`。
2. 控制台吊销这台机器。
3. 机器上：`sudo systemctl disable --now rn-signer-<实例> rn-signer-<实例>-check.socket`，
   销毁状态目录 `/var/lib/rn-signer-<实例>`（私钥与本机记录）与 `/etc/rn-signer-<实例>.env`。
4. **已有密钥里发给它的那份密文不会自动消失**，但下一次重新封装或换密钥时它就不在收件人里了。
   要立刻收回，在主签名闸上等一次重新封装（撤销信任后主会在缺收件人时重算），或直接换一次密钥（会换证书，谨慎）。
5. 确认：控制台里它是 revoked；`signer list` 里没有它；主签名闸日志里不再有「信任的签名闸不在服务端 active 列表」告警。

### 4.3 换掉主签名闸（旧主故障或被攻陷）

1. 控制台把路由主切到备（或先吊销旧主）。
2. 在新主本机：`signer promote --import <旧主的 signed.jsonl>`（旧主状态目录还在），
   或 `--manual`（目录也没了：逐个包名输入已签过的最大 versionCode，取离线记录或设备上的版本，**不取服务端**）。
   `promote` 会自动撤销本机对旧主的信任。
3. 其余每台备：`signer trust-peer --revoke --peer <旧主>`，再 `signer trust-peer --peer <新主>`。
4. 旧主那台机器按 4.2 清掉。**它不能原地改当备**：状态目录里还是主的记录，别人也已经撤销了对它的信任。
   要重新用作签名闸，按新机器重装。
5. 确认：控制台「签名密钥」就绪；新主 `signer list` 里没有旧主；排一个包能签出来。

## 5. 离线恢复密钥（整个平台一次，新平台必做）

1. 离线机器上：`build-keystore recovery-key create --out <目录> --name <名字>`，口令手输两遍。
2. 口令进密码管理器；`recovery-private.key` 进两个离线 U 盘；公钥指纹也记进密码管理器。
3. 控制台「平台维护 → 签名闸恢复密钥」粘贴 `recovery-public.json`。
4. 每台签名闸本机 `signer trust-recovery`，粘贴密码管理器里的指纹（不取控制台的值）。
5. 确认：控制台机器卡片的信任列表里有恢复公钥；之后生成的密钥收件人里能看到它。

**没有它就不能新建签名闸，也不能生成密钥**——签名闸全丢时它是唯一的救命绳。

## 6. 换租户签名密钥（控制台一键）

前提：主签名闸本机为主、备已被主信任、两台都信任恢复公钥、当前密钥的收件人都确认过当前版本
（否则返回 409，要么等它们跟上，要么明确勾选「仍然生成」）。

1. 该租户控制台「配置中心 → 打包与签名 → 打包配置」→「生成签名密钥」，填原因。
2. 主签名闸在本机生成，只加密给本机信任的签名闸与恢复公钥，交回服务端；备自动接受。
3. **已有密钥的租户会换证书：老用户不能覆盖升级，必须卸载重装。** 确认弹层会写明。
4. 生成后：把证书 sha256 记进密码管理器；RN-App `tenants/<租户>/tenant.json` 的 `signerSha256` 改成新值
   （取**主签名闸本机** `signer list`，不取控制台）。
5. 确认：控制台「签名密钥」就绪；排一个新包，`apksigner verify --print-certs` 的证书等于控制台显示的值。

## 7. 发一个包

1. 控制台「发布中心 → 打包任务」排任务，版本号与 build 号都要大于线上。
   证书或包名要变时服务端会回 409，需要明确确认「改变 App 身份」。
2. 任务流转：排队中 → 已领取 → 构建中 → 待签名 → 签名中 → 成功。卡在待签名时看任务详情里的不就绪原因。
3. 下载产物核对：`apksigner verify --print-certs <apk>`，恰好 1 个签名者、证书等于控制台显示的值。
4. 控制台「发布管理」发布这个版本。

**依赖校验**：RN-App 的 `gradle/verification-metadata.xml` 记着每个 Android 依赖的 sha256。
改依赖、升 Expo、或者构建机缓存被清空之后，可能出现清单里没有的坐标 → 构建直接失败（这是设计如此）。
按 RN-App 手册重新生成清单（`pnpm android:verification-metadata <slug>`，冷缓存下跑真实构建）。

## 8. 离线要抄的东西

放密码管理器或离线记录，不要只留在服务器上：

- 恢复密钥口令、恢复公钥指纹。
- 每台签名闸的机器名与两个公钥指纹（`signer show-key`）。
- 每个租户的签名证书 sha256（取签名闸本机 `signer list`）。
- 每次 `confirm`、`trust-*`、`promote` 之后：`signer list` 的记录行数与末行哈希。
- 每次发布的安装包 sha256 与它的证书。
