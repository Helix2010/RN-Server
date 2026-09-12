# amos 部署：API + 扫链 + 两个租户的控制台

和 web4 不同，amos 上**没有 Docker**，也不打算装。这里沿用打包机代理那一套：
交叉编译出二进制，scp 过去，systemd 拉起，配置放 `/etc` 下 0600。

## 先说一件必须知道的事

**这台机器同时是打包机。这是开发环境的取舍，生产环境要把两者分开。**

`internal/buildkeystore/seal.go` 的注释把这条边界写得很清楚：Android keystore 不
用 `STORAGE_MASTER_KEY` 加密，而是运维用自己的口令封成一个盒子，服务端只存盒子、
没有钥匙；打包机本地持有口令。两半分在两台机器上，任何一台被拿下都还不够开盒。

把 API 搬到 amos 之后，两半在同一台机器上：这个进程能读到库里的密文盒子，而口令
就在同机的 `/etc/rn-build-agent.env` 里。unit 里的 `InaccessiblePaths` 挡住了同机
非 root 的那条路径，但挡不住提权。而 keystore 泄露在 direct 分发下没有补救办法
——Android 按「包名 + 签名证书」认身份，对方能签一个同签名的 APK 在用户设备上原地
覆盖安装，钱包数据目录原样留着，补救只能换包名让每个用户手动卸载重装。

所以这套部署只适用于开发/联调环境。**上生产时必须把打包机代理挪到另一台机器**，
那条边界才重新成立。下面的 unit 里该加的隔离都加了（`InaccessiblePaths` 挡掉打包机
的配置与状态目录），但那只挡同机非 root，挡不住提权——不要把它当成边界本身。

## 结构

| 路径 | 内容 |
| --- | --- |
| `/opt/rn-foundation/rn-server` | 程序本体，API、扫链、迁移共用 |
| `/opt/rn-foundation/admin/<租户>/` | 控制台静态产物，一个租户一份 |
| `/etc/rn-foundation.env` | 配置，0600 root，含数据库口令 |
| `/var/lib/rn-foundation/` | 状态目录 |
| `/etc/nginx/conf.d/rn-foundation.conf` | 四个域名的站点配置 |
| `/usr/local/sbin/rn-foundation-apply` | 特权收口脚本，换二进制／换控制台都走它 |
| `/var/lib/rn-foundation-deploy/incoming/` | 部署暂存目录，属 `rndeploy` |

三个 systemd unit：`rn-foundation-server`（监听 `127.0.0.1:13080`）、
`rn-foundation-indexer`（不监听任何端口）、`rn-foundation-migrate`（oneshot，
只在部署时被调用）。

证书两套，按域名的暴露方式分：

| 链接 | 证书来源 | 覆盖 |
| --- | --- | --- |
| `/etc/nginx/ssl/rn-foundation` | Let's Encrypt，acme.sh TLS-ALPN-01 | predict.kim（将来 any123.top） |
| `/etc/nginx/ssl/rn-foundation-anyfun` | Cloudflare Origin CA，15 年 | anyfun.win |

## 域名与租户

| 域名 | 租户 | 由谁服务 | 公网能否到本机 443 |
| --- | --- | --- | --- |
| `api.predict.kim` | 100000002 | nginx 反代到 `127.0.0.1:13080` | 能 |
| `console.predict.kim` | 100000002 | nginx 直接发静态文件 | 能 |
| `api.any123.top` | 100000003 | nginx 反代到 `127.0.0.1:13080` | **不可达** |
| `console.any123.top` | 100000003 | nginx 直接发静态文件 | **终止在 206.223.224.29**，那台服务的是 `cca.cryptostack.ai` 的证书 |

四行已写进 `tenant_domain`（2026-09-12）。any123.top 两个域名的入站链路还没通，
证书里因此只有 predict.kim 那两个——一个域名验不过整张证书都签不出来，不能硬凑。
链路打通后重跑 `setup-tls.sh`，它会自己探测并把新域名加进来。

**这台机器的入站只有 443**，没有 80，也没有 13080。所以 nginx 直接听 443，应用在
`127.0.0.1:13080`（`BIND_ADDRESS=127.0.0.1`，不写的话 Go 会绑所有网卡，裸机没有
Docker 的端口映射兜底，13080 就绕过 nginx 直接对外了）。

**租户是按 Host 头认的**（`tenant_domain` 表）。所以反代必须原样传 `$host`；
amos 上原有那份 `console.any123.top` 写的是 `proxy_set_header Host 127.0.0.1:13080`，
照抄过来服务端会一律回 `TENANT_DOMAIN_NOT_FOUND`。顺带一提那个文件没有 `.conf`
后缀，而 `nginx.conf` include 的是 `conf.d/*.conf`，所以它一直没被加载过。

控制台把 API 地址**编译进包里**（`VITE_API_BASE_URL`），所以两个租户是两份产物，
不是同一份配两个 `server_name`。加租户就在 `deploy.sh` 的 `TENANTS` 里加一行。

## 与 web4 共用一个数据库，安全吗（web4 已于 2026-09-12 退役）

查过三处会打架的地方：

- **扫链**：每条链在 `chain_scan_state` 上有一把租约（`lease_owner` /
  `lease_until`），只有抢到的那台推进游标。两台同时开着是安全的。
- **推送派发**：出站队列的认领是 CAS（`WHERE id=? AND status='pending'` 看
  `RowsAffected`），不会重复发。但两台一起派发只是分摊，收益为零，默认留给 web4。
- **表结构**：`MYSQL_AUTO_MIGRATE=false`，迁移不在服务启动时跑。web4 在役时由
  它的 `start.sh` 推进，amos 刻意不碰，免得两个写入方抢同一张 `schema_migrations`。
  **web4 退役后执行方换成 amos**：`rn-foundation-migrate.service`（oneshot），
  `deploy.sh server` 会在换完二进制、起服务之前自动调它，失败就停在那里不起服务。
  做成 unit 是为了复用同一份 EnvironmentFile，数据库口令不进命令行参数。

有两个值**必须和 web4 一致**：`STORAGE_MASTER_KEY`（它解密库里的租户对象存储
凭据，换一把就全读不出来）和 `DEVICE_IDENTITY_HMAC_KEY`（换了同一台设备在两边
会算出不同的 installation 指纹）。`ADMIN_API_KEY` 则**必须不一样**：同一把放两台，
任何一台泄漏就等于两台都失守。

## 装一台

```bash
# 0. 现状：这套已经在 amos 上跑着（2026-09-12 起承接生产）。以下是从零装一台的步骤
# 1. 把这一整个目录送上去
ssh amos 'mkdir -p ~/rn-foundation-deploy'
scp deploy/amos/* amos:~/rn-foundation-deploy/

# 2. 在 amos 上建目录、用户、systemd、nginx 站点
ssh amos 'cd ~/rn-foundation-deploy && ./install.sh'

# 3. 填 /etc/rn-foundation.env 里的 CHANGE_ME_*
#    数据库四项与 STORAGE_MASTER_KEY 照抄 web4 的 .env；ADMIN_API_KEY 另生成：
#    openssl rand -hex 32

# 4. 回开发机，编译并推送二进制与两份控制台
./deploy/amos/deploy.sh

# 5. 开机自启
ssh amos 'sudo systemctl enable --now rn-foundation-server rn-foundation-indexer'

# 6. 证书与自动续期。先用测试环境验链路，再签正式的
ssh amos 'cd ~/rn-foundation-deploy && CERTBOT_EMAIL=<邮箱> STAGING=1 ./setup-tls.sh'
ssh amos 'cd ~/rn-foundation-deploy && CERTBOT_EMAIL=<邮箱> ./setup-tls.sh'

# 7. 开 CI 部署：建受限账号、装特权脚本、生成 CI 密钥
ssh amos 'cd ~/rn-foundation-deploy && ./setup-ci-deploy.sh <对外地址> <SSH 端口>'
```

## 证书

Let's Encrypt，**TLS-ALPN-01**，走 443。入站没有 80，HTTP-01 用不了。

用 **acme.sh 而不是 certbot**：certbot 至今没有实现 TLS-ALPN-01，它的 standalone
只支持 HTTP-01，`--preferred-challenges tls-alpn-01` 会直接报 "None of the preferred
challenges are supported by the selected plugin"。换新版没用，这是能力缺失不是版本
问题。

nginx 配置里的证书路径指向软链接 `/etc/nginx/ssl/rn-foundation`：没证书时指向自签
占位（`install.sh` 生成，浏览器会报不受信任），签好后 `setup-tls.sh` 改指
`/etc/nginx/ssl/rn-foundation-le`。配置文件本身不含具体证书路径，所以重跑
`install.sh` 不会把 TLS 退回去。

签发和续期期间 acme.sh 要独占 443，nginx 让开几秒。pre / post hook 存在域名配置
里（`Le_PreHook` / `Le_PostHook`），acme.sh 自己的 cron 续期时照样执行；
`--reloadcmd` 同理，续期成功后自动 `nginx -t && systemctl reload nginx`，不然证书
换了 nginx 还拿着旧的。cron 是安装 acme.sh 时自动写的，一天四次，只有接近到期才
真的续。

申请前脚本会**逐个域名握手、比对对端证书指纹和本机正在用的那张**，而不是比对 A
记录：路径上可能有转发或 SNI 路由，比 IP 会把能用的判成不能用、也会把终止在别处
的判成能用。探不到的域名直接排除在证书之外——一个域名验不过，整张证书都签不出来。

先用 `STAGING=1` 跑一遍验链路：正式环境对失败有频率限制，测试环境没有。

## 日常更新

**正常路径是 CI。** 两个仓库各有一个 `.github/workflows/deploy-amos.yml`，推到
`main` 就跑：RN-Server 交叉编译服务端，RN-Admin 给每个租户各构建一份控制台，都通过
amos 上的 `rndeploy` 账号送过去，再调用同一个 `rn-foundation-apply`。

手工／应急路径：

```bash
./deploy/amos/deploy.sh          # 服务端 + 全部控制台
./deploy/amos/deploy.sh server   # 只换二进制
./deploy/amos/deploy.sh admin    # 只换控制台
```

两条路径最后调的是同一个脚本，停服务、换二进制、跑迁移、健康检查、失败回滚都在
那里面，不存在"CI 那套和手工这套行为不一样"的问题。

服务端和 web4 的升级顺序一样：**先服务端后代理**。服务端用
`DisallowUnknownFields`，代理比服务端新时上报会 400，任务卡在 claimed。

### CI 是怎么授权的

CI 用的是 amos 上的 `rndeploy`，它**全部**的 sudo 权限就一条：

```
rndeploy ALL=(root) NOPASSWD: /usr/local/sbin/rn-foundation-apply
```

不给 `ubuntu` 的密钥，是因为 `ubuntu` 是 `NOPASSWD: ALL`——把它交给 GitHub 等于把
这台机器的 root 交出去，而这台机器上放着 Android keystore 的封装口令。实测过边界：
`rndeploy` 读不到 `/etc/rn-build-agent.env`，也读不到 `/etc/rn-foundation.env`，
`sudo` 跑任何别的命令都要密码。换上去的二进制以 `rnfoundation` 身份运行，不是 root。
CI 密钥被偷的最坏结果是"发了一版坏代码"，不是"整台机器没了"。

`sudoers` 里故意不限制参数——参数校验在脚本里。把 `install`/`mv`/`rm`/`systemctl`
逐条写进 sudoers，任何一条带通配符的规则写松一点就等于给了 root。

**这个特权脚本不由 CI 自己更新**，那等于把 root 还回去。仓库里改了它，要有人在
amos 上重跑一次 `setup-ci-deploy.sh`；workflow 会比对两边的 sha256，不一致时打
warning，没装时直接报错。

一次性配置：

```bash
scp deploy/amos/{rn-foundation-apply,rn-foundation-deploy.sudoers,setup-ci-deploy.sh} amos:~/
ssh amos './setup-ci-deploy.sh <这台机器对外的地址> <SSH 端口>'
```

它会建账号、装脚本与 sudoers（先 `visudo -c` 验语法再落地）、生成一把只给 CI 用的
ed25519 密钥，并打印要填进 GitHub 的四个 secret。私钥留在机器上，用
`sudo cat /var/lib/rn-foundation-deploy/.ssh/ci_ed25519` 自己取——**在你自己的终端里
取**，别经过任何会被记录的通道。

两个仓库都要有：

| 名称 | 位置 | 值 |
| --- | --- | --- |
| `AMOS_HOST` | Secret | amos 对外地址 |
| `AMOS_PORT` | Secret | SSH 端口（非 22） |
| `AMOS_KNOWN_HOSTS` | Secret | `setup-ci-deploy.sh` 打印的那一行 |
| `AMOS_SSH_KEY` | Secret | 上面那把私钥全文 |
| `AMOS_DEPLOY_ENABLED` | Variable | `true`，否则只跑校验不部署 |

### 加一个租户

租户清单只有一份：`RN-Admin/deploy/tenants.txt`，CI 和 `deploy.sh` 读的是同一个
文件。加一行还不够，另外两件事：nginx 里要有对应域名的 `server` 块，链路上按 SNI
放行的那台设备的白名单里也要有这个域名。

## 注意事项

按踩过的顺序记，每条都是真出过问题的。

**入站只有 443，而且按 SNI 放行。** 链路上有一台设备只转发白名单内的 SNI，白名单
外的 TLS 握手直接丢掉，连不带 SNI 的连接也丢。判断某个域名通不通，要**从外部带
SNI 握手看拿到哪张证书**，不能比对 A 记录、更不能用裸 TCP 探——裸 TCP 没有
ClientHello，一定被丢，会得出「443 完全不通」的错误结论。新增域名时除了改配置，
还要请人把它加进那个白名单。

**反代必须传 `$host`。** 租户是按 Host 头从 `tenant_domain` 认的。本机既有站点的
写法是 `proxy_set_header Host 127.0.0.1:13080`，照抄过来服务端会一律回
`TENANT_DOMAIN_NOT_FOUND`。

**`conf.d` 只加载 `*.conf`。** 本机原有的 `console.any123.top`（没有后缀）从来没
被加载过。片段文件因此**必须**用 `.inc` 结尾——用 `.conf` 会被当成独立配置加载，
里面的 `location` 不在 `server` 块里，nginx 直接起不来。

**`BIND_ADDRESS` 不能省。** 应用默认绑 `*:PORT`。Docker 部署时端口映射替我们限制
了暴露面，裸机没有这层，不写的话 13080 绕过 nginx 直接对外，TLS 和它上面的一切
都白设。

**`.env` 里含 `$` 的值要加单引号。** `ADMIN_PASSWORD_HASH` 是 scrypt 格式，带
`$`。systemd 读 EnvironmentFile 不做展开，但任何 `source` 这个文件的脚本都会把
`$3` 当变量吃掉。加了引号两边都对。

**证书路径写软链接，不写具体目录。** 签发脚本只改链接指向，nginx 配置本身不动。
这样重跑 `install.sh` 不会把 TLS 退回占位证书——那种退化 `nginx -t` 照样通过，
不会有人发现。同理不要用 certbot 的 `--nginx` 插件，它会就地改写这个文件。

**certbot 不支持 TLS-ALPN-01。** 这是能力缺失不是版本问题，换新版一样报
"None of the preferred challenges are supported by the selected plugin"。所以用
acme.sh。

**nginx reload 是优雅的。** 换完证书紧接着探一次，很可能还落在旧 worker 上拿到
旧证书，等两秒再看。第一次装 Origin CA 时就被这个骗过一次。

**`set -e` 下两种写法会静默打断脚本**：`[ 条件 ] && 赋值` 在条件不成立时整条
AND 列返回 1；命令替换里的管道失败同样触发。探测循环第一次只跑了两个域名就停，
就是后者。

**与 web4 共库的三处并发点**已经查过：扫链每条链有租约（只有抢到的推进游标）、
推送派发是 CAS 认领（不会重发）、表结构由单一执行方推进。`STORAGE_MASTER_KEY`
和 `DEVICE_IDENTITY_HMAC_KEY` 必须与另一端一致，`ADMIN_API_KEY` 必须不同。

**回滚只回二进制，不回迁移。** `rn-foundation-apply` 在迁移失败或健康检查不过时
会把上一版二进制装回去重启。已经执行过的迁移不会退回来——这套迁移只加不减，旧代码
能在新表结构上跑，回滚才成立。哪天写了一条破坏性迁移，这个前提就没了。

**部署账号的权限边界是设计的一部分。** 别图省事把 CI 换成 `ubuntu` 账号，也别把
`rn-foundation-apply` 拆成一串 sudoers 规则。理由见上面「CI 是怎么授权的」。

**回滚**：把 Cloudflare 上的 A 记录改回 web4 的 IP，并按 `deploy/web4/README.md`
重建那边的 `.env`（值从 `/etc/rn-foundation.env` 取，web4 上的已经 shred 掉了）。
数据在共用的数据库里，不需要迁移。
