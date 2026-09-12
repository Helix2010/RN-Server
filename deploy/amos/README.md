# amos 部署：API + 扫链 + 两个租户的控制台

和 web4 不同，amos 上**没有 Docker**，也不打算装。这里沿用打包机代理那一套：
交叉编译出二进制，scp 过去，systemd 拉起，配置放 `/etc` 下 0600。

## 先说一件必须知道的事

**这台机器同时是打包机,而打包机和 wallet 后端原本是刻意分开的。**

`internal/buildkeystore/seal.go` 的注释把这条边界写得很清楚：Android keystore 不
用 `STORAGE_MASTER_KEY` 加密，而是运维用自己的口令封成一个盒子，服务端只存盒子、
没有钥匙；打包机本地持有口令。两半分在两台机器上，任何一台被拿下都还不够开盒。

把 API 搬到 amos 之后，两半在同一台机器上：这个进程能读到库里的密文盒子，而口令
就在同机的 `/etc/rn-build-agent.env` 里。unit 里的 `InaccessiblePaths` 挡住了同机
非 root 的那条路径，但挡不住提权。而 keystore 泄露在 direct 分发下没有补救办法
——Android 按「包名 + 签名证书」认身份，对方能签一个同签名的 APK 在用户设备上原地
覆盖安装，钱包数据目录原样留着，补救只能换包名让每个用户手动卸载重装。

要真正保住这条边界，只有把打包机代理挪到另一台机器。下面的部署按「就是要放一起」
来写，把能加的隔离都加上了，但它不等于那条边界还在。

## 结构

| 路径 | 内容 |
| --- | --- |
| `/opt/rn-foundation/rn-server` | 程序本体，API 与扫链共用 |
| `/opt/rn-foundation/admin/<租户>/` | 控制台静态产物，一个租户一份 |
| `/etc/rn-foundation.env` | 配置，0600 root，含数据库口令 |
| `/var/lib/rn-foundation/` | 状态目录 |
| `/etc/nginx/conf.d/rn-foundation.conf` | 四个域名的站点配置 |

两个 systemd unit：`rn-foundation-server`（监听 `127.0.0.1:13080`）与
`rn-foundation-indexer`（不监听任何端口）。

## 域名与租户

| 域名 | 由谁服务 |
| --- | --- |
| `api.any123.top` / `api.predict.kim` | nginx 反代到 `127.0.0.1:13080` |
| `console.any123.top` / `console.predict.kim` | nginx 直接发静态文件 |

**租户是按 Host 头认的**（`tenant_domain` 表）。所以反代必须原样传 `$host`；
amos 上原有那份 `console.any123.top` 写的是 `proxy_set_header Host 127.0.0.1:13080`，
照抄过来服务端会一律回 `TENANT_DOMAIN_NOT_FOUND`。顺带一提那个文件没有 `.conf`
后缀，而 `nginx.conf` include 的是 `conf.d/*.conf`，所以它一直没被加载过。

四个域名都要在 `tenant_domain` 里有行，否则请求进不到租户作用域。

控制台把 API 地址**编译进包里**（`VITE_API_BASE_URL`），所以两个租户是两份产物，
不是同一份配两个 `server_name`。加租户就在 `deploy.sh` 的 `TENANTS` 里加一行。

## 与 web4 共用一个数据库，安全吗

查过三处会打架的地方：

- **扫链**：每条链在 `chain_scan_state` 上有一把租约（`lease_owner` /
  `lease_until`），只有抢到的那台推进游标。两台同时开着是安全的。
- **推送派发**：出站队列的认领是 CAS（`WHERE id=? AND status='pending'` 看
  `RowsAffected`），不会重复发。但两台一起派发只是分摊，收益为零，默认留给 web4。
- **表结构**：只由 web4 推进。amos 这份 `MYSQL_AUTO_MIGRATE=false`，也不要从
  amos 跑 `migrate`——两个写入方抢同一张 `schema_migrations` 没有意义。

有两个值**必须和 web4 一致**：`STORAGE_MASTER_KEY`（它解密库里的租户对象存储
凭据，换一把就全读不出来）和 `DEVICE_IDENTITY_HMAC_KEY`（换了同一台设备在两边
会算出不同的 installation 指纹）。`ADMIN_API_KEY` 则**必须不一样**：同一把放两台，
任何一台泄漏就等于两台都失守。

## 装一台

```bash
# 1. 把这四个文件送上去
scp deploy/amos/{install.sh,setup-tls.sh,rn-foundation*.service,rn-foundation.env.example,nginx-rn-foundation.conf} amos:~/rn-foundation-deploy/

# 2. 在 amos 上建目录、用户、systemd、nginx 站点
ssh amos 'cd ~/rn-foundation-deploy && ./install.sh'

# 3. 填 /etc/rn-foundation.env 里的 CHANGE_ME_*
#    数据库四项与 STORAGE_MASTER_KEY 照抄 web4 的 .env；ADMIN_API_KEY 另生成：
#    openssl rand -hex 32

# 4. 回开发机，编译并推送二进制与两份控制台
./deploy/amos/deploy.sh

# 5. 开机自启
ssh amos 'sudo systemctl enable --now rn-foundation-server rn-foundation-indexer'

# 6. 证书与自动续期
ssh amos 'cd ~/rn-foundation-deploy && CERTBOT_EMAIL=<邮箱> ./setup-tls.sh'
```

## 证书

Let's Encrypt，HTTP-01，certbot 的 nginx 插件。**不需要 Cloudflare token**：web4
那套走 DNS-01 是因为它的域名挂在 Cloudflare 代理后面、回源 IP 不对外；amos 这四个
域名直接解析到本机，80 端口可达，HTTP-01 更简单。

自动续期是 certbot 自带的 `certbot.timer`，一天两次，剩余不到 30 天才真的续。
`setup-tls.sh` 额外装了一个 deploy hook 在续期成功后重载 nginx——不重载的话证书
换了、nginx 还拿着旧的，直到下次重启才生效。脚本最后会 `--dry-run` 演练一次，
演练不过就说明续期那天也会不过。

申请前脚本会核对四个域名是不是都指向本机。指错了不要硬试：Let's Encrypt 对失败有
频率限制，连撞几次会被锁一小时。

## 日常更新

```bash
./deploy/amos/deploy.sh          # 服务端 + 控制台
./deploy/amos/deploy.sh server   # 只换二进制
./deploy/amos/deploy.sh admin    # 只换控制台
```

服务端和 web4 的升级顺序一样：**先服务端后代理**。服务端用
`DisallowUnknownFields`，代理比服务端新时上报会 400，任务卡在 claimed。
