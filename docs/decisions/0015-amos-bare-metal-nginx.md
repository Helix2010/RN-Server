# ADR-0015：生产迁到 amos，网关换成宿主机 nginx

- 状态：Accepted
- 日期：2026-09-12
- 取代：ADR-0006（隔离的 Caddy 容器作为 HTTPS 网关）

## 背景

生产原本跑在 web4 上：一套 Docker Compose，Caddy 容器占 80/443，Cloudflare
DNS-01 签泛域名证书（ADR-0006）。迁到 amos 有三个硬约束：

- **amos 上没有 Docker**，也不打算装。那台机器是打包机，装的东西越少越好。
- **amos 已经有 nginx 在跑**，服务于其它项目。不能再起一个容器去抢 80/443。
- **amos 的入站只有 443**。没有 80，也没有 13080——这不是防火墙配置，是链路上
  一台按 SNI 放行的设备，白名单外的 TLS 握手直接被丢掉，连不带 SNI 的连接也丢。

第三条是实测出来的：本机直连回环时任意 SNI 都能握手，从外部只有白名单里的名字
能握手。曾经因为用裸 TCP 探测（没有 ClientHello、没有 SNI）而误判成「443 完全
不通」，绕了一圈。

## 决策

沿用打包机代理那套部署规范：交叉编译二进制、scp、systemd 拉起，配置放
`/etc/rn-foundation.env`（0600 root）。

- **网关是宿主机 nginx**，只听 443，配置在 `/etc/nginx/conf.d/rn-foundation.conf`。
  server 块**按证书分组**而不是按用途，一个 zone 一张证书各自独立续期。
- **应用绑回环**：`BIND_ADDRESS=127.0.0.1`，端口 13080。Docker 部署时端口映射
  替我们做了这件事，裸机没有这层，不显式绑定的话应用端口会绕过 nginx 直接对外。
- **两个 systemd unit 加一个 oneshot**：`rn-foundation-server`（API）、
  `rn-foundation-indexer`（扫链）、`rn-foundation-migrate`（数据库迁移）。
  迁移做成 unit 而不是在脚本里直接调二进制，是为了复用同一份 EnvironmentFile，
  数据库口令不进命令行参数。
- **证书按域名的暴露方式分两种**：直接解析到本机的域名走 TLS-ALPN-01（acme.sh，
  签发与续期时 nginx 让开几秒）；挂在 Cloudflare 代理后面的域名走 Cloudflare
  Origin CA 证书，15 年有效、不需要 ACME、不需要在这台机器上留能改 DNS 的凭据。

## 为什么不继续用 Caddy 或 certbot

装 Docker 只为跑一个网关，等于在打包机上多一个攻击面和一套要维护的东西，而
宿主机 nginx 已经在那里了。

certbot **至今没有实现 TLS-ALPN-01**，standalone 只支持 HTTP-01，
`--preferred-challenges tls-alpn-01` 直接报
"None of the preferred challenges are supported by the selected plugin"。
换新版没用，这是能力缺失不是版本问题。而 80 端口在这台机器上拿不到。

certbot 的 `--nginx` 插件还有个更隐蔽的问题：它会就地改写
`/etc/nginx/conf.d/rn-foundation.conf`，而那个文件由 `install.sh` 从仓库装上去，
下一次跑安装就把 TLS 配置覆盖回去——`nginx -t` 照样通过，站点悄悄退回纯 HTTP，
没有任何人会发现。所以 nginx 配置里写的是**软链接路径**，签发脚本只改链接指向，
配置文件本身不含具体证书路径。

## 代价

**打包机和 wallet 后端现在同机，这条边界没有了。** 原本的论证是：Android
keystore 用运维口令封成盒子存在数据库里，服务端只有密文没有钥匙，打包机本地持有
口令——两半分在两台机器上，拿下任何一台都不够开盒（见
`internal/buildkeystore/seal.go`）。同机之后，后端进程能读到密文盒子，而口令就在
本机 `/etc/rn-build-agent.env`。unit 里的 `InaccessiblePaths` 挡住了同机非 root
的那条路径，但挡不住提权。

keystore 泄露在 direct 分发下没有补救办法：Android 按「包名 + 签名证书」认身份，
对方能签一个同签名的 APK 在用户设备上原地覆盖安装，钱包数据目录原样留着，补救
只能换包名让每个用户手动卸载重装。

要恢复这条边界，只有把打包机代理挪到另一台机器。这是已知且被接受的取舍，不是
疏忽。
