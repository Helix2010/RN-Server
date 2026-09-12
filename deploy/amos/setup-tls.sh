#!/usr/bin/env bash
# 申请 Let's Encrypt 证书并打开自动续期。在 amos 上跑。
#
#   CERTBOT_EMAIL=ops@example.com ./setup-tls.sh                       # 默认域名列表
#   CERTBOT_EMAIL=... DOMAINS="a.example b.example" ./setup-tls.sh     # 指定域名
#   CERTBOT_EMAIL=... STAGING=1 ./setup-tls.sh                         # 先验链路
#   CERTBOT_EMAIL=... METHOD=dns ZONE=rn-foundation-anyfun \
#     DOMAINS="api.anyfun.win console.anyfun.win" CF_Token=<token> \
#     ./setup-tls.sh                                                     # 走 DNS-01
#
# 验证走 **TLS-ALPN-01**（443），因为这台机器的入站只有 443 没有 80，而 HTTP-01
# 只认 80 端口。
#
# 用 acme.sh 而不是 certbot：**certbot 至今没有实现 TLS-ALPN-01**，它的 standalone
# 只支持 HTTP-01，`--preferred-challenges tls-alpn-01` 会直接报
# "None of the preferred challenges are supported by the selected plugin"。
# 这不是版本问题，换新版也一样。
#
# 签发和续期期间 acme.sh 要独占 443，nginx 得让开几秒。pre/post hook 会写进域名
# 配置，acme.sh 自己的 cron 续期时照样执行。
#
# 只签**当前真的能从公网走到本机 443** 的域名。签不下来的那些不要硬凑进同一张证书：
# 一个域名验证失败，整张证书都签不出来。
#
# METHOD=dns 走 DNS-01。挂在 Cloudflare 代理后面的域名（anyfun.win）**只能用它**：
# TLS 由 Cloudflare 终止，ALPN 校验的握手根本到不了本机。DNS-01 也不需要任何入站
# 端口，续期同理。代价是这台机器上要放一个能改该 zone DNS 记录的 token。
set -euo pipefail

EMAIL="${CERTBOT_EMAIL:-}"
# ZONE 决定这张证书装到哪个链接下，要和 nginx 配置里的 ssl_certificate 对上
ZONE="${ZONE:-rn-foundation}"
LINK="/etc/nginx/ssl/$ZONE"
LIVE="/etc/nginx/ssl/$ZONE-le"
ACME=/root/.acme.sh/acme.sh
read -r -a DOMAIN_LIST <<<"${DOMAINS:-api.predict.kim console.predict.kim api.any123.top console.any123.top}"

[ -n "$EMAIL" ] || { echo "先设 CERTBOT_EMAIL=<能收到期提醒的邮箱>" >&2; exit 2; }

echo "== 安装 acme.sh =="
if ! sudo test -x "$ACME"; then
  curl -fsS https://get.acme.sh | sudo sh -s "email=$EMAIL" >/dev/null
  echo "   已安装（含每日续期 cron）"
else
  echo "   已存在"
fi
sudo "$ACME" --set-default-ca --server letsencrypt >/dev/null

if [ "${METHOD:-alpn}" = "dns" ]; then
  : "${CF_Token:?METHOD=dns 需要 CF_Token=<Cloudflare API token>}"
  export CF_Token
  usable=("${DOMAIN_LIST[@]}")
  echo "== DNS-01（不探测可达性：这条路不需要入站端口）=="
  printf '   %s\n' "${usable[@]}"
else

echo "== 探测哪些域名能走到本机的 443 =="
# 不比对 A 记录：路径上可能有转发或 SNI 路由。真正要验的是"TLS 握手最后落在不落在
# 本机"，那就看对端证书指纹和本机现用的那张是不是同一张
local_fp="$(sudo openssl x509 -in "$LINK/fullchain.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
usable=()
for d in "${DOMAIN_LIST[@]}"; do
  # 末尾的 `|| true` 不能省：域名不可达时整条管道返回非零，而 set -e 对命令替换
  # 里的失败同样生效，脚本会在第一个连不上的域名处当场退出，后面的一个都探不到
  fp="$( { timeout 8 openssl s_client -connect "$d:443" -servername "$d" </dev/null 2>/dev/null || true; } |
        openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)"
  if [ "$fp" = "$local_fp" ]; then
    printf '   %-24s 到本机\n' "$d"
    usable+=("$d")
  elif [ -n "$fp" ]; then
    printf '   %-24s 终止在别处（对端证书不是本机这张）\n' "$d"
  else
    printf '   %-24s 不可达\n' "$d"
  fi
done
if [ "${#usable[@]}" -eq 0 ]; then
  echo "没有一个域名能走到本机的 443，不申请。" >&2
  exit 1
fi
fi

echo "== 申请证书（TLS-ALPN-01，443）=="
args=()
for d in "${usable[@]}"; do args+=(-d "$d"); done
if [ "${STAGING:-0}" = "1" ]; then
  args+=(--staging)
fi

if [ "${METHOD:-alpn}" = "dns" ]; then
  # DNS-01 不碰 443，nginx 不用停
  sudo CF_Token="$CF_Token" "$ACME" --issue --dns dns_cf "${args[@]}"
else
  sudo "$ACME" --issue --alpn --tlsport 443 "${args[@]}" \
    --pre-hook  'systemctl stop nginx' \
    --post-hook 'systemctl start nginx'
fi

if [ "${STAGING:-0}" = "1" ]; then
  echo
  echo "测试环境签发成功，443 链路是通的。去掉 STAGING=1 再跑一次拿正式证书。"
  exit 0
fi

echo "== 装到 nginx 用的位置 =="
# nginx 配置写的是 /etc/nginx/ssl/rn-foundation/{fullchain,privkey}.pem，这里只换
# 软链接的指向，配置文件一个字都不用改——重跑 install.sh 也不会把 TLS 退掉。
# --reloadcmd 会存进域名配置，续期成功后自动重载，不然证书换了 nginx 还拿着旧的
sudo mkdir -p "$LIVE"
sudo "$ACME" --install-cert -d "${usable[0]}" \
  --fullchain-file "$LIVE/fullchain.pem" \
  --key-file       "$LIVE/privkey.pem" \
  --reloadcmd      'nginx -t && systemctl reload nginx'
sudo chmod 0600 "$LIVE/privkey.pem"
sudo ln -sfn "$LIVE" "$LINK"
sudo nginx -t
sudo systemctl reload nginx

echo "== 自动续期 =="
# acme.sh 装的时候就写好了 root 的 cron，每天跑一次，剩余不到 30 天才真的续
sudo crontab -l 2>/dev/null | grep acme.sh || echo "   警告：没找到 acme.sh 的 cron"

echo "== 结果 =="
sudo "$ACME" --list
echo "   nginx 证书指向 $(readlink -f "$LINK")"
for d in "${usable[@]}"; do
  printf '   %-24s %s\n' "$d" \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://$d/" 2>/dev/null || echo 不可达)"
done
