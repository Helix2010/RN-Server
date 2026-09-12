#!/usr/bin/env bash
# 给四个域名申请 Let's Encrypt 证书，装上 TLS 版 nginx 配置，并把自动续期打开。
# 在 amos 上跑，同目录要有 nginx-rn-foundation-tls.conf。
#
#   CERTBOT_EMAIL=ops@example.com ./setup-tls.sh
#
# 用 HTTP-01 的 **webroot** 方式，不用 --nginx 插件：插件会就地改写
# /etc/nginx/conf.d/rn-foundation.conf，而那个文件是 install.sh 从仓库装上去的，
# 下一次跑 install.sh 就会把 TLS 配置覆盖掉，且不报错。webroot 方式下 certbot
# 只往 /var/www/acme 写校验文件，nginx 配置始终由我们自己管。
#
# 续期靠 certbot 自带的 certbot.timer（一天两次，剩余不到 30 天才真的续），外加
# 一个 deploy hook 在续期成功后重载 nginx——不重载的话证书换了、进程还拿着旧的。
set -euo pipefail

cd "$(dirname "$0")"

EMAIL="${CERTBOT_EMAIL:-}"
CERT_NAME=rn-foundation
WEBROOT=/var/www/acme
DOMAINS=(api.any123.top console.any123.top api.predict.kim console.predict.kim)

[ -n "$EMAIL" ] || { echo "先设 CERTBOT_EMAIL=<能收到期提醒的邮箱>" >&2; exit 2; }
[ -f nginx-rn-foundation-tls.conf ] || { echo "缺少 nginx-rn-foundation-tls.conf" >&2; exit 1; }

echo "== 安装 certbot =="
if ! command -v certbot >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y certbot
fi

echo "== 准备校验目录 =="
sudo mkdir -p "$WEBROOT/.well-known/acme-challenge"
sudo chmod -R a+rX /var/www/acme

echo "== 探测四个域名能否走到本机的 :80 =="
# 不比对 A 记录：解析可能指向一台做转发的前置机（amos 上的 console.any123.top
# 就是这样）。真正要验证的是"这个域名的 ACME 路径能不能读到本机写下的文件"，
# 那就直接写一个文件去读。
probe="probe-$(date +%s)-$$"
echo "$probe" | sudo tee "$WEBROOT/.well-known/acme-challenge/$probe" >/dev/null
bad=0
for d in "${DOMAINS[@]}"; do
  got="$(curl -fsS --max-time 10 "http://$d/.well-known/acme-challenge/$probe" 2>/dev/null || true)"
  if [ "$got" = "$probe" ]; then
    printf '   %-24s 可达\n' "$d"
  else
    printf '   %-24s 读不到校验文件\n' "$d"
    bad=1
  fi
done
sudo rm -f "$WEBROOT/.well-known/acme-challenge/$probe"
if [ "$bad" = 1 ]; then
  cat >&2 <<'HINT'

上面这些域名的 :80 走不到本机。先确认：
  - nginx 已加载 rn-foundation.conf（install.sh 装的那份，含 acme-challenge 位置）
  - 域名解析或前置转发确实落到本机的 80 端口
不要硬试：Let's Encrypt 对失败有频率限制，连撞几次会被锁一小时。
HINT
  exit 1
fi

echo "== 申请证书 =="
args=()
for d in "${DOMAINS[@]}"; do args+=(-d "$d"); done
sudo certbot certonly --webroot -w "$WEBROOT" \
  --non-interactive --agree-tos --email "$EMAIL" \
  --cert-name "$CERT_NAME" --keep-until-expiring "${args[@]}"

echo "== certbot 的 nginx 参数文件 =="
# webroot 方式不会自动生成这两个文件，而 TLS 配置 include 了它们
if [ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]; then
  sudo tee /etc/letsencrypt/options-ssl-nginx.conf >/dev/null <<'SSLOPT'
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;
ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305";
SSLOPT
fi
if [ ! -f /etc/letsencrypt/ssl-dhparams.pem ]; then
  # ffdhe2048（RFC 7919），公开的标准参数组，不需要现生成
  sudo curl -fsSLo /etc/letsencrypt/ssl-dhparams.pem \
    https://ssl-config.mozilla.org/ffdhe2048.txt
fi

echo "== 换上 TLS 配置 =="
sudo install -m 0644 nginx-rn-foundation-tls.conf /etc/nginx/conf.d/rn-foundation.conf
sudo nginx -t
sudo systemctl reload nginx

echo "== 自动续期 =="
sudo systemctl enable --now certbot.timer
sudo systemctl list-timers certbot.timer --no-pager | head -3

hook=/etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
sudo mkdir -p "$(dirname "$hook")"
printf '#!/bin/sh\nnginx -t && systemctl reload nginx\n' | sudo tee "$hook" >/dev/null
sudo chmod 0755 "$hook"

echo "== 演练一次续期（不会真的换证书）=="
sudo certbot renew --dry-run

echo "== 结果 =="
sudo certbot certificates | grep -E "Certificate Name|Domains|Expiry"
for d in "${DOMAINS[@]}"; do
  printf '   %-24s %s\n' "$d" "$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 10 "https://$d/" 2>/dev/null || echo 不可达)"
done
