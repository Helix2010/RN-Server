#!/usr/bin/env bash
# 给 amos 上的四个域名申请 Let's Encrypt 证书，并把自动续期打开。在 amos 上跑。
#
# 用 HTTP-01 + certbot 的 nginx 插件：证书申请和续期都不需要改 DNS，也不需要
# Cloudflare API token（web4 那套用 DNS-01 是因为它的域名挂在 Cloudflare 代理后面，
# 回源 IP 不对外）。前提是这四个 A 记录都指向本机、80 端口从公网进得来。
#
# 自动续期由 certbot 自带的 systemd timer 负责，一天跑两次，剩余不到 30 天才真的
# 续。续期成功后用 --deploy-hook 重载 nginx——不重载的话证书换了、进程还拿着旧的。
set -euo pipefail

EMAIL="${CERTBOT_EMAIL:-}"
DOMAINS=(api.any123.top console.any123.top api.predict.kim console.predict.kim)

[ -n "$EMAIL" ] || { echo "先设 CERTBOT_EMAIL=<能收到期提醒的邮箱>" >&2; exit 2; }

echo "== 安装 certbot =="
if ! command -v certbot >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y certbot python3-certbot-nginx
fi

echo "== 检查解析 =="
# 解析没指过来就先别申请：HTTP-01 会失败，而 Let's Encrypt 对失败有频率限制，
# 连撞几次会被锁一小时，反而更慢
me="$(curl -fsS -4 --max-time 8 https://ifconfig.me)"
bad=0
for d in "${DOMAINS[@]}"; do
  ip="$(getent ahostsv4 "$d" | head -1 | awk '{print $1}')"
  if [ "$ip" = "$me" ]; then
    printf '   %-24s %s\n' "$d" "指向本机"
  else
    printf '   %-24s %s（本机 %s）\n' "$d" "${ip:-无 A 记录}" "$me"
    bad=1
  fi
done
if [ "$bad" = 1 ]; then
  echo "上面这些域名还没指到本机，先改 DNS 再跑。" >&2
  exit 1
fi

echo "== 申请证书 =="
args=()
for d in "${DOMAINS[@]}"; do args+=(-d "$d"); done
# --nginx 会就地改 conf.d/rn-foundation.conf：补出 443 的 server 块、写证书路径、
# 把 :80 改成跳转。--redirect 明确要求这个跳转，别让它问
sudo certbot --nginx --non-interactive --agree-tos --redirect \
  --email "$EMAIL" --cert-name rn-foundation "${args[@]}"

echo "== 自动续期 =="
# 包装版 certbot 自带 certbot.timer；确认它是启用的，别只依赖"装上了应该就有"
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
