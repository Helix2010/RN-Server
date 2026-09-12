#!/usr/bin/env bash
# 装一张 Cloudflare Origin CA 源站证书。在 amos 上跑。
#
#   ./install-origin-cert.sh <证书文件> <私钥文件> [ZONE]
#   ./install-origin-cert.sh ~/origin.pem ~/origin.key rn-foundation-anyfun
#
# Origin CA 证书**只被 Cloudflare 信任**，不是公共 CA 签的。用在橙云代理后面的
# 源站上正合适：浏览器看到的是 Cloudflare 边缘证书，这张只负责 Cloudflare 到源站
# 这一段。好处是 15 年有效、不需要 ACME、不需要在这台机器上留任何能改 DNS 的
# 凭据——而这台机器同时持有 Android 签名密钥的封装口令，少放一个凭据就少一分风险。
#
# 前提：该域名在 Cloudflare 上必须是**代理开启（橙云）**且 SSL 模式为 Full 或
# Full (strict)。灰云（仅 DNS）下浏览器会直连源站，这张证书不被公共信任，用户会
# 看到证书错误。
set -euo pipefail

CERT="${1:-}"
KEY="${2:-}"
ZONE="${3:-rn-foundation-anyfun}"
EXPECT_HOSTS=(api.anyfun.win console.anyfun.win)

if [ -z "$CERT" ] || [ -z "$KEY" ]; then
  echo "用法: $0 <证书文件> <私钥文件> [ZONE]" >&2
  exit 2
fi
[ -r "$CERT" ] || { echo "读不到证书文件: $CERT" >&2; exit 1; }
[ -r "$KEY" ]  || { echo "读不到私钥文件: $KEY" >&2; exit 1; }

echo "== 校验 =="
subject="$(openssl x509 -in "$CERT" -noout -subject 2>/dev/null)" || {
  echo "不是有效的 PEM 证书" >&2; exit 1; }
issuer="$(openssl x509 -in "$CERT" -noout -issuer)"
echo "   $subject"
echo "   $issuer"
openssl x509 -in "$CERT" -noout -dates | sed 's/^/   /'

# 证书和私钥必须是一对。不校验的话 nginx 起不来，而报错要到 reload 时才看见
cert_pub="$(openssl x509 -in "$CERT" -noout -pubkey | openssl md5)"
key_pub="$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl md5)" || {
  echo "私钥解析失败（格式不对，或者这是加密私钥）" >&2; exit 1; }
[ "$cert_pub" = "$key_pub" ] || { echo "证书和私钥不匹配" >&2; exit 1; }
echo "   证书与私钥匹配"

# 域名覆盖。Origin CA 常见签法是 *.anyfun.win + anyfun.win，所以通配符也要认
sans="$(openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | tr -d ' ' | tr ',' '\n' | sed -n 's/^DNS://p')"
for host in "${EXPECT_HOSTS[@]}"; do
  wildcard="*.${host#*.}"
  if grep -qxF "$host" <<<"$sans" || grep -qxF "$wildcard" <<<"$sans"; then
    echo "   覆盖 $host"
  else
    echo "   证书不覆盖 $host（SAN: $(tr '\n' ' ' <<<"$sans")）" >&2
    exit 1
  fi
done

case "$issuer" in
*CloudFlare*Origin*|*Cloudflare*Origin*) echo "   确认是 Cloudflare Origin CA" ;;
*) echo "   注意：签发者不像 Cloudflare Origin CA，确认这是你要装的那张" ;;
esac

echo "== 安装到 /etc/nginx/ssl/$ZONE-origin =="
dest="/etc/nginx/ssl/$ZONE-origin"
sudo mkdir -p "$dest"
sudo install -m 0644 -o root -g root "$CERT" "$dest/fullchain.pem"
sudo install -m 0600 -o root -g root "$KEY"  "$dest/privkey.pem"
sudo ln -sfn "$dest" "/etc/nginx/ssl/$ZONE"

echo "== 生效 =="
sudo nginx -t
sudo systemctl reload nginx
echo "   /etc/nginx/ssl/$ZONE -> $(readlink -f "/etc/nginx/ssl/$ZONE")"

echo "== 本机自检（带 SNI 直连回环）=="
for host in "${EXPECT_HOSTS[@]}"; do
  got="$(timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$host" </dev/null 2>/dev/null |
         openssl x509 -noout -subject 2>/dev/null || true)"
  printf '   %-24s %s\n' "$host" "${got:-握手失败}"
done

cat <<'NEXT'

装好了。源文件里的私钥现在有两份，把你自己放上来的那份删掉：
  shred -u <私钥文件> 2>/dev/null || rm -f <私钥文件>

还要确认两件事，否则线上会看到证书错误或 502：
  1. Cloudflare 上 anyfun.win 是代理开启（橙云），SSL 模式 Full 或 Full (strict)
  2. 链路上那台按 SNI 放行的设备，名单里要有 api.anyfun.win 和 console.anyfun.win
NEXT
