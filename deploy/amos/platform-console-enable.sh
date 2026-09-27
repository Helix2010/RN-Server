#!/usr/bin/env bash
# 一次性：打开平台控制台（platform.anyfun.win，设计 docs/design/service-and-console-split-2026-09-27.md
# 第 6 节第二步）。稳定之后删掉这个脚本。
#
#   sudo bash platform-console-enable.sh [平台控制台域名] [装机命令里的服务端地址]
#   sudo bash platform-console-enable.sh --rollback DIR
#
# 默认 platform.anyfun.win 与 https://api.anyfun.win。在 amos 上以 root 跑，同目录下要有本仓库 deploy/amos
# 的 nginx 配置与片段。前提：已经跑过 service-split-switch.sh（三个进程），CI 已部署带平台控制台的新二进制。
#
# 做的事，任何一步失败都自动退回：
#   1. 备份 /etc/rn-foundation.env 与 nginx 配置到 /root/rn-foundation-platform-console-<时间>/；
#   2. 拿部署锁；env 里没有 PLATFORM_CONSOLE_HOST、MACHINE_API_ORIGIN 就补上（已有的不改）；
#   3. 装 nginx 配置（含 platform.* 的 server 块），nginx -t 通过才 reload；
#   4. 重启平台端，经 nginx 核对：平台控制台的统一登录开着，发起时的回调地址是平台控制台的域名。
#
# 租户端不再认平台会话那一版（第二步后半段）合并之后再跑一次：它会装上不再把 console.* 的
# /v1/admin/platform/ 转给平台端的 nginx 片段（env 已有的两行不会重复加）。
#
# 平台控制台的静态产物由 RN-Admin 的 CI 放到 /opt/rn-foundation/admin/platform；公网能不能到还要
# 网关按 SNI 放行、认证中心登记回调域名，这两件不在这里。
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE=/etc/rn-foundation.env
NGINX_DIR=/etc/nginx/conf.d
BINARY=/opt/rn-foundation/rn-server

log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "要以 root 跑：sudo bash $0"

declare -A NGINX_FILES=([rn-foundation.conf]=nginx-rn-foundation.conf)
for f in "$SRC"/nginx-snippet-*.inc; do
  [ -e "$f" ] || continue
  f="${f##*/}"
  NGINX_FILES["rn-foundation-snippet-${f#nginx-snippet-}"]="$f"
done

wait_platform() { # $1 = 最多等几秒
  local deadline=$(( $(date +%s) + $1 ))
  until curl -fsS --max-time 3 http://127.0.0.1:13080/health/ready >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}

restore() { # $1 = 备份目录
  local backup="$1" f
  log "退回（备份 $backup）"
  install -m 0600 -o root -g root "$backup/rn-foundation.env" "$ENV_FILE"
  for f in "${!NGINX_FILES[@]}"; do
    if [ -f "$backup/nginx/$f" ]; then
      install -m 0644 -o root -g root "$backup/nginx/$f" "$NGINX_DIR/$f"
    else
      rm -f "$NGINX_DIR/$f"
    fi
  done
  if nginx -t 2>/dev/null; then
    systemctl reload nginx
  else
    printf '!! 恢复出来的 nginx 配置 nginx -t 不过，没有 reload，需要人工看\n' >&2
  fi
  systemctl restart rn-foundation-platform || true
  wait_platform 60 && log "已退回" || printf '!! 平台端 60 秒内没就绪：journalctl -u rn-foundation-platform -n 50\n' >&2
}

lock() {
  exec 9>/var/lib/rn-foundation-deploy/.apply.lock
  flock -w 300 9 || die "另一个部署正在进行，等了 5 分钟还没轮到"
}

if [ "${1:-}" = "--rollback" ]; then
  backup="${2:-}"
  [ -n "$backup" ] && [ -f "$backup/rn-foundation.env" ] || die "用法: $0 --rollback <备份目录>"
  lock
  restore "$backup"
  exit 0
fi
[ $# -le 2 ] || die "用法: $0 [平台控制台域名] [装机命令里的服务端地址] | $0 --rollback <备份目录>"
PLATFORM_HOST="${1:-platform.anyfun.win}"
MACHINE_ORIGIN="${2:-https://api.anyfun.win}"
[[ "$PLATFORM_HOST" =~ ^[a-z0-9.-]+$ ]] || die "平台控制台域名不对：$PLATFORM_HOST"
[[ "$MACHINE_ORIGIN" =~ ^https://[a-z0-9.-]+$ ]] || die "服务端地址要是 https://域名：$MACHINE_ORIGIN"

log "核对前提"
[ -f /etc/systemd/system/rn-foundation-platform.service ] || die "还没拆成三个进程：先跑 service-split-switch.sh"
[ -n "${NGINX_FILES[rn-foundation-snippet-platform.inc]:-}" ] || die "$SRC 下没有 nginx-snippet-platform.inc"
# 新二进制才读这个键（internal/config）
grep -aq PLATFORM_CONSOLE_HOST "$BINARY" || die "$BINARY 还不认 PLATFORM_CONSOLE_HOST：先让 CI 部署新版本"
wait_platform 5 || die "平台端现在不健康（13080 没就绪），先查清楚"

BACKUP="/root/rn-foundation-platform-console-$(date -u +%Y%m%dT%H%M%SZ)"
log "备份到 $BACKUP"
install -d -m 0700 "$BACKUP" "$BACKUP/nginx"
cp -a "$ENV_FILE" "$BACKUP/rn-foundation.env"
for f in "${!NGINX_FILES[@]}"; do
  if [ -f "$NGINX_DIR/$f" ]; then cp -a "$NGINX_DIR/$f" "$BACKUP/nginx/"; fi
done

lock
done_ok=no
on_exit() {
  local code=$?
  if [ "$done_ok" = no ]; then
    printf '!! 没有完成（退出码 %s），自动退回\n' "$code" >&2
    restore "$BACKUP"
  fi
}
trap on_exit EXIT

log "env"
# 只按键判断、只追加，不读也不打印别的行（这份文件里有数据库口令与主密钥）
for pair in "PLATFORM_CONSOLE_HOST=$PLATFORM_HOST" "MACHINE_API_ORIGIN=$MACHINE_ORIGIN"; do
  if grep -q "^${pair%%=*}=" "$ENV_FILE"; then
    printf '   %s 已有，不改\n' "${pair%%=*}"
  else
    printf '%s\n' "$pair" >> "$ENV_FILE"
    printf '   加上 %s\n' "$pair"
  fi
done

log "nginx"
for f in "${!NGINX_FILES[@]}"; do
  install -m 0644 -o root -g root "$SRC/${NGINX_FILES[$f]}" "$NGINX_DIR/$f"
done
nginx -t || die "新的 nginx 配置 nginx -t 不过"
systemctl reload nginx

log "重启平台端"
systemctl restart rn-foundation-platform
wait_platform 60 || die "平台端 60 秒内没就绪"
sleep 2

log "经 nginx 核对"
methods="$(curl -sk --max-time 10 --resolve "$PLATFORM_HOST:443:127.0.0.1" "https://$PLATFORM_HOST/v1/admin/auth/methods" || true)"
[ "$methods" = '{"cid":true}' ] || die "平台控制台的统一登录没开：/v1/admin/auth/methods = $methods"
start="$(curl -sk -o /dev/null -w '%{redirect_url}' --max-time 10 --resolve "$PLATFORM_HOST:443:127.0.0.1" \
  "https://$PLATFORM_HOST/v1/admin/auth/cid/start?mode=login" || true)"
case "$start" in
  *"redirect_uri=https%3A%2F%2F$PLATFORM_HOST%2Fclient%2Fv1%2Foauth%2Flogin"*) log "   发起统一登录 → 回调地址是 https://$PLATFORM_HOST/client/v1/oauth/login" ;;
  *) die "发起统一登录没有回到平台控制台：$start" ;;
esac
code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$PLATFORM_HOST:443:127.0.0.1" -X POST "https://$PLATFORM_HOST/v1/build-agent/claim" || true)"
[ "$code" = 404 ] || die "平台控制台上不该开机器接口：POST /v1/build-agent/claim -> $code"
# 租户控制台上的平台接口：过渡期的片段转给平台端（没登录 401），租户端不认平台会话之后的片段不转（租户端 404）
want=404
if grep -q 'location ^~ /v1/admin/platform/' "$SRC/nginx-snippet-console.inc"; then want=401; fi
code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "console.anyfun.win:443:127.0.0.1" "https://console.anyfun.win/v1/admin/platform/accounts" || true)"
[ "$code" = "$want" ] || die "租户控制台上的 /v1/admin/platform/accounts -> $code，应为 $want"
done_ok=yes

cat <<DONE

平台控制台的服务端已就绪（$PLATFORM_HOST）。备份在 $BACKUP。
还差：
  - 网关按 SNI 放行 $PLATFORM_HOST（现在公网请求到不了这台机器）；
  - 认证中心给 RN 应用登记回调域名 $PLATFORM_HOST；
  - RN-Admin 的 CI 把平台控制台产物部署到 /opt/rn-foundation/admin/platform。
出问题要退回：sudo bash $0 --rollback $BACKUP
DONE
