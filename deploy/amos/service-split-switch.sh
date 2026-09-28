#!/usr/bin/env bash
# 一次性：把 amos 上的 API 从一个进程（rn-foundation-server，13080）切成按角色的三个进程
# （设计 docs/design/service-and-console-split-2026-09-27.md 第 6 节第一步）。切完、稳定之后删掉这个脚本。
#
#   sudo bash service-split-switch.sh                 切换
#   sudo bash service-split-switch.sh --rollback DIR  退回切换前（DIR 是切换时打印的备份目录）
#
# 在 amos 上以 root 跑，同目录下要有本仓库 deploy/amos 的这几份文件：三个 API unit、扫链 unit、
# rn-foundation-apply、nginx 配置与三个片段。
#
# **前提：新二进制已经由 CI 部署上去**（认得 app/tenant/platform 子命令）。旧二进制不认这些参数，
# 会照旧在 13080 上起一个全量进程，三个 unit 就抢同一个端口——所以下面先核对二进制。
#
# 切换做的事，按顺序；任何一步失败都自动退回切换前的状态：
#   1. 备份旧 unit、rn-foundation-apply、nginx 配置到 /root/rn-foundation-service-split-<时间>/；
#   2. 拿部署锁（与 CI 的 rn-foundation-apply 同一把），切换期间 CI 部署会排队等；
#   3. 装新 unit 与新的 rn-foundation-apply（等于重跑 setup-ci-deploy.sh 里装脚本的那一步，sudoers 不变）；
#   4. 停旧进程，起三个新进程，等三个端口都就绪；
#   5. 换 nginx 配置，nginx -t 通过才 reload；
#   6. 经 nginx 核对分流：api.* 的管理接口 404（App 端没有）、机器接口到平台端；控制台的
#      /v1/admin 到租户端、/v1/admin/platform 到平台端；
#   7. 都通过之后才停用、删除旧 unit（备份里留着）。
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR=/etc/systemd/system
NGINX_DIR=/etc/nginx/conf.d
APPLY=/usr/local/sbin/rn-foundation-apply
BINARY=/opt/rn-foundation/rn-server
NEW_UNITS=(rn-foundation-platform rn-foundation-tenant rn-foundation-app)
NGINX_FILES=(rn-foundation.conf rn-foundation-snippet-api.inc rn-foundation-snippet-api-proxy.inc rn-foundation-snippet-console.inc)
# 经 nginx 核对用的域名：anyfun 的 api 与控制台（本机 443，--resolve 到回环，不出网）
API_HOST=api.anyfun.win
CONSOLE_HOST=console.anyfun.win

log() { printf '== %s\n' "$*"; }
die() { printf '!! %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "要以 root 跑：sudo bash $0"

wait_port() { # $1 = 端口，$2 = 最多等几秒
  local deadline=$(( $(date +%s) + $2 ))
  until curl -fsS --max-time 3 "http://127.0.0.1:$1/health/ready" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 2
  done
}

# 恢复备份里的文件并回到单进程。切换中途失败与 --rollback 都走这里
restore() { # $1 = 备份目录
  local backup="$1" f
  log "退回切换前（备份 $backup）"
  systemctl stop rn-foundation-indexer "${NEW_UNITS[@]}" 2>/dev/null || true
  systemctl disable "${NEW_UNITS[@]}" 2>/dev/null || true
  for u in "${NEW_UNITS[@]}"; do rm -f "$UNIT_DIR/$u.service"; done
  install -m 0644 -o root -g root "$backup/rn-foundation-server.service" "$UNIT_DIR/"
  install -m 0644 -o root -g root "$backup/rn-foundation-indexer.service" "$UNIT_DIR/"
  install -m 0755 -o root -g root "$backup/rn-foundation-apply" "$APPLY"
  systemctl daemon-reload
  systemctl enable rn-foundation-server >/dev/null 2>&1 || true
  systemctl start rn-foundation-server
  systemctl start rn-foundation-indexer || true
  for f in "${NGINX_FILES[@]}"; do
    install -m 0644 -o root -g root "$backup/$f" "$NGINX_DIR/$f"
  done
  if nginx -t 2>/dev/null; then
    systemctl reload nginx
  else
    printf '!! 恢复出来的 nginx 配置 nginx -t 不过，没有 reload，需要人工看\n' >&2
  fi
  if wait_port 13080 60; then
    log "已回到单进程（rn-foundation-server，13080）"
  else
    printf '!! rn-foundation-server 60 秒内没就绪：journalctl -u rn-foundation-server -n 50\n' >&2
  fi
}

if [ "${1:-}" = "--rollback" ]; then
  backup="${2:-}"
  [ -n "$backup" ] && [ -f "$backup/rn-foundation-server.service" ] || die "用法: $0 --rollback <备份目录>"
  exec 9>/var/lib/rn-foundation-deploy/.apply.lock
  flock -w 300 9 || die "另一个部署正在进行，等了 5 分钟还没轮到"
  restore "$backup"
  exit 0
fi
[ $# = 0 ] || die "用法: $0 | $0 --rollback <备份目录>"

log "核对前提"
for f in "${NEW_UNITS[@]/%/.service}" rn-foundation-indexer.service rn-foundation-apply \
         nginx-rn-foundation.conf nginx-snippet-api.inc nginx-snippet-api-proxy.inc nginx-snippet-console.inc; do
  [ -f "$SRC/$f" ] || die "$SRC 下缺 $f"
done
[ -f "$UNIT_DIR/rn-foundation-server.service" ] || die "没有 $UNIT_DIR/rn-foundation-server.service：已经切过了？"
# 新二进制才有这句报错（cmd/server/serve_args.go 经 api.ParseRole）
grep -aq 'want app, tenant or platform' "$BINARY" \
  || die "$BINARY 还是旧版本（不认角色子命令）：先让 CI 把新版本部署上来再切"
wait_port 13080 5 || die "现在的 rn-foundation-server 不健康（13080 没就绪），先查清楚再切"
for port in 13081 13082; do
  if ss -Hltn "sport = :$port" | grep -q .; then
    die "端口 $port 已经有人在听：ss -ltnp 'sport = :$port'"
  fi
done

BACKUP="/root/rn-foundation-service-split-$(date -u +%Y%m%dT%H%M%SZ)"
log "备份到 $BACKUP"
install -d -m 0700 "$BACKUP"
cp -a "$UNIT_DIR/rn-foundation-server.service" "$UNIT_DIR/rn-foundation-indexer.service" "$APPLY" "$BACKUP/"
for f in "${NGINX_FILES[@]}"; do cp -a "$NGINX_DIR/$f" "$BACKUP/"; done

# 与 CI 的 rn-foundation-apply 同一把锁：切换期间 CI 部署排队，不会在半路换二进制
exec 9>/var/lib/rn-foundation-deploy/.apply.lock
flock -w 300 9 || die "另一个部署正在进行，等了 5 分钟还没轮到（什么都还没改）"

# 从这里起改动了线上文件，失败就退回
switched=no
on_exit() {
  local code=$?
  if [ "$switched" = no ]; then
    printf '!! 切换没有完成（退出码 %s），自动退回\n' "$code" >&2
    restore "$BACKUP"
    printf '!! 已退回切换前。备份保留在 %s\n' "$BACKUP" >&2
  fi
}
trap on_exit EXIT

log "装 unit 与 rn-foundation-apply"
for u in "${NEW_UNITS[@]}" rn-foundation-indexer; do
  install -m 0644 -o root -g root "$SRC/$u.service" "$UNIT_DIR/$u.service"
done
install -m 0755 -o root -g root "$SRC/rn-foundation-apply" "$APPLY"
systemctl daemon-reload
systemd-analyze verify "${NEW_UNITS[@]/#/$UNIT_DIR/}" 2>&1 | sed 's/^/   /' || true

log "停旧进程，起三个新进程"
systemctl stop rn-foundation-indexer rn-foundation-server
systemctl start "${NEW_UNITS[@]}"
for port in 13080 13081 13082; do
  if ! wait_port "$port" 60; then
    for u in "${NEW_UNITS[@]}"; do journalctl -u "$u" -n 20 --no-pager -o cat >&2 || true; done
    die "端口 $port 60 秒内没就绪"
  fi
done
systemctl start rn-foundation-indexer || printf '!! 扫链没起来，API 不受影响：journalctl -u rn-foundation-indexer\n' >&2

log "换 nginx 配置"
install -m 0644 -o root -g root "$SRC/nginx-rn-foundation.conf" "$NGINX_DIR/rn-foundation.conf"
for f in api api-proxy console; do
  install -m 0644 -o root -g root "$SRC/nginx-snippet-$f.inc" "$NGINX_DIR/rn-foundation-snippet-$f.inc"
done
nginx -t || die "新的 nginx 配置 nginx -t 不过"
systemctl reload nginx
sleep 2

log "经 nginx 核对分流"
status() { # $1 = 域名，$2 = 方法，$3 = 路径
  curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --resolve "$1:443:127.0.0.1" -X "$2" "https://$1$3" || true
}
failed=0
expect() { # $1 = 期望状态码，其余同 status；$5 = 说明
  local got
  got="$(status "$2" "$3" "$4")"
  if [ "$got" = "$1" ]; then
    printf '   ok   %s %s %s -> %s（%s）\n' "$2" "$3" "$4" "$got" "$5"
  else
    printf '   FAIL %s %s %s -> %s，应为 %s（%s）\n' "$2" "$3" "$4" "$got" "$1" "$5" >&2
    failed=1
  fi
}
expect 200 "$API_HOST"     GET  /health/ready                "App 端"
expect 404 "$API_HOST"     GET  /v1/admin/auth/methods       "App 端没有管理接口"
expect 401 "$API_HOST"     POST /v1/build-agent/claim        "打包机接口在平台端，没带令牌"
expect 401 "$API_HOST"     POST /v1/signer/claim             "签名闸接口在平台端，没带令牌"
expect 200 "$CONSOLE_HOST" GET  /v1/admin/auth/methods       "租户端"
expect 401 "$CONSOLE_HOST" GET  /v1/admin/auth/session       "租户端，没登录"
expect 401 "$CONSOLE_HOST" GET  /v1/admin/platform/accounts  "平台端（租户端没有这条路由，会是 404）"
[ "$failed" = 0 ] || die "分流核对没通过"

log "停用并删除旧 unit"
systemctl disable rn-foundation-server >/dev/null 2>&1 || true
rm -f "$UNIT_DIR/rn-foundation-server.service"
systemctl daemon-reload
systemctl enable "${NEW_UNITS[@]}" rn-foundation-indexer >/dev/null
switched=yes

systemctl is-active "${NEW_UNITS[@]}" rn-foundation-indexer | paste -sd' ' | sed 's/^/   /'
cat <<DONE

切换完成：平台端 13080、App 端 13081、租户端 13082。备份在 $BACKUP。
接下来：
  - 签名闸仍连 127.0.0.1:13080（平台端），不用动；控制台上看一眼机器卡片都在线；
  - 用管理密钥直连的自动化（发 OTA）：租户接口 /v1/admin/* 改连 127.0.0.1:13082，平台接口仍是 13080；
  - 出问题要退回：sudo bash $0 --rollback $BACKUP
DONE
