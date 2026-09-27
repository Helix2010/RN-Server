#!/usr/bin/env bash
# 从开发机部署 amos 上的 RN-Foundation（API + 扫链 + 控制台）。
#
#   ./deploy.sh            全量：服务端 + 全部控制台
#   ./deploy.sh server     只更新服务端与扫链
#   ./deploy.sh admin      只更新控制台静态产物
#
# 正常情况下走 GitHub Actions（两个仓库各一个 deploy-amos.yml），这个脚本是手工／
# 应急通道。两边最后都调用 amos 上的 /usr/local/sbin/rn-foundation-apply：停服务、
# 换二进制、跑迁移、健康检查、失败回滚都在那一个脚本里，这里只负责"编译 + 送过去"。
#
# 和打包机代理同一套做法：在开发机交叉编译，送过去，systemd 换进程。amos 上没有 Go
# 工具链，也不装——那台机器上能跑的东西越少越好。
set -euo pipefail

HOST="${AMOS_HOST:-amos}"
SERVER_REPO="${SERVER_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
ADMIN_REPO="${ADMIN_REPO:-$(cd "$SERVER_REPO/../RN-Admin" && pwd)}"
WHAT="${1:-all}"
APPLY=/usr/local/sbin/rn-foundation-apply
STAGE=/var/lib/rn-foundation-deploy/incoming
STAGING_LOCAL=$(mktemp -d)
trap 'rm -rf "$STAGING_LOCAL"' EXIT

require_apply() {
  # shellcheck disable=SC2029  # 这些路径就是要在本机展开，远端只收到最终字符串
  ssh "$HOST" "test -x $APPLY" || {
    echo "amos 上没装 $APPLY。在那台机器上跑一次 deploy/amos/setup-ci-deploy.sh" >&2
    exit 1
  }
}

# 控制台只有一份产物：请求 API 走同源 /v1/，由各 console.* 的 nginx 转给 rn-server，包里不编 API 地址
# （RN-Admin 设计 console-single-build-same-origin-2026-09-25）。apply 的 admin 子命令收的是目录名
ADMIN_DIR=console

build_server() {
  echo "== 编译服务端 =="
  # GOTOOLCHAIN=local：go.mod 的 go 指令固定了版本，不让它自己去下别的工具链
  (cd "$SERVER_REPO" && GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "$STAGING_LOCAL/rn-server" ./cmd/server)
  echo "   $(du -h "$STAGING_LOCAL/rn-server" | cut -f1)"
}

ship_server() {
  echo "== 上传并切换 =="
  # 经一次 /tmp 是因为这个账号（一般是 ubuntu）对暂存目录没有写权限，那个目录属于
  # CI 的 rndeploy。传完 sudo install 进去，再调同一个特权脚本
  ssh "$HOST" "cat > /tmp/rn-server.part" < "$STAGING_LOCAL/rn-server"
  # shellcheck disable=SC2029
  ssh "$HOST" "set -e
    sudo mkdir -p '$STAGE'
    sudo install -m 0644 -o root -g root /tmp/rn-server.part '$STAGE/rn-server'
    rm -f /tmp/rn-server.part
    sudo $APPLY server"
}

build_admin() {
  echo "== 构建控制台 =="
  (cd "$ADMIN_REPO" && pnpm install --frozen-lockfile >/dev/null)
  # 生产包不认 VITE_API_BASE_URL（只给 pnpm dev 用），开发机 .env 里的本地地址编不进去
  (cd "$ADMIN_REPO" && rm -rf dist && pnpm build >/dev/null)
  [ -s "$ADMIN_REPO/dist/index.html" ] || { echo "   构建产物里没有 index.html" >&2; exit 1; }
  mkdir -p "$STAGING_LOCAL/admin/$ADMIN_DIR"
  cp -r "$ADMIN_REPO/dist/." "$STAGING_LOCAL/admin/$ADMIN_DIR/"
}

ship_admin() {
  echo "== 上传控制台 =="
  # 用 tar 走管道，不用 rsync：amos 上没有 rsync，为了发几个静态文件去装一个工具
  # 不值得。整目录换过去，顺带拿到 --delete 的效果
  # shellcheck disable=SC2029
  tar -C "$STAGING_LOCAL/admin/$ADMIN_DIR" -czf - . | ssh "$HOST" "
    set -eu
    sudo mkdir -p '$STAGE/admin'
    sudo rm -rf '$STAGE/admin/$ADMIN_DIR'
    sudo mkdir -p '$STAGE/admin/$ADMIN_DIR'
    sudo tar -C '$STAGE/admin/$ADMIN_DIR' -xzf -
    sudo $APPLY admin '$ADMIN_DIR'"
}

require_apply
case "$WHAT" in
all)    build_server; build_admin; ship_server; ship_admin ;;
server) build_server; ship_server ;;
admin)  build_admin;  ship_admin ;;
*)      echo "用法: $0 [all|server|admin]" >&2; exit 2 ;;
esac

echo "== 健康检查 =="
# 平台端 13080、App 端 13081、租户端 13082（端口写在各自 unit 的 ExecStart 里）
ssh "$HOST" 'systemctl is-active rn-foundation-platform rn-foundation-tenant rn-foundation-app rn-foundation-indexer | tr "\n" " "; echo
  for port in 13080 13081 13082; do curl -fsS "http://127.0.0.1:$port/health/ready" && echo; done'
