#!/usr/bin/env bash
# 从开发机部署 amos 上的 RN-Foundation（API + 扫链 + 两个租户的控制台）。
#
#   ./deploy.sh            全量：服务端 + 两份控制台
#   ./deploy.sh server     只更新服务端与扫链
#   ./deploy.sh admin      只更新控制台静态产物
#
# 和打包机代理同一套做法：在开发机交叉编译，scp 过去，systemd 换进程。amos 上
# 没有 Go 工具链，也不装——那台机器上能跑的东西越少越好。
set -euo pipefail

HOST="${AMOS_HOST:-amos}"
SERVER_REPO="${SERVER_REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
ADMIN_REPO="${ADMIN_REPO:-$(cd "$SERVER_REPO/../RN-Admin" && pwd)}"
WHAT="${1:-all}"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# 租户 → 控制台目录 → 该租户的 API 源。控制台把 API 地址编译进包里，所以一个租户
# 一份产物；加租户就在这里加一行
TENANTS=(
  "any123:https://api.any123.top"
  "predict-kim:https://api.predict.kim"
)

build_server() {
  echo "== 编译服务端 =="
  # GOTOOLCHAIN=local：go.mod 的 go 指令固定在 1.24，不让它自己去下别的工具链
  (cd "$SERVER_REPO" && GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "$STAGE/rn-server" ./cmd/server)
  echo "   $(du -h "$STAGE/rn-server" | cut -f1)"
}

ship_server() {
  echo "== 上传并重启 =="
  scp -q "$STAGE/rn-server" "$HOST:/tmp/rn-server"
  # 先停扫链再停 API：扫链依赖 API 先就绪，反过来停会多打一轮连接失败的日志
  ssh "$HOST" 'sudo systemctl stop rn-foundation-indexer rn-foundation-server || true
    sudo install -m 0755 -o root -g root /tmp/rn-server /opt/rn-foundation/rn-server
    rm -f /tmp/rn-server
    sudo systemctl start rn-foundation-server
    sudo systemctl start rn-foundation-indexer'
}

build_admin() {
  echo "== 构建控制台 =="
  (cd "$ADMIN_REPO" && pnpm install --frozen-lockfile >/dev/null)
  for entry in "${TENANTS[@]}"; do
    local slug="${entry%%:*}" api="${entry#*:}"
    echo "   $slug -> $api"
    (cd "$ADMIN_REPO" && VITE_API_BASE_URL="$api" pnpm build >/dev/null)
    mkdir -p "$STAGE/admin/$slug"
    cp -r "$ADMIN_REPO/dist/." "$STAGE/admin/$slug/"
  done
}

ship_admin() {
  echo "== 上传控制台 =="
  # 先传到家目录下的暂存区，再用 sudo 搬进 /opt。直接 rsync 到 /opt 要先把目录
  # chown 给登录用户，那会留下一段「网站根目录可被普通用户写」的窗口
  local stage_remote="\$HOME/.rn-foundation-admin-stage"
  for entry in "${TENANTS[@]}"; do
    local slug="${entry%%:*}"
    # shellcheck disable=SC2029  # slug 就是要在本机展开
    ssh "$HOST" "mkdir -p $stage_remote/$slug"
    # --delete：上一版留下的旧 chunk 必须消失，否则目录只会越长越大
    rsync -a --delete "$STAGE/admin/$slug/" "$HOST:.rn-foundation-admin-stage/$slug/"
    # shellcheck disable=SC2029
    ssh "$HOST" "sudo mkdir -p /opt/rn-foundation/admin/$slug \
      && sudo rsync -a --delete $stage_remote/$slug/ /opt/rn-foundation/admin/$slug/ \
      && sudo chown -R root:root /opt/rn-foundation/admin/$slug \
      && sudo chmod -R a+rX /opt/rn-foundation/admin/$slug \
      && rm -rf $stage_remote/$slug"
  done
  ssh "$HOST" 'sudo nginx -t && sudo systemctl reload nginx'
}

case "$WHAT" in
all)    build_server; build_admin; ship_server; ship_admin ;;
server) build_server; ship_server ;;
admin)  build_admin;  ship_admin ;;
*)      echo "用法: $0 [all|server|admin]" >&2; exit 2 ;;
esac

echo "== 健康检查 =="
ssh "$HOST" 'systemctl is-active rn-foundation-server rn-foundation-indexer | tr "\n" " "; echo
  curl -fsS http://127.0.0.1:13080/health/ready && echo'
