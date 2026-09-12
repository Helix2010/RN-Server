#!/usr/bin/env bash
# 批量清理历史发布产物。在 web4 上跑（管理密钥只在那台机器的 .env 里）：
#
#   DRY_RUN=1 ./purge-history.sh android    # 先看要删什么
#   ./purge-history.sh android              # 真删
#
# "历史"的定义就一条：build 号低于当前 active 全量包的那些。比 active 更高的
# verified 记录是待发布，不动。OTA 全部尝试删除，由服务端决定哪一条要留——正在给
# 当前出货版本下发的那条会返回 409 OTA_RELEASE_IN_USE，脚本把它算作"保留"。
#
# 不可撤销：对象存储里的包体和数据库记录一起消失。每一次删除都带理由进审计。
set -euo pipefail

PLATFORM="${1:-android}"
DRY_RUN="${DRY_RUN:-0}"
REASON="${REASON:-scheduled cleanup of historical release artifacts}"
API="${API:-http://127.0.0.1:3100}"
SERVICE_DIR="${SERVICE_DIR:-/home/ubuntu/fy/service}"

# shellcheck disable=SC1091
. "$SERVICE_DIR/.env"

hdr=(-H "Host: api.anyfun.win" -H "x-admin-key: $ADMIN_API_KEY"
  -H "x-admin-id: ${ADMIN_ID:-ops@local}" -H "content-type: application/json")
body="$(jq -nc --arg r "$REASON" '{reason:$r,confirm:true}')"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

get() { curl -sS "${hdr[@]}" "$API$1"; }
del() { curl -sS -o "$tmp" -w '%{http_code}' -X DELETE "${hdr[@]}" -d "$body" "$API$1"; }

sweep() { # $1 = 接口前缀，其余 = 要删的 id
  local path="$1" id code deleted=0 kept=0 failed=0
  shift
  if [ "$#" -eq 0 ]; then
    echo "  没有要处理的记录"
    return 0
  fi
  for id in "$@"; do
    if [ "$DRY_RUN" = "1" ]; then
      echo "  待删 $id"
      continue
    fi
    code="$(del "$path/$id")"
    case "$code" in
    200) deleted=$((deleted + 1)) ;;
    409)
      kept=$((kept + 1))
      echo "  保留 $id  $(jq -r '.code // "?"' "$tmp")"
      ;;
    *)
      failed=$((failed + 1))
      echo "  失败 $id  HTTP $code  $(jq -r '.code // .detail // "?"' "$tmp")"
      ;;
    esac
  done
  echo "  删除=$deleted 保留=$kept 失败=$failed"
}

echo "== OTA 修订（$PLATFORM）=="
ota=()
while IFS= read -r line; do ota+=("$line"); done < <(
  get "/v1/admin/ota/releases?platform=$PLATFORM&pageSize=500" | jq -r '.items[].id'
)
sweep /v1/admin/ota/releases ${ota[@]+"${ota[@]}"}

echo "== 全量包（$PLATFORM）=="
releases="$(get "/v1/admin/releases?platform=$PLATFORM&pageSize=500")"
live="$(jq -r '[.items[] | select(.status=="active") | .buildNumber] | max // empty' <<<"$releases")"
if [ -z "$live" ]; then
  echo "  没有 active 全量包，不清理——无从判断哪些算历史"
  exit 0
fi
echo "  当前出货 build=$live，只清 build 低于它的"
old=()
while IFS= read -r line; do old+=("$line"); done < <(
  jq -r --argjson live "$live" '.items[] | select(.buildNumber < $live) | .id' <<<"$releases"
)
sweep /v1/admin/releases ${old[@]+"${old[@]}"}
