#!/usr/bin/env bash
# 轮换 FCM 服务账号密钥。在 amos 上跑。
#
#   ./rotate-fcm-key.sh --check                 只看当前配置里那把是哪个 key、还能不能用
#   ./rotate-fcm-key.sh <新的 service-account.json>
#
# 为什么需要这个脚本而不是直接改配置：服务端加载凭据走的是
# google.CredentialsFromJSON，**它只在本地解析 JSON，不联网**。密钥被吊销了服务照样
# 能起来、日志一行错都没有，直到第一次真发推送才炸。所以换之前换之后都要做一次真
# 的令牌交换，那才是"这把密钥现在有效"的证据。
#
# 令牌交换用 openssl 手搓 JWT，不依赖任何 python 包——这台机器上装的东西越少越好。
set -euo pipefail

ENV_FILE=/etc/rn-foundation.env
SCOPE="https://www.googleapis.com/auth/firebase.messaging"

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# 用服务账号 JSON 做一次真实的 OAuth 令牌交换。成功 = 这把密钥当前有效且有权限
verify_key() { # $1 = service account json 文件
  local json="$1" email key_id key_file now header claims signed assertion resp
  email="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["client_email"])' "$json")"
  key_id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("private_key_id",""))' "$json")"
  key_file="$(mktemp)"
  # trap 在函数里不好清，显式删；私钥落盘期间权限收紧
  chmod 600 "$key_file"
  python3 -c 'import json,sys;sys.stdout.write(json.load(open(sys.argv[1]))["private_key"])' "$json" > "$key_file"

  now="$(date +%s)"
  header="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
  claims="$(printf '{"iss":"%s","scope":"%s","aud":"https://oauth2.googleapis.com/token","iat":%s,"exp":%s}' \
            "$email" "$SCOPE" "$now" "$((now + 300))" | b64url)"
  signed="$(printf '%s.%s' "$header" "$claims" | openssl dgst -sha256 -sign "$key_file" -binary | b64url)"
  assertion="$header.$claims.$signed"
  shred -u "$key_file" 2>/dev/null || rm -f "$key_file"

  resp="$(curl -s --max-time 20 -X POST https://oauth2.googleapis.com/token \
           -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
           --data-urlencode "assertion=$assertion" || true)"
  if printf '%s' "$resp" | grep -q '"access_token"'; then
    echo "   有效：$email（key id ${key_id:0:12}…）拿到了访问令牌"
    return 0
  fi
  echo "   无效：$email（key id ${key_id:0:12}…）" >&2
  printf '%s' "$resp" | head -c 300 >&2; echo >&2
  return 1
}

current_json() { # 把配置里那把 base64 解出来到临时文件
  local out="$1" v
  v="$(sudo grep -m1 '^FCM_SERVICE_ACCOUNT_JSON=' "$ENV_FILE" | cut -d= -f2- | tr -d "'\"")"
  [ -n "$v" ] || return 1
  printf '%s' "$v" | base64 -d > "$out" 2>/dev/null || return 1
  chmod 600 "$out"
}

if [ "${1:-}" = "--check" ]; then
  cur="$(mktemp)"; chmod 600 "$cur"
  trap 'shred -u "$cur" 2>/dev/null || rm -f "$cur"' EXIT
  if current_json "$cur"; then
    echo "== 当前配置里的密钥 =="
    python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print("   项目:",d["project_id"]);print("   账号:",d["client_email"]);print("   key id:",d["private_key_id"])' "$cur"
    verify_key "$cur" || true
  else
    echo "配置里没有 FCM_SERVICE_ACCOUNT_JSON" >&2; exit 1
  fi
  exit 0
fi

NEW="${1:-}"
if [ -z "$NEW" ] || [ ! -r "$NEW" ]; then
  echo "用法: $0 --check | $0 <新的 service-account.json>" >&2
  exit 2
fi

echo "== 新密钥 =="
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));assert d["type"]=="service_account";print("   项目:",d["project_id"]);print("   账号:",d["client_email"]);print("   key id:",d["private_key_id"])' "$NEW"

echo "== 换之前先证明新密钥真的能用 =="
# 这一步失败就什么都不改：拿一把用不了的密钥去换正在工作的，等于自己把推送停了
verify_key "$NEW"

echo "== 记下旧密钥的 key id（换完去控制台删它）=="
old="$(mktemp)"; chmod 600 "$old"
if current_json "$old"; then
  python3 -c 'import json,sys;print("   旧 key id:",json.load(open(sys.argv[1]))["private_key_id"])' "$old"
else
  echo "   配置里原本没有，跳过"
fi
shred -u "$old" 2>/dev/null || rm -f "$old"

echo "== 写入配置并重启 =="
printf 'FCM_SERVICE_ACCOUNT_JSON=%s\n' "$(base64 -w0 "$NEW")" | "$(dirname "$0")/merge-env.sh" >/dev/null
sudo systemctl restart rn-foundation-server
for _ in $(seq 1 15); do
  curl -fsS --max-time 3 http://127.0.0.1:13080/health/ready >/dev/null 2>&1 && break
  sleep 2
done
systemctl is-active rn-foundation-server | sed 's/^/   服务状态: /'
sudo journalctl -u rn-foundation-server -n 30 --no-pager -o cat | grep -i "push dispatcher" | tail -3 || echo "   启动日志里没有推送初始化错误"

echo "== 换完再验一次（读的是配置里的那份）=="
cur="$(mktemp)"; chmod 600 "$cur"
current_json "$cur" && verify_key "$cur"
shred -u "$cur" 2>/dev/null || rm -f "$cur"

cat <<'NEXT'

接下来：
  1. 把你放上来的新 JSON 删掉：shred -u <文件>
  2. 去 Google Cloud 控制台把上面那个「旧 key id」删掉
     IAM 与管理 → 服务账号 → 该账号 → 密钥
  3. 删完再跑一次 ./rotate-fcm-key.sh --check，确认现在这把仍然有效
NEXT
