#!/usr/bin/env bash
# 轮换**封装口令**——不是换签名密钥。在开发机上跑（需要 go、ssh amos）。
#
#   ./rotate-keystore-passphrase.sh --check     只看当前状态，什么都不改
#   ./rotate-keystore-passphrase.sh
#
# ## 这个脚本换的是什么
#
# 签名密钥存在数据库里，外面套着一个用**封装口令**封的盒子。服务端没有那个口令，
# 打不开盒子——这是"签名密钥可以进数据库"的全部依据。口令只在打包机的
# /etc/rn-build-agent.env 里。
#
# 口令泄漏了（或者怀疑泄漏）时，要换的是口令，**不是密钥**：
#
#   - 换口令 = 用同一把密钥重新封一次盒子。对 App 侧零影响。
#   - 换密钥 = 换签名证书 = Android 认为这是另一个 App。装着旧版的用户升不上去，
#     只能换包名让每个人手动卸载重装。
#
# 所以只要明文 keystore 还在手上，就永远换口令，不换密钥。
#
# ## 一个绕不开的窗口
#
# 打包机上只有**一个**封装口令，全租户共用。所以"上传新盒子"和"改打包机口令"之间
# 必然有一小段时间对不上，那段时间构建会失败。脚本把它压到几秒，并且按
# 「先传新盒子，再改机器」的顺序——反过来的话窗口一样存在，但失败的是已经在跑的构建。
#
# ## 口令绝不经过命令行
#
# read -rsp 读进变量再 export，不回显、不进 argv、不进 shell 历史。脚本自己也从不
# 打印它。别用 --passphrase 这种参数把它塞进命令行：ps 看得见，history 也留着。
set -euo pipefail

AMOS="${AMOS_HOST:-amos}"
AGENT_ENV=/etc/rn-build-agent.env
# 已经有明文 keystore、需要"重新封一次"的租户：<api 域名>|<keystore 文件>|<口令文件>|<alias>
RESEAL=(
  "api.anyfun.win|$HOME/release-keys/anyfun/anyfun-release.jks|$HOME/release-keys/anyfun/anyfun-release.password|anyfun"
)
# 没有明文 keystore、也没有已发布的包，直接用新口令重新生成的租户：<api 域名>
REGENERATE=("api.predict.kim")

# 脚本在 deploy/amos/ 下，go run 要在仓库根跑
cd "$(dirname "$0")/../.."

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# 管理端凭据从 amos 上读进变量。只在本进程里存在，不打印、不落盘。
admin_key() {
  ssh "$AMOS" "sudo grep -m1 '^ADMIN_API_KEY=' /etc/rn-foundation.env | cut -d= -f2-"
}

# api 调管理端接口。凭据从**标准输入**喂给 curl（--config -），不进命令行——
# argv 是全机器可读的（ps），而这把密钥和封装口令一样，不该被旁边任何一个进程看见。
api() { # $1=域名 $2=方法 $3=路径 [$4=请求体文件]
  local host="$1" method="$2" path="$3" file="${4:-}"
  {
    printf 'url = "https://%s%s"\n' "$host" "$path"
    printf 'request = "%s"\n' "$method"
    printf 'silent\nshow-error\n'
    printf 'header = "x-admin-key: %s"\n' "$ADMIN_KEY"
    if [ -n "$file" ]; then
      printf 'header = "content-type: application/json"\n'
      printf 'data-binary = "@%s"\n' "$file"
    fi
  } | curl --config -
}

status() {
  local host="$1"
  api "$host" GET /v1/admin/build-keystore | python3 -c '
import sys, json
d = json.load(sys.stdin)
if not d.get("configured"):
    print("   还没有密钥"); raise SystemExit
c = d.get("check") or {}
print("   version=%s alias=%s 打包机验证=%s %s" % (
    d.get("version"), d.get("keyAlias"), c.get("status"), (c.get("error") or "")[:60]))
'
}

if [ "${1:-}" = "--check" ]; then
  ADMIN_KEY="$(admin_key)"
  for entry in "${RESEAL[@]}" "${REGENERATE[@]}"; do
    host="${entry%%|*}"
    say "$host"; status "$host"
  done
  exit 0
fi

# ---- 1. 新口令。只在这里出现一次，之后只经过环境变量 ----
read -rsp "新的封装口令（至少 12 个字符，不回显）: " NEW_PASSPHRASE; echo
read -rsp "再输一次: " AGAIN; echo
[ "$NEW_PASSPHRASE" = "$AGAIN" ] || die "两次不一致"
unset AGAIN
[ "${#NEW_PASSPHRASE}" -ge 12 ] || die "至少 12 个字符：数据库落到别人手里时，它是签名密钥前面唯一的东西"
# shellcheck disable=SC2029  # 路径是常量，就是要在本机展开成最终字符串
ssh "$AMOS" "sudo grep -q '^BUILD_KEYSTORE_PASSPHRASE=' $AGENT_ENV" || die "打包机上没有 BUILD_KEYSTORE_PASSPHRASE 这一行"

ADMIN_KEY="$(admin_key)"
[ -n "$ADMIN_KEY" ] || die "读不到 ADMIN_API_KEY"

WORK="$(mktemp -d)"
cleanup() {
  # 请求体里是封好的盒子，不是明文密钥，但没有理由留在磁盘上
  find "$WORK" -type f -exec shred -u {} + 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- 2. 用新口令重新封已有的密钥 ----
for entry in "${RESEAL[@]}"; do
  IFS='|' read -r host keystore pwfile alias <<<"$entry"
  say "== $host：用新口令重新封 $alias =="
  [ -f "$keystore" ] || die "找不到明文 keystore：$keystore。没有它就只能换密钥，那会让老用户升不上去"
  [ -f "$pwfile" ] || die "找不到 keystore 口令文件：$pwfile"
  version="$(api "$host" GET /v1/admin/build-keystore | python3 -c 'import sys,json;print(json.load(sys.stdin).get("version",0))')"

  # 三个秘密全部走环境变量，一个都不进命令行
  ANDROID_RELEASE_KEYSTORE_PASSWORD="$(cat "$pwfile")" \
  ANDROID_RELEASE_KEY_PASSWORD="$(cat "$pwfile")" \
  BUILD_KEYSTORE_PASSPHRASE="$NEW_PASSPHRASE" \
    go run ./cmd/build-keystore seal \
      --keystore "$keystore" --alias "$alias" \
      --expected-version "$version" --out "$WORK/$alias.json" >/dev/null
  # 不带 --package：同一把密钥，证书指纹没变，发布身份不需要动

  api "$host" PUT /v1/admin/build-keystore "$WORK/$alias.json" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print("   已上传，version=%s" % d.get("version") if d.get("configured") else "   上传失败: %s" % json.dumps(d,ensure_ascii=False)[:200])'
done

# ---- 3. 改打包机。窗口从这一刻起闭合 ----
#
# 口令走 stdin，不进 argv、不进远端的 shell 历史、不落盘。改写脚本本身不含秘密，
# 所以可以大方地用 heredoc 送过去。
say "== 打包机换口令并重启代理 =="
ssh "$AMOS" "cat > /tmp/rotate-passphrase.py" <<'REMOTE_PY'
import sys

# 从标准输入读新口令。整行原样用，不 strip 空格——口令里可能就有
value = sys.stdin.read()
value = value[:-1] if value.endswith("\n") else value
path = "/etc/rn-build-agent.env"
lines = open(path).read().splitlines()
hit = False
out = []
for line in lines:
    if line.startswith("BUILD_KEYSTORE_PASSPHRASE="):
        out.append("BUILD_KEYSTORE_PASSPHRASE=" + value)
        hit = True
    else:
        out.append(line)
if not hit:
    raise SystemExit("BUILD_KEYSTORE_PASSPHRASE= not found in " + path)
open(path, "w").write("\n".join(out) + "\n")
print("   打包机口令已更新")
REMOTE_PY
# shellcheck disable=SC2029  # 同上：$AGENT_ENV 在本机展开，$(date) 留给远端
printf '%s' "$NEW_PASSPHRASE" | ssh "$AMOS" "
  set -e
  # -n：sudo 要是弹口令提示，它会把标准输入上的封装口令吃掉，然后写进一个
  # 面目全非的配置文件。宁可在这里硬失败
  sudo -n cp $AGENT_ENV $AGENT_ENV.bak-\$(date +%s)
  sudo -n python3 /tmp/rotate-passphrase.py
  rm -f /tmp/rotate-passphrase.py
  sudo -n systemctl restart rn-build-agent
  printf '   代理状态：'; systemctl is-active rn-build-agent
"

# ---- 4. 用新口令给没有密钥（或密钥作废）的租户重新生成 ----
for host in "${REGENERATE[@]}"; do
  say "== $host：用新口令重新生成密钥 =="
  meta="$(api "$host" GET /v1/admin/build-keystore)"
  kver="$(printf '%s' "$meta" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("version",0))')"
  ident="$(api "$host" GET /v1/admin/release-identity/android)"
  pkg="$(printf '%s' "$ident" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("packageName") or "")')"
  rver="$(printf '%s' "$ident" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("version",0))')"
  [ -n "$pkg" ] || die "$host 还没登记包名，先在控制台填上再跑"

  NEW_PASSPHRASE="$NEW_PASSPHRASE" PKG="$pkg" KVER="$kver" RVER="$rver" \
    python3 -c '
import json, os
print(json.dumps({
    "packageName": os.environ["PKG"],
    "commonName": os.environ["PKG"].split(".")[-1],
    "keyAlias": "release",
    "keySize": 2048,
    "validityYears": 30,
    "sealPassphrase": os.environ["NEW_PASSPHRASE"],
    "expectedVersion": int(os.environ["KVER"]),
    "releaseIdentityExpectedVersion": int(os.environ["RVER"]),
    "reason": "rotate the sealing passphrase",
    "confirm": True,
}))' > "$WORK/generate.json"

  out="$WORK/generated-$host.json"
  api "$host" POST /v1/admin/build-keystore/generate "$WORK/generate.json" > "$out"
  # 明文 keystore 和 store 口令**只在这一次响应里出现**，必须当场备份
  backup="$HOME/release-keys/$(printf '%s' "$host" | sed 's/^api\.//')"
  mkdir -p "$backup"; chmod 700 "$backup"
  OUT="$out" BACKUP="$backup" python3 -c '
import base64, json, os, sys
d = json.load(open(os.environ["OUT"]))
if "keystoreBase64" not in d:
    print("   生成失败:", json.dumps(d, ensure_ascii=False)[:300]); sys.exit(1)
backup = os.environ["BACKUP"]
ks = os.path.join(backup, d["fileName"])
with open(os.open(ks, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
    f.write(base64.b64decode(d["keystoreBase64"]))
pw = os.path.join(backup, d["fileName"] + ".password")
with open(os.open(pw, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
    f.write(d["storePassword"])
print("   已生成并备份到 %s（0600）：%s 与同名 .password" % (backup, d["fileName"]))
print("   证书指纹 %s" % d["signerSha256"])
'
done

# ---- 5. 让打包机自己说能不能打开 ----
say "== 等打包机验证（它是唯一有口令的一方）=="
for _ in $(seq 1 12); do
  pending=0
  for entry in "${RESEAL[@]}" "${REGENERATE[@]}"; do
    host="${entry%%|*}"
    st="$(api "$host" GET /v1/admin/build-keystore | python3 -c 'import sys,json;print((json.load(sys.stdin).get("check") or {}).get("status","pending"))')"
    [ "$st" = "pending" ] && pending=1
  done
  [ "$pending" = "0" ] && break
  sleep 10
done
for entry in "${RESEAL[@]}" "${REGENERATE[@]}"; do
  host="${entry%%|*}"
  say "$host"; status "$host"
done

unset NEW_PASSPHRASE ADMIN_KEY
say ""
say "口令没有出现在任何命令行、日志或输出里。它现在只在两个地方：你的密码管理器，"
say "和打包机的 $AGENT_ENV。"
