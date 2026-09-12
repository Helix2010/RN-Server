#!/usr/bin/env bash
# 从标准输入读 KEY=VALUE，逐行覆盖 /etc/rn-foundation.env 里的同名项。
# 值不回显，只报告哪些键被写入、以及还有没有 CHANGE_ME_ 残留。
#
#   printf 'PUSH_DISPATCH_ENABLED=true\n' | ./merge-env.sh
#   ssh 另一台 '读出若干 KEY=VALUE' | ./merge-env.sh     # 值不经过中间终端
#
# 用途是跨机同步配置而不让值出现在命令行参数、shell 历史或对话记录里。
set -euo pipefail

TARGET="${TARGET:-/etc/rn-foundation.env}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
# shellcheck disable=SC2024  # 重定向确实在调用者身上，这正是要的：sudo 只用来读
# root-only 的源文件，写入目标是本用户的 mktemp
sudo cat "$TARGET" > "$TMP"

written=()
while IFS= read -r line; do
  [ -n "$line" ] || continue
  key="${line%%=*}"
  # 用 python 做替换而不是 sed：值里可能有 / & $ 等会把 sed 表达式打断的字符
  KEY="$key" LINE="$line" python3 - "$TMP" <<'PY'
import os, sys
path = sys.argv[1]
key, line = os.environ["KEY"], os.environ["LINE"]
out, hit = [], False
for raw in open(path).read().splitlines():
    if raw.startswith(key + "="):
        out.append(line); hit = True
    else:
        out.append(raw)
if not hit:
    out.append(line)
open(path, "w").write("\n".join(out) + "\n")
PY
  written+=("$key")
done

sudo install -m 0600 -o root -g root "$TMP" "$TARGET"
echo "已写入: ${written[*]:-（无）}"

# `|| true` 不能省：没有残留时 grep 返回 1，在 set -e + pipefail 下会让这个脚本
# 以非零退出，进而把调用方一起带停。轮换 FCM 密钥那次就是这样——配置写进去了，
# 服务却没重启，进程里还是旧密钥，而脚本看起来只是"提前结束"
remaining="$(sudo grep -cE '=CHANGE_ME_' "$TARGET" || true)"
echo "残留 CHANGE_ME_: $remaining"
if [ "$remaining" != "0" ]; then
  sudo grep -oE '^[A-Za-z0-9_]+=CHANGE_ME_[A-Z_]*' "$TARGET" | cut -d= -f1 | tr '\n' ' '
  echo
fi
