#!/usr/bin/env bash
# 在 amos 上放一份 iOS 构建依赖的固定副本，打包机从 https://api.anyfun.win/build-deps/<路径> 下
# （nginx-snippet-api.inc 里的 /build-deps/）。
#
# 为什么要有：有的 pod 在 prepare_command 里直接 curl github.com 的 release——YttriumWrapper 的
# libyttrium.xcframework.zip，87 MB，上游不校验——mac-01 上三次挂两次。RN-App 改成从这里下、按 sha256
# 校验（RN-App scripts/lib/ios-pinned-pods.js）。钉哪个版本、sha256 是多少以那边为准，这个脚本不存任何版本。
#
# 用法（在 amos 上，需要 sudo）：
#   sudo bash install-build-dep.sh <上游地址> <sha256> <路径>
# 例：
#   sudo bash install-build-dep.sh \
#     https://github.com/reown-com/yttrium/releases/download/0.10.54/libyttrium.xcframework.zip \
#     1d8555bdd7526ec984f43e227e7fcf30a83d090a0e7d481cd5dfb2d55f0fa32b \
#     yttrium/0.10.54/libyttrium.xcframework.zip
#
# 路径带版本，放进去就不再变：nginx 给它一年的缓存，Cloudflare 边缘也缓存。所以同一路径已经有文件时，
# sha256 相同就什么都不做，不同就拒绝——要换内容就换路径（换版本号）。
set -euo pipefail

ROOT=/opt/rn-foundation/build-deps

die() {
  echo "$*" >&2
  exit 1
}

[ $# -eq 3 ] || die "用法：sudo bash $0 <上游地址> <sha256> <路径>"
upstream=$1
sha256=$2
path=$3
case $upstream in
  https://*) ;;
  *) die "上游地址必须是 https：$upstream" ;;
esac
[[ $sha256 =~ ^[0-9a-f]{64}$ ]] || die "sha256 应当是 64 位小写十六进制：$sha256"
# 只许 a/b/c 这样的相对路径：不许以 / 开头、不许空段、不许 . 或 .. 段
[[ $path =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || die "路径只许字母、数字与 ._-，用 / 分段：$path"
[[ /$path/ != */../* && /$path/ != */./* ]] || die "路径里不许有 . 或 .. 段：$path"
[ "$(id -u)" -eq 0 ] || die "要 root：sudo bash $0 …"

target=$ROOT/$path
if [ -e "$target" ]; then
  got=$(sha256sum "$target" | awk '{print $1}')
  [ "$got" = "$sha256" ] || die "$target 已经在了，但 sha256 是 $got，不是 $sha256。路径放进去就不再变：换内容就换路径"
  echo "已就位：$target"
  exit 0
fi

install -d -o root -g root -m 0755 "$ROOT" "$(dirname "$target")"
# 下到同一个目录里再改名：改名是原子的，nginx 不会发出半个文件。下载中的临时文件是 0600，nginx 读不到
work=$(mktemp "$(dirname "$target")/.incoming.XXXXXX")
trap 'rm -f "$work"' EXIT
echo "下载 $upstream"
curl --fail --location --silent --show-error --retry 5 --retry-all-errors \
  --connect-timeout 30 --max-time 1800 -o "$work" "$upstream"
got=$(sha256sum "$work" | awk '{print $1}')
[ "$got" = "$sha256" ] || die "校验失败：期望 $sha256，实际 $got。没有放进去"
chmod 0644 "$work"
mv "$work" "$target"
trap - EXIT
echo "放好了：$target（$(stat -c %s "$target") 字节）"
echo "打包机从这里下：https://api.anyfun.win/build-deps/$path"
