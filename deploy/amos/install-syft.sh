#!/usr/bin/env bash
# 在打包机上装 syft（SBOM 生成器）。
#
# 为什么固定版本 + 固定 sha256，而不是官方那条 `curl … | sh`：那条管道每次装到的
# 是"当天的最新版"，而 SBOM 是要被别人当证据读的东西——同一个 commit 在两台机器
# 上扫出不同的组件数，没人能判断是依赖变了还是工具变了。校验和写死在这里，改版本
# 必须同时改这两个值，改动会留在 git 记录里。
#
# 用法（在打包机上，需要 sudo）：
#   sudo bash install-syft.sh
#
# 校验和来源：syft_<版本>_checksums.txt（release 页同目录），已核对压缩包与解出来的
# 二进制两层。
set -euo pipefail

VERSION=1.51.1
TARBALL_SHA256=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3
BINARY_SHA256=abca2def61de9952fa06d3977bb1e064818facb9badfce502b450d3d6846a91f
TARGET=/usr/local/bin/syft

if [ "$(uname -m)" != "x86_64" ]; then
  echo "这份校验和对应 linux_amd64，当前是 $(uname -m)" >&2
  exit 1
fi

if [ -x "$TARGET" ] && [ "$(sha256sum "$TARGET" | awk '{print $1}')" = "$BINARY_SHA256" ]; then
  echo "syft $VERSION 已就位：$TARGET"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
url="https://github.com/anchore/syft/releases/download/v${VERSION}/syft_${VERSION}_linux_amd64.tar.gz"
echo "下载 syft $VERSION"
curl -fsSL --max-time 300 -o "$work/syft.tgz" "$url"

got=$(sha256sum "$work/syft.tgz" | awk '{print $1}')
if [ "$got" != "$TARBALL_SHA256" ]; then
  echo "压缩包校验失败：期望 $TARBALL_SHA256，实际 $got" >&2
  exit 1
fi

tar -xzf "$work/syft.tgz" -C "$work" syft
got=$(sha256sum "$work/syft" | awk '{print $1}')
if [ "$got" != "$BINARY_SHA256" ]; then
  echo "二进制校验失败：期望 $BINARY_SHA256，实际 $got" >&2
  exit 1
fi

install -o root -g root -m 0755 "$work/syft" "$TARGET"
echo "装好了：$("$TARGET" version | awk '/^Version:/{print $2}') → $TARGET"
