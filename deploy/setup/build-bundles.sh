#!/usr/bin/env bash
# 构建新机器的安装包：
#   deploy/setup/build-bundles.sh <输出目录>
#
# 产出（约定：签名闸自动化「6. 安装脚本与安装包」）：
#   signer.tar.gz    bin/signer、bin/signer-check、templates/（unit 与 env 模板，@INSTANCE@ 占位）、README.md、install.sh
#   builder.tar.gz   linux/amd64：bin/build-agent、bin/build-runner、rn-build-agent.service、
#                    rn-build-agent.sudoers、rn-build-agent.env.example、README.md
#   builder-darwin-arm64.tar.gz
#                    darwin/arm64（Mac 打包机）：bin/build-agent、bin/build-runner、bin/ios-upload、
#                    bin/rn-build-agent-upgrade、run-agent、两份 launchd plist、sudoers、
#                    rn-build-agent-macos.env.example，以及两把公钥（release-key.pub、
#                    allowed_signers；由 RN_RELEASE_KEY_PUB / RN_ALLOWED_SIGNERS 指定，
#                    缺了只警告，但 install-macos.sh 会拒绝安装）
#   manifest.json    {"format":"rn-machine-bundles/v1","commit",
#                     "bundles":{"signer":{"archive","archiveSha256","archiveSize","files":[{"name","size","sha256"}]},
#                                "builder":{…},"builder-darwin-arm64":{…}}}
#
# **builder.tar.gz 仍然是 linux/amd64**：Linux 的 install.sh 与已经部署的清单都按这个名字取，
# 换名字等于让所有在跑的构建机在下一次装机时断掉。macOS 那组另起一个并列的名字。
#
# CI 部署服务端时跑它，把三个文件传到 amos 的暂存目录，`rn-foundation-apply bundles <提交>` 放进
# /opt/rn-foundation/machine-bundles/<提交>/ 并切换 current；服务端从那里给 install.sh 提供下载。
#
# 可复现：-trimpath、tar 固定顺序/属主/mtime（取提交时间）、gzip -n。同一提交、同一 Go 版本构建出的归档
# 逐字节相同，最后打印的 sha256 就是运维 `install.sh --expect-sha256` 要核对的值。
# 工作区必须干净（含未跟踪文件）；本地试验可以 RN_BUNDLE_ALLOW_DIRTY=1，提交记为 <sha>-dirty。
set -euo pipefail

OUT="${1:?用法: build-bundles.sh <输出目录>}"
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  if [ "${RN_BUNDLE_ALLOW_DIRTY:-}" != 1 ]; then
    echo "工作区不干净（含未跟踪文件），拒绝打包；本地试验用 RN_BUNDLE_ALLOW_DIRTY=1" >&2
    exit 1
  fi
  COMMIT="$COMMIT-dirty"
fi
EPOCH="$(git -C "$ROOT" log -1 --format=%ct HEAD)"

TEMPLATES="$ROOT/deploy/signer/templates"
for f in 'rn-signer-@INSTANCE@.service' 'rn-signer-@INSTANCE@-check.socket' 'rn-signer-@INSTANCE@-check@.service' 'rn-signer-@INSTANCE@.env'; do
  [ -f "$TEMPLATES/$f" ] || { echo "缺少签名闸模板 deploy/signer/templates/$f" >&2; exit 1; }
done

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
install -d "$STAGE/signer/bin" "$STAGE/signer/templates" "$STAGE/builder/bin" "$STAGE/builder-darwin-arm64/bin"

# 提交注入进 build-agent：自升级靠它回答"这台机器上跑的是哪一版"（设计 §5.6）。
# CI 与这里必须用同一个 -X 路径，两处不一致会让控制台永远看到一个追不上审批值的版本。
LDFLAGS="-s -w -X main.commit=$COMMIT"

export GOTOOLCHAIN=local CGO_ENABLED=0
(cd "$ROOT" && GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" -o "$STAGE/builder/bin/build-agent" ./cmd/build-agent)
(cd "$ROOT" && GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder/bin/build-runner" ./cmd/build-agent/build-runner)
# Mac 打包机那一组。ios-upload 只进这一组：机房那台 Linux 构建机不上传任何东西，
# 给它一个能传 build 的程序只会多一处能被误用的地方
(cd "$ROOT" && GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" -o "$STAGE/builder-darwin-arm64/bin/build-agent" ./cmd/build-agent)
(cd "$ROOT" && GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder-darwin-arm64/bin/build-runner" ./cmd/build-agent/build-runner)
(cd "$ROOT" && GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder-darwin-arm64/bin/ios-upload" ./cmd/build-agent/ios-upload)
# 升级程序以 root 跑，由停机标记触发；它验清单签名、核单调序号与目标提交之后才换二进制
(cd "$ROOT" && GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder-darwin-arm64/bin/rn-build-agent-upgrade" ./cmd/build-agent/upgrade)
# 与 deploy/signer/README.md「构建」同一组参数
(cd "$ROOT/signing" && GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -o "$STAGE/signer/bin/" ./cmd/signer ./cmd/signer-check)

cp "$TEMPLATES"/*@INSTANCE@* "$STAGE/signer/templates/"
cp "$ROOT/deploy/signer/README.md" "$STAGE/signer/README.md"
cp "$ROOT/internal/machinesetup/install.sh" "$STAGE/signer/install.sh"
cp "$ROOT/deploy/build-agent/rn-build-agent.service" "$ROOT/deploy/build-agent/rn-build-agent.sudoers" \
  "$ROOT/deploy/build-agent/rn-build-agent.env.example" "$ROOT/deploy/build-agent/README.md" "$STAGE/builder/"
# Mac 那一组还要带上两把**公钥**：发布公钥（自升级的信任根）与 allowed_signers（提交签名
# 的信任根）。它们不是机密，但也不在仓库里——一个由离线机器上的 bundle-sign 生成，一个由
# 平台维护。装机脚本从安装包里取出来之后，会与运维从密码管理器里带来的 sha256 比对；
# 缺了它们的安装包装不了 Mac（install-macos.sh 会当场停下），所以这里只警告不失败：
# 一次只出 Linux 包的构建不该因此断掉。
RELEASE_KEY_PUB="${RN_RELEASE_KEY_PUB:-$ROOT/deploy/build-agent-macos/release-key.pub}"
ALLOWED_SIGNERS="${RN_ALLOWED_SIGNERS:-$ROOT/deploy/build-agent-macos/allowed_signers}"
for f in "$RELEASE_KEY_PUB" "$ALLOWED_SIGNERS"; do
  if [ -f "$f" ]; then
    install -m 0644 "$f" "$STAGE/builder-darwin-arm64/$(basename "$f")"
  else
    echo "!! 缺 $f：builder-darwin-arm64.tar.gz 不含它，install-macos.sh 会拒绝安装。" >&2
    echo "   用 RN_RELEASE_KEY_PUB / RN_ALLOWED_SIGNERS 指过去，或者放进 deploy/build-agent-macos/。" >&2
  fi
done
cp "$ROOT/deploy/build-agent-macos/rn-build-agent-macos.env.example" \
  "$ROOT/deploy/build-agent-macos/rn-build-agent.sudoers" \
  "$ROOT/deploy/build-agent-macos/run-agent" \
  "$ROOT/deploy/build-agent-macos/win.anyfun.rn-build-agent.plist" \
  "$ROOT/deploy/build-agent-macos/win.anyfun.rn-build-agent-upgrade.plist" \
  "$STAGE/builder-darwin-arm64/"

for role in signer builder builder-darwin-arm64; do
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --mode='u+rwX,go+rX,go-w' \
    -C "$STAGE/$role" -cf - . | gzip -n -9 >"$OUT/$role.tar.gz.part"
  mv -f "$OUT/$role.tar.gz.part" "$OUT/$role.tar.gz"
done

python3 -I - "$STAGE" "$OUT" "$COMMIT" <<'PY'
import hashlib, json, os, sys

stage, out, commit = sys.argv[1:4]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

bundles = {}
for role in ("signer", "builder", "builder-darwin-arm64"):
    root = os.path.join(stage, role)
    files = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            files.append({"name": rel, "size": os.path.getsize(path), "sha256": sha256(path)})
    files.sort(key=lambda f: f["name"].encode())
    archive = os.path.join(out, role + ".tar.gz")
    bundles[role] = {"archive": role + ".tar.gz", "archiveSha256": sha256(archive),
                     "archiveSize": os.path.getsize(archive), "files": files}
manifest = {"format": "rn-machine-bundles/v1", "commit": commit, "bundles": bundles}
with open(os.path.join(out, "manifest.json.part"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
os.replace(os.path.join(out, "manifest.json.part"), os.path.join(out, "manifest.json"))
PY

# 冒烟：空环境的 build-agent 必须以 2 退出（只在 linux/amd64 上能跑）
if [ "$(uname -s)/$(uname -m)" = Linux/x86_64 ]; then
  code=0
  env -i "$STAGE/builder/bin/build-agent" >/dev/null 2>&1 || code=$?
  [ "$code" = 2 ] || { echo "build-agent 空环境退出码 $code，应为 2" >&2; exit 1; }
fi

echo "安装包：$OUT（提交 $COMMIT）"
(cd "$OUT" && sha256sum signer.tar.gz builder.tar.gz builder-darwin-arm64.tar.gz)
(cd "$STAGE/signer" && sha256sum install.sh bin/signer bin/signer-check)
(cd "$STAGE/builder" && sha256sum bin/build-agent bin/build-runner)
# darwin 的二进制在 Linux 上跑不了，冒烟只能在 Mac 上做（升级脚本会做，见 §5.6）。
# 交叉编译出来的 darwin 二进制带 Go 链接器默认的 ad-hoc 签名，在 Mac 上用
# `codesign -dv bin/build-agent` 核一次
(cd "$STAGE/builder-darwin-arm64" && sha256sum bin/build-agent bin/build-runner bin/ios-upload bin/rn-build-agent-upgrade)
