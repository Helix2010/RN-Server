#!/usr/bin/env bash
# 构建新机器的安装包：
#   deploy/setup/build-bundles.sh <输出目录>
#
# 产出（约定：签名闸自动化「6. 安装脚本与安装包」）：
#   signer.tar.gz    bin/signer、bin/signer-check、templates/（unit 与 env 模板，@INSTANCE@ 占位）、README.md、install.sh
#   builder.tar.gz   bin/build-agent、bin/build-runner、rn-build-agent.service、rn-build-agent.sudoers、
#                    rn-build-agent.env.example、README.md
#   manifest.json    {"format":"rn-machine-bundles/v1","commit",
#                     "bundles":{"signer":{"archive","archiveSha256","archiveSize","files":[{"name","size","sha256"}]},"builder":{…}}}
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
install -d "$STAGE/signer/bin" "$STAGE/signer/templates" "$STAGE/builder/bin"

export GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0
(cd "$ROOT" && go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder/bin/build-agent" ./cmd/build-agent)
(cd "$ROOT" && go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$STAGE/builder/bin/build-runner" ./cmd/build-agent/build-runner)
# 与 deploy/signer/README.md「构建」同一组参数
(cd "$ROOT/signing" && go build -trimpath -buildvcs=false -o "$STAGE/signer/bin/" ./cmd/signer ./cmd/signer-check)

cp "$TEMPLATES"/*@INSTANCE@* "$STAGE/signer/templates/"
cp "$ROOT/deploy/signer/README.md" "$STAGE/signer/README.md"
cp "$ROOT/internal/machinesetup/install.sh" "$STAGE/signer/install.sh"
cp "$ROOT/deploy/build-agent/rn-build-agent.service" "$ROOT/deploy/build-agent/rn-build-agent.sudoers" \
  "$ROOT/deploy/build-agent/rn-build-agent.env.example" "$ROOT/deploy/build-agent/README.md" "$STAGE/builder/"

for role in signer builder; do
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" --mode='u+rwX,go+rX,go-w' \
    -C "$STAGE/$role" -cf - . | gzip -n -9 >"$OUT/$role.tar.gz.part"
  mv -f "$OUT/$role.tar.gz.part" "$OUT/$role.tar.gz"
done

python3 - "$STAGE" "$OUT" "$COMMIT" <<'PY'
import hashlib, json, os, sys

stage, out, commit = sys.argv[1:4]

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

bundles = {}
for role in ("signer", "builder"):
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
(cd "$OUT" && sha256sum signer.tar.gz builder.tar.gz)
(cd "$STAGE/signer" && sha256sum install.sh bin/signer bin/signer-check)
(cd "$STAGE/builder" && sha256sum bin/build-agent bin/build-runner)
