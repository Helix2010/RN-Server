#!/usr/bin/env bash
# 【已被取代】新机器用服务端下发的 internal/machinesetup/install.sh（安装包由 deploy/setup/build-bundles.sh 构建），
# 手册见 deploy/amos/SIGNING_GATE_ROLLOUT.md。这个脚本只为 amos 的首次手工上线保留，amos 迁移完成后删除，不要再用于新机器。
# 签名闸上线 · 第 0 步（开发机）：从当前提交构建部署包。
#   deploy/amos/signing-gate-rollout/0-bundle.sh <输出目录>
# 输出目录里是 build-agent、build-runner、signer、signer-check 与部署文件，外加 SHA256SUMS 与 COMMIT。
# 二进制 sha256 抄进离线记录；上线后在 amos 上 sha256sum -c 核对。
set -euo pipefail
OUT="${1:?用法: 0-bundle.sh <输出目录>}"
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
test -z "$(git -C "$ROOT" status --porcelain)" || { echo "工作区不干净，拒绝打包" >&2; exit 1; }
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT"
git rev-parse HEAD > "$OUT/COMMIT"
export GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 CGO_ENABLED=0
go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$OUT/build-agent" ./cmd/build-agent
go build -trimpath -buildvcs=false -ldflags="-s -w" -o "$OUT/build-runner" ./cmd/build-agent/build-runner
(cd signing && go build -trimpath -buildvcs=false -o "$OUT/" ./cmd/signer ./cmd/signer-check)
rm -rf "$OUT/signer-deploy" "$OUT/build-agent-deploy" "$OUT/rollout"
cp -r deploy/signer "$OUT/signer-deploy"
cp -r deploy/build-agent "$OUT/build-agent-deploy"
cp -r deploy/amos/signing-gate-rollout "$OUT/rollout"
cp deploy/amos/rn-foundation-apply deploy/amos/rn-foundation-deploy.sudoers \
  deploy/amos/rn-foundation-server.service deploy/amos/rn-foundation-indexer.service \
  deploy/amos/rn-foundation-migrate.service "$OUT/"
(cd "$OUT" && sha256sum build-agent build-runner signer signer-check > SHA256SUMS && cat SHA256SUMS)
code=0; env -i "$OUT/build-agent" >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || { echo "build-agent 空环境退出码 $code，应为 2" >&2; exit 1; }
echo "部署包：$OUT（提交 $(cat "$OUT/COMMIT")）"
