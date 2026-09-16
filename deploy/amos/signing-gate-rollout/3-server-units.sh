#!/usr/bin/env bash
# 【已被取代】新机器用服务端下发的 internal/machinesetup/install.sh（安装包由 deploy/setup/build-bundles.sh 构建），
# 手册见 deploy/amos/SIGNING_GATE_ROLLOUT.md。这个脚本只为 amos 的首次手工上线保留，amos 迁移完成后删除，不要再用于新机器。
# 签名闸上线 · 第 3 步（amos，root）：换上服务端、扫链、迁移三个 unit（去掉备份用的 LoadCredential，
# 加上挡签名闸路径的 InaccessiblePaths）并重启服务端与扫链。
# 必须在签名闸启动之后跑：/run 下的签名闸目录与 socket 只有在服务启动时已经存在才会被遮住。
#   sudo bash 3-server-units.sh <部署包目录>
set -euo pipefail
B="$(cd "${1:?用法: 3-server-units.sh <部署包目录>}" && pwd)"
for s in rn-signer-a-check.sock rn-signer-b-check.sock; do
  [ -S "/run/$s" ] || { echo "/run/$s 不存在：先完成第 2 步（签名闸启动）" >&2; exit 1; }
done
L=/root/rn-foundation-units-previous-$(date -u +%Y-%m-%d)
install -d -m 0700 "$L"
for u in rn-foundation-server rn-foundation-indexer rn-foundation-migrate; do
  [ -e "$L/$u.service" ] || cp -a "/etc/systemd/system/$u.service" "$L/"
  install -o root -g root -m 0644 "$B/$u.service" "/etc/systemd/system/$u.service"
done
systemd-analyze verify /etc/systemd/system/rn-foundation-server.service /etc/systemd/system/rn-foundation-indexer.service \
  /etc/systemd/system/rn-foundation-migrate.service 2>&1 || true
systemctl daemon-reload
systemctl restart rn-foundation-server
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13080/health/ready || true)"
  [ "$code" = 200 ] && break; sleep 1
done
[ "$code" = 200 ] || { echo "服务端 30 秒内没有就绪（最后状态码 $code），旧 unit 在 $L" >&2; exit 1; }
systemctl restart rn-foundation-indexer
systemctl is-active rn-foundation-server rn-foundation-indexer
echo "第 3 步完成：服务端已按新 unit 运行（旧 unit 留存在 $L）。"
