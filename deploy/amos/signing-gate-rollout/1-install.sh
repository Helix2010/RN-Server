#!/usr/bin/env bash
# 【已被取代，请勿再用】新机器用服务端下发的 internal/machinesetup/install.sh（安装包由 deploy/setup/build-bundles.sh
# 构建），手册见 deploy/amos/SIGNING_GATE_ROLLOUT.md。这个脚本只记录 amos 2026-09-16 首次手工上线做过什么。
#
# 【安全提醒】这里的构建机迁移做法已过时，**不要再用它做 amos 的升级迁移**：它保留了 builder 写过的仓库镜像
# 与 ~/.ssh（只 chown、不重建），而控制进程 git fetch 会读镜像本地配置、ssh 会读 ~/.ssh/config——builder 曾能写它们。
# 升级到会校验镜像的新构建机二进制时，按 SIGNING_GATE_ROLLOUT.md 第 5.1 节「重建构建机仓库镜像与 ~/.ssh、装固定
# known_hosts」重建（旧镜像与旧 ~/.ssh 整棵移进留存目录、以 rn-build-agent 重新克隆、known_hosts 用固定主机公钥重写）。
# 签名闸上线 · 第 1 步（amos，root，不涉及任何令牌）：迁移构建机到两个用户、安装签名闸与 CI 收口脚本。
#   sudo bash 1-install.sh <部署包目录>      部署包由 0-bundle.sh 在开发机上生成后 scp 过来
# 可重复执行。旧构建机的配置、二进制、agent-key 留存在 /root/rn-build-agent-legacy-<日期>/，回滚用。
set -euo pipefail
B="$(cd "${1:?用法: 1-install.sh <部署包目录>}" && pwd)"
L=/root/rn-build-agent-legacy-$(date -u +%Y-%m-%d)

echo "== 核对二进制"
(cd "$B" && sha256sum -c SHA256SUMS)

echo "== 停旧构建机"
systemctl stop rn-build-agent
pkill -KILL -u builder || true
sleep 2

echo "== 留存旧配置、旧二进制、旧密钥（root 独读，新链路稳定后按清理步骤销毁）"
install -d -o root -g root -m 0700 "$L"
[ -e "$L/rn-build-agent.env" ] || cp -a /etc/rn-build-agent.env "$L/rn-build-agent.env"
[ -e "$L/rn-build-agent.service" ] || cp -a /etc/systemd/system/rn-build-agent.service "$L/rn-build-agent.service"
[ -e "$L/build-agent.previous" ] || cp -a /opt/rn-build-agent/build-agent "$L/build-agent.previous"
for f in agent-key backup-signing.key .gitconfig; do
  if [ -e "/var/lib/rn-build-agent/$f" ]; then mv "/var/lib/rn-build-agent/$f" "$L/"; fi
done

echo "== 用户与组"
getent group rn-build-jobs >/dev/null || groupadd --system rn-build-jobs
id rn-build-agent >/dev/null 2>&1 || useradd --system --home-dir /var/lib/rn-build-agent --no-create-home \
  --shell /usr/sbin/nologin --user-group --groups rn-build-jobs rn-build-agent
usermod -d /nonexistent -s /usr/sbin/nologin -aG rn-build-jobs builder
for f in /etc/cron.deny /etc/at.deny; do touch "$f"; grep -qx builder "$f" || echo builder >> "$f"; done

echo "== 清掉 builder 写过的缓存与工作区（按被下毒处理）"
rm -rf /var/lib/rn-build-agent/.android /var/lib/rn-build-agent/.cache /var/lib/rn-build-agent/.expo \
  /var/lib/rn-build-agent/.kotlin /var/lib/rn-build-agent/.local /var/lib/rn-build-agent/.npm \
  /var/lib/rn-build-agent/workspace /var/cache/rn-build-agent/gradle /var/cache/rn-build-agent/pnpm-store
find /tmp /var/tmp /dev/shm -maxdepth 1 -user builder -exec rm -rf {} + 2>/dev/null || true

echo "== 目录"
chown -R rn-build-agent:rn-build-agent /var/lib/rn-build-agent
chmod 0700 /var/lib/rn-build-agent /var/lib/rn-build-agent/.ssh
install -d -o rn-build-agent -g rn-build-agent -m 0700 /var/lib/rn-build-agent/state /var/lib/rn-build-agent/repos
chmod 0700 /var/lib/rn-build-agent/repos/rn-app.git
install -d -o rn-build-agent -g rn-build-jobs -m 2750 /var/lib/rn-build-jobs

echo "== 构建机二进制、sudoers、unit"
install -o root -g root -m 0755 "$B/build-agent" "$B/build-runner" /opt/rn-build-agent/
visudo -cf "$B/build-agent-deploy/rn-build-agent.sudoers"
install -o root -g root -m 0440 "$B/build-agent-deploy/rn-build-agent.sudoers" /etc/sudoers.d/rn-build-agent
install -o root -g root -m 0644 "$B/build-agent-deploy/rn-build-agent.service" /etc/systemd/system/rn-build-agent.service

echo "== 签名闸用户、程序、apksigner 副本、unit"
for s in a b; do
  id "rn-signer-$s" >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin --user-group "rn-signer-$s"
done
install -d -o root -g root -m 0755 /opt/rn-signer /opt/rn-signer/bin /opt/rn-signer/build-tools \
  /opt/rn-signer/build-tools/35.0.0 /opt/rn-signer/build-tools/35.0.0/lib
install -o root -g root -m 0755 "$B/signer" "$B/signer-check" /opt/rn-signer/bin/
install -o root -g root -m 0644 /opt/android-sdk/build-tools/35.0.0/lib/apksigner.jar \
  /opt/rn-signer/build-tools/35.0.0/lib/apksigner.jar
install -o root -g root -m 0644 "$B/signer-deploy/README.md" /opt/rn-signer/README.md
cd "$B/signer-deploy"
install -o root -g root -m 0644 rn-signer-a.service rn-signer-b.service rn-signer-a-check.socket \
  rn-signer-b-check.socket 'rn-signer-a-check@.service' 'rn-signer-b-check@.service' /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/rn-signer-a.service /etc/systemd/system/rn-signer-b.service \
  /etc/systemd/system/rn-signer-a-check.socket /etc/systemd/system/rn-signer-b-check.socket \
  /etc/systemd/system/rn-build-agent.service 2>&1 || true

echo "== CI 部署用的收口脚本与 sudoers（等同 setup-ci-deploy.sh 里的这两步）"
install -m 0755 -o root -g root "$B/rn-foundation-apply" /usr/local/sbin/rn-foundation-apply
install -m 0440 -o root -g root "$B/rn-foundation-deploy.sudoers" /etc/sudoers.d/rn-foundation-deploy.tmp
if visudo -c -f /etc/sudoers.d/rn-foundation-deploy.tmp >/dev/null; then
  mv /etc/sudoers.d/rn-foundation-deploy.tmp /etc/sudoers.d/rn-foundation-deploy
else
  rm -f /etc/sudoers.d/rn-foundation-deploy.tmp; echo "rn-foundation-deploy sudoers 语法没过，未安装" >&2; exit 1
fi

echo "== sha256 与冒烟"
sha256sum /opt/rn-build-agent/build-agent /opt/rn-build-agent/build-runner /opt/rn-signer/bin/signer \
  /opt/rn-signer/bin/signer-check /opt/rn-signer/build-tools/35.0.0/lib/apksigner.jar /usr/local/sbin/rn-foundation-apply
# 这两个命令按设计以非 0 退出，不能让 set -e 把它们当成脚本失败
code=0; env -i /opt/rn-build-agent/build-agent >/dev/null 2>&1 || code=$?
echo "build-agent 空环境 exit=$code (应为 2)"
code=0; /opt/rn-build-agent/build-runner >/dev/null 2>&1 || code=$?
echo "build-runner 无参数 exit=$code (应为 2)"
id rn-build-agent; id builder; id rn-signer-a; id rn-signer-b
echo "第 1 步完成。下一步：控制台新建机器，然后 sudo bash 2-configure.sh"
