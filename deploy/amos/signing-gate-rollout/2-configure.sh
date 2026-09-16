#!/usr/bin/env bash
# 【已被取代】新机器用服务端下发的 internal/machinesetup/install.sh（安装包由 deploy/setup/build-bundles.sh 构建），
# 手册见 deploy/amos/SIGNING_GATE_ROLLOUT.md。这个脚本只为 amos 的首次手工上线保留，amos 迁移完成后删除，不要再用于新机器。
# 签名闸上线 · 第 2 步（amos，root，**在你自己的终端里跑**，不要经过会把输出送进对话记录的通道）
#   sudo bash 2-configure.sh                 逐个提示粘贴令牌
# 前提：控制台「平台维护 → 打包机与签名闸」已新建 amos-builder（构建机）、amos-signer-a（签名闸，主）、
# amos-signer-b（签名闸，备）三台机器，令牌各显示了一次。
# 本脚本逐个提示输入三台机器的令牌（不回显、不进命令行参数），写好三份 env，启动服务，
# 最后打印三台机器的公钥与完整指纹（公开信息），供 pin 文件与控制台接受公钥核对。
set -euo pipefail
JAVA_HOME_DIR=/usr/lib/jvm/java-17-openjdk-amd64

# 用法二：sudo bash 2-configure.sh <令牌目录>——目录里是 amos-builder、amos-signer-a、amos-signer-b 三个文件，
# 各含一台机器的令牌（root 0600，由主机到主机的管道写入，不经过屏幕）。读完即删。
TOKEN_DIR="${1:-}"
if [ -n "$TOKEN_DIR" ]; then
  [ "$(stat -c '%U %a' "$TOKEN_DIR")" = "root 700" ] || { echo "$TOKEN_DIR 必须是 root 0700" >&2; exit 1; }
fi

read_token() {
  local name="$1" var
  if [ -n "$TOKEN_DIR" ]; then
    [ "$(stat -c '%U %a' "$TOKEN_DIR/$name")" = "root 600" ] || { echo "$TOKEN_DIR/$name 必须是 root 0600" >&2; exit 1; }
    var="$(cat "$TOKEN_DIR/$name")"
  else
    read -rsp "$name 的机器令牌（输入不回显）: " var; echo >&2
  fi
  case "$var" in rnm_*) ;; *) echo "$name：令牌格式不对（应以 rnm_ 开头）" >&2; exit 1 ;; esac
  printf '%s' "$var"
}

write_env() { # $1 文件 $2 属组 $3 模式；内容从 stdin 读，先写临时文件再原子替换
  local tmp; tmp="$(mktemp "$1.XXXXXX")"
  cat > "$tmp"
  chown "root:$2" "$tmp"; chmod "$3" "$tmp"; mv "$tmp" "$1"
}

BUILDER_TOKEN="$(read_token amos-builder)"
SIGNER_A_TOKEN="$(read_token amos-signer-a)"
SIGNER_B_TOKEN="$(read_token amos-signer-b)"

echo "== 构建机 env（/etc/rn-build-agent.env，root 0600）"
write_env /etc/rn-build-agent.env root 0600 <<ENV
BUILD_AGENT_SERVER=https://api.anyfun.win
BUILD_AGENT_MACHINE_TOKEN="$BUILDER_TOKEN"
BUILD_AGENT_REPO=/var/lib/rn-build-agent/repos/rn-app.git
BUILD_AGENT_WORKSPACE=/var/lib/rn-build-jobs
BUILD_AGENT_STATE_DIR=/var/lib/rn-build-agent/state
BUILD_AGENT_PLATFORMS=android
BUILD_AGENT_TIMEOUT_MINUTES=45
BUILD_AGENT_RUNNER=/opt/rn-build-agent/build-runner
BUILD_AGENT_RUNNER_USER=builder
LANG=C.UTF-8
ANDROID_HOME=/opt/android-sdk
ANDROID_SDK_ROOT=/opt/android-sdk
JAVA_HOME=$JAVA_HOME_DIR
ENV

for s in a b; do
  if [ "$s" = a ]; then TOKEN="$SIGNER_A_TOKEN"; else TOKEN="$SIGNER_B_TOKEN"; fi
  echo "== 签名闸 $s env（/etc/rn-signer-$s.env，root:rn-signer-$s 0640）"
  write_env "/etc/rn-signer-$s.env" "rn-signer-$s" 0640 <<ENV
SIGNER_SERVER_URL="http://127.0.0.1:13080"
SIGNER_MACHINE_TOKEN="$TOKEN"
SIGNER_NAME="amos-signer-$s"
SIGNER_STATE_DIR="/var/lib/rn-signer-$s"
SIGNER_RUNTIME_DIR="/run/rn-signer-$s"
SIGNER_JAVA_HOME="$JAVA_HOME_DIR"
SIGNER_BUILD_TOOLS_DIR="/opt/rn-signer/build-tools/35.0.0"
SIGNER_CHECK_SOCKET="/run/rn-signer-$s-check.sock"
SIGNER_MAX_VERSION_CODE_JUMP="100"
SIGNER_MAX_VERSION_CODE="10000000"
ENV
done
unset BUILDER_TOKEN SIGNER_A_TOKEN SIGNER_B_TOKEN TOKEN
if [ -n "$TOKEN_DIR" ]; then
  shred -u "$TOKEN_DIR/amos-builder" "$TOKEN_DIR/amos-signer-a" "$TOKEN_DIR/amos-signer-b"
  rmdir "$TOKEN_DIR"
fi

echo "== 启动"
systemctl daemon-reload
systemctl enable --now rn-signer-a-check.socket rn-signer-a.service
systemctl enable --now rn-signer-b-check.socket rn-signer-b.service
systemctl enable rn-build-agent
systemctl restart rn-build-agent
sleep 10
systemctl --no-pager --lines=0 status rn-signer-a rn-signer-b rn-build-agent || true

echo
echo "== 三台机器的公钥与完整指纹（公开信息；抄进离线 pin 文件、在控制台接受公钥时逐位核对）"
sudo -u rn-signer-a /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-a.env
sudo -u rn-signer-b /opt/rn-signer/bin/signer show-key --env-file /etc/rn-signer-b.env
sudo -u rn-build-agent /opt/rn-build-agent/build-agent show-key --state-dir /var/lib/rn-build-agent/state
echo
echo "第 2 步完成。下一步见 SIGNING_GATE_ROLLOUT.md 第 6 步：控制台接受公钥、promote、trust-builder。"
