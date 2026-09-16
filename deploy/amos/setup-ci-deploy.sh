#!/usr/bin/env bash
# 在 amos 上开一个只能部署、别的什么都干不了的账号，给 GitHub Actions 用。跑一次。
#
#   ./setup-ci-deploy.sh <这台机器对外的地址> <SSH 端口>
#
# 为什么不直接把 ubuntu 的密钥丢给 CI：ubuntu 是 NOPASSWD: ALL，等于把这台机器的
# root 交给 GitHub，而签名闸开发阶段也在这台机器上。
#
# 这个账号只能跑 /usr/local/sbin/rn-foundation-apply，换上去的程序以 rnfoundation /
# builder 身份运行而不是 root，脚本自己也不以 root 执行 CI 传来的二进制。但 CI 密钥
# 被偷不只是"发了一版坏代码"：坏代码以那两个身份跑，读得到各自进程的配置与状态。
# 签名闸同机期间打包机那一路必须关着，见 README.md。
set -euo pipefail

cd "$(dirname "$0")"
HOST="${1:-}"
PORT="${2:-22}"
USER_NAME=rndeploy
HOME_DIR=/var/lib/rn-foundation-deploy
KEY="$HOME_DIR/.ssh/ci_ed25519"

if [ -z "$HOST" ]; then
  echo "用法: $0 <这台机器对外的地址> [SSH 端口]" >&2
  exit 2
fi
for f in rn-foundation-apply rn-foundation-deploy.sudoers; do
  [ -f "$f" ] || { echo "缺少 $f" >&2; exit 1; }
done

echo "== 账号 =="
# 要能执行命令，所以给 shell；但不建普通家目录，家就是暂存目录本身
if id "$USER_NAME" >/dev/null 2>&1; then
  echo "   $USER_NAME 已存在"
else
  sudo useradd --system --create-home --home-dir "$HOME_DIR" \
    --shell /bin/bash "$USER_NAME"
  echo "   已创建 $USER_NAME"
fi
sudo mkdir -p "$HOME_DIR/incoming/admin" "$HOME_DIR/.ssh"
sudo chown -R "$USER_NAME:$USER_NAME" "$HOME_DIR/incoming"
sudo chmod 0700 "$HOME_DIR/.ssh"
sudo chown "$USER_NAME:$USER_NAME" "$HOME_DIR" "$HOME_DIR/.ssh"

echo "== 特权收口脚本 =="
sudo install -m 0755 -o root -g root rn-foundation-apply /usr/local/sbin/rn-foundation-apply
# sudoers 语法错了会让整台机器的 sudo 失效，装之前先验一遍
sudo install -m 0440 -o root -g root rn-foundation-deploy.sudoers /etc/sudoers.d/rn-foundation-deploy.tmp
if sudo visudo -c -f /etc/sudoers.d/rn-foundation-deploy.tmp >/dev/null; then
  sudo mv /etc/sudoers.d/rn-foundation-deploy.tmp /etc/sudoers.d/rn-foundation-deploy
  echo "   /etc/sudoers.d/rn-foundation-deploy 已就位"
else
  sudo rm -f /etc/sudoers.d/rn-foundation-deploy.tmp
  echo "   sudoers 语法检查没过，未安装" >&2
  exit 1
fi

echo "== CI 密钥 =="
if sudo test -f "$KEY"; then
  echo "   已存在，保持不变（要换就先删掉 $KEY 再跑）"
else
  sudo ssh-keygen -t ed25519 -N '' -C "github-actions@rn-foundation" -f "$KEY" >/dev/null
  echo "   已生成"
fi
# 公钥进 authorized_keys，顺手关掉这个账号用不上的转发能力
sudo bash -c "printf 'no-agent-forwarding,no-port-forwarding,no-X11-forwarding %s\n' \
  \"\$(cat '$KEY.pub')\" > '$HOME_DIR/.ssh/authorized_keys'"
sudo chown "$USER_NAME:$USER_NAME" "$HOME_DIR/.ssh/authorized_keys"
sudo chmod 0600 "$HOME_DIR/.ssh/authorized_keys"

echo
echo "== 填进 GitHub 的东西 =="
echo
echo "两个仓库（RN-Server、RN-Admin）都要设，Settings → Secrets and variables → Actions："
echo
echo "  AMOS_HOST         = $HOST"
echo "  AMOS_PORT         = $PORT"
echo "  AMOS_KNOWN_HOSTS  = 下面这一行"
printf '      '
if [ "$PORT" = "22" ]; then
  sudo awk -v h="$HOST" '{print h, $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub
else
  sudo awk -v h="[$HOST]:$PORT" '{print h, $1, $2}' /etc/ssh/ssh_host_ed25519_key.pub
fi
echo "  AMOS_SSH_KEY      = 私钥全文，取法见下"
echo
echo "  变量（Variables 标签页，不是 Secrets）：AMOS_DEPLOY_ENABLED = true"
echo
cat <<NEXT
私钥怎么拿：在**你自己的终端**里执行

  sudo cat $KEY

把输出整段贴进 AMOS_SSH_KEY。注意两件事：

  - 别用会话里的 ! 前缀跑这条命令，那会把私钥写进对话记录
  - 两个仓库贴的是同一把私钥，贴完不用删机器上这份（authorized_keys 认的是它）

设完之后在任一仓库 Actions 页手动触发一次 workflow_dispatch 验证。
NEXT
