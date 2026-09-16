#!/usr/bin/env bash
# 新机器安装脚本（草稿，正在实现）。
#   curl -fsSL <API>/v1/machine-setup/install.sh | sudo bash -s -- --server <API> --code <注册码> [--recovery-sha256 <指纹>]
set -euo pipefail
echo "install.sh: this build of the server ships a draft installer; install is not available yet" >&2
exit 1
