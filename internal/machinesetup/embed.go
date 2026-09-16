// Package machinesetup 提供新机器的安装脚本。
//
// 服务端 GET /v1/machine-setup/install.sh 原样下发 InstallScript；运维在新机器本机以 root 执行
// `curl -fsSL <API>/v1/machine-setup/install.sh | sudo bash -s -- --server <API> --code <注册码>`。
// 脚本按注册码查出机器角色，下载并核对安装包，按角色安装、注册、启动，打印下一步。
//
// 设计见 docs/design/android-signing-gate-automation-2026-09-16.md「2. 新机器」。
package machinesetup

import _ "embed"

// InstallScript 是 install.sh 的内容（bash，root 执行）。
//
//go:embed install.sh
var InstallScript []byte
