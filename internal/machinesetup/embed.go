// Package machinesetup 提供新机器的安装脚本。
//
// 服务端原样下发（go:embed）：
//
//	GET /v1/machine-setup/install.sh        Linux 的签名闸与构建机
//	GET /v1/machine-setup/install-macos.sh  Mac 打包机
//
// 运维在新机器本机以 root 执行它，脚本按注册码查出机器角色，下载并核对安装包，按角色
// 安装、注册、启动，打印下一步。
//
// 两份脚本的骨架与协议一样（describe → 下载核对安装包 → 安装 → enroll → 启动），
// 分开两份而不是加分支，是因为差的不是几个命令：用户怎么建、服务怎么常驻、退出码怎么
// 处理、要检查哪些前提，macOS 与 Linux 没有一条是一样的。
//
// 设计见 docs/design/android-signing-gate-automation-2026-09-16.md「2. 新机器」与
// docs/design/ios-mac-builders-home-network-2026-09-18.md §4.5。
package machinesetup

import _ "embed"

// InstallScript 是 install.sh 的内容（bash，Linux，root 执行）。
//
//go:embed install.sh
var InstallScript []byte

// InstallMacOSScript 是 install-macos.sh 的内容（bash，macOS，root 执行）。
//
//go:embed install-macos.sh
var InstallMacOSScript []byte
