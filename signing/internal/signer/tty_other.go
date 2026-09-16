//go:build !linux

package signer

// isTerminal：签名闸只在 Linux 上运行，其它平台一律当作不是终端（运维命令拒绝执行）。
func isTerminal(uintptr) bool { return false }
