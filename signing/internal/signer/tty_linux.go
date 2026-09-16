//go:build linux

package signer

import (
	"syscall"
	"unsafe"
)

// isTerminal 用 TCGETS 判断 fd 是不是终端。/dev/null 也是字符设备，只看文件类型不够。
func isTerminal(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&termios)))
	return errno == 0
}
