//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

func isTerminal(fd uintptr) bool {
	_, err := getTermios(fd)
	return err == nil
}

func getTermios(fd uintptr) (syscall.Termios, error) {
	var t syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&t))); errno != 0 {
		return t, errno
	}
	return t, nil
}

func setTermios(fd uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}
