//go:build linux

package signer

import (
	"fmt"
	"net"
	"syscall"
)

// checkPeerUID 用 SO_PEERCRED 核对 unix socket 对端的 uid。对连接方来说，对端凭据是
// 调用 listen(2) 的进程的：socket 激活时是 systemd（uid 0）。
func checkPeerUID(conn *net.UnixConn, want int) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return fmt.Errorf("read the checker socket's peer credentials: %w", credErr)
	}
	if int(cred.Uid) != want {
		return fmt.Errorf("the checker socket is served by uid %d, expected uid %d (systemd socket activation); refusing to send the package to it", cred.Uid, want)
	}
	return nil
}
