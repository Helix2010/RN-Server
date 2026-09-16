//go:build !linux

package signer

import (
	"errors"
	"net"
)

// checkPeerUID：签名闸只在 Linux 上运行，其它平台无法核对对端，一律拒绝。
func checkPeerUID(*net.UnixConn, int) error {
	return errors.New("cannot verify the checker socket's peer on this platform")
}
