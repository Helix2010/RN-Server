//go:build linux

package securefs

import (
	"fmt"
	"syscall"
)

// tmpfsMagic 是 statfs(2) 里 tmpfs 的 f_type（linux/magic.h TMPFS_MAGIC）。
const tmpfsMagic = 0x01021994

// CheckTmpfs 要求 path 位于 tmpfs 上：明文 keystore 与口令文件只能写进不落盘的文件系统。
// 进程内存不被换出（systemd MemorySwapMax=0）之外，这是"明文不上磁盘"的另一半。
func CheckTmpfs(path string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return err
	}
	if int64(st.Type) != tmpfsMagic {
		return fmt.Errorf("%s: not on tmpfs (filesystem type 0x%x); the plaintext keystore must never reach a disk", path, st.Type)
	}
	return nil
}
