//go:build darwin

package securefs

import "errors"

// CheckTmpfs：签名闸只在 Linux 上运行；其它平台一律拒绝。
func CheckTmpfs(path string) error {
	return errors.New(path + ": cannot verify tmpfs on this platform")
}
