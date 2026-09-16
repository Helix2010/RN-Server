//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

// 其它平台不支持不回显读口令：恢复密钥相关子命令直接拒绝。
func openTTYPassphrase(*os.File) (passphraseSource, error) {
	return nil, errors.New("这个平台不支持从终端不回显地读口令；请在 Linux 或 macOS 的离线机器上运行")
}
