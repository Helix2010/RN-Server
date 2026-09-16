//go:build linux || darwin

// Package securefs 是签名闸状态目录、运行时目录与本机私钥文件的文件系统操作。
//
// 真正的隔离边界是文件权限（同机的其它用户读不到），所以每次打开都核对：不是符号链接、
// 属主是当前有效用户、组与其它用户没有任何权限。写入一律 O_EXCL + fsync，目录项变化后
// 再 fsync 目录，崩溃后不会留下"看起来写了其实没落盘"的文件。
package securefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// CheckPrivateDir 要求 path 是当前用户所有、权限不含组与其它用户位的真实目录。
func CheckPrivateDir(path string) error {
	return checkPrivate(path, true)
}

// CheckPrivateFile 要求 path 是当前用户所有、权限不含组与其它用户位的普通文件。
func CheckPrivateFile(path string) error {
	return checkPrivate(path, false)
}

func checkPrivate(path string, dir bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s: path must be absolute", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mode := info.Mode()
	if mode&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: must not be a symbolic link", path)
	}
	if dir && !mode.IsDir() {
		return fmt.Errorf("%s: must be a directory", path)
	}
	if !dir && !mode.IsRegular() {
		return fmt.Errorf("%s: must be a regular file", path)
	}
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("%s: permissions %04o allow group or other access; expected %s", path, mode.Perm(), map[bool]string{true: "0700", false: "0600"}[dir])
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read the owner", path)
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not by the current user (uid %d)", path, stat.Uid, os.Geteuid())
	}
	return nil
}

// EnsurePrivateDir 创建（如不存在）并核对一个 0700 目录。父目录必须已经存在。
func EnsurePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return CheckPrivateDir(path)
}

// WriteFileExclusive 以 O_EXCL|0600 创建文件、写入、fsync 文件与所在目录。
func WriteFileExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// ReadPrivateFile 核对权限后读取，最多 limit 字节（超过报错）。
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	if err := CheckPrivateFile(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	buf := make([]byte, info.Size())
	if _, err := f.ReadAt(buf, 0); err != nil && info.Size() > 0 {
		return nil, err
	}
	return buf, nil
}

// SyncDir fsync 一个目录，让目录项（新建、改名、删除）落盘。
func SyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Lock 对打开的文件加 flock。exclusive=false 是共享锁。阻塞直到拿到锁。
func Lock(f *os.File, exclusive bool) error {
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		err := syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}

// TryLock 非阻塞地加独占锁；已被别人持有时返回 false。
func TryLock(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

// Unlock 释放 flock。
func Unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// CheckTrustedPath 要求签名闸要执行或加载的文件（java、apksigner.jar、signer-check）以及它
// 所在的每一级目录（按原路径与解析符号链接后的真实路径各查一遍）都只能由 root 或当前用户
// 修改：属主是 root 或当前有效用户，没有组与其它用户写权限（带粘滞位的目录如 /tmp 除外）。
//
// 这挡住"把 SIGNER_BUILD_TOOLS_DIR 指向构建机那份 Android SDK"这类配置：构建机用户能改的
// apksigner.jar 等于能在签名闸里执行任意代码。
func CheckTrustedPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s: path must be absolute", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for _, p := range []string{filepath.Clean(path), resolved} {
		for current := p; ; current = filepath.Dir(current) {
			if err := checkTrustedComponent(current, current == p); err != nil {
				return err
			}
			if current == "/" {
				break
			}
		}
	}
	return nil
}

func checkTrustedComponent(path string, leaf bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read the owner", path)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		// 符号链接本身的权限没有意义；它指向哪里由解析后的路径检查。只要求链接属主可信
		if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
			return fmt.Errorf("%s: symbolic link owned by uid %d, which could repoint it", path, stat.Uid)
		}
		return nil
	}
	if stat.Uid != 0 && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d; files the signing gate executes must be owned by root or by the signing gate user", path, stat.Uid)
	}
	perm := info.Mode().Perm()
	if perm&0o022 != 0 && !(info.IsDir() && info.Mode()&fs.ModeSticky != 0 && !leaf) {
		return fmt.Errorf("%s: permissions %04o let group or other users modify it", path, perm)
	}
	return nil
}

// MaxTrustedTreeEntries 是 CheckTrustedTree 最多检查的目录项数（一个 JDK 通常几百项）。
const MaxTrustedTreeEntries = 100_000

// CheckTrustedTree 对目录 root 做 CheckTrustedPath，并要求它下面的每个文件与子目录都只能由
// root 或当前用户修改；树里的符号链接按解析后的目标再做一次 CheckTrustedPath（可以指向树外，
// 例如发行版 JDK 指向 /etc 的配置）。
//
// 用于 JAVA_HOME：java 进程会加载树里的 lib/*.so、lib/modules、conf/security 等文件，
// 只查 bin/java 挡不住替换这些文件。
func CheckTrustedTree(root string) error {
	if err := CheckTrustedPath(root); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	entries := 0
	return filepath.WalkDir(resolved, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entries++; entries > MaxTrustedTreeEntries {
			return fmt.Errorf("%s: more than %d entries", root, MaxTrustedTreeEntries)
		}
		if err := checkTrustedComponent(path, !d.IsDir()); err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if err := CheckTrustedPath(path); err != nil {
				// 悬空链接不会被加载，不算问题
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
		}
		return nil
	})
}

// RemoveContents 删除目录里的全部内容（目录本身保留）。用于清空运行时目录。
func RemoveContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var first error
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil && first == nil {
			first = err
		}
	}
	return first
}
