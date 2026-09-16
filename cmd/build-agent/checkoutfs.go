package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// checkoutFS 往检出里写文件，**不跟随检出内容里的任何符号链接**。
//
// 检出内容来自仓库 main，对控制进程是不可信数据：main 上提交一个
// `ota-certificate.pem -> /var/lib/rn-build-agent/state/provenance-ed25519.key`，控制进程照常
// os.WriteFile 就会把出处私钥覆盖掉（评审 R1 复现过），目录链接同理能把文件写到状态目录里。
//
// 做法两层：os.Root 保证无论如何写不出检出目录；每一级路径用 Lstat 逐段核对是真实目录，
// 目标本身是符号链接或特殊文件就拒绝（判任务失败），是普通文件就删掉再以 O_EXCL 新建。
// 这时执行进程还没启动，检出只有控制进程在写，逐段核对没有竞争。
type checkoutFS struct {
	dir  string
	root *os.Root
}

func openCheckoutFS(dir string) (*checkoutFS, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &checkoutFS{dir: dir, root: root}, nil
}

func (c *checkoutFS) Close() error { return c.root.Close() }

// clean 把相对路径规范化，拒绝绝对路径、.. 与空路径。
func (c *checkoutFS) clean(rel string) (string, error) {
	cleaned := filepath.Clean(rel)
	if !filepath.IsLocal(cleaned) || cleaned == "." {
		return "", fmt.Errorf("refusing a path that leaves the checkout: %q", firstRunes(rel, 64))
	}
	return cleaned, nil
}

// mkdirAll 逐段建目录。已存在的每一段都必须是真实目录，符号链接一律拒绝。
func (c *checkoutFS) mkdirAll(rel string) error {
	cleaned, err := c.clean(rel)
	if err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := c.root.Lstat(current)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := c.root.Mkdir(current, 0o750); err != nil {
				return fmt.Errorf("cannot create %s in the checkout: %w", current, err)
			}
		case err != nil:
			return fmt.Errorf("cannot inspect %s in the checkout: %w", current, err)
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("the checkout has a symlink at %s; refusing to write through it", current)
		case !info.IsDir():
			return fmt.Errorf("the checkout has a non-directory at %s", current)
		}
	}
	return nil
}

// create 以 O_EXCL 新建一个文件。目标是普通文件就先删掉（仓库里可以有同名的旧文件，
// 例如 tenants/anyfun/tenant.json）；是符号链接、目录或特殊文件就拒绝。
func (c *checkoutFS) create(rel string) (*os.File, error) {
	cleaned, err := c.clean(rel)
	if err != nil {
		return nil, err
	}
	if parent := filepath.Dir(cleaned); parent != "." {
		if err := c.mkdirAll(parent); err != nil {
			return nil, err
		}
	}
	info, err := c.root.Lstat(cleaned)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("cannot inspect %s in the checkout: %w", cleaned, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("the checkout has a symlink at %s; refusing to write through it", cleaned)
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("the checkout has a non-regular file at %s", cleaned)
	default:
		if err := c.root.Remove(cleaned); err != nil {
			return nil, fmt.Errorf("cannot replace %s in the checkout: %w", cleaned, err)
		}
	}
	file, err := c.root.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, fmt.Errorf("cannot create %s in the checkout: %w", cleaned, err)
	}
	return file, nil
}

// writeFile 新建并写满一个文件；失败时删掉写了一半的文件。
func (c *checkoutFS) writeFile(rel string, content []byte) error {
	return c.writeFrom(rel, func(w io.Writer) error {
		_, err := w.Write(content)
		return err
	})
}

func (c *checkoutFS) writeFrom(rel string, fill func(io.Writer) error) error {
	file, err := c.create(rel)
	if err != nil {
		return err
	}
	fillErr := fill(file)
	closeErr := file.Close()
	if fillErr == nil {
		fillErr = closeErr
	}
	if fillErr != nil {
		_ = c.root.Remove(filepath.Clean(rel))
		return fillErr
	}
	return nil
}

// isRegularFile 判断路径逐段都不是符号链接、最后是普通文件。
func (c *checkoutFS) isRegularFile(rel string) bool {
	cleaned, err := c.clean(rel)
	if err != nil {
		return false
	}
	current := ""
	parts := strings.Split(cleaned, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := c.root.Lstat(current)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			return false
		}
		if i < len(parts)-1 && !info.IsDir() {
			return false
		}
		if i == len(parts)-1 {
			return info.Mode().IsRegular()
		}
	}
	return false
}

// writeNewFile 在一个控制进程自己建的目录里以 O_EXCL 写文件（spec.json）。
func writeNewFile(dir, name string, content []byte) error {
	fsys, err := openCheckoutFS(dir)
	if err != nil {
		return err
	}
	defer fsys.Close()
	file, err := fsys.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
