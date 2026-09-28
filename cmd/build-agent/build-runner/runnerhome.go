package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

// 执行账户在密码数据库里的家目录（mac-01 上是 /var/rn-build-home）。
//
// Xcode 只认它、不认 $HOME（实施记录 2026-09-21「_rnbuilder 要有一个可写的家目录」），于是它成了执行账户
// 唯一能跨任务写的地方：RN-App 把**当前租户的**描述文件装进这里（build-ios-release.mjs 的 accountHomes），
// 不清的话下一个租户的构建也看得见，这次任务往里写的东西下次任务也会吃进去。每个任务开始前、结束后按
// 白名单清空，只留 Xcode 自己的缓存，免得每次重新索引。
//
// 只在生产形态（执行进程与控制进程是不同 uid）下动手，而且这个目录必须是执行账户自己的真实目录：
// 本地测试时密码数据库里的家目录就是开发者自己的家，绝不能碰。Linux 上执行账户的家是 /var/empty 之类
// 不属于它的目录，自然跳过。
var runnerHomeKeep = []string{"Library/Caches/com.apple.dt.Xcode"}

// pruneRunnerHome 清理执行账户的家目录；不该动（不是生产形态、不是它自己的目录）时什么都不做。
func pruneRunnerHome(out io.Writer, who identity) error {
	if !who.separated {
		return nil
	}
	account, err := user.Current()
	if err != nil {
		// 读不到密码数据库就没有"另一个家"可清：Xcode 也只能用 $HOME
		return nil
	}
	return pruneAccountHome(out, who, account.HomeDir)
}

func pruneAccountHome(out io.Writer, who identity, home string) error {
	home = filepath.Clean(home)
	if !filepath.IsAbs(home) || home == "/" || home == "/var/empty" {
		return nil
	}
	info, err := os.Lstat(home)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect the runner account's home %s: %w", home, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || int(st.Uid) != who.uid {
		// 不是执行账户自己的真实目录：不是我们该清的
		return nil
	}
	removed, err := pruneKeeping(home, "", runnerHomeKeep)
	if err != nil {
		return fmt.Errorf("cannot clean the runner account's home %s: %w", home, err)
	}
	if removed > 0 {
		logf(out, "cleaned the runner account's home %s (%d entries; kept %s)", home, removed, strings.Join(runnerHomeKeep, ", "))
	}
	return nil
}

// pruneKeeping 删掉 dir 下除 keep（相对于最初那一层的路径）以外的一切，返回删了几项。
// 符号链接只删链接本身，不跟进去。
func pruneKeeping(dir, rel string, keep []string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		entryRel := filepath.ToSlash(filepath.Join(rel, entry.Name()))
		kept, ancestor := false, false
		for _, k := range keep {
			if k == entryRel {
				kept = true
			} else if strings.HasPrefix(k, entryRel+"/") {
				ancestor = true
			}
		}
		if kept {
			continue
		}
		if ancestor && entry.Type()&os.ModeSymlink == 0 && entry.IsDir() {
			n, err := pruneKeeping(path, entryRel, keep)
			removed += n
			if err != nil {
				return removed, err
			}
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
