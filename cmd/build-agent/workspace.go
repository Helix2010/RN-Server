package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// pruneOrphanWorktrees 清掉上一条命留下的检出。
//
// 每个任务一份检出：workspace/<任务ID>/ 是源码，裸库里 worktrees/<任务ID>/ 是登记，
// 两边互相指（检出里的 .git 是个文件，写着登记的路径；登记里的 gitdir 写回检出）。
// 正常收尾时 removeWorktree 两边一起删。
//
// 但进程被硬杀时——OOM、断电、systemctl kill、机器重启——那一行根本执行不到，检出和
// 登记都会永远留在盘上。留下的不只是磁盘：那个目录里有本次构建解开的
// .build-keystore.jks。整套设计说的是"签名密钥只在构建期间以明文存在"，崩一次就不
// 再成立。
//
// 启动这一刻代理手上一个任务都没有，所以 workspace 下的东西**全都是**孤儿，不需要
// 去问服务端哪些还活着。前提是这个 workspace 只有这一个代理在用，而
// BUILD_AGENT_WORKSPACE 本来就是每机一份。
//
// 两件事都要做：只删目录，git worktree list 会一直列着一个指向不存在路径的条目；只
// prune，磁盘照占。
func pruneOrphanWorktrees(ctx context.Context, cfg config) {
	entries, err := os.ReadDir(cfg.Workspace)
	if err != nil {
		slog.Warn("cannot look for leftover build worktrees", "workspace", cfg.Workspace, "error", err)
		return
	}
	buf := newLogBuffer(newRedactor())
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(cfg.Workspace, entry.Name())
		gitCtx, cancel := context.WithTimeout(ctx, time.Minute)
		_ = run(gitCtx, buf, cfg.Workspace, os.Environ(), "git", "-C", cfg.Repo, "worktree", "remove", "--force", path)
		cancel()
		if err := os.RemoveAll(path); err != nil {
			slog.Error("cannot remove a leftover build worktree", "path", path, "error", err)
			continue
		}
		removed++
		// 提到 keystore 是有意的：看到这条日志的人应该知道刚才盘上躺着什么
		slog.Warn("removed a build worktree left behind by an earlier run; it may have held an unsealed keystore",
			"path", path)
	}
	gitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	_ = run(gitCtx, buf, cfg.Workspace, os.Environ(), "git", "-C", cfg.Repo, "worktree", "prune")
	if removed > 0 {
		slog.Info("cleaned up leftover build worktrees", "count", removed)
	}
}
