package main

import (
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// pruneOrphans 清掉上一条命留下的任务目录与 spool 副本。
//
// 进程被硬杀时（OOM、断电、systemctl kill、机器重启）收尾那一步执行不到，任务目录会留在盘上，
// 里面执行进程的文件属于 builder，控制进程删不动——所以先请执行进程自己清空，再删控制进程的部分。
//
// 启动这一刻控制进程手上一个任务都没有，所以任务根目录下的东西**全都是**孤儿，不需要去问
// 服务端哪些还活着。前提是这个根目录只有这一个控制进程在用，而 BUILD_AGENT_WORKSPACE 本来就是每机一份。
func (a *agent) pruneOrphans() {
	_ = os.RemoveAll(filepath.Join(a.cfg.StateDir, spoolDirName))
	entries, err := os.ReadDir(a.cfg.Workspace)
	if err != nil {
		a.log.Warn("cannot look for leftover job directories", "jobsRoot", a.cfg.Workspace, "error", err)
		return
	}
	removed := 0
	for _, entry := range entries {
		path := filepath.Join(a.cfg.Workspace, entry.Name())
		if layout, err := jobspec.NewLayout(a.cfg.Workspace, entry.Name()); err == nil && entry.IsDir() {
			a.cleanupJob(layout)
		} else if err := removeControllerTree(path); err != nil {
			a.log.Error("cannot remove an unexpected entry in the jobs root", "path", path, "error", err)
			continue
		}
		if _, err := os.Lstat(path); err == nil {
			continue
		}
		removed++
		a.log.Warn("removed a job directory left behind by an earlier run", "path", path)
	}
	if removed > 0 {
		a.log.Info("cleaned up leftover job directories", "count", removed)
	}
}
