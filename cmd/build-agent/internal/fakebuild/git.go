package fakebuild

import (
	"os"
	"os/exec"
)

func gitCommand(dir string, args ...string) *exec.Cmd {
	// 与控制进程一样关掉自动维护：fetch / commit 之后 detach 出去的 git maintenance 会在测试
	// 以为 git 已经结束之后继续往仓库里写
	full := append([]string{"-c", "maintenance.auto=false", "-c", "gc.auto=0"}, args...)
	cmd := exec.Command("git", full...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	return cmd
}
