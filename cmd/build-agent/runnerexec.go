package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// sudoPath 是 sudo 的绝对路径。做成变量只为测试。
var sudoPath = "/usr/bin/sudo"

// runnerStopGrace 同时是两件事的时限（exec.Cmd.WaitDelay）：请执行进程停下（SIGTERM）之后
// 等它退出的时间，过了就 SIGKILL；执行进程退出之后等输出管道关闭的时间，过了就强制关掉。
// 经 sudo 时 SIGTERM 由 sudo 转发给执行进程；SIGKILL 只杀得到 sudo 本身。两种情况下留下的
// builder 进程都由随后的 cleanup 回收。
var runnerStopGrace = 20 * time.Second

// runnerCommand 构造启动执行进程的命令。执行进程的环境与控制进程无关：这里只给 sudo /
// 执行进程一个最小的环境（不含令牌），执行进程给子进程的环境来自任务说明里的白名单。
func (a *agent) runnerCommand(ctx context.Context, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if a.cfg.runnerSeparated() {
		full := append([]string{"-n", "-u", a.cfg.RunnerUser, "--", a.cfg.Runner}, args...)
		cmd = exec.CommandContext(ctx, sudoPath, full...)
	} else {
		cmd = exec.CommandContext(ctx, a.cfg.Runner, args...)
	}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if a.cfg.runnerSeparated() {
			// sudo 是 setuid 程序，真实 uid 是本用户，所以发得了信号；它把 SIGTERM 转给执行进程
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = runnerStopGrace
	return cmd
}

// runnerOutcome 是一次执行进程调用的结果。
type runnerOutcome struct {
	ExitCode int
	// Reason 是执行进程最后一行 "build-runner: error: " 之后的文字（不可信文本，已清洗）
	Reason string
}

// invokeRunner 启动执行进程，把它的输出按行收进日志，等它退出。
func (a *agent) invokeRunner(ctx context.Context, buf *logBuffer, args ...string) (runnerOutcome, error) {
	cmd := a.runnerCommand(ctx, args...)
	outcome := runnerOutcome{}
	lines := newLineWriter(buf, func(line string) {
		if reason, ok := strings.CutPrefix(line, "build-runner: error: "); ok {
			outcome.Reason = truncate(reason, 500)
		}
	})
	cmd.Stdout = lines
	cmd.Stderr = lines
	if err := cmd.Start(); err != nil {
		return runnerOutcome{}, fmt.Errorf("the build runner could not start: %w", err)
	}
	err := cmd.Wait()
	lines.Close()
	if errors.Is(err, exec.ErrWaitDelay) {
		// 执行进程已经成功退出，但它留下的进程还握着输出管道：管道已被强制关掉，进程由 cleanup 回收
		buf.add("build-runner exited but a process it left behind kept its output open; it will be reaped")
		return outcome, nil
	}
	if err == nil {
		return outcome, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		outcome.ExitCode = exit.ExitCode()
		if outcome.ExitCode < 0 {
			outcome.ExitCode = -1
		}
		return outcome, nil
	}
	return outcome, err
}

// runBuild 让执行进程构建这个任务。
func (a *agent) runBuild(ctx context.Context, prepared preparedJob, buf *logBuffer) error {
	outcome, err := a.invokeRunner(ctx, buf, "build",
		"--jobs-root", prepared.Layout.Root, "--job", prepared.Layout.JobID, "--kind", string(prepared.Spec.Kind))
	if err != nil {
		return err
	}
	if outcome.ExitCode == 0 {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if outcome.Reason != "" {
		return fmt.Errorf("the build runner failed: %s", outcome.Reason)
	}
	return fmt.Errorf("the build runner exited with status %d", outcome.ExitCode)
}

// cleanupJob 收掉一个任务目录：先让执行进程删掉它自己的文件并回收 builder 的残留进程，
// 再删控制进程自己的部分。执行进程删不干净时把剩下的留给下次启动时的清理，并打出来。
func (a *agent) cleanupJob(layout jobspec.Layout) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	buf := newLogBuffer(a.red)
	outcome, err := a.invokeRunner(ctx, buf, "cleanup", "--jobs-root", layout.Root, "--job", layout.JobID)
	if err != nil || outcome.ExitCode != 0 {
		a.log.Warn("the build runner could not empty a job directory", "job", layout.JobID,
			"exit", outcome.ExitCode, "reason", outcome.Reason, "error", err)
	}
	if err := removeControllerTree(layout.Dir()); err != nil {
		a.log.Error("a job directory could not be removed; it will be retried at the next start", "job", layout.JobID, "error", err)
	}
}

// removeControllerTree 删掉任务目录。执行进程的文件已经由它自己删掉；这里不跟随符号链接。
func removeControllerTree(path string) error {
	err := os.RemoveAll(path)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// checkRunner 在启动时确认执行进程能按配置跑起来：二进制不能被本用户改写（否则"分用户"
// 形同虚设），sudo 规则装好了，执行进程确实是另一个用户，任务根目录它进得去。
func (a *agent) checkRunner(ctx context.Context) error {
	info, err := os.Stat(a.cfg.Runner)
	if err != nil {
		return fmt.Errorf("BUILD_AGENT_RUNNER: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("BUILD_AGENT_RUNNER %s is not an executable file", a.cfg.Runner)
	}
	args := []string{"self-check", "--jobs-root", a.cfg.Workspace, "--protocol", strconv.Itoa(jobspec.SpecVersion)}
	if a.cfg.runnerSeparated() {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("BUILD_AGENT_RUNNER %s must belong to root and not be writable by group or others", a.cfg.Runner)
		}
		args = append(args, "--expect-separated")
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	buf := newLogBuffer(a.red)
	outcome, err := a.invokeRunner(checkCtx, buf, args...)
	if err != nil {
		return err
	}
	if outcome.ExitCode != 0 {
		detail := outcome.Reason
		if detail == "" {
			detail = strings.Join(buf.snapshot(), " | ")
		}
		return fmt.Errorf("the build runner self-check failed (exit %d): %s", outcome.ExitCode, truncate(detail, 500))
	}
	return nil
}
