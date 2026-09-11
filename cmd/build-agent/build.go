package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// logBuffer 只留尾部若干行。完整日志留在构建机上，上报的是够定位失败的那一段。
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	red   *redactor
}

func newLogBuffer(red *redactor) *logBuffer {
	return &logBuffer{max: 200, red: red}
}

func (b *logBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, b.red.line(line))
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

// run 执行一条命令并把输出收进 logBuffer。用独立进程组，超时时杀整棵树——
// Gradle 会拉起一个常驻 daemon，只杀父进程会留下一个还在跑的构建。
func run(ctx context.Context, buf *logBuffer, dir string, env []string, name string, args ...string) error {
	buf.add("$ " + name + " " + strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s could not start: %w", name, err)
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		buf.add(scanner.Text())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type buildResult struct {
	CommitSHA    string
	ArtifactPath string
	SHA256       string
}

// buildJob 跑完一个任务的全部步骤。每一步失败都直接返回，调用方负责上报 fail
// 并清理 worktree。
func buildJob(ctx context.Context, cfg config, job claimedJob, buf *logBuffer) (buildResult, error) {
	var result buildResult
	if job.Platform != "android" {
		return result, fmt.Errorf("this agent only builds android, got %q", job.Platform)
	}
	if job.TenantDirectory == "" {
		return result, fmt.Errorf("the job does not say which tenants/ directory to build; set repoDirectory in this tenant's build configuration")
	}
	// 目录名会被拼进路径。服务端已经校验过，代理再挡一次——两端分属不同的信任域，
	// 各自把住自己那一侧是这类路径拼接的常规做法。
	if strings.ContainsAny(job.TenantDirectory, `/\`) || strings.Contains(job.TenantDirectory, "..") {
		return result, fmt.Errorf("refusing a tenant directory that escapes tenants/: %q", job.TenantDirectory)
	}
	worktree := filepath.Join(cfg.Workspace, job.ID)
	env := os.Environ()

	// 每个任务一个全新 worktree。共用检出会把别人未提交的改动混进产物。
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "fetch", "--all", "--prune"); err != nil {
		return result, err
	}
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "worktree", "add", "--detach", worktree, job.GitRef); err != nil {
		return result, err
	}
	commit, err := exec.CommandContext(ctx, "git", "-C", worktree, "rev-parse", "HEAD").Output()
	if err != nil {
		return result, fmt.Errorf("cannot resolve %s: %w", job.GitRef, err)
	}
	result.CommitSHA = strings.TrimSpace(string(commit))
	buf.add("commit " + result.CommitSHA)

	// 只许改 version 与 androidVersionCode；改到第三个字段就是在改产物身份
	tenantFile := filepath.Join(worktree, "tenants", job.TenantDirectory, "tenant.json")
	if err := applyBuildVersion(tenantFile, job.Version, job.BuildNumber); err != nil {
		return result, err
	}
	buf.add(fmt.Sprintf("tenant %s pinned to %s (%d)", job.TenantDirectory, job.Version, job.BuildNumber))

	// 证书随任务下发，代理不去猜该编哪一张
	if strings.TrimSpace(job.OTACertificatePEM) == "" {
		return result, fmt.Errorf("tenant %s has no OTA signing key; install one before building a package that must verify updates", job.TenantSlug)
	}
	certPath := filepath.Join(worktree, "ota-certificate.pem")
	if err := os.WriteFile(certPath, []byte(job.OTACertificatePEM), 0o644); err != nil {
		return result, err
	}
	env = append(env,
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=./ota-certificate.pem",
		"EXPO_REQUIRE_OTA_SIGNING=1",
		"EXPO_PUBLIC_TENANT="+job.TenantDirectory,
	)

	if err := run(ctx, buf, worktree, env, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return result, err
	}
	// 现成的产物身份门禁在这条命令里面：权限清单、applicationId、签名指纹、
	// Gradle 依赖校验。代理不复制其中任何一条，也不绕过它们。
	if err := run(ctx, buf, worktree, env, "pnpm", "android:release", job.TenantDirectory); err != nil {
		return result, err
	}

	artifact := filepath.Join(worktree, "artifacts",
		fmt.Sprintf("%s-%s-build%d-release.apk", job.TenantDirectory, job.Version, job.BuildNumber))
	if _, err := os.Stat(artifact); err != nil {
		return result, fmt.Errorf("the build reported success but %s is not there: %w", filepath.Base(artifact), err)
	}
	result.ArtifactPath = artifact
	if result.SHA256, err = fileSHA256(artifact); err != nil {
		return result, err
	}
	buf.add("artifact sha256 " + result.SHA256)
	return result, nil
}

func removeWorktree(cfg config, job claimedJob, buf *logBuffer) {
	worktree := filepath.Join(cfg.Workspace, job.ID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = run(ctx, buf, cfg.Workspace, os.Environ(), "git", "-C", cfg.Repo, "worktree", "remove", "--force", worktree)
	_ = os.RemoveAll(worktree)
}
