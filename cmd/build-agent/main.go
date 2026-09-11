// build-agent 是打包机上的常驻进程。
//
// 它**必须**和 wallet 后端部署在不同的机器上：这台机器持有 Android keystore，而
// 整套设计的安全论证（服务端不下发密钥、不执行命令）在两者同机的那一刻就作废了
// ——后端的一个 RCE 直接读到磁盘上的密钥。
//
// 它只出不进：轮询服务端要任务，服务端从不连它。这台机器因此可以不开放任何入站
// 端口。反过来做就要在握着签名密钥的机器上开一个监听端口，那个端口的每一个 bug
// 都直接通向 keystore。
//
// 设计见 docs/design/build-service-2026-09-11.md 阶段 2b。
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("build agent configuration is incomplete", "error", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(cfg.Workspace, 0o750); err != nil {
		slog.Error("cannot create the workspace", "path", cfg.Workspace, "error", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("build agent started", "server", cfg.Server, "agent", cfg.Name,
		"platforms", cfg.Platforms, "workspace", cfg.Workspace)
	api := newClient(cfg)
	for {
		worked := pollOnce(ctx, cfg, api)
		if ctx.Err() != nil {
			slog.Info("build agent stopped")
			return
		}
		if worked {
			// 刚做完一个，队列里可能还有，不必等满一轮
			continue
		}
		select {
		case <-ctx.Done():
			slog.Info("build agent stopped")
			return
		case <-time.After(cfg.PollEvery):
		}
	}
}

// pollOnce 领一个任务并把它做完，返回是否真的做了事。任何失败都上报给服务端——
// 悄悄失败会让管理端上的任务永远停在 running，而没人知道该去哪台机器上看。
func pollOnce(ctx context.Context, cfg config, api *client) bool {
	job, ok, err := api.claim(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("cannot claim a build", "error", err)
		}
		return false
	}
	if !ok {
		return false
	}
	slog.Info("claimed a build", "job", job.ID, "tenant", job.TenantSlug,
		"version", job.Version, "buildNumber", job.BuildNumber, "gitRef", job.GitRef)

	red := newRedactor()
	buf := newLogBuffer(red)
	buildCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	beats := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-beats:
				return
			case <-ticker.C:
				if err := api.heartbeat(context.WithoutCancel(buildCtx), job.ID, buf.snapshot()); err != nil {
					slog.Warn("heartbeat failed", "job", job.ID, "error", err)
				}
			}
		}
	}()

	result, buildErr := buildJob(buildCtx, cfg, job, buf)
	close(beats)
	removeWorktree(cfg, job, buf)

	// 上报用一个不受构建超时影响的 context：构建因为超时被杀掉时，正是最需要
	// 把失败原因送回去的时候。
	reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer reportCancel()
	if buildErr != nil {
		reason := red.line(buildErr.Error())
		if buildCtx.Err() == context.DeadlineExceeded {
			reason = "build timed out after " + cfg.Timeout.String()
		}
		slog.Error("build failed", "job", job.ID, "reason", reason)
		// 带上已经解析出来的提交：失败的构建同样需要能查"它到底构建了哪一版"
		if err := api.fail(reportCtx, job.ID, reason, result.CommitSHA, buf.snapshot()); err != nil {
			slog.Error("cannot report the failure", "job", job.ID, "error", err)
		}
		return true
	}
	slog.Info("build succeeded", "job", job.ID, "commit", result.CommitSHA, "sha256", result.SHA256)
	// releaseId 留空：产物上传接入在阶段 2b 的下一步，现在先把构建结果与指纹落回去
	if err := api.complete(reportCtx, job.ID, result.CommitSHA, result.SHA256, "", buf.snapshot()); err != nil {
		slog.Error("cannot report the result", "job", job.ID, "error", err)
	}
	return true
}
