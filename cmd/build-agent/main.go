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
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
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
	// 本机私钥。没有就生成一把——服务端从此把签名密钥加密给对应的公钥，没有人需要
	// 敲封装口令。丢了它的后果和丢了封装口令一样：已有的盒子全部打不开
	private, public, err := loadOrCreateAgentKey(cfg.StateDir)
	if err != nil {
		slog.Error("cannot load this machine's build agent key", "stateDir", cfg.StateDir, "error", err)
		os.Exit(2)
	}
	cfg.AgentPrivateKey = private
	cfg.AgentPublicKey = public
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// 停机信号只用来"不再领新活"，正在跑的构建不打断（见 pollOnce）。单独起一个
	// goroutine 说一声，否则 systemctl stop 会静静地挂着，看的人不知道它在等什么。
	go func() {
		<-ctx.Done()
		slog.Info("stop requested: not claiming any more builds; the one in flight will finish")
	}()

	// 上一条命留下的检出：硬杀时收尾那一步执行不到，检出、登记和里面解开的 keystore
	// 都会留在盘上。这一刻手上没有任务，凡是在 workspace 里的都是孤儿。
	pruneOrphanWorktrees(ctx, cfg)

	slog.Info("build agent started", "server", cfg.Server, "agent", cfg.Name,
		"platforms", cfg.Platforms, "workspace", cfg.Workspace,
		"keyFingerprint", cfg.AgentPublicKey.Fingerprint())
	api := newClient(cfg)

	// 登记本机公钥。服务端此后把签名密钥加密给它，没有人需要敲封装口令。
	//
	// 登记不成功不退出：服务端可能正在重启，而已经存在的任务还应该照常跑。第一次
	// 登记之前也确实没有任何密钥加密给这台机器，没什么可损失的。
	registerCtx, cancelRegister := context.WithTimeout(ctx, 30*time.Second)
	if status, err := api.registerPublicKey(registerCtx, cfg.AgentPublicKey.PublicKey, cfg.Name); err != nil {
		slog.Warn("cannot register this machine's public key; the server has nothing to encrypt new keystores to",
			"fingerprint", cfg.AgentPublicKey.Fingerprint(), "error", err)
	} else {
		// pending_acceptance：服务端上已经固定了另一把公钥，换它要人核对指纹后接受。
		// 自动接受的话，偷到令牌的人登记自己的公钥就能收下以后每一把新密钥
		slog.Info("registered this machine's public key", "status", status,
			"fingerprint", cfg.AgentPublicKey.Fingerprint())
	}
	cancelRegister()
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
		// 队列空着的这一轮顺手验一下新存进来的盒子。放在这里是因为它要用同一个
		// 封装口令，而构建正忙时没有理由和它抢——验证不急，早几秒晚几秒都行，
		// 但它必须发生在"有人发起构建"之前。
		verifyPendingKeystores(ctx, cfg, api)
		if ctx.Err() != nil {
			slog.Info("build agent stopped")
			return
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
	// 构建不挂在 ctx 上：收到 SIGTERM 就把一个跑了五分钟、已经签完名的构建拦腰砍掉
	// 是不值当的，何况换二进制是我们自己发起的动作。信号让循环停在下一次领活之前，
	// 这一条做完为止。unit 里的 TimeoutStopSec 必须给得比 BUILD_AGENT_TIMEOUT_MINUTES
	// 长，否则 systemd 会在中途补一刀 SIGKILL。
	buildCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Timeout)
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

	result, buildErr := buildJob(buildCtx, cfg, api, job, buf)

	// 产物必须在删掉 worktree **之前**传走。第一版把删除放在前面，于是构建成功
	// 之后包就没了，只剩一个 sha256——"成功"却拿不到任何可分发的东西。
	releaseID := ""
	if buildErr == nil {
		buf.add("uploading " + filepath.Base(result.ArtifactPath) + " and its SBOM")
		releaseID, buildErr = api.uploadArtifact(buildCtx, job.ID, result.ArtifactPath, result.SBOMPath, buf)
		if buildErr != nil {
			buildErr = fmt.Errorf("the package was built but could not be uploaded: %w", buildErr)
		} else {
			buf.add("release " + releaseID)
		}
	}
	close(beats)
	removeWorktree(cfg, job, buf)

	// 上报用一个不受构建超时影响的 context：构建因为超时被杀掉时，正是最需要
	// 把失败原因送回去的时候。
	reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer reportCancel()
	if buildErr != nil {
		reason := red.line(buildErr.Error())
		if buildCtx.Err() == context.DeadlineExceeded {
			reason = "build timed out after " + cfg.Timeout.String()
		}
		slog.Error("build failed", "job", job.ID, "reason", reason)
		// 带上已经解析出来的提交：失败的构建同样需要能查"它到底构建了哪一版"
		report(reportCtx, job.ID, "failure", func(ctx context.Context) error {
			return api.fail(ctx, job.ID, reason, result.CommitSHA, buf.snapshot())
		})
		return true
	}
	slog.Info("build succeeded", "job", job.ID, "commit", result.CommitSHA, "sha256", result.SHA256, "release", releaseID)
	// releaseId 留空：产物上传接入在阶段 2b 的下一步，现在先把构建结果与指纹落回去
	report(reportCtx, job.ID, "result", func(ctx context.Context) error {
		return api.complete(ctx, job.ID, result.CommitSHA, result.SHA256, releaseID, buf.snapshot())
	})
	return true
}

// report 反复重试最后那一次上报。
//
// 这一步失败的代价和别处不一样：任务会永远停在 claimed，管理端上看不出发生了
// 什么，那个 build 号也一直被占着。2026-09-11 部署时撞上过一次——上报正好落在
// 服务端重启的几秒里拿到 521，任务从此卡住。
//
// 构建已经做完了，多等一会儿不浪费任何东西，所以退避重试到分钟级。
func report(ctx context.Context, jobID, what string, send func(context.Context) error) {
	delay := 2 * time.Second
	for attempt := 1; attempt <= 8; attempt++ {
		if err := send(ctx); err == nil {
			return
		} else {
			slog.Warn("cannot report the "+what+", will retry", "job", jobID, "attempt", attempt, "error", err)
		}
		select {
		case <-ctx.Done():
			slog.Error("gave up reporting the "+what, "job", jobID)
			return
		case <-time.After(delay):
		}
		if delay < 60*time.Second {
			delay *= 2
		}
	}
	slog.Error("gave up reporting the "+what+" after repeated failures", "job", jobID)
}
