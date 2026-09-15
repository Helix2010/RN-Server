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

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"time"
)

func main() {
	// show-key 打印本机身份。恢复时要靠它核对 agent-key 有没有放对位置——
	// manifest.agentKeyFingerprint 就是它的比对对象。没有这条子命令，
	// RECOVERY.md 第 4 步是一条必然失败的指引。
	if len(os.Args) == 2 && os.Args[1] == "show-key" {
		showKey()
		return
	}
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
	// 备份签名私钥。和上面那把是两把不同算法、不同用途的钥匙：一把开盒子，
	// 一把给备份包签名。缺了它只影响备份，不影响构建
	signingKey, signingPublic, err := loadOrCreateBackupSigningKey(cfg.StateDir)
	if err != nil {
		slog.Error("cannot load this machine's backup signing key; backups will be refused",
			"stateDir", cfg.StateDir, "error", err)
	} else {
		cfg.BackupSigningKey = signingKey
		cfg.BackupSigningPublicKey = signingPublic
	}
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

	// 备份签名公钥。规则和上面那把一样：库里没有就自动接受，已有另一把就挂成
	// 待确认——自动接受等于偷到令牌的人换掉签名公钥，此后他伪造的备份包全都验得过
	if cfg.BackupSigningPublicKey != "" {
		signCtx, cancelSign := context.WithTimeout(ctx, 30*time.Second)
		if status, err := api.registerBackupSigningKey(signCtx, cfg.BackupSigningPublicKey); err != nil {
			slog.Warn("cannot register this machine's backup signing key; backups will be refused", "error", err)
		} else {
			slog.Info("registered this machine's backup signing key", "status", status)
		}
		cancelSign()
	}
	// 上一次进程留下的明文暂存。SIGKILL 之后它会一直躺在磁盘上
	resetBackupStaging(cfg.StateDir)

	for {
		// 备份放在**领构建之前**看一眼。现有的密钥校验挂在 `if worked { continue }`
		// 下面，只有队列空的那一轮才跑——照抄的话，只要有人连着排构建，备份就
		// 永远轮不上。放这里，备份最多等一条正在跑的构建。
		if request, ok, err := api.pendingBackup(ctx); err != nil {
			// 不要把 error 吞成「没有待办」：「老服务端 + 新打包机」和「服务端挂了」
			// 在日志里会长得一模一样
			slog.Warn("cannot ask the server whether a backup is pending", "error", err)
		} else if ok {
			// 自带超时，而且**小于服务端 30 分钟的产出超时**：一次卡住的上传会让
			// 这个 goroutine 永远不返回，而它跑在轮询循环里——症状是构建队列
			// 无限堆积，日志里什么都没有
			backupCtx, cancelBackup := context.WithTimeout(ctx, backupTimeout)
			runBackup(backupCtx, cfg, api, request)
			cancelBackup()
		}
		if ctx.Err() != nil {
			slog.Info("build agent stopped")
			return
		}

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
		if job.Kind == "ota" {
			buf.add("uploading " + filepath.Base(result.ArtifactPath))
			releaseID, buildErr = api.uploadOTAPackage(buildCtx, job.ID, result.ArtifactPath, result.CommitSHA, buf)
		} else {
			buf.add("uploading " + filepath.Base(result.ArtifactPath) + " and its SBOM")
			releaseID, buildErr = api.uploadArtifact(buildCtx, job.ID, result.ArtifactPath, result.SBOMPath, result.NativeFingerprint, buf)
		}
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

// showKey 打印 agent-key 的指纹和公钥 base64，以及备份签名公钥的指纹。
//
// 指纹用的是既有实现那一种（原始公钥字节的 sha256 截断到 16 字符），
// 和 manifest.agentKeyFingerprint **必须逐字节相同**——不同的话，恢复时
// 那唯一一处身份核对永远对不上，而它是「文件放没放对」唯一的检查。
func showKey() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置读不了:", err)
		os.Exit(2)
	}
	_, public, err := loadOrCreateAgentKey(cfg.StateDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "读不了本机身份文件:", err)
		os.Exit(2)
	}
	fmt.Printf("agent-key fingerprint: %s\n", public.Fingerprint())
	fmt.Printf("agent-key public key:  %s\n", public.PublicKey)
	if _, signingPublic, err := loadOrCreateBackupSigningKey(cfg.StateDir); err == nil {
		if pub, err := backupcontainer.ParseSigningPublicKey(signingPublic); err == nil {
			if fingerprint, err := backupcontainer.SigningFingerprint(pub); err == nil {
				fmt.Printf("backup signing fingerprint: %s\n", fingerprint)
				fmt.Printf("backup signing public key:  %s\n", signingPublic)
			}
		}
	}
	fmt.Printf("state dir: %s\n", cfg.StateDir)
}
