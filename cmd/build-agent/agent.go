package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/machinekey"
	"github.com/Helix2010/RN-Server/signing/provenance"
)

var (
	// errAttemptStale 是任务上下文被取消的原因之一：服务端说这次认领已经过期。
	errAttemptStale = errors.New("the server says this claim is no longer ours (BUILD_ATTEMPT_STALE)")
	errTimedOut     = errors.New("build timed out")
)

// agent 是构建控制进程。它持有本机令牌与出处密钥，执行进程两样都拿不到。
type agent struct {
	cfg  config
	api  *client
	keys *keyring
	red  *redactor
	log  *slog.Logger

	heartbeatEvery time.Duration
	reportDelay    time.Duration
	now            func() time.Time

	// iosProbe 覆盖上传 Key 的只读探测（测试用）；nil = 按配置决定探不探
	iosProbe func(ctx context.Context, teamID string, bundleIDs []string) string
	// iosScan 覆盖整次签名材料盘点（测试用）；nil = 真去问钥匙串与磁盘。
	// 盘点要起 `security` 子进程、读这台机器的钥匙串，没有一台 Mac 就测不了，
	// 而"领到任务前再核一次材料"这条规则本身是要有用例守着的
	iosScan func(ctx context.Context) iosInventory
	// lastSaid 是 sayOnce 的去重表：盘点每 10 秒一次，说的话几天不变
	lastSaid map[string]string

	keyActive      bool
	keyCheckedAt   time.Time
	keyCheckEvery  time.Duration
	lastKeyMessage string

	// mirrorProtocol 是 fetch 仓库镜像时唯一放行的传输协议（生产里是 ssh；测试的镜像从本地路径取，是 file）。
	// 空值一律当 ssh：配置没设、或者构造 agent 的地方没填，都要落在最严的那一档。
	// pinnedFilesOwner 是那些"控制进程自己改不了"的文件必须的属主（生产里是 root）：
	// 固定 known_hosts 与 allowed_signers。两者都不来自配置——能改它们的进程可以决定
	// 连的是不是 GitHub、认的是不是我们的签名者。
	mirrorProtocol   string
	pinnedFilesOwner int
}

func newAgent(cfg config, keys *keyring) *agent {
	return &agent{
		cfg:              cfg,
		api:              newClient(cfg),
		keys:             keys,
		red:              newRedactor(),
		log:              slog.Default(),
		heartbeatEvery:   30 * time.Second,
		reportDelay:      2 * time.Second,
		now:              time.Now,
		keyCheckEvery:    10 * time.Minute,
		mirrorProtocol:   mirrorProtocolOr(cfg.MirrorProtocol),
		pinnedFilesOwner: rootUID,
	}
}

// ensureKeyAccepted 登记出处公钥，返回服务端是否已接受（active）。
//
// 登记与接受是两件事：机器自己登记，平台管理员在控制台核对完整 sha256 后接受。没接受之前
// 不领任务——领了也签不出服务端认的出处声明。已 active 且运维执行过 rotate-key 时，
// 用当前私钥签换钥证明把下一把登记上去；服务端接受下一把之后换上它。
func (a *agent) ensureKeyAccepted(ctx context.Context) bool {
	if a.keyActive && a.now().Sub(a.keyCheckedAt) < a.keyCheckEvery {
		return true
	}
	current := a.keys.current
	reg, err := a.api.registerKey(ctx, current.publicBase64(), nil)
	if errorCode(err) == codeKeyRotationUnproven && a.keys.next != nil {
		// 服务端认的已经是下一把：同钥重复登记是幂等的
		if nextReg, nextErr := a.api.registerKey(ctx, a.keys.next.publicBase64(), nil); nextErr == nil &&
			nextReg.Status == "active" && nextReg.PublicKeySHA256 == a.keys.next.sha256 {
			if err := a.keys.promoteNext(); err != nil {
				a.log.Error("the server accepted the rotation key but it could not be put in place", "error", err)
				a.keyActive = false
				return false
			}
			a.log.Warn("the rotation key was accepted by the server and is now this machine's provenance key",
				"publicKeySha256", a.keys.current.sha256)
			a.keyActive, a.keyCheckedAt = true, a.now()
			return true
		}
	}
	if err != nil {
		a.keyActive = false
		switch errorCode(err) {
		case codeKeyRotationUnproven:
			a.say("the server has a different provenance key active for this machine; if this machine's state directory was lost, treat it as a new machine (new token in the console, trust-builder on the signers)",
				"publicKeySha256", current.sha256)
		default:
			if ctx.Err() == nil {
				a.say("cannot register this machine's provenance key", "error", err)
			}
		}
		return false
	}
	switch reg.Status {
	case "pending_key":
		a.keyActive = false
		a.say("waiting for a platform administrator to accept this machine's provenance key in the console; compare the full sha256 with `build-agent show-key`",
			"publicKeySha256", current.sha256)
		return false
	case "active":
	default:
		a.keyActive = false
		a.say("the server answered the key registration with an unknown status", "status", firstRunes(reg.Status, 32))
		return false
	}
	if reg.PublicKeySHA256 != current.sha256 {
		a.keyActive = false
		a.say("the server reports a different active provenance key", "server", firstRunes(reg.PublicKeySHA256, 64), "local", current.sha256)
		return false
	}
	a.keyActive, a.keyCheckedAt = true, a.now()
	if next := a.keys.next; next != nil && reg.PendingPublicKeySHA256 != next.sha256 {
		a.proposeRotation(ctx, reg, *next)
	}
	return true
}

func (a *agent) proposeRotation(ctx context.Context, reg keyRegistration, next machineKey) {
	if reg.MachineID == "" {
		a.log.Error("cannot propose the rotation key: the server did not say this machine's id (machineId) in the key registration response",
			"nextPublicKeySha256", next.sha256)
		return
	}
	signature, err := machinekey.SignRotation(a.keys.current.private, reg.MachineID, next.sha256, "")
	if err != nil {
		a.log.Error("cannot sign the key rotation", "error", err)
		return
	}
	rotation, err := a.api.registerKey(ctx, next.publicBase64(), signature)
	if err != nil {
		a.log.Error("the server refused the rotation key", "nextPublicKeySha256", next.sha256, "error", err)
		return
	}
	a.log.Warn("rotation key registered; it becomes this machine's provenance key once accepted in the console. Trust it on every signer (signer trust-builder) before accepting it",
		"status", rotation.Status, "pendingPublicKeySha256", firstRunes(rotation.PendingPublicKeySHA256, 64), "nextPublicKeySha256", next.sha256)
}

// say 打一条"在等什么"的日志，同一句话不重复刷屏。
func (a *agent) say(message string, args ...any) {
	key := message + fmt.Sprint(args...)
	if key == a.lastKeyMessage {
		return
	}
	a.lastKeyMessage = key
	a.log.Warn(message, args...)
}

// pollOnce 领一个任务并把它做完，返回是否真的做了事。
// claimRequest 组装这一次认领要自报的东西（设计 §5.2、§5.4、§6.2）。
//
// 每次认领都重新盘点一遍签名材料，而不是启动时盘一次记住：材料是运维用手导进钥匙串、
// 拷进目录的，中途加一个租户、删一张过期证书都不会通知这个进程。每 10 秒起一次
// `security` 子进程的代价，换的是"控制台上看到的就是这台机器现在真实有的东西"。
func (a *agent) claimRequest(ctx context.Context) claimRequest {
	request := claimRequest{Platforms: a.cfg.Platforms, AgentCommit: agentCommit(), OS: runtime.GOOS}
	// 空闲空间：磁盘满时每条任务都会在 pnpm install 或 archive 那一步失败，各烧掉一个
	// build 号。报上去让控制台看得见，低于阈值就暂停认领——但仍然来报到，
	// 否则控制台只能显示"离线"，而磁盘满和关机要做的处理完全不同
	if free, err := freeGiB(a.cfg.Workspace); err != nil {
		a.log.Warn("cannot read the free space of the jobs root", "path", a.cfg.Workspace, "error", err)
	} else {
		request.FreeGb = free
		if a.cfg.MinFreeGB > 0 && free < a.cfg.MinFreeGB {
			request.Paused = true
			request.PausedReason = fmt.Sprintf("%s has %d GiB free, below BUILD_AGENT_MIN_FREE_GB=%d; not claiming until there is room",
				a.cfg.Workspace, free, a.cfg.MinFreeGB)
			a.sayOnce("lowDisk", request.PausedReason)
		}
	}
	if !containsPlatform(a.cfg.Platforms, jobspec.PlatformIOS) {
		return request
	}
	inventory := a.iosInventory(ctx)
	for _, team := range inventory.Teams {
		report := appleTeamSelfReport{TeamID: team.TeamID, BundleIDs: team.BundleIDs, UploadProbe: team.UploadProbe}
		if !team.ExpiresAt.IsZero() {
			report.ExpiresAt = team.ExpiresAt.UTC().Format(time.RFC3339)
		}
		request.AppleTeams = append(request.AppleTeams, report)
	}
	return request
}

// iosInventory 盘点一次签名材料，并把"看见了但用不了"的东西打进日志——每轮都打会把
// 日志刷满（认领每 10 秒一次），所以只在内容变了的时候打。
func (a *agent) iosInventory(ctx context.Context) iosInventory {
	if a.iosScan != nil {
		return a.iosScan(ctx)
	}
	scanner := newIOSScanner(a.cfg)
	scanner.Now = a.now
	scanner.Probe = a.probeUploadKey
	if a.iosProbe != nil {
		scanner.Probe = a.iosProbe
	}
	inventory := scanner.scan(ctx)
	a.sayOnce("iosTeams", "signing material for "+strings.Join(inventory.teamIDs(), ", "))
	if len(inventory.Problems) > 0 {
		a.sayOnce("iosProblems", strings.Join(inventory.Problems, "; "))
	}
	return inventory
}

// sayOnce 只在这条消息与上一次不同时打一行。盘点与磁盘检查每 10 秒做一次，
// 而它们要说的话几天都不会变。
func (a *agent) sayOnce(topic, message string) {
	if a.lastSaid == nil {
		a.lastSaid = map[string]string{}
	}
	if a.lastSaid[topic] == message {
		return
	}
	a.lastSaid[topic] = message
	a.log.Info(message, "topic", topic)
}

// freeGiB 是这个路径所在卷的可用空间（GiB，向下取整）。
func freeGiB(path string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(uint64(stat.Bavail) * uint64(stat.Bsize) / (1 << 30)), nil
}

func (a *agent) pollOnce(ctx context.Context) bool {
	if a.api.isRevoked() {
		return false
	}
	if !a.ensureKeyAccepted(ctx) {
		return false
	}
	if ctx.Err() != nil {
		// 已经收到停机信号：不再发起新的领取
		return false
	}
	// 领取请求不随停机信号取消：服务端已经派出的任务，响应丢在半路就只能等下次启动时判失败。
	// 领到了就照常做完（停机只是不再发起新的领取）。
	request := a.claimRequest(ctx)
	result, err := a.api.claim(context.WithoutCancel(ctx), request)
	if err != nil {
		switch errorCode(err) {
		case codeKeyNotAccepted:
			a.keyActive = false
			a.log.Warn("cannot claim a build", "error", err)
		case codeClaimInProgress:
			// 上一次领取请求还在服务端手里（超时后重发）：等下一轮再领
			a.log.Info("a previous claim from this machine is still being processed; retrying later")
		default:
			a.log.Warn("cannot claim a build", "error", err)
		}
		return false
	}
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer cancel()
	switch {
	case result.Active != nil:
		// 本机手上没有任务（这里是单线程的领取循环），服务端却记着一条：上一条命里被打断的构建。
		// 中断的构建不续跑——半截的依赖安装与编译状态续下去比重来更危险。明确判失败，
		// 让控制台立刻看到原因，而不是干等回收定时器。
		a.log.Warn("the server says this machine still has a build in flight from an earlier run; reporting it as failed",
			"job", result.Active.JobID, "attempt", result.Active.Attempt)
		a.report(reportCtx, result.Active.JobID, "failure", func(ctx context.Context) error {
			return a.api.fail(ctx, result.Active.JobID, result.Active.Attempt,
				"构建机重启或丢失了领取结果，中断的构建不续跑；需要的话重新排队", "", nil)
		})
		return true
	case result.Refused != nil:
		a.log.Error("refusing a claimed job", "job", firstRunes(result.Refused.JobID, 80), "reason", result.Refused.Reason)
		if jobspec.ValidJobID(result.Refused.JobID) && result.Refused.Attempt > 0 {
			a.report(reportCtx, result.Refused.JobID, "failure", func(ctx context.Context) error {
				return a.api.fail(ctx, result.Refused.JobID, result.Refused.Attempt, result.Refused.Reason, "", nil)
			})
		}
		return true
	case result.Job == nil:
		return false
	case request.Paused:
		// 认领时说了"我现在不领活"，服务端还是派了一条过来。一台正常的服务端不会这么做
		// （它看到 paused 就回 204），所以这里不是"要不要将就一下"，而是收到了不该收到的
		// 东西：照做会在磁盘满的机器上跑一次注定失败的构建。判失败并说清原因，让人看得见
		a.log.Error("the server dispatched a job to a machine that reported itself paused",
			"job", result.Job.ID, "reason", request.PausedReason)
		a.report(reportCtx, result.Job.ID, "failure", func(ctx context.Context) error {
			return a.api.fail(ctx, result.Job.ID, result.Job.Attempt, request.PausedReason, "", nil)
		})
		return true
	}
	a.runJob(ctx, *result.Job)
	return true
}

// runJob 做完一个任务：准备目录、让执行进程构建、交付、上报，最后清理。
func (a *agent) runJob(ctx context.Context, job claimedJob) {
	a.log.Info("claimed a build", "job", job.ID, "attempt", job.Attempt, "kind", job.Kind,
		"tenant", job.TenantSlug, "version", job.Version, "buildNumber", job.BuildNumber,
		"runnerSeparated", a.cfg.runnerSeparated())
	if !a.cfg.runnerSeparated() {
		a.log.Warn("this build runs with BUILD_AGENT_RUNNER_USER=-: the runner shares the build agent's user; local testing only, never in production", "job", job.ID)
	}
	buf := newLogBuffer(a.red)

	// 构建不挂在进程的停机信号上：收到 SIGTERM 只是不再领新活，这一条做完为止。
	// 心跳收到 409 BUILD_ATTEMPT_STALE 则立刻取消。
	jobCtx, cancelJob := context.WithCancelCause(context.WithoutCancel(ctx))
	defer cancelJob(nil)
	// 机器被吊销（任何一条请求先撞上都算）：立刻中止
	stopWatchingRevocation := context.AfterFunc(a.api.revoked, func() { cancelJob(errMachineRevoked) })
	defer stopWatchingRevocation()
	buildCtx, cancelTimeout := context.WithTimeoutCause(jobCtx, a.cfg.Timeout, errTimedOut)
	defer cancelTimeout()

	beats := make(chan struct{})
	beatsDone := make(chan struct{})
	go func() {
		defer close(beatsDone)
		ticker := time.NewTicker(a.heartbeatEvery)
		defer ticker.Stop()
		for {
			select {
			case <-beats:
				return
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				err := a.api.heartbeat(jobCtx, job, buf.snapshot())
				if isStale(err) {
					a.log.Warn("heartbeat says the claim is stale; aborting the build now", "job", job.ID, "attempt", job.Attempt)
					cancelJob(errAttemptStale)
					return
				}
				if err != nil && jobCtx.Err() == nil {
					a.log.Warn("heartbeat failed", "job", job.ID, "error", err)
				}
			}
		}
	}()

	commit, err := a.buildAndDeliver(buildCtx, job, buf)
	close(beats)
	<-beatsDone

	if layout, layoutErr := jobspec.NewLayout(a.cfg.Workspace, job.ID); layoutErr == nil {
		if _, statErr := os.Lstat(layout.Dir()); statErr == nil {
			a.cleanupJob(layout)
		}
	}
	_ = os.RemoveAll(a.spoolDir(job.ID))

	if a.api.isRevoked() {
		a.log.Error("build aborted: this machine was revoked; nothing more is reported", "job", job.ID, "attempt", job.Attempt)
		return
	}
	if errors.Is(context.Cause(jobCtx), errAttemptStale) || isStale(err) {
		a.log.Warn("build aborted: the server no longer counts this attempt; nothing more is reported", "job", job.ID, "attempt", job.Attempt)
		return
	}
	reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
	defer reportCancel()
	if err != nil {
		reason := a.red.line(err.Error())
		if errors.Is(context.Cause(buildCtx), errTimedOut) {
			reason = "build timed out after " + a.cfg.Timeout.String()
		}
		a.log.Error("build failed", "job", job.ID, "reason", reason)
		a.report(reportCtx, job.ID, "failure", func(ctx context.Context) error {
			return a.api.fail(ctx, job.ID, job.Attempt, reason, commit, buf.snapshot())
		})
		return
	}
	a.log.Info("build delivered", "job", job.ID, "commit", commit)
}

// buildAndDeliver 返回检出的提交与第一个错误。安装包任务以 /built 结束，热更新任务以 /complete 结束。
func (a *agent) buildAndDeliver(ctx context.Context, job claimedJob, buf *logBuffer) (string, error) {
	// 盘点与认领之间可能有人动过钥匙串或删掉了描述文件（设计 §5.2 最后一行）。
	// 在检出仓库、装依赖、跑 archive 之前先核一次：缺材料的话那几十分钟一定白花，
	// 而且失败会出现在 xcodebuild 的输出里，看起来像构建问题而不是材料问题
	if job.Kind == string(jobspec.KindAPK) && job.Platform == string(jobspec.PlatformIOS) {
		if team, bundle := job.AppleTeamID(), job.BundleID(); !a.iosInventory(ctx).covers(team, bundle) {
			return "", fmt.Errorf("this machine has no usable signing material for Apple Team %s / bundle id %s: "+
				"import the distribution certificate into the keychain and put the provisioning profile under %s, then restart the agent",
				team, bundle, a.cfg.MachineEnv[jobspec.IOSSigningDirEnv])
		}
	}
	prepared, err := a.prepareWorktree(ctx, job, buf)
	if err != nil {
		return prepared.Commit, err
	}
	if err := a.runBuild(ctx, prepared, buf); err != nil {
		return prepared.Commit, err
	}
	if err := context.Cause(ctx); err != nil {
		return prepared.Commit, err
	}
	switch {
	case prepared.Spec.Kind == jobspec.KindAPK && prepared.Spec.Platform == jobspec.PlatformIOS:
		return prepared.Commit, a.deliverIPA(ctx, job, prepared, buf)
	case prepared.Spec.Kind == jobspec.KindAPK:
		return prepared.Commit, a.deliverAPK(ctx, job, prepared, buf)
	case prepared.Spec.Kind == jobspec.KindOTA:
		return prepared.Commit, a.deliverOTA(ctx, job, prepared, buf)
	}
	return prepared.Commit, errors.New("unknown job kind")
}

func (a *agent) deliverAPK(ctx context.Context, job claimedJob, prepared preparedJob, buf *logBuffer) error {
	result, err := readResult(prepared.Layout, jobspec.KindAPK, jobspec.PlatformAndroid)
	if err != nil {
		return err
	}
	spool := a.spoolDir(job.ID)
	unsigned, err := spoolOutput(prepared.Layout, jobspec.UnsignedFileName, spool, jobspec.MaxUnsignedSize)
	if err != nil {
		return err
	}
	buf.add(fmt.Sprintf("unsigned package %d bytes, sha256 %s", unsigned.Size, unsigned.SHA256))
	sbom, err := spoolOutput(prepared.Layout, jobspec.SBOMFileName, spool, jobspec.MaxSBOMSize)
	if err != nil {
		return err
	}
	if err := checkSBOMBinding(sbom.Path, unsigned.SHA256, jobspec.ArtifactName(job.TenantDirectory, job.Version, job.BuildNumber)); err != nil {
		return err
	}
	buf.add("SBOM sha256 " + sbom.SHA256 + " (bound to the unsigned package)")

	if err := withRetry(ctx, buf, "unsigned package upload", 6, func(ctx context.Context) error {
		return a.api.uploadStream(ctx, job, "/unsigned/upload", unsigned.Path, unsigned.SHA256, unsigned.Size)
	}); err != nil {
		return fmt.Errorf("the unsigned package was built but could not be uploaded: %w", err)
	}
	if err := withRetry(ctx, buf, "SBOM upload", 6, func(ctx context.Context) error {
		return a.api.uploadStream(ctx, job, "/sbom/upload", sbom.Path, sbom.SHA256, sbom.Size)
	}); err != nil {
		return fmt.Errorf("the SBOM could not be uploaded: %w", err)
	}

	// 换钥进行中：签名之前再问一次服务端，控制台刚接受了下一把的话先换上，免得用旧密钥签出
	// 一份服务端已经不认的声明
	if a.keys.next != nil {
		a.keyActive = false
		if !a.ensureKeyAccepted(ctx) {
			return errors.New("this machine's provenance key is no longer accepted by the server")
		}
	}
	statement := provenance.Statement{
		Version:           provenance.Version,
		Purpose:           provenance.Purpose,
		JobID:             job.ID,
		Attempt:           job.Attempt,
		TenantSlug:        job.TenantSlug,
		PackageName:       job.PackageName(),
		VersionCode:       int64(job.BuildNumber),
		VersionName:       job.Version,
		CommitSHA:         prepared.Commit,
		UnsignedSHA256:    unsigned.SHA256,
		UnsignedSize:      unsigned.Size,
		SBOMSHA256:        sbom.SHA256,
		NativeFingerprint: result.NativeFingerprint,
		BuilderID:         job.ClaimedMachineID,
		BuiltAt:           a.now().UTC().Format(time.RFC3339),
	}
	envelope, err := provenance.Sign(statement, a.keys.current.private)
	if err != nil {
		return fmt.Errorf("cannot sign the provenance statement: %w", err)
	}
	buf.add("provenance signed by " + a.keys.current.sha256)
	if err := withRetry(ctx, buf, "delivery", 6, func(ctx context.Context) error {
		return a.api.built(ctx, job, prepared.Commit, result.NativeFingerprint, envelope, buf.snapshot())
	}); err != nil {
		return fmt.Errorf("the server did not accept the delivery: %w", err)
	}
	a.log.Info("unsigned package delivered; waiting for the signing gate", "job", job.ID,
		"unsignedSha256", unsigned.SHA256, "sbomSha256", sbom.SHA256)
	return nil
}

// deliverIPA 交付 iOS 安装包任务。
//
// 与 Android 那条的三点不同，每一条都来自"iOS 的签名与构建分不开"（设计 §4.2）：
//
//  1. **产物不上传**。xcodebuild 导出的 .ipa 已经签好名，而用户装的那一份是 Apple
//     重签、瘦身之后的东西——把这一份当发布产物存起来，只会让发布记录的 sha256 变成
//     一个对不上任何东西的值。这里只算一遍摘要记进审计；
//  2. **没有出处签名**。那套是给签名闸验货用的，iOS 没有签名闸这一环；
//  3. **一步到 succeeded**，不经过 built / signing。
func (a *agent) deliverIPA(ctx context.Context, job claimedJob, prepared preparedJob, buf *logBuffer) error {
	result, err := readResult(prepared.Layout, jobspec.KindAPK, jobspec.PlatformIOS)
	if err != nil {
		return err
	}
	ipa, err := spoolOutput(prepared.Layout, jobspec.IPAFileName, a.spoolDir(job.ID), jobspec.MaxIPASize)
	if err != nil {
		return err
	}
	buf.add(fmt.Sprintf("ipa %d bytes, sha256 %s", ipa.Size, ipa.SHA256))
	// 自己读一遍包，确认它就是这条任务要的那个。执行进程跑第三方依赖，它交上来的
	// 东西按不可信处理；而下一步是**撤不回来的**：包一旦进了 App Store Connect，
	// 只能再出一个 build 号顶掉它
	identity, err := readIPAIdentity(ipa.Path)
	if err != nil {
		return err
	}
	if err := checkIPAMatchesJob(identity, job); err != nil {
		return err
	}
	buf.add("package identity checked: " + identity.BundleID + " " + identity.ShortVersion + " (" + identity.BuildNumber + ")")
	var outcome uploadOutcome
	if a.cfg.IOSUpload {
		if outcome, err = a.uploadIPA(ctx, job, ipa.Path, identity, buf); err != nil {
			return err
		}
		if outcome.UploadedByEarlierAttempt {
			buf.add("App Store Connect already had this build number; an earlier attempt uploaded it")
		} else {
			buf.add("uploaded to App Store Connect")
		}
	} else {
		buf.add("not uploaded: this machine is not configured to upload (BUILD_AGENT_IOS_UPLOAD)")
	}
	if err := withRetry(ctx, buf, "result report", 8, func(ctx context.Context) error {
		return a.api.iosRelease(ctx, job, prepared.Commit, ipa.SHA256, ipa.Size, iosReleaseReport{
			Uploaded: outcome.Uploaded, UploadedByEarlierAttempt: outcome.UploadedByEarlierAttempt,
			Toolchain: result.Toolchain,
		}, buf.snapshot())
	}); err != nil {
		return fmt.Errorf("the iOS package was built but the job could not be completed: %w", err)
	}
	a.log.Info("ios package delivered", "job", job.ID, "ipaSha256", ipa.SHA256,
		"uploaded", outcome.Uploaded, "uploadedByEarlierAttempt", outcome.UploadedByEarlierAttempt)
	return nil
}

func (a *agent) deliverOTA(ctx context.Context, job claimedJob, prepared preparedJob, buf *logBuffer) error {
	if _, err := readResult(prepared.Layout, jobspec.KindOTA, jobspec.PlatformAndroid); err != nil {
		return err
	}
	pkg, err := spoolOutput(prepared.Layout, jobspec.OTAFileName, a.spoolDir(job.ID), jobspec.MaxOTASize)
	if err != nil {
		return err
	}
	buf.add(fmt.Sprintf("ota package %d bytes, sha256 %s", pkg.Size, pkg.SHA256))
	releaseID, err := a.api.uploadOTAPackage(ctx, job, pkg.Path, pkg.Size, prepared.Commit, buf)
	if err != nil {
		return fmt.Errorf("the OTA package was built but could not be uploaded: %w", err)
	}
	buf.add("release " + releaseID)
	if err := withRetry(ctx, buf, "result report", 8, func(ctx context.Context) error {
		return a.api.complete(ctx, job, prepared.Commit, pkg.SHA256, releaseID, buf.snapshot())
	}); err != nil {
		return fmt.Errorf("the OTA revision was created but the job could not be completed: %w", err)
	}
	return nil
}

// serve 是常驻循环：领任务、做完、再领。停机信号到来时排空后返回 0；机器被吊销时返回
// exitMachineRevoked——令牌已经没用了，systemd 不该把它无限重启（unit 的 RestartPreventExitStatus）。
func (a *agent) serve(ctx context.Context) int {
	for {
		worked := a.pollOnce(ctx)
		if a.api.isRevoked() {
			a.log.Error("this build machine was revoked in the console (or its token is no longer recognised); stopping. "+
				"Create a new machine in the console and put its token in the env file to build again",
				"exitStatus", exitMachineRevoked)
			return exitMachineRevoked
		}
		if ctx.Err() != nil {
			a.log.Info("build agent stopped")
			return 0
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			a.log.Info("build agent stopped")
			return 0
		case <-a.api.revoked.Done():
		case <-time.After(a.cfg.PollEvery):
		}
	}
}

// report 反复重试最后那一次上报（失败原因）。这一步失败的代价是任务停在 claimed、
// 管理端看不出发生了什么，所以退避重试到分钟级；服务端明确拒绝（含 409 过期）就停。
func (a *agent) report(ctx context.Context, jobID, what string, send func(context.Context) error) {
	delay := a.reportDelay
	for attempt := 1; attempt <= 8; attempt++ {
		err := send(ctx)
		if err == nil {
			return
		}
		if !worthRetrying(err) {
			a.log.Error("the server refused the "+what+" report", "job", jobID, "error", err)
			return
		}
		a.log.Warn("cannot report the "+what+", will retry", "job", jobID, "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			a.log.Error("gave up reporting the "+what, "job", jobID)
			return
		case <-time.After(delay):
		}
		if delay < 60*time.Second {
			delay *= 2
		}
	}
	a.log.Error("gave up reporting the "+what+" after repeated failures", "job", jobID)
}

// mirrorProtocolOr：空值落回生产默认 ssh。
func mirrorProtocolOr(p string) string {
	if p == "" {
		return "ssh"
	}
	return p
}
