// Package signer 是签名闸主进程与运维子命令的实现（signing/cmd/signer 只做参数分发）。
//
// 主进程 `signer run` 持有本机令牌、两把本机私钥与本机记录，只向外连服务端。它不解析
// APK：解析与签名前检查交给隔离的检查进程，检查通过之前不解密签名密钥。
package signer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/internal/securefs"
	"github.com/Helix2010/RN-Server/signing/policy"
	"github.com/Helix2010/RN-Server/signing/records"
)

// 上报给服务端的结论类型（约定 5.3 reject.kind）。
const (
	rejectViolation = "violation"
	rejectTransient = "transient"
)

var (
	commitPattern            = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	nativeFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)

	errJobFinished = errors.New("job finished")
	errStale       = errors.New("the server says this sign attempt is stale")
	errRevoked     = errors.New("the server revoked this signing gate's machine token (MACHINE_REVOKED); register the machine again with a new token")
)

// autoReleaseOperator 是签名闸自己释放预留时写进记录的操作者。
const autoReleaseOperator = "signer-run"

// maxUploadRounds：complete 报 SIGNED_ARTIFACT_MISSING 时最多重新上传几轮。
const maxUploadRounds = 3

// Runner 是签名闸主循环。字段在 Run 之前填好；间隔字段为零时用默认值。
type Runner struct {
	Config  Config
	Keys    MachineKeys
	Store   *records.Store
	API     API
	Checker Checker
	Signer  APKSigner
	Log     *slog.Logger

	PollInterval      time.Duration
	ChecksInterval    time.Duration
	HeartbeatInterval time.Duration
	RetryDelays       []time.Duration

	mu         sync.Mutex
	ready      []ReadyItem
	lastChecks time.Time
	trials     map[string]trialResult
	waiting    bool
}

type trialResult struct {
	ok  bool
	msg string
	at  time.Time
}

func (r *Runner) defaults() {
	if r.PollInterval == 0 {
		r.PollInterval = 15 * time.Second
	}
	if r.ChecksInterval == 0 {
		r.ChecksInterval = time.Minute
	}
	if r.HeartbeatInterval == 0 {
		r.HeartbeatInterval = time.Minute
	}
	if r.RetryDelays == nil {
		r.RetryDelays = []time.Duration{2 * time.Second, 5 * time.Second, 15 * time.Second}
	}
	if r.Log == nil {
		r.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if r.trials == nil {
		r.trials = map[string]trialResult{}
	}
}

func (r *Runner) workDir() string { return filepath.Join(r.Config.StateDir, workDirName) }

// Prepare 清掉运行时目录与工作目录里上次留下的一切（明文 keystore 不能跨进程存活）。
func (r *Runner) Prepare() error {
	r.defaults()
	if err := securefs.CheckPrivateDir(r.Config.RuntimeDir); err != nil {
		return fmt.Errorf("%s: %w", EnvRuntimeDir, err)
	}
	if err := securefs.RemoveContents(r.Config.RuntimeDir); err != nil {
		return fmt.Errorf("clear the runtime directory: %w", err)
	}
	if err := securefs.EnsurePrivateDir(r.workDir()); err != nil {
		return fmt.Errorf("work directory: %w", err)
	}
	return securefs.RemoveContents(r.workDir())
}

// AcquireRunLock 保证同一个状态目录只有一个 signer run。
func AcquireRunLock(stateDir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(stateDir, runLockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	ok, err := securefs.TryLock(f)
	if err != nil || !ok {
		f.Close()
		return nil, errors.New("another `signer run` is already using this state directory")
	}
	return f, nil
}

// Run 登记公钥后循环：定期试解与上报确认状态；本机是主时认领并签名。ctx 取消时返回 nil。
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Prepare(); err != nil {
		return err
	}
	if err := r.Register(ctx); err != nil {
		return err
	}
	for ctx.Err() == nil {
		worked, err := r.RunOnce(ctx)
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(r.PollInterval):
		}
	}
	return nil
}

// Register 登记本机公钥（同钥重复登记幂等）。临时错误原地重试，直到成功或 ctx 取消。
func (r *Runner) Register(ctx context.Context) error {
	r.defaults()
	for {
		status, err := r.API.RegisterKey(ctx, r.Keys.X25519PublicKey(), r.Keys.Ed25519PublicKey())
		if err == nil {
			return r.checkKeyStatus(status)
		}
		if ctx.Err() != nil {
			return nil
		}
		if !IsTransient(err) {
			return fmt.Errorf("register this signing gate's public keys: %w", err)
		}
		r.Log.Warn("public key registration failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.PollInterval):
		}
	}
}

func (r *Runner) checkKeyStatus(s KeyStatus) error {
	ours, oursEd := r.Keys.X25519SHA256(), r.Keys.Ed25519SHA256()
	switch s.Status {
	case "active":
		if s.PublicKeySHA256 == nil || *s.PublicKeySHA256 != ours || s.Ed25519PublicKeySHA256 == nil || *s.Ed25519PublicKeySHA256 != oursEd {
			return errors.New("the server's active keys for this machine token are not this signing gate's keys; register this machine as a new signing gate instead of reusing the token")
		}
		r.Log.Info("public keys are active on the server", "machineId", cleanText(s.MachineID, 80), "x25519Sha256", ours, "ed25519Sha256", oursEd)
	case "pending_key":
		r.Log.Warn("public keys are waiting for a platform admin to accept them in the console; compare with `signer show-key` and the offline pin file",
			"machineId", cleanText(s.MachineID, 80), "x25519Sha256", ours, "ed25519Sha256", oursEd)
	default:
		return &ProtocolError{Msg: "unknown public-key status"}
	}
	return nil
}

// RunOnce 做一轮：到期就试解并上报；本机是主就认领一条任务并处理。worked 表示处理了任务。
// 返回的错误是致命的（本机记录不可用等），签名闸应当退出。
func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	r.defaults()
	if r.lastChecks.IsZero() || time.Since(r.lastChecks) >= r.ChecksInterval {
		if err := r.RunChecks(ctx); err != nil {
			var fatal *fatalError
			if errors.As(err, &fatal) {
				return false, fatal.err
			}
			if IsRevoked(err) {
				return false, errRevoked
			}
			if isKeyNotAccepted(err) {
				if !r.waiting {
					r.Log.Warn("the server has not accepted this signing gate's public keys yet")
				}
				r.waiting = true
				return false, nil
			}
			r.Log.Warn("keystore checks failed", "error", err)
		}
		r.waiting = false
		r.lastChecks = time.Now()
	}
	role, err := r.Store.Role()
	if err != nil {
		return false, err
	}
	if role.Role != records.RolePrimary {
		return false, nil
	}
	r.mu.Lock()
	ready := append([]ReadyItem(nil), r.ready...)
	r.mu.Unlock()
	if len(ready) == 0 {
		return false, nil
	}
	claim, err := r.API.Claim(ctx, ready)
	if err != nil {
		if IsRevoked(err) {
			return false, errRevoked
		}
		if !isKeyNotAccepted(err) && ctx.Err() == nil {
			r.Log.Warn("claim failed", "error", err)
		}
		return false, nil
	}
	if claim == nil {
		return false, nil
	}
	return true, r.handle(ctx, claim)
}

func isKeyNotAccepted(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == codeMachineKeyNotAccepted
}

type fatalError struct{ err error }

func (f *fatalError) Error() string { return f.err.Error() }

// ---- 试解、确认状态、试签 ----

// RunChecks 取回发给本机的密文，逐份试解、查本机确认、试签，上报并更新就绪列表。
func (r *Runner) RunChecks(ctx context.Context) error {
	r.defaults()
	resp, err := r.API.KeystoreChecks(ctx)
	if err != nil {
		r.setReady(nil)
		return err
	}
	reports := []CheckReport{}
	var ready []ReadyItem
	for _, item := range resp.Items {
		report, readyItem, err := r.checkItem(ctx, item)
		if err != nil {
			r.setReady(nil)
			return &fatalError{err}
		}
		if report != nil {
			reports = append(reports, *report)
		}
		if readyItem != nil {
			ready = append(ready, *readyItem)
		}
	}
	r.setReady(ready)
	return r.retry(ctx, "report keystore checks", func(ctx context.Context) error { return r.API.ReportChecks(ctx, reports) })
}

func (r *Runner) setReady(ready []ReadyItem) {
	r.mu.Lock()
	r.ready = ready
	r.mu.Unlock()
}

// isReady 判断一项是否在本机最近一次声明的就绪列表里。
func (r *Runner) isReady(item ReadyItem) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ready := range r.ready {
		if ready == item {
			return true
		}
	}
	return false
}

// Ready 返回当前就绪列表（测试与日志用）。
func (r *Runner) Ready() []ReadyItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ReadyItem(nil), r.ready...)
}

func (r *Runner) checkItem(ctx context.Context, item CheckItem) (*CheckReport, *ReadyItem, error) {
	if !ident.ValidTenantSlug(item.TenantSlug) {
		// 服务端会忽略不认识的 slug，这一项无从上报；不回显原值
		r.Log.Warn("the server sent a keystore check item with a malformed tenant slug; skipping it")
		return nil, nil, nil
	}
	report := &CheckReport{TenantSlug: item.TenantSlug, KeystoreVersion: item.KeystoreVersion, Decrypt: "failed", TrialSign: "pending"}
	fail := func(msg string) (*CheckReport, *ReadyItem, error) {
		m := cleanText(msg, 300)
		report.Error = &m
		return report, nil, nil
	}
	switch {
	case item.KeystoreVersion < 0:
		return fail("the server's keystore record has a malformed keystoreVersion")
	case !ident.ValidPackageName(item.PackageName):
		return fail("the server's keystore record has a malformed packageName")
	case !fingerprint.Valid(item.CertificateSHA256):
		return fail("the server's keystore record has a malformed certificateSha256")
	case item.Box.ValidateShape() != nil:
		return fail("the server's keystore box is malformed")
	}
	material, err := openKeystore(item.Box, r.Keys, expectedIdentity{item.TenantSlug, item.PackageName, item.CertificateSHA256})
	if err != nil {
		return fail(err.Error())
	}
	report.Decrypt = "ok"
	conf, ok, err := r.Store.Confirmation(item.PackageName, item.CertificateSHA256)
	if err != nil {
		return nil, nil, err
	}
	if !ok || conf.TenantSlug != item.TenantSlug {
		return report, nil, nil
	}
	report.Confirmed = true
	digest := conf.TrustRootsDigest
	report.ConfirmedTrustRootsDigest = &digest

	trial := r.trialSign(ctx, item, material, conf)
	if !trial.ok {
		report.TrialSign = "failed"
		msg := cleanText(trial.msg, 300)
		report.Error = &msg
		return report, nil, nil
	}
	report.TrialSign = "ok"
	if item.TrustRootsDigest == nil || *item.TrustRootsDigest != conf.TrustRootsDigest {
		// 服务端的信任根与本机确认值不同：不就绪，等运维重新确认
		return report, nil, nil
	}
	return report, &ReadyItem{TenantSlug: conf.TenantSlug, PackageName: conf.PackageName, CertificateSHA256: conf.CertificateSHA256, TrustRootsDigest: conf.TrustRootsDigest}, nil
}

func (r *Runner) trialSign(ctx context.Context, item CheckItem, material keystoreMaterial, conf records.Confirmation) trialResult {
	boxJSON, _ := json.Marshal(item.Box)
	sum := sha256.Sum256(append(boxJSON, []byte(strconv.FormatInt(conf.MinSDK, 10)+conf.CertificateSHA256)...))
	key := hex.EncodeToString(sum[:])
	if cached, ok := r.trials[key]; ok && (cached.ok || time.Since(cached.at) < 10*time.Minute) {
		return cached
	}
	result := trialResult{ok: true, at: time.Now()}
	if err := TrialSign(ctx, r.Signer, r.Config.RuntimeDir, material, conf.MinSDK, conf.CertificateSHA256); err != nil {
		result = trialResult{ok: false, msg: "trial signing failed: " + err.Error(), at: time.Now()}
		r.Log.Warn("trial signing failed", "tenant", conf.TenantSlug, "error", err)
	}
	r.trials[key] = result
	return result
}

// TrialSign 现场合成一个最小 APK（别的包名、无代码），用这把密钥签名并复核证书。
// 输入输出都在运行时目录的临时子目录里，结束即删除，不上传、不保留。
func TrialSign(ctx context.Context, s APKSigner, runtimeDir string, material keystoreMaterial, minSDK int64, certificateSHA256 string) (err error) {
	unsigned, err := BuildTrialAPK(minSDK)
	if err != nil {
		return err
	}
	files, err := writeRuntimeFiles(runtimeDir, material)
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := files.Remove(); removeErr != nil && err == nil {
			err = fmt.Errorf("remove the plaintext keystore after the trial signature: %w", removeErr)
		}
	}()
	in := filepath.Join(files.Dir, "trial-unsigned.apk")
	out := filepath.Join(files.Dir, "trial-signed.apk")
	if err := securefs.WriteFileExclusive(in, unsigned); err != nil {
		return err
	}
	if err := s.Sign(ctx, SignParams{
		KeystorePath: files.KeystorePath, KeyAlias: material.Plain.KeyAlias,
		StorePasswordFile: files.StorePasswordFile, KeyPasswordFile: files.KeyPasswordFile,
		MinSDK: minSDK, In: in, Out: out, TmpDir: files.Dir,
	}); err != nil {
		return err
	}
	result, err := s.Verify(ctx, out, minSDK, files.Dir)
	if err != nil {
		return err
	}
	return CheckSigned(result, certificateSHA256)
}

// ---- 签名任务 ----

type outcomeKind int

const (
	outcomeDone outcomeKind = iota
	outcomeStale
	outcomeShutdown
	outcomeDeferred
	outcomeViolation
	outcomeTransient
	outcomeRevoked
)

type outcome struct {
	kind   outcomeKind
	code   string
	detail string
	fatal  error
}

func deferred(code, format string, args ...any) outcome {
	return outcome{kind: outcomeDeferred, code: code, detail: fmt.Sprintf(format, args...)}
}

func violationOutcome(code, format string, args ...any) outcome {
	return outcome{kind: outcomeViolation, code: code, detail: fmt.Sprintf(format, args...)}
}

func transient(code, format string, args ...any) outcome {
	return outcome{kind: outcomeTransient, code: code, detail: fmt.Sprintf(format, args...)}
}

func (r *Runner) handle(ctx context.Context, claim *Claim) error {
	jobID, attempt := claim.Job.ID, claim.Job.SignAttempt
	log := r.Log.With("job", jobID, "signAttempt", attempt)
	if !ident.ValidServerID(jobID) || attempt < 1 {
		// id 不合法时连上报的 URL 都拼不出来：不上报，等服务端心跳超时回收
		log = r.Log
		log.Error("the server sent a claim with a malformed job id or sign attempt; ignoring it")
		return nil
	}
	jobCtx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.heartbeat(jobCtx, cancel, jobID, attempt, log)
	}()
	log.Info("signing job claimed", "tenant", claim.Job.TenantSlug, "buildNumber", claim.Job.BuildNumber)
	out := r.sign(jobCtx, claim, log)
	if cause := context.Cause(jobCtx); errors.Is(cause, errRevoked) && out.kind != outcomeDone {
		out = outcome{kind: outcomeRevoked, fatal: errRevoked}
	} else if errors.Is(cause, errStale) && out.kind != outcomeDone {
		out = outcome{kind: outcomeStale, fatal: out.fatal}
	} else if ctx.Err() != nil && out.kind != outcomeDone && out.kind != outcomeStale && out.kind != outcomeRevoked {
		out = outcome{kind: outcomeShutdown, fatal: out.fatal}
	}
	cancel(errJobFinished)
	wg.Wait()
	if err := securefs.RemoveContents(r.Config.RuntimeDir); err != nil {
		log.Error("could not clear the runtime directory after the job", "error", err)
		if out.fatal == nil {
			out.fatal = fmt.Errorf("clear the runtime directory: %w", err)
		}
	}
	if err := securefs.RemoveContents(r.workDir()); err != nil {
		log.Warn("could not clear the work directory", "error", err)
	}
	r.report(ctx, claim, out, log)
	return out.fatal
}

func (r *Runner) heartbeat(ctx context.Context, cancel context.CancelCauseFunc, jobID string, attempt int, log *slog.Logger) {
	ticker := time.NewTicker(r.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := r.API.Heartbeat(ctx, jobID, attempt)
			if IsRevoked(err) {
				log.Error("heartbeat says this signing gate's machine token is revoked; abandoning the job immediately")
				cancel(errRevoked)
				return
			}
			if IsStale(err) {
				log.Warn("heartbeat says the sign attempt is stale; abandoning the job immediately")
				cancel(errStale)
				return
			}
			if err != nil && ctx.Err() == nil {
				log.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

func (r *Runner) report(ctx context.Context, claim *Claim, out outcome, log *slog.Logger) {
	jobID, attempt := claim.Job.ID, claim.Job.SignAttempt
	detail := cleanText(out.detail, 500)
	var err error
	switch out.kind {
	case outcomeDone:
		return
	case outcomeStale:
		log.Warn("sign attempt is stale; nothing to report")
		return
	case outcomeRevoked:
		log.Error("the machine token is revoked; nothing can be reported")
		return
	case outcomeShutdown:
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		err = r.API.Release(shutdownCtx, jobID, attempt, "SIGNER_SHUTTING_DOWN", "the signing gate is stopping; the job goes back to waiting for signature")
	case outcomeDeferred:
		log.Warn("cannot sign yet", "code", out.code, "detail", detail)
		err = r.retry(ctx, "release", func(ctx context.Context) error { return r.API.Release(ctx, jobID, attempt, out.code, detail) })
	case outcomeViolation:
		log.Error("refusing to sign", "code", out.code, "detail", detail)
		err = r.retry(ctx, "reject", func(ctx context.Context) error {
			return r.API.Reject(ctx, jobID, attempt, rejectViolation, out.code, detail)
		})
	case outcomeTransient:
		log.Warn("transient failure", "code", out.code, "detail", detail)
		err = r.retry(ctx, "reject", func(ctx context.Context) error {
			return r.API.Reject(ctx, jobID, attempt, rejectTransient, out.code, detail)
		})
	}
	if err != nil {
		log.Error("could not report the outcome; the server will reclaim the job after the heartbeat timeout", "error", err)
	}
}

// retry 对临时错误原地有限重试；409 过期与其它错误立即返回。
func (r *Runner) retry(ctx context.Context, op string, fn func(context.Context) error) error {
	for i := 0; ; i++ {
		err := fn(ctx)
		if err == nil || IsStale(err) || !IsTransient(err) || i >= len(r.RetryDelays) || ctx.Err() != nil {
			return err
		}
		r.Log.Warn(op+" failed; retrying", "error", err, "attempt", i+1)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(r.RetryDelays[i]):
		}
	}
}

func (r *Runner) sign(ctx context.Context, c *Claim, log *slog.Logger) outcome {
	job := c.Job
	if err := validateClaim(c); err != nil {
		return violationOutcome("CLAIM_INVALID", "the signing claim is malformed: %v", err)
	}
	role, err := r.Store.Role()
	if err != nil {
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}
	if role.Role != records.RolePrimary {
		return deferred("SIGNER_NOT_PRIMARY", "this signing gate is not the primary in its local records")
	}
	pkg, cert := c.Keystore.PackageName, c.Keystore.CertificateSHA256
	conf, ok, err := r.Store.Confirmation(pkg, cert)
	if err != nil {
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}
	if !ok {
		return deferred("CERTIFICATE_NOT_CONFIRMED", "this signing gate has not confirmed %s with certificate %s (signer confirm)", pkg, cert)
	}
	if conf.TenantSlug != job.TenantSlug {
		return violationOutcome("TENANT_MISMATCH", "package %s with this certificate is confirmed for tenant %s, not %s", pkg, conf.TenantSlug, job.TenantSlug)
	}
	if c.TrustRootsDigest != conf.TrustRootsDigest {
		return deferred("TRUST_ROOTS_NOT_CONFIRMED", "the tenant's trust roots changed since they were confirmed on this signing gate (signer confirm)")
	}
	if c.Keystore.Box.RecipientSHA256 != r.Keys.X25519SHA256() {
		return transient("KEYSTORE_NOT_FOR_THIS_SIGNER", "the claim carries a keystore box for a different signing gate")
	}
	if !r.isReady(ReadyItem{TenantSlug: job.TenantSlug, PackageName: pkg, CertificateSHA256: cert, TrustRootsDigest: c.TrustRootsDigest}) {
		// 服务端只该派本机声明就绪的租户；试签没过或刚换了确认值时不签
		return deferred("SIGNER_NOT_READY", "this signing gate has not declared tenant %s with this package, certificate and trust roots ready", job.TenantSlug)
	}
	view, err := r.Store.SignedState(pkg, cert, job.ID, job.UnsignedSHA256)
	if err != nil {
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}
	if e := view.Existing; e != nil && (e.PackageName != pkg || e.CertificateSHA256 != cert || e.UnsignedSHA256 != job.UnsignedSHA256 || e.VersionCode != job.BuildNumber) {
		return violationOutcome("RESERVATION_CONFLICT", "job %s already holds a reservation for a different package or versionCode on this signing gate", job.ID)
	}
	if e := view.Existing; e != nil && e.Status == records.StatusCompleted {
		// 本机已经把这个任务交付成发布，服务端又派回来（例如服务端数据库回滚）：不重签，交给人查
		return violationOutcome("JOB_ALREADY_COMPLETED", "this signing gate already delivered job %s as release %s", job.ID, e.ReleaseID)
	}
	builders, err := r.Store.TrustedBuilders()
	if err != nil {
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}

	// 第 3 条：下载并核对摘要
	unsignedPath := filepath.Join(r.workDir(), fmt.Sprintf("%s-s%d-unsigned.apk", job.ID, job.SignAttempt))
	var dl Download
	err = r.retry(ctx, "download", func(ctx context.Context) error {
		f, err := os.OpenFile(unsignedPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return &ProtocolError{Msg: "cannot create the download file: " + err.Error()}
		}
		dl, err = r.API.DownloadUnsigned(ctx, job.ID, job.SignAttempt, f, job.UnsignedSize)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		return err
	})
	switch {
	case IsRevoked(err):
		return outcome{kind: outcomeRevoked, fatal: errRevoked}
	case IsStale(err):
		return outcome{kind: outcomeStale}
	case err != nil:
		return transient("DOWNLOAD_FAILED", "downloading the unsigned package failed: %v", err)
	}
	if dl.Size != job.UnsignedSize {
		return violationOutcome("UNSIGNED_SIZE_MISMATCH", "the downloaded package is %d bytes, the job says %d", dl.Size, job.UnsignedSize)
	}
	if dl.SHA256 != job.UnsignedSHA256 || (dl.HeaderPresent && dl.HeaderSHA256 != job.UnsignedSHA256) {
		return violationOutcome("UNSIGNED_SHA256_MISMATCH", "the downloaded package sha256 %s does not match the job's %s", dl.SHA256, job.UnsignedSHA256)
	}

	// 第 2、4–16 条：检查进程
	input := policy.Input{
		Version: policy.InputVersion,
		Job: policy.Job{ID: job.ID, TenantSlug: job.TenantSlug, Version: job.Version, BuildNumber: job.BuildNumber,
			Attempt: job.Attempt, SignAttempt: job.SignAttempt, CommitSHA: job.CommitSHA, UnsignedSHA256: job.UnsignedSHA256,
			UnsignedSize: job.UnsignedSize, SBOMSHA256: job.SBOMSHA256, NativeFingerprint: job.NativeFingerprint},
		Provenance: policy.Provenance{Statement: c.Provenance.Statement, Signature: c.Provenance.Signature,
			BuilderID: c.Provenance.BuilderID, BuilderPublicKey: c.Provenance.BuilderPublicKey},
		Confirmed: policy.Confirmed{TenantSlug: conf.TenantSlug, PackageName: conf.PackageName, CertificateSHA256: conf.CertificateSHA256,
			TrustRoots: conf.TrustRoots, MinSDK: conf.MinSDK, TargetSDK: conf.TargetSDK, FirstSignMaxVersionCode: conf.FirstSignMaxVersionCode},
		Signed:  policy.Signed{HasMax: view.HasMax, MaxVersionCode: view.Max},
		Limits:  policy.Limits{MaxVersionCodeJump: r.Config.MaxVersionCodeJump, MaxVersionCode: r.Config.MaxVersionCode},
		APKSize: dl.Size,
	}
	for _, b := range builders {
		input.TrustedBuilders = append(input.TrustedBuilders, policy.TrustedBuilder{ID: b.BuilderID, Ed25519PublicKeySHA256: b.Ed25519PublicKeySHA256})
	}
	verdict, err := r.Checker.Check(ctx, input, unsignedPath)
	if ctx.Err() != nil {
		return transient("CHECKER_FAILED", "the check was interrupted")
	}
	if err != nil {
		return transient("CHECKER_FAILED", "the checker produced no verdict: %v", err)
	}
	if !verdict.OK {
		return violationOutcome(verdict.Code, "%s", verdict.Detail)
	}
	f := verdict.Facts
	if verdict.CheckedSHA256 != dl.SHA256 || f == nil || f.PackageName != conf.PackageName || f.VersionCode != job.BuildNumber ||
		f.VersionName != job.Version || f.NativeFingerprint != job.NativeFingerprint {
		return transient("CHECKER_FAILED", "the checker's verdict does not describe the downloaded package")
	}

	// 预留（解密前落盘）。递增、跳号、绝对上限、首签上限在记录的锁里再核一遍：
	// 检查进程看到的已签最大值可能已经过时（另一个进程刚写了记录）。
	existing, err := r.Store.Reserve(records.Reservation{JobID: job.ID, SignAttempt: job.SignAttempt, TenantSlug: conf.TenantSlug,
		PackageName: conf.PackageName, CertificateSHA256: conf.CertificateSHA256, VersionCode: job.BuildNumber, UnsignedSHA256: dl.SHA256},
		records.ReserveLimits{MaxVersionCode: r.Config.MaxVersionCode, MaxJump: r.Config.MaxVersionCodeJump, FirstSignMaxVersionCode: conf.FirstSignMaxVersionCode})
	switch {
	case errors.Is(err, records.ErrVersionCodeTaken):
		return violationOutcome("VERSION_CODE_ALREADY_RESERVED", "versionCode %d of %s is already reserved on this signing gate by another job or another unsigned package", job.BuildNumber, pkg)
	case errors.Is(err, records.ErrJobConflict):
		return violationOutcome("RESERVATION_CONFLICT", "job %s already holds a different reservation on this signing gate", job.ID)
	case errors.Is(err, records.ErrVersionCodeNotIncreasing):
		return violationOutcome("VERSION_CODE_NOT_INCREASING", "versionCode %d of %s is not above the highest already signed", job.BuildNumber, pkg)
	case errors.Is(err, records.ErrVersionCodeOutOfBounds):
		return violationOutcome("VERSION_CODE_OUT_OF_BOUNDS", "versionCode %d of %s is above the absolute, jump or first-signature limit", job.BuildNumber, pkg)
	case err != nil:
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}
	if existing != nil {
		if existing.Status == records.StatusCompleted {
			return violationOutcome("JOB_ALREADY_COMPLETED", "this signing gate already delivered job %s as release %s", job.ID, existing.ReleaseID)
		}
		log.Info("resuming an existing reservation for this job and unsigned package", "status", existing.Status)
	}
	// MarkSigned 之前失败：签出的包（如果有）还没离开本机、随工作目录清掉，释放预留，
	// 免得这个 versionCode 永久占住。已经记过签名（status=signed）的预留不能释放：
	// 那个包可能已经在服务端手里。
	releasable := existing == nil || existing.Status == records.StatusReserved
	unsent := func(o outcome) outcome {
		if !releasable {
			return o
		}
		if _, err := r.Store.Abandon(job.ID, autoReleaseOperator, "released automatically, no signed package left this machine: "+o.code); err != nil {
			log.Error("could not release the local reservation", "error", err)
			if o.fatal == nil {
				o.fatal = fmt.Errorf("release the local reservation of job %s: %w", job.ID, err)
			}
			return o
		}
		log.Info("released the local reservation; no signed package left this machine", "code", o.code)
		return o
	}

	// 第 17 条：解密并与本机确认值比对；别名取密文里的
	material, err := openKeystore(c.Keystore.Box, r.Keys, expectedIdentity{conf.TenantSlug, conf.PackageName, conf.CertificateSHA256})
	if err != nil {
		var ke *keystoreError
		if errors.As(err, &ke) {
			return unsent(violationOutcome(ke.Code, "%s", ke.Msg))
		}
		return unsent(violationOutcome("KEYSTORE_UNUSABLE", "%v", err))
	}
	// 交给 apksigner 的必须是检查进程检查过的那份字节
	if sum, size, err := hashPath(unsignedPath); err != nil || sum != dl.SHA256 || size != dl.Size {
		return unsent(transient("UNSIGNED_CHANGED_BEFORE_SIGNING", "the unsigned package on disk is no longer the checked one"))
	}

	// 第 18 条：签名
	signedPath := filepath.Join(r.workDir(), fmt.Sprintf("%s-s%d-signed.apk", job.ID, job.SignAttempt))
	_ = os.Remove(signedPath)
	files, err := writeRuntimeFiles(r.Config.RuntimeDir, material)
	if err != nil {
		return unsent(transient("RUNTIME_FILES_FAILED", "writing the keystore into the runtime directory failed: %v", err))
	}
	if ctx.Err() != nil {
		_ = files.Remove()
		return unsent(transient("SIGNER_INTERRUPTED", "the job was interrupted before signing"))
	}
	signErr := r.Signer.Sign(ctx, SignParams{
		KeystorePath: files.KeystorePath, KeyAlias: material.Plain.KeyAlias,
		StorePasswordFile: files.StorePasswordFile, KeyPasswordFile: files.KeyPasswordFile,
		MinSDK: conf.MinSDK, In: unsignedPath, Out: signedPath, TmpDir: files.Dir,
	})
	material = keystoreMaterial{}
	if err := files.Remove(); err != nil {
		return unsent(outcome{kind: outcomeTransient, code: "RUNTIME_FILES_FAILED", detail: "removing the plaintext keystore failed", fatal: fmt.Errorf("remove plaintext keystore files: %w", err)})
	}
	if signErr != nil {
		return unsent(transient("APKSIGNER_FAILED", "%v", signErr))
	}

	// 第 19 条：复核
	result, err := r.Signer.Verify(ctx, signedPath, conf.MinSDK, "")
	if err != nil {
		return unsent(transient("SIGNED_VERIFY_FAILED", "%v", err))
	}
	if err := CheckSigned(result, conf.CertificateSHA256); err != nil {
		return unsent(transient("SIGNED_VERIFY_FAILED", "%v", err))
	}
	signedSHA, signedSize, err := hashPath(signedPath)
	if err != nil {
		return unsent(transient("SIGNED_VERIFY_FAILED", "reading the signed package failed: %v", err))
	}
	if ctx.Err() != nil {
		return unsent(transient("SIGNER_INTERRUPTED", "the job was interrupted before the signed package was recorded"))
	}
	// 包离开本机之前落盘：从这里起这条预留不能再释放
	if err := r.Store.MarkSigned(job.ID, dl.SHA256, signedSHA); err != nil {
		return outcome{kind: outcomeDeferred, code: "SIGNER_RECORDS_UNAVAILABLE", detail: "local records are unavailable", fatal: err}
	}

	return r.deliver(ctx, c, conf, dl.SHA256, f.NativeFingerprint, signedPath, signedSHA, signedSize, log)
}

// deliver 上传签名包并提交完成。服务端每次上传换一个对象、complete 只认最后一次上传：
// SIGNED_ARTIFACT_REPLACED 重新 complete（retry 里当临时错误），SIGNED_ARTIFACT_MISSING 重新上传。
func (r *Runner) deliver(ctx context.Context, c *Claim, conf records.Confirmation, unsignedSHA, nativeFingerprint, signedPath, signedSHA string, signedSize int64, log *slog.Logger) outcome {
	job := c.Job
	var releaseID string
	for round := 1; ; round++ {
		var up Upload
		err := r.retry(ctx, "upload", func(ctx context.Context) error {
			var err error
			up, err = r.API.UploadSigned(ctx, job.ID, job.SignAttempt, signedPath)
			return err
		})
		switch {
		case IsRevoked(err):
			return outcome{kind: outcomeRevoked, fatal: errRevoked}
		case IsStale(err):
			return outcome{kind: outcomeStale}
		case err != nil:
			return transient("UPLOAD_FAILED", "uploading the signed package failed: %v", err)
		case up.SHA256 != signedSHA || up.Size != signedSize:
			return transient("UPLOAD_MISMATCH", "the server stored %d bytes with sha256 %s, but the signed package is %d bytes with sha256 %s", up.Size, cleanText(up.SHA256, 64), signedSize, signedSHA)
		}

		err = r.retry(ctx, "complete", func(ctx context.Context) error {
			var err error
			releaseID, err = r.API.Complete(ctx, job.ID, job.SignAttempt, CompleteRequest{
				SignedSHA256: signedSHA, SignedSize: signedSize, CertificateSHA256: conf.CertificateSHA256,
				UnsignedSHA256: unsignedSHA, NativeFingerprint: nativeFingerprint,
			})
			return err
		})
		if err == nil {
			break
		}
		var apiErr *APIError
		switch {
		case IsRevoked(err):
			return outcome{kind: outcomeRevoked, fatal: errRevoked}
		case IsStale(err):
			return outcome{kind: outcomeStale}
		case errors.As(err, &apiErr) && apiErr.Code == codeSignedArtifactMissing && round < maxUploadRounds:
			log.Warn("the server lost the signed upload; uploading again", "round", round)
		case errors.As(err, &apiErr) && (apiErr.Code == codeSignResultMismatch || apiErr.Code == codeSignedArtifactMismatch):
			return violationOutcome("SERVER_REJECTED_SIGNED_PACKAGE", "the server refused the signed package: %s %s", apiErr.Code, apiErr.Detail)
		default:
			return transient("COMPLETE_FAILED", "completing the job failed: %v", err)
		}
	}
	if !records.ValidReleaseID(releaseID) {
		return transient("COMPLETE_FAILED", "the server returned a malformed release id")
	}
	switch err := r.Store.Complete(job.ID, unsignedSHA, signedSHA, releaseID); {
	case errors.Is(err, records.ErrAlreadyCompleted):
		log.Error("the server completed the job, but the local record already holds a different release for it", "releaseId", releaseID)
	case err != nil:
		log.Error("the job is complete on the server but the local record could not be written", "error", err, "releaseId", releaseID)
		return outcome{kind: outcomeDone, fatal: err}
	}
	log.Info("signed and delivered", "releaseId", releaseID, "signedSha256", signedSHA)
	return outcome{kind: outcomeDone}
}

func hashPath(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// validateClaim 严格校验服务端派下来的认领。不合格的字段只报字段名。
func validateClaim(c *Claim) error {
	j := c.Job
	switch {
	case !ident.ValidTenantSlug(j.TenantSlug):
		return errors.New("job.tenantSlug")
	case j.Platform != "android":
		return errors.New("job.platform")
	case j.Version == "" || len(j.Version) > 64 || !ident.PrintableASCII(j.Version) || containsSpace(j.Version):
		return errors.New("job.version")
	case j.BuildNumber < 1 || j.BuildNumber > records.MaxVersionCode:
		return errors.New("job.buildNumber")
	case j.Attempt < 1:
		return errors.New("job.attempt")
	case !commitPattern.MatchString(j.CommitSHA):
		return errors.New("job.commitSha")
	case !fingerprint.Valid(j.UnsignedSHA256):
		return errors.New("job.unsignedSha256")
	case j.UnsignedSize < 1 || j.UnsignedSize > apk.DefaultLimits().MaxFileSize:
		return errors.New("job.unsignedSize")
	case !fingerprint.Valid(j.SBOMSHA256):
		return errors.New("job.sbomSha256")
	case !nativeFingerprintPattern.MatchString(j.NativeFingerprint):
		return errors.New("job.nativeFingerprint")
	}
	p := c.Provenance
	pub, err := base64.StdEncoding.Strict().DecodeString(p.BuilderPublicKey)
	switch {
	case !ident.ValidServerID(p.BuilderID):
		return errors.New("provenance.builderId")
	case err != nil || len(pub) != 32:
		return errors.New("provenance.builderPublicKey")
	case p.Statement == "" || p.Signature == "" || len(p.Statement) > 64<<10 || len(p.Signature) > 256:
		return errors.New("provenance.statement or provenance.signature")
	}
	k := c.Keystore
	switch {
	case k.KeystoreVersion < 0:
		return errors.New("keystore.keystoreVersion")
	case !ident.ValidPackageName(k.PackageName):
		return errors.New("keystore.packageName")
	case !fingerprint.Valid(k.CertificateSHA256):
		return errors.New("keystore.certificateSha256")
	case k.Box.ValidateShape() != nil:
		return errors.New("keystore.box")
	case !fingerprint.Valid(c.TrustRootsDigest):
		return errors.New("trustRootsDigest")
	}
	return nil
}

func containsSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return true
		}
	}
	return false
}
