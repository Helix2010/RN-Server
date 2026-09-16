package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/internal/checkwire"
	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/policy"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/releasekey"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

const (
	testToken     = "rnm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testAlias     = "anyfun-release"
	testMachine   = "amos-signer-a"
	serverAlias   = "server-claims-this-alias"
	testReleaseID = "rel_fixtureRELEASE01"
)

var (
	tenantKeyOnce sync.Once
	tenantKey     releasekey.Result
	tenantKeyErr  error
)

// sharedTenantKey 生成一次租户签名密钥（RSA 2048，测试用），所有测试共用。
func sharedTenantKey(t testing.TB) releasekey.Result {
	t.Helper()
	tenantKeyOnce.Do(func() {
		tenantKey, tenantKeyErr = releasekey.Generate(releasekey.Params{Alias: testAlias, CommonName: "AnyFun Test", KeyBits: 2048, ValidityYears: 30})
	})
	if tenantKeyErr != nil {
		t.Fatal(tenantKeyErr)
	}
	return tenantKey
}

// ---- 假服务端（约定 5.3）----

type call struct {
	Job, Kind, Code, Detail string
	Attempt                 string
}

// problem 是假服务端按脚本返回的错误。
type problem struct {
	status int
	code   string
}

type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	keyStatus     string
	activeKey     string
	activeEdKey   string
	checksStatus  int
	items         []map[string]any
	reports       [][]CheckReport
	claims        []map[string]any // 依次派发；用完返回 204
	claimBodies   [][]ReadyItem
	apks          map[string][]byte // jobId → 未签名包
	headerSHA     map[string]string
	heartbeats    map[string]int
	staleJobs     map[string]bool
	uploads       map[string][]byte // 每个任务最后一次上传（服务端只认最后一次）
	uploadCount   map[string]int
	completes     []CompleteRequest
	completeFails map[string][]problem // jobId → 依次返回的错误
	revoked       bool                 // 令牌被吊销：一切请求 401 MACHINE_REVOKED
	authRequired  bool                 // 令牌失效：一切请求 401 MACHINE_AUTH_REQUIRED
	repeatClaim   map[string]any       // 非 nil 时每次认领都派这一条（模拟服务端没有冷却）
	claimTimes    []time.Time
	releases      []call
	rejects       []call
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, keyStatus: "active", apks: map[string][]byte{}, headerSHA: map[string]string{}, heartbeats: map[string]int{},
		staleJobs: map[string]bool{}, uploads: map[string][]byte{}, uploadCount: map[string]int{}, completeFails: map[string][]problem{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/signer/public-key", f.publicKey)
	mux.HandleFunc("GET /v1/signer/keystore-checks", f.getChecks)
	mux.HandleFunc("POST /v1/signer/keystore-checks", f.postChecks)
	mux.HandleFunc("POST /v1/signer/claim", f.claim)
	mux.HandleFunc("POST /v1/signer/jobs/{id}/heartbeat", f.heartbeat)
	mux.HandleFunc("GET /v1/signer/jobs/{id}/unsigned/download", f.download)
	mux.HandleFunc("PUT /v1/signer/jobs/{id}/signed/upload", f.upload)
	mux.HandleFunc("POST /v1/signer/jobs/{id}/complete", f.complete)
	mux.HandleFunc("POST /v1/signer/jobs/{id}/release", f.release)
	mux.HandleFunc("POST /v1/signer/jobs/{id}/reject", f.reject)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-machine-token") != testToken {
			problemJSON(w, 401, "MACHINE_AUTH_REQUIRED", "no token")
			return
		}
		f.mu.Lock()
		revoked, authRequired := f.revoked, f.authRequired
		f.mu.Unlock()
		if revoked {
			problemJSON(w, 401, "MACHINE_REVOKED", "revoked")
			return
		}
		if authRequired {
			problemJSON(w, 401, "MACHINE_AUTH_REQUIRED", "unknown token")
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func problemJSON(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("content-type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "status": status, "code": code, "detail": detail})
}

// decodeStrict 按约定的字段名严格解码请求体：签名闸多发或拼错一个字段都会失败。
func (f *fakeServer) decodeStrict(r *http.Request, v any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		f.t.Errorf("%s %s: request body violates the contract: %v", r.Method, r.URL.Path, err)
		return false
	}
	return true
}

func (f *fakeServer) attempt(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("x-sign-attempt") == "" {
		f.t.Errorf("%s %s without x-sign-attempt", r.Method, r.URL.Path)
	}
	if f.staleJobs[id] {
		problemJSON(w, 409, "SIGN_ATTEMPT_STALE", "stale")
		return id, false
	}
	return id, true
}

func (f *fakeServer) publicKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		X25519PublicKey   string  `json:"x25519PublicKey"`
		Ed25519PublicKey  string  `json:"ed25519PublicKey"`
		RotationSignature *string `json:"rotationSignature"`
	}
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	x, _ := base64.StdEncoding.DecodeString(body.X25519PublicKey)
	ed, _ := base64.StdEncoding.DecodeString(body.Ed25519PublicKey)
	xs, eds := sha(x), sha(ed)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.activeKey != "" {
		xs, eds = f.activeKey, f.activeEdKey
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"machineId": "mch_signerA0001", "status": f.keyStatus, "publicKeySha256": xs, "ed25519PublicKeySha256": eds, "pendingPublicKeySha256": nil})
}

func (f *fakeServer) getChecks(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.checksStatus != 0 {
		problemJSON(w, f.checksStatus, "MACHINE_KEY_NOT_ACCEPTED", "pending")
		return
	}
	items := f.items
	if items == nil {
		items = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"machineId": "mch_signerA0001", "signerRole": "primary", "items": items})
}

func (f *fakeServer) postChecks(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Items []CheckReport `json:"items"`
	}
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	f.mu.Lock()
	f.reports = append(f.reports, body.Items)
	f.mu.Unlock()
	w.WriteHeader(204)
}

func (f *fakeServer) claim(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ready []ReadyItem `json:"ready"`
	}
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claimBodies = append(f.claimBodies, body.Ready)
	f.claimTimes = append(f.claimTimes, time.Now())
	if f.repeatClaim != nil {
		_ = json.NewEncoder(w).Encode(f.repeatClaim)
		return
	}
	if len(f.claims) == 0 {
		w.WriteHeader(204)
		return
	}
	next := f.claims[0]
	f.claims = f.claims[1:]
	_ = json.NewEncoder(w).Encode(next)
}

func (f *fakeServer) heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	f.heartbeats[id]++
	f.mu.Unlock()
	w.WriteHeader(204)
}

func (f *fakeServer) download(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	raw, header := f.apks[id], f.headerSHA[id]
	f.mu.Unlock()
	if raw == nil {
		problemJSON(w, 424, "UNSIGNED_ARTIFACT_MISSING", "the unsigned artifact is gone")
		return
	}
	if header == "" {
		header = sha(raw)
	}
	w.Header().Set("x-content-sha256", header)
	w.Header().Set("content-type", "application/octet-stream")
	w.Header().Set("content-length", strconv.Itoa(len(raw)))
	_, _ = w.Write(raw)
}

func (f *fakeServer) upload(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	if ct := r.Header.Get("content-type"); ct != "application/octet-stream" {
		f.t.Errorf("signed upload with content-type %q", ct)
		problemJSON(w, 415, "UPLOAD_CONTENT_TYPE_INVALID", "octet-stream only")
		return
	}
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.uploads[id] = raw
	f.uploadCount[id]++
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"sha256": sha(raw), "size": len(raw)})
}

func (f *fakeServer) complete(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	var body CompleteRequest
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fails := f.completeFails[id]; len(fails) > 0 {
		f.completeFails[id] = fails[1:]
		if fails[0].code == "SIGNED_ARTIFACT_MISSING" {
			delete(f.uploads, id)
		}
		problemJSON(w, fails[0].status, fails[0].code, "scripted failure")
		return
	}
	if uploaded := f.uploads[id]; sha(uploaded) != body.SignedSHA256 || int64(len(uploaded)) != body.SignedSize {
		problemJSON(w, 422, "SIGNED_ARTIFACT_MISMATCH", "complete does not describe the upload")
		return
	}
	f.completes = append(f.completes, body)
	_ = json.NewEncoder(w).Encode(map[string]any{"releaseId": testReleaseID})
}

func (f *fakeServer) release(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	var body struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	f.mu.Lock()
	f.releases = append(f.releases, call{Job: id, Code: body.Code, Detail: body.Detail, Attempt: r.Header.Get("x-sign-attempt")})
	f.mu.Unlock()
	w.WriteHeader(204)
}

func (f *fakeServer) reject(w http.ResponseWriter, r *http.Request) {
	id, ok := f.attempt(w, r)
	if !ok {
		return
	}
	var body struct {
		Kind   string `json:"kind"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if !f.decodeStrict(r, &body) {
		problemJSON(w, 400, "BAD", "bad")
		return
	}
	f.mu.Lock()
	f.rejects = append(f.rejects, call{Job: id, Kind: body.Kind, Code: body.Code, Detail: body.Detail, Attempt: r.Header.Get("x-sign-attempt")})
	f.mu.Unlock()
	w.WriteHeader(204)
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ---- 假 apksigner ----

type fakeSigner struct {
	t        *testing.T
	mu       sync.Mutex
	password string
	cert     string // Verify 报出的证书
	signs    []SignParams
	block    chan struct{} // 非 nil 时 Sign 等它关闭（或 ctx 取消）
	failSign error
	varying  bool // 每次签出的字节不同（模拟 ECDSA 签名的随机数）
}

// Sign 断言明文 keystore 与口令文件确实只在运行时目录里、权限正确、口令只以文件出现；
// 然后"签名"：输出 = 输入 + 固定后缀（确定性，便于幂等重签比对）。
func (s *fakeSigner) Sign(ctx context.Context, p SignParams) error {
	s.mu.Lock()
	s.signs = append(s.signs, p)
	block, failSign := s.block, s.failSign
	s.mu.Unlock()
	for _, path := range []string{p.KeystorePath, p.StorePasswordFile, p.KeyPasswordFile} {
		info, err := os.Lstat(path)
		if err != nil {
			s.t.Errorf("runtime file %s is missing during signing: %v", path, err)
			return err
		}
		if info.Mode().Perm() != 0o600 {
			s.t.Errorf("runtime file %s has mode %o", path, info.Mode().Perm())
		}
	}
	if info, err := os.Lstat(filepath.Dir(p.KeystorePath)); err != nil || info.Mode().Perm() != 0o700 {
		s.t.Errorf("runtime job directory is not 0700")
	}
	pass, _ := os.ReadFile(p.StorePasswordFile)
	if string(pass) != s.password+"\n" {
		s.t.Errorf("store password file does not hold the decrypted password")
	}
	if p.KeyAlias != testAlias {
		s.t.Errorf("signing used alias %q; it must come from the decrypted keystore, not the server", p.KeyAlias)
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if failSign != nil {
		return failSign
	}
	in, err := os.ReadFile(p.In)
	if err != nil {
		return err
	}
	if s.varying {
		s.mu.Lock()
		in = append(in, []byte(fmt.Sprintf("\nNONCE:%d", len(s.signs)))...)
		s.mu.Unlock()
	}
	return os.WriteFile(p.Out, append(in, []byte("\nFAKE-SIGNED-BY:"+s.cert)...), 0o600)
}

func (s *fakeSigner) Verify(_ context.Context, path string, minSDK int64, _ string) (VerifyResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return VerifyResult{}, err
	}
	i := bytes.LastIndex(raw, []byte("\nFAKE-SIGNED-BY:"))
	if i < 0 {
		return VerifyResult{}, errors.New("not signed")
	}
	cert := string(raw[i+len("\nFAKE-SIGNED-BY:"):])
	return VerifyResult{Verified: true, V2: true, V3: true, Signers: 1, Certificates: []string{cert}}, nil
}

func (s *fakeSigner) signCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.signs)
}

// ---- 进程内检查进程：走真实线协议 ----

type pipeChecker struct{}

func (pipeChecker) Check(ctx context.Context, in policy.Input, path string) (policy.Verdict, error) {
	f, err := os.Open(path)
	if err != nil {
		return policy.Verdict{}, err
	}
	defer f.Close()
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(checkwire.WriteRequest(pw, in, f)) }()
	var out, errOut bytes.Buffer
	if code := checkwire.Serve(pr, &out, &errOut); code != 0 {
		_ = pr.Close()
		return policy.Verdict{}, fmt.Errorf("checker exited %d: %s", code, errOut.String())
	}
	return checkwire.ReadVerdict(&out)
}

// ---- 签名闸与本机记录 ----

type harness struct {
	t       *testing.T
	cfg     Config
	keys    MachineKeys
	store   *records.Store
	builder testfixture.Builder
	key     releasekey.Result
	box     keystorebox.Box
	roots   trustroots.Roots
	digest  string
	server  *fakeServer
	signer  *fakeSigner
	runner  *Runner
	logs    *syncBuffer
}

type harnessOptions struct {
	role        records.Role // 默认主
	noConfirm   bool
	noBuilder   bool
	checker     Checker
	confirmMod  func(*records.Confirmation)
	serverRoots func(*trustroots.Roots)
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()
	stateDir, runtimeDir := t.TempDir(), t.TempDir()
	for _, d := range []string{stateDir, runtimeDir} {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys, created, err := InitState(stateDir, testMachine)
	if err != nil || !created {
		t.Fatalf("InitState: %v %v", created, err)
	}
	_, store, err := OpenRecords(stateDir, testMachine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := &harness{t: t, keys: keys, store: store, builder: testfixture.NewBuilder(t), key: sharedTenantKey(t), logs: &syncBuffer{}}
	h.cfg = Config{ServerURL: "http://127.0.0.1", MachineToken: testToken, Name: testMachine, StateDir: stateDir, RuntimeDir: runtimeDir,
		JavaHome: "/nonexistent", BuildToolsDir: "/nonexistent", CheckExec: "/nonexistent", MaxVersionCodeJump: 100, MaxVersionCode: 10_000_000}
	if opts.role != records.RoleStandby {
		must(t, store.SetRole(records.RoleChange{Role: records.RolePrimary, Mode: records.RoleModeInitial, Operator: "ops", Reason: "test primary"}))
	}
	if !opts.noBuilder {
		must(t, store.TrustBuilder(records.BuilderTrust{BuilderID: h.builder.ID, Ed25519PublicKeySHA256: h.builder.SHA256(), Name: "amos-builder", Operator: "ops"}))
	}
	h.roots = testfixture.Roots(t)
	h.digest, _ = trustroots.Digest(h.roots)
	if !opts.noConfirm {
		c := records.Confirmation{TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName, CertificateSHA256: h.key.CertificateSHA256,
			KeyAlias: testAlias, KeystoreVersion: 3, TrustRoots: h.roots, TrustRootsDigest: h.digest, MinSDK: 24, TargetSDK: 35,
			FirstSignMaxVersionCode: 100, ConfirmedBy: "ops"}
		if opts.confirmMod != nil {
			opts.confirmMod(&c)
		}
		must(t, store.Confirm(c))
	}
	h.box = h.sealBox(testfixture.TenantSlug, testfixture.PackageName, h.key.CertificateSHA256)
	h.server = newFakeServer(t)
	serverRoots := h.roots
	if opts.serverRoots != nil {
		opts.serverRoots(&serverRoots)
	}
	serverDigest, _ := trustroots.Digest(serverRoots)
	h.server.items = []map[string]any{{
		"tenantSlug": testfixture.TenantSlug, "keystoreVersion": 3, "packageName": testfixture.PackageName,
		"certificateSha256": h.key.CertificateSHA256, "keyAlias": serverAlias, "box": h.box,
		"trustRoots": serverRoots, "trustRootsDigest": serverDigest,
	}}
	h.signer = &fakeSigner{t: t, password: h.key.Password, cert: h.key.CertificateSHA256}
	checker := opts.checker
	if checker == nil {
		checker = pipeChecker{}
	}
	h.runner = &Runner{Config: h.cfg, Keys: keys, Store: store, API: NewHTTPClient(h.server.srv.URL, testToken, nil), Checker: checker,
		Signer: h.signer, Log: slogTo(h.logs), PollInterval: time.Millisecond, ChecksInterval: time.Hour, HeartbeatInterval: 20 * time.Millisecond,
		RetryDelays: []time.Duration{time.Millisecond, time.Millisecond}}
	if err := h.runner.Prepare(); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) sealBox(tenant, pkg, cert string) keystorebox.Box {
	h.t.Helper()
	box, err := keystorebox.Seal(keystorebox.Plaintext{
		Purpose: keystorebox.Purpose, TenantSlug: tenant, PackageName: pkg, CertificateSHA256: cert, KeyAlias: testAlias,
		Recipients: []string{h.keys.X25519SHA256()}, CreatedAt: "2026-09-16T00:00:00Z",
		P12Base64: base64.StdEncoding.EncodeToString(h.key.PKCS12), StorePassword: h.key.Password, KeyPassword: h.key.Password,
	}, h.keys.X25519PublicKey())
	if err != nil {
		h.t.Fatal(err)
	}
	return box
}

// claimFor 按约定 5.3 的字段名拼签名认领的 200 响应。
func (h *harness) claimFor(b testfixture.Build, signAttempt int, mutate func(map[string]any)) map[string]any {
	claim := map[string]any{
		"job": map[string]any{
			"id": b.JobID, "tenantSlug": testfixture.TenantSlug, "platform": "android", "version": testfixture.VersionName,
			"buildNumber": b.VersionCode, "attempt": b.Attempt, "signAttempt": signAttempt, "commitSha": testfixture.CommitSHA,
			"unsignedSha256": b.SHA256, "unsignedSize": len(b.APK), "sbomSha256": testfixture.SBOMSHA256,
			"nativeFingerprint": apktest.DefaultNativeFingerprint,
		},
		"provenance": map[string]any{
			"statement": b.Envelope.Statement, "signature": b.Envelope.Signature, "builderId": b.Builder.ID,
			"builderPublicKey": base64.StdEncoding.EncodeToString(b.Builder.Pub), "builderPublicKeySha256": b.Builder.SHA256(),
		},
		"keystore": map[string]any{
			"keystoreVersion": 3, "packageName": testfixture.PackageName, "certificateSha256": h.key.CertificateSHA256,
			"keyAlias": serverAlias, "box": h.box,
		},
		"trustRoots": h.roots, "trustRootsDigest": h.digest,
	}
	if mutate != nil {
		mutate(claim)
	}
	return claim
}

// enqueue 让服务端下一次认领派这条任务，并准备好下载内容。
func (h *harness) enqueue(b testfixture.Build, signAttempt int, mutate func(map[string]any)) {
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	h.server.claims = append(h.server.claims, h.claimFor(b, signAttempt, mutate))
	h.server.apks[b.JobID] = b.APK
}

func (h *harness) build(jobID string, vc int64, mutate func(*apktest.Spec)) testfixture.Build {
	return testfixture.NewBuild(h.t, h.builder, jobID, vc, mutate)
}

// runOnce 跑一轮。这些测试关心任务怎么处理，不关心节奏：先清掉上一条结果留下的认领退避。
func (h *harness) runOnce() bool {
	h.t.Helper()
	h.runner.mu.Lock()
	h.runner.claimNotBefore = time.Time{}
	h.runner.mu.Unlock()
	worked, err := h.runner.RunOnce(context.Background())
	if err != nil {
		h.t.Fatalf("RunOnce: %v\nlogs:\n%s", err, h.logs.String())
	}
	return worked
}

func (h *harness) assertRuntimeEmpty() {
	h.t.Helper()
	for _, dir := range []string{h.cfg.RuntimeDir, filepath.Join(h.cfg.StateDir, workDirName)} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			h.t.Fatal(err)
		}
		if len(entries) != 0 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			h.t.Fatalf("%s is not empty after the job: %s", dir, strings.Join(names, ", "))
		}
	}
}

// testLimits 与 harness 的 Config、确认值一致。
var testLimits = records.ReserveLimits{MaxVersionCode: 10_000_000, MaxJump: 100, FirstSignMaxVersionCode: 100}

func (h *harness) reservation(jobID string) records.Reservation {
	h.t.Helper()
	list, err := h.store.Reservations()
	if err != nil {
		h.t.Fatal(err)
	}
	var out *records.Reservation
	for i := range list {
		if list[i].JobID == jobID {
			out = &list[i]
		}
	}
	if out == nil {
		h.t.Fatalf("no reservation for %s: %+v", jobID, list)
	}
	return *out
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
