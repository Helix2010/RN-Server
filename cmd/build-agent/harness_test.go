package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/fakebuild"
	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/machinekey"
)

// runnerBinary 是测试开始时现编的 build-runner。控制进程的端到端测试以 BUILD_AGENT_RUNNER_USER=-
// 直接执行它（同一个用户），分用户的部分由 build-runner 自己的测试与权限断言覆盖。
var runnerBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "build-runner-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	runnerBinary = filepath.Join(dir, "build-runner")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", runnerBinary, "github.com/Helix2010/RN-Server/cmd/build-agent/build-runner")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build build-runner for the tests: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// testToken 形状合法、值是假的
const testToken = "rnm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

const testMachineID = "mch_builderTEST01"

type recordedCall struct {
	Method  string
	Path    string
	Query   string
	Attempt string
	Token   string
	Body    []byte
}

// fakeServer 按约定 5.2 的 JSON 扮演服务端的 /v1/build-agent。
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	keyStatus     string
	activeKey     ed25519.PublicKey
	pendingSHA    string
	omitMachineID bool
	claims        []func(http.ResponseWriter)
	heartbeatCode string
	calls         []recordedCall
	uploads       map[string][]byte
	// failNext 按路径后缀排好的错误响应，依次消耗
	failNext map[string][]injectedProblem
	// redirects 让以某个后缀结尾的请求回 307 到给定的源
	redirects map[string]string
	// authCode 非空时每个请求都回 401 这个码（MACHINE_REVOKED / MACHINE_AUTH_REQUIRED）
	authCode string
	// material 是 /v1/build-agent/ios-material 回的清单；materialBoxes 按
	// "kind/team/scope" 存密文原文
	material      []map[string]any
	materialBoxes map[string][]byte
	// materialTruncated：清单被服务端的 LIMIT 截断了（响应里 complete=false）
	materialTruncated bool
	// materialLayout 非空时，带了能力 tenant-signing-material 的清单请求回这个 layout（按租户的服务端）；
	// 租户格的密文按 "<租户>/kind/team/scope" 存在 materialBoxes 里
	materialLayout string
	// delays 让以某个后缀结尾的请求先睡这么久再回（不占着锁，心跳照常进来）
	delays map[string]time.Duration
}

func (f *fakeServer) delayFor(path string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	for suffix, delay := range f.delays {
		if strings.HasSuffix(path, suffix) {
			return delay
		}
	}
	return 0
}

func (f *fakeServer) setHeartbeatCode(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatCode = code
}

func (f *fakeServer) setKeyStatus(status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keyStatus = status
}

func (f *fakeServer) setOmitMachineID(omit bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.omitMachineID = omit
}

// loadIndependentBound 是"不应该要等这么久"的上限。测试里的假构建一旦没被中止就睡
// neverFinishesSeconds 秒，所以上限只要明显小于它、又远大于任何负载下的正常耗时即可——
// 断言不依赖机器快慢（整仓 go test -race ./... 并行跑时单个任务慢到几秒是常事）。
const (
	loadIndependentBound = 5 * time.Minute
	neverFinishesSeconds = "1800"
)

// waitFor 轮询一个条件直到成立；等不到就失败。取代"sleep 一会儿再看"。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(loadIndependentBound)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *fakeServer) setAuthCode(code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authCode = code
}

type injectedProblem struct {
	status int
	code   string
}

// failOnce 让以 suffix 结尾的下一次请求返回这个 Problem Details（可以连着排几次）。
func (f *fakeServer) failOnce(suffix string, status int, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[suffix] = append(f.failNext[suffix], injectedProblem{status: status, code: code})
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, keyStatus: "active", uploads: map[string][]byte{}, failNext: map[string][]injectedProblem{}, redirects: map[string]string{}}
	f.materialBoxes = map[string][]byte{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) queueClaim(body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = append(f.claims, func(w http.ResponseWriter) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write(raw)
	})
}

func (f *fakeServer) queueProblem(status int, code string, extra map[string]any) {
	body := map[string]any{"type": "about:blank", "status": status, "code": code, "detail": code}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims = append(f.claims, func(w http.ResponseWriter) {
		w.Header().Set("content-type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = w.Write(raw)
	})
}

func (f *fakeServer) problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("content-type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "detail": code})
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if delay := f.delayFor(r.URL.Path); delay > 0 {
		time.Sleep(delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Attempt: r.Header.Get(headerBuildAttempt),
		Token: r.Header.Get(headerMachineToken), Body: body})
	if r.Header.Get(headerMachineToken) != testToken {
		f.problem(w, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED")
		return
	}
	if f.authCode != "" {
		f.problem(w, http.StatusUnauthorized, f.authCode)
		return
	}
	path := r.URL.Path
	for suffix, origin := range f.redirects {
		if strings.HasSuffix(path, suffix) {
			http.Redirect(w, r, origin+path, http.StatusTemporaryRedirect)
			return
		}
	}
	for suffix, queue := range f.failNext {
		if strings.HasSuffix(path, suffix) && len(queue) > 0 {
			f.failNext[suffix] = queue[1:]
			f.problem(w, queue[0].status, queue[0].code)
			return
		}
	}
	switch {
	case path == "/v1/build-agent/public-key":
		f.publicKey(w, body)
	case path == "/v1/build-agent/ios-material":
		answer := map[string]any{"items": f.material, "complete": !f.materialTruncated}
		if f.materialLayout != "" && r.URL.Query().Get("capability") == "tenant-signing-material" {
			answer["layout"] = f.materialLayout
		}
		_ = json.NewEncoder(w).Encode(answer)
	case path == "/v1/build-agent/ios-material/box":
		key := r.URL.Query().Get("kind") + "/" + r.URL.Query().Get("teamId") + "/" + r.URL.Query().Get("scope")
		if tenant := r.URL.Query().Get("tenantId"); tenant != "" {
			key = tenant + "/" + key
		}
		box, ok := f.materialBoxes[key]
		if !ok {
			f.problem(w, http.StatusNotFound, "IOS_MATERIAL_NOT_FOUND")
			return
		}
		_, _ = w.Write(box)
	case path == "/v1/build-agent/claim":
		if len(f.claims) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next := f.claims[0]
		f.claims = f.claims[1:]
		next(w)
	case strings.HasSuffix(path, "/heartbeat"):
		if f.heartbeatCode != "" {
			f.problem(w, http.StatusConflict, f.heartbeatCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(path, "/unsigned/upload"), strings.HasSuffix(path, "/sbom/upload"), strings.HasSuffix(path, "/ota-artifact"),
		strings.HasSuffix(path, "/ipa/upload"):
		trimmed := strings.TrimSuffix(path, "/upload")
		f.uploads[trimmed[strings.LastIndex(trimmed, "/")+1:]] = body
		sum := sha256.Sum256(body)
		_ = json.NewEncoder(w).Encode(map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": len(body)})
	case strings.HasSuffix(path, "/ota-uploads"):
		jobPrefix := strings.TrimSuffix(path, "/ota-uploads")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"artifact": map[string]any{"token": "ota-token"},
			"upload":   map[string]any{"method": "PUT", "url": f.srv.URL + jobPrefix + "/ota-artifact", "headers": map[string]string{"content-type": "application/zip"}},
		})
	case strings.Contains(path, "/icons/"):
		w.Header().Set("content-type", "image/png")
		_, _ = w.Write([]byte("png-from-server"))
	case strings.HasSuffix(path, "/ota-release"):
		_ = json.NewEncoder(w).Encode(map[string]any{"release": map[string]any{"id": "ota_rel0001"}})
	case strings.HasSuffix(path, "/ios-release"):
		_ = json.NewEncoder(w).Encode(map[string]any{"releaseId": "rel_ios00000001"})
	case strings.HasSuffix(path, "/built"), strings.HasSuffix(path, "/fail"), strings.HasSuffix(path, "/complete"):
		w.WriteHeader(http.StatusNoContent)
	default:
		f.problem(w, http.StatusNotFound, "NOT_FOUND")
	}
}

func (f *fakeServer) publicKey(w http.ResponseWriter, body []byte) {
	var request struct {
		PublicKey         string  `json:"publicKey"`
		RotationSignature *string `json:"rotationSignature"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		f.problem(w, http.StatusBadRequest, "INVALID_PUBLIC_KEY")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(request.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		f.problem(w, http.StatusBadRequest, "INVALID_PUBLIC_KEY")
		return
	}
	sha := fingerprint.SHA256Hex(pub)
	respond := func(status string) {
		out := map[string]any{"status": status, "publicKeySha256": nil, "pendingPublicKeySha256": nil}
		if f.activeKey != nil {
			out["publicKeySha256"] = fingerprint.SHA256Hex(f.activeKey)
		}
		if f.pendingSHA != "" {
			out["pendingPublicKeySha256"] = f.pendingSHA
		}
		if !f.omitMachineID {
			out["machineId"] = testMachineID
		}
		_ = json.NewEncoder(w).Encode(out)
	}
	if f.keyStatus == "pending_key" {
		f.pendingSHA = sha
		respond("pending_key")
		return
	}
	if f.activeKey == nil {
		f.activeKey = pub
	}
	if sha == fingerprint.SHA256Hex(f.activeKey) {
		respond("active")
		return
	}
	if request.RotationSignature == nil {
		f.problem(w, http.StatusForbidden, codeKeyRotationUnproven)
		return
	}
	signature, err := base64.StdEncoding.DecodeString(*request.RotationSignature)
	if err != nil || !machinekey.VerifyRotation(f.activeKey, testMachineID, sha, "", signature) {
		f.problem(w, http.StatusForbidden, codeKeyRotationUnproven)
		return
	}
	f.pendingSHA = sha
	respond("active")
}

// acceptPending 模拟平台管理员在控制台接受待定公钥。
func (f *fakeServer) acceptPending(pub ed25519.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activeKey, f.pendingSHA, f.keyStatus = pub, "", "active"
}

func (f *fakeServer) callsTo(suffix string) []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recordedCall
	for _, call := range f.calls {
		if strings.HasSuffix(call.Path, suffix) {
			out = append(out, call)
		}
	}
	return out
}

func (f *fakeServer) allCalls() []recordedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCall(nil), f.calls...)
}

// testRig 是一台本地的"构建机"：假服务端、假 pnpm/node、真 build-runner、真 git 裸库。
type testRig struct {
	server *fakeServer
	tools  fakebuild.Tools
	agent  *agent
	commit string
	bare   string
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	restore := retryBaseDelay
	retryBaseDelay = time.Millisecond
	t.Cleanup(func() { retryBaseDelay = restore })

	root := t.TempDir()
	tools := fakebuild.Install(t, filepath.Join(root, "tools"))
	signingDir := installFakeSigningMaterial(t, filepath.Join(root, "signing"))
	bare, commit := fakebuild.SourceRepo(t, filepath.Join(root, "repo"), "anyfun")
	// 与 install.sh 克隆出的镜像一样：只有控制进程用户能写（控制进程 fetch 前核对）
	for path, mode := range map[string]os.FileMode{bare: 0o700, filepath.Join(bare, "config"): 0o600} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	server := newFakeServer(t)
	cfg := config{
		Server:       server.srv.URL,
		MachineToken: testToken,
		Repo:         bare,
		Workspace:    filepath.Join(root, "jobs"),
		StateDir:     filepath.Join(root, "state"),
		Platforms:    []string{"android"},
		Timeout:      2 * time.Minute,
		PollEvery:    10 * time.Millisecond,
		Runner:       runnerBinary,
		RunnerUser:   directRunner,
		MachineEnv:   map[string]string{"PATH": tools.PATH(), "LANG": "C.UTF-8", jobspec.IOSSigningDirEnv: signingDir},
		SSHKey:       filepath.Join(root, "ssh", "id_ed25519"),
		KnownHosts:   filepath.Join(root, "ssh", "github_known_hosts"),
	}
	if err := os.MkdirAll(filepath.Dir(cfg.KnownHosts), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.KnownHosts, []byte("github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cfg.Workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	keys, err := loadOrCreateKeyring(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(cfg, keys)
	// 测试的镜像从本地路径取；固定 known_hosts 属于当前用户
	a.mirrorProtocol = "file"
	a.pinnedFilesOwner = os.Geteuid()
	a.heartbeatEvery = 50 * time.Millisecond
	a.reportDelay = time.Millisecond
	return &testRig{server: server, tools: tools, agent: a, commit: commit, bare: bare}
}

// installFakeSigningMaterial 铺出 §4.2 那套固定布局：钥匙串、口令、一份描述文件。
// 假的 `security` 不会真去开它，但执行进程会核对文件在不在、口令的字母表对不对。
func installFakeSigningMaterial(t *testing.T, dir string) string {
	t.Helper()
	tenant := baseTenant()
	team := tenant["appleTeamId"].(string)
	profiles := filepath.Join(dir, "profiles", team)
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(dir, "rn-signing.keychain-db"):                               "fake keychain",
		filepath.Join(dir, "rn-signing.password"):                                  "Passw0rd-for-tests_0123456789\n",
		filepath.Join(profiles, tenant["iosBundleId"].(string)+".mobileprovision"): "fake profile",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// fakeIOSInventory 是"这台机器手上有测试租户那个 Team 的全套材料"。真盘点要起
// `security` 子进程读钥匙串，没有一台 Mac 就跑不了，而"领到任务前再核一次材料"这条
// 规则要有用例守着（真盘点本身由 ios_inventory_test.go 直接测）。
func fakeIOSInventory(context.Context) iosInventory {
	tenant := baseTenant()
	return iosInventory{Teams: []appleTeamMaterial{{
		TeamID:      tenant["appleTeamId"].(string),
		BundleIDs:   []string{tenant["iosBundleId"].(string)},
		ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).UTC(),
		UploadProbe: "ok",
	}}}
}

func claimBody(id, kind string) map[string]any {
	tenant := baseTenant()
	tenant["applicationId"] = "dex-mobile"
	body := map[string]any{
		"id": id, "attempt": 2, "claimedMachineId": testMachineID, "tenantSlug": "AnyFun", "tenantDirectory": "anyfun",
		"platform": "android", "kind": kind, "gitRef": "main", "version": "1.3.7", "buildNumber": 33,
		"status": "claimed", "commitSha": nil, "logTail": []string{}, "releaseNotes": map[string]any{},
		"baseReleaseId": nil, "channel": nil, "applyStrategy": nil,
		"otaCertificatePem": fakebuild.CertificatePEM, "otaCertificateSha256": strings.Repeat("ab", 32),
		"googleServicesJson": base64.StdEncoding.EncodeToString([]byte(`{"project_info":{}}`)),
		"icons":              []string{}, "tenantFile": tenant,
	}
	if kind == "ota" {
		body["baseReleaseId"] = "rel_base0001"
		body["channel"] = "production"
		body["applyStrategy"] = "next_launch"
		body["runtimeVersion"] = "1.3.7"
	}
	return body
}

func jobRootEntries(t *testing.T, a *agent) []string {
	t.Helper()
	entries, err := os.ReadDir(a.cfg.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
