package main

import (
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
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, keyStatus: "active", uploads: map[string][]byte{}}
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCall{Method: r.Method, Path: r.URL.Path, Attempt: r.Header.Get(headerBuildAttempt),
		Token: r.Header.Get(headerMachineToken), Body: body})
	if r.Header.Get(headerMachineToken) != testToken {
		f.problem(w, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED")
		return
	}
	path := r.URL.Path
	switch {
	case path == "/v1/build-agent/public-key":
		f.publicKey(w, body)
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
	case strings.HasSuffix(path, "/unsigned/upload"), strings.HasSuffix(path, "/sbom/upload"), strings.HasSuffix(path, "/ota-artifact"):
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
	case strings.HasSuffix(path, "/ota-release"):
		_ = json.NewEncoder(w).Encode(map[string]any{"release": map[string]any{"id": "ota_rel0001"}})
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
	bare, commit := fakebuild.SourceRepo(t, filepath.Join(root, "repo"), "anyfun")
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
		MachineEnv:   map[string]string{"PATH": tools.PATH(), "LANG": "C.UTF-8"},
	}
	if err := os.MkdirAll(cfg.Workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	keys, err := loadOrCreateKeyring(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(cfg, keys)
	a.heartbeatEvery = 50 * time.Millisecond
	a.reportDelay = time.Millisecond
	return &testRig{server: server, tools: tools, agent: a, commit: commit, bare: bare}
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
