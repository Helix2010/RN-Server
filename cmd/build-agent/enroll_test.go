package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	testEnrollCode   = "rne_CODEcodeCODEcodeCODEcodeCODEcodeCODEcode123"
	testEnrolledName = "test-builder"
	// enrollSentinelToken 形状合法（enroll 会核对形状），只要出现在输出里测试就失败
	enrollSentinelToken = "rnm_ENROLLsentinelTOKENmustNEVERbePRINTED123456"
)

// fakeSetupServer 扮演 /v1/machine-setup 的 describe 与 enroll。
type fakeSetupServer struct {
	*httptest.Server
	t *testing.T

	mu          sync.Mutex
	calls       []string
	enrolledKey string

	role            string
	describeStatus  int
	enrollMachineID string
	enrollToken     string
}

func newFakeSetupServer(t *testing.T) *fakeSetupServer {
	f := &fakeSetupServer{t: t, role: "builder", describeStatus: http.StatusOK, enrollMachineID: testMachineID, enrollToken: enrollSentinelToken}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSetupServer) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["code"] != testEnrollCode || r.Method != http.MethodPost {
		f.t.Errorf("%s %s: bad request body or method", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.calls = append(f.calls, r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	switch r.URL.Path {
	case "/v1/machine-setup/describe":
		if f.describeStatus != http.StatusOK {
			w.WriteHeader(f.describeStatus)
			_, _ = w.Write([]byte(`{"code":"ENROLLMENT_CODE_INVALID","detail":"the enrollment code is not valid"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"machineId": testMachineID, "name": testEnrolledName, "role": f.role, "signerRole": nil,
			"bundle": map[string]any{"role": f.role, "archive": f.role + ".tar.gz"}, "recoveryKeys": []any{}, "primarySigner": nil,
		})
	case "/v1/machine-setup/enroll":
		if body["x25519PublicKey"] != nil {
			f.t.Errorf("a build machine sent an x25519 public key")
		}
		key, _ := body["ed25519PublicKey"].(string)
		f.mu.Lock()
		f.enrolledKey = key
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"machineId": f.enrollMachineID, "token": f.enrollToken, "status": "pending_key"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeSetupServer) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type enrollFixture struct {
	opts   enrollOptions
	stdout bytes.Buffer
}

func newEnrollFixture(t *testing.T, server string) *enrollFixture {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.Mkdir(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	return &enrollFixture{opts: enrollOptions{
		server: server, code: testEnrollCode,
		envFile: filepath.Join(etc, "rn-build-agent.env"), stateDir: filepath.Join(root, "state"),
	}}
}

func (x *enrollFixture) run(t *testing.T) error {
	t.Helper()
	client := &http.Client{CheckRedirect: refuseRedirects}
	return runEnroll(context.Background(), x.opts, client, &x.stdout)
}

func assertNoSecret(t *testing.T, what, text string) {
	t.Helper()
	if strings.Contains(text, enrollSentinelToken) || strings.Contains(text, testEnrollCode) {
		t.Fatalf("%s contains the machine token or the enrollment code", what)
	}
}

func TestEnrollWritesTheTokenIntoANewEnvFileWithoutPrintingIt(t *testing.T) {
	server := newFakeSetupServer(t)
	x := newEnrollFixture(t, server.URL)
	if err := x.run(t); err != nil {
		assertNoSecret(t, "the error", err.Error())
		t.Fatal(err)
	}
	assertNoSecret(t, "stdout", x.stdout.String())
	if got := server.called(); strings.Join(got, ",") != "/v1/machine-setup/describe,/v1/machine-setup/enroll" {
		t.Fatalf("calls: %v", got)
	}

	info, err := os.Stat(x.opts.envFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("env file: %v %v", info, err)
	}
	lines, _, err := readEnvFile(x.opts.envFile)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"BUILD_AGENT_SERVER": x.opts.server, "BUILD_AGENT_MACHINE_TOKEN": enrollSentinelToken, "BUILD_AGENT_STATE_DIR": x.opts.stateDir,
		"BUILD_AGENT_RUNNER_USER": "builder", "JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64",
	} {
		if got, _ := envValue(lines, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	ring, err := readKeyringReadOnly(x.opts.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	enrolledKey := server.enrolledKey
	server.mu.Unlock()
	if enrolledKey != ring.current.publicBase64() {
		t.Fatal("the enrolled public key is not the provenance key in the state dir")
	}
	out := x.stdout.String()
	for _, want := range []string{ring.current.sha256, testEnrolledName, testMachineID, "provenance key created", "trust-builder --builder " + testEnrolledName} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(x.opts.envFile), ".*enroll*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

// 写出来的 env 文件就是常驻进程能启动的配置
func TestEnrolledEnvFileIsAValidAgentConfig(t *testing.T) {
	x := newEnrollFixture(t, "https://api.example.com")
	if err := os.WriteFile(x.opts.envFile, renderEnrolledEnv(nil, false, x.opts, testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, _ := readEnvFile(x.opts.envFile)
	overrides := map[string]string{}
	for _, line := range lines {
		if key, value, ok := envAssignment(line); ok {
			overrides[key] = value
		}
	}
	applyConfigEnv(t, overrides)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("the enrolled env file is not a valid agent configuration: %v", err)
	}
	if cfg.MachineToken != testToken || cfg.StateDir != x.opts.stateDir || cfg.RunnerUser != "builder" || cfg.Server != x.opts.server {
		t.Fatalf("unexpected config: %v", cfg)
	}
}

// 已有 env 文件：令牌与服务端换成这次的，其它行（含注释、自定义的 JAVA_HOME）原样保留，缺的键补上
func TestEnrollKeepsTheExistingEnvFile(t *testing.T) {
	server := newFakeSetupServer(t)
	x := newEnrollFixture(t, server.URL)
	existing := strings.Join([]string{
		"# operator notes",
		"BUILD_AGENT_SERVER=http://127.0.0.1:1",
		"BUILD_AGENT_MACHINE_TOKEN=",
		"JAVA_HOME=/opt/jdk-17",
		"GRADLE_RO_DEP_CACHE=/var/cache/rn-build-agent/gradle-ro",
		"BUILD_AGENT_SERVER=http://127.0.0.1:2",
	}, "\n") + "\n"
	if err := os.WriteFile(x.opts.envFile, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := x.run(t); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(x.opts.envFile)
	text := string(raw)
	lines, _, _ := readEnvFile(x.opts.envFile)
	if got, _ := envValue(lines, "JAVA_HOME"); got != "/opt/jdk-17" {
		t.Errorf("JAVA_HOME was changed to %q", got)
	}
	if !strings.HasPrefix(text, "# operator notes\n") || !strings.Contains(text, "GRADLE_RO_DEP_CACHE=/var/cache/rn-build-agent/gradle-ro\n") {
		t.Errorf("existing lines were not kept")
	}
	if strings.Count(text, "BUILD_AGENT_SERVER=") != 1 || strings.Count(text, "BUILD_AGENT_MACHINE_TOKEN=") != 1 || strings.Count(text, "JAVA_HOME=") != 1 {
		t.Errorf("keys are duplicated or missing")
	}
	if got, _ := envValue(lines, "BUILD_AGENT_SERVER"); got != server.URL {
		t.Errorf("BUILD_AGENT_SERVER = %q", got)
	}
	if got, _ := envValue(lines, "BUILD_AGENT_REPO"); got != "/var/lib/rn-build-agent/repos/rn-app.git" {
		t.Errorf("a missing default was not added")
	}
	if info, _ := os.Stat(x.opts.envFile); info.Mode().Perm() != 0o600 {
		t.Errorf("the replaced env file has mode %o", info.Mode().Perm())
	}
}

// 已注册：不连服务端、不改任何文件，注册码留着
func TestEnrollIsANoOpOnAnEnrolledMachine(t *testing.T) {
	server := newFakeSetupServer(t)
	x := newEnrollFixture(t, server.URL)
	ring, err := loadOrCreateKeyring(x.opts.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	existing := "BUILD_AGENT_SERVER=https://api.example.com\nBUILD_AGENT_MACHINE_TOKEN=\"" + testToken + "\"\n"
	if err := os.WriteFile(x.opts.envFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := x.run(t); err != nil {
		t.Fatal(err)
	}
	if calls := server.called(); len(calls) != 0 {
		t.Fatalf("an enrolled machine contacted the server: %v", calls)
	}
	if raw, _ := os.ReadFile(x.opts.envFile); string(raw) != existing {
		t.Fatal("the env file of an enrolled machine was changed")
	}
	if out := x.stdout.String(); !strings.Contains(out, "already enrolled") || !strings.Contains(out, ring.current.sha256) || strings.Contains(out, testToken) {
		t.Fatalf("unexpected output:\n%s", out)
	}

	// 有令牌却没有密钥：身份已经丢了，不假装成功
	if err := os.Remove(filepath.Join(x.opts.stateDir, provenanceKeyFile)); err != nil {
		t.Fatal(err)
	}
	err = x.run(t)
	if err == nil || !strings.Contains(err.Error(), "identity is gone") {
		t.Fatalf("a token without a key was accepted: %v", err)
	}
	assertNoSecret(t, "the error", err.Error())
	if _, statErr := os.Stat(filepath.Join(x.opts.stateDir, provenanceKeyFile)); !os.IsNotExist(statErr) {
		t.Fatal("a new key was created for a machine that already has a token")
	}
}

func TestEnrollRefusesBeforeUsingTheCode(t *testing.T) {
	cases := map[string]struct {
		setup   func(t *testing.T, server *fakeSetupServer, x *enrollFixture)
		wantErr string
		calls   string
	}{
		"legacy env file": {
			setup: func(t *testing.T, _ *fakeSetupServer, x *enrollFixture) {
				_ = os.WriteFile(x.opts.envFile, []byte("BUILD_AGENT_TOKEN=old\nBUILD_AGENT_MACHINE_TOKEN=\n"), 0o600)
			},
			wantErr: "BUILD_AGENT_TOKEN", calls: "",
		},
		"state dir differs from the env file": {
			setup: func(t *testing.T, _ *fakeSetupServer, x *enrollFixture) {
				_ = os.WriteFile(x.opts.envFile, []byte("BUILD_AGENT_STATE_DIR=/elsewhere\n"), 0o600)
			},
			wantErr: "must be the same directory", calls: "",
		},
		"malformed token already in the env file": {
			setup: func(t *testing.T, _ *fakeSetupServer, x *enrollFixture) {
				_ = os.WriteFile(x.opts.envFile, []byte("BUILD_AGENT_MACHINE_TOKEN=rnm_REPLACE_ME\n"), 0o600)
			},
			wantErr: "not a machine token", calls: "",
		},
		"code for a signing gate": {
			setup:   func(t *testing.T, server *fakeSetupServer, _ *enrollFixture) { server.role = "signer" },
			wantErr: "signer enroll", calls: "/v1/machine-setup/describe",
		},
		"invalid code": {
			setup: func(t *testing.T, server *fakeSetupServer, _ *enrollFixture) {
				server.describeStatus = http.StatusNotFound
			},
			wantErr: "reissue it in the console", calls: "/v1/machine-setup/describe",
		},
		"env directory not writable": {
			setup: func(t *testing.T, _ *fakeSetupServer, x *enrollFixture) {
				if os.Geteuid() == 0 {
					t.Skip("root can write anywhere")
				}
				dir := filepath.Dir(x.opts.envFile)
				_ = os.Chmod(dir, 0o555)
				t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
			},
			wantErr: "cannot write next to", calls: "/v1/machine-setup/describe",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			server := newFakeSetupServer(t)
			x := newEnrollFixture(t, server.URL)
			tc.setup(t, server, x)
			before, _ := os.ReadFile(x.opts.envFile)
			err := x.run(t)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want an error containing %q, got %v", tc.wantErr, err)
			}
			assertNoSecret(t, "the error", err.Error())
			if got := strings.Join(server.called(), ","); got != tc.calls {
				t.Fatalf("calls %q, want %q", got, tc.calls)
			}
			if after, _ := os.ReadFile(x.opts.envFile); !bytes.Equal(before, after) {
				t.Fatal("the env file was changed")
			}
		})
	}
}

// 服务端的回答不对：令牌不落盘，也不出现在报错里
func TestEnrollDiscardsAnUnexpectedEnrollment(t *testing.T) {
	for name, mutate := range map[string]func(*fakeSetupServer){
		"another machine":   func(s *fakeSetupServer) { s.enrollMachineID = "mch_someoneELSE01" },
		"malformed token":   func(s *fakeSetupServer) { s.enrollToken = enrollSentinelToken + "x" },
		"token not rnm_ish": func(s *fakeSetupServer) { s.enrollToken = "Bearer " + enrollSentinelToken },
	} {
		t.Run(name, func(t *testing.T) {
			server := newFakeSetupServer(t)
			mutate(server)
			x := newEnrollFixture(t, server.URL)
			err := x.run(t)
			if err == nil {
				t.Fatal("an unexpected enrollment was accepted")
			}
			assertNoSecret(t, "the error", err.Error())
			assertNoSecret(t, "stdout", x.stdout.String())
			if _, statErr := os.Stat(x.opts.envFile); !os.IsNotExist(statErr) {
				t.Fatal("the env file was written")
			}
			if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(x.opts.envFile), ".*")); len(leftovers) != 0 {
				t.Fatalf("temporary files left behind: %v", leftovers)
			}
		})
	}
}

// 已有出处密钥（例如 rotate-key 之前装过）：复用，不另造
func TestEnrollReusesAnExistingProvenanceKey(t *testing.T) {
	server := newFakeSetupServer(t)
	x := newEnrollFixture(t, server.URL)
	ring, err := loadOrCreateKeyring(x.opts.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.run(t); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	enrolledKey := server.enrolledKey
	server.mu.Unlock()
	if enrolledKey != ring.current.publicBase64() || !strings.Contains(x.stdout.String(), "reused") {
		t.Fatal("the existing provenance key was not reused")
	}
}

// 服务端回重定向：不跟随（请求体里有注册码）
func TestEnrollNeverFollowsRedirects(t *testing.T) {
	elsewhere := newFakeSetupServer(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	x := newEnrollFixture(t, redirect.URL)
	if err := x.run(t); err == nil {
		t.Fatal("a redirect was followed or ignored")
	}
	if calls := elsewhere.called(); len(calls) != 0 {
		t.Fatalf("the redirect target received %v", calls)
	}
}

func TestEnrollFlags(t *testing.T) {
	good := []string{"--server", "https://api.example.com/", "--code", testEnrollCode}
	var stderr bytes.Buffer
	opts, ok := parseEnrollFlags(good, &stderr)
	if !ok || opts.server != "https://api.example.com" || opts.envFile != "/etc/rn-build-agent.env" || opts.stateDir != "/var/lib/rn-build-agent/state" {
		t.Fatalf("good flags rejected or defaults wrong: %v %+v %s", ok, opts.envFile, stderr.String())
	}
	for name, args := range map[string][]string{
		"http to a public host": {"--server", "http://api.example.com", "--code", testEnrollCode},
		"loopback look-alike":   {"--server", "http://127.0.0.1.example.com", "--code", testEnrollCode},
		"path in the server":    {"--server", "https://api.example.com/v1", "--code", testEnrollCode},
		"userinfo":              {"--server", "https://u:p@api.example.com", "--code", testEnrollCode},
		"malformed code":        {"--server", "https://api.example.com", "--code", "rne_short-" + sentinelSecret},
		"relative env file":     append(append([]string{}, good...), "--env-file", "etc/rn-build-agent.env"),
		"unclean state dir":     append(append([]string{}, good...), "--state-dir", "/var/lib/../lib/rn-build-agent/state"),
		"positional argument":   append(append([]string{}, good...), "extra"),
	} {
		stderr.Reset()
		if _, ok := parseEnrollFlags(args, &stderr); ok {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(stderr.String(), sentinelSecret) {
			t.Errorf("%s: the code was echoed", name)
		}
	}
	for _, server := range []string{"http://localhost:13080", "http://127.0.0.1:13080", "https://api.example.com:8443"} {
		if err := checkEnrollServer(server); err != nil {
			t.Errorf("%s rejected: %v", server, err)
		}
	}
}

// Go 里的默认值与 deploy/build-agent/rn-build-agent.env.example 一致：示例是运维看的，程序写的是这里
func TestEnrollDefaultsMatchTheEnvExample(t *testing.T) {
	lines, exists, err := readEnvFile(filepath.Join("..", "..", "deploy", "build-agent", "rn-build-agent.env.example"))
	if err != nil || !exists {
		t.Fatalf("cannot read the example: %v", err)
	}
	example := map[string]string{}
	for _, line := range lines {
		if key, value, ok := envAssignment(line); ok {
			example[key] = value
		}
	}
	covered := map[string]bool{"BUILD_AGENT_SERVER": true, "BUILD_AGENT_MACHINE_TOKEN": true}
	if example["BUILD_AGENT_STATE_DIR"] != "/var/lib/rn-build-agent/state" {
		t.Errorf("the example's BUILD_AGENT_STATE_DIR is not the enroll default")
	}
	covered["BUILD_AGENT_STATE_DIR"] = true
	for _, entry := range envDefaults {
		if example[entry.key] != entry.value {
			t.Errorf("%s: enroll writes %q, the example says %q", entry.key, entry.value, example[entry.key])
		}
		covered[entry.key] = true
	}
	for key := range example {
		if !covered[key] {
			t.Errorf("the example sets %s but enroll does not write it", key)
		}
	}
}
