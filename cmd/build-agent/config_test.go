package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var configKeys = []string{
	"BUILD_AGENT_SERVER", "BUILD_AGENT_MACHINE_TOKEN", "BUILD_AGENT_REPO", "BUILD_AGENT_WORKSPACE",
	"BUILD_AGENT_STATE_DIR", "BUILD_AGENT_PLATFORMS", "BUILD_AGENT_TIMEOUT_MINUTES", "BUILD_AGENT_RUNNER",
	"BUILD_AGENT_RUNNER_USER", "BUILD_AGENT_TOKEN", "BUILD_KEYSTORE_PASSPHRASE", "GRADLE_RO_DEP_CACHE",
	"JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "BUILD_AGENT_SSH_KEY", "BUILD_AGENT_SSH_KNOWN_HOSTS",
	"BUILD_AGENT_PROXY", "BUILD_AGENT_NO_PROXY",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

func applyConfigEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	full := map[string]string{
		"BUILD_AGENT_SERVER":        "https://api.example.com",
		"BUILD_AGENT_MACHINE_TOKEN": testToken,
		"BUILD_AGENT_REPO":          "/var/lib/rn-build-agent/repos/rn-app.git",
		"BUILD_AGENT_WORKSPACE":     "/var/lib/rn-build-jobs",
		"BUILD_AGENT_STATE_DIR":     "/var/lib/rn-build-agent/state",
		"PATH":                      "/usr/local/bin:/usr/bin:/bin",
	}
	for _, key := range configKeys {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	for key, value := range full {
		t.Setenv(key, value)
	}
	for key, value := range overrides {
		if value == "" {
			os.Unsetenv(key)
		} else {
			t.Setenv(key, value)
		}
	}
}

func TestLoadConfigRefusesAnIncompleteOrUnsafeSetup(t *testing.T) {
	applyConfigEnv(t, nil)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("a complete configuration was rejected: %v", err)
	}
	if cfg.Runner != "/opt/rn-build-agent/build-runner" || cfg.RunnerUser != "builder" || cfg.Timeout != 45*time.Minute {
		t.Fatalf("defaults = %q %q %s", cfg.Runner, cfg.RunnerUser, cfg.Timeout)
	}
	if cfg.SSHKey != "/var/lib/rn-build-agent/.ssh/id_ed25519" || cfg.KnownHosts != "/opt/rn-build-agent/github_known_hosts" {
		t.Fatalf("ssh defaults = %q %q", cfg.SSHKey, cfg.KnownHosts)
	}
	if _, ok := cfg.MachineEnv["BUILD_AGENT_MACHINE_TOKEN"]; ok || cfg.MachineEnv["PATH"] == "" {
		t.Fatalf("machine env = %v", cfg.MachineEnv)
	}
	for name, overrides := range map[string]map[string]string{
		"no server":               {"BUILD_AGENT_SERVER": ""},
		"no token":                {"BUILD_AGENT_MACHINE_TOKEN": ""},
		"malformed token":         {"BUILD_AGENT_MACHINE_TOKEN": "not-a-machine-token"},
		"old token key":           {"BUILD_AGENT_TOKEN": "legacy-shared-token"},
		"old keystore key":        {"BUILD_KEYSTORE_PASSPHRASE": "leftover-passphrase"},
		"no repo":                 {"BUILD_AGENT_REPO": ""},
		"no workspace":            {"BUILD_AGENT_WORKSPACE": ""},
		"no state dir":            {"BUILD_AGENT_STATE_DIR": ""},
		"relative workspace":      {"BUILD_AGENT_WORKSPACE": "workspace"},
		"state inside jobs root":  {"BUILD_AGENT_STATE_DIR": "/var/lib/rn-build-jobs/state"},
		"jobs root inside state":  {"BUILD_AGENT_WORKSPACE": "/var/lib/rn-build-agent/state/jobs"},
		"repo inside jobs root":   {"BUILD_AGENT_REPO": "/var/lib/rn-build-jobs/rn-app.git"},
		"plain http":              {"BUILD_AGENT_SERVER": "http://api.example.com"},
		"ios":                     {"BUILD_AGENT_PLATFORMS": "android,ios"},
		"absurd timeout":          {"BUILD_AGENT_TIMEOUT_MINUTES": "0"},
		"timeout not a number":    {"BUILD_AGENT_TIMEOUT_MINUTES": "soon"},
		"relative runner":         {"BUILD_AGENT_RUNNER": "build-runner"},
		"runner user injection":   {"BUILD_AGENT_RUNNER_USER": "builder -s"},
		"root dep cache missing":  {"GRADLE_RO_DEP_CACHE": "/nonexistent/gradle-ro"},
		"no PATH":                 {"PATH": ""},
		"ssh key shell injection": {"BUILD_AGENT_SSH_KEY": "/x -o ProxyCommand=touch%20/tmp/y"},
		"relative ssh key":        {"BUILD_AGENT_SSH_KEY": "id_ed25519"},
		"known hosts with quotes": {"BUILD_AGENT_SSH_KNOWN_HOSTS": "/opt/x';touch /tmp/y'"},
		"unclean known hosts":     {"BUILD_AGENT_SSH_KNOWN_HOSTS": "/opt/rn-build-agent/../github_known_hosts"},
	} {
		applyConfigEnv(t, overrides)
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "legacy-shared-token") || strings.Contains(err.Error(), "leftover-passphrase") {
			t.Errorf("%s: the error echoes a secret: %v", name, err)
		}
	}
	applyConfigEnv(t, map[string]string{"BUILD_AGENT_SERVER": "http://127.0.0.1:3000", "BUILD_AGENT_RUNNER_USER": "-"})
	if cfg, err := loadConfig(); err != nil || cfg.runnerSeparated() {
		t.Fatalf("a loopback development setup was rejected: %v", err)
	}
}

// 只读 Gradle 依赖缓存：执行进程能改写它就能给之后每个任务下毒
func TestReadOnlyDependencyCacheMustNotBeWritableByOthers(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "gradle-ro")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkReadOnlyCache(cache); err != nil {
		t.Fatalf("a private cache was refused: %v", err)
	}
	if err := os.Chmod(cache, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := checkReadOnlyCache(cache); err == nil {
		t.Fatal("a group-writable cache was accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cache, link); err != nil {
		t.Fatal(err)
	}
	if err := checkReadOnlyCache(link); err == nil {
		t.Fatal("a symlinked cache was accepted")
	}
}

// rn-foundation-apply 以 builder 身份、空环境跑新二进制做冒烟，必须以 2 退出且什么都不写
func TestEmptyEnvironmentExitsWithStatusTwo(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "build-agent")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, "github.com/Helix2010/RN-Server/cmd/build-agent")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	workdir := t.TempDir()
	cmd := exec.Command(binary)
	cmd.Env = []string{}
	cmd.Dir = workdir
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 {
		t.Fatalf("empty environment: %v, want exit status 2", err)
	}
	if entries, _ := os.ReadDir(workdir); len(entries) != 0 {
		t.Fatalf("the smoke run wrote files: %v", entries)
	}
	unknown := exec.Command(binary, "backup")
	unknown.Env = []string{}
	if err := unknown.Run(); err == nil {
		t.Fatal("an unknown subcommand succeeded")
	}
}

// 可重试与不可重试要分清：5xx 重试，409 这类明确拒绝不重试
func TestUploadRetriesTransientFailuresButNotRejections(t *testing.T) {
	restore := retryBaseDelay
	retryBaseDelay = time.Millisecond
	defer func() { retryBaseDelay = restore }()
	attempts := 0
	mode := "flaky"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if mode == "reject" {
			w.Header().Set("content-type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"BUILD_ATTEMPT_STALE","detail":"stale"}`))
			return
		}
		if attempts < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"sha256":"` + strings.Repeat("0", 64) + `","size":3}`))
	}))
	defer server.Close()
	api := newClient(config{Server: server.URL, MachineToken: testToken})
	file := filepath.Join(t.TempDir(), "unsigned.apk")
	if err := os.WriteFile(file, []byte("apk"), 0o600); err != nil {
		t.Fatal(err)
	}
	job := claimedJob{ID: "bld_retry0001", Attempt: 1}
	buf := newLogBuffer(newRedactor())
	err := withRetry(context.Background(), buf, "upload", 6, func(ctx context.Context) error {
		return api.uploadStream(ctx, job, "/unsigned/upload", file, strings.Repeat("0", 64), 3)
	})
	if err != nil || attempts != 3 {
		t.Fatalf("two 502s then success: err=%v attempts=%d", err, attempts)
	}
	mode, attempts = "reject", 0
	err = withRetry(context.Background(), buf, "upload", 6, func(ctx context.Context) error {
		return api.uploadStream(ctx, job, "/unsigned/upload", file, strings.Repeat("0", 64), 3)
	})
	if !isStale(err) || attempts != 1 {
		t.Fatalf("a 409 was retried or misread: err=%v attempts=%d", err, attempts)
	}
}

// 票据指向对象存储（预签名地址）时不把本机令牌发出去
func TestOTATicketToAnotherOriginDoesNotReceiveTheToken(t *testing.T) {
	var gotToken, gotAttempt string
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken, gotAttempt = r.Header.Get(headerMachineToken), r.Header.Get(headerBuildAttempt)
	}))
	defer storage.Close()
	api := newClient(config{Server: "https://api.example.invalid", MachineToken: testToken})
	file := filepath.Join(t.TempDir(), "ota.zip")
	if err := os.WriteFile(file, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	var ticket uploadTicket
	ticket.Upload.URL = storage.URL + "/bucket/key?X-Amz-Signature=abc"
	ticket.Upload.Headers = map[string]string{"x-machine-token": "smuggled"}
	if err := api.putTicket(context.Background(), claimedJob{ID: "bld_ticket0001", Attempt: 1}, ticket, file, 3); err != nil {
		t.Fatal(err)
	}
	if gotToken != "" || gotAttempt != "" {
		t.Fatalf("the object store received token %q attempt %q", gotToken, gotAttempt)
	}
}

// 代理只配一次：BUILD_AGENT_PROXY 一个键，控制进程展开成构建进程要的大小写两套、
// 上传程序要的参数；自己的服务端总在不走代理的名单里。
func TestProxyIsConfiguredOnceAndExpandedForEveryUser(t *testing.T) {
	applyConfigEnv(t, map[string]string{
		"BUILD_AGENT_PROXY":    "http://127.0.0.1:7897",
		"BUILD_AGENT_NO_PROXY": "anyfun.win",
	})
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	wantNoProxy := "localhost,127.0.0.1,::1,api.example.com,anyfun.win"
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if cfg.MachineEnv[key] != "http://127.0.0.1:7897" {
			t.Fatalf("%s = %q", key, cfg.MachineEnv[key])
		}
	}
	if cfg.MachineEnv["NO_PROXY"] != wantNoProxy || cfg.MachineEnv["no_proxy"] != wantNoProxy {
		t.Fatalf("no-proxy = %q / %q", cfg.MachineEnv["NO_PROXY"], cfg.MachineEnv["no_proxy"])
	}
	a := &agent{cfg: cfg}
	a.cfg.RunnerUser = directRunner
	args := a.uploaderCommand(context.Background(), "--probe").Args
	want := []string{cfg.IOSUploader, "--proxy", "http://127.0.0.1:7897", "--no-proxy", wantNoProxy, "--probe"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("uploader args = %v, want %v", args, want)
	}
}

func TestNoProxyConfiguredMeansDirectEverywhere(t *testing.T) {
	applyConfigEnv(t, nil)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	for key := range cfg.MachineEnv {
		if strings.Contains(strings.ToLower(key), "proxy") {
			t.Fatalf("an unconfigured proxy leaked %s into the job environment", key)
		}
	}
	a := &agent{cfg: cfg}
	a.cfg.RunnerUser = directRunner
	if args := a.uploaderCommand(context.Background(), "--probe").Args; len(args) != 2 {
		t.Fatalf("uploader args = %v", args)
	}
}

// 直接写 HTTPS_PROXY 这些是旧写法：它们只管得到一部分使用方，所以拒绝启动，并说清该怎么写。
func TestProxyVariablesInTheEnvFileAreRefused(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		applyConfigEnv(t, map[string]string{key: "http://127.0.0.1:7897"})
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "BUILD_AGENT_PROXY") {
			t.Errorf("%s in the env file: err = %v", key, err)
		}
	}
	for name, value := range map[string]string{
		"credentials": "http://user:secret@127.0.0.1:7897",
		"no scheme":   "127.0.0.1:7897",
	} {
		applyConfigEnv(t, map[string]string{"BUILD_AGENT_PROXY": value})
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s was accepted", name)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error echoes the credentials: %v", name, err)
		}
	}
}
