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
	"JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT",
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
	if _, ok := cfg.MachineEnv["BUILD_AGENT_MACHINE_TOKEN"]; ok || cfg.MachineEnv["PATH"] == "" {
		t.Fatalf("machine env = %v", cfg.MachineEnv)
	}
	for name, overrides := range map[string]map[string]string{
		"no server":              {"BUILD_AGENT_SERVER": ""},
		"no token":               {"BUILD_AGENT_MACHINE_TOKEN": ""},
		"malformed token":        {"BUILD_AGENT_MACHINE_TOKEN": "not-a-machine-token"},
		"old token key":          {"BUILD_AGENT_TOKEN": "legacy-shared-token"},
		"old keystore key":       {"BUILD_KEYSTORE_PASSPHRASE": "leftover-passphrase"},
		"no repo":                {"BUILD_AGENT_REPO": ""},
		"no workspace":           {"BUILD_AGENT_WORKSPACE": ""},
		"no state dir":           {"BUILD_AGENT_STATE_DIR": ""},
		"relative workspace":     {"BUILD_AGENT_WORKSPACE": "workspace"},
		"state inside jobs root": {"BUILD_AGENT_STATE_DIR": "/var/lib/rn-build-jobs/state"},
		"jobs root inside state": {"BUILD_AGENT_WORKSPACE": "/var/lib/rn-build-agent/state/jobs"},
		"repo inside jobs root":  {"BUILD_AGENT_REPO": "/var/lib/rn-build-jobs/rn-app.git"},
		"plain http":             {"BUILD_AGENT_SERVER": "http://api.example.com"},
		"ios":                    {"BUILD_AGENT_PLATFORMS": "android,ios"},
		"absurd timeout":         {"BUILD_AGENT_TIMEOUT_MINUTES": "0"},
		"timeout not a number":   {"BUILD_AGENT_TIMEOUT_MINUTES": "soon"},
		"relative runner":        {"BUILD_AGENT_RUNNER": "build-runner"},
		"runner user injection":  {"BUILD_AGENT_RUNNER_USER": "builder -s"},
		"root dep cache missing": {"GRADLE_RO_DEP_CACHE": "/nonexistent/gradle-ro"},
		"no PATH":                {"PATH": ""},
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
