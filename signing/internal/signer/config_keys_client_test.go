package signer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/records"
)

func validEnv(t *testing.T) map[string]string {
	return map[string]string{
		EnvServerURL: "https://api.anyfun.win", EnvMachineToken: testToken, EnvName: "amos-signer-a",
		EnvStateDir: "/var/lib/rn-signer-a", EnvRuntimeDir: "/run/rn-signer-a", EnvJavaHome: "/usr/lib/jvm/java-17-openjdk-amd64",
		EnvBuildToolsDir: "/opt/android-sdk/build-tools/35.0.0", EnvCheckSocket: "/run/rn-signer-a-check.sock",
	}
}

func TestLoadConfig(t *testing.T) {
	env := validEnv(t)
	cfg, err := LoadConfig(func(k string) string { return env[k] }, NeedAll)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxVersionCodeJump != DefaultMaxVersionCodeJump || cfg.MaxVersionCode != DefaultMaxVersionCode {
		t.Fatalf("defaults: %+v", cfg)
	}
	cases := map[string]struct {
		key, value, mention string
	}{
		"http to a public host": {EnvServerURL, "http://api.anyfun.win", "http://api.anyfun.win"},
		"path in server url":    {EnvServerURL, "https://api.anyfun.win/v1", "no path"},
		"bad token":             {EnvMachineToken, "rnm_short", EnvMachineToken},
		"bad name":              {EnvName, "Amos Signer", "Amos Signer"},
		"relative state dir":    {EnvStateDir, "var/lib/x", "var/lib/x"},
		"runtime inside state":  {EnvRuntimeDir, "/var/lib/rn-signer-a/run", "must not contain each other"},
		"both checker modes":    {EnvCheckExec, "/opt/rn-signer/bin/signer-check", "exactly one"},
		"jump not a number":     {EnvMaxVersionCodeJump, "lots", "lots"},
		"jump zero":             {EnvMaxVersionCodeJump, "0", EnvMaxVersionCodeJump},
		"max too large":         {EnvMaxVersionCode, "3000000000", "3000000000"},
		"leading zero":          {EnvMaxVersionCode, "0100", "0100"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			changed := validEnv(t)
			changed[tc.key] = tc.value
			_, err := LoadConfig(func(k string) string { return changed[k] }, NeedAll)
			if err == nil || !strings.Contains(err.Error(), tc.mention) {
				t.Fatalf("LoadConfig = %v; want it to mention %q", err, tc.mention)
			}
		})
	}
	noChecker := validEnv(t)
	delete(noChecker, EnvCheckSocket)
	if _, err := LoadConfig(func(k string) string { return noChecker[k] }, NeedAll); err == nil {
		t.Fatal("accepted a config without a checker")
	}
	loopback := validEnv(t)
	loopback[EnvServerURL] = "http://127.0.0.1:8080"
	if _, err := LoadConfig(func(k string) string { return loopback[k] }, NeedAll); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
	// 只读命令不需要令牌与服务端地址
	local := map[string]string{EnvName: "amos-signer-a", EnvStateDir: "/var/lib/rn-signer-a"}
	if _, err := LoadConfig(func(k string) string { return local[k] }, NeedLocal); err != nil {
		t.Fatalf("local config: %v", err)
	}
}

func TestConfigNeverPrintsTheToken(t *testing.T) {
	const sentinel = "rnm_SENTINELSENTINELSENTINELSENTINELSENTINELabc" // rnm_ + 43 个字符
	env := validEnv(t)
	env[EnvMachineToken] = sentinel
	cfg, err := LoadConfig(func(k string) string { return env[k] }, NeedAll)
	if err != nil {
		t.Fatal(err)
	}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, cfg), fmt.Sprintf(verb, &cfg))
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("starting", "config", cfg)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("starting", "config", cfg)
	outputs = append(outputs, logs.String())
	if raw, err := json.Marshal(cfg); err == nil {
		outputs = append(outputs, string(raw))
	}
	env[EnvMachineToken] = sentinel + "x" // 格式不对时报错也不能回显
	if _, err := LoadConfig(func(k string) string { return env[k] }, NeedAll); err != nil {
		outputs = append(outputs, err.Error())
	}
	for _, out := range outputs {
		if strings.Contains(out, "SENTINEL") {
			t.Fatalf("the machine token leaked: %s", out)
		}
	}
	keys := newHarness(t, harnessOptions{}).keys
	seed := fmt.Sprintf("%x", keys.Ed25519.Seed())
	for _, out := range []string{fmt.Sprintf("%v %+v %#v %x", keys, keys, keys, keys), keys.String()} {
		if strings.Contains(out, seed) || strings.Contains(out, fmt.Sprintf("%x", keys.X25519.Bytes())) {
			t.Fatalf("machine keys leaked: %s", out)
		}
	}
}

// 解开的签名密钥：任何格式化、日志、JSON 都不带出原件与口令。
func TestKeystoreMaterialNeverPrintsSecrets(t *testing.T) {
	const password = "PASSWORD-SENTINEL-123"
	p12 := []byte("P12-SENTINEL-BYTES")
	m := keystoreMaterial{P12: p12, Plain: keystorebox.Plaintext{TenantSlug: "AnyFun", KeyAlias: testAlias, StorePassword: password, KeyPassword: password,
		P12Base64: base64.StdEncoding.EncodeToString(p12)}}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, m), fmt.Sprintf(verb, &m), fmt.Sprintf(verb, []keystoreMaterial{m}))
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "material", m)
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "material", m)
	outputs = append(outputs, logs.String())
	if raw, err := json.Marshal(m); err == nil {
		outputs = append(outputs, string(raw))
	}
	for _, out := range outputs {
		for _, secret := range []string{password, string(p12), base64.StdEncoding.EncodeToString(p12), fmt.Sprintf("%x", p12)} {
			if strings.Contains(out, secret) {
				t.Fatalf("keystore material leaked: %s", out)
			}
		}
	}
}

func TestCleanTextStaysWithinTheByteLimit(t *testing.T) {
	for _, in := range []string{strings.Repeat("a", 400), strings.Repeat("签", 200), "ok", "bad\x1b[2Jutf8\xff", strings.Repeat("é", 151)} {
		for _, max := range []int{300, 64, 5, 2} {
			out := cleanText(in, max)
			if len(out) > max || !utf8.ValidString(out) || strings.ContainsAny(out, "\x1b\xff") {
				t.Fatalf("cleanText(%q, %d) = %q (%d bytes)", in, max, out, len(out))
			}
		}
	}
	if got := cleanText(strings.Repeat("a", 400), 300); len(got) != 300 || !strings.HasSuffix(got, "…") {
		t.Fatalf("truncation marker: %q", got)
	}
	if got := cleanText("short", 300); got != "short" {
		t.Fatalf("short text changed: %q", got)
	}
}

func TestReadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rn-signer-a.env")
	content := "# comment\n\n" + EnvServerURL + "=\"https://api.anyfun.win\"\n" + EnvMachineToken + "='" + testToken + "'\n" + EnvName + "=amos-signer-a\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := ReadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values[EnvServerURL] != "https://api.anyfun.win" || values[EnvMachineToken] != testToken || values[EnvName] != "amos-signer-a" {
		t.Fatalf("values: %v", values)
	}
	for name, body := range map[string]string{
		"unknown key": "SIGNER_TOKEN=" + testToken + "\n",
		"duplicate":   EnvName + "=a\n" + EnvName + "=b\n",
		"no equals":   testToken + "\n",
	} {
		bad := filepath.Join(t.TempDir(), "bad.env")
		_ = os.WriteFile(bad, []byte(body), 0o600)
		_, err := ReadEnvFile(bad)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), testToken) {
			t.Errorf("%s: the error echoes the token line", name)
		}
	}
}

func TestInitStateLifecycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(dir); err == nil || !strings.Contains(err.Error(), "signer run") {
		t.Fatalf("LoadKeys before init: %v", err)
	}
	keys, created, err := InitState(dir, "amos-signer-a")
	if err != nil || !created {
		t.Fatalf("InitState: %v %v", created, err)
	}
	for _, name := range []string{x25519KeyFile, ed25519KeyFile, records.TrustFileName, records.SignedFileName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	again, created, err := InitState(dir, "amos-signer-a")
	if err != nil || created || again.X25519SHA256() != keys.X25519SHA256() || again.Ed25519SHA256() != keys.Ed25519SHA256() {
		t.Fatalf("second InitState regenerated keys: %v %v", created, err)
	}
	if _, _, err := OpenRecords(dir, "amos-signer-b"); err == nil {
		t.Fatal("opened records under a different machine name")
	}

	// 记录丢了、私钥还在：拒绝启动，不悄悄重建（重建等于忘了签过什么）
	if err := os.Remove(filepath.Join(dir, records.SignedFileName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := InitState(dir, "amos-signer-a"); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("partial state: %v", err)
	}

	// 首次启动半途崩溃（有标记）：清掉重来
	crashed := t.TempDir()
	if err := os.Chmod(crashed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashed, initMarkerFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashed, x25519KeyFile), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, created, err := InitState(crashed, "amos-signer-a"); err != nil || !created {
		t.Fatalf("recovery from an interrupted first start: %v %v", created, err)
	}

	// 私钥文件权限放宽：拒绝
	if err := os.Chmod(filepath.Join(crashed, x25519KeyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeys(crashed); err == nil {
		t.Fatal("loaded a world-readable private key")
	}
}

func TestRunLockAndPrepare(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	lock, err := AcquireRunLock(h.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := AcquireRunLock(h.cfg.StateDir); err == nil {
		t.Fatal("a second signer run acquired the lock")
	}
	// 启动时清掉运行时目录里上次留下的明文
	leftover := filepath.Join(h.cfg.RuntimeDir, "sign-leftover")
	if err := os.MkdirAll(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leftover, "keystore.p12"), []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.runner.Prepare(); err != nil {
		t.Fatal(err)
	}
	h.assertRuntimeEmpty()
}

func TestHTTPClient(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-machine-token") != "" {
			redirected.Add(1)
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	var seenAttempt atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/signer/claim":
			http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
		case "/v1/signer/jobs/bld_abc12345/heartbeat":
			seenAttempt.Store(r.Header.Get("x-sign-attempt"))
			problemJSON(w, 409, "SIGN_ATTEMPT_STALE", "stale\x1b[2J attempt")
		case "/v1/signer/jobs/bld_abc12345/release":
			problemJSON(w, 409, "RELEASE_SEQUENCE_BUSY", "busy")
		case "/v1/signer/jobs/bld_abc12345/reject":
			problemJSON(w, 503, "UNAVAILABLE", "down")
		case "/v1/signer/keystore-checks":
			problemJSON(w, 401, "MACHINE_REVOKED", "revoked")
		case "/v1/signer/jobs/bld_abc12345/complete":
			problemJSON(w, 409, "SIGNED_ARTIFACT_REPLACED", "replaced")
		case "/v1/signer/jobs/bld_abc12345/signed/upload":
			problemJSON(w, 424, "UPLOAD_STORAGE_FAILED", "storage")
		case "/v1/signer/jobs/bld_abc12345/unsigned/download":
			w.Header().Set("content-length", "100")
			_, _ = w.Write([]byte("short"))
		default:
			problemJSON(w, 404, "NOT_FOUND", "nope")
		}
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, testToken, nil)
	ctx := context.Background()

	if _, err := c.Claim(ctx, nil); err == nil {
		t.Fatal("a redirect response was treated as success")
	}
	if redirected.Load() != 0 {
		t.Fatal("the machine token was sent to a redirect target")
	}
	err := c.Heartbeat(ctx, "bld_abc12345", 7)
	if !IsStale(err) || seenAttempt.Load() != "7" {
		t.Fatalf("heartbeat: %v, attempt header %v", err, seenAttempt.Load())
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatal("a server detail with control characters reached the error text")
	}
	if err := c.Release(ctx, "bld_abc12345", 1, "X", "y"); !IsTransient(err) {
		t.Fatalf("RELEASE_SEQUENCE_BUSY must be transient: %v", err)
	}
	if err := c.Reject(ctx, "bld_abc12345", 1, "violation", "X", "y"); !IsTransient(err) {
		t.Fatalf("503 must be transient: %v", err)
	}
	var apiErr *APIError
	if _, err := c.KeystoreChecks(ctx); !IsRevoked(err) || IsTransient(err) {
		t.Fatalf("401 MACHINE_REVOKED: %v", err)
	}
	if _, err := c.Complete(ctx, "bld_abc12345", 1, CompleteRequest{}); !IsTransient(err) || IsStale(err) {
		t.Fatalf("SIGNED_ARTIFACT_REPLACED must be retried: %v", err)
	}
	signed := filepath.Join(t.TempDir(), "signed.apk")
	must(t, os.WriteFile(signed, []byte("apk"), 0o600))
	if _, err := c.UploadSigned(ctx, "bld_abc12345", 1, signed); !IsTransient(err) {
		t.Fatalf("UPLOAD_STORAGE_FAILED must be retried: %v", err)
	}
	if err := c.ReportChecks(ctx, "leader", TrustReport{}, nil); err == nil || IsTransient(err) {
		t.Fatalf("an unknown local role was sent: %v", err)
	}
	if err := c.ReportChecks(ctx, records.RoleStandby, TrustReport{}, nil); !errors.As(err, &apiErr) || apiErr.Transient() || IsTransient(err) {
		t.Fatalf("404 must not be transient: %v", err)
	}
	var sink bytes.Buffer
	if _, err := c.DownloadUnsigned(ctx, "bld_abc12345", 1, &sink, 1000); err == nil {
		t.Fatal("a truncated download succeeded")
	}
	if strings.Contains(c.String(), testToken) {
		t.Fatal("the client's String includes the token")
	}
}
