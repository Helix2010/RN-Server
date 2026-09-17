package signer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/records"
)

// peerMachine 是测试里另一台签名闸的两把密钥。
type peerMachine struct {
	name string
	id   string
	x    *ecdh.PrivateKey
	ed   ed25519.PrivateKey
}

func newPeerMachine(t *testing.T, name, id string) peerMachine {
	t.Helper()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return peerMachine{name: name, id: id, x: x, ed: ed}
}

func (p peerMachine) xPub() []byte             { return p.x.PublicKey().Bytes() }
func (p peerMachine) edPub() ed25519.PublicKey { return p.ed.Public().(ed25519.PublicKey) }
func (p peerMachine) xSHA() string             { return fingerprint.SHA256Hex(p.xPub()) }
func (p peerMachine) edSHA() string            { return fingerprint.SHA256Hex(p.edPub()) }
func (p peerMachine) machineKeys() MachineKeys { return MachineKeys{X25519: p.x, Ed25519: p.ed} }
func (p peerMachine) trust(mode string) records.PeerTrust {
	return records.PeerTrust{Name: p.name, X25519PublicKeySHA256: p.xSHA(), Ed25519PublicKeySHA256: p.edSHA(), Mode: mode, Operator: "ops-alice"}
}

func (p peerMachine) view(role string) PeerSigner {
	r := role
	return PeerSigner{MachineID: p.id, Name: p.name, Status: "active", SignerRole: &r,
		X25519PublicKey: base64.StdEncoding.EncodeToString(p.xPub()), X25519PublicKeySHA256: p.xSHA(),
		Ed25519PublicKey: base64.StdEncoding.EncodeToString(p.edPub()), Ed25519PublicKeySHA256: p.edSHA()}
}

type recoveryKeyPair struct {
	priv *ecdh.PrivateKey
	view PeerRecoveryKey
}

func newRecoveryKeyPair(t *testing.T, name string) recoveryKeyPair {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	return recoveryKeyPair{priv: k, view: PeerRecoveryKey{Name: name, X25519PublicKey: base64.StdEncoding.EncodeToString(pub), X25519PublicKeySHA256: fingerprint.SHA256Hex(pub)}}
}

func (r recoveryKeyPair) trust() records.RecoveryTrust {
	return records.RecoveryTrust{Name: r.view.Name, X25519PublicKeySHA256: r.view.X25519PublicKeySHA256, Mode: records.TrustModeOperator, Operator: "ops-alice"}
}

// enrollFixture 是一台待注册的签名闸：由模板渲染的 env 文件、还不存在的状态目录、按测试用户改造的 rootHost。
type enrollFixture struct {
	dir      string
	envFile  string
	stateDir string
	server   *fakeServer
	host     *rootHost
	exec     bool // true：enroll-init 以子进程执行
	primary  peerMachine
	recovery recoveryKeyPair
}

func newEnrollFixture(t *testing.T, signerRole string) *enrollFixture {
	t.Helper()
	dir := t.TempDir()
	tmpl, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "signer", "templates", "rn-signer-@INSTANCE@.env"))
	if err != nil {
		t.Fatalf("read the env template: %v", err)
	}
	f := &enrollFixture{dir: dir, envFile: filepath.Join(dir, "rn-signer-amos-signer-c.env"), stateDir: filepath.Join(dir, "state"),
		server: newFakeServer(t), primary: newPeerMachine(t, "amos-signer-a", "mch_signerA0001"), recovery: newRecoveryKeyPair(t, "platform-recovery")}
	rendered := strings.ReplaceAll(string(tmpl), "/var/lib/rn-signer-@INSTANCE@", f.stateDir)
	rendered = strings.ReplaceAll(rendered, "@INSTANCE@", "amos-signer-c")
	must(t, os.WriteFile(f.envFile, []byte(rendered), 0o640))
	must(t, os.Chmod(f.envFile, 0o640))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	f.host = &rootHost{rootUID: uid, exe: exe, lookupUser: func(g int) (enrollAccount, error) {
		if g != gid {
			return enrollAccount{}, errors.New("unexpected group")
		}
		return enrollAccount{Name: "rn-signer-amos-signer-c", UID: uid, GID: gid}, nil
	}}
	role := signerRole
	f.server.enrollToken = testToken
	f.server.describe = map[string]any{
		"machineId": "mch_signerC0001", "name": "amos-signer-c", "role": "signer", "signerRole": role,
		"bundle":       map[string]any{"role": "signer", "commit": "abc", "archive": "signer.tar.gz"},
		"recoveryKeys": []PeerRecoveryKey{f.recovery.view, newRecoveryKeyPair(t, "other-recovery").view},
	}
	if signerRole == "standby" {
		v := f.primary.view("primary")
		f.server.describe["primarySigner"] = map[string]any{"machineId": v.MachineID, "name": v.Name, "x25519PublicKey": v.X25519PublicKey,
			"x25519PublicKeySha256": v.X25519PublicKeySHA256, "ed25519PublicKey": v.Ed25519PublicKey, "ed25519PublicKeySha256": v.Ed25519PublicKeySHA256}
	} else {
		f.server.describe["primarySigner"] = nil
	}
	return f
}

func (f *enrollFixture) opts() EnrollOptions {
	return EnrollOptions{ServerURL: f.server.srv.URL, Code: testEnrollCode, EnvFile: f.envFile, RecoverySHA256: strings.ToUpper(f.recovery.view.X25519PublicKeySHA256)}
}

func (f *enrollFixture) enroll(opts EnrollOptions) (string, error) {
	var out bytes.Buffer
	var host enrollHost = f.host
	if !f.exec {
		host = inProcessHost{f.host}
	}
	err := Enroll(context.Background(), opts, NewHTTPClient(f.server.srv.URL, "", nil), host, &out)
	return out.String(), err
}

// inProcessHost 与 rootHost 相同，只是不启动子进程（-race 下启动测试二进制很慢）。
// TestEnrollStandby 走真正的子进程路径。
type inProcessHost struct{ *rootHost }

func (h inProcessHost) Init(_ enrollAccount, req enrollInitRequest) (enrollInitResult, error) {
	return runEnrollInit(req)
}

func TestEnrollStandby(t *testing.T) {
	f := newEnrollFixture(t, "standby")
	f.exec = true
	// 注册码走环境变量时，降权执行的 enroll-init 子进程拿不到它（TestMain 在子进程里核对）
	t.Setenv(EnvEnrollmentCode, testEnrollCode)
	out, err := f.enroll(f.opts())
	if err != nil {
		t.Fatalf("Enroll: %v\n%s", err, out)
	}
	// 令牌与注册码都不上屏
	if strings.Contains(out, testToken) || strings.Contains(out, testEnrollCode) {
		t.Fatal("enroll printed the machine token or the enrollment code")
	}
	info, err := os.Stat(f.envFile)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("env file mode: %v %v", info, err)
	}
	values, err := ReadEnvFile(f.envFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(func(k string) string { return values[k] }, NeedServer)
	if err != nil {
		t.Fatalf("the written env file does not load: %v", err)
	}
	if cfg.MachineToken != testToken || cfg.Name != "amos-signer-c" || cfg.ServerURL != f.server.srv.URL || cfg.StateDir != f.stateDir || values[EnvCheckSocket] != "/run/rn-signer-amos-signer-c-check.sock" {
		t.Fatalf("env: %v", cfg)
	}
	raw, _ := os.ReadFile(f.envFile)
	if !strings.Contains(string(raw), "# versionCode 上限") || !strings.Contains(string(raw), "# written by signer enroll") {
		t.Fatal("the template's comments were not kept")
	}
	keys, store, err := OpenRecords(f.stateDir, "amos-signer-c")
	if err != nil {
		t.Fatalf("OpenRecords after enroll: %v", err)
	}
	defer store.Close()
	for _, want := range []string{"amos-signer-c", keys.X25519SHA256(), keys.Ed25519SHA256(), f.recovery.view.X25519PublicKeySHA256,
		"trust-peer --peer amos-signer-a", "trust-peer --peer amos-signer-c"} {
		if !strings.Contains(out, want) {
			t.Fatalf("enroll output lacks %q:\n%s", want, out)
		}
	}
	// 主签名闸的指纹要从那台机器上抄，不从服务端给的值上屏
	if strings.Contains(out, f.primary.edSHA()) || strings.Contains(out, f.primary.xSHA()) {
		t.Fatalf("enroll printed the server's fingerprints for the primary:\n%s", out)
	}
	if len(f.server.enrolls) != 1 || f.server.enrolls[0]["x25519PublicKey"] != base64.StdEncoding.EncodeToString(keys.X25519PublicKey()) ||
		f.server.enrolls[0]["ed25519PublicKey"] != base64.StdEncoding.EncodeToString(keys.Ed25519PublicKey()) {
		t.Fatalf("enrolled keys: %+v", f.server.enrolls)
	}
	role, _ := store.Role()
	rec, _ := store.TrustedRecoveryKeys()
	peers, _ := store.TrustedPeers()
	if role.Role != records.RoleStandby || role.Mode != records.RoleModeEnroll ||
		len(rec) != 1 || rec[0].X25519PublicKeySHA256 != f.recovery.view.X25519PublicKeySHA256 || rec[0].Mode != records.TrustModeEnroll ||
		len(peers) != 0 {
		t.Fatalf("records: role %+v recovery %+v peers %+v", role, rec, peers)
	}
	if _, created, err := InitState(f.stateDir, "amos-signer-c"); err != nil || created {
		t.Fatalf("signer run's InitState after enroll: %v %v", created, err)
	}

	// 重复执行（install.sh 幂等）：注册码已用过，不再访问服务端
	out, err = f.enroll(f.opts())
	if err != nil || !strings.Contains(out, "already enrolled") || !strings.Contains(out, keys.X25519SHA256()) {
		t.Fatalf("second enroll: %v\n%s", err, out)
	}
}

// 评审 P1-1、P1-2（TestReviewSecondLocalPrimaryCanReuseVersionCode）：服务端说这台是主、给了一台主签名闸，
// enroll 照样只写本机备、不信任任何签名闸。主只由本机 promote 产生，签名闸之间的信任只由本机 trust-peer 写入。
func TestEnrollIgnoresTheServersRoleAndPrimary(t *testing.T) {
	cases := map[string]struct {
		signerRole string
		mutate     func(*enrollFixture)
		want       []string
		notWant    []string
	}{
		"console says primary": {signerRole: "primary",
			want: []string{"registered this machine as the primary", "promote --first", "trust-builder --builder"}},
		"console says standby": {signerRole: "standby",
			want: []string{"trust-peer --peer amos-signer-a", "trust-peer --peer amos-signer-c"}},
		"standby before any primary": {signerRole: "standby", mutate: func(f *enrollFixture) { f.server.describe["primarySigner"] = nil },
			want: []string{"no primary signing gate yet", "install the primary first"}, notWant: []string{"trust-peer --peer amos-signer-a"}},
		"primary names itself": {signerRole: "standby", mutate: func(f *enrollFixture) {
			f.server.describe["primarySigner"].(map[string]any)["name"] = "amos-signer-c"
		}, notWant: []string{"trust-peer --peer amos-signer-a"}},
		"primary key mismatch": {signerRole: "standby", mutate: func(f *enrollFixture) {
			f.server.describe["primarySigner"].(map[string]any)["ed25519PublicKeySha256"] = strings.Repeat("cd", 32)
		}, want: []string{"trust-peer --peer amos-signer-a"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newEnrollFixture(t, c.signerRole)
			if c.mutate != nil {
				c.mutate(f)
			}
			opts := f.opts()
			opts.NameCheck = "amos-signer-c"
			out, err := f.enroll(opts)
			if err != nil {
				t.Fatalf("Enroll: %v\n%s", err, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range append(c.notWant, f.primary.edSHA(), f.primary.xSHA()) {
				if strings.Contains(out, w) {
					t.Errorf("output contains %q:\n%s", w, out)
				}
			}
			keys, store, err := OpenRecords(f.stateDir, "amos-signer-c")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			role, _ := store.Role()
			peers, _ := store.TrustedPeers()
			if role.Role != records.RoleStandby || role.Mode != records.RoleModeEnroll || len(peers) != 0 {
				t.Fatalf("role %+v peers %+v", role, peers)
			}
			// 平台第一台主：在本机 promote --first，接在 enroll 写的备记录后面
			if c.signerRole == "primary" {
				env := OperatorEnv{Keys: keys, Store: store}
				term := newTerm("ops-erin", "first primary signing gate", "amos-signer-c")
				env.Term = term
				if err := Promote(env, PromoteFirst, ""); err != nil {
					t.Fatalf("promote --first after enroll: %v\n%s", err, term.out.String())
				}
				if role, _ := store.Role(); role.Role != records.RolePrimary || role.Mode != records.RoleModeInitial {
					t.Fatalf("role after promote --first: %+v", role)
				}
			}
		})
	}
}

// 评审 P2-b：注册码可以走环境变量 RN_ENROLLMENT_CODE（不进进程参数）；与 --code 同时给且不同就拒绝；
// 读完从本进程环境里清掉。
func TestEnrollCodeFromTheEnvironment(t *testing.T) {
	other := "rne_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"
	run := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		// --env-file 故意给相对路径：在碰 root 与网络之前失败，只看注册码的取值
		code := Main(append([]string{"enroll", "--server", "https://api.example.com", "--env-file", "relative.env", "--recovery-sha256", strings.Repeat("ab", 32)}, args...),
			os.Stdin, &stdout, &stderr, os.Getenv)
		return code, stdout.String() + stderr.String()
	}
	t.Setenv(EnvEnrollmentCode, testEnrollCode)
	code, out := run("--code", other)
	if code != 1 || !strings.Contains(out, EnvEnrollmentCode) || strings.Contains(out, testEnrollCode) || strings.Contains(out, other) {
		t.Fatalf("different --code and %s: exit %d\n%s", EnvEnrollmentCode, code, out)
	}
	if v, ok := os.LookupEnv(EnvEnrollmentCode); ok {
		t.Fatalf("%s is still in the environment (%d characters)", EnvEnrollmentCode, len(v))
	}
	for name, args := range map[string][]string{"environment only": nil, "same value in both": {"--code", testEnrollCode}} {
		t.Setenv(EnvEnrollmentCode, testEnrollCode)
		code, out := run(args...)
		// 注册码被接受，往下走到 --env-file 的检查
		if code != 1 || !strings.Contains(out, "--env-file must be an absolute clean path") || strings.Contains(out, testEnrollCode) {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
		if _, ok := os.LookupEnv(EnvEnrollmentCode); ok {
			t.Errorf("%s: %s is still in the environment", name, EnvEnrollmentCode)
		}
	}
	os.Unsetenv(EnvEnrollmentCode)
	if code, out := run(); code != 1 || !strings.Contains(out, "not an enrollment code") {
		t.Fatalf("no code at all: exit %d\n%s", code, out)
	}
}

func TestEnrollRefusals(t *testing.T) {
	refusals := map[string]struct {
		mutate func(*enrollFixture, *EnrollOptions)
		want   string
	}{
		"recovery sha unknown": {func(f *enrollFixture, o *EnrollOptions) { o.RecoverySHA256 = strings.Repeat("ab", 32) }, "no recovery key"},
		"recovery sha missing": {func(f *enrollFixture, o *EnrollOptions) { o.RecoverySHA256 = "" }, "--recovery-sha256 is required"},
		"recovery sha short":   {func(f *enrollFixture, o *EnrollOptions) { o.RecoverySHA256 = "abcd" }, "--recovery-sha256"},
		"builder code":         {func(f *enrollFixture, o *EnrollOptions) { f.server.describe["role"] = "builder" }, "not for a signing gate"},
		"name check":           {func(f *enrollFixture, o *EnrollOptions) { o.NameCheck = "amos-signer-d" }, "not amos-signer-d"},
		"bad code":             {func(f *enrollFixture, o *EnrollOptions) { o.Code = "rne_short-secret-code" }, "not an enrollment code"},
		"unknown code":         {func(f *enrollFixture, o *EnrollOptions) { f.server.describe = nil }, "ENROLLMENT_CODE_INVALID"},
		"http server":          {func(f *enrollFixture, o *EnrollOptions) { o.ServerURL = "http://api.anyfun.win" }, "loopback"},
		"relative env":         {func(f *enrollFixture, o *EnrollOptions) { o.EnvFile = "rn-signer.env" }, "--env-file"},
		"env world readable": {func(f *enrollFixture, o *EnrollOptions) {
			must(t, os.Chmod(f.envFile, 0o644))
		}, "permissions"},
	}
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			f := newEnrollFixture(t, "standby")
			opts := f.opts()
			c.mutate(f, &opts)
			before, _ := os.ReadFile(f.envFile)
			out, err := f.enroll(opts)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Enroll = %v, want %q\n%s", err, c.want, out)
			}
			if strings.Contains(err.Error(), "short-secret-code") || strings.Contains(out, "short-secret-code") {
				t.Fatal("the enrollment code was echoed")
			}
			after, _ := os.ReadFile(f.envFile)
			if !bytes.Equal(before, after) || len(f.server.enrolls) != 0 {
				t.Fatal("a refused enrollment changed the env file or enrolled")
			}
			if entries, _ := os.ReadDir(f.stateDir); len(entries) != 0 {
				t.Fatalf("a refused enrollment left files in the state directory: %d", len(entries))
			}
		})
	}
}

// 已经有本机记录（手工流程装的机器、或者状态目录被复用）：enroll 不重新初始化。
func TestEnrollRefusesExistingRecords(t *testing.T) {
	f := newEnrollFixture(t, "standby")
	must(t, os.Mkdir(f.stateDir, 0o700))
	if _, _, err := InitState(f.stateDir, "amos-signer-c"); err != nil {
		t.Fatal(err)
	}
	out, err := f.enroll(f.opts())
	if err == nil || !strings.Contains(err.Error(), "already holds machine keys") {
		t.Fatalf("Enroll over existing records: %v\n%s", err, out)
	}
	if len(f.server.enrolls) != 0 {
		t.Fatal("enrolled over existing records")
	}
	// env 里有令牌但状态目录是空的：不复用令牌
	g := newEnrollFixture(t, "standby")
	raw, _ := os.ReadFile(g.envFile)
	must(t, os.WriteFile(g.envFile, append(raw, []byte("SIGNER_MACHINE_TOKEN=\""+testToken+"\"\n")...), 0o640))
	if _, err := g.enroll(g.opts()); err == nil || !strings.Contains(err.Error(), "already has a machine token") {
		t.Fatalf("token without state: %v", err)
	}
}

// 换到令牌之前中断：留下 enroll.incomplete，signer run 拒绝启动；换一个新注册码重跑时清掉重来。
func TestEnrollInterruptedBeforeTheToken(t *testing.T) {
	f := newEnrollFixture(t, "standby")
	describe := f.server.describe
	// enroll 接口失败（注册码被别人抢先用掉）
	f.host.exe = mustExecutable(t)
	orig := f.server.enrollToken
	f.server.enrollToken = "not-a-token"
	out, err := f.enroll(f.opts())
	if err == nil || !strings.Contains(err.Error(), "malformed machine token") {
		t.Fatalf("Enroll with a bad token response: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(f.stateDir, enrollMarkerFile)); err != nil {
		t.Fatal("no enroll marker after an interrupted enrollment")
	}
	if _, _, err := InitState(f.stateDir, "amos-signer-c"); !errors.Is(err, errEnrollPending) {
		t.Fatalf("signer run started on an unfinished enrollment: %v", err)
	}
	if _, err := LoadKeys(f.stateDir); !errors.Is(err, errEnrollPending) {
		t.Fatalf("operator commands used an unfinished enrollment: %v", err)
	}
	firstKeys := f.server.enrolls[0]["x25519PublicKey"]
	// 控制台重发注册码后重跑
	f.server.describe, f.server.enrollToken = describe, orig
	if out, err := f.enroll(f.opts()); err != nil {
		t.Fatalf("re-enroll: %v\n%s", err, out)
	}
	keys, store, err := OpenRecords(f.stateDir, "amos-signer-c")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if base64.StdEncoding.EncodeToString(keys.X25519PublicKey()) == firstKeys {
		t.Fatal("the interrupted enrollment's keys were reused")
	}
	if role, _ := store.Role(); role.Role != records.RoleStandby || role.Mode != records.RoleModeEnroll {
		t.Fatalf("records after re-enrollment: %+v", role)
	}
}

func TestUpdateEnvFile(t *testing.T) {
	raw := []byte("# comment SIGNER_NAME=\"x\"\nSIGNER_STATE_DIR=\"/var/lib/a\"\n  SIGNER_MACHINE_TOKEN=\"old\"\nSIGNER_MAX_VERSION_CODE=\"5\"")
	out := string(updateEnvFile(raw, map[string]string{EnvServerURL: "https://api.example.com", EnvName: "amos-signer-c", EnvMachineToken: testToken}))
	want := "# comment SIGNER_NAME=\"x\"\nSIGNER_STATE_DIR=\"/var/lib/a\"\nSIGNER_MACHINE_TOKEN=\"" + testToken + "\"\nSIGNER_MAX_VERSION_CODE=\"5\"\n" +
		"\n# written by signer enroll\nSIGNER_SERVER_URL=\"https://api.example.com\"\nSIGNER_NAME=\"amos-signer-c\"\n"
	if out != want {
		t.Fatalf("updateEnvFile:\n%s\nwant:\n%s", out, want)
	}
}

func TestEnrollResponseNeverPrintsTheToken(t *testing.T) {
	r := EnrollResponse{MachineID: "mch_x0001", Token: testToken, Status: "pending_key"}
	var buf bytes.Buffer
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		buf.Reset()
		_, _ = fmt.Fprintf(&buf, format, r)
		if strings.Contains(buf.String(), testToken) || strings.Contains(buf.String(), "414141") {
			t.Fatalf("%s leaks the token: %s", format, buf.String())
		}
	}
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}
