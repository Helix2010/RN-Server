package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// 升级程序的每一道闸（设计 ios-mac-builders-home-network-2026-09-18 §5.6）。
//
// 自升级是唯一一条"服务端能往每台 Mac 上放可执行代码"的路，而每台 Mac 上放着全部租户的
// 签名材料。所以这一组用例盯的不是"能不能升级成功"，而是**该拒的时候拒不拒**。

const (
	newCommit = "1111111111111111111111111111111111111111"
	oldCommit = "2222222222222222222222222222222222222222"
)

type fakeBundleServer struct {
	t         *testing.T
	bundle    string
	manifest  []byte
	signature bundlesig.Signature
	archive   []byte
	server    *httptest.Server
}

// newBundle 造一组安装包：一个 tar.gz，里面是可执行的假二进制，配一份清单与离线签名。
func newBundle(t *testing.T, private ed25519.PrivateKey, commit string, sequence int64, agentScript string) *fakeBundleServer {
	t.Helper()
	files := map[string][]byte{
		"bin/build-agent":  []byte(agentScript),
		"bin/build-runner": []byte("#!/bin/sh\nexit 0\n"),
		"bin/ios-upload":   []byte("#!/bin/sh\nexit 0\n"),
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	writer := tar.NewWriter(gz)
	entries := []string{"bin/build-agent", "bin/build-runner", "bin/ios-upload"}
	for _, name := range entries {
		body := files[name]
		if err := writer.WriteHeader(&tar.Header{Name: "./" + name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	listed := []map[string]any{}
	for _, name := range entries {
		sum := sha256.Sum256(files[name])
		listed = append(listed, map[string]any{"name": name, "size": len(files[name]), "sha256": hex.EncodeToString(sum[:])})
	}
	archiveSum := sha256.Sum256(archive.Bytes())
	manifest, err := json.Marshal(map[string]any{
		"format": "rn-machine-bundles/v1", "commit": commit,
		"bundles": map[string]any{"builder": map[string]any{
			"archive": "builder.tar.gz", "archiveSha256": hex.EncodeToString(archiveSum[:]),
			"archiveSize": archive.Len(), "files": listed,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := bundlesig.Sign(private, manifest, commit, sequence, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeBundleServer{t: t, bundle: "builder", manifest: manifest, signature: signature, archive: archive.Bytes()}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-machine-token") == "" {
			t.Error("the upgrade helper did not send the machine token")
		}
		switch r.URL.Path {
		case "/v1/build-agent/bundle":
			sum := sha256.Sum256(fake.archive)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle": fake.bundle, "commit": fake.signature.Commit,
				"manifestBase64": base64.StdEncoding.EncodeToString(fake.manifest),
				"signature":      fake.signature,
				"archive": map[string]any{"name": "builder.tar.gz", "sha256": hex.EncodeToString(sum[:]),
					"size": len(fake.archive), "url": "/v1/build-agent/bundle/archive"},
			})
		case "/v1/build-agent/bundle/archive":
			_, _ = w.Write(fake.archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fake.server.Close)
	return fake
}

// machine 摆出一台装好的机器：安装目录、状态目录、env 文件、pin 好的发布公钥。
type machine struct {
	installDir string
	stateDir   string
	envFile    string
}

func newMachine(t *testing.T, public ed25519.PublicKey, server string) machine {
	t.Helper()
	root := t.TempDir()
	m := machine{
		installDir: filepath.Join(root, "opt"),
		stateDir:   filepath.Join(root, "state"),
		envFile:    filepath.Join(root, "rn-build-agent.env"),
	}
	for _, dir := range []string{m.installDir, m.stateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(m.installDir, releaseKeyName),
		[]byte(bundlesig.SSHPublicKeyLine(public, "rn-release-key")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range upgradeBinaries {
		if err := os.WriteFile(filepath.Join(m.installDir, name), []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := "BUILD_AGENT_SERVER=" + server + "\n" +
		"BUILD_AGENT_MACHINE_TOKEN=rnm_" + strings.Repeat("a", 43) + "\n" +
		"BUILD_AGENT_STATE_DIR=" + m.stateDir + "\n" +
		"# a comment\n\n"
	if err := os.WriteFile(m.envFile, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m machine) requestUpgrade(t *testing.T, commit string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(m.stateDir, haltFileName), []byte("upgrade:"+commit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (m machine) run(t *testing.T) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"--env", m.envFile, "--install-dir", m.installDir}, &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

// 冒烟用的假 build-agent：空环境下以 2 退出，就像真的那个"配置不全"。
const goodAgent = "#!/bin/sh\nexit 2\n"

func TestUpgradeInstallsASignedBundle(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := newBundle(t, private, newCommit, 5, goodAgent)
	m := newMachine(t, public, fake.server.URL)
	m.requestUpgrade(t, newCommit)

	if code, output := m.run(t); code != 0 {
		t.Fatalf("upgrade: %d %s", code, output)
	}
	installed, err := os.ReadFile(filepath.Join(m.installDir, "build-agent"))
	if err != nil || string(installed) != goodAgent {
		t.Fatalf("the binary was not replaced: %q %v", installed, err)
	}
	// 成败都要删标记：不删的话 launchd 永远不会把代理拉起来，机器就静悄悄地离线了
	if _, err := os.Stat(filepath.Join(m.stateDir, haltFileName)); !os.IsNotExist(err) {
		t.Fatal("the halt marker was left behind")
	}
	if got := readSequence(filepath.Join(m.installDir, sequenceFileName)); got != 5 {
		t.Fatalf("sequence high-water mark is %d", got)
	}
	// 同一份清单再来一次也行（序号相等不算降级）；更低的就不行了
	m.requestUpgrade(t, newCommit)
	if code, output := m.run(t); code != 0 {
		t.Fatalf("re-running the same upgrade: %d %s", code, output)
	}
}

func TestUpgradeRefusesEverythingItCannotProve(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		build   func(*testing.T) *fakeBundleServer
		request string
		want    string
	}{
		"signed by another release key": {
			build:   func(t *testing.T) *fakeBundleServer { return newBundle(t, otherKey, newCommit, 9, goodAgent) },
			request: newCommit, want: "another release key",
		},
		"a manifest that was changed after signing": {
			build: func(t *testing.T) *fakeBundleServer {
				fake := newBundle(t, private, newCommit, 9, goodAgent)
				fake.manifest = append(fake.manifest, ' ')
				return fake
			},
			request: newCommit, want: "does not match its signature",
		},
		"another commit than the one the agent was told": {
			build:   func(t *testing.T) *fakeBundleServer { return newBundle(t, private, oldCommit, 9, goodAgent) },
			request: newCommit, want: "but this machine was told to install",
		},
		"a binary that cannot run here": {
			build: func(t *testing.T) *fakeBundleServer {
				return newBundle(t, private, newCommit, 9, "#!/bin/sh\nexit 0\n")
			},
			request: newCommit, want: "expected 2",
		},
		"an archive that does not match the signed manifest": {
			build: func(t *testing.T) *fakeBundleServer {
				fake := newBundle(t, private, newCommit, 9, goodAgent)
				fake.archive = append(fake.archive, 0)
				return fake
			},
			request: newCommit, want: "archive",
		},
	}
	for name, testCase := range cases {
		fake := testCase.build(t)
		m := newMachine(t, public, fake.server.URL)
		m.requestUpgrade(t, testCase.request)
		code, output := m.run(t)
		if code == 0 {
			t.Errorf("%s was installed", name)
			continue
		}
		if !strings.Contains(output, testCase.want) {
			t.Errorf("%s: %s", name, output)
		}
		// 旧的二进制原样留着，标记删掉了（代理这就回来接着跑旧版），失败原因记下来了
		if raw, err := os.ReadFile(filepath.Join(m.installDir, "build-agent")); err != nil || !strings.Contains(string(raw), "exit 9") {
			t.Errorf("%s: the old binary was replaced anyway: %q", name, raw)
		}
		if _, err := os.Stat(filepath.Join(m.stateDir, haltFileName)); !os.IsNotExist(err) {
			t.Errorf("%s: the halt marker was left behind, so launchd will never start the agent again", name)
		}
		if _, err := os.Stat(filepath.Join(m.stateDir, "upgrade-failed.json")); err != nil {
			t.Errorf("%s: the failure was not recorded for the agent to report", name)
		}
	}
}

// 降级要挡住：攻破服务端的人不能把机器推回一个当初确实被签过、但有已知漏洞的旧版。
func TestUpgradeRefusesALowerSequence(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := newBundle(t, private, newCommit, 9, goodAgent)
	m := newMachine(t, public, fake.server.URL)
	m.requestUpgrade(t, newCommit)
	if code, output := m.run(t); code != 0 {
		t.Fatalf("first upgrade: %d %s", code, output)
	}
	older := newBundle(t, private, oldCommit, 4, goodAgent)
	m2 := machine{installDir: m.installDir, stateDir: m.stateDir, envFile: m.envFile}
	if err := os.WriteFile(m2.envFile, []byte(strings.Replace(readFile(t, m2.envFile), fake.server.URL, older.server.URL, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	m2.requestUpgrade(t, oldCommit)
	code, output := m2.run(t)
	if code == 0 || !strings.Contains(output, "below the 9 this machine already accepted") {
		t.Fatalf("a downgrade was accepted: %d %s", code, output)
	}
}

// 标记不是"去升级"（例如机器被吊销）：这个程序什么都不做，**尤其不删那个标记**——
// 被吊销的机器就该停在那里。
func TestUpgradeLeavesAnUnrelatedHaltMarkerAlone(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fake := newBundle(t, private, newCommit, 1, goodAgent)
	m := newMachine(t, public, fake.server.URL)
	if err := os.WriteFile(filepath.Join(m.stateDir, haltFileName), []byte("revoked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, output := m.run(t); code != 0 {
		t.Fatalf("%d %s", code, output)
	}
	if _, err := os.Stat(filepath.Join(m.stateDir, haltFileName)); err != nil {
		t.Fatal("a halt marker that was not an upgrade request was removed")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
