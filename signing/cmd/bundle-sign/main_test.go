package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func bundleDir(t *testing.T, commit string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := map[string]any{
		"format": "rn-machine-bundles/v1", "commit": commit,
		"bundles": map[string]any{"builder": map[string]any{"archive": "builder.tar.gz"}},
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newReleaseKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"key", "create", "--out", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("key create: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "public key sha256:") {
		t.Fatalf("key create must print the sha256 to check out of band: %s", stdout.String())
	}
	info, err := os.Stat(filepath.Join(dir, "release-key.ed25519"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the private key must be 0600: %v %v", info, err)
	}
	return dir
}

func TestSignThenVerifyRoundTrip(t *testing.T) {
	keys := newReleaseKey(t)
	dir := bundleDir(t, testCommit)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--key", filepath.Join(keys, "release-key.ed25519"), "--dir", dir, "--sequence", "5"}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign: %d %s", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, bundlesig.FileName))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := bundlesig.Parse(raw)
	if err != nil || signature.Sequence != 5 || signature.Commit != testCommit {
		t.Fatalf("signature: %+v %v", signature, err)
	}
	pub := filepath.Join(keys, "release-key.pub")
	stdout.Reset()
	if code := run([]string{"verify", "--pub", pub, "--dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("verify: %d %s", code, stderr.String())
	}
	// 序号回退与提交不符都要拒：这两条正是"攻破服务端之后能做什么"的边界
	if code := run([]string{"verify", "--pub", pub, "--dir", dir, "--min-sequence", "6"}, &stdout, &stderr); code == 0 {
		t.Fatal("a signature older than the one this machine saw was accepted")
	}
	if code := run([]string{"verify", "--pub", pub, "--dir", dir, "--expect-commit", strings.Repeat("a", 40)}, &stdout, &stderr); code == 0 {
		t.Fatal("a signature for another commit was accepted")
	}
}

// 清单被改过：验签当场失败。安装包目录在服务端上，这正是它被攻破时会做的事。
func TestVerifyRefusesATamperedManifest(t *testing.T) {
	keys := newReleaseKey(t)
	dir := bundleDir(t, testCommit)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--key", filepath.Join(keys, "release-key.ed25519"), "--dir", dir, "--sequence", "1"}, &stdout, &stderr); code != 0 {
		t.Fatalf("sign: %d %s", code, stderr.String())
	}
	path := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(raw, []byte("builder.tar.gz"), []byte("builder.tar.gX"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"verify", "--pub", filepath.Join(keys, "release-key.pub"), "--dir", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("a manifest that was changed after signing verified")
	}
}

// 工作区不干净的构建签不了：它的提交号带 -dirty，而那样的东西不该上任何一台 Mac。
func TestSignRefusesADirtyBundle(t *testing.T) {
	keys := newReleaseKey(t)
	dir := bundleDir(t, testCommit+"-dirty")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"sign", "--key", filepath.Join(keys, "release-key.ed25519"), "--dir", dir, "--sequence", "1"}, &stdout, &stderr); code == 0 {
		t.Fatal("a -dirty bundle was signed")
	}
}

// 已经有一把私钥时不覆盖：那把签过历史清单，盖掉它等于让所有 Mac 的单调序号断在半路。
func TestKeyCreateNeverOverwritesAnExistingKey(t *testing.T) {
	dir := newReleaseKey(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"key", "create", "--out", dir}, &stdout, &stderr); code == 0 {
		t.Fatal("an existing release key was overwritten")
	}
}

func TestUsageIsRefusedNotGuessed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for name, args := range map[string][]string{
		"no arguments":  {},
		"unknown":       {"publish"},
		"key no create": {"key", "rotate"},
		"sign no key":   {"sign", "--dir", t.TempDir(), "--sequence", "1"},
		"sign no seq":   {"sign", "--key", "k", "--dir", t.TempDir()},
	} {
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}
