package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// 出处私钥：状态目录 0700、文件 0600，第二次读到同一把
func TestProvenanceKeyIsCreatedOnceAndKeptPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	ring, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o700, filepath.Join(dir, provenanceKeyFile): 0o600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s has mode %o, want %o", path, info.Mode().Perm(), want)
		}
	}
	again, err := loadOrCreateKeyring(dir)
	if err != nil || again.current.sha256 != ring.current.sha256 {
		t.Fatalf("a second load produced another key: %v", err)
	}
	if ring.current.sha256 != fingerprint.SHA256Hex(ring.current.public) || len(ring.current.sha256) != 64 {
		t.Fatal("the fingerprint is not the full sha256 of the public key")
	}
}

// 权限不对就拒绝启动，而不是把密钥留在别人能读的地方
func TestProvenanceKeyRefusesLoosePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if _, err := loadOrCreateKeyring(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKeyring(dir); err == nil {
		t.Fatal("a group-readable state directory was accepted")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, provenanceKeyFile), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKeyring(dir); err == nil {
		t.Fatal("a group-readable key file was accepted")
	}
	if _, err := readKeyringReadOnly(dir); err == nil {
		t.Fatal("show-key read a group-readable key file")
	}
	// 私钥文件换成符号链接（哪怕指向一个权限正确的文件）也拒绝
	key := filepath.Join(dir, provenanceKeyFile)
	real := filepath.Join(t.TempDir(), "elsewhere.key")
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(key, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, key); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKeyring(dir); err == nil {
		t.Fatal("a symlinked key file was accepted")
	}
}

// show-key 只读：空目录下不造密钥，打印的是完整 sha256 与公钥 base64
func TestShowKeyNeverCreatesAKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := showKey([]string{"--state-dir", dir}, &stdout, &stderr); code != 2 {
		t.Fatalf("show-key on an empty state dir exited %d", code)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("show-key created %v", entries)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if code := showKey([]string{"--state-dir", missing}, &stdout, &stderr); code != 2 {
		t.Fatal("show-key on a missing state dir succeeded")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("show-key created the state dir")
	}

	ring, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := showKey([]string{"--state-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("show-key exited %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, ring.current.sha256) || !strings.Contains(out, ring.current.publicBase64()) {
		t.Fatalf("show-key output lacks the full sha256 or the public key:\n%s", out)
	}
	seed, _ := os.ReadFile(filepath.Join(dir, provenanceKeyFile))
	if strings.Contains(out, strings.TrimSpace(string(seed))) {
		t.Fatal("show-key printed the private key")
	}
	pub, _ := base64.StdEncoding.DecodeString(ring.current.publicBase64())
	if len(pub) != ed25519.PublicKeySize {
		t.Fatal("the printed public key is not an ed25519 key")
	}
}

func TestRotateKeyCreatesTheNextKeyOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	if code := rotateKey([]string{"--state-dir", dir}, &stdout, &stderr); code != 2 {
		t.Fatal("rotate-key without a current key succeeded")
	}
	ring, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code := rotateKey([]string{"--state-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("rotate-key exited %d: %s", code, stderr.String())
	}
	first, _ := readKeyringReadOnly(dir)
	if first.next == nil || first.next.sha256 == ring.current.sha256 || !strings.Contains(stdout.String(), first.next.sha256) {
		t.Fatalf("no distinct rotation key:\n%s", stdout.String())
	}
	if code := rotateKey([]string{"--state-dir", dir}, &stdout, &stderr); code != 0 {
		t.Fatal("a second rotate-key failed")
	}
	second, _ := readKeyringReadOnly(dir)
	if second.next.sha256 != first.next.sha256 {
		t.Fatal("a second rotate-key replaced the pending rotation key")
	}
	info, err := os.Stat(filepath.Join(dir, provenanceNextKeyFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotation key file mode: %v %v", info, err)
	}
}
