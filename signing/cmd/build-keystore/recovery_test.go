package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/internal/signer"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
	"github.com/Helix2010/RN-Server/signing/recovery"
)

const testRecoveryPassphrase = "offline recovery passphrase 2026"

// scriptedPassphrase 依次返回预设的口令，记下提示。
type scriptedPassphrase struct {
	answers []string
	prompts []string
	closed  bool
}

func (s *scriptedPassphrase) ReadPassphrase(prompt string) ([]byte, error) {
	s.prompts = append(s.prompts, prompt)
	if len(s.answers) == 0 {
		return nil, errors.New("no more scripted input")
	}
	next := s.answers[0]
	s.answers = s.answers[1:]
	return []byte(next), nil
}

func (s *scriptedPassphrase) Close() error { s.closed = true; return nil }

func withPassphrases(t *testing.T, answers ...string) *scriptedPassphrase {
	t.Helper()
	src := &scriptedPassphrase{answers: answers}
	old := openPassphraseSource
	openPassphraseSource = func() (passphraseSource, error) { return src, nil }
	t.Cleanup(func() { openPassphraseSource = old })
	return src
}

func assertNoSecret(t *testing.T, output string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(output, s) {
			t.Fatalf("output contains a secret (%q…)", s[:min(len(s), 6)])
		}
	}
}

// 恢复密钥生成 → 用签名闸的生成流程加密（给签名闸与恢复公钥）→ 用恢复私钥解开 → 证书一致。
func TestRecoveryKeyRoundTripWithSignerGeneration(t *testing.T) {
	work := t.TempDir()
	keyDir := filepath.Join(work, "usb")
	src := withPassphrases(t, testRecoveryPassphrase, testRecoveryPassphrase)
	code, stdout, stderr := runTool("recovery-key", "create", "--out", keyDir, "--name", "platform-recovery")
	if code != 0 {
		t.Fatalf("recovery-key create exit %d: %s", code, stderr)
	}
	if len(src.prompts) != 2 || !src.closed {
		t.Fatalf("passphrase prompts %q closed %v", src.prompts, src.closed)
	}
	privPath, pubPath := filepath.Join(keyDir, recoveryPrivateFile), filepath.Join(keyDir, recoveryPublicFile)
	if mode(t, keyDir) != 0o700 || mode(t, privPath) != 0o600 || mode(t, pubPath) != 0o644 {
		t.Fatalf("modes: dir %o private %o public %o", mode(t, keyDir), mode(t, privPath), mode(t, pubPath))
	}
	pubRaw, _ := os.ReadFile(pubPath)
	pub, err := recovery.ParsePublic(pubRaw)
	if err != nil {
		t.Fatalf("public file: %v", err)
	}
	if !strings.Contains(stdout, pub.X25519PublicKeySHA256) || !strings.Contains(stdout, "platform-recovery") {
		t.Fatalf("stdout lacks the full fingerprint:\n%s", stdout)
	}
	assertNoSecret(t, stdout+stderr, testRecoveryPassphrase)
	privRaw, _ := os.ReadFile(privPath)
	if strings.Contains(string(privRaw), testRecoveryPassphrase) {
		t.Fatal("the private key file contains the passphrase")
	}

	// 签名闸生成：加密给一台签名闸与恢复公钥
	signerKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, generator, _ := ed25519.GenerateKey(rand.Reader)
	recoveryPub, _ := pub.PublicKey()
	generated, err := signer.GenerateKeystore(signer.GenerateParams{
		RequestID: "kgr_roundtrip01", TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", KeyAlias: "anyfun-release",
		Recipients: [][]byte{signerKey.PublicKey().Bytes(), recoveryPub}, Generator: generator, KeyBits: 2048, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := keystorebox.VerifyGeneration(generator.Public().(ed25519.PublicKey), "kgr_roundtrip01", generated.Upload, generated.Signature); err != nil {
		t.Fatalf("generation signature: %v", err)
	}
	exported, _ := json.MarshalIndent(generated.Upload, "", "  ")
	uploadPath := filepath.Join(work, "AnyFun-keystore-export.json")
	must(t, os.WriteFile(uploadPath, exported, 0o600))

	outDir := filepath.Join(work, "recovered")
	withPassphrases(t, testRecoveryPassphrase)
	code, stdout, stderr = runTool("recover", "--recovery-key", privPath, "--upload", uploadPath, "--out-dir", outDir)
	if code != 0 {
		t.Fatalf("recover exit %d: %s", code, stderr)
	}
	p12Path, passwordPath, certPath := filepath.Join(outDir, "anyfun-release.p12"), filepath.Join(outDir, "anyfun-release.password"), filepath.Join(outDir, "certificate.pem")
	for _, p := range []string{p12Path, passwordPath, certPath} {
		if mode(t, p) != 0o600 {
			t.Fatalf("%s mode %o", p, mode(t, p))
		}
	}
	if mode(t, outDir) != 0o700 {
		t.Fatalf("out dir mode %o", mode(t, outDir))
	}
	password := readPassword(t, passwordPath)
	p12, _ := os.ReadFile(p12Path)
	entry, err := pkcs12.FindKey(p12, password, "anyfun-release")
	if err != nil {
		t.Fatalf("recovered p12: %v", err)
	}
	if got := pkcs12.CertificateSHA256(entry); got != generated.CertificateSHA256 || got != generated.Upload.CertificateSHA256 {
		t.Fatalf("recovered certificate %s, generated %s", got, generated.CertificateSHA256)
	}
	if !strings.Contains(stdout, generated.CertificateSHA256) || !strings.Contains(stdout, "build-keystore seal") {
		t.Fatalf("recover stdout:\n%s", stdout)
	}
	assertNoSecret(t, stdout+stderr, password, testRecoveryPassphrase)

	// 恢复出来的原件能直接 seal 给新的签名闸
	c := newSigner(t, "new-signer-a", "primary")
	pinPath := writePins(t, work, c.pin)
	sealed := filepath.Join(work, "resealed.json")
	if code, _, stderr := runTool("seal", "--pins", pinPath, "--p12", p12Path, "--password-file", passwordPath,
		"--tenant", "AnyFun", "--package", "com.anyfun.foundation", "--out", sealed); code != 0 {
		t.Fatalf("seal the recovered keystore: %s", stderr)
	}

	t.Run("wrong passphrase", func(t *testing.T) {
		out := filepath.Join(work, "wrong")
		withPassphrases(t, "not the recovery passphrase")
		code, _, stderr := runTool("recover", "--recovery-key", privPath, "--upload", uploadPath, "--out-dir", out)
		if code != 1 || !strings.Contains(stderr, "口令不对") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("created the out dir after a wrong passphrase")
		}
	})

	t.Run("existing out dir", func(t *testing.T) {
		src := withPassphrases(t, testRecoveryPassphrase)
		code, _, stderr := runTool("recover", "--recovery-key", privPath, "--upload", uploadPath, "--out-dir", outDir)
		if code != 1 || !strings.Contains(stderr, "已经存在") || len(src.prompts) != 0 {
			t.Fatalf("exit %d prompts %d: %s", code, len(src.prompts), stderr)
		}
	})

	t.Run("upload not addressed to the recovery key", func(t *testing.T) {
		onlySigner, err := signer.GenerateKeystore(signer.GenerateParams{
			RequestID: "kgr_roundtrip02", TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", KeyAlias: "anyfun-release",
			Recipients: [][]byte{signerKey.PublicKey().Bytes()}, Generator: generator, KeyBits: 2048, Now: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(onlySigner.Upload)
		path := filepath.Join(work, "signer-only.json")
		must(t, os.WriteFile(path, raw, 0o600))
		src := withPassphrases(t, testRecoveryPassphrase)
		code, _, stderr := runTool("recover", "--recovery-key", privPath, "--upload", path, "--out-dir", filepath.Join(work, "x"))
		if code != 1 || !strings.Contains(stderr, "没有加密给恢复密钥") || !strings.Contains(stderr, pub.X25519PublicKeySHA256) || len(src.prompts) != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})

	t.Run("outer fields tampered", func(t *testing.T) {
		tampered := generated.Upload
		tampered.CertificateSHA256 = strings.Repeat("ab", 32)
		raw, _ := json.Marshal(tampered)
		path := filepath.Join(work, "tampered.json")
		must(t, os.WriteFile(path, raw, 0o600))
		withPassphrases(t, testRecoveryPassphrase)
		out := filepath.Join(work, "tampered-out")
		code, _, stderr := runTool("recover", "--recovery-key", privPath, "--upload", path, "--out-dir", out)
		if code != 1 || !strings.Contains(stderr, "不一致") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("exported a keystore whose outer fields were tampered with")
		}
	})

	t.Run("create refuses to overwrite", func(t *testing.T) {
		src := withPassphrases(t, testRecoveryPassphrase, testRecoveryPassphrase)
		code, _, stderr := runTool("recovery-key", "create", "--out", keyDir, "--name", "platform-recovery")
		if code != 1 || !strings.Contains(stderr, "已经存在") || len(src.prompts) != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		again, _ := os.ReadFile(privPath)
		if string(again) != string(privRaw) {
			t.Fatal("the private key file changed")
		}
	})
}

func TestRecoveryKeyCreateRejectsBadPassphrases(t *testing.T) {
	work := t.TempDir()
	for name, answers := range map[string][]string{
		"mismatch":  {testRecoveryPassphrase, testRecoveryPassphrase + "x"},
		"too short": {"short", "short"},
		"control":   {"passphrase\twith tab", "passphrase\twith tab"},
		"eof":       {testRecoveryPassphrase},
	} {
		out := filepath.Join(work, strings.ReplaceAll(name, " ", "-"))
		withPassphrases(t, answers...)
		code, stdout, stderr := runTool("recovery-key", "create", "--out", out, "--name", "platform-recovery")
		if code != 1 {
			t.Errorf("%s: exit %d: %s", name, code, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: left the new out dir behind", name)
		}
		assertNoSecret(t, stdout+stderr, testRecoveryPassphrase, "passphrase\twith tab")
	}
	// 已存在的目录（例如 U 盘挂载点）只写两个新文件，失败时不删目录
	existing := filepath.Join(work, "existing")
	must(t, os.Mkdir(existing, 0o755))
	withPassphrases(t, testRecoveryPassphrase, "different passphrase!!")
	if code, _, _ := runTool("recovery-key", "create", "--out", existing, "--name", "platform-recovery"); code != 1 {
		t.Fatal("mismatch accepted")
	}
	if _, err := os.Stat(existing); err != nil {
		t.Fatal("removed a directory it did not create")
	}
	withPassphrases(t, testRecoveryPassphrase, testRecoveryPassphrase)
	if code, _, stderr := runTool("recovery-key", "create", "--out", existing, "--name", "Bad_Name"); code != 1 || !strings.Contains(stderr, "--name") {
		t.Fatalf("bad name: %d %s", code, stderr)
	}
}

func TestPassphraseNeedsATerminal(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeR.Close()
	defer pipeW.Close()
	work := t.TempDir()
	for _, stdin := range []*os.File{devnull, pipeR} {
		if _, err := openTTYPassphrase(stdin); !errors.Is(err, errNotTTY) {
			t.Fatalf("openTTYPassphrase(%s) = %v", stdin.Name(), err)
		}
		old := openPassphraseSource
		openPassphraseSource = func() (passphraseSource, error) { return openTTYPassphrase(stdin) }
		out := filepath.Join(work, "key")
		code, _, stderr := runTool("recovery-key", "create", "--out", out, "--name", "platform-recovery")
		openPassphraseSource = old
		if code != 1 || !strings.Contains(stderr, "交互终端") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("created files without a terminal")
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
