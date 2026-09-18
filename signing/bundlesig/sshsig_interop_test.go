package bundlesig

// 这些用例把 signSSHSig/verifySSHSig 与**系统上真正的 ssh-keygen** 对拍。
//
// 为什么非要对拍：Mac 装机脚本不跑这里的 Go 代码，它跑的是 macOS 自带的
// `ssh-keygen -Y verify`。如果我们写出来的装甲块只有自己认得，那台 Mac 上就装不上——而
// 且会在"运维已经把机器搬到位"的时候才发现。这两个方向都要通：我们签的 ssh-keygen 认，
// ssh-keygen 签的我们认。

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sshKeygen 找 ssh-keygen；没有就跳过（不把测试变成对环境的要求）。
func sshKeygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("no ssh-keygen on this machine")
	}
	return path
}

// runVerify 按装机脚本里那条命令调用 ssh-keygen -Y verify。
func runVerify(t *testing.T, keygen, dir, namespace string, message []byte) error {
	t.Helper()
	cmd := exec.Command(keygen, "-Y", "verify",
		"-f", filepath.Join(dir, "allowed_signers"),
		"-I", SignerIdentity, "-n", namespace,
		"-s", filepath.Join(dir, "manifest.sig"))
	cmd.Stdin = strings.NewReader(string(message))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("ssh-keygen: %s", strings.TrimSpace(string(out)))
	}
	return err
}

func writeSigned(t *testing.T, dir string, public ed25519.PublicKey, armored string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "allowed_signers"), []byte(AllowedSignersLine(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(armored), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHKeygenAcceptsWhatWeSign(t *testing.T) {
	keygen := sshKeygen(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("rn-machine-bundles-signature/v1\ncommit=" + strings.Repeat("a", 40) + "\nsequence=7\nmanifestSha256=" + strings.Repeat("b", 64) + "\n")
	dir := t.TempDir()
	writeSigned(t, dir, public, signSSHSig(private, Namespace, message))

	if err := runVerify(t, keygen, dir, Namespace, message); err != nil {
		t.Fatalf("ssh-keygen rejected a signature we produced: %v", err)
	}
}

func TestSSHKeygenRejectsATamperedMessage(t *testing.T) {
	keygen := sshKeygen(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("sequence=7\n")
	dir := t.TempDir()
	writeSigned(t, dir, public, signSSHSig(private, Namespace, message))

	if err := runVerify(t, keygen, dir, Namespace, []byte("sequence=6\n")); err == nil {
		t.Fatal("ssh-keygen accepted a message that was not the one signed")
	}
}

// namespace 是这个格式里"这把签名是干什么用的"那一栏。它不对的时候必须验不过，否则同一把
// 发布密钥在别处签的任何东西都能被当成清单签名拿来用。
func TestSSHKeygenRejectsAnotherNamespace(t *testing.T) {
	keygen := sshKeygen(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("sequence=7\n")
	dir := t.TempDir()
	writeSigned(t, dir, public, signSSHSig(private, "some-other-purpose", message))

	if err := runVerify(t, keygen, dir, Namespace, message); err == nil {
		t.Fatal("ssh-keygen accepted a signature made for another namespace")
	}
}

// 反方向：ssh-keygen 签的，Mac 上的自升级程序（Go）也要认——两侧读的是同一份 manifest.sig。
func TestWeAcceptWhatSSHKeygenSigns(t *testing.T) {
	keygen := sshKeygen(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "release-key", "-f", keyPath).CombinedOutput(); err != nil {
		t.Fatalf("cannot generate an ssh key: %v %s", err, out)
	}
	messagePath := filepath.Join(dir, "message")
	message := []byte("rn-machine-bundles-signature/v1\nsequence=9\n")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-Y", "sign", "-f", keyPath, "-n", Namespace, messagePath).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen could not sign: %v %s", err, out)
	}
	armoured, err := os.ReadFile(messagePath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	public, err := ParsePublicKey(pubRaw)
	if err != nil {
		t.Fatalf("cannot read an ssh-keygen public key: %v", err)
	}
	if err := verifySSHSig(public, Namespace, message, string(armoured)); err != nil {
		t.Fatalf("we rejected a signature ssh-keygen produced: %v", err)
	}
	if err := verifySSHSig(public, Namespace, []byte("sequence=8\n"), string(armoured)); err == nil {
		t.Fatal("we accepted a message that was not the one ssh-keygen signed")
	}
	if err := verifySSHSig(public, "some-other-purpose", message, string(armoured)); err == nil {
		t.Fatal("we accepted a signature made for another namespace")
	}
}

// 装甲块里带着签名者的公钥。只按它验签等于让签名自己决定"谁签的"——必须和 pin 的那把比。
func TestWeRejectASignatureFromAnotherKeyEvenThoughItIsSelfConsistent(t *testing.T) {
	pinned, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("sequence=7\n")
	err = verifySSHSig(pinned, Namespace, message, signSSHSig(attacker, Namespace, message))
	if err == nil {
		t.Fatal("a self-consistent signature from another key was accepted")
	}
	if !strings.Contains(err.Error(), "another release key") {
		t.Fatalf("unhelpful error for a foreign key: %v", err)
	}
}
