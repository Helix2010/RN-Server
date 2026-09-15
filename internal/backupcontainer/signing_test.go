package backupcontainer

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func signingPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv := signingPair(t)
	payload := []byte("an inner package, sealed")
	sig := SignPayload(priv, payload)
	if err := VerifyPayload(pub, payload, sig); err != nil {
		t.Fatalf("a signature we just produced must verify: %v", err)
	}
}

func TestVerifyRejectsForgeryAndTampering(t *testing.T) {
	pub, priv := signingPair(t)
	other, _ := signingPair(t)
	payload := []byte("an inner package, sealed")
	sig := SignPayload(priv, payload)

	if err := VerifyPayload(other, payload, sig); err == nil {
		t.Fatal("a signature from another machine was accepted")
	}
	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0x01
	if err := VerifyPayload(pub, tampered, sig); err == nil {
		t.Fatal("a modified payload was accepted")
	}
	if err := VerifyPayload(pub, payload, sig[:10]); err == nil {
		t.Fatal("a truncated signature was accepted")
	}
}

func TestSigningPublicKeyRoundTrip(t *testing.T) {
	pub, _ := signingPair(t)
	encoded, err := EncodeSigningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSigningPublicKey(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !pub.Equal(back) {
		t.Fatal("round-trip produced a different key")
	}
	if _, err := ParseSigningPublicKey("not base64!"); err == nil {
		t.Fatal("garbage was accepted")
	}
}

// 灾难当天验签走的是 openssl，不是这个包。这条测试跑的就是 README-FIRST.txt
// 里给持有人的那两条命令：先把 base64 的 DER 转成 PEM，再 pkeyutl -verify。
//
// 存 DER SPKI 而不是 32 字节裸公钥，理由就在这里——裸公钥要人手拼 SPKI 头，
// 那是灾难当天最不该出现的一步
func TestOpenSSLCanVerifyOurSignature(t *testing.T) {
	openssl := lookOpenSSL(t)
	pub, priv := signingPair(t)
	dir := t.TempDir()

	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(dir, "inner.rnbk")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "inner.rnbk.sig")
	if err := os.WriteFile(sigPath, SignPayload(priv, payload), 0o600); err != nil {
		t.Fatal(err)
	}

	encoded, err := EncodeSigningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	derPath := filepath.Join(dir, "signing.der")
	if err := os.WriteFile(derPath, decodeBase64(t, encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "signing.pem")
	run(t, openssl, dir, "pkey", "-pubin", "-inform", "DER", "-in", derPath, "-out", pubPath)

	out := run(t, openssl, dir, "pkeyutl", "-verify", "-pubin", "-inkey", pubPath,
		"-rawin", "-in", payloadPath, "-sigfile", sigPath)
	if !strings.Contains(string(out), "Success") {
		t.Fatalf("openssl did not report a successful verification: %s", out)
	}

	// 改一位就必须验不过——否则「验签通过之前不要跑 recover.sh」这条约束是空的
	tampered := append([]byte{}, payload...)
	tampered[100] ^= 0x01
	badPath := filepath.Join(dir, "tampered.rnbk")
	if err := os.WriteFile(badPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAllowFail(openssl, dir, "pkeyutl", "-verify", "-pubin", "-inkey", pubPath,
		"-rawin", "-in", badPath, "-sigfile", sigPath); err == nil {
		t.Fatal("openssl accepted a signature over different bytes")
	}
}

// SigningFingerprint 和恢复公钥用同一个定义，三个持有人抄的就是这一行
func TestSigningFingerprintIsTheSame64CharForm(t *testing.T) {
	pub, _ := signingPair(t)
	fp, err := SigningFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint is %d chars, the spec says 64", len(fp))
	}
	direct, err := Fingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if fp != direct {
		t.Fatal("SigningFingerprint must be the same definition as Fingerprint")
	}
}
