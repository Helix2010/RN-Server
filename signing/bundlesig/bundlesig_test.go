package bundlesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestSignedManifestVerifies(t *testing.T) {
	public, private := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1","commit":"` + testCommit + `","bundles":{}}`)
	signature, err := Sign(private, manifest, testCommit, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, manifest, signature); err != nil {
		t.Fatalf("a manifest this key signed did not verify: %v", err)
	}
	// 走一遍文件形状：升级程序读到的是 JSON，不是内存里的结构体
	encoded, err := json.Marshal(signature)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(public, manifest, parsed); err != nil {
		t.Fatalf("the signature did not survive a round trip: %v", err)
	}
	if parsed.Sequence != 7 || parsed.Commit != testCommit || parsed.PublicKeySHA256 != PublicKeySHA256(public) {
		t.Fatalf("parsed: %+v", parsed)
	}
}

// 改一个字节就不认：清单里是每个归档与每个文件的 sha256，签了它等于签了那些文件。
func TestVerifyRefusesATamperedManifest(t *testing.T) {
	public, private := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1","commit":"` + testCommit + `","bundles":{"builder":{"archiveSha256":"aa"}}}`)
	signature, err := Sign(private, manifest, testCommit, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(manifest), `"aa"`, `"bb"`, 1))
	if err := Verify(public, tampered, signature); err == nil {
		t.Fatal("a manifest that was changed after signing verified")
	}
}

// 另一把合法密钥签的清单要报成"不是这台机器信的那把"，而不是"签名不对"——
// 这两句话会把人引去完全不同的地方。
func TestVerifyNamesTheWrongReleaseKey(t *testing.T) {
	pinned, _ := testKey(t)
	_, other := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1","commit":"` + testCommit + `","bundles":{}}`)
	signature, err := Sign(other, manifest, testCommit, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(pinned, manifest, signature)
	if err == nil || !strings.Contains(err.Error(), "another release key") {
		t.Fatalf("%v", err)
	}
}

// 签名字段被换成另一把密钥对同一内容的签名：公钥指纹这一关先拦住它，
// 把指纹也改对之后，签名本身不过。
func TestVerifyRefusesASwappedSignature(t *testing.T) {
	public, private := testKey(t)
	_, other := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1","commit":"` + testCommit + `","bundles":{}}`)
	signature, err := Sign(private, manifest, testCommit, 3, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(other, manifest, testCommit, 3, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signature.Signature = forged.Signature
	if err := Verify(public, manifest, signature); err == nil {
		t.Fatal("a signature made by another key verified")
	}
}

// -dirty 的构建签不了：一个工作区不干净的构建不该被放到任何一台 Mac 上。
func TestSignRefusesADirtyCommitAndABadSequence(t *testing.T) {
	_, private := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1"}`)
	if _, err := Sign(private, manifest, testCommit+"-dirty", 1, time.Now()); err == nil {
		t.Fatal("a -dirty commit was signed")
	}
	if _, err := Sign(private, manifest, testCommit, 0, time.Now()); err == nil {
		t.Fatal("sequence 0 was signed")
	}
}

// 形状不对的签名文件在验签之前就拒：读它的是 Mac 上的升级程序，而那份文件来自服务端。
func TestParseRefusesMalformedSignatureFiles(t *testing.T) {
	public, private := testKey(t)
	manifest := []byte(`{"format":"rn-machine-bundles/v1"}`)
	good, err := Sign(private, manifest, testCommit, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(good)
	for name, raw := range map[string][]byte{
		"empty":         {},
		"not json":      []byte("nope"),
		"unknown field": []byte(`{"format":"` + Format + `","commit":"` + testCommit + `","sequence":1,"manifestSha256":"` + ManifestSHA256(manifest) + `","publicKeySha256":"` + PublicKeySHA256(public) + `","signature":"x","signedAt":"","extra":1}`),
		"other format":  []byte(strings.Replace(string(encoded), Format, "rn-machine-bundles-signature/v2", 1)),
		"short commit":  []byte(strings.Replace(string(encoded), testCommit, "abc", 1)),
		"zero sequence": []byte(strings.Replace(string(encoded), `"sequence":2`, `"sequence":0`, 1)),
		"huge":          []byte(strings.Repeat("x", MaxSize+1)),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestParsePublicKeyRefusesJunk(t *testing.T) {
	public, _ := testKey(t)
	if _, err := ParsePublicKey([]byte(SSHPublicKeyLine(public, "rn-release-key") + "\n")); err != nil {
		t.Fatalf("a valid public key was refused: %v", err)
	}
	if _, err := ParsePublicKey([]byte(SSHPublicKeyLine(public, "") + "\n")); err != nil {
		t.Fatalf("a public key without a comment was refused: %v", err)
	}
	for name, raw := range map[string]string{
		"not base64":        "ssh-ed25519 !!!!",
		"wrong size":        "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(sshString([]byte("ssh-ed25519")), sshString([]byte("short"))...)),
		"empty":             "",
		"another algorithm": "ssh-rsa " + base64.StdEncoding.EncodeToString(sshPublicKeyBlob(public)),
		"trailing bytes":    "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(sshPublicKeyBlob(public), 'x')),
		"bare base64 (旧格式)": base64.StdEncoding.EncodeToString(public),
	} {
		if _, err := ParsePublicKey([]byte(raw)); err == nil {
			t.Errorf("%s was accepted as a public key", name)
		}
	}
}
