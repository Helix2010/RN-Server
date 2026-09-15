package backupcontainer

import (
	"archive/tar"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func newSHA256() hash.Hash { return sha256.New() }

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// lookOpenSSL 找 openssl。找不到就跳过而不是失败：这些测试断言的是
// 「我们产出的包，别人的工具能打开」，没有那个工具时无从断言
func lookOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed; skipping the cross-implementation checks")
	}
	return path
}

func run(t *testing.T, bin, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", filepath.Base(bin), args, err, stderr.String())
	}
	return out
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	body := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustMarshalPKIX(t *testing.T, pub *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// concat 做的就是恢复端那条 `cat meta.json key.bin payload.enc` ——
// MAC 的覆盖顺序是规范的一部分，这里必须和规范一字不差
func concat(t *testing.T, dst string, parts ...string) {
	t.Helper()
	var buf bytes.Buffer
	for _, p := range parts {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(body)
	}
	if err := os.WriteFile(dst, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rebuild 按容器规定的顺序把四个成员重新打成 tar，给篡改测试用
func rebuild(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, name := range []string{metaName, keyName, payloadName, macName} {
		body, ok := members[name]
		if !ok {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)),
			Typeflag: tar.TypeReg, Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decodeBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// runAllowFail 跑一条预期会失败的命令，把退出码作为结果返回而不是让测试挂掉
func runAllowFail(bin, dir string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	return cmd.Run()
}
