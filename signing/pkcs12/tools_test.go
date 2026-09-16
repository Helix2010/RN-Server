package pkcs12

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// 这一组测试让真正的读者来读：Java 的 KeyStore（apksigner 用它打开 keystore）与 OpenSSL。
// 自己解自己写的格式只能证明前后一致。口令一律经文件传给工具，不进参数。

func findKeytool() string {
	if home := os.Getenv("JAVA_HOME"); home != "" {
		if path := filepath.Join(home, "bin", "keytool"); isExecutable(path) {
			return path
		}
	}
	matches, _ := filepath.Glob("/usr/lib/jvm/*/bin/keytool")
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, m := range matches {
		if isExecutable(m) {
			return m
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func writeSecretFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTool(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func colonUpper(hex string) string {
	var parts []string
	for i := 0; i+2 <= len(hex); i += 2 {
		parts = append(parts, strings.ToUpper(hex[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func TestKeytoolReadsOurKeystore(t *testing.T) {
	keytool := findKeytool()
	if keytool == "" {
		t.Skip("no keytool on this machine")
	}
	p := testPairs(t)[0]
	password := randomPassword(t)
	data, err := Encode(p.key, p.cert, "anyfun-release", password)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := writeSecretFile(t, dir, "release.p12", string(data))
	pass := writeSecretFile(t, dir, "store.password", password+"\n")
	out, err := runTool(t, keytool, "-list", "-v", "-storetype", "PKCS12", "-keystore", store, "-storepass:file", pass)
	if err != nil {
		t.Fatalf("keytool refused our keystore: %v\n%s", err, out)
	}
	for _, want := range []string{"Alias name: anyfun-release", "Entry type: PrivateKeyEntry", colonUpper(fingerprint.SHA256Hex(p.cert.Raw))} {
		if !strings.Contains(out, want) {
			t.Fatalf("keytool output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, password) {
		t.Fatal("keytool output contains the password")
	}
}

func TestDecodeKeytoolGeneratedKeystore(t *testing.T) {
	keytool := findKeytool()
	if keytool == "" {
		t.Skip("no keytool on this machine")
	}
	dir := t.TempDir()
	password := randomPassword(t)
	pass := writeSecretFile(t, dir, "store.password", password+"\n")
	store := filepath.Join(dir, "keytool.p12")
	out, err := runTool(t, keytool, "-genkeypair", "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
		"-storetype", "PKCS12", "-keystore", store, "-storepass:file", pass, "-keypass:file", pass,
		"-dname", "CN=keytool test", "-alias", "k")
	if err != nil {
		t.Fatalf("keytool -genkeypair: %v\n%s", err, out)
	}
	exported, err := runTool(t, keytool, "-exportcert", "-rfc", "-alias", "k", "-storetype", "PKCS12", "-keystore", store, "-storepass:file", pass)
	if err != nil {
		t.Fatalf("keytool -exportcert: %v\n%s", err, exported)
	}
	block, _ := pem.Decode([]byte(exported[strings.Index(exported, "-----BEGIN"):]))
	if block == nil {
		t.Fatalf("no PEM in keytool output:\n%s", exported)
	}
	data, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := FindKey(data, password, "k")
	if err != nil {
		t.Fatalf("FindKey on a keytool keystore: %v", err)
	}
	if CertificateSHA256(entry) != fingerprint.SHA256Hex(block.Bytes) {
		t.Fatal("certificate fingerprint differs from keytool -exportcert")
	}
	if _, err := Decode(data, password+"x"); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password on a keytool keystore: %v", err)
	}
}

func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on this machine")
	}
	p := testPairs(t)[1]
	dir := t.TempDir()
	password := randomPassword(t)
	pass := writeSecretFile(t, dir, "p12.password", password+"\n")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := writeSecretFile(t, dir, "key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})))
	certPEM := writeSecretFile(t, dir, "cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw})))

	t.Run("openssl reads ours", func(t *testing.T) {
		data, err := Encode(p.key, p.cert, "ours", password)
		if err != nil {
			t.Fatal(err)
		}
		ours := writeSecretFile(t, dir, "ours.p12", string(data))
		out, err := runTool(t, openssl, "pkcs12", "-info", "-nokeys", "-in", ours, "-passin", "file:"+pass)
		if err != nil {
			t.Fatalf("openssl refused our keystore: %v\n%s", err, out)
		}
		if !strings.Contains(out, "friendlyName: ours") {
			t.Fatalf("openssl did not report the alias:\n%s", out)
		}
	})

	t.Run("we read openssl default export", func(t *testing.T) {
		exported := filepath.Join(dir, "openssl.p12")
		out, err := runTool(t, openssl, "pkcs12", "-export", "-inkey", keyPEM, "-in", certPEM, "-name", "k",
			"-passout", "file:"+pass, "-out", exported)
		if err != nil {
			t.Fatalf("openssl pkcs12 -export: %v\n%s", err, out)
		}
		data, err := os.ReadFile(exported)
		if err != nil {
			t.Fatal(err)
		}
		entry, err := FindKey(data, password, "k")
		if err != nil {
			t.Fatalf("FindKey on an OpenSSL export: %v", err)
		}
		if !p.key.Equal(entry.PrivateKey) || CertificateSHA256(entry) != fingerprint.SHA256Hex(p.cert.Raw) {
			t.Fatal("OpenSSL export decoded to a different key or certificate")
		}
	})

	t.Run("legacy export is rejected", func(t *testing.T) {
		exported := filepath.Join(dir, "legacy.p12")
		out, err := runTool(t, openssl, "pkcs12", "-export", "-legacy", "-inkey", keyPEM, "-in", certPEM, "-name", "k",
			"-passout", "file:"+pass, "-out", exported)
		if err != nil {
			t.Skipf("this openssl cannot write legacy PKCS#12 (legacy provider missing?): %v\n%s", err, out)
		}
		data, err := os.ReadFile(exported)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(data, password); !errors.Is(err, ErrLegacyEncryption) {
			t.Fatalf("legacy export: %v", err)
		}
	})
}
