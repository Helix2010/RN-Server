package androidkeystore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func generateForTest(t *testing.T) Result {
	t.Helper()
	result, err := Generate(Params{
		CommonName:    "AnyFun Wallet",
		Organization:  "AnyFun",
		Country:       "sg",
		KeyAlias:      "anyfun-release",
		KeySize:       2048,
		ValidityYears: 30,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return result
}

func TestGenerateProducesAReadableKeystore(t *testing.T) {
	result := generateForTest(t)
	if len(result.PKCS12) == 0 {
		t.Fatal("no keystore bytes")
	}
	if len(result.SignerSHA256) != 64 || len(result.KeystoreSHA256) != 64 {
		t.Fatalf("digests look wrong: signer=%q keystore=%q", result.SignerSHA256, result.KeystoreSHA256)
	}
	if result.StorePassword == "" {
		t.Fatal("no store password")
	}
	digest, err := CertificateSHA256(result.PKCS12, result.StorePassword)
	if err != nil {
		t.Fatalf("CertificateSHA256: %v", err)
	}
	if digest != result.SignerSHA256 {
		t.Fatalf("fingerprint read back as %s, generated %s", digest, result.SignerSHA256)
	}
	if _, err := CertificateSHA256(result.PKCS12, "not-the-password"); err == nil {
		t.Fatal("a wrong password opened the keystore")
	}
	if got := result.Certificate.Subject.CommonName; got != "AnyFun Wallet" {
		t.Fatalf("common name %q", got)
	}
	if got := result.Certificate.Subject.Country; len(got) != 1 || got[0] != "SG" {
		t.Fatalf("country %v, want [SG]", got)
	}
}

func TestGenerateRejectsUnusableParameters(t *testing.T) {
	base := Params{CommonName: "A", Organization: "B", KeyAlias: "a", KeySize: 2048, ValidityYears: 30}
	for name, mutate := range map[string]func(*Params){
		"no common name":   func(p *Params) { p.CommonName = " " },
		"alias with space": func(p *Params) { p.KeyAlias = "my alias" },
		"empty alias":      func(p *Params) { p.KeyAlias = "" },
		"odd key size":     func(p *Params) { p.KeySize = 3072 },
		"short validity":   func(p *Params) { p.ValidityYears = 2 },
		"absurd validity":  func(p *Params) { p.ValidityYears = 500 },
		"long country":     func(p *Params) { p.Country = "SGP" },
	} {
		t.Run(name, func(t *testing.T) {
			params := base
			mutate(&params)
			if _, err := Generate(params); err == nil {
				t.Fatal("expected the parameters to be rejected")
			}
		})
	}
}

// keytool 是这套东西真正的读者：Gradle 用 Java 的 KeyStore 打开这个文件。
// 自己解自己写的格式只能证明前后一致，证明不了 Java 读得懂。
func TestKeytoolReadsTheKeystore(t *testing.T) {
	keytool := findKeytool()
	if keytool == "" {
		t.Skip("no keytool on this machine; the format check needs a JDK")
	}
	result := generateForTest(t)
	path := filepath.Join(t.TempDir(), "release.p12")
	if err := os.WriteFile(path, result.PKCS12, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(keytool, "-list", "-v", "-keystore", path, "-storepass", result.StorePassword).CombinedOutput()
	if err != nil {
		t.Fatalf("keytool refused the keystore: %v\n%s", err, output)
	}
	text := string(output)
	// 别名是这个测试真正盯着的东西：Gradle 拿 keyAlias 去找条目，找不到就在
	// 构建的最后一步失败。没有 friendlyName 属性时 Java 会把别名编成 "1"。
	if !strings.Contains(text, "Alias name: anyfun-release") {
		t.Fatalf("keytool did not report the alias we asked for:\n%s", text)
	}
	if !strings.Contains(text, "PrivateKeyEntry") {
		t.Fatalf("the entry is not a private key entry:\n%s", text)
	}
	// keytool 打的是带冒号的大写十六进制，apksigner 打的是小写不带冒号，
	// 两者是同一个值——发布身份 pin 的就是它
	fingerprint := strings.ToUpper(colonize(result.SignerSHA256))
	if !strings.Contains(text, fingerprint) {
		t.Fatalf("keytool reports a different SHA-256 than we computed (%s):\n%s", fingerprint, text)
	}
}

func colonize(hex string) string {
	var parts []string
	for i := 0; i+2 <= len(hex); i += 2 {
		parts = append(parts, hex[i:i+2])
	}
	return strings.Join(parts, ":")
}

func findKeytool() string {
	if path, err := exec.LookPath("keytool"); err == nil {
		return path
	}
	matches, _ := filepath.Glob("/usr/lib/jvm/*/bin/keytool")
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}
