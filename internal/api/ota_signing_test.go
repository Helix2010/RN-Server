package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

func testSigningKey(t *testing.T, bits int) (*rsa.PrivateKey, string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rn-app ota signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return key, keyPEM, certPEM
}

var signatureField = regexp.MustCompile(`sig="([^"]*)"`)

// 这条用例是整件事的地基：服务端签出来的东西，客户端那套算法必须验得过。
// expo-updates 用 Signature.getInstance("SHA256withRSA")，即 PKCS#1 v1.5 + SHA-256
// （CodeSigningConfiguration.kt:93-96）。这里用同一套算法在 Go 侧复验。
func TestSignedOTABodyVerifiesWithWhatTheClientRuns(t *testing.T) {
	key, _, _ := testSigningKey(t, 2048)
	body := []byte(`{"id":"e2e","runtimeVersion":"1.3.7"}`)

	header, err := signOTABody(key, "main", body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(header, `alg="rsa-v1_5-sha256"`) || !strings.Contains(header, `keyid="main"`) {
		t.Fatalf("header is not the structured dictionary the client parses: %s", header)
	}
	match := signatureField.FindStringSubmatch(header)
	if match == nil {
		t.Fatalf("no sig field: %s", header)
	}
	signature, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		t.Fatalf("sig is not standard base64: %v", err)
	}
	digest := sha256.Sum256(body)
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("the client would reject this signature: %v", err)
	}

	// 改一个字节就必须验不过——否则签的等于没签
	tampered := append([]byte{}, body...)
	tampered[len(tampered)-2] ^= 0x01
	tamperedDigest := sha256.Sum256(tampered)
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, tamperedDigest[:], signature) == nil {
		t.Fatal("a tampered body still verified")
	}
}

func TestOTASignatureHeaderEscapesStringFields(t *testing.T) {
	// keyid 来自配置，配的人可能写进引号或反斜杠；没转义的话整个字典解析不了，
	// 客户端报的是"找不到 sig 字段"，跟 keyid 完全对不上号
	header := otaSignatureHeader([]byte{1, 2, 3}, `we"ird\id`)
	if !strings.Contains(header, `keyid="we\"ird\\id"`) {
		t.Fatalf("key id was not escaped: %s", header)
	}
}

func TestParseRSAPrivateKeyPEMAcceptsBothEncodingsAndRejectsWeakKeys(t *testing.T) {
	_, pkcs8PEM, _ := testSigningKey(t, 2048)
	if _, err := parseRSAPrivateKeyPEM(pkcs8PEM); err != nil {
		t.Fatalf("PKCS#8 should be accepted (expo's generator emits it): %v", err)
	}

	// openssl 的老参数给 PKCS#1，也会被人贴进来
	key, _, _ := testSigningKey(t, 2048)
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	if _, err := parseRSAPrivateKeyPEM(pkcs1PEM); err != nil {
		t.Fatalf("PKCS#1 should be accepted: %v", err)
	}

	_, weakPEM, _ := testSigningKey(t, 1024)
	if _, err := parseRSAPrivateKeyPEM(weakPEM); err == nil {
		t.Fatal("a 1024-bit key protects the whole JS layer; it must be refused")
	}
	for name, text := range map[string]string{
		"空":       "",
		"不是 PEM":  "hunter2",
		"是证书不是私钥": func() string { _, _, cert := testSigningKey(t, 2048); return cert }(),
	} {
		if _, err := parseRSAPrivateKeyPEM(text); err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}

// 证书和私钥不是一对时，服务端签得出来而客户端一定验不过，表现是所有设备静默
// 停在内置 bundle——最难查的那种故障。必须在写入时就拦住。
func TestCertificateMustMatchThePrivateKey(t *testing.T) {
	key, _, certPEM := testSigningKey(t, 2048)
	if err := certificateMatchesKey(certPEM, key); err != nil {
		t.Fatalf("a matching pair was rejected: %v", err)
	}
	other, _, _ := testSigningKey(t, 2048)
	if err := certificateMatchesKey(certPEM, other); err == nil {
		t.Fatal("a certificate from a different key was accepted")
	}
	if err := certificateMatchesKey("not pem", key); err == nil {
		t.Fatal("garbage was accepted as a certificate")
	}
}

func TestOTASigningViewNeverLeaksThePrivateKey(t *testing.T) {
	_, _, certPEM := testSigningKey(t, 2048)
	record := &otaSigningRecord{
		Value: otaSigningKey{
			KeyID:       "main",
			PrivateKey:  "c2VjcmV0LWtleS1tYXRlcmlhbA==",
			Certificate: certPEM,
		},
		Version:   3,
		UpdatedBy: "release-bot",
		UpdatedAt: time.Now().UTC(),
	}
	view := otaSigningView(record)
	if _, present := view["privateKey"]; present {
		t.Fatal("the view exposes the private key")
	}
	for _, value := range view {
		if text, ok := value.(string); ok && strings.Contains(text, "c2VjcmV0") {
			t.Fatalf("private key material leaked into the view: %v", view)
		}
	}
	if view["keyId"] != "main" || view["certificateSha256"] == nil {
		t.Fatalf("the view should carry the public facts: %v", view)
	}
	if otaSigningView(nil)["configured"] != false {
		t.Fatal("an unconfigured tenant must report configured=false")
	}
}

func TestUpdateOTASigningKeyRejectsInvalidBodiesBeforeTouchingTheDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// db 为 nil：任何走到数据库的路径都会 panic
	s := &server{cfg: config.Config{Environment: "production"}}
	_, keyPEM, certPEM := testSigningKey(t, 2048)
	body := func(overrides map[string]string) string {
		fields := map[string]string{
			"privateKeyPem":  keyPEM,
			"certificatePem": certPEM,
			"reason":         "install signing key",
		}
		for k, v := range overrides {
			fields[k] = v
		}
		return `{"privateKeyPem":` + quote(fields["privateKeyPem"]) +
			`,"certificatePem":` + quote(fields["certificatePem"]) +
			`,"expectedVersion":0,"reason":` + quote(fields["reason"]) + `,"confirm":true}`
	}
	for name, payload := range map[string]string{
		"not confirmed": strings.Replace(body(nil), `"confirm":true`, `"confirm":false`, 1),
		"short reason":  body(map[string]string{"reason": "x"}),
		"bad key":       body(map[string]string{"privateKeyPem": "hunter2"}),
		"mismatched certificate": func() string {
			_, _, other := testSigningKey(t, 2048)
			return body(map[string]string{"certificatePem": other})
		}(),
		"not json": `{`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("PUT", "/v1/admin/ota/signing-key", strings.NewReader(payload))
		c.Request.Header.Set("Content-Type", "application/json")
		s.updateOTASigningKey(c)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_OTA_SIGNING_KEY") {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func TestClientExpectsOTASignature(t *testing.T) {
	if !clientExpectsOTASignature(`sig, keyid="main", alg="rsa-v1_5-sha256"`) {
		t.Fatal("a client sending the header expects a signature")
	}
	for _, header := range []string{"", "   "} {
		if clientExpectsOTASignature(header) {
			t.Fatalf("%q should not count as expecting a signature", header)
		}
	}
}

// nil signer 必须是"不签名"而不是 panic：没配密钥的租户照常下发，要验签的客户端
// 自己拒绝并回落到内置 bundle。
func TestNilSignerProducesNoSignature(t *testing.T) {
	var signer *otaSigner
	signature, err := signer.sign([]byte("{}"))
	if err != nil || signature != "" {
		t.Fatalf("nil signer should be a silent no-op, got %q / %v", signature, err)
	}
}

// quote 把任意字符串（PEM 里有换行）编成合法的 JSON 字串字面量
func quote(v string) string {
	encoded, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}
