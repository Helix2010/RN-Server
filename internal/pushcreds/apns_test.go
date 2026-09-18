package pushcreds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func p8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Apple 后台两种推送凭据并存（旧证书、新 .p8 令牌密钥），名字都叫"密钥"。
// 传错的那一份要在保存时就说清楚，而不是变成运行时一句签名失败。
func TestParseAPNsAuthKeyRejectsCertificate(t *testing.T) {
	key := ecKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := ParseAPNsAuthKey(certPEM); !errors.Is(err, ErrLooksLikeCertificate) {
		t.Fatalf("证书应当被识别出来，得到 %v", err)
	}
	// .p12 是二进制的，PEM 解不出来——同样归到"这是证书"那条提示
	if err := ParseAPNsAuthKey([]byte{0x30, 0x82, 0x04, 0x01}); !errors.Is(err, ErrLooksLikeCertificate) {
		t.Fatalf("二进制 .p12 应当被识别出来，得到 %v", err)
	}
}

// APNs 的令牌密钥一定是 ECDSA。放一把 RSA 过去，签出来的 JWT Apple 不认，
// 而错误发生在第一条推送时。
func TestParseAPNsAuthKeyRejectsRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseAPNsAuthKey(p8(t, key)); err == nil {
		t.Fatal("RSA 私钥应当被拒")
	}
}

func TestParseAPNsAuthKeyAcceptsECDSA(t *testing.T) {
	if err := ParseAPNsAuthKey(p8(t, ecKey(t))); err != nil {
		t.Fatalf("合法的 .p8 被拒了：%v", err)
	}
	if err := ParseAPNsAuthKey([]byte("   ")); err == nil {
		t.Fatal("空文件应当被拒")
	}
}

// 空值收敛到 production（设计 §2.4）：TestFlight 装的包走 production，
// 默认选错会让所有 TestFlight 用户收不到推送。
func TestNormalizeAPNsEnvironmentDefaultsToProduction(t *testing.T) {
	for _, input := range []string{"", "production"} {
		got, err := NormalizeAPNsEnvironment(input)
		if err != nil || got != APNsEnvironmentProduction {
			t.Fatalf("%q → %q, %v", input, got, err)
		}
	}
	if got, err := NormalizeAPNsEnvironment("sandbox"); err != nil || got != APNsEnvironmentSandbox {
		t.Fatalf("sandbox → %q, %v", got, err)
	}
	if _, err := NormalizeAPNsEnvironment("prod"); err == nil {
		t.Fatal("拼错的环境名应当被拒，而不是悄悄当成 production")
	}
}

// 密文不能出现在日志里。这一条和 FCM 那边的同名约束对齐（ADR-0017：真正的
// 约束是"不写入日志或客户端包"）。
func TestAPNsValueNeverPrintsSecret(t *testing.T) {
	value := APNs{TeamID: "ABCDE12345", KeyID: "XYZ9876543", Environment: "production",
		AuthKeyEncrypted: "c3VwZXItc2VjcmV0LWNpcGhlcnRleHQ"}
	for _, rendered := range []string{value.String(), value.GoString(), value.LogValue().String()} {
		if strings.Contains(rendered, "c3VwZXItc2VjcmV0") {
			t.Fatalf("密文漏进了 %q", rendered)
		}
		if !strings.Contains(rendered, "ABCDE12345") {
			t.Fatalf("Team ID 不是机密，应当留着方便排查：%q", rendered)
		}
	}
}
