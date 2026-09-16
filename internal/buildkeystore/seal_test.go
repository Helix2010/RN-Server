package buildkeystore

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sample() Bundle {
	return Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString([]byte("not a real keystore")),
		StorePassword:  "store-secret",
		KeyAlias:       "anyfun",
		KeyPassword:    "key-secret",
	}
}

func TestSealedKeystoreRoundTrips(t *testing.T) {
	sealed, err := Seal(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if opened != sample() {
		t.Fatalf("round trip changed the bundle: %+v", opened)
	}
}

// 这是整个方案成立的前提：服务端存的、日志里可能出现的那个东西，不含任何明文。
func TestSealedFormCarriesNoPlaintext(t *testing.T) {
	sealed, err := Seal(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"store-secret", "key-secret", "anyfun", "not a real keystore"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("%q survives into the sealed form: %s", secret, raw)
		}
	}
}

func TestWrongPassphraseIsRefusedWithoutSayingWhy(t *testing.T) {
	sealed, err := Seal(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Open(sealed, "correct horse battery stapl")
	if err == nil {
		t.Fatal("a wrong passphrase opened the bundle")
	}
	// 区分"口令错"与"内容坏"等于给爆破者一个免费的预言机
	damaged := sealed
	damaged.Ciphertext = base64.StdEncoding.EncodeToString([]byte("garbage that is long enough"))
	_, other := Open(damaged, "correct horse battery staple")
	if other == nil || other.Error() != err.Error() {
		t.Fatalf("a wrong passphrase and damaged content give different answers: %v vs %v", err, other)
	}
}

// KDF 参数和盒子存在一起，所以必须当成不可信输入：改成 N=2 的盒子会让离线爆破
// 从"很贵"变成"很便宜"。
func TestWeakenedKDFParametersAreRefused(t *testing.T) {
	sealed, err := Seal(sample(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Sealed){
		"tiny N": func(s *Sealed) { s.N = 2 },
		"tiny r": func(s *Sealed) { s.R = 1 },
		"tiny p": func(s *Sealed) { s.P = 0 },
	} {
		weak := sealed
		mutate(&weak)
		if _, err := Open(weak, "correct horse battery staple"); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

func TestShortPassphraseIsRefusedAtSealTime(t *testing.T) {
	// 口令是数据库转储和签名密钥之间唯一的东西
	if _, err := Seal(sample(), "short"); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
	if _, err := Seal(Bundle{KeyAlias: "x"}, "correct horse battery staple"); err == nil {
		t.Fatal("an empty keystore was accepted")
	}
}

func TestSealedFormatIsRejectedWhenUnknown(t *testing.T) {
	sealed, _ := Seal(sample(), "correct horse battery staple")
	future := sealed
	future.Version = 2
	if _, err := Open(future, "correct horse battery staple"); err == nil {
		t.Fatal("an unknown format version was opened anyway")
	}
}

// 上传接口原来只认 v1（scrypt + salt），而 CLI 今天产出的全是 v2。
// 那不是「少支持一种格式」——那等于手上有明文 .p12 也装不回一个新库，
// 而那正是灾难恢复里绕不过去的一步
func TestValidateShapeAcceptsBothFormats(t *testing.T) {
	v1 := Sealed{Version: 1, KDF: "scrypt", N: 1 << 16, R: 8, P: 1,
		Salt: "c2FsdA==", Nonce: "bm9uY2U=", Ciphertext: "Y3Q="}
	if err := v1.ValidateShape(); err != nil {
		t.Fatalf("v1 应当被接受: %v", err)
	}
	v2 := Sealed{Version: 2, Algorithm: "x25519-hkdf-sha256+secretbox",
		EphemeralPublicKey: "ZXBr", RecipientKeyID: "kid", Nonce: "bm9uY2U=", Ciphertext: "Y3Q="}
	if err := v2.ValidateShape(); err != nil {
		t.Fatalf("v2 应当被接受——不接受就等于密钥装不回去: %v", err)
	}
}

func TestValidateShapeRejectsMalformedBoxes(t *testing.T) {
	cases := []struct {
		name   string
		sealed Sealed
		want   string
	}{
		{"没有密文", Sealed{Version: 2, Algorithm: "a", EphemeralPublicKey: "e", Nonce: "n"}, "nonce and ciphertext"},
		{"没有 nonce", Sealed{Version: 1, KDF: "scrypt", Salt: "s", Ciphertext: "c"}, "nonce and ciphertext"},
		{"v1 缺 salt", Sealed{Version: 1, KDF: "scrypt", Nonce: "n", Ciphertext: "c"}, "carry a salt"},
		{"v1 参数太弱", Sealed{Version: 1, KDF: "scrypt", Salt: "s", N: 1024, R: 8, P: 1,
			Nonce: "n", Ciphertext: "c"}, "at least N=65536"},
		{"v2 缺 epk", Sealed{Version: 2, Algorithm: "a", Nonce: "n", Ciphertext: "c"}, "alg and epk"},
		{"版本不认识", Sealed{Version: 3, Nonce: "n", Ciphertext: "c"}, "unsupported"},
		{"版本为零", Sealed{Nonce: "n", Ciphertext: "c"}, "unsupported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.sealed.ValidateShape()
			if err == nil {
				t.Fatal("应当被拒绝")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误应当提到 %q，得到: %v", tc.want, err)
			}
		})
	}
}
