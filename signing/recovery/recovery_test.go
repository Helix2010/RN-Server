package recovery

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
)

var (
	testPassphrase = []byte("correct horse battery staple")
	testTime       = time.Date(2026, 9, 16, 12, 34, 56, 789, time.UTC)
)

// 测试用最小的 N 提速；TestProductionParameters 单独跑一次生产参数。
func generate(t *testing.T) (PublicFile, PrivateFile) {
	t.Helper()
	pub, priv, err := Generate("platform-recovery-1", testPassphrase, testTime, MinScryptN)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestGenerateEncodeParseOpenRoundTrip(t *testing.T) {
	pub, priv := generate(t)
	if pub.Format != PublicFormat || pub.Name != "platform-recovery-1" || pub.CreatedAt != "2026-09-16T12:34:56Z" {
		t.Fatalf("public file: %+v", pub)
	}
	if priv.X25519PublicKeySHA256 != pub.X25519PublicKeySHA256 || priv.Name != pub.Name || priv.KDF.N != MinScryptN || priv.KDF.R != 8 || priv.KDF.P != 1 {
		t.Fatalf("private file: %+v", priv)
	}
	pubRaw, err := Encode(pub)
	if err != nil {
		t.Fatal(err)
	}
	privRaw, err := Encode(priv)
	if err != nil {
		t.Fatal(err)
	}
	// JSON 字段名是契约
	for _, field := range []string{`"format"`, `"name"`, `"x25519PublicKey"`, `"x25519PublicKeySha256"`, `"createdAt"`} {
		if !bytes.Contains(pubRaw, []byte(field)) {
			t.Fatalf("public file lacks %s:\n%s", field, pubRaw)
		}
	}
	for _, field := range []string{`"format"`, `"name"`, `"x25519PublicKeySha256"`, `"kdf"`, `"alg"`, `"salt"`, `"n"`, `"r"`, `"p"`, `"nonce"`, `"ciphertext"`} {
		if !bytes.Contains(privRaw, []byte(field)) {
			t.Fatalf("private file lacks %s:\n%s", field, privRaw)
		}
	}
	gotPub, err := ParsePublic(pubRaw)
	if err != nil || gotPub != pub {
		t.Fatalf("ParsePublic: %+v %v", gotPub, err)
	}
	gotPriv, err := ParsePrivate(privRaw)
	if err != nil || gotPriv != priv {
		t.Fatalf("ParsePrivate: %+v %v", gotPriv, err)
	}
	key, err := gotPriv.Open(testPassphrase)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pubKey, _ := gotPub.PublicKey()
	if !bytes.Equal(key.PublicKey().Bytes(), pubKey) {
		t.Fatal("the decrypted private key does not match the public file")
	}
	// 私钥文件里没有公钥原文，也没有私钥原文
	if bytes.Contains(privRaw, []byte(base64.StdEncoding.EncodeToString(key.Bytes()))) {
		t.Fatal("the private key appears in clear in the private key file")
	}
}

func TestRecoveryKeyIsAKeystoreboxRecipient(t *testing.T) {
	pub, priv := generate(t)
	pubKey, _ := pub.PublicKey()
	plain := keystorebox.Plaintext{
		Purpose: keystorebox.Purpose, TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation",
		CertificateSHA256: strings.Repeat("ab", 32), KeyAlias: "anyfun-release", Recipients: []string{pub.X25519PublicKeySHA256},
		CreatedAt: "2026-09-16T00:00:00Z", P12Base64: base64.StdEncoding.EncodeToString([]byte("p12")), StorePassword: "pw-000000", KeyPassword: "pw-000000",
	}
	box, err := keystorebox.Seal(plain, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if box.RecipientSHA256 != pub.X25519PublicKeySHA256 {
		t.Fatalf("box recipient %s, recovery key %s", box.RecipientSHA256, pub.X25519PublicKeySHA256)
	}
	key, err := priv.Open(testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keystorebox.Open(box, key.Bytes())
	if err != nil || got.StorePassword != plain.StorePassword {
		t.Fatalf("keystorebox.Open with the recovery key: %v", err)
	}
}

func TestOpenRejectsWrongPassphraseAndTampering(t *testing.T) {
	_, priv := generate(t)
	if _, err := priv.Open([]byte("correct horse battery stapler")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := priv.Open(nil); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("empty passphrase: %v", err)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	flip := func(b64 string, i int) string {
		raw, _ := base64.StdEncoding.DecodeString(b64)
		raw[i] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	cases := map[string]func(*PrivateFile){
		// 附加数据绑定公钥指纹：改指纹解不开
		"sha256":     func(f *PrivateFile) { f.X25519PublicKeySHA256 = fingerprint.SHA256Hex(other.PublicKey().Bytes()) },
		"ciphertext": func(f *PrivateFile) { f.Ciphertext = flip(f.Ciphertext, 3) },
		"tag":        func(f *PrivateFile) { f.Ciphertext = flip(f.Ciphertext, 40) },
		"nonce":      func(f *PrivateFile) { f.Nonce = flip(f.Nonce, 0) },
		"salt":       func(f *PrivateFile) { f.KDF.Salt = flip(f.KDF.Salt, 0) },
		"n":          func(f *PrivateFile) { f.KDF.N *= 2 },
	}
	for name, mutate := range cases {
		f := priv
		mutate(&f)
		if _, err := f.Open(testPassphrase); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: Open = %v", name, err)
		}
	}
}

func TestParsePublicIsStrict(t *testing.T) {
	pub, _ := generate(t)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	mutations := map[string]func(map[string]any){
		"unknown field":  func(m map[string]any) { m["private"] = "x" },
		"format":         func(m map[string]any) { m["format"] = "rn-recovery-public/v2" },
		"name uppercase": func(m map[string]any) { m["name"] = "Recovery" },
		"name too short": func(m map[string]any) { m["name"] = "a" },
		"sha mismatch":   func(m map[string]any) { m["x25519PublicKeySha256"] = fingerprint.SHA256Hex(other.PublicKey().Bytes()) },
		"sha uppercase":  func(m map[string]any) { m["x25519PublicKeySha256"] = strings.ToUpper(pub.X25519PublicKeySHA256) },
		"key other": func(m map[string]any) {
			m["x25519PublicKey"] = base64.StdEncoding.EncodeToString(other.PublicKey().Bytes())
		},
		"key short":       func(m map[string]any) { m["x25519PublicKey"] = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"key urlsafe b64": func(m map[string]any) { m["x25519PublicKey"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"createdAt local": func(m map[string]any) { m["createdAt"] = "2026-09-16T12:00:00+08:00" },
		"missing field":   func(m map[string]any) { delete(m, "x25519PublicKey") },
	}
	base, _ := json.Marshal(pub)
	for name, mutate := range mutations {
		var m map[string]any
		_ = json.Unmarshal(base, &m)
		mutate(m)
		raw, _ := json.Marshal(m)
		if _, err := ParsePublic(raw); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: ParsePublic = %v", name, err)
		}
	}
	for name, raw := range map[string][]byte{
		"trailing": append(append([]byte{}, base...), []byte(`{}`)...),
		"empty":    nil,
		"array":    []byte(`[]`),
		"huge":     []byte(strings.Repeat(" ", MaxFileSize+1)),
	} {
		if _, err := ParsePublic(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePrivateIsStrict(t *testing.T) {
	_, priv := generate(t)
	base, _ := json.Marshal(priv)
	mutations := map[string]func(map[string]any){
		"unknown field": func(m map[string]any) { m["x25519PublicKey"] = "x" },
		"format":        func(m map[string]any) { m["format"] = PublicFormat },
		"alg":           func(m map[string]any) { m["kdf"].(map[string]any)["alg"] = "pbkdf2" },
		"n too small":   func(m map[string]any) { m["kdf"].(map[string]any)["n"] = 1 << 10 },
		"n too large":   func(m map[string]any) { m["kdf"].(map[string]any)["n"] = 1 << 21 },
		"n not pow2":    func(m map[string]any) { m["kdf"].(map[string]any)["n"] = 100000 },
		"r":             func(m map[string]any) { m["kdf"].(map[string]any)["r"] = 1 },
		"p":             func(m map[string]any) { m["kdf"].(map[string]any)["p"] = 2 },
		"salt short": func(m map[string]any) {
			m["kdf"].(map[string]any)["salt"] = base64.StdEncoding.EncodeToString(make([]byte, 8))
		},
		"nonce short": func(m map[string]any) { m["nonce"] = base64.StdEncoding.EncodeToString(make([]byte, 8)) },
		"ct short":    func(m map[string]any) { m["ciphertext"] = base64.StdEncoding.EncodeToString(make([]byte, 32)) },
		"kdf unknown": func(m map[string]any) { m["kdf"].(map[string]any)["iterations"] = 1 },
	}
	for name, mutate := range mutations {
		var m map[string]any
		_ = json.Unmarshal(base, &m)
		mutate(m)
		raw, _ := json.Marshal(m)
		if _, err := ParsePrivate(raw); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: ParsePrivate = %v", name, err)
		}
	}
}

func TestPassphraseAndParameterValidation(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for name, p := range map[string][]byte{
		"short":        []byte("elevenchars"),
		"control":      []byte("twelve chars\x07!"),
		"newline":      []byte("twelve chars\nmore"),
		"invalid utf8": append([]byte("twelve chars"), 0xff),
		"too long":     bytes.Repeat([]byte("a"), MaxPassphraseLength+1),
	} {
		if _, err := SealPrivate("recovery", key, p, MinScryptN); err == nil {
			t.Errorf("%s passphrase accepted", name)
		}
	}
	if _, err := SealPrivate("recovery", key, testPassphrase, MinScryptN+1); err == nil {
		t.Error("N that is not a power of two accepted")
	}
	if _, err := SealPrivate("Recovery", key, testPassphrase, MinScryptN); err == nil {
		t.Error("malformed name accepted")
	}
	p256, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := SealPrivate("recovery", p256, testPassphrase, MinScryptN); err == nil {
		t.Error("non-X25519 key accepted")
	}
	if _, err := Encode(struct{}{}); err == nil {
		t.Error("Encode accepted an arbitrary value")
	}
}

func TestProductionParameters(t *testing.T) {
	if testing.Short() {
		t.Skip("scrypt N=2^17 needs about 128 MiB")
	}
	_, priv, err := Generate("platform-recovery", testPassphrase, testTime, ScryptN)
	if err != nil {
		t.Fatal(err)
	}
	if priv.KDF.N != 1<<17 || priv.KDF.R != 8 || priv.KDF.P != 1 {
		t.Fatalf("kdf: %+v", priv.KDF)
	}
	if _, err := priv.Open(testPassphrase); err != nil {
		t.Fatal(err)
	}
}
