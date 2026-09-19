package sealedbox

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const (
	testLabel   = "rn-test-box/v1"
	testPurpose = "unit-test"
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRoundTrip(t *testing.T) {
	key := newKey(t)
	payload := []byte("这一段里装着口令与私钥")
	sealed, err := Seal(testLabel, testPurpose, payload, key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed.Ciphertext, base64.StdEncoding.EncodeToString(payload)) {
		t.Fatal("the payload is sitting in the ciphertext in the clear")
	}
	got, err := Open(sealed, testLabel, testPurpose, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round trip changed the payload: %q", got)
	}
}

// 信封绑死三样：收件人、label、purpose。任何一样不符都解不开——这不是调用方记得检查，
// 是解密这一步就失败。label 与 purpose 是两套材料之间的域分隔：Android 的签名密钥与
// iOS 的签名材料即便共用一把私钥，一种的密文也绝不会被当成另一种解开。
func TestOpenIsBoundToRecipientLabelAndPurpose(t *testing.T) {
	key, other := newKey(t), newKey(t)
	sealed, err := Seal(testLabel, testPurpose, []byte("secret"), key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, testLabel, testPurpose, other); !errors.Is(err, ErrNotAddressedToThisKey) {
		t.Errorf("another key opened it: %v", err)
	}
	for name, attempt := range map[string]struct{ label, purpose string }{
		"another label":      {"rn-build-keystore/v3", testPurpose},
		"another purpose":    {testLabel, "android-release-keystore"},
		"empty label":        {"", testPurpose},
		"empty purpose":      {testLabel, ""},
		"label and purpose":  {"rn-build-keystore/v3", "android-release-keystore"},
		"purpose with a tab": {testLabel, testPurpose + "\t"},
	} {
		if _, err := Open(sealed, attempt.label, attempt.purpose, key); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: Open = %v, want ErrDecrypt", name, err)
		}
	}
	if _, err := Open(sealed, testLabel, testPurpose, key); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// 密文、nonce、临时公钥任一被改都解不开，而且回的是同一句话——错误信息不该变成一个
// 可以试探"我改对了哪一段"的口子。
func TestOpenRejectsTampering(t *testing.T) {
	key := newKey(t)
	sealed, err := Seal(testLabel, testPurpose, []byte("secret"), key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	flip := func(s string) string {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	for name, broken := range map[string]Sealed{
		"ciphertext":     {sealed.RecipientSHA256, sealed.EphemeralPublicKey, sealed.Nonce, flip(sealed.Ciphertext)},
		"nonce":          {sealed.RecipientSHA256, sealed.EphemeralPublicKey, flip(sealed.Nonce), sealed.Ciphertext},
		"ephemeral key":  {sealed.RecipientSHA256, flip(sealed.EphemeralPublicKey), sealed.Nonce, sealed.Ciphertext},
		"short nonce":    {sealed.RecipientSHA256, sealed.EphemeralPublicKey, "AAEC", sealed.Ciphertext},
		"empty ct":       {sealed.RecipientSHA256, sealed.EphemeralPublicKey, sealed.Nonce, ""},
		"not base64":     {sealed.RecipientSHA256, sealed.EphemeralPublicKey, sealed.Nonce, "!!!"},
		"padded ct":      {sealed.RecipientSHA256, sealed.EphemeralPublicKey, sealed.Nonce, sealed.Ciphertext + "="},
		"epk zero point": {sealed.RecipientSHA256, base64.StdEncoding.EncodeToString(make([]byte, KeySize)), sealed.Nonce, sealed.Ciphertext},
	} {
		if _, err := Open(broken, testLabel, testPurpose, key); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: Open = %v, want ErrDecrypt", name, err)
		}
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	key := newKey(t)
	if _, err := Seal(testLabel, testPurpose, nil, make([]byte, 31)); err == nil {
		t.Error("a 31 byte recipient key was accepted")
	}
	if _, err := SealWith(testLabel, testPurpose, nil, key.PublicKey().Bytes(), key, make([]byte, 11)); err == nil {
		t.Error("an 11 byte nonce was accepted")
	}
	if _, err := PrivateKey(make([]byte, 31)); err == nil {
		t.Error("a 31 byte private key was accepted")
	}
}

// 同一份载荷封两次，密文不能一样：临时密钥与 nonce 每次都得重取。
func TestSealIsNotDeterministic(t *testing.T) {
	key := newKey(t)
	first, err := Seal(testLabel, testPurpose, []byte("secret"), key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Seal(testLabel, testPurpose, []byte("secret"), key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if first.Ciphertext == second.Ciphertext || first.Nonce == second.Nonce || first.EphemeralPublicKey == second.EphemeralPublicKey {
		t.Fatal("sealing the same payload twice produced the same box; the ephemeral key or nonce is being reused")
	}
}
