package keystorebox

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"
)

// 哨兵值：只要它出现在任何格式化输出里，就是泄漏
const (
	sentinelStore = "SENTINEL-STORE-PASSWORD-7f3a"
	sentinelKey   = "SENTINEL-KEY-PASSWORD-91bc"
	sentinelP12   = "U0VOVElORUwtUDEyLUJZVEVT" // base64("SENTINEL-P12-BYTES")
)

func newKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func samplePlaintext(recipients ...*ecdh.PrivateKey) Plaintext {
	var shas []string
	for _, r := range recipients {
		shas = append(shas, RecipientSHA256(r.PublicKey().Bytes()))
	}
	sort.Strings(shas)
	return Plaintext{
		Purpose:           Purpose,
		TenantSlug:        "AnyFun",
		PackageName:       "com.anyfun.foundation",
		CertificateSHA256: strings.Repeat("ab", 32),
		KeyAlias:          "anyfun-release",
		Recipients:        shas,
		CreatedAt:         "2026-09-16T00:00:00Z",
		P12Base64:         sentinelP12,
		StorePassword:     sentinelStore,
		KeyPassword:       sentinelKey,
	}
}

func TestSealOpenRoundTripForEveryRecipient(t *testing.T) {
	a, b := newKey(t), newKey(t)
	p := samplePlaintext(a, b)
	for _, k := range []*ecdh.PrivateKey{a, b} {
		box, err := Seal(p, k.PublicKey().Bytes())
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		got, err := Open(box, k.Bytes())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got.StorePassword != p.StorePassword || got.P12Base64 != p.P12Base64 || got.TenantSlug != p.TenantSlug ||
			strings.Join(got.Recipients, ",") != strings.Join(p.Recipients, ",") {
			t.Fatal("round trip changed the plaintext")
		}
	}
}

// 金标向量由独立实现（Python cryptography：X25519 + HKDF + AESGCM）按约定 3.2
// 算出，锁住 KDF info、附加数据与明文 JSON 的字段顺序。服务端、离线工具与签名闸
// 任何一边改了构造，这个测试先失败。
const goldenBox = `{"v":3,"alg":"x25519-hkdf-sha256-aes256gcm","recipientSha256":"aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041","epk":"ZLEBsdC+WocEvQePmJUAH8A+jp+VIvGI3RKNmEbUhGY=","nonce":"AAECAwQFBgcICQoL","ct":"Qu3gWezYw3IXYXN6p0yUGqOioRjP3WuNiWmXXdEjR0qT4k4tcRJQ/GQDUX5xkfXpdFiC+oCHMGPog9NQosidVx1sFIDIVqZS3XMRKguYQp+xYbxKtBXynh0Wy47c1pqYYAncSzV7Vs7OrRsVzj8mQyVjkf/FQnn6ZLM0D3UJf36SmBvcLWrSgufrWeZ3tthn9v3chZB1vqgWIudb1GnFkJHfxXQLpSmcsTNlUqxgJZvKCRh7PRlBCGQn/GH2UUoDYzNkcZk40OQsqnvzSqsJqgyAi6dQqz/Jl9TvaulU3N/kwK8DElWLg2hIGB6QxPrcJUMkv0DctiIZBh32Nkq/AlUVa4NojSlhozNOpzYNiZWd4lvwIkkgfSEIedfuZrzIRnjoCFbe+fhALYtjCxHD49ToXBQzQG3mNQS2xeJnEXpRwCid2hbYel7u1+ZkLmHW1wqFvLU36+mtys53nPYw9OitLi48XjMCPGvFXFyjp0nD4Et/SbPc8x/iHLTPz6ILjFacWqdVBzEFw0ksLn4Yge6oYlSCIJuzYuaFQeVxn6HrGydBMUXf"}`

func fixedBytes(start byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func TestGoldenVector(t *testing.T) {
	recipient, err := ecdh.X25519().NewPrivateKey(fixedBytes(1, 32))
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.X25519().NewPrivateKey(fixedBytes(0x41, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := Plaintext{
		Purpose: Purpose, TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation",
		CertificateSHA256: strings.Repeat("ab", 32), KeyAlias: "anyfun-release",
		Recipients: []string{RecipientSHA256(recipient.PublicKey().Bytes())},
		CreatedAt:  "2026-09-16T00:00:00Z", P12Base64: "AAECAw==", StorePassword: "store-pass", KeyPassword: "key-pass",
	}
	var want Box
	if err := json.Unmarshal([]byte(goldenBox), &want); err != nil {
		t.Fatal(err)
	}
	got, err := sealWith(plain, recipient.PublicKey().Bytes(), ephemeral, fixedBytes(0, 12))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sealWith does not reproduce the golden box:\n got %+v\nwant %+v", got, want)
	}
	opened, err := Open(want, recipient.Bytes())
	if err != nil {
		t.Fatalf("Open(golden): %v", err)
	}
	if opened.StorePassword != "store-pass" || opened.KeyAlias != "anyfun-release" {
		t.Fatal("golden box opened to the wrong content")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	a, b := newKey(t), newKey(t)
	p := samplePlaintext(a)
	box, err := Seal(p, a.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	flip := func(field string, i int) string {
		raw, _ := base64.StdEncoding.DecodeString(field)
		raw[i] ^= 1
		return base64.StdEncoding.EncodeToString(raw)
	}
	otherEphemeral := base64.StdEncoding.EncodeToString(newKey(t).PublicKey().Bytes())
	cases := map[string]struct {
		mutate func(*Box)
		key    []byte
		want   error
	}{
		"ciphertext byte": {func(x *Box) { x.Ciphertext = flip(x.Ciphertext, 3) }, a.Bytes(), ErrDecrypt},
		"gcm tag": {func(x *Box) {
			raw, _ := base64.StdEncoding.DecodeString(x.Ciphertext)
			x.Ciphertext = flip(x.Ciphertext, len(raw)-1)
		}, a.Bytes(), ErrDecrypt},
		"nonce":                    {func(x *Box) { x.Nonce = flip(x.Nonce, 0) }, a.Bytes(), ErrDecrypt},
		"ephemeral key":            {func(x *Box) { x.EphemeralPublicKey = otherEphemeral }, a.Bytes(), ErrDecrypt},
		"low-order ephemeral":      {func(x *Box) { x.EphemeralPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32)) }, a.Bytes(), ErrDecrypt},
		"recipient fingerprint":    {func(x *Box) { x.RecipientSHA256 = strings.Repeat("0", 64) }, a.Bytes(), ErrNotAddressedToThisKey},
		"opened by another key":    {func(*Box) {}, b.Bytes(), ErrNotAddressedToThisKey},
		"readdressed to other key": {func(x *Box) { x.RecipientSHA256 = RecipientSHA256(b.PublicKey().Bytes()) }, b.Bytes(), ErrDecrypt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := box
			tc.mutate(&tampered)
			if _, err := Open(tampered, tc.key); !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
		})
	}
}

// 附加数据绑定：同一份密文，只要附加数据里的 purpose 或收件人指纹不同就解不开。
func TestAdditionalDataIsAuthenticated(t *testing.T) {
	a := newKey(t)
	box, err := Seal(samplePlaintext(a), a.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for name, aad := range map[string][]byte{
		"other purpose":   []byte(kdfLabel + "\nandroid-debug-keystore\n" + box.RecipientSHA256),
		"other recipient": additionalData(strings.Repeat("1", 64)),
		"other version":   []byte("rn-build-keystore/v2\n" + Purpose + "\n" + box.RecipientSHA256),
		"empty":           nil,
	} {
		if _, err := open(box, a, aad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: open = %v, want ErrDecrypt", name, err)
		}
	}
	if _, err := open(box, a, additionalData(box.RecipientSHA256)); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// encryptRaw 绕过 Seal 的校验，直接把任意明文字节加密给 recipient，用来测 Open
// 对"密码学上合法、内容不合法"的明文的处理。
func encryptRaw(t *testing.T, recipient *ecdh.PrivateKey, plain []byte) Box {
	t.Helper()
	eph := newKey(t)
	shared, err := eph.ECDH(recipient.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAEAD(shared, eph.PublicKey().Bytes(), recipient.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	sha := RecipientSHA256(recipient.PublicKey().Bytes())
	return Box{
		Version: Version, Algorithm: Algorithm, RecipientSHA256: sha,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:         base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, additionalData(sha))),
	}
}

func TestOpenRejectsInvalidPlaintext(t *testing.T) {
	a, b := newKey(t), newKey(t)
	marshal := func(p Plaintext) []byte {
		raw, err := json.Marshal(wirePlaintext(p))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	notListed := samplePlaintext(b) // 收件人列表里没有 a
	wrongPurpose := samplePlaintext(a)
	wrongPurpose.Purpose = "android-debug-keystore"
	badFingerprint := samplePlaintext(a)
	badFingerprint.CertificateSHA256 = strings.Repeat("AB", 32)
	newline := samplePlaintext(a)
	newline.StorePassword = "line1\nline2"
	withUnknown := bytes.Replace(marshal(samplePlaintext(a)), []byte(`{`), []byte(`{"kid":"x",`), 1)
	trailing := append(marshal(samplePlaintext(a)), []byte(`{}`)...)
	for name, plain := range map[string][]byte{
		"recipient not listed": marshal(notListed),
		"wrong purpose":        marshal(wrongPurpose),
		"uppercase cert":       marshal(badFingerprint),
		"newline in password":  marshal(newline),
		"unknown field":        withUnknown,
		"trailing data":        trailing,
		"not json":             []byte("not json"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Open(encryptRaw(t, a, plain), a.Bytes())
			if !errors.Is(err, ErrInvalidPlaintext) {
				t.Fatalf("Open = %v, want ErrInvalidPlaintext", err)
			}
			if err != nil && (strings.Contains(err.Error(), sentinelStore) || strings.Contains(err.Error(), "line1")) {
				t.Fatalf("error leaks a password: %v", err)
			}
		})
	}
}

func TestSealRejectsBadInput(t *testing.T) {
	a, b := newKey(t), newKey(t)
	if _, err := Seal(samplePlaintext(b), a.PublicKey().Bytes()); err == nil {
		t.Fatal("sealed to a recipient that is not listed in the plaintext")
	}
	if _, err := Seal(samplePlaintext(a), a.PublicKey().Bytes()[:31]); err == nil {
		t.Fatal("accepted a short public key")
	}
	unsorted := samplePlaintext(a, b)
	unsorted.Recipients[0], unsorted.Recipients[1] = unsorted.Recipients[1], unsorted.Recipients[0]
	if _, err := Seal(unsorted, a.PublicKey().Bytes()); err == nil {
		t.Fatal("accepted unsorted recipients")
	}
	dup := samplePlaintext(a)
	dup.Recipients = append(dup.Recipients, dup.Recipients[0])
	if _, err := Seal(dup, a.PublicKey().Bytes()); err == nil {
		t.Fatal("accepted duplicate recipients")
	}
	for name, mutate := range map[string]func(*Plaintext){
		"slug":       func(p *Plaintext) { p.TenantSlug = "any fun" },
		"package":    func(p *Plaintext) { p.PackageName = "Com.Anyfun" },
		"alias":      func(p *Plaintext) { p.KeyAlias = "a b" },
		"createdAt":  func(p *Plaintext) { p.CreatedAt = "2026-09-16" },
		"p12":        func(p *Plaintext) { p.P12Base64 = "" },
		"p12 base64": func(p *Plaintext) { p.P12Base64 = "!!" },
		"store pass": func(p *Plaintext) { p.StorePassword = "" },
		"key pass":   func(p *Plaintext) { p.KeyPassword = "a\x00b" },
	} {
		p := samplePlaintext(a)
		mutate(&p)
		_, err := Seal(p, a.PublicKey().Bytes())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), sentinelStore) || strings.Contains(err.Error(), sentinelKey) {
			t.Errorf("%s: error leaks a password: %v", name, err)
		}
	}
}

func TestPlaintextNeverFormatsSecrets(t *testing.T) {
	a := newKey(t)
	p := samplePlaintext(a)
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%T %v"} {
		outputs = append(outputs, fmt.Sprintf(verb, p), fmt.Sprintf(verb, &p), fmt.Sprintf(verb, []Plaintext{p}),
			fmt.Sprintf(verb, map[string]Plaintext{"k": p}), fmt.Sprintf(verb, struct{ Inner Plaintext }{p}))
	}
	outputs = append(outputs, p.String(), p.GoString(), fmt.Errorf("wrapped: %v", p).Error(), fmt.Sprint(p), fmt.Sprintln(p))
	for _, handler := range []func(*bytes.Buffer) slog.Handler{
		func(w *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		func(w *bytes.Buffer) slog.Handler { return slog.NewTextHandler(w, nil) },
	} {
		var buf bytes.Buffer
		logger := slog.New(handler(&buf))
		logger.Info("opened", "plaintext", p, "pointer", &p)
		logger.Info("any", slog.Any("plaintext", p))
		outputs = append(outputs, buf.String())
	}
	if raw, err := json.Marshal(p); err == nil {
		t.Fatalf("json.Marshal succeeded: %s", raw)
	}
	if raw, err := json.Marshal(struct{ P Plaintext }{p}); err == nil {
		t.Fatalf("json.Marshal of a wrapper succeeded: %s", raw)
	}
	decoded, _ := base64.StdEncoding.DecodeString(sentinelP12)
	for _, out := range outputs {
		for _, secret := range []string{sentinelStore, sentinelKey, sentinelP12, string(decoded)} {
			if strings.Contains(out, secret) {
				t.Fatalf("formatted output leaks a secret: %s", out)
			}
		}
	}
	if !strings.Contains(p.String(), "anyfun-release") {
		t.Fatal("whitelisted fields are missing from the formatted output")
	}
}

func validUpload(t *testing.T) Upload {
	a, b := newKey(t), newKey(t)
	p := samplePlaintext(a, b)
	var boxes []Box
	for _, k := range []*ecdh.PrivateKey{a, b} {
		box, err := Seal(p, k.PublicKey().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		boxes = append(boxes, box)
	}
	return Upload{
		Format: UploadFormat, TenantSlug: p.TenantSlug, PackageName: p.PackageName, KeyAlias: p.KeyAlias,
		CertificateSHA256: p.CertificateSHA256, CreatedAt: p.CreatedAt, Boxes: boxes,
	}
}

func TestUploadValidateShape(t *testing.T) {
	if err := validUpload(t).ValidateShape(); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}
	cases := map[string]func(*Upload){
		"format v2":      func(u *Upload) { u.Format = "rn-android-keystore-upload/v2" },
		"slug":           func(u *Upload) { u.TenantSlug = "" },
		"package":        func(u *Upload) { u.PackageName = "anyfun" },
		"alias":          func(u *Upload) { u.KeyAlias = "" },
		"certificate":    func(u *Upload) { u.CertificateSHA256 = "abc" },
		"createdAt":      func(u *Upload) { u.CreatedAt = "now" },
		"no boxes":       func(u *Upload) { u.Boxes = nil },
		"duplicate box":  func(u *Upload) { u.Boxes[1] = u.Boxes[0] },
		"too many boxes": func(u *Upload) { u.Boxes = append(u.Boxes, make([]Box, MaxBoxes)...) },
		"box version":    func(u *Upload) { u.Boxes[0].Version = 2 },
		"box alg":        func(u *Upload) { u.Boxes[0].Algorithm = "x25519" },
		"box recipient":  func(u *Upload) { u.Boxes[0].RecipientSHA256 = strings.ToUpper(u.Boxes[0].RecipientSHA256) },
		"box epk length": func(u *Upload) { u.Boxes[0].EphemeralPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"box epk encoding": func(u *Upload) {
			u.Boxes[0].EphemeralPublicKey = base64.RawStdEncoding.EncodeToString(make([]byte, 32))
		},
		"box nonce":         func(u *Upload) { u.Boxes[0].Nonce = base64.StdEncoding.EncodeToString(make([]byte, 24)) },
		"box ct too short":  func(u *Upload) { u.Boxes[0].Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 16)) },
		"box ct not base64": func(u *Upload) { u.Boxes[0].Ciphertext = "***" },
		"box ct too large": func(u *Upload) {
			u.Boxes[0].Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, maxCiphertextSize+1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			u := validUpload(t)
			mutate(&u)
			if err := u.ValidateShape(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// 非规范 base64（末尾填充位不为零）也要拒：两份字节不同的字符串解出同一个值，
// 服务端按字符串去重就会漏掉。
func TestBoxRejectsNonCanonicalBase64(t *testing.T) {
	u := validUpload(t)
	epk := u.Boxes[0].EphemeralPublicKey // 32 字节 → 44 字符，最后一个数据字符的低 2 位是填充位
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	idx := strings.IndexByte(alphabet, epk[len(epk)-2])
	u.Boxes[0].EphemeralPublicKey = epk[:len(epk)-2] + string(alphabet[idx^1]) + "="
	if raw, err := base64.StdEncoding.DecodeString(u.Boxes[0].EphemeralPublicKey); err != nil || len(raw) != 32 {
		t.Fatalf("the lenient decoder should still accept the variant: %v", err)
	}
	if err := u.Boxes[0].ValidateShape(); err == nil {
		t.Fatal("accepted non-canonical base64")
	}
}
