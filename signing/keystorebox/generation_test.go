package keystorebox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// goldenUploadJSON 故意带缩进：摘要按解码后的结构体重新 Marshal 计算，与原始字节的空白无关。
var goldenUploadJSON = `{
  "format": "rn-android-keystore-upload/v3",
  "tenantSlug": "AnyFun",
  "packageName": "com.anyfun.foundation",
  "keyAlias": "anyfun-release",
  "certificateSha256": "` + strings.Repeat("ab", 32) + `",
  "createdAt": "2026-09-16T00:00:00Z",
  "boxes": [` + goldenBox + `]
}
`

// 由独立实现（Python：json.dumps(separators=(',', ':')) 按结构体字段顺序 + hashlib.sha256）算出。
const goldenUploadDigest = "cea4257a4603ea28d6ddd3e9b3e6038ef78f39f5e40ffb24d352e8865addfc5e"

func TestUploadDigestGoldenVector(t *testing.T) {
	u, err := ParseUpload([]byte(goldenUploadJSON))
	if err != nil {
		t.Fatalf("ParseUpload: %v", err)
	}
	digest, err := UploadDigest(u)
	if err != nil || digest != goldenUploadDigest {
		t.Fatalf("UploadDigest = %q, %v; want %s", digest, err, goldenUploadDigest)
	}
	msg, err := GenerationMessage("kgr_fixtureREQUEST01", u)
	if err != nil {
		t.Fatal(err)
	}
	if want := "rn-keystore-generation/v1\nkgr_fixtureREQUEST01\n" + goldenUploadDigest; string(msg) != want {
		t.Fatalf("GenerationMessage = %q", msg)
	}
}

func TestGenerationSignRoundTripAndTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	u := validUpload(t)
	sig, err := SignGeneration(priv, "kgr_request0001", u)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyGeneration(pub, "kgr_request0001", u, sig); err != nil {
		t.Fatalf("VerifyGeneration: %v", err)
	}

	swapped := u
	swapped.Boxes = []Box{u.Boxes[1], u.Boxes[0]}
	dropped := u
	dropped.Boxes = u.Boxes[:1]
	otherCert := u
	otherCert.CertificateSHA256 = strings.Repeat("cd", 32)
	cases := map[string]struct {
		pub       ed25519.PublicKey
		requestID string
		upload    Upload
		sig       string
	}{
		"other request":      {pub, "kgr_request0002", u, sig},
		"other generator":    {otherPub, "kgr_request0001", u, sig},
		"box order":          {pub, "kgr_request0001", swapped, sig},
		"box dropped":        {pub, "kgr_request0001", dropped, sig},
		"certificate":        {pub, "kgr_request0001", otherCert, sig},
		"not base64":         {pub, "kgr_request0001", u, "!!"},
		"short signature":    {pub, "kgr_request0001", u, base64.StdEncoding.EncodeToString([]byte("short"))},
		"short public key":   {pub[:10], "kgr_request0001", u, sig},
		"request with \\n":   {pub, "kgr_request0001\nx", u, sig},
		"empty request id":   {pub, "", u, sig},
		"malformed upload":   {pub, "kgr_request0001", Upload{}, sig},
		"request too long":   {pub, strings.Repeat("a", 129), u, sig},
		"request with slash": {pub, "kgr/../x", u, sig},
	}
	for name, c := range cases {
		if err := VerifyGeneration(c.pub, c.requestID, c.upload, c.sig); !errors.Is(err, ErrGenerationSignature) {
			t.Errorf("%s: VerifyGeneration = %v", name, err)
		}
	}
	if _, err := SignGeneration(priv, "bad id", u); err == nil {
		t.Fatal("signed with a malformed request id")
	}
	if _, err := UploadDigest(Upload{}); err == nil {
		t.Fatal("digested a malformed upload")
	}
}

func TestParseUploadIsStrict(t *testing.T) {
	u := validUpload(t)
	raw, _ := json.Marshal(u)
	if got, err := ParseUpload(raw); err != nil || got.CertificateSHA256 != u.CertificateSHA256 || len(got.Boxes) != 2 {
		t.Fatalf("ParseUpload: %v", err)
	}
	var generic map[string]any
	_ = json.Unmarshal(raw, &generic)
	generic["extra"] = true
	withExtra, _ := json.Marshal(generic)
	for name, input := range map[string][]byte{
		"unknown field": withExtra,
		"trailing data": append(append([]byte{}, raw...), []byte(`{}`)...),
		"bad shape":     []byte(`{"format":"rn-android-keystore-upload/v3"}`),
		"too large":     []byte(strings.Repeat(" ", MaxUploadSize+1)),
	} {
		if _, err := ParseUpload(input); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	box, ok := u.BoxFor(u.Boxes[1].RecipientSHA256)
	if !ok || box != u.Boxes[1] {
		t.Fatal("BoxFor did not find the box")
	}
	if _, ok := u.BoxFor(strings.Repeat("0", 64)); ok {
		t.Fatal("BoxFor found a box for an unknown recipient")
	}
}
