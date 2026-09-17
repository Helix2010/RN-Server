package keystorebox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 同证书重新封装（reseal）的签名格式：与生成签名分开的前缀，重封 id 必须带 rsl_ 前缀。

const testResealID = "rsl_fixtureRESEAL000000001"

func TestResealIDFormat(t *testing.T) {
	if !ValidResealID(testResealID) || !ValidGenerationRequestID(testResealID) {
		t.Fatalf("%s must be a valid reseal id and a valid generation request id", testResealID)
	}
	for _, bad := range []string{
		"", "rsl_", "rsl_short", "kgr_fixtureRESEAL000000001", "RSL_fixtureRESEAL000000001",
		"rsl_fixtureRESEAL0000000012", "rsl_fixtureRESEAL00000000!", "rsl_fixtureRESEAL0000000\n1", "xrsl_fixtureRESEAL000000001",
	} {
		if ValidResealID(bad) {
			t.Errorf("ValidResealID(%q) = true", bad)
		}
	}
}

func TestResealMessageGoldenVector(t *testing.T) {
	u, err := ParseUpload([]byte(goldenUploadJSON))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ResealMessage(testResealID, u)
	if err != nil {
		t.Fatal(err)
	}
	if want := "rn-keystore-reseal/v1\n" + testResealID + "\n" + goldenUploadDigest; string(msg) != want {
		t.Fatalf("ResealMessage = %q", msg)
	}
	generation, _ := GenerationMessage(testResealID, u)
	if string(generation) == string(msg) {
		t.Fatal("a reseal message equals the generation message for the same id and upload")
	}
	if _, err := ResealMessage("kgr_request0001", u); err == nil {
		t.Fatal("a reseal message without the rsl_ prefix was built")
	}
}

func TestResealSignRoundTripAndTampering(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	u := validUpload(t)
	sig, err := SignReseal(priv, testResealID, u)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReseal(pub, testResealID, u, sig); err != nil {
		t.Fatalf("VerifyReseal: %v", err)
	}
	dropped := u
	dropped.Boxes = u.Boxes[:1]
	swapped := u
	swapped.Boxes = []Box{u.Boxes[1], u.Boxes[0]}
	otherCert := u
	otherCert.CertificateSHA256 = strings.Repeat("cd", 32)
	for name, c := range map[string]struct {
		pub      ed25519.PublicKey
		resealID string
		upload   Upload
		sig      string
	}{
		"other reseal id":     {pub, "rsl_fixtureRESEAL000000002", u, sig},
		"other signer":        {otherPub, testResealID, u, sig},
		"box dropped":         {pub, testResealID, dropped, sig},
		"box order":           {pub, testResealID, swapped, sig},
		"certificate":         {pub, testResealID, otherCert, sig},
		"not base64":          {pub, testResealID, u, "!!"},
		"short public key":    {pub[:10], testResealID, u, sig},
		"id without prefix":   {pub, "fixtureRESEAL0000001xxxx", u, sig},
		"generation-style id": {pub, "kgr_request0001", u, sig},
		"malformed upload":    {pub, testResealID, Upload{}, sig},
	} {
		if err := VerifyReseal(c.pub, c.resealID, c.upload, c.sig); !errors.Is(err, ErrResealSignature) {
			t.Errorf("%s: VerifyReseal = %v", name, err)
		}
	}
	if _, err := SignReseal(priv, "kgr_request0001", u); err == nil {
		t.Fatal("signed a reseal with an id without the rsl_ prefix")
	}
}

// 跨域重放：同一把 Ed25519、同一个 id（rsl_… 也满足生成请求 id 的格式）、同一份上传文件，生成签名不能当重封签名用，
// 反过来也不行。
func TestResealAndGenerationSignaturesAreNotInterchangeable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	u := validUpload(t)
	generation, err := SignGeneration(priv, testResealID, u)
	if err != nil {
		t.Fatal(err)
	}
	reseal, err := SignReseal(priv, testResealID, u)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReseal(pub, testResealID, u, generation); !errors.Is(err, ErrResealSignature) {
		t.Fatalf("a generation signature verified as a reseal: %v", err)
	}
	if err := VerifyGeneration(pub, testResealID, u, reseal); !errors.Is(err, ErrGenerationSignature) {
		t.Fatalf("a reseal signature verified as a generation: %v", err)
	}
}

// Kind 为空时明文 JSON 与加这个字段之前逐字节相同；重新封装的明文必须 Kind=reseal 且 supersedes 等于证书本身，
// 生成的明文 supersedes 仍然不能等于证书本身；不认识的 Kind 拒绝。
func TestGenerationKindRules(t *testing.T) {
	a := newKey(t)
	cert := samplePlaintext(a).CertificateSHA256
	digest := strings.Repeat("cd", 32)

	generated := samplePlaintext(a)
	generated.Generation = &Generation{TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 157}
	raw, _ := json.Marshal(wirePlaintext(generated))
	const legacyGeneration = `"generation":{"trustRootsDigest":"` + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
		`","minSdk":24,"targetSdk":28,"firstSignMaxVersionCode":157,"supersedesCertificateSha256":""}}`
	if !strings.HasSuffix(string(raw), legacyGeneration) {
		t.Fatalf("a generation plaintext no longer serializes as before: %s", raw)
	}

	resealed := samplePlaintext(a)
	resealed.Generation = &Generation{TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 157, SupersedesCertificateSHA256: cert, Kind: GenerationKindReseal}
	box, err := Seal(resealed, a.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("seal a reseal plaintext: %v", err)
	}
	got, err := Open(box, a.Bytes())
	if err != nil || got.Generation == nil || *got.Generation != *resealed.Generation {
		t.Fatalf("reseal round trip: %+v %v", got.Generation, err)
	}
	if !strings.Contains(got.String(), `kind="reseal"`) {
		t.Fatalf("String does not show the kind: %s", got.String())
	}
	raw, _ = json.Marshal(wirePlaintext(resealed))
	if !strings.Contains(string(raw), `"kind":"reseal"`) {
		t.Fatalf("the reseal kind is not serialized: %s", raw)
	}

	for name, g := range map[string]Generation{
		"reseal of another certificate": {TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 1, SupersedesCertificateSHA256: strings.Repeat("ef", 32), Kind: GenerationKindReseal},
		"reseal without supersedes":     {TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 1, Kind: GenerationKindReseal},
		"unknown kind":                  {TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 1, SupersedesCertificateSHA256: cert, Kind: "rotate"},
		"generation superseding itself": {TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 1, SupersedesCertificateSHA256: cert},
	} {
		bad := samplePlaintext(a)
		bad.Generation = &g
		if _, err := Seal(bad, a.PublicKey().Bytes()); err == nil {
			t.Errorf("%s: sealed", name)
		}
		// 解封时同样拒绝（服务端或别的签名闸塞进来的明文）
		plain, _ := json.Marshal(wirePlaintext(bad))
		if _, err := Open(encryptRaw(t, a, plain), a.Bytes()); !errors.Is(err, ErrInvalidPlaintext) {
			t.Errorf("%s: Open = %v", name, err)
		}
	}
	// 不认识 kind 字段的旧明文结构（例如回滚前的签名闸）读到 kind 会拒绝：这是新增字段带来的单向兼容，这里固定下来
	var legacy struct {
		TrustRootsDigest            string `json:"trustRootsDigest"`
		MinSDK                      int64  `json:"minSdk"`
		TargetSDK                   int64  `json:"targetSdk"`
		FirstSignMaxVersionCode     int64  `json:"firstSignMaxVersionCode"`
		SupersedesCertificateSHA256 string `json:"supersedesCertificateSha256"`
	}
	kindJSON, _ := json.Marshal(resealed.Generation)
	decoder := json.NewDecoder(strings.NewReader(string(kindJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacy); err == nil {
		t.Fatal("a strict decoder without the kind field accepted a reseal binding")
	}
}
