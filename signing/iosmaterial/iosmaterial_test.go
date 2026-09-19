package iosmaterial

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/internal/sealedbox"
)

func newRecipient(t *testing.T) (priv, pub []byte) {
	t.Helper()
	key, err := sealedbox.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes(), key.PublicKey().Bytes()
}

func certificate() Material {
	return Material{
		Kind: KindCertificate, TeamID: "J4JDFC8LCC",
		P12Base64:   base64.StdEncoding.EncodeToString([]byte("pretend this is a pkcs12")),
		P12Password: "correct horse battery staple",
	}
}

func profile() Material {
	return Material{
		Kind: KindProfile, TeamID: "J4JDFC8LCC", BundleID: "com.anyfun.foundation",
		ProfileBase64: base64.StdEncoding.EncodeToString([]byte("pretend this is a mobileprovision")),
	}
}

func uploadKey() Material {
	return Material{
		Kind: KindUploadKey, TeamID: "J4JDFC8LCC", MachineID: "mch_YSX7-u_TPeImo0mQ2uUoYA",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----")),
	}
}

func TestRoundTripForEveryKind(t *testing.T) {
	priv, pub := newRecipient(t)
	for name, material := range map[string]Material{
		"certificate": certificate(), "profile": profile(), "upload key": uploadKey(),
	} {
		box, err := Seal(material, pub)
		if err != nil {
			t.Fatalf("%s: Seal: %v", name, err)
		}
		if box.RecipientSHA256 != fingerprint.SHA256Hex(pub) {
			t.Errorf("%s: recipient fingerprint is wrong", name)
		}
		got, err := Open(box, priv)
		if err != nil {
			t.Fatalf("%s: Open: %v", name, err)
		}
		switch material.Kind {
		case KindCertificate:
			if got.P12Base64 != material.P12Base64 || got.P12Password != material.P12Password {
				t.Errorf("%s: the certificate came back changed", name)
			}
		case KindProfile:
			if got.ProfileBase64 != material.ProfileBase64 || got.BundleID != material.BundleID {
				t.Errorf("%s: the profile came back changed", name)
			}
		case KindUploadKey:
			if got.P8Base64 != material.P8Base64 || got.KeyID != material.KeyID || got.IssuerID != material.IssuerID {
				t.Errorf("%s: the upload key came back changed", name)
			}
		}
	}
}

// 按角色分两把密钥的整个意义：拿到构建账户那把，解不开上传 Key。
func TestBuilderKeyCannotOpenUploaderMaterial(t *testing.T) {
	priv, pub := newRecipient(t)
	uploader, err := Seal(uploadKey(), pub)
	if err != nil {
		t.Fatal(err)
	}
	// 同一把密钥当然解得开（这里两个角色用了同一把，只为隔离出"用途"这一个变量）：
	// 真正要证明的是用途参与了认证——把它改成构建账户那一个就解不开
	if _, err := Open(uploader, priv); err != nil {
		t.Fatalf("control: %v", err)
	}
	uploader.Purpose = PurposeBuilder
	if _, err := Open(uploader, priv); err == nil {
		t.Fatal("an upload key opened under the builder purpose; the two roles are not separated at all")
	}
	// 种类与用途对不上，形状检查就该拦住
	uploader.Kind = KindCertificate
	if _, err := Open(uploader, priv); err == nil {
		t.Fatal("a box whose kind and purpose disagree was accepted")
	}
}

// Android 的密钥与 iOS 的材料即便共用一把私钥，也不能互相解开——标签不同。
func TestAndroidKeystoreCiphertextIsNotOpenable(t *testing.T) {
	priv, pub := newRecipient(t)
	// 用 Android 那套标签封一份"看起来像 iOS 材料"的载荷
	plain, err := json.Marshal(wireMaterial(certificate()))
	if err != nil {
		t.Fatal(err)
	}
	// 两种：用途也不同（真实的 Android 密文长这样），以及**用途相同只有标签不同**
	// ——后者单独证明标签本身在起作用，不是靠用途撑着
	for _, purpose := range []string{"android-release-keystore", PurposeBuilder} {
		sealed, err := sealedbox.Seal("rn-build-keystore/v3", purpose, plain, pub)
		if err != nil {
			t.Fatal(err)
		}
		box := Box{
			Version: Version, Algorithm: Algorithm, Purpose: PurposeBuilder, Kind: KindCertificate,
			TeamID: "J4JDFC8LCC", RecipientSHA256: sealed.RecipientSHA256,
			EphemeralPublicKey: sealed.EphemeralPublicKey, Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if _, err := Open(box, priv); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("a box from the Android domain (purpose %q) opened as iOS material: %v", purpose, err)
		}
	}
}

func TestOpenRejectsAnotherKeyAndTampering(t *testing.T) {
	priv, pub := newRecipient(t)
	other, _ := newRecipient(t)
	box, err := Seal(profile(), pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(box, other); !errors.Is(err, ErrNotAddressedToThisKey) {
		t.Errorf("another key: %v", err)
	}
	// 外层那几个字段是给服务端路由的提示，改了它们不能让内容被当成别的东西用
	moved := box
	moved.BundleID = "com.attacker.app"
	if _, err := Open(moved, priv); err == nil {
		t.Error("the outer bundleId was trusted")
	}
	tampered := box
	raw, _ := base64.StdEncoding.DecodeString(box.Ciphertext)
	raw[0] ^= 1
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	if _, err := Open(tampered, priv); !errors.Is(err, ErrDecrypt) {
		t.Errorf("tampered ciphertext: %v", err)
	}
}

// 一个种类只许带它自己的机密字段。混着带的话，落地那一步会照 kind 走，多出来的那份
// 材料谁都没核对过。
func TestSealRejectsMixedKinds(t *testing.T) {
	_, pub := newRecipient(t)
	for name, broken := range map[string]func(Material) Material{
		"certificate with a p8":   func(m Material) Material { m.P8Base64 = "AAAA"; return m },
		"profile with a password": func(m Material) Material { m.P12Password = "x"; return m },
		"certificate with bundle": func(m Material) Material { m.BundleID = "com.x.y"; return m },
		"profile with machine":    func(m Material) Material { m.MachineID = "mch_x"; return m },
	} {
		base := certificate()
		if strings.HasPrefix(name, "profile") {
			base = profile()
		}
		if _, err := Seal(broken(base), pub); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSealRejectsMalformedIdentifiers(t *testing.T) {
	_, pub := newRecipient(t)
	for name, broken := range map[string]Material{
		"lowercase team": func() Material { m := certificate(); m.TeamID = "j4jdfc8lcc"; return m }(),
		"short team":     func() Material { m := certificate(); m.TeamID = "J4JD"; return m }(),
		"wildcard bundle": func() Material {
			m := profile()
			m.BundleID = "com.anyfun.*"
			return m
		}(),
		"empty password": func() Material { m := certificate(); m.P12Password = ""; return m }(),
		"bad keyId":      func() Material { m := uploadKey(); m.KeyID = "lowercase1"; return m }(),
		"unknown kind":   func() Material { m := certificate(); m.Kind = "something-else"; return m }(),
	} {
		if _, err := Seal(broken, pub); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// 这个类型装着私钥与口令：不许被打进日志，也不许被 json.Marshal 出去。
func TestMaterialNeverFormatsSecrets(t *testing.T) {
	m := certificate()
	m.P12Password = "SUPER-SECRET-PASSWORD"
	for name, rendered := range map[string]string{
		"String":   m.String(),
		"%v":       strings.TrimSpace(strings.Join([]string{sprint(m)}, "")),
		"GoString": m.GoString(),
	} {
		if strings.Contains(rendered, "SUPER-SECRET-PASSWORD") || strings.Contains(rendered, m.P12Base64) {
			t.Errorf("%s leaked a secret: %s", name, rendered)
		}
	}
	if _, err := json.Marshal(m); err == nil {
		t.Error("Material was marshalled to JSON; it holds a private key and a password")
	}
}

func sprint(m Material) string { return m.String() }

func TestParseBoxRejectsJunk(t *testing.T) {
	_, pub := newRecipient(t)
	box, err := Seal(certificate(), pub)
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBox(good); err != nil {
		t.Fatalf("a good box was rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"empty":            {},
		"not json":         []byte("{"),
		"trailing content": append(append([]byte{}, good...), '{'),
		"unknown field":    []byte(`{"v":1,"alg":"x25519-hkdf-sha256-aes256gcm","surprise":1}`),
		"wrong version":    []byte(strings.Replace(string(good), `"v":1`, `"v":2`, 1)),
	} {
		if _, err := ParseBox(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
