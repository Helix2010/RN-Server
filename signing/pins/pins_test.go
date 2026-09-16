package pins

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

func signer(t *testing.T, name, role string) Signer {
	t.Helper()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Entry(name, role, x.PublicKey().Bytes(), edPub)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func encode(t *testing.T, f File) []byte {
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseValidFile(t *testing.T) {
	a, b := signer(t, "amos-signer-a", RolePrimary), signer(t, "amos-signer-b", RoleStandby)
	f, err := Parse(encode(t, File{Format: Format, Signers: []Signer{a, b}}))
	if err != nil {
		t.Fatal(err)
	}
	rec := f.RecipientSHA256s()
	if len(rec) != 2 || rec[0] >= rec[1] {
		t.Fatalf("recipients not sorted: %v", rec)
	}
	if _, err := f.Signers[0].PublicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejects(t *testing.T) {
	a, b := signer(t, "amos-signer-a", RolePrimary), signer(t, "amos-signer-b", RoleStandby)
	mismatched := b
	mismatched.X25519PublicKeySHA256 = a.X25519PublicKeySHA256
	sameKey := b
	sameKey.X25519PublicKey, sameKey.X25519PublicKeySHA256 = a.X25519PublicKey, a.X25519PublicKeySHA256
	twoPrimaries := b
	twoPrimaries.Role = RolePrimary
	sameName := b
	sameName.Name = a.Name
	badRole := b
	badRole.Role = "backup"
	badName := b
	badName.Name = "Amos Signer"
	upper := b
	upper.X25519PublicKeySHA256 = strings.ToUpper(b.X25519PublicKeySHA256)
	noEd := b
	noEd.Ed25519PublicKeySHA256 = ""
	sameEd := b
	sameEd.Ed25519PublicKeySHA256 = a.Ed25519PublicKeySHA256
	for name, raw := range map[string][]byte{
		"fingerprint mismatch": encode(t, File{Format: Format, Signers: []Signer{a, mismatched}}),
		"duplicate key":        encode(t, File{Format: Format, Signers: []Signer{a, sameKey}}),
		"duplicate ed25519":    encode(t, File{Format: Format, Signers: []Signer{a, sameEd}}),
		"two primaries":        encode(t, File{Format: Format, Signers: []Signer{a, twoPrimaries}}),
		"duplicate name":       encode(t, File{Format: Format, Signers: []Signer{a, sameName}}),
		"bad role":             encode(t, File{Format: Format, Signers: []Signer{a, badRole}}),
		"bad name":             encode(t, File{Format: Format, Signers: []Signer{a, badName}}),
		"uppercase sha":        encode(t, File{Format: Format, Signers: []Signer{a, upper}}),
		"missing ed25519":      encode(t, File{Format: Format, Signers: []Signer{a, noEd}}),
		"empty":                encode(t, File{Format: Format}),
		"wrong format":         encode(t, File{Format: "rn-signer-pins/v2", Signers: []Signer{a}}),
		"unknown field":        []byte(`{"format":"rn-signer-pins/v1","signers":[],"extra":1}`),
		"trailing":             append(encode(t, File{Format: Format, Signers: []Signer{a}}), '{', '}'),
		"not json":             []byte("amos-signer-a"),
		"too large":            make([]byte, MaxFileSize+1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	short := a
	short.X25519PublicKey = "AAAA"
	if err := short.Validate(); err == nil {
		t.Fatal("accepted a short public key")
	}
}
