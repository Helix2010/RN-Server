package machinekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestRotationMessageLayout(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	got := string(RotationMessage("mch_x", a, b))
	if got != "rn-machine-key-rotation/v1\nmch_x\n"+a+"\n"+b {
		t.Fatalf("layout: %q", got)
	}
	if string(RotationMessage("mch_x", a, "")) != "rn-machine-key-rotation/v1\nmch_x\n"+a+"\n" {
		t.Fatal("builder layout (empty ed25519 sha) is wrong")
	}
}

func TestSignVerifyRotation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	newKey, newEd := strings.Repeat("1", 64), strings.Repeat("2", 64)
	sig, err := SignRotation(priv, "mch_abcd1234", newKey, newEd)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyRotation(pub, "mch_abcd1234", newKey, newEd, sig) {
		t.Fatal("valid rotation rejected")
	}
	for name, ok := range map[string]bool{
		"other key":     VerifyRotation(otherPub, "mch_abcd1234", newKey, newEd, sig),
		"other machine": VerifyRotation(pub, "mch_abcd1235", newKey, newEd, sig),
		"other new key": VerifyRotation(pub, "mch_abcd1234", strings.Repeat("3", 64), newEd, sig),
		"dropped ed":    VerifyRotation(pub, "mch_abcd1234", newKey, "", sig),
		"short sig":     VerifyRotation(pub, "mch_abcd1234", newKey, newEd, sig[:10]),
		"short pub":     VerifyRotation(pub[:5], "mch_abcd1234", newKey, newEd, sig),
		"newline id":    VerifyRotation(pub, "mch\nx", newKey, newEd, sig),
	} {
		if ok {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := SignRotation(priv, "mch_abcd1234", "ABC", ""); err == nil {
		t.Fatal("signed a malformed fingerprint")
	}
	if _, err := SignRotation(priv[:10], "mch_abcd1234", newKey, ""); err == nil {
		t.Fatal("accepted a short private key")
	}
}
