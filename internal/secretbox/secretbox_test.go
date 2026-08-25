package secretbox

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncryptDecryptBindsCiphertextToTenant(t *testing.T) {
	key := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	box, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.Encrypt("super-secret", "tenant-a:secret")
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == "super-secret" {
		t.Fatal("secret was stored as plaintext")
	}
	plaintext, err := box.Decrypt(ciphertext, "tenant-a:secret")
	if err != nil || plaintext != "super-secret" {
		t.Fatalf("unexpected decryption result %q: %v", plaintext, err)
	}
	if _, err := box.Decrypt(ciphertext, "tenant-b:secret"); err == nil {
		t.Fatal("ciphertext decrypted for a different tenant")
	}
}

func TestRejectsInvalidMasterKey(t *testing.T) {
	if _, err := New(base64.RawStdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected invalid master key to be rejected")
	}
}
