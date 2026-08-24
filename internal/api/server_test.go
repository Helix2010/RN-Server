package api

import (
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestVerifyPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key, err := scrypt.Key([]byte("correct-horse-battery-staple"), salt, 32768, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("scrypt$32768$8$1$%s$%s", base64.RawURLEncoding.EncodeToString(salt), base64.RawURLEncoding.EncodeToString(key))
	if !verifyPassword("correct-horse-battery-staple", hash) {
		t.Fatal("expected password to verify")
	}
	if verifyPassword("wrong-password", hash) {
		t.Fatal("wrong password verified")
	}
}

func TestVersionComparison(t *testing.T) {
	if !validVersion("1.2.3") || compareVersion("1.0.0", "1.1.0") >= 0 {
		t.Fatal("semantic version behavior is invalid")
	}
}
