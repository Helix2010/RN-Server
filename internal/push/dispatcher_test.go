package push

import "testing"

func TestDecodeSecretSupportsBase64AndEscapedPem(t *testing.T) {
	if got := string(decodeSecret("aGVsbG8=")); got != "hello" {
		t.Fatalf("base64 decode = %q", got)
	}
	if got := string(decodeSecret(`line1\nline2`)); got != "line1\nline2" {
		t.Fatalf("escaped pem decode = %q", got)
	}
}
