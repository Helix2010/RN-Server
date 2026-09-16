package fingerprint

import (
	"strings"
	"testing"
)

func TestSHA256Hex(t *testing.T) {
	// sha256("abc")，FIPS 180-2 附录 B.1
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Fatalf("SHA256Hex(abc) = %s", got)
	}
	if !Valid(SHA256Hex(nil)) {
		t.Fatal("digest of empty input is not a valid fingerprint")
	}
}

func TestValid(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	for _, bad := range []string{
		"",
		good[:63],
		good + "0",
		strings.ToUpper(good),
		good[:62] + "g0",
		good[:62] + " 0",
		good[:16], // 旧代码的 16 字符截短指纹
	} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
	if !Valid(good) {
		t.Fatal("a 64-char lowercase hex string was rejected")
	}
}

func TestNormalize(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	var colon []string
	for i := 0; i < len(good); i += 2 {
		colon = append(colon, strings.ToUpper(good[i:i+2]))
	}
	for _, in := range []string{good, strings.ToUpper(good), strings.Join(colon, ":")} {
		got, ok := Normalize(in)
		if !ok || got != good {
			t.Errorf("Normalize(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", " " + good, good + "\n", good[:62], "zz" + good[2:]} {
		if _, ok := Normalize(bad); ok {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}
