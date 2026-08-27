package api

import "testing"

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Console.AnyFun.Win:443": "console.anyfun.win",
		"api.anyfun.win.":        "api.anyfun.win",
		"localhost:3000":         "localhost",
	}
	for input, expected := range tests {
		actual, err := normalizeHost(input)
		if err != nil {
			t.Fatalf("normalizeHost(%q): %v", input, err)
		}
		if actual != expected {
			t.Errorf("normalizeHost(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestNormalizeHostRejectsInvalidValues(t *testing.T) {
	for _, input := range []string{"", "bad host", "a/b", "a\\b"} {
		if _, err := normalizeHost(input); err == nil {
			t.Errorf("normalizeHost(%q) accepted invalid host", input)
		}
	}
}

func TestSimplifiedObjectKeyScopesTenantAndRelease(t *testing.T) {
	key := releaseArtifactObjectKey("releases", "100000001", "art_abc", "../signed.apk")
	if key != "releases/tenants/100000001/release-uploads/art_abc/application.apk" {
		t.Fatalf("unexpected object key: %s", key)
	}
}
