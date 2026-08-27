package api

import "testing"

func TestLanguageResourceObjectKeyAvoidsDuplicatingPathIdentity(t *testing.T) {
	got := languageResourceObjectKey("tenant-prefix", "100000001", "en-US", "260827012848")
	want := "tenant-prefix/localization/100000001/en-US/260827012848.json"
	if got != want {
		t.Fatalf("languageResourceObjectKey() = %q, want %q", got, want)
	}
}

func TestLanguageResourceObjectKeyNormalizesPrefixSeparators(t *testing.T) {
	got := languageResourceObjectKey("/", "100000001", "zh-CN", "260827012848")
	if got != "localization/100000001/zh-CN/260827012848.json" {
		t.Fatalf("languageResourceObjectKey() = %q", got)
	}
}
