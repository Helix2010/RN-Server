package store

import "testing"

func TestRNAppLocalizationSeedHasMatchingCompleteLocales(t *testing.T) {
	zh, err := readRNAppLocaleSeed("zh-CN")
	if err != nil {
		t.Fatal(err)
	}
	en, err := readRNAppLocaleSeed("en-US")
	if err != nil {
		t.Fatal(err)
	}
	if len(zh.Messages) != len(en.Messages) {
		t.Fatalf("locale key counts differ: zh=%d en=%d", len(zh.Messages), len(en.Messages))
	}
	if len(zh.Messages) < 700 {
		t.Fatalf("RN-App seed unexpectedly incomplete: %d keys", len(zh.Messages))
	}
	for key := range zh.Messages {
		if _, ok := en.Messages[key]; !ok {
			t.Fatalf("English seed is missing %s", key)
		}
	}
	for _, key := range []string{
		"wallet.import.submit",
		"common.processing",
		"send.error.unsafe",
		"update.versionInfo",
	} {
		if zh.Messages[key] == "" || en.Messages[key] == "" {
			t.Fatalf("required current UI key is missing: %s", key)
		}
	}
}
