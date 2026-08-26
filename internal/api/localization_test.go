package api

import "testing"

func TestMergeLanguagesUsesFieldLevelTenantOverrides(t *testing.T) {
	global := defaultStoredLanguagesConfig()
	label := "日本語"
	enabled := true
	global.Languages["ja-JP"] = languageOverride{Label: &label, NativeName: &label, Enabled: &enabled, Direction: strPtr("ltr"), Sort: intPtr(3)}
	tenant := storedLanguagesConfig{FallbackLanguage: "en-US", Languages: map[string]languageOverride{"zh-CN": {Enabled: boolPtr(false)}}}
	result, err := mergeLanguages(global, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if result.Languages["zh-CN"].Enabled {
		t.Fatal("tenant disabled language should override global")
	}
	if _, ok := result.Languages["ja-JP"]; !ok {
		t.Fatal("global language should remain visible to tenant")
	}
	if result.FallbackLanguage != "en-US" {
		t.Fatalf("fallback = %q", result.FallbackLanguage)
	}
}

func TestMergeLanguagesRejectsUnderscoreCodes(t *testing.T) {
	global := defaultStoredLanguagesConfig()
	value := "错误"
	global.Languages["zh_CN"] = languageOverride{Label: &value, NativeName: &value, Enabled: boolPtr(true), Direction: strPtr("ltr"), Sort: intPtr(1)}
	if _, err := mergeLanguages(global, storedLanguagesConfig{}); err == nil {
		t.Fatal("underscore language code must be rejected")
	}
}

func strPtr(value string) *string { return &value }
func intPtr(value int) *int       { return &value }
func boolPtr(value bool) *bool    { return &value }
