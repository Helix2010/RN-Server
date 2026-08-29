package api

import "testing"

func TestMergeBrandingUsesTenantFieldOverrides(t *testing.T) {
	global := map[string]any{
		"launch": map[string]any{
			"enabled":       true,
			"defaultVisual": map[string]any{"light": map[string]any{"backgroundColor": "#fff"}},
		},
		"cachePolicy": map[string]any{"keepVersions": 2},
	}
	tenant := map[string]any{
		"launch": map[string]any{"defaultVisual": map[string]any{"light": map[string]any{"backgroundColor": "#000"}}},
	}
	merged := mergeBranding(global, tenant)
	launch := merged["launch"].(map[string]any)
	visual := launch["defaultVisual"].(map[string]any)["light"].(map[string]any)
	if visual["backgroundColor"] != "#000" || launch["enabled"] != true {
		t.Fatalf("unexpected merged branding: %#v", merged)
	}
}

func TestValidateBrandingConfigRequiresSchemaAndMessageKeys(t *testing.T) {
	config := map[string]any{"schemaVersion": float64(1), "launch": map[string]any{"messages": map[string]any{"titleKey": "launch.title", "subtitleKey": "launch.subtitle"}}}
	if err := validateBrandingConfig(config); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
	delete(config["launch"].(map[string]any)["messages"].(map[string]any), "titleKey")
	if err := validateBrandingConfig(config); err == nil {
		t.Fatal("expected missing title key to be rejected")
	}
}
