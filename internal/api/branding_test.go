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

func TestHasTenantObjectPrefixNormalizesLeadingSlash(t *testing.T) {
	if !hasTenantObjectPrefix("/tenants/100000001/branding/logo.png", "100000001") {
		t.Fatal("expected a normalized tenant object key to match")
	}
	if hasTenantObjectPrefix("tenants/100000002/branding/logo.png", "100000001") {
		t.Fatal("expected a different tenant object key to be rejected")
	}
}

func TestResolveBrandingInheritsImagesAcrossThemes(t *testing.T) {
	logo := map[string]any{"assetId": "tenant-logo", "fileUrl": "/v1/mobile/branding/assets/tenant-logo"}
	config := cloneMap(defaultBrandingConfig)
	launch := config["launch"].(map[string]any)
	visuals := launch["defaultVisual"].(map[string]any)
	visuals["light"].(map[string]any)["logo"] = logo

	resolved := resolveBranding(config, "zh-CN", "zh-CN", map[string]string{
		"launch.title":    "AnyFun",
		"launch.subtitle": "正在同步",
	})
	resolvedVisuals := resolved["launch"].(map[string]any)["visuals"].(map[string]any)
	dark := resolvedVisuals["dark"].(map[string]any)

	if darkLogo := dark["logo"].(map[string]any); darkLogo["assetId"] != "tenant-logo" {
		t.Fatalf("dark theme did not inherit tenant logo: %#v", resolvedVisuals)
	}
	if dark["backgroundColor"] != "#0B1220" {
		t.Fatalf("dark theme background color must be preserved: %#v", dark)
	}
}
