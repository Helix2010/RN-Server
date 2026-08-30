package api

import "testing"

func TestValidConfigRequiresAtLeastOneBusinessModule(t *testing.T) {
	base := map[string]any{
		"configVersion": "2026.08.30.1",
		"ttlSeconds":    float64(300),
		"localization":  map[string]any{},
		"theme":         map[string]any{},
		"features":      map[string]any{},
		"updatePolicy":  map[string]any{},
		"support":       map[string]any{},
	}
	base["modules"] = map[string]any{"predict": false, "dex": false}
	if validConfig(base) {
		t.Fatal("config with both business modules disabled must be rejected")
	}
	base["modules"] = map[string]any{"predict": true, "dex": false}
	if !validConfig(base) {
		t.Fatal("config with Predict enabled must be accepted")
	}
	delete(base, "modules")
	if !validConfig(base) {
		t.Fatal("legacy config without modules must inherit safe defaults")
	}
}
