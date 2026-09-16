package api

import "testing"

func baseModuleConfig() map[string]any {
	return map[string]any{
		"configVersion": "2026.08.30.1",
		"ttlSeconds":    float64(300),
		"localization":  map[string]any{},
		"theme":         map[string]any{},
		"features":      map[string]any{},
		// updatePolicy 的版本号必须是 semver（非法值会让强制升级静默失效），且 android/ios 都要有值
		"updatePolicy": map[string]any{
			"minSupportedVersion": map[string]any{"android": "1.0.0", "ios": "1.0.0"},
			"latestVersion":       map[string]any{"android": "1.1.0", "ios": "1.1.0"},
		},
		"support": map[string]any{},
	}
}

// 四种模块组合都是正式形态，包括 00（Wallet-only）：那是一个可独立售卖的
// 纯钱包产品，不是异常。这条替换了历史上的"至少开启一个模块"限制。
func TestValidConfigAcceptsEveryModuleCombination(t *testing.T) {
	for _, tc := range []struct{ predict, dex bool }{
		{true, true}, {true, false}, {false, true}, {false, false},
	} {
		base := baseModuleConfig()
		base["modules"] = map[string]any{"predict": tc.predict, "dex": tc.dex}
		if !validConfig(base) {
			t.Fatalf("modules predict=%v dex=%v must be accepted", tc.predict, tc.dex)
		}
	}
	base := baseModuleConfig()
	delete(base, "modules")
	if !validConfig(base) {
		t.Fatal("a config without modules must still validate; the modules section is normalized on read")
	}
}

// normalizeModules 不得把 00 改写成 11：那会把管理员的显式选择悄悄换掉，
// 管理端看到的和 App 拿到的从此不是一回事。
func TestNormalizeModulesKeepsWalletOnly(t *testing.T) {
	got := normalizeModules(map[string]any{"predict": false, "dex": false})
	if truth(got["predict"]) || truth(got["dex"]) {
		t.Fatalf("Wallet-only must survive normalization, got %v", got)
	}
}

func TestNormalizeModulesKeepsEachCombination(t *testing.T) {
	for _, tc := range []struct{ predict, dex bool }{
		{true, true}, {true, false}, {false, true}, {false, false},
	} {
		got := normalizeModules(map[string]any{"predict": tc.predict, "dex": tc.dex})
		if truth(got["predict"]) != tc.predict || truth(got["dex"]) != tc.dex {
			t.Fatalf("predict=%v dex=%v was rewritten to %v", tc.predict, tc.dex, got)
		}
	}
}

// 整段缺失时才用平台默认值——这是文档化、管理端可见的声明式默认。
func TestNormalizeModulesFillsMissingSectionWithPlatformDefault(t *testing.T) {
	got := normalizeModules(nil)
	if !truth(got["predict"]) || !truth(got["dex"]) {
		t.Fatalf("a missing modules section must fall back to the platform default, got %v", got)
	}
}
