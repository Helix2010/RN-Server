package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// 更新包不能改变应用身份。App 应用 OTA 之后读的是**更新包 manifest 里的** expoConfig，
// 所以 manifest 里的 apiBaseUrl 决定设备此后把请求发给谁，bootstrapSignerAddress 决定
// 它信谁的签名。改掉这两个字段等于把全部设备迁到另一台服务器并换掉信任锚，而设备上
// 没有任何可见迹象。在加这道闸之前，manifest 只被要求 scopeKey 非空。
func TestDBOTAIdentityRejectsAPackageThatRedirectsTheApp(t *testing.T) {
	db := openTestDB(t)
	s := otaTestServer(t, db)
	tenant := testTenant(20)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)

	identity, err := func() (tenantManifest, error) {
		buildCfg, _, err := s.buildConfigFor(context.Background(), tenant, slug)
		if err != nil {
			return tenantManifest{}, err
		}
		return s.tenantManifestFor(context.Background(), tenant, buildCfg, "1.0.0", 1)
	}()
	if err != nil {
		t.Fatal(err)
	}
	good := func() map[string]any {
		raw, _ := json.Marshal(map[string]any{
			"extra": map[string]any{
				"scopeKey":   identity.APIBaseURL,
				"apiBaseUrl": identity.APIBaseURL,
				"expoClient": map[string]any{
					"extra": map[string]any{
						"apiBaseUrl":             identity.APIBaseURL,
						"bootstrapSignerAddress": identity.BootstrapSignerAddress,
					},
				},
			},
		})
		var manifest map[string]any
		_ = json.Unmarshal(raw, &manifest)
		return manifest
	}

	if err := s.otaIdentityMismatch(context.Background(), tenant, good(), "1.0.0", 1); err != nil {
		t.Fatalf("本租户自己的包被拒了：%v", err)
	}

	// 把 API 地址换成别人的：这是"一个热更新包把所有设备迁走"的那种攻击
	redirected := good()
	redirected["extra"].(map[string]any)["apiBaseUrl"] = "https://evil.example"
	redirected["extra"].(map[string]any)["expoClient"].(map[string]any)["extra"].(map[string]any)["apiBaseUrl"] = "https://evil.example"
	if err := s.otaIdentityMismatch(context.Background(), tenant, redirected, "1.0.0", 1); err == nil ||
		!strings.Contains(err.Error(), "apiBaseUrl") {
		t.Fatalf("改了 API 地址的包没被拒：%v", err)
	}

	// 换掉信任锚：设备此后会信攻击者签的配置
	swapped := good()
	swapped["extra"].(map[string]any)["expoClient"].(map[string]any)["extra"].(map[string]any)["bootstrapSignerAddress"] =
		"0x0000000000000000000000000000000000000001"
	if err := s.otaIdentityMismatch(context.Background(), tenant, swapped, "1.0.0", 1); err == nil ||
		!strings.Contains(err.Error(), "bootstrapSignerAddress") {
		t.Fatalf("换了 bootstrap 签名地址的包没被拒：%v", err)
	}

	// scopeKey 决定 expo-updates 的存储作用域，同样不能换
	rescoped := good()
	rescoped["extra"].(map[string]any)["scopeKey"] = "https://evil.example"
	if err := s.otaIdentityMismatch(context.Background(), tenant, rescoped, "1.0.0", 1); err == nil ||
		!strings.Contains(err.Error(), "scopeKey") {
		t.Fatalf("换了 scopeKey 的包没被拒：%v", err)
	}
}

// 动了原生就不能走热更新：设备拉到之后会去调一个 APK 里不存在的原生模块，
// 表现是所有装了那一版的设备启动即崩。
func TestOTAFingerprintGate(t *testing.T) {
	manifestWith := func(fingerprint string) map[string]any {
		return map[string]any{"extra": map[string]any{"nativeFingerprint": fingerprint}}
	}
	base := []byte(`{"nativeFingerprint":"1cbc9dab04fc06bde46caf263a5685d7bf2a97b5"}`)

	if err := otaFingerprintMismatch(manifestWith("1cbc9dab04fc06bde46caf263a5685d7bf2a97b5"), base); err != nil {
		t.Fatalf("同一个指纹被拒了：%v", err)
	}
	if err := otaFingerprintMismatch(manifestWith("0000000000000000000000000000000000000000"), base); err == nil ||
		!strings.Contains(err.Error(), "原生") {
		t.Fatalf("原生变了没被拒：%v", err)
	}
	// 更新包没带指纹：说明它是用旧脚本构建的，判断不了，不放行
	if err := otaFingerprintMismatch(manifestWith(""), base); err == nil {
		t.Fatal("没带指纹的包被放行了")
	}
	// 基线没有记录指纹：在这个功能上线之前构建的包，同样判断不了
	err := otaFingerprintMismatch(manifestWith("1cbc9dab04fc06bde46caf263a5685d7bf2a97b5"), []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "先出一个新的安装包") {
		t.Fatalf("没有基线指纹时应该说清楚怎么办：%v", err)
	}
}

// 资源地址必须来自租户自己的 apiBaseUrl，不能来自请求的 Host。
//
// 打包机所有请求都发到它配置的那一个域名，于是它帮 B 租户建的修订会被写进 A 租户的
// 地址：设备一个资源都拉不到（AssetsFailedToLoad），而 extra.apiBaseUrl 也被一起改掉
// ——正是身份闸要防的那件事，只不过是服务端自己干的。
func TestDBOTAAssetURLsComeFromTheTenantNotTheHost(t *testing.T) {
	db := openTestDB(t)
	s := otaTestServer(t, db)
	tenant := testTenant(21)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)

	identity, err := s.tenantIdentityFor(context.Background(), tenant, "1.0.0", 1)
	if err != nil {
		t.Fatal(err)
	}
	if identity.APIBaseURL == "" {
		t.Fatal("合成身份里没有 apiBaseUrl")
	}
	manifest := map[string]any{
		"assets":      []any{map[string]any{"path": "assets/x.png"}},
		"launchAsset": map[string]any{"path": "bundle.hbc"},
		"extra":       map[string]any{},
	}
	base := strings.TrimRight(identity.APIBaseURL, "/")
	rewritten := rewriteManifestURLs(manifest, base+"/v1/ota/assets/ota_x/")
	raw, _ := json.Marshal(rewritten)
	if !strings.Contains(string(raw), base+"/v1/ota/assets/ota_x/") {
		t.Fatalf("资源地址没有指向租户自己的域名：%s", raw)
	}
}
