package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

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

// 品牌图片的上传票据必须始终指向服务端自己，即使 ARTIFACT_UPLOAD_MODE=direct。
//
// 给浏览器签一个直传对象存储的地址，要求**桶上**配了允许控制台来源的跨域规则，而那
// 是对象存储控制台上的设置，不在我们任何配置文件里。没配的表现是界面上一句"无法连接
// 对象存储"，而服务端这边一条日志都没有——预检是浏览器和桶之间的事，我们不在链路上。
// 2026-09-12 线上实测：票据 201、curl 直接 PUT 200、浏览器预检 403 CORSResponse。
func TestDBBrandingUploadTicketAlwaysPointsAtTheServer(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(71)
	s := purgeServer(t, db, tenant, newFakeObjectStore())
	box, err := secretbox.New(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.secrets = box
	// direct 是生产上的取值：就算是它，品牌图片也不能走直传
	s.cfg = config.Config{Environment: "test", ArtifactUploadMode: "direct", ArtifactUploadTTL: 900}

	c, recorder := testContext(t, tenant, "POST", "/v1/admin/branding/assets/uploads", map[string]any{
		"fileName": "logo.png", "contentType": "image/png", "size": 1024,
		"assetType": "launch_logo", "theme": "light",
	})
	s.createBrandingAssetUpload(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("签发票据失败：%d %s", recorder.Code, recorder.Body.String())
	}
	upload := decodeBody(t, recorder)["upload"].(map[string]any)
	url, _ := upload["url"].(string)
	if !strings.Contains(url, "/v1/admin/branding/assets/upload") {
		t.Fatalf("票据指向了服务端之外的地址（直传要桶上配跨域规则，我们配不了）：%s", url)
	}
	if upload["requiresCredentials"] != true {
		t.Fatalf("经服务端中转必须带凭据：%v", upload["requiresCredentials"])
	}
	headers := upload["headers"].(map[string]any)
	if _, ok := headers["x-branding-asset-token"]; !ok {
		t.Fatalf("中转上传要带票据头，否则落盘那一侧认不出是谁：%v", headers)
	}
}

// 落盘那一侧同样不能按 ARTIFACT_UPLOAD_MODE 拒：签票据已经一律指向这里，这里再按
// mode 返回 404 就是自己把自己挡掉——表现和"跨域没配"一模一样，都是传不上去。
func TestDBBrandingUploadEndpointAcceptsInDirectMode(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(72)
	s := purgeServer(t, db, tenant, newFakeObjectStore())
	s.cfg = config.Config{Environment: "test", ArtifactUploadMode: "direct", ArtifactUploadTTL: 900}

	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/branding/assets/upload", nil)
	s.uploadBrandingAsset(c)
	// 没带票据应当是 401，而不是 404「服务端上传已禁用」
	if recorder.Code == http.StatusNotFound {
		t.Fatalf("direct 模式下落盘接口被自己 404 掉了：%s", recorder.Body.String())
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("没带票据应当是 401，实际 %d %s", recorder.Code, recorder.Body.String())
	}
}
