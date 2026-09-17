package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

func TestParseIOSReleaseIdentityNormalizesAndValidates(t *testing.T) {
	value, err := parseIOSReleaseIdentity([]byte(`{"appleTeamId":" ab12cd34ef ","bundleId":" com.anyfun.foundation "}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Team ID 大小写不敏感地入库成大写，两头空白去掉
	if value.AppleTeamID != "AB12CD34EF" || value.BundleID != "com.anyfun.foundation" {
		t.Fatalf("unexpected normalisation: %#v", value)
	}
	for name, raw := range map[string]string{
		"团队号太短":         `{"appleTeamId":"AB12","bundleId":"com.anyfun.foundation"}`,
		"团队号带符号":        `{"appleTeamId":"AB12CD34E-","bundleId":"com.anyfun.foundation"}`,
		"bundle 不是反向域名": `{"appleTeamId":"AB12CD34EF","bundleId":"foundation"}`,
		"bundle 带下划线":   `{"appleTeamId":"AB12CD34EF","bundleId":"com.any_fun.foundation"}`,
		"不是 JSON":       `{`,
	} {
		if _, err := parseIOSReleaseIdentity([]byte(raw)); err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}

func TestUpdateIOSReleaseIdentityRejectsInvalidBodiesBeforeTouchingTheDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// db 为 nil：任何走到数据库的路径都会 panic，所以这些用例同时证明校验先于存储
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, body := range map[string]string{
		"not confirmed":    `{"appleTeamId":"AB12CD34EF","bundleId":"com.anyfun.foundation","expectedVersion":0,"reason":"pin ios","confirm":false}`,
		"short reason":     `{"appleTeamId":"AB12CD34EF","bundleId":"com.anyfun.foundation","expectedVersion":0,"reason":"x","confirm":true}`,
		"bad team id":      `{"appleTeamId":"AB12","bundleId":"com.anyfun.foundation","expectedVersion":0,"reason":"pin ios","confirm":true}`,
		"bad bundle id":    `{"appleTeamId":"AB12CD34EF","bundleId":"foundation","expectedVersion":0,"reason":"pin ios","confirm":true}`,
		"negative version": `{"appleTeamId":"AB12CD34EF","bundleId":"com.anyfun.foundation","expectedVersion":-1,"reason":"pin ios","confirm":true}`,
		"not json":         `{`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("PUT", "/v1/admin/release-identity/ios", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		s.updateIOSReleaseIdentity(c)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_RELEASE_IDENTITY") {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

// 通用链接声明只覆盖两条窄路径。整域声明会让任意一个 API 地址都试图拉起 App，
// 这条断言就是防止有人"顺手"把它改成 `*`。
func TestAppleAppSiteAssociationClaimsOnlyTheTwoDeepLinkPaths(t *testing.T) {
	raw, err := json.Marshal(appleAppSiteAssociation(iosReleaseIdentity{AppleTeamID: "AB12CD34EF", BundleID: "com.anyfun.foundation"}))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Applinks struct {
			Apps    []string `json:"apps"`
			Details []struct {
				AppID      string   `json:"appID"`
				Paths      []string `json:"paths"`
				AppIDs     []string `json:"appIDs"`
				Components []struct {
					Path string `json:"/"`
				} `json:"components"`
			} `json:"details"`
		} `json:"applinks"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode aasa: %v (%s)", err, raw)
	}
	if len(document.Applinks.Details) != 1 {
		t.Fatalf("expected exactly one detail entry: %s", raw)
	}
	detail := document.Applinks.Details[0]
	// 新老两种形状都要在：iOS 13 起读 appIDs/components，更早的系统读 appID/paths
	if detail.AppID != "AB12CD34EF.com.anyfun.foundation" || len(detail.AppIDs) != 1 || detail.AppIDs[0] != detail.AppID {
		t.Fatalf("unexpected app id: %s", raw)
	}
	// 两条都要在，而且两种形状里要一致：只声明钱包回跳时，同一个邀请链接在 Android 上
	// 唤起 App、在 iOS 上打开网页，而这看起来像"iOS 深链没做"，不像漏了一行配置
	want := []string{appLinkPath, appleInviteLinkPattern}
	if len(detail.Paths) != len(want) {
		t.Fatalf("legacy paths must list exactly %v: %s", want, raw)
	}
	for i, path := range want {
		if detail.Paths[i] != path {
			t.Fatalf("legacy paths[%d] = %q, want %q: %s", i, detail.Paths[i], path, raw)
		}
		if detail.Components[i].Path != path {
			t.Fatalf("components[%d] = %q, want %q: %s", i, detail.Components[i].Path, path, raw)
		}
	}
	if len(detail.Components) != len(want) {
		t.Fatalf("components must list exactly %v: %s", want, raw)
	}
	// 通配只允许出现在邀请码那一段的末尾。`/app/*` 或 `*` 都会把整个站点交出去
	if appLinkPath == "/" || strings.Contains(appLinkPath, "*") {
		t.Fatalf("the wallet return path must stay a narrow path, got %q", appLinkPath)
	}
	if !strings.HasPrefix(appleInviteLinkPattern, "/app/invite/") || strings.Count(appleInviteLinkPattern, "*") != 1 ||
		!strings.HasSuffix(appleInviteLinkPattern, "*") {
		t.Fatalf("the invite pattern must stay /app/invite/<code>, got %q", appleInviteLinkPattern)
	}
}

// installUrl 是会被下发进 App、并被落地页直接跳转的一个字符串。允许任意 host 等于
// 给了一个"改一个字段就把全体 iOS 用户导去任意站点"的开关。
func TestIOSInstallURLOnlyAcceptsApplesOwnEntryPoints(t *testing.T) {
	for name, url := range map[string]string{
		"空值就是没配":          "",
		"TestFlight 公开链接": "https://testflight.apple.com/join/ABCD1234",
		"App Store 页面":    "https://apps.apple.com/cn/app/id6811004741",
	} {
		if err := validateIOSInstallURL(url); err != nil {
			t.Fatalf("%s: unexpected rejection: %v", name, err)
		}
	}
	for name, url := range map[string]string{
		"http 明文":    "http://testflight.apple.com/join/ABCD1234",
		"第三方域名":      "https://testflight.apple.com.evil.example/join/ABCD1234",
		"没有路径":       "https://testflight.apple.com",
		"只有斜杠":       "https://testflight.apple.com/",
		"自定义 scheme": "itms-beta://testflight.apple.com/join/ABCD1234",
		"太长":         "https://testflight.apple.com/join/" + strings.Repeat("A", 260),
	} {
		if err := validateIOSInstallURL(url); err == nil {
			t.Fatalf("%s: expected a rejection for %q", name, url)
		}
	}
}

// 没有链接就不该留下一个孤零零的来源标记，否则界面会显示"同步来的（空）"
func TestNormalizeIOSReleaseIdentityClearsSourceWithoutAnInstallURL(t *testing.T) {
	value := normalizeIOSReleaseIdentity(iosReleaseIdentity{
		AppleTeamID: "AB12CD34EF", BundleID: "com.anyfun.foundation",
		InstallURL: "  ", InstallURLSource: iosInstallURLSourceSynced,
	})
	if value.InstallURLSource != "" {
		t.Fatalf("expected the source to be cleared, got %q", value.InstallURLSource)
	}
	// 反过来：有链接但没说来源，按人填的算——同步那条路径自己会写 synced
	value = normalizeIOSReleaseIdentity(iosReleaseIdentity{
		AppleTeamID: "AB12CD34EF", BundleID: "com.anyfun.foundation",
		InstallURL: "https://testflight.apple.com/join/ABCD1234",
	})
	if value.InstallURLSource != iosInstallURLSourceManual {
		t.Fatalf("expected manual, got %q", value.InstallURLSource)
	}
	// 过期时刻统一成 UTC 的 RFC3339，免得库里同时存着两种写法
	value = normalizeIOSReleaseIdentity(iosReleaseIdentity{
		AppleTeamID: "AB12CD34EF", BundleID: "com.anyfun.foundation",
		BuildExpiresAt: "2026-12-16T16:00:00+08:00",
	})
	if value.BuildExpiresAt != "2026-12-16T08:00:00Z" {
		t.Fatalf("expected a UTC timestamp, got %q", value.BuildExpiresAt)
	}
}

// 历史记录里没有这三个新字段，读出来必须仍然合法——加字段不该让已经配好的租户
// 在下一次读 AASA 时变成 500
func TestParseIOSReleaseIdentityAcceptsRecordsWrittenBeforeTheInstallURL(t *testing.T) {
	value, err := parseIOSReleaseIdentity([]byte(`{"appleTeamId":"AB12CD34EF","bundleId":"com.anyfun.foundation"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value.InstallURL != "" || value.InstallURLSource != "" || value.BuildExpiresAt != "" {
		t.Fatalf("unexpected defaults: %#v", value)
	}
}
