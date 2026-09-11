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

// 通用链接声明只覆盖一条路径。整域声明会让任意一个 API 地址都试图拉起 App，
// 这条断言就是防止有人"顺手"把它改成 `*`。
func TestAppleAppSiteAssociationOnlyClaimsTheWalletConnectPath(t *testing.T) {
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
	if len(detail.Paths) != 1 || detail.Paths[0] != appLinkPath {
		t.Fatalf("legacy paths must list only %s: %s", appLinkPath, raw)
	}
	if len(detail.Components) != 1 || detail.Components[0].Path != appLinkPath {
		t.Fatalf("components must list only %s: %s", appLinkPath, raw)
	}
	if appLinkPath == "/" || strings.Contains(appLinkPath, "*") {
		t.Fatalf("the app link path must stay a narrow path, got %q", appLinkPath)
	}
}
