package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/ascapi"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

// 校验必须发生在碰数据库之前：db 为 nil，任何走到库的路径都会 panic。
func TestUpdateIOSASCCredentialsRejectsInvalidBodiesBeforeTouchingTheDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, body := range map[string]string{
		"没确认":        `{"issuerId":"iss","keyId":"KEY1234567","privateKey":"x","expectedVersion":0,"reason":"install key","confirm":false}`,
		"原因太短":       `{"issuerId":"iss","keyId":"KEY1234567","privateKey":"x","expectedVersion":0,"reason":"x","confirm":true}`,
		"缺 issuerId": `{"issuerId":" ","keyId":"KEY1234567","privateKey":"x","expectedVersion":0,"reason":"install key","confirm":true}`,
		"缺 keyId":    `{"issuerId":"iss","keyId":"","privateKey":"x","expectedVersion":0,"reason":"install key","confirm":true}`,
		"版本号为负":      `{"issuerId":"iss","keyId":"KEY1234567","privateKey":"x","expectedVersion":-1,"reason":"install key","confirm":true}`,
		"私钥为空":       `{"issuerId":"iss","keyId":"KEY1234567","privateKey":"","expectedVersion":0,"reason":"install key","confirm":true}`,
		"不是 JSON":    `{`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("PUT", "/v1/admin/ios/asc-credentials", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		s.updateIOSASCCredentials(c)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "INVALID_IOS_ASC") {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
	// 形状不对的私钥要在联网之前就拒掉，并且 422 而不是 400——请求本身是合法的
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("PUT", "/v1/admin/ios/asc-credentials",
		strings.NewReader(`{"issuerId":"iss","keyId":"KEY1234567","privateKey":"not-a-pem","expectedVersion":0,"reason":"install key","confirm":true}`))
	c.Request.Header.Set("Content-Type", "application/json")
	s.updateIOSASCCredentials(c)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a malformed key must be refused locally: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 私钥不经任何接口返回。这条断言的价值在于它会挡住"顺手把整条记录塞进视图"。
func TestIOSASCViewNeverCarriesTheKey(t *testing.T) {
	verified := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	view := iosASCView(&iosASCRecord{
		Value: iosASC{IssuerID: "iss", KeyID: "KEY1234567", AppID: "6811004741",
			PrivateKeyEncrypted: "c2VjcmV0", VerifiedAt: &verified},
		Version: 3, UpdatedBy: "admin", UpdatedAt: verified,
	})
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"privateKey", "c2VjcmV0", "PRIVATE KEY"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("%q leaked into the view: %s", forbidden, raw)
		}
	}
	for _, expected := range []string{"KEY1234567", "6811004741", "\"configured\":true"} {
		if !strings.Contains(string(raw), expected) {
			t.Fatalf("the view should still answer \"which key is in use\": %s", raw)
		}
	}
	// 没装 Key 不是错误，是模式 B
	empty, _ := json.Marshal(iosASCView(nil))
	if !strings.Contains(string(empty), "\"configured\":false") {
		t.Fatalf("unexpected empty view: %s", empty)
	}
}

func TestObservedTestFlightPicksTheExternalPublicLinkAndTheLiveBuild(t *testing.T) {
	expires := time.Date(2026, 12, 16, 8, 0, 0, 0, time.UTC)
	older := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	observed := observedTestFlight(
		[]ascapi.Build{
			// 最新的那个已经过期：90 天时钟要的是"现在还能装的那一个"
			{Version: "10", Expired: true, ExpirationDate: &older},
			{Version: "9", Expired: false, ExpirationDate: &expires},
		},
		[]ascapi.BetaGroup{
			// 内部组没有公开链接；开着链接的外部组才算
			{Name: "Internal", IsInternal: true, PublicLinkEnabled: true, PublicLink: "https://testflight.apple.com/join/INTERNAL"},
			{Name: "External-closed", IsInternal: false, PublicLinkEnabled: false, PublicLink: "https://testflight.apple.com/join/CLOSED"},
			{Name: "External", IsInternal: false, PublicLinkEnabled: true, PublicLink: "https://testflight.apple.com/join/ABCD1234"},
		},
	)
	if observed.PublicLink != "https://testflight.apple.com/join/ABCD1234" {
		t.Fatalf("unexpected public link: %q", observed.PublicLink)
	}
	if observed.BuildExpiresAt != "2026-12-16T08:00:00Z" {
		t.Fatalf("unexpected expiry: %q", observed.BuildExpiresAt)
	}
	// 什么都没有时不要编：字段留空，界面显示"未知"比显示一个猜出来的日期好
	if empty := observedTestFlight(nil, nil); empty.PublicLink != "" || empty.BuildExpiresAt != "" {
		t.Fatalf("nothing observed must stay empty: %#v", empty)
	}
	// 全部 build 都过期了也不写过期日：写一个过去的时间会让"还剩几天"变成负数
	allExpired := observedTestFlight([]ascapi.Build{{Version: "10", Expired: true, ExpirationDate: &older}}, nil)
	if allExpired.BuildExpiresAt != "" {
		t.Fatalf("an expired build must not become the clock: %q", allExpired.BuildExpiresAt)
	}
}
