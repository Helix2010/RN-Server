package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDecodeLanguageSettingsAcceptsSchemaVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("PUT", "/v1/admin/localization/languages", strings.NewReader(`{
		"settings": {
			"schemaVersion": 2,
			"fallbackLanguage": "en-US",
			"refreshIntervalSeconds": 21600,
			"languages": {
				"en-US": {"label":"English","nativeName":"Eng","enabled":true,"direction":"ltr","sort":2}
			}
		},
		"expectedVersion": 2,
		"reason": "增加文案"
	}`))
	var body struct {
		Settings        languageSettingsInput `json:"settings"`
		ExpectedVersion int                   `json:"expectedVersion"`
		Reason          string                `json:"reason"`
	}
	if err := decode(c, &body); err != nil {
		t.Fatalf("language settings request should decode: %v", err)
	}
	if body.Settings.SchemaVersion != 2 || body.ExpectedVersion != 2 || body.Reason != "增加文案" {
		t.Fatalf("decoded request = %+v", body)
	}
}

func TestNormalizeMessageKeyUsesCanonicalLowercase(t *testing.T) {
	if got := normalizeMessageKey("  Action.CheckUpdate  "); got != "action.checkupdate" {
		t.Fatalf("normalizeMessageKey() = %q", got)
	}
	if !messageKeyPattern.MatchString(normalizeMessageKey("Wallet.Connect_2")) {
		t.Fatal("normalized message key should satisfy the storage format")
	}
}
