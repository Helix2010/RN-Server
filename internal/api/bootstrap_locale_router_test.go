package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// TestDBBootstrapDefaultsToTenantFallbackLanguage：App 的默认语言就是管理端「多语言管理」
// 里设的回退语言。App 不带 locale、或带一种没开启的语言请求 bootstrap，都要拿到它。
// 以前不带 locale 时落到应用配置里旧的 localization.fallbackLocale（种子里是 zh-CN），
// 管理端把回退语言改成 en-US 也不生效。
func TestDBBootstrapDefaultsToTenantFallbackLanguage(t *testing.T) {
	db := openTestDB(t)
	domain := "locale-" + uniqueSuffix() + ".test"
	tenant := canaryRouterTenant(t, db, domain)
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'languages',?,1,'test',?)`,
		tenant, `{"fallbackLanguage":"en-US"}`, time.Now().UTC()); err != nil {
		t.Fatalf("seed tenant language settings: %v", err)
	}
	router := New(config.Config{
		Environment:       "test",
		DeviceIdentityKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		StorageMasterKey:  base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout: 10,
	}, &store.Store{DB: db})

	for _, item := range []struct{ name, target, want string }{
		{"不带 locale：回退语言", "/v1/mobile/bootstrap", "en-US"},
		{"带开启的语言：用它", "/v1/mobile/bootstrap?locale=zh-CN", "zh-CN"},
		{"带没开启的语言：回退语言", "/v1/mobile/bootstrap?locale=ja-JP", "en-US"},
	} {
		t.Run(item.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, item.target, nil)
			request.Host = domain
			request.Header.Set("x-platform", "android")
			request.Header.Set("x-application-id", "dex-mobile")
			request.Header.Set("x-app-version", "1.3.0")
			request.Header.Set("x-build-number", "26")
			request.Header.Set("x-distribution-channel", "direct")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("bootstrap failed: %d %s", recorder.Code, recorder.Body.String())
			}
			localization := object(decodeBody(t, recorder)["localization"])
			if localization["selectedLocale"] != item.want || localization["fallbackLocale"] != "en-US" {
				t.Fatalf("want selected %s with fallback en-US, got %v / %v",
					item.want, localization["selectedLocale"], localization["fallbackLocale"])
			}
		})
	}
}
