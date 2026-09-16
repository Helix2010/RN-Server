package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

func TestNormalizeUpdatePolicyUpgradesLegacyFlatStringConfig(t *testing.T) {
	legacy := map[string]any{"minSupportedVersion": "1.2.3", "latestVersion": "1.5.0", "otaChannel": "production"}
	normalized := normalizeUpdatePolicy(legacy)
	min := object(normalized["minSupportedVersion"])
	if min["android"] != "1.2.3" || min["ios"] != "1.2.3" {
		t.Fatalf("legacy flat minSupportedVersion must apply to both platforms, got %v", min)
	}
	latest := object(normalized["latestVersion"])
	if latest["android"] != "1.5.0" || latest["ios"] != "1.5.0" {
		t.Fatalf("legacy flat latestVersion must apply to both platforms, got %v", latest)
	}
}

func TestNormalizeUpdatePolicyPreservesPerPlatformShape(t *testing.T) {
	current := map[string]any{
		"minSupportedVersion": map[string]any{"android": "2.0.0", "ios": "1.0.0"},
		"latestVersion":       map[string]any{"android": "3.0.0", "ios": "2.5.0"},
		"otaChannel":          "production",
	}
	normalized := normalizeUpdatePolicy(current)
	min := object(normalized["minSupportedVersion"])
	if min["android"] != "2.0.0" || min["ios"] != "1.0.0" {
		t.Fatalf("per-platform values must be preserved untouched, got %v", min)
	}
	latest := object(normalized["latestVersion"])
	if latest["android"] != "3.0.0" || latest["ios"] != "2.5.0" {
		t.Fatalf("per-platform values must be preserved untouched, got %v", latest)
	}
}

// updatePolicyPlatformTestTenant 建一个和 canaryRouterTenant 同风格的最小租户，
// 但 updatePolicy 两个平台的最低支持版本故意设成不同值，用来验证按平台分别判定。
func updatePolicyPlatformTestTenant(t *testing.T, minAndroid, minIOS, latestAndroid, latestIOS string) (db *sql.DB, tenantID, domain string) {
	t.Helper()
	sqlDB := openTestDB(t)
	now := time.Now().UTC()
	domain = "update-policy-" + uniqueSuffix() + ".test"
	result, err := sqlDB.Exec(`INSERT INTO tenants(slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,1,?,?,0,?,?)`,
		"update-policy-"+uniqueSuffix(), now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	id, _ := result.LastInsertId()
	if _, err := sqlDB.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at) VALUES(?,?,1,'active',0,?,?)`, id, domain, now, now); err != nil {
		t.Fatalf("insert tenant domain: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &cfg); err != nil {
		t.Fatalf("parse initial config: %v", err)
	}
	cfg["wallet"] = map[string]any{"chains": []string{"bsc"}, "onchainSends": false}
	cfg["modules"] = map[string]any{"predict": false, "dex": true}
	cfg["updatePolicy"] = map[string]any{
		"minSupportedVersion": map[string]any{"android": minAndroid, "ios": minIOS},
		"latestVersion":       map[string]any{"android": latestAndroid, "ios": latestIOS},
		"otaChannel":          "production",
	}
	raw, _ := json.Marshal(cfg)
	if _, err := sqlDB.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,1,'test',?)`, id, raw, now); err != nil {
		t.Fatalf("seed tenant bootstrap config: %v", err)
	}
	return sqlDB, strconv.FormatInt(id, 10), domain
}

// TestBootstrapUpdateDecisionIsScopedPerPlatform 是这次改动要修的核心行为：同一个
// 租户对 Android 和 iOS 声明不同的最低支持版本时，bootstrap 必须按请求的 x-platform
// 分别判定，而不是全租户共用同一个阈值——后者会在 iOS 审核落后于 Android 发布时，
// 把所有 iOS 用户锁在一个走不通的强更弹窗里（RELIABILITY_AND_RELEASE.md §3.2）。
func TestBootstrapUpdateDecisionIsScopedPerPlatform(t *testing.T) {
	sqlDB, _, domain := updatePolicyPlatformTestTenant(t, "2.0.0", "1.0.0", "3.0.0", "3.0.0")
	cfg := config.Config{
		Environment:       "test",
		DeviceIdentityKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		StorageMasterKey:  base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout: 10,
	}
	router := New(cfg, &store.Store{DB: sqlDB})

	call := func(platform string) map[string]any {
		request := httptest.NewRequest(http.MethodGet, "/v1/mobile/bootstrap", nil)
		request.Host = domain
		request.Header.Set("x-platform", platform)
		request.Header.Set("x-application-id", "dex-mobile")
		request.Header.Set("x-app-version", "1.5.0")
		request.Header.Set("x-build-number", "10")
		request.Header.Set("x-distribution-channel", "direct")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("bootstrap failed for platform %s: %d %s", platform, recorder.Code, recorder.Body.String())
		}
		return decodeBody(t, recorder)
	}

	android := object(call("android")["update"])
	if android["decision"] != "required" {
		t.Fatalf("android 1.5.0 is below the android minimum 2.0.0, want required, got %v", android["decision"])
	}
	ios := object(call("ios")["update"])
	if ios["decision"] != "recommended" {
		t.Fatalf("ios 1.5.0 clears the ios minimum 1.0.0 but trails latest 3.0.0, want recommended, got %v", ios["decision"])
	}
}
