package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 平台控制台上按租户的平台级设置（platform_tenant_settings.go，设计 service-and-console-split-2026-09-27 §4.2、§7）：
// 在平台控制台（不属于任何租户）上看全部租户、改某个租户的打包目录与预测平台关联；租户会话进不来。
func TestDBPlatformTenantSettings(t *testing.T) {
	db := openTestDB(t)
	tenantA := accountsTestTenantRow(t, db, "ptsa")
	tenantB := accountsTestTenantRow(t, db, "ptsb")
	var slugA string
	if err := db.QueryRow(`SELECT slug FROM tenants WHERE id=?`, tenantA.id).Scan(&slugA); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, tenant := range []string{tenantA.id, tenantB.id} {
			_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key IN (?,'mobile-bootstrap')`, tenant, buildConfigKey)
		}
	})
	platformHost := "platform-" + uniqueSuffix() + ".test"
	router := New(config.Config{
		Environment:         "test",
		StorageMasterKey:    base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:   10,
		AdminSessionTTL:     3600,
		PlatformConsoleHost: platformHost,
	}, &store.Store{DB: db})
	platformToken, _, _ := activePlatformSession(t, db)
	admin := &browser{router: router, tenant: tenantA, cookies: map[string]string{adminSessionCookie: platformToken}, host: platformHost}
	member := &browser{router: router, tenant: tenantA, cookies: map[string]string{adminSessionCookie: activeTenantSession(t, db, tenantA)}}
	itemFor := func(body map[string]any, tenant string) map[string]any {
		t.Helper()
		for _, raw := range body["items"].([]any) {
			if item := raw.(map[string]any); item["tenantId"] == tenant || item["id"] == tenant {
				return item
			}
		}
		t.Fatalf("tenant %s is missing from %v", tenant, body)
		return nil
	}

	t.Run("租户列表与跨租户的成员列表", func(t *testing.T) {
		tenants := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/tenants", nil, nil), 200)
		a := itemFor(tenants, tenantA.id)
		if a["slug"] != slugA || a["status"] != "active" || !strings.Contains(strings.Join(toStrings(a["domains"]), ","), tenantA.console) {
			t.Fatalf("tenant A = %v", a)
		}
		externalAccount(t, db, tenantB.id, testSubject(), "pts-b@chainup.test")
		accounts := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/tenant-accounts", nil, nil), 200)
		found := false
		for _, raw := range accounts["items"].([]any) {
			if item := raw.(map[string]any); item["email"] == "pts-b@chainup.test" {
				found = item["tenantId"] == tenantB.id
			}
		}
		if !found {
			t.Fatalf("tenant B's member is missing or not tagged with its tenant: %v", accounts)
		}
		// 租户会话进不来
		wantProblem(t, member.do("GET", "/v1/admin/platform/tenant-accounts", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})

	t.Run("租户打包目录：只在平台控制台改，租户页原样带回", func(t *testing.T) {
		list := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/build-directories", nil, nil), 200)
		if a := itemFor(list, tenantA.id); a["repoDirectory"] != slugA || a["defaulted"] != true || a["version"] != float64(0) {
			t.Fatalf("before = %v", a)
		}
		put := func(directory string, version int) map[string]any {
			return map[string]any{"repoDirectory": directory, "expectedVersion": version, "reason": "对齐仓库目录", "confirm": true}
		}
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/build-directories/"+tenantA.id, put("../etc", 0), nil), 400, "INVALID_BUILD_DIRECTORY")
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/build-directories/999999999", put("x", 0), nil), 404, "TENANT_NOT_FOUND")
		// 租户还没保存过构建配置：新建一行，只带目录
		saved := admin.mustCode(t, admin.do("PUT", "/v1/admin/platform/build-directories/"+tenantA.id, put("pts-dir", 0), nil), 200)
		if saved["repoDirectory"] != "pts-dir" || saved["defaulted"] != false || saved["version"] != float64(1) || saved["slug"] != slugA {
			t.Fatalf("saved = %v", saved)
		}
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/build-directories/"+tenantA.id, put("pts-dir-2", 0), nil), 409, "STALE_BUILD_CONFIG")
		mine := member.mustCode(t, member.do("GET", "/v1/admin/build-config", nil, nil), 200)
		if mine["repoDirectory"] != "pts-dir" || mine["identityConfigured"] != false {
			t.Fatalf("tenant view = %v", mine)
		}
		// 租户保存自己的配置时原样带回目录，其余字段照存；平台再改目录不动租户的字段
		member.mustCode(t, member.do("PUT", "/v1/admin/build-config", map[string]any{
			"repoDirectory": "pts-dir", "expectedVersion": 1, "reason": "填应用身份", "confirm": true,
			"identity": map[string]any{"appName": "Pts", "scheme": "pts", "apiBaseUrl": "https://" + tenantA.api},
		}, nil), 200)
		admin.mustCode(t, admin.do("PUT", "/v1/admin/platform/build-directories/"+tenantA.id, put("pts-dir-2", 2), nil), 200)
		mine = member.mustCode(t, member.do("GET", "/v1/admin/build-config", nil, nil), 200)
		if mine["repoDirectory"] != "pts-dir-2" || object(mine["identity"])["appName"] != "Pts" {
			t.Fatalf("tenant view after the platform changed the directory = %v", mine)
		}
		var audits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='build_directory_update'`, tenantA.id).Scan(&audits); err != nil || audits != 2 {
			t.Fatalf("audit events under the tenant = %d, %v", audits, err)
		}
	})

	t.Run("外部系统关联：预测平台只在平台控制台改", func(t *testing.T) {
		scope := "0x" + strings.Repeat("3", 64)
		seeded := map[string]any{
			"ttlSeconds": 3600, "localization": map[string]any{}, "theme": map[string]any{"primary": "#123456"}, "features": map[string]any{"crashAutoReport": false}, "support": map[string]any{},
			"updatePolicy": map[string]any{
				"minSupportedVersion": map[string]any{"android": "1.0.0", "ios": "1.0.0"},
				"latestVersion":       map[string]any{"android": "1.0.0", "ios": "1.0.0"},
			},
			"modules": map[string]any{"predict": false},
			"wallet":  map[string]any{"chains": []any{"bsc"}},
		}
		raw, _ := json.Marshal(seeded)
		seedTenantConfig(t, db, tenantA.id, "mobile-bootstrap", string(raw))
		list := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/predict-links", nil, nil), 200)
		if a := itemFor(list, tenantA.id); a["predict"] != nil || a["predictEnabled"] != false || a["version"] != float64(1) || fmt.Sprint(a["chains"]) != "[bsc]" {
			t.Fatalf("before = %v", a)
		}
		link := func(predict any, version int) map[string]any {
			return map[string]any{"predict": predict, "expectedVersion": version, "reason": "关联预测平台", "confirm": true}
		}
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/predict-links/"+tenantA.id, link(map[string]any{"domain": "https://x", "scopeId": scope, "chain": "bsc"}, 1), nil), 400, "INVALID_SERVICES_CONFIG")
		saved := admin.mustCode(t, admin.do("PUT", "/v1/admin/platform/predict-links/"+tenantA.id, link(map[string]any{"domain": "predict.pts.test", "scopeId": strings.ToUpper(scope[:2]) + scope[2:], "chain": "bsc"}, 1), nil), 200)
		if object(saved["predict"])["scopeId"] != scope || saved["version"] != float64(2) {
			t.Fatalf("saved = %v", saved)
		}
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/predict-links/"+tenantA.id, link(nil, 1), nil), 409, "STALE_APP_CONFIG")
		// 别的字段没动：租户改的主题还在
		config, version, err := mobileBootstrapFor(t.Context(), db, tenantA.id, false)
		if err != nil || version != 2 || object(config["theme"])["primary"] != "#123456" || object(object(config["services"])["predict"])["domain"] != "predict.pts.test" {
			t.Fatalf("stored = %v v%d %v", config, version, err)
		}
		// 预测市场模块开着就不能取消关联
		enabled := map[string]any{}
		for key, value := range config {
			enabled[key] = value
		}
		enabled["modules"] = map[string]any{"predict": true}
		raw, _ = json.Marshal(enabled)
		if _, err := db.Exec(`UPDATE app_configs SET config_value=?, version=3 WHERE tenant_id=? AND config_key='mobile-bootstrap'`, raw, tenantA.id); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, admin.do("PUT", "/v1/admin/platform/predict-links/"+tenantA.id, link(nil, 3), nil), 400, "INVALID_SERVICES_CONFIG")
		var events, pushes int
		_ = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='predict_link_update'`, tenantA.id).Scan(&events)
		_ = db.QueryRow(`SELECT COUNT(*) FROM app_push_outbox WHERE tenant_id=? AND event_type='bootstrap_updated'`, tenantA.id).Scan(&pushes)
		if events != 1 || pushes != 1 {
			t.Fatalf("audit %d, push events %d", events, pushes)
		}
	})

	t.Run("平台推送默认与平台发布存储默认", func(t *testing.T) {
		seedPlatformRow(t, db, pushcreds.FCMConfigKey,
			`{"projectId":"platform-proj","clientEmail":"push@platform-proj.iam.gserviceaccount.com","privateKeyId":"abcdef0123456789","serviceAccountEncrypted":"x"}`)
		push := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/push/credentials", nil, nil), 200)
		fcm := object(push["fcm"])
		if fcm["inherited"] != false || fcm["clientEmail"] == nil || fcm["inheritors"] == nil {
			t.Fatalf("platform push view = %v", push)
		}
		if _, has := fcm["projectMatches"]; has {
			t.Fatalf("the platform row has no google-services.json to match: %v", fcm)
		}
		seedPlatformRow(t, db, releaseStorageConfigKey,
			`{"provider":"s3","endpoint":"https://s3.platform.test","region":"r1","bucket":"platform-bucket","objectPrefix":"p","accessKeyIdEncrypted":"x","secretAccessKeyEncrypted":"y"}`)
		storage := admin.mustCode(t, admin.do("GET", "/v1/admin/platform/release-storage", nil, nil), 200)
		if storage["inherited"] != false || storage["bucket"] == "" || storage["inheritors"] == nil {
			t.Fatalf("platform storage view = %v", storage)
		}
		cors := admin.do("GET", "/v1/admin/platform/release-storage/cors", nil, nil)
		if cors.Code != 200 || !strings.Contains(cors.Body.String(), tenantA.console) || !strings.Contains(cors.Body.String(), tenantB.console) {
			t.Fatalf("platform CORS = %d %s", cors.Code, cors.Body.String())
		}
		wantProblem(t, member.do("GET", "/v1/admin/platform/release-storage", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})
}

func toStrings(v any) []string {
	var out []string
	for _, item := range v.([]any) {
		out = append(out, item.(string))
	}
	return out
}
