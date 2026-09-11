package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 路由级的灰度回归：走真实的 gin 路由、中间件和按 Host 解析租户，验证客户端
// 真正会发的那组请求头能不能一路走到决策点。前面 canary_test.go 直接调处理函数，
// 绕过了路由与中间件——App 侧最容易出错的恰恰是"头发出去了但没被认出来"。

func canaryRouterTenant(t *testing.T, db *sql.DB, domain string) string {
	t.Helper()
	now := time.Now().UTC()
	result, err := db.Exec(`INSERT INTO tenants(slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,1,?,?,0,?,?)`,
		"canary-"+uniqueSuffix(), now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	id, _ := result.LastInsertId()
	if _, err := db.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at) VALUES(?,?,1,'active',0,?,?)`, id, domain, now, now); err != nil {
		t.Fatalf("insert tenant domain: %v", err)
	}
	// bootstrap 不下发"零条链"的钱包段、也不下发"开着但没配"的预测模块（都会 503）：
	// 从平台默认配置起步，补一条启用的链并关掉预测。代币目录由迁移全局种下，不用再管。
	// 不能 SELECT 平台那行来改：tenant_id=0 的配置是 appConfigView 第一次被调用时才
	// 懒插的，全新库上还不存在，SELECT 会插 0 行然后在 bootstrap 那里炸成 503
	var config map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &config); err != nil {
		t.Fatalf("parse initial config: %v", err)
	}
	config["wallet"] = map[string]any{"chains": []string{"bsc"}, "onchainSends": false}
	config["modules"] = map[string]any{"predict": false, "dex": true}
	raw, _ := json.Marshal(config)
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,1,'test',?)`, id, raw, now); err != nil {
		t.Fatalf("seed tenant bootstrap config: %v", err)
	}
	return strconv.FormatInt(id, 10)
}

// TestDBCanaryOverTheRealRouter 用真实路由跑一遍"App 会发什么、服务端怎么答"。
func TestDBCanaryOverTheRealRouter(t *testing.T) {
	db := openTestDB(t)
	domain := "canary-" + uniqueSuffix() + ".test"
	tenant := canaryRouterTenant(t, db, domain)
	cfg := config.Config{
		Environment:       "test",
		DeviceIdentityKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		StorageMasterKey:  base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		OTAChannel:        "production",
		AndroidDirectURL:  "https://" + domain + "/download",
		MySQLQueryTimeout: 10,
	}
	router := New(cfg, &store.Store{DB: db})
	// 服务端与路由各建一个：注册安装要走 saveInstallation，路由上没有这个测试入口
	direct := canaryTestServer(db)
	direct.cfg = cfg

	insider, outsider := "inst_router_in_"+uniqueSuffix(), "inst_router_out_"+uniqueSuffix()
	insiderCredential := canaryInstallation(t, direct, tenant, insider)
	outsiderCredential := canaryInstallation(t, direct, tenant, outsider)
	insertCanaryTestRelease(t, db, tenant, "rel_router_active_"+uniqueSuffix(), "6.0.0", 80, "active", nil, false)
	canaryID := "rel_router_canary_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, canaryID, "6.1.0", 81, "canary", []string{insider}, false)

	// call 发一条 App 真实形状的请求：带上客户端一定会发的那组头
	call := func(target, installationID, credential string, extra map[string]string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		request.Host = domain
		request.Header.Set("x-platform", "android")
		request.Header.Set("x-application-id", "dex-mobile")
		request.Header.Set("x-app-version", "1.3.0")
		request.Header.Set("x-build-number", "26")
		request.Header.Set("x-distribution-channel", "direct")
		if installationID != "" {
			request.Header.Set("x-installation-id", installationID)
		}
		if credential != "" {
			request.Header.Set("Authorization", "Installation "+credential)
		}
		for key, value := range extra {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder
	}

	t.Run("bootstrap：名单内设备拿到灰度版本并拿到灰度令牌", func(t *testing.T) {
		recorder := call("/v1/mobile/bootstrap", insider, insiderCredential, nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("bootstrap failed: %d %s", recorder.Code, recorder.Body.String())
		}
		update := object(decodeBody(t, recorder)["update"])
		if update["latestVersion"] != "6.1.0" {
			t.Fatalf("want the canary version, got %v", update["latestVersion"])
		}
		canary := object(update["canary"])
		if canary["enrolled"] != true {
			t.Fatalf("enrolled must be true, got %v", canary["enrolled"])
		}
		token, _ := canary["otaToken"].(string)
		if token == "" {
			t.Fatal("an authenticated installation must receive a canary token")
		}
		// 令牌不透明：安装 ID 不能从里面读出来，而且能被服务端解回同一个身份
		if strings.Contains(token, insider) {
			t.Fatal("the token must not leak the installation id")
		}
		if got := direct.decodeCanaryToken(tenant, token); got != insider {
			t.Fatalf("token round trip failed, got %q", got)
		}
		// base64url 的字符集不需要在 RFC 8941 字典里转义
		if strings.ContainsAny(token, `"\ ,;=`) {
			t.Fatalf("token is not safe inside a structured field: %q", token)
		}
	})

	t.Run("bootstrap：名单外设备只拿到 active，也拿得到自己的令牌", func(t *testing.T) {
		recorder := call("/v1/mobile/bootstrap", outsider, outsiderCredential, nil)
		update := object(decodeBody(t, recorder)["update"])
		if update["latestVersion"] != "6.0.0" {
			t.Fatalf("want active, got %v", update["latestVersion"])
		}
		canary := object(update["canary"])
		if canary["enrolled"] != false {
			t.Fatalf("enrolled must be false, got %v", canary["enrolled"])
		}
		if token, _ := canary["otaToken"].(string); token == "" {
			t.Fatal("a verified installation outside the audience still needs a token for future canaries")
		}
	})

	t.Run("bootstrap：凭证无效不影响配置下发，只是没有灰度和令牌", func(t *testing.T) {
		for _, item := range []struct{ name, id, credential string }{
			{"不带身份", "", ""},
			{"带 ID 不带凭证", insider, ""},
			{"凭证伪造", insider, "icred_" + strings.Repeat("x", 43)},
		} {
			t.Run(item.name, func(t *testing.T) {
				recorder := call("/v1/mobile/bootstrap", item.id, item.credential, nil)
				if recorder.Code != http.StatusOK {
					t.Fatalf("bootstrap must still succeed: %d %s", recorder.Code, recorder.Body.String())
				}
				body := decodeBody(t, recorder)
				update := object(body["update"])
				if update["latestVersion"] != "6.0.0" {
					t.Fatalf("want active, got %v", update["latestVersion"])
				}
				canary := object(update["canary"])
				if canary["enrolled"] != false || canary["otaToken"] != nil {
					t.Fatalf("an unverified installation must get no canary and no token, got %v", canary)
				}
				// 配置照发：钱包段、文案、主题都在
				if object(body["localization"])["selectedLocale"] == nil || body["wallet"] == nil {
					t.Fatal("bootstrap must still deliver the full configuration")
				}
			})
		}
	})

	t.Run("公开 latest：匿名只看得到 active，名单内设备看得到灰度", func(t *testing.T) {
		anonymous := call("/v1/public/releases/latest?platform=android", "", "", nil)
		if anonymous.Code != http.StatusOK {
			t.Fatalf("latest failed: %d %s", anonymous.Code, anonymous.Body.String())
		}
		if body := decodeBody(t, anonymous); body["version"] != "6.0.0" || body["status"] != "active" {
			t.Fatalf("anonymous must only see active, got %v/%v", body["version"], body["status"])
		}
		allowlisted := call("/v1/public/releases/latest?platform=android", insider, insiderCredential, nil)
		if body := decodeBody(t, allowlisted); body["version"] != "6.1.0" || body["status"] != "canary" {
			t.Fatalf("allowlisted must see the canary, got %v/%v", body["version"], body["status"])
		}
	})

	t.Run("公开下载：名单外拿着发布 ID 也只拿到 404", func(t *testing.T) {
		outside := call("/v1/public/releases/"+canaryID+"/download", outsider, outsiderCredential, nil)
		if outside.Code != http.StatusNotFound {
			t.Fatalf("want 404 outside the audience, got %d %s", outside.Code, outside.Body.String())
		}
		// 名单内走到存储层才失败（测试环境没有对象存储），说明可见性这一关放行了
		inside := call("/v1/public/releases/"+canaryID+"/download", insider, insiderCredential, nil)
		if inside.Code == http.StatusNotFound {
			t.Fatalf("an allowlisted device must get past the visibility check, got 404: %s", inside.Body.String())
		}
	})

	// 联调时踩过：客户端只带凭证、漏了平台与应用身份，服务端按四元组查不到行，
	// 凭证有效也判成匿名，灰度包一直 404 而客户端只看得到"下载失败"
	t.Run("下载：只带凭证、漏掉平台与应用身份，仍然是匿名", func(t *testing.T) {
		partial := httptest.NewRequest(http.MethodGet, "/v1/public/releases/"+canaryID+"/download", nil)
		partial.Host = domain
		partial.Header.Set("x-installation-id", insider)
		partial.Header.Set("Authorization", "Installation "+insiderCredential)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, partial)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("without the application/platform headers the credential cannot be located, want 404, got %d", recorder.Code)
		}
		// 补齐两个头就能过可见性这一关
		full := httptest.NewRequest(http.MethodGet, "/v1/public/releases/"+canaryID+"/download", nil)
		full.Host = domain
		full.Header.Set("x-platform", "android")
		full.Header.Set("x-application-id", "dex-mobile")
		full.Header.Set("x-installation-id", insider)
		full.Header.Set("Authorization", "Installation "+insiderCredential)
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, full)
		if recorder.Code == http.StatusNotFound {
			t.Fatalf("with the full identity header set the download must get past the visibility check: %s", recorder.Body.String())
		}
	})

	t.Run("OTA manifest：灰度令牌走 Expo-Extra-Params，认不出就回 active", func(t *testing.T) {
		base := "rel_router_ota_base_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, base, "6.2.0", 82, "active", nil, false)
		now := time.Now().UTC()
		insertCanaryTestOTAForRuntime(t, db, tenant, "ota_router_active_"+uniqueSuffix(), base, "6.2.0", 1, "active", nil, now)
		insertCanaryTestOTAForRuntime(t, db, tenant, "ota_router_canary_"+uniqueSuffix(), base, "6.2.0", 2, "canary", []string{insider}, now)
		token, err := direct.encodeCanaryToken(tenant, insider, now)
		if err != nil {
			t.Fatalf("encode token: %v", err)
		}
		manifest := func(extraParams string) int {
			extra := map[string]string{
				"expo-platform":         "android",
				"expo-runtime-version":  "6.2.0",
				"expo-channel-name":     "production",
				"expo-protocol-version": "1",
				"eas-client-id":         "client",
			}
			if extraParams != "" {
				extra["Expo-Extra-Params"] = extraParams
			}
			recorder := call("/v1/ota/manifest", "", "", extra)
			// 没有对象存储，取到哪一条会在读 manifest 时失败；用返回码区分不了，
			// 于是直接查一次服务端此刻会选中的 revision
			return recorder.Code
		}
		// 带令牌与不带令牌都不能 500：一条是 canary 一条是 active，都要能走到存储层
		if code := manifest(canaryExtraParamKey + `="` + token + `"`); code == http.StatusInternalServerError {
			t.Fatalf("a canary manifest request must not 500, got %d", code)
		}
		if code := manifest(""); code == http.StatusInternalServerError {
			t.Fatalf("an anonymous manifest request must not 500, got %d", code)
		}
		// 真正的选中结果用同一条 SQL 断言
		revision := func(header string) int {
			request := httptest.NewRequest(http.MethodGet, "/v1/ota/manifest", nil)
			request.Host = domain
			if header != "" {
				request.Header.Set("Expo-Extra-Params", header)
			}
			context, _ := testContext(t, tenant, http.MethodGet, "/v1/ota/manifest", nil)
			context.Request = request
			audience := direct.canaryAudienceFromExtraParams(context, tenant)
			var found int
			if err := db.QueryRow(`SELECT o.revision FROM ota_releases o WHERE o.tenant_id=? AND o.platform='android' AND o.channel='production' AND o.runtime_version='6.2.0' AND `+canaryVisibleOTASQL+` ORDER BY o.revision DESC LIMIT 1`, tenant, audience, audience).Scan(&found); err != nil {
				t.Fatalf("manifest lookup: %v", err)
			}
			return found
		}
		if got := revision(canaryExtraParamKey + `="` + token + `"`); got != 2 {
			t.Fatalf("an allowlisted device must reach the canary revision, got %d", got)
		}
		if got := revision(""); got != 1 {
			t.Fatalf("without a token the device must stay on active, got %d", got)
		}
	})
}

func insertCanaryTestOTAForRuntime(t *testing.T, db *sql.DB, tenant, id, base, runtime string, revision int, status string, audience []string, now time.Time) {
	t.Helper()
	var raw any
	if audience != nil {
		encoded, _ := json.Marshal(audience)
		raw = encoded
	}
	if _, err := db.Exec(`INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,release_kind,status,canary_installations,manifest_key,manifest_sha256,release_notes,created_by,published_at,created_at,updated_at) VALUES(?,?,?,'android','production',?,?,?,'update',?,?,?,?,'{}','tester',?,?,?)`,
		id, tenant, base, runtime, revision, randomUUID(), status, raw, "objects/"+id+"/manifest.json", strings.Repeat("b", 64), now, now, now); err != nil {
		t.Fatalf("insert ota %s: %v", id, err)
	}
}
