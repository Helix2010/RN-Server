package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// ttlSeconds 现在真的决定每台设备多久重新拉一次配置，下限跟着提到 300：
// 填 30 就是每台设备每 30 秒打一次这个接口。
func TestValidConfigRejectsATTLBelowTheRequestFloor(t *testing.T) {
	load := func(ttl float64) map[string]any {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(initialConfig), &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["ttlSeconds"] = ttl
		return cfg
	}
	for _, item := range []struct {
		ttl   float64
		valid bool
	}{{30, false}, {299, false}, {300, true}, {21600, true}, {86400, true}, {86401, false}} {
		if got := validConfig(load(item.ttl)); got != item.valid {
			t.Fatalf("ttlSeconds=%v validConfig=%v, want %v", item.ttl, got, item.valid)
		}
	}
}

// 下发给 App 的刷新节奏必须来自配置自己的 ttlSeconds。它以前来自语言设置里的
// refreshIntervalSeconds——一个跟语言无关的值藏在多语言管理里，而「基础配置」
// 上那个 TTL 谁也没在读。字段名还留着是因为已装机的 App 严格解析 bootstrap。
func TestDBBootstrapRefreshIntervalComesFromTheConfigTTL(t *testing.T) {
	db := openTestDB(t)
	domain := "ttl-" + uniqueSuffix() + ".test"
	tenant := canaryRouterTenant(t, db, domain)
	now := time.Now().UTC()

	if _, err := db.Exec(`UPDATE app_configs SET config_value=JSON_SET(config_value,'$.ttlSeconds',3600)
		WHERE tenant_id=? AND config_key='mobile-bootstrap'`, tenant); err != nil {
		t.Fatalf("seed bootstrap config: %v", err)
	}
	// 语言设置里那个旧字段还留着一个不一样的值：它不能再影响下发
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'languages',?,1,'test',?)`,
		tenant, `{"refreshIntervalSeconds":900}`, now); err != nil {
		t.Fatalf("seed tenant language settings: %v", err)
	}

	router := New(config.Config{
		Environment:       "test",
		DeviceIdentityKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		StorageMasterKey:  base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout: 10,
	}, &store.Store{DB: db})
	request := httptest.NewRequest(http.MethodGet, "/v1/mobile/bootstrap", nil)
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

	body := decodeBody(t, recorder)
	if ttl, _ := body["ttlSeconds"].(float64); ttl != 3600 {
		t.Fatalf("ttlSeconds = %v", body["ttlSeconds"])
	}
	localization := object(body["localization"])
	if interval, _ := localization["refreshIntervalSeconds"].(float64); interval != 3600 {
		t.Fatalf("refreshIntervalSeconds = %v，语言设置里那个 900 又跑回来了", localization["refreshIntervalSeconds"])
	}
}
