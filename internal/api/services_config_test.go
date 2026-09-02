package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const testScope = "0xfb05e4134e5b30db022b94b822e7d19b1e5cd1c244468eada63789fd3514454a"

func predictConfig(domain, scope, chain string) map[string]any {
	return map[string]any{"domain": domain, "scopeId": scope, "chain": chain}
}

func TestParsePredictServiceNormalizesAndRejects(t *testing.T) {
	got, err := parsePredictService(predictConfig(" Predict.Prax1s.xyz ", strings.ToUpper(testScope), "op-sepolia"))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if got.Domain != "predict.prax1s.xyz" || got.ScopeID != testScope || got.Chain != "op-sepolia" {
		t.Fatalf("normalized = %+v", got)
	}
	for name, raw := range map[string]map[string]any{
		"protocol in domain": predictConfig("https://predict.prax1s.xyz", testScope, "op-sepolia"),
		"port in domain":     predictConfig("predict.prax1s.xyz:443", testScope, "op-sepolia"),
		"single label":       predictConfig("localhost", testScope, "op-sepolia"),
		"short scope":        predictConfig("predict.prax1s.xyz", "0xfb05", "op-sepolia"),
		"unknown chain":      predictConfig("predict.prax1s.xyz", testScope, "solana"),
	} {
		if _, err := parsePredictService(raw); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestParseServicesSectionRejectsUnknownService(t *testing.T) {
	if _, err := parseServicesSection(map[string]any{"predikt": predictConfig("predict.prax1s.xyz", testScope, "op-sepolia")}); err == nil {
		t.Fatal("a misspelled service key must not be stored silently")
	}
	section, err := parseServicesSection(map[string]any{"predict": predictConfig("predict.prax1s.xyz", testScope, "op-sepolia")})
	if err != nil || object(section["predict"])["domain"] != "predict.prax1s.xyz" {
		t.Fatalf("section = %v, err = %v", section, err)
	}
}

func TestPredictServiceForEnforcesTheModuleRule(t *testing.T) {
	wallet := normalizeWallet(map[string]any{"chains": []any{"eth", "op-sepolia"}})
	off := map[string]any{"predict": false, "dex": true}
	on := map[string]any{"predict": true, "dex": true}
	if got, err := predictServiceFor(off, map[string]any{}, wallet); got != nil || err != nil {
		t.Fatalf("predict off must deliver nothing: %v %v", got, err)
	}
	if _, err := predictServiceFor(on, map[string]any{}, wallet); err == nil {
		t.Fatal("predict on without services.predict must fail")
	}
	// 链没在租户启用的集合里：App 没有这条链的端点和目录，关联无从成立
	if _, err := predictServiceFor(on, map[string]any{"predict": predictConfig("predict.prax1s.xyz", testScope, "bsc")}, wallet); err == nil {
		t.Fatal("predict chain outside the enabled chains must fail")
	}
	got, err := predictServiceFor(on, map[string]any{"predict": predictConfig("predict.prax1s.xyz", testScope, "op-sepolia")}, wallet)
	if err != nil || got == nil || got.Chain != "op-sepolia" {
		t.Fatalf("valid predict config = %v, err = %v", got, err)
	}
}

func TestNormalizeServicesDropsInvalidStoredEntries(t *testing.T) {
	out := normalizeServices(map[string]any{"predict": predictConfig("not a host", testScope, "op-sepolia")})
	if _, present := out["predict"]; present {
		t.Fatal("an invalid stored entry must not be delivered")
	}
	if normalizeServices(nil) == nil {
		t.Fatal("normalizeServices must always return an object")
	}
}

func probeWith(t *testing.T, publicInfo any, status int, body map[string]any) (int, map[string]any) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tenant-Domain") == "" {
			t.Error("probe must send X-Tenant-Domain")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(publicInfo)
	}))
	defer upstream.Close()
	previous := gammaPublicInfoURL
	gammaPublicInfoURL = func(string) string { return upstream.URL + "/public-info" }
	defer func() { gammaPublicInfoURL = previous }()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	raw, _ := json.Marshal(body)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/admin/predict/probe", strings.NewReader(string(raw)))
	c.Request.Header.Set("Content-Type", "application/json")
	(&server{}).probePredictService(c)
	var out map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &out)
	return recorder.Code, out
}

func TestProbePredictServiceComparesScopeAndChain(t *testing.T) {
	info := map[string]any{
		"scopeId": strings.ToUpper(testScope),
		"chain":   map[string]any{"chainId": 11155420, "name": "OP Sepolia"},
		"brand":   map[string]any{"title": "prax1s.xyz"},
	}
	code, out := probeWith(t, info, 200, predictConfig("predict.prax1s.xyz", testScope, "op-sepolia"))
	if code != 200 || out["ok"] != true || out["brand"] != "prax1s.xyz" {
		t.Fatalf("matching probe = %d %v", code, out)
	}
	// 配成别的租户的平台：scopeId 对不上，保存前就要发现
	code, out = probeWith(t, info, 200, predictConfig("predict.prax1s.xyz", "0x"+strings.Repeat("ab", 32), "op-sepolia"))
	if code != 200 || out["ok"] != false || len(out["problems"].([]any)) != 1 {
		t.Fatalf("scope mismatch = %d %v", code, out)
	}
	// 链对不上
	code, out = probeWith(t, info, 200, predictConfig("predict.prax1s.xyz", testScope, "eth"))
	if code != 200 || out["ok"] != false {
		t.Fatalf("chain mismatch = %d %v", code, out)
	}
}

func TestProbePredictServiceReportsUpstreamFailures(t *testing.T) {
	code, out := probeWith(t, map[string]any{"error": "expired"}, 403, predictConfig("predict.prax1s.xyz", testScope, "op-sepolia"))
	if code != 502 || out["code"] != "PREDICT_PROBE_FAILED" {
		t.Fatalf("upstream 403 = %d %v", code, out)
	}
	code, _ = probeWith(t, nil, 200, predictConfig("predict.prax1s.xyz:443", testScope, "op-sepolia"))
	if code != 400 {
		t.Fatalf("invalid input must be 400, got %d", code)
	}
}
