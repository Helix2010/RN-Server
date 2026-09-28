package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 出口合规由租户自己声明（ios_export_compliance.go）：声明了才进 tenant.json，false 也是一个声明；
// 撤回之后回到每个 build 在 ASC 上人工回答。需要真实 MySQL（RN_TEST_MYSQL_DSN）。

func exportCompliance(f *gateFixture, method string, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, method, "/v1/admin/ios/export-compliance", body)
	if method == http.MethodGet {
		f.s.getIOSExportCompliance(c)
	} else {
		f.s.updateIOSExportCompliance(c)
	}
	return recorder
}

// manifestJSON 是打包机领任务时会拿到的那份 tenant.json。
func manifestJSON(t *testing.T, f *gateFixture) string {
	t.Helper()
	cfg, _, err := f.s.buildConfigFor(context.Background(), f.tenant, f.slug)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := f.s.tenantManifestFor(context.Background(), f.tenant, cfg, "1.0.0", 1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(manifest)
	return string(raw)
}

func TestDBIOSExportComplianceIsTheTenantsOwnDeclaration(t *testing.T) {
	f, _ := newIOSPool(t, 163, 1)

	// 默认没声明：tenant.json 不带这个键，RN-App 不写 Info.plist，每个 build 人工回答
	if view := decodeBody(t, exportCompliance(f, http.MethodGet, nil)); view["declared"] != false || view["usesNonExemptEncryption"] != nil {
		t.Fatalf("default: %v", view)
	}
	if manifest := manifestJSON(t, f); strings.Contains(manifest, "iosUsesNonExemptEncryption") {
		t.Fatalf("an undeclared tenant must not carry the key: %s", manifest)
	}

	// 没确认、没原因不收
	if recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": false, "expectedVersion": 0, "reason": "legal"}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("a write without confirm was accepted: %d %s", recorder.Code, recorder.Body.String())
	}

	// 声明"只用豁免的加密"：false 也要进 tenant.json
	recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": false, "expectedVersion": 0, "reason": "legal said exempt", "confirm": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("declare: %d %s", recorder.Code, recorder.Body.String())
	}
	if view := decodeBody(t, recorder); view["declared"] != true || view["usesNonExemptEncryption"] != false || view["version"] != float64(1) {
		t.Fatalf("after declaring: %v", view)
	}
	if manifest := manifestJSON(t, f); !strings.Contains(manifest, `"iosUsesNonExemptEncryption":false`) {
		t.Fatalf("a false declaration was dropped from tenant.json: %s", manifest)
	}

	// 同样的声明、过期的版本号都不收
	if recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": false, "expectedVersion": 1, "reason": "again", "confirm": true}); problemCode(t, recorder) != "IOS_EXPORT_COMPLIANCE_UNCHANGED" {
		t.Fatalf("an unchanged declaration: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": true, "expectedVersion": 0, "reason": "stale", "confirm": true}); problemCode(t, recorder) != "STALE_IOS_EXPORT_COMPLIANCE" {
		t.Fatalf("a stale write: %d %s", recorder.Code, recorder.Body.String())
	}

	// 改成 true，再撤回
	if recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": true, "expectedVersion": 1, "reason": "we added our own crypto", "confirm": true}); recorder.Code != http.StatusOK {
		t.Fatalf("change: %d %s", recorder.Code, recorder.Body.String())
	}
	if manifest := manifestJSON(t, f); !strings.Contains(manifest, `"iosUsesNonExemptEncryption":true`) {
		t.Fatalf("tenant.json after changing: %s", manifest)
	}
	recorder = exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": nil, "expectedVersion": 2, "reason": "back to answering per build", "confirm": true})
	if recorder.Code != http.StatusOK || decodeBody(t, recorder)["declared"] != false {
		t.Fatalf("withdraw: %d %s", recorder.Code, recorder.Body.String())
	}
	if manifest := manifestJSON(t, f); strings.Contains(manifest, "iosUsesNonExemptEncryption") {
		t.Fatalf("a withdrawn declaration is still in tenant.json: %s", manifest)
	}
	if recorder := exportCompliance(f, http.MethodPut, map[string]any{"usesNonExemptEncryption": nil, "expectedVersion": 0, "reason": "nothing to withdraw", "confirm": true}); problemCode(t, recorder) != "IOS_EXPORT_COMPLIANCE_UNCHANGED" {
		t.Fatalf("withdrawing nothing: %d %s", recorder.Code, recorder.Body.String())
	}

	var changes int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_export_compliance_update'`, f.tenant).Scan(&changes); err != nil || changes != 3 {
		t.Fatalf("every change must be audited: %d %v", changes, err)
	}
}
