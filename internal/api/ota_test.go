package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWriteExpoNoUpdateIncludesProtocolHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)

	writeExpoNoUpdate(context)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
	if recorder.Header().Get("expo-protocol-version") != "1" {
		t.Fatal("no-update response must declare Expo protocol version 1")
	}
	if recorder.Header().Get("expo-sfv-version") != "0" {
		t.Fatal("no-update response must declare Expo SFV version 0")
	}
	if recorder.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("no-update response must not be cached as a permanent result")
	}
}

func TestOTASequenceLockNameFitsMySQLLimit(t *testing.T) {
	runtime := "3f6df6c8584862471d6f2f045d60c9bdac129cd6-runtime-with-a-long-fingerprint"
	name := otaSequenceLockName("100000001", "android", "production", runtime)
	if len(name) > 64 {
		t.Fatalf("lock name exceeds MySQL GET_LOCK limit: %d", len(name))
	}
	if name != otaSequenceLockName("100000001", "android", "production", runtime) {
		t.Fatal("lock name must be deterministic")
	}
	if name == otaSequenceLockName("100000002", "android", "production", runtime) {
		t.Fatal("lock name must include tenant scope")
	}
}

func TestRewriteOTAClientIdentityUsesBaseReleaseAndTenant(t *testing.T) {
	manifest := map[string]any{
		"extra": map[string]any{
			"expoClient": map[string]any{
				"version": "0.0.1",
				"android": map[string]any{"versionCode": 1},
				"extra":   map[string]any{"apiBaseUrl": "https://old.example"},
			},
		},
	}
	rewriteOTAClientIdentity(manifest, otaClientIdentity{APIBaseURL: "https://tenant.example", ApplicationID: "com.example.app", AppVersion: "2.3.4", BuildNumber: 42, Platform: "android", Distribution: "direct", OTAChannel: "production"})
	extra := manifest["extra"].(map[string]any)
	client := extra["expoClient"].(map[string]any)
	clientExtra := client["extra"].(map[string]any)
	if client["version"] != "2.3.4" || client["android"].(map[string]any)["versionCode"] != 42 || clientExtra["apiBaseUrl"] != "https://tenant.example" || extra["distributionChannel"] != "direct" {
		t.Fatalf("manifest identity was not rewritten: %#v", manifest)
	}
	if _, err := json.Marshal(manifest); err != nil {
		t.Fatalf("rewritten manifest must remain JSON serializable: %v", err)
	}
}

func TestOTAManifestIdentityExtractsClientFields(t *testing.T) {
	manifest := map[string]any{
		"runtimeVersion": "runtime-a",
		"platform":       "android",
		"channel":        "production",
		"extra": map[string]any{
			"apiBaseUrl":          "https://tenant.example",
			"distributionChannel": "direct",
			"otaChannel":          "production",
			"applicationId":       "com.example.app",
			"appVersion":          "2.3.4",
			"buildNumber":         42,
			"expoClient": map[string]any{
				"version": "2.3.4",
				"android": map[string]any{"versionCode": 42},
			},
		},
	}
	identity := otaManifestIdentity(manifest)
	if identity["apiBaseUrl"] != "https://tenant.example" || identity["expoClientVersion"] != "2.3.4" || identity["expoClientAndroidVersionCode"] != 42 {
		t.Fatalf("manifest identity extraction failed: %#v", identity)
	}
}

func TestOTAClientBaselineRequiresVersionAndBuild(t *testing.T) {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/v1/ota/manifest", nil)
	if _, _, ok := otaClientBaseline(context); ok {
		t.Fatal("OTA must fail closed when APK baseline headers are absent")
	}
	context.Request.Header.Set("x-app-version", "1.1.8")
	if _, _, ok := otaClientBaseline(context); ok {
		t.Fatal("OTA must require both version and build")
	}
	context.Request.Header.Set("x-build-number", "12")
	version, build, ok := otaClientBaseline(context)
	if !ok || version != "1.1.8" || build != "12" {
		t.Fatalf("unexpected baseline: version=%q build=%q ok=%v", version, build, ok)
	}
}

func TestValidateOTAManifestPackageRequiresMatchingRuntimeAndHashes(t *testing.T) {
	content := []byte("console.log('ok')")
	digest := sha256.Sum256(content)
	manifest := map[string]any{
		"id": "123e4567-e89b-12d3-a456-426614174000", "runtimeVersion": "fingerprint-a", "platform": "android",
		"createdAt":   "2026-08-28T00:00:00Z",
		"extra":       map[string]any{"scopeKey": "anyfun", "applicationId": "dex-mobile"},
		"launchAsset": map[string]any{"path": "bundle.js", "key": "bundle", "contentType": "application/javascript", "url": "https://example.test/bundle.js", "fileExtension": ".js", "hash": base64.RawURLEncoding.EncodeToString(digest[:])},
		"assets":      []any{},
	}
	f := makeZipFile(t, "bundle.js", content)
	if err := validateOTAManifestPackage(manifest, map[string]*zip.File{"bundle.js": f}, "android", "fingerprint-a", "production"); err != nil {
		t.Fatalf("expected valid manifest: %v", err)
	}
	manifest["runtimeVersion"] = "other"
	if err := validateOTAManifestPackage(manifest, map[string]*zip.File{"bundle.js": f}, "android", "fingerprint-a", "production"); err == nil {
		t.Fatal("expected runtime mismatch")
	}
}

// 应用身份必须由 OTA 包自己带上（构建脚本从租户配置写入 extra.applicationId），
// 服务端不能拿基线 APK 的包名顶替：装了 OTA 的设备会以另一个身份上报，
// app_installations 里就会出现同一台设备的两条记录，凭证也对不上。
// validateOTAManifestPackage 只要求字段存在；与基线 APK 内嵌值的比对见 otaApplicationIDMismatch
func TestValidateOTAManifestPackageRequiresApplicationID(t *testing.T) {
	content := []byte("console.log('ok')")
	digest := sha256.Sum256(content)
	f := makeZipFile(t, "bundle.js", content)
	manifest := func(extra map[string]any) map[string]any {
		return map[string]any{
			"id": "123e4567-e89b-12d3-a456-426614174000", "runtimeVersion": "fingerprint-a", "platform": "android",
			"createdAt":   "2026-08-28T00:00:00Z",
			"extra":       extra,
			"launchAsset": map[string]any{"path": "bundle.js", "key": "bundle", "contentType": "application/javascript", "url": "https://example.test/bundle.js", "fileExtension": ".js", "hash": base64.RawURLEncoding.EncodeToString(digest[:])},
			"assets":      []any{},
		}
	}
	err := validateOTAManifestPackage(manifest(map[string]any{"scopeKey": "anyfun"}), map[string]*zip.File{"bundle.js": f}, "android", "fingerprint-a", "production")
	if err == nil || !strings.Contains(err.Error(), "extra.applicationId") {
		t.Fatalf("manifest without applicationId must be rejected, got %v", err)
	}
	nested := map[string]any{"scopeKey": "anyfun", "expoClient": map[string]any{"extra": map[string]any{"applicationId": "dex-mobile"}}}
	if err := validateOTAManifestPackage(manifest(nested), map[string]*zip.File{"bundle.js": f}, "android", "fingerprint-a", "production"); err != nil {
		t.Fatalf("applicationId nested under expoClient.extra must be accepted: %v", err)
	}
}

func makeZipFile(t *testing.T, name string, body []byte) *zip.File {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return reader.File[0]
}

func TestApplyManifestStrategyOverridesBakedMetadata(t *testing.T) {
	raw := []byte(`{"id":"u1","metadata":{"channel":"production","applyStrategy":"next_launch","sourceCommitSha":"abc"},"extra":{"x":1}}`)
	out, err := applyManifestStrategy(raw, "immediate")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	metadata := m["metadata"].(map[string]any)
	if metadata["applyStrategy"] != "immediate" || metadata["sourceCommitSha"] != "abc" || metadata["channel"] != "production" {
		t.Fatalf("metadata not overridden in place: %v", metadata)
	}
	if m["extra"] == nil {
		t.Fatal("other manifest fields must survive")
	}
	same, err := applyManifestStrategy(raw, "next_launch")
	if err != nil || string(same) != string(raw) {
		t.Fatal("unchanged strategy must return the stored bytes untouched")
	}
	if _, err := applyManifestStrategy([]byte("not json"), "immediate"); err == nil {
		t.Fatal("invalid manifest must be reported, not served")
	}
}

func TestFlagEditableOnlyWhileTheRecordStillReachesClients(t *testing.T) {
	for _, status := range []string{"verified", "active", "paused"} {
		if !releaseFlagEditable(status) || !otaFlagEditable(status) {
			t.Fatalf("%s must allow editing", status)
		}
	}
	for _, status := range []string{"completed", "rejected", "rolled_back", "uploaded", "superseded", "draft"} {
		if releaseFlagEditable(status) || otaFlagEditable(status) {
			t.Fatalf("%s must not allow editing", status)
		}
	}
}

func TestOTAApplicationIDMustMatchBaseAPK(t *testing.T) {
	manifest := map[string]any{"extra": map[string]any{"scopeKey": "anyfun", "applicationId": "dex-mobile"}}
	if err := otaApplicationIDMismatch(manifest, "dex-mobile"); err != nil {
		t.Fatalf("matching application id rejected: %v", err)
	}
	if err := otaApplicationIDMismatch(manifest, "other-app"); err == nil || !strings.Contains(err.Error(), "does not match the base APK") {
		t.Fatalf("mismatching application id must be rejected, got %v", err)
	}
	if err := otaApplicationIDMismatch(manifest, ""); err == nil {
		t.Fatal("unknown base application id must be rejected, never treated as a match")
	}
	nested := map[string]any{"extra": map[string]any{"scopeKey": "anyfun", "expoClient": map[string]any{"extra": map[string]any{"applicationId": "dex-mobile"}}}}
	if err := otaApplicationIDMismatch(nested, "dex-mobile"); err != nil {
		t.Fatalf("nested application id must be compared: %v", err)
	}
}

func TestOTAObjectRecordDistinguishesLegacyUnlistedAndInvalid(t *testing.T) {
	raw := []byte(`{"bundle.js":{"size":1234,"etag":"abc"}}`)
	record, state, err := otaObjectRecord(raw, "bundle.js")
	if err != nil || state != otaObjectRecorded || record.Size != 1234 || record.ETag != "abc" {
		t.Fatalf("recorded path = %+v %v %v", record, state, err)
	}
	if _, state, err := otaObjectRecord(raw, "missing.js"); err != nil || state != otaObjectUnlisted {
		t.Fatalf("unlisted path must be 404-able, got %v %v", state, err)
	}
	if _, state, err := otaObjectRecord(nil, "bundle.js"); err != nil || state != otaObjectLegacy {
		t.Fatalf("NULL object_metadata must be legacy, got %v %v", state, err)
	}
	if _, state, err := otaObjectRecord([]byte(`{broken`), "bundle.js"); err == nil || state != otaObjectInvalid {
		t.Fatalf("invalid JSON must be a data incident, got %v %v", state, err)
	}
	if _, state, err := otaObjectRecord([]byte(`{"bundle.js":{"etag":"abc"}}`), "bundle.js"); err == nil || state != otaObjectInvalid {
		t.Fatalf("entry without a size must be invalid, got %v %v", state, err)
	}
}

func TestBindsApplicationIDToBaseOnlyForAndroid(t *testing.T) {
	if !bindsApplicationIDToBase("android") {
		t.Fatal("Android bases carry a server-readable embedded application id and must be bound")
	}
	if bindsApplicationIDToBase("ios") {
		t.Fatal("iOS bases have no server-readable embedded config; binding would reject every iOS OTA")
	}
}

func TestOTAObjectRecordRejectsAnEmptyETag(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":   `{"bundle.js":{"size":10,"etag":""}}`,
		"missing": `{"bundle.js":{"size":10}}`,
		"number":  `{"bundle.js":{"size":10,"etag":7}}`,
	} {
		if _, state, err := otaObjectRecord([]byte(raw), "bundle.js"); state != otaObjectInvalid || err == nil {
			t.Fatalf("%s: state=%v err=%v; an ETag-less record must be a data incident, not a size-only check", name, state, err)
		}
	}
	if entry, state, err := otaObjectRecord([]byte(`{"bundle.js":{"size":10,"etag":"abc-3"}}`), "bundle.js"); err != nil || state != otaObjectRecorded || entry.ETag != "abc-3" {
		t.Fatalf("recorded = %+v %v %v", entry, state, err)
	}
}

// 真正出问题的是"写入路径没有调用校验"，所以除了校验函数本身，
// 还要从请求这一层确认两个保存接口都会拒绝错误的形状。
func TestSaveOTAReleaseRejectsStringReleaseNotes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/v1/build-agent/jobs/bj_1/ota-release", strings.NewReader(
		`{"artifactToken":"t","baseReleaseId":"rel_1","channel":"production","applyStrategy":"immediate","releaseNotes":{"zh-CN":"写成了字符串"}}`,
	))

	(&server{}).saveOTARelease(context)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d body %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("problem body must be JSON: %v", err)
	}
	if body["code"] != "INVALID_RELEASE_NOTES" {
		t.Fatalf("expected INVALID_RELEASE_NOTES, got %v", body["code"])
	}
}

func TestCreateReleaseFromArtifactRejectsStringReleaseNotes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodPost, "/v1/admin/releases", strings.NewReader(
		`{"artifactToken":"t","platform":"android","version":"1.3.1","buildNumber":27,"releaseNotes":{"zh-CN":"写成了字符串"},"mandatory":false}`,
	))

	(&server{}).createReleaseFromArtifact(context)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d body %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("problem body must be JSON: %v", err)
	}
	if body["code"] != "INVALID_RELEASE_NOTES" {
		t.Fatalf("expected INVALID_RELEASE_NOTES, got %v", body["code"])
	}
}
