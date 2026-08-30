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

func TestOTAClientBaselineHeadersRemainOptionalForLegacyClients(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/ota/manifest", nil)
	if got := strings.TrimSpace(request.Header.Get("x-app-version")); got != "" {
		t.Fatalf("legacy request app version = %q", got)
	}
	request.Header.Set("x-app-version", "1.1.8")
	request.Header.Set("x-build-number", "12")
	if request.Header.Get("x-app-version") != "1.1.8" || request.Header.Get("x-build-number") != "12" {
		t.Fatal("OTA baseline headers must preserve APK identity")
	}
}

func TestValidateOTAManifestPackageRequiresMatchingRuntimeAndHashes(t *testing.T) {
	content := []byte("console.log('ok')")
	digest := sha256.Sum256(content)
	manifest := map[string]any{
		"id": "123e4567-e89b-12d3-a456-426614174000", "runtimeVersion": "fingerprint-a", "platform": "android",
		"createdAt":   "2026-08-28T00:00:00Z",
		"extra":       map[string]any{"scopeKey": "anyfun"},
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
