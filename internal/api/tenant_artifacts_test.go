package api

import (
	"strings"
	"testing"
)

func TestBuildObjectKeyIsTenantScopedAndIgnoresUserFilePath(t *testing.T) {
	key := buildObjectKey("release-assets", "tenant_alpha", "artifact_123", "../../恶意.apk")
	if key != "release-assets/tenants/tenant_alpha/artifacts/artifact_123/application.apk" {
		t.Fatalf("unexpected object key: %s", key)
	}
	if strings.Contains(key, "..") || !strings.Contains(key, "/tenant_alpha/") {
		t.Fatalf("unsafe object key: %s", key)
	}
}

func TestProductionStorageURLsRequireHTTPS(t *testing.T) {
	if validStorageURL("http://storage.example.com", false, "production") {
		t.Fatal("production accepted an HTTP storage URL")
	}
	if !validStorageURL("https://storage.example.com", false, "production") {
		t.Fatal("production rejected an HTTPS storage URL")
	}
	if !validStorageURL("", true, "production") {
		t.Fatal("optional URL rejected an empty value")
	}
}

func TestStorageSecretAADChangesAcrossTenantsAndVersions(t *testing.T) {
	first := storageAAD("tenant-a", 1, "secret-key")
	if first == storageAAD("tenant-b", 1, "secret-key") || first == storageAAD("tenant-a", 2, "secret-key") {
		t.Fatal("storage secret associated data is not tenant/version scoped")
	}
}

func TestLegacyUploadedReleaseCannotBePromotedWithoutArtifactVerification(t *testing.T) {
	if _, ok := transitions["verify"]; ok {
		t.Fatal("legacy metadata-only release can still be marked verified")
	}
}
