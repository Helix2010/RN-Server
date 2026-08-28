package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

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
