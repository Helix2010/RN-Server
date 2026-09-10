package apkinspect

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReadEmbeddedConfigReadsRuntimeVersionFromFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	entry, err := archive.Create("assets/fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("89bf81ffce9ae67427199b4aad8579c7455b229b\n")); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readEmbeddedConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeVersion != "89bf81ffce9ae67427199b4aad8579c7455b229b" {
		t.Fatalf("readEmbeddedConfig().RuntimeVersion = %q", got.RuntimeVersion)
	}
}

func TestReadEmbeddedConfigAllowsMissingFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "without-runtime.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readEmbeddedConfig(path)
	if err != nil || got.RuntimeVersion != "" {
		t.Fatalf("readEmbeddedConfig() = %+v, %v", got, err)
	}
}

func TestReadEmbeddedConfigReadsExplicitRuntimeVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "explicit-runtime.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	entry, err := archive.Create("assets/app.config")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(`{"runtimeVersion":"1.1.9"}`)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := readEmbeddedConfig(path)
	if err != nil || got.RuntimeVersion != "1.1.9" {
		t.Fatalf("readEmbeddedConfig() = %+v, %v", got, err)
	}
}

func TestInspectAPKFromEnvironment(t *testing.T) {
	path := os.Getenv("TEST_APK_PATH")
	if path == "" {
		t.Skip("TEST_APK_PATH is not set")
	}
	metadata, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.PackageName == "" || metadata.VersionName == "" || metadata.VersionCode < 1 || metadata.MinSDK < 1 || metadata.SignerSHA256 == "" || metadata.Size < 1 {
		t.Fatalf("incomplete APK metadata: %+v", metadata)
	}
	fmt.Printf("verified APK: package=%s version=%s build=%d runtime=%s minSdk=%d signer=%s scheme=v%d size=%d sha256=%s\n", metadata.PackageName, metadata.VersionName, metadata.VersionCode, metadata.RuntimeVersion, metadata.MinSDK, metadata.SignerSHA256, metadata.SigningScheme, metadata.Size, metadata.SHA256)
}

func TestRejectsNonAPK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-an-apk.apk")
	if err := os.WriteFile(path, []byte("not an apk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err == nil {
		t.Fatal("expected malformed APK to be rejected")
	}
}

func writeArchive(t *testing.T, name string, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for entryName, body := range entries {
		entry, err := archive.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadEmbeddedConfigReadsApplicationIDAndRuntimeInOnePass(t *testing.T) {
	path := writeArchive(t, "with-app-id.apk", map[string]string{
		"assets/fingerprint": "89bf81ffce9ae67427199b4aad8579c7455b229b\n",
		"assets/app.config":  `{"runtimeVersion":"1.2.11","extra":{"applicationId":"dex-mobile","apiBaseUrl":"https://api.example.test"}}`,
	})
	got, err := readEmbeddedConfig(path)
	if err != nil || got.ApplicationID != "dex-mobile" || got.RuntimeVersion != "89bf81ffce9ae67427199b4aad8579c7455b229b" {
		t.Fatalf("readEmbeddedConfig() = %+v, %v", got, err)
	}
}

func TestReadEmbeddedConfigIsEmptyWithoutEmbeddedConfig(t *testing.T) {
	path := writeArchive(t, "without-app-id.apk", map[string]string{"assets/fingerprint": "abc\n"})
	got, err := readEmbeddedConfig(path)
	if err != nil || got.ApplicationID != "" || got.RuntimeVersion != "abc" {
		t.Fatalf("readEmbeddedConfig() = %+v, %v", got, err)
	}
	path = writeArchive(t, "config-without-app-id.apk", map[string]string{"assets/app.config": `{"runtimeVersion":"1.2.11","extra":{}}`})
	got, err = readEmbeddedConfig(path)
	if err != nil || got.ApplicationID != "" || got.RuntimeVersion != "1.2.11" {
		t.Fatalf("readEmbeddedConfig() without extra.applicationId = %+v, %v", got, err)
	}
}

func TestReadEmbeddedConfigRejectsCorruptConfigInsteadOfTreatingItAsMissing(t *testing.T) {
	path := writeArchive(t, "corrupt-config.apk", map[string]string{"assets/app.config": `{"runtimeVersion":`})
	_, err := readEmbeddedConfig(path)
	if !errors.Is(err, ErrEmbeddedConfigInvalid) {
		t.Fatalf("corrupt embedded config must surface ErrEmbeddedConfigInvalid, got %v", err)
	}
}
