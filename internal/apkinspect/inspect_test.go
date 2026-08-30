package apkinspect

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeVersionFromArchive(t *testing.T) {
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
	got, err := runtimeVersionFromArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "89bf81ffce9ae67427199b4aad8579c7455b229b" {
		t.Fatalf("runtimeVersionFromArchive() = %q", got)
	}
}

func TestRuntimeVersionFromArchiveAllowsMissingFingerprint(t *testing.T) {
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
	got, err := runtimeVersionFromArchive(path)
	if err != nil || got != "" {
		t.Fatalf("runtimeVersionFromArchive() = %q, %v", got, err)
	}
}

func TestRuntimeVersionFromArchiveReadsExplicitRuntimeVersion(t *testing.T) {
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

	got, err := runtimeVersionFromArchive(path)
	if err != nil || got != "1.1.9" {
		t.Fatalf("runtimeVersionFromArchive() = %q, %v", got, err)
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
