package apkinspect

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

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
	fmt.Printf("verified APK: package=%s version=%s build=%d minSdk=%d signer=%s scheme=v%d size=%d sha256=%s\n", metadata.PackageName, metadata.VersionName, metadata.VersionCode, metadata.MinSDK, metadata.SignerSHA256, metadata.SigningScheme, metadata.Size, metadata.SHA256)
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
