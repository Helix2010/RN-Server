package apkinspect

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/avast/apkverifier"
	"github.com/shogo82148/androidbinary/apk"
)

type Metadata struct {
	PackageName       string
	VersionName       string
	VersionCode       int64
	MinSDK            int
	SHA256            string
	Size              int64
	SignerSHA256      string
	SigningScheme     int
	SignerCertificate string
	RuntimeVersion    string
}

func Inspect(path string) (Metadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("open APK: %w", err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	closeErr := file.Close()
	if err != nil {
		return Metadata{}, fmt.Errorf("hash APK: %w", err)
	}
	if closeErr != nil {
		return Metadata{}, fmt.Errorf("close APK: %w", closeErr)
	}

	parsed, err := apk.OpenFile(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("parse APK manifest: %w", err)
	}
	defer parsed.Close()
	manifest := parsed.Manifest()
	versionName, err := manifest.VersionName.String()
	if err != nil {
		return Metadata{}, fmt.Errorf("read APK versionName: %w", err)
	}
	versionCode, err := manifest.VersionCode.Int32()
	if err != nil || versionCode < 1 {
		return Metadata{}, fmt.Errorf("read APK versionCode: %w", err)
	}
	minSDK, err := manifest.SDK.Min.Int32()
	if err != nil || minSDK < 1 {
		return Metadata{}, fmt.Errorf("read APK minSdkVersion: %w", err)
	}

	verification, err := apkverifier.Verify(path, nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("verify APK signature: %w", err)
	}
	certificateInfo, _ := apkverifier.PickBestApkCert(verification.SignerCerts)
	if certificateInfo == nil {
		return Metadata{}, fmt.Errorf("verify APK signature: signer certificate missing")
	}
	runtimeVersion, err := runtimeVersionFromArchive(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("read Expo runtime version: %w", err)
	}
	return Metadata{
		PackageName:       parsed.PackageName(),
		VersionName:       versionName,
		VersionCode:       int64(versionCode),
		MinSDK:            int(minSDK),
		SHA256:            hex.EncodeToString(hash.Sum(nil)),
		Size:              size,
		SignerSHA256:      certificateInfo.Sha256,
		SigningScheme:     verification.SigningSchemeId,
		SignerCertificate: certificateInfo.Subject,
		RuntimeVersion:    runtimeVersion,
	}, nil
}

func runtimeVersionFromArchive(path string) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("open APK archive: %w", err)
	}
	defer archive.Close()
	for _, entry := range archive.File {
		name := entry.Name
		if !strings.HasSuffix(strings.TrimSuffix(name, "/"), "/assets/fingerprint") && name != "assets/fingerprint" {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("open fingerprint entry: %w", err)
		}
		value, readErr := io.ReadAll(io.LimitReader(reader, 256))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return "", fmt.Errorf("read fingerprint entry")
		}
		runtime := strings.TrimSpace(string(value))
		if runtime == "" {
			return "", fmt.Errorf("fingerprint entry is empty")
		}
		return runtime, nil
	}
	for _, entry := range archive.File {
		if entry.Name != "assets/app.config" && entry.Name != "assets/app.manifest" {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			return "", fmt.Errorf("open app config entry: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(reader, 1024*1024))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil {
			return "", fmt.Errorf("read app config entry")
		}
		var config struct {
			RuntimeVersion string `json:"runtimeVersion"`
		}
		if json.Unmarshal(raw, &config) == nil && strings.TrimSpace(config.RuntimeVersion) != "" {
			return strings.TrimSpace(config.RuntimeVersion), nil
		}
	}
	return "", nil
}
