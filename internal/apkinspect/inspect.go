package apkinspect

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	// ApplicationID 是 APK 内嵌 Expo 配置 extra.applicationId（App 的 X-Application-ID）；
	// 没有内嵌配置或配置里没有该字段时为空，由调用方决定是否拒绝
	ApplicationID string
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
	embedded, err := readEmbeddedConfig(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("read embedded Expo config: %w", err)
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
		RuntimeVersion:    embedded.RuntimeVersion,
		ApplicationID:     embedded.ApplicationID,
	}, nil
}

// ErrEmbeddedConfigInvalid：APK 里有内嵌 Expo 配置（assets/app.config 或 app.manifest）但不是合法 JSON。
// 这是构建产物损坏，不是"没有配置"，调用方必须区分开来拒绝，而不是当成字段缺失。
var ErrEmbeddedConfigInvalid = errors.New("embedded Expo config is not valid JSON")

// embeddedConfig 是 APK 内嵌 Expo 配置里服务端关心的两个字段。
type embeddedConfig struct {
	// RuntimeVersion 优先取 expo-updates 打进包里的 assets/fingerprint，其次取配置的 runtimeVersion；都没有为空
	RuntimeVersion string
	// ApplicationID 是 extra.applicationId（App 的 X-Application-ID）；没有内嵌配置或配置里没有该字段时为空
	ApplicationID string
}

// readEmbeddedConfig 只打开一次 zip，读 assets/fingerprint 与 assets/app.config|app.manifest，
// 一次返回 runtimeVersion 与 extra.applicationId。RN-App 构建脚本在复制产物前已校验 applicationId 与
// 租户配置一致，这里读出来是为了让服务端把 OTA 的 extra.applicationId 绑到基线 APK 上。
func readEmbeddedConfig(path string) (embeddedConfig, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return embeddedConfig{}, fmt.Errorf("open APK archive: %w", err)
	}
	defer archive.Close()
	var result embeddedConfig
	var fingerprint *zip.File
	var appConfig *zip.File
	for _, entry := range archive.File {
		name := entry.Name
		switch {
		case fingerprint == nil && (name == "assets/fingerprint" || strings.HasSuffix(strings.TrimSuffix(name, "/"), "/assets/fingerprint")):
			fingerprint = entry
		case appConfig == nil && (name == "assets/app.config" || name == "assets/app.manifest"):
			appConfig = entry
		}
	}
	if fingerprint != nil {
		value, err := readEntry(fingerprint, 256)
		if err != nil {
			return embeddedConfig{}, fmt.Errorf("read fingerprint entry: %w", err)
		}
		result.RuntimeVersion = strings.TrimSpace(string(value))
		if result.RuntimeVersion == "" {
			return embeddedConfig{}, fmt.Errorf("fingerprint entry is empty")
		}
	}
	if appConfig != nil {
		raw, err := readEntry(appConfig, 1024*1024)
		if err != nil {
			return embeddedConfig{}, fmt.Errorf("read app config entry: %w", err)
		}
		var config struct {
			RuntimeVersion string `json:"runtimeVersion"`
			Extra          struct {
				ApplicationID string `json:"applicationId"`
			} `json:"extra"`
		}
		if err := json.Unmarshal(raw, &config); err != nil {
			return embeddedConfig{}, fmt.Errorf("%w: %v", ErrEmbeddedConfigInvalid, err)
		}
		if result.RuntimeVersion == "" {
			result.RuntimeVersion = strings.TrimSpace(config.RuntimeVersion)
		}
		result.ApplicationID = strings.TrimSpace(config.Extra.ApplicationID)
	}
	return result, nil
}

func readEntry(entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(reader, limit))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return raw, nil
}
