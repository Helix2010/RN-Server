package apkinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

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
	}, nil
}
