package signer

import (
	"archive/zip"
	"bytes"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

// TrialPackageName 是试签包的包名。故意不是任何租户的包名（.invalid 是保留域名），
// 所以即使试签包流出去，也不能被当成租户 App 的升级包安装。
const TrialPackageName = "invalid.rnsigner.trial"

// BuildTrialAPK 现场合成一个最小的未签名 APK：只有 AndroidManifest.xml，没有代码
// （hasCode=false）、没有权限、testOnly。它只用来证明"这把密钥能被 apksigner 用来签名，
// 签出来的证书是确认过的那张"。
func BuildTrialAPK(minSDK int64) ([]byte, error) {
	manifest, err := axml.Encode(&axml.Node{
		Name: "manifest",
		Attrs: []axml.Attr{
			axml.AndroidAttr("versionCode", axml.IntValue(1)),
			axml.AndroidAttr("versionName", axml.StringValue("trial")),
			{Name: "package", Value: axml.StringValue(TrialPackageName)},
		},
		Children: []*axml.Node{
			{Name: "uses-sdk", Attrs: []axml.Attr{
				axml.AndroidAttr("minSdkVersion", axml.IntValue(minSDK)),
				axml.AndroidAttr("targetSdkVersion", axml.IntValue(minSDK)),
			}},
			{Name: "application", Attrs: []axml.Attr{
				axml.AndroidAttr("hasCode", axml.BoolValue(false)),
				axml.AndroidAttr("testOnly", axml.BoolValue(true)),
				axml.AndroidAttr("allowBackup", axml.BoolValue(false)),
			}},
		},
	})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	header := &zip.FileHeader{Name: "AndroidManifest.xml", Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	fw, err := w.CreateHeader(header)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(manifest); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
