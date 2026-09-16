package apk_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

// FuzzParse：任意输入都不能 panic、不能挂住；失败只能是 *apk.Error。
func FuzzParse(f *testing.F) {
	good, err := apktest.Build(apktest.Default())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(good[:len(good)/2])
	manifestBytes, err := axml.Encode(apktest.ManifestNode(apktest.Default()))
	if err != nil {
		f.Fatal(err)
	}
	fs, err := apktest.Files(apktest.Default(), manifestBytes)
	if err != nil {
		f.Fatal(err)
	}
	if signed, err := apktest.WriteZip(fs, apktest.ZipOptions{Align: true, SigningBlock: true}); err == nil {
		f.Add(signed)
	}
	// 清单不压缩的小包，让变异更容易打到二进制 XML 本身
	if small, err := apktest.WriteZip([]apktest.File{{Name: "AndroidManifest.xml", Data: manifestBytes}}, apktest.ZipOptions{}); err == nil {
		f.Add(small)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		lim := apk.DefaultLimits()
		lim.MaxManifestSize = 1 << 20
		lim.MaxJSONAssetSize = 1 << 20
		pkg, err := apk.Parse(bytes.NewReader(data), int64(len(data)), lim)
		if err != nil {
			var e *apk.Error
			if !errors.As(err, &e) {
				t.Fatalf("non-*apk.Error: %T %v", err, err)
			}
			return
		}
		if pkg.Manifest == nil {
			t.Fatal("success without a manifest")
		}
	})
}
