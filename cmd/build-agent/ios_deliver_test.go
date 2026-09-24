package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 控制进程自己读 .ipa 的身份（设计 ios-mac-builders-home-network-2026-09-18 §4.3 第 1 步）。
//
// 这一步在**上传之前**：包一旦进了 App Store Connect 就撤不回来，只能再出一个 build 号
// 顶掉它。交上来的包由执行进程产出，而执行进程跑的是第三方依赖，所以这里用 Go 自己的
// zip 与 plist 解析器，不对这个文件调 unzip / plutil。

func writeIPA(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.ipa")
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for name, body := range entries {
		entry, err := archive.Create(name)
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
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func infoPlistXML(bundleID, version, build string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
	<key>CFBundleShortVersionString</key><string>` + version + `</string>
	<key>CFBundleVersion</key><string>` + build + `</string>
</dict></plist>`
}

func TestReadIPAIdentityTakesTheAppNotItsExtensions(t *testing.T) {
	// 扩展（share extension、watch app）自己也有 Info.plist，bundle id 是 `<主 id>.<后缀>`。
	// 认错了会让一个身份不对的包通过核对
	path := writeIPA(t, map[string]string{
		"Payload/AnyFun.app/Info.plist":                     infoPlistXML("com.anyfun.foundation", "1.3.7", "33"),
		"Payload/AnyFun.app/PlugIns/Share.appex/Info.plist": infoPlistXML("com.anyfun.foundation.share", "9.9.9", "1"),
		"Payload/AnyFun.app/Watch/W.app/Info.plist":         infoPlistXML("com.anyfun.foundation.watch", "9.9.9", "1"),
		"Payload/AnyFun.app/embedded.mobileprovision":       "binary",
	})
	identity, err := readIPAIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.BundleID != "com.anyfun.foundation" || identity.ShortVersion != "1.3.7" || identity.BuildNumber != "33" {
		t.Fatalf("identity: %+v", identity)
	}
}

func TestReadIPAIdentityRefusesPackagesItCannotTrust(t *testing.T) {
	notAZip := filepath.Join(t.TempDir(), "x.ipa")
	if err := os.WriteFile(notAZip, []byte("fake-ipa-0000"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"not a zip":  notAZip,
		"no payload": writeIPA(t, map[string]string{"README.txt": "hello"}),
		"two apps": writeIPA(t, map[string]string{
			"Payload/A.app/Info.plist": infoPlistXML("com.a", "1.0.0", "1"),
			"Payload/B.app/Info.plist": infoPlistXML("com.b", "1.0.0", "1"),
		}),
		"missing keys": writeIPA(t, map[string]string{
			"Payload/A.app/Info.plist": `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleName</key><string>A</string></dict></plist>`,
		}),
		"not a plist": writeIPA(t, map[string]string{"Payload/A.app/Info.plist": "not a plist at all"}),
	} {
		if _, err := readIPAIdentity(path); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// 包的身份必须就是这条任务要的那个。对不上就不交付、更不上传。
func TestCheckIPAMatchesJobRefusesAnotherPackage(t *testing.T) {
	job := mustClaimedJob(t, claimBody("bld_identity00001", "apk"))
	good := ipaIdentity{BundleID: "com.anyfun.foundation", ShortVersion: "1.3.7", BuildNumber: "33"}
	if err := checkIPAMatchesJob(good, job); err != nil {
		t.Fatalf("the job's own package was refused: %v", err)
	}
	for name, identity := range map[string]ipaIdentity{
		"another app":     {BundleID: "com.other.app", ShortVersion: "1.3.7", BuildNumber: "33"},
		"another version": {BundleID: "com.anyfun.foundation", ShortVersion: "1.3.8", BuildNumber: "33"},
		"another build":   {BundleID: "com.anyfun.foundation", ShortVersion: "1.3.7", BuildNumber: "34"},
	} {
		err := checkIPAMatchesJob(identity, job)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "not this job's") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
