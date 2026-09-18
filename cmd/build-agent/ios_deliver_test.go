package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
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

// realBinaryInfoPlist 是 Python plistlib 产出的真二进制 plist（bplist00），
// 里面既有字符串、布尔、整数，也有嵌套字典与数组——Xcode 导出的 Info.plist 就是这个形状。
const realBinaryInfoPlist = "YnBsaXN0MDDZAQIDBAUGBwgJCg8QERITFBUWXENGQnVuZGxlRGVlcF8QEkNGQnVuZGxlSWRlbnRpZmllclxDRkJ1bmRsZU5hbWVfEBRDRkJ1bmRsZU51bWVyaWNUaGluZ18QGkNGQnVuZGxlU2hvcnRWZXJzaW9uU3RyaW5nXxAPQ0ZCdW5kbGVWZXJzaW9uXxASTFNSZXF1aXJlc0lQaG9uZU9TXxAWVUlMYXVuY2hTdG9yeWJvYXJkTmFtZV8QHFVJUmVxdWlyZWREZXZpY2VDYXBhYmlsaXRpZXPRCwxRYdENDlFiUWNfEBVjb20uYW55ZnVuLmZvdW5kYXRpb25WQW55RnVuECpVMS4zLjdSMzMJXFNwbGFzaFNjcmVlbqEXVWFybXY3AAgAGwAoAD0ASgBhAH4AkAClAL4A3QDgAOIA5QDnAOkBAQEIAQoBEAETARQBIQEjAAAAAAAAAgEAAAAAAAAAGAAAAAAAAAAAAAAAAAAAASk="

func TestBinaryPlistReadsWhatXcodeWrites(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(realBinaryInfoPlist)
	if err != nil {
		t.Fatal(err)
	}
	value, err := parseBinaryPlist(raw)
	if err != nil {
		t.Fatalf("a real binary plist was refused: %v", err)
	}
	fields, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("the root is %T", value)
	}
	for key, want := range map[string]string{
		"CFBundleIdentifier":         "com.anyfun.foundation",
		"CFBundleShortVersionString": "1.3.7",
		"CFBundleVersion":            "33",
		"CFBundleName":               "AnyFun",
	} {
		if got := plistString(fields, key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if fields["LSRequiresIPhoneOS"] != true || fields["CFBundleNumericThing"] != int64(42) {
		t.Fatalf("booleans and integers did not survive: %#v", fields)
	}
	if nested := plistDict(plistDict(fields, "CFBundleDeep"), "a"); plistString(nested, "b") != "c" {
		t.Fatalf("nested dictionaries did not survive: %#v", fields["CFBundleDeep"])
	}
	if list, _ := fields["UIRequiredDeviceCapabilities"].([]any); len(list) != 1 || list[0] != "armv7" {
		t.Fatalf("arrays did not survive: %#v", fields["UIRequiredDeviceCapabilities"])
	}
}

// 构造出来的文件不能让解析器打转或读到界外：这个文件来自不可信的一侧。
func TestBinaryPlistRefusesMalformedInput(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(realBinaryInfoPlist)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":        {},
		"not a plist":  []byte("PK\x03\x04 this is a zip"),
		"truncated":    raw[:len(raw)/2],
		"header only":  []byte("bplist00"),
		"no trailer":   raw[:len(raw)-8],
		"bad trailer":  append(append([]byte{}, raw[:len(raw)-16]...), bytes.Repeat([]byte{0xff}, 16)...),
		"zero offsets": append(append([]byte{}, raw[:8]...), bytes.Repeat([]byte{0x00}, 40)...),
	}
	for name, data := range cases {
		if _, err := parseBinaryPlist(data); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

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
