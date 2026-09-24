package ipa

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 服务端对自助上传 .ipa 的核对：这个包会交到租户手里，所以"它只能交给 App Store"必须是检查
// 出来的，不是假设的——开发、Ad Hoc、企业签名的包都能直接装机。

func writeIPA(t *testing.T, entries map[string]string) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "app.ipa")
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
	if err := os.WriteFile(filePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func infoPlist(bundleID, version, build string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
	<key>CFBundleShortVersionString</key><string>` + version + `</string>
	<key>CFBundleVersion</key><string>` + build + `</string>
</dict></plist>`
}

// profile 造一份描述文件：CMS 外壳用几个二进制字节代替，里面是 XML plist。extra 插进顶层字典，
// entitlements 插进 Entitlements 字典。
func profile(team, bundle, extra, entitlements string) string {
	return "\x30\x82\x10\x00binary-cms-header" + `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>ExpirationDate</key><date>2027-09-20T03:03:38Z</date>
	<key>TeamIdentifier</key><array><string>` + team + `</string></array>
	<key>Entitlements</key><dict>
		<key>application-identifier</key><string>` + team + `.` + bundle + `</string>
		<key>com.apple.developer.team-identifier</key><string>` + team + `</string>
		` + entitlements + `
	</dict>
	` + extra + `
</dict></plist>` + "\x00\x00binary-cms-signature"
}

func storePackage(profileText string, more map[string]string) map[string]string {
	entries := map[string]string{
		"Payload/AnyFun.app/Info.plist":                 infoPlist("com.anyfun.foundation", "1.0.0", "34"),
		"Payload/AnyFun.app/embedded.mobileprovision":   profileText,
		"Payload/AnyFun.app/AnyFun":                     "mach-o",
		"Payload/AnyFun.app/PlugIns/S.appex/Info.plist": infoPlist("com.anyfun.foundation.share", "1.0.0", "34"),
		"SwiftSupport/iphoneos/libswiftCore.dylib":      "dylib",
		"Symbols/ABCD.symbols":                          "symbols",
	}
	for name, body := range more {
		entries[name] = body
	}
	return entries
}

func TestInspectAcceptsAnAppStorePackage(t *testing.T) {
	got, err := Inspect(writeIPA(t, storePackage(profile("J4JDFC8LCC", "com.anyfun.foundation", "", `<key>get-task-allow</key><false/>`), nil)))
	if err != nil {
		t.Fatalf("an App Store package was refused: %v", err)
	}
	if got.Identity != (Identity{BundleID: "com.anyfun.foundation", ShortVersion: "1.0.0", BuildNumber: "34"}) {
		t.Fatalf("identity: %+v", got.Identity)
	}
	if got.Profile.TeamID != "J4JDFC8LCC" || got.Profile.BundleID != "com.anyfun.foundation" ||
		len(got.Profile.TeamIdentifiers) != 1 || got.Profile.ExpiresAt.IsZero() {
		t.Fatalf("profile: %+v", got.Profile)
	}
}

func TestInspectRefusesPackagesThatInstallOutsideTheAppStore(t *testing.T) {
	team, bundle := "J4JDFC8LCC", "com.anyfun.foundation"
	cases := map[string]struct {
		entries map[string]string
		want    string
	}{
		"development":           {storePackage(profile(team, bundle, "", `<key>get-task-allow</key><true/>`), nil), "get-task-allow"},
		"ad hoc":                {storePackage(profile(team, bundle, `<key>ProvisionedDevices</key><array><string>00008030-001</string></array>`, ""), nil), "lists devices"},
		"enterprise":            {storePackage(profile(team, bundle, `<key>ProvisionsAllDevices</key><true/>`, ""), nil), "enterprise"},
		"no profile":            {map[string]string{"Payload/AnyFun.app/Info.plist": infoPlist(bundle, "1.0.0", "34")}, "embedded.mobileprovision"},
		"extra top-level entry": {storePackage(profile(team, bundle, "", ""), map[string]string{"notes/readme.txt": "hi"}), "does not export"},
		"file at the root":      {storePackage(profile(team, bundle, "", ""), map[string]string{"readme.txt": "hi"}), "does not export"},
		"path traversal":        {storePackage(profile(team, bundle, "", ""), map[string]string{"Payload/../evil": "x"}), "unsafe path"},
		"two apps":              {storePackage(profile(team, bundle, "", ""), map[string]string{"Payload/Other.app/Info.plist": infoPlist("com.other", "1.0.0", "1")}), "more than one app"},
	}
	for name, tc := range cases {
		_, err := Inspect(writeIPA(t, tc.entries))
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want it to mention %q)", name, err, tc.want)
		}
	}
}

func TestParseProfileNeedsAnApplicationIdentifier(t *testing.T) {
	if _, err := ParseProfile([]byte("no plist here")); err == nil {
		t.Fatal("a file without a plist was accepted")
	}
	raw := `<?xml version="1.0"?><plist version="1.0"><dict><key>Entitlements</key><dict><key>application-identifier</key><string>nodot</string></dict></dict></plist>`
	if _, err := ParseProfile([]byte(raw)); err == nil {
		t.Fatal("an application-identifier without a team was accepted")
	}
}

// 扩展（share extension、watch app）自己也有 Info.plist，bundle id 是 `<主 id>.<后缀>`。
// 认错了会让一个身份不对的包通过核对。
func TestReadIdentityTakesTheAppNotItsExtensions(t *testing.T) {
	identity, err := ReadIdentity(writeIPA(t, storePackage("unused", nil)))
	if err != nil || identity.BundleID != "com.anyfun.foundation" {
		t.Fatalf("identity: %+v %v", identity, err)
	}
}
