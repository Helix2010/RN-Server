package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
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

// 评审（2026-09-24）复现过的几种夹带方式：白名单只看最上层目录时，这些都能混进交给租户的包里。
func TestInspectRefusesWhatXcodeWouldNotPutThere(t *testing.T) {
	team, bundle := "J4JDFC8LCC", "com.anyfun.foundation"
	good := profile(team, bundle, "", `<key>get-task-allow</key><false/>`)
	cases := map[string]struct {
		path string
		want string
	}{
		"a file next to the app":      {writeIPA(t, storePackage(good, map[string]string{"Payload/payload.exe": "x"})), "does not export"},
		"a directory next to the app": {writeIPA(t, storePackage(good, map[string]string{"Payload/extra/tool.sh": "x"})), "does not export"},
		"a second app, other case":    {writeIPA(t, storePackage(good, map[string]string{"Payload/Other.APP/Info.plist": infoPlist("com.other", "1.0.0", "1")})), "more than one app"},
		"data in front of the zip":    {prefixed(t, writeIPA(t, storePackage(good, nil))), "does not start with a zip entry"},
		"a symbolic link":             {withSymlink(t, storePackage(good, nil), "Payload/AnyFun.app/link", "/etc/passwd"), "symbolic link"},
		"a duplicated entry":          {withDuplicate(t, storePackage(good, nil), "Payload/AnyFun.app/AnyFun"), "twice"},
		"team identifier mismatch":    {writeIPA(t, storePackage(strings.Replace(good, "<array><string>"+team, "<array><string>ZZ99YY88XX", 1), nil)), "TeamIdentifier"},
	}
	for name, tc := range cases {
		_, err := Inspect(tc.path)
		if err == nil {
			t.Errorf("%s was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want it to mention %q)", name, err, tc.want)
		}
	}
}

// 描述文件是服务端解析的不可信输入：层层嵌套的 <array> 不能把解析它的请求栈撑爆
func TestParseProfileRefusesDeepNesting(t *testing.T) {
	deep := strings.Repeat("<array>", 100) + strings.Repeat("</array>", 100)
	raw := `<?xml version="1.0"?><plist version="1.0"><dict><key>x</key>` + deep +
		`<key>Entitlements</key><dict><key>application-identifier</key><string>J4JDFC8LCC.com.a</string></dict></dict></plist>`
	if _, err := ParseProfile([]byte(raw)); err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("deep nesting was accepted: %v", err)
	}
}

func prefixed(t *testing.T, filePath string) string {
	t.Helper()
	raw, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "prefixed.ipa")
	if err := os.WriteFile(out, append(bytes.Repeat([]byte{'#'}, 32<<10), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func withSymlink(t *testing.T, entries map[string]string, name, target string) string {
	t.Helper()
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for entryName, body := range entries {
		entry, err := archive.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write([]byte(body))
	}
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte(target))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(t.TempDir(), "symlink.ipa")
	if err := os.WriteFile(filePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func withDuplicate(t *testing.T, entries map[string]string, name string) string {
	t.Helper()
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for entryName, body := range entries {
		entry, err := archive.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = entry.Write([]byte(body))
	}
	entry, err := archive.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("second copy"))
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(t.TempDir(), "duplicate.ipa")
	if err := os.WriteFile(filePath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

// DeveloperCertificates 按证书 DER 算 SHA-1，与 `security find-identity` 打印的是同一个值：Mac 装
// 描述文件前拿它核对「这份描述文件包含本租户那张证书」。plist 里的 data 带换行与缩进。
func TestParseProfileHashesTheDeveloperCertificates(t *testing.T) {
	first, second := []byte("first certificate der"), []byte("second certificate der")
	encoded := base64.StdEncoding.EncodeToString(second)
	extra := `<key>DeveloperCertificates</key><array>
		<data>` + base64.StdEncoding.EncodeToString(first) + `</data>
		<data>
		` + encoded[:8] + `
		` + encoded[8:] + `
		</data>
	</array>`
	parsed, err := ParseProfile([]byte(profile("J4JDFC8LCC", "com.anyfun.foundation", extra,
		`<key>aps-environment</key><string>production</string>`)))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{sha1Hex(first), sha1Hex(second)}
	if strings.Join(parsed.DeveloperCertificateSHA1s, ",") != strings.Join(want, ",") {
		t.Fatalf("certificate hashes %v, want %v", parsed.DeveloperCertificateSHA1s, want)
	}
	if parsed.APSEnvironment != "production" {
		t.Errorf("aps-environment %q", parsed.APSEnvironment)
	}

	broken := `<key>DeveloperCertificates</key><array><data>not base64!</data></array>`
	if _, err := ParseProfile([]byte(profile("J4JDFC8LCC", "com.anyfun.foundation", broken, ""))); err == nil {
		t.Fatal("a certificate that is not base64 was skipped instead of refused")
	}
}

func sha1Hex(b []byte) string {
	digest := sha1.Sum(b)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}
