package apk_test

import (
	"bytes"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
)

// TestRealReleaseAPK 用线上公开发布的 anyfun 包（RN_SIGNING_TEST_APK 指向它）证明解析器
// 能完整读出真实包的信任根与权限，且严格规则不误伤真实产物。CI 上没有这个文件，跳过。
func TestRealReleaseAPK(t *testing.T) {
	path := os.Getenv("RN_SIGNING_TEST_APK")
	if path == "" {
		t.Skip("RN_SIGNING_TEST_APK is not set")
	}
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	pkg, err := apk.Parse(bytes.NewReader(signed), int64(len(signed)), apk.DefaultLimits())
	if err != nil {
		t.Fatalf("the signed release APK does not parse: %v", err)
	}
	t.Logf("parsed %d bytes, %d entries in %v", len(signed), len(pkg.Entries), time.Since(start))
	if !pkg.SigningBlock {
		t.Fatal("the signed release APK has no signing block?")
	}

	unsigned, err := apktest.StripSigningBlock(signed)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = apk.Parse(bytes.NewReader(unsigned), int64(len(unsigned)), apk.DefaultLimits())
	if err != nil {
		t.Fatalf("the stripped APK does not parse: %v", err)
	}
	if pkg.SigningBlock || pkg.MisalignedCount != 0 || len(pkg.V1SignatureFiles) != 0 {
		t.Fatalf("signing block %v, misaligned %d %+v, v1 files %v", pkg.SigningBlock, pkg.MisalignedCount, pkg.Misaligned, pkg.V1SignatureFiles)
	}

	m := pkg.Manifest
	if m.Package != "com.anyfun.foundation" || m.VersionCode == nil || *m.VersionCode != 46 || m.VersionName == nil || *m.VersionName != "1.3.16" {
		t.Fatalf("identity: package %q versionCode %v versionName %v", m.Package, m.VersionCode, m.VersionName)
	}
	if m.MinSDK == nil || *m.MinSDK != 24 || m.TargetSDK == nil || *m.TargetSDK != 36 {
		t.Fatalf("sdk: %v %v", m.MinSDK, m.TargetSDK)
	}
	if m.VersionCodeMajor || m.SharedUserID {
		t.Fatal("versionCodeMajor or sharedUserId present")
	}
	app := m.Application
	if app == nil || app.AllowBackup == nil || *app.AllowBackup || app.Debuggable || app.TestOnly || app.NetworkSecurityConfig {
		t.Fatalf("application: %+v", app)
	}
	if app.UsesCleartextTraffic != nil {
		t.Fatalf("usesCleartextTraffic is present (%v); the real APK does not declare it", *app.UsesCleartextTraffic)
	}

	// aapt dump badging 列出的 34 条权限（ALLOWED_PERMISSIONS 里的 32 条 + REQUEST_INSTALL_PACKAGES + 按包名生成的一条）
	want := append([]string{}, apktest.AnyfunPermissions...)
	want = append(want, "com.anyfun.foundation.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
	var got []string
	for _, p := range m.UsesPermissions {
		if p.Element != "uses-permission" {
			t.Errorf("unexpected %s %s", p.Element, p.Name)
		}
		got = append(got, p.Name)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") || len(got) != 34 {
		t.Fatalf("permissions differ:\n got %v\nwant %v", got, want)
	}
	if len(m.Permissions) != 1 || m.Permissions[0].Name != "com.anyfun.foundation.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" ||
		m.Permissions[0].ProtectionLevel == nil || *m.Permissions[0].ProtectionLevel != 2 {
		t.Fatalf("permission definitions: %+v", m.Permissions)
	}
	if m.PermissionTrees != 0 || m.PermissionGroups != 0 {
		t.Fatal("permission trees/groups present")
	}

	meta := map[string]apk.MetaData{}
	for _, md := range app.MetaData {
		if _, dup := meta[md.Name]; dup {
			t.Fatalf("duplicate meta-data %s", md.Name)
		}
		meta[md.Name] = md
	}
	cert, ok := meta["expo.modules.updates.CODE_SIGNING_CERTIFICATE"].Value.Str()
	if !ok || !strings.HasPrefix(cert, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("OTA certificate meta-data: %+v", meta["expo.modules.updates.CODE_SIGNING_CERTIFICATE"])
	}
	if url, ok := meta["expo.modules.updates.EXPO_UPDATE_URL"].Value.Str(); !ok || url != "https://api.anyfun.win/v1/ota/manifest" {
		t.Fatalf("EXPO_UPDATE_URL: %q", url)
	}
	if enabled, ok := meta["expo.modules.updates.ENABLED"].Value.Bool(); !ok || !enabled {
		t.Fatal("expo.modules.updates.ENABLED is not true")
	}

	hosts := map[string]bool{}
	schemes := map[string]bool{}
	for _, f := range m.IntentFilters {
		https := false
		for _, s := range f.Schemes {
			if s == "https" || s == "http" {
				https = true
			} else {
				schemes[s] = true
			}
		}
		if https {
			if f.AutoVerify == nil || !*f.AutoVerify {
				t.Errorf("https intent-filter on %s without autoVerify", f.ComponentName)
			}
			for _, h := range f.Hosts {
				hosts[h] = true
			}
		}
	}
	if len(hosts) != 1 || !hosts["api.anyfun.win"] {
		t.Fatalf("app link hosts: %v", hosts)
	}
	if len(schemes) != 2 || !schemes["anyfun"] || !schemes["exp+anyfun-app"] {
		t.Fatalf("custom schemes: %v", schemes)
	}

	c := pkg.AppConfig
	if c == nil {
		t.Fatal("no assets/app.config")
	}
	for name, pair := range map[string][2]*string{
		"apiBaseUrl":             {c.APIBaseURL, ptr("https://api.anyfun.win")},
		"applicationId":          {c.ApplicationID, ptr("dex-mobile")},
		"distributionChannel":    {c.DistributionChannel, ptr("direct")},
		"bootstrapSignerAddress": {c.BootstrapSignerAddress, ptr("0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17")},
		"updates.url":            {c.UpdatesURL, ptr("https://api.anyfun.win/v1/ota/manifest")},
		"scheme":                 {c.Scheme, ptr("anyfun")},
		"slug":                   {c.Slug, ptr("anyfun-app")},
		"android.package":        {c.AndroidPackage, ptr("com.anyfun.foundation")},
	} {
		if pair[0] == nil || *pair[0] != *pair[1] {
			t.Errorf("app.config %s = %v, want %s", name, pair[0], *pair[1])
		}
	}
	if c.UpdatesEnabled == nil || !*c.UpdatesEnabled {
		t.Error("app.config updates.enabled is not true")
	}
	if !pkg.HasAppManifest || pkg.AppManifest != nil {
		t.Errorf("app.manifest: has=%v expoClient=%v (the real one has no extra.expoClient)", pkg.HasAppManifest, pkg.AppManifest != nil)
	}
	// 线上 1.3.16 没有 assets/fingerprint：策略第 16 条要求它存在，这个包过不了那一条
	if pkg.NativeFingerprint != nil {
		t.Errorf("unexpected assets/fingerprint %q", *pkg.NativeFingerprint)
	}
}

func ptr(s string) *string { return &s }
