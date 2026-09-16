package policy

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/apk/axml"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

const (
	builderID = "mch_builderTESTTESTTEST"
	jobID     = "bld_jobTESTTESTTESTTEST1"
	certSHA   = "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"
	commitSHA = "0123456789abcdef0123456789abcdef01234567"
	sbomSHA   = "5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a"
)

var builderPub, builderPriv, _ = ed25519.GenerateKey(rand.Reader)

// scenario 描述一次检查：先按 spec 合成包、按包的真实摘要签出处声明，再允许逐项篡改。
type scenario struct {
	spec          func(*apktest.Spec)
	manifest      func(*axml.Node)            // 改清单树
	zip           *apktest.ZipOptions         // 用自定义 ZIP 选项写包
	extraFiles    []apktest.File              // 追加条目（走 zip 选项路径）
	statement     func(*provenance.Statement) // 签名前改声明
	input         func(*Input)                // 改策略输入
	replaceAPK    func(spec apktest.Spec) []byte
	signWith      ed25519.PrivateKey
	expectCode    string
	expectDetails string
}

func buildAPK(t *testing.T, spec apktest.Spec, sc scenario) []byte {
	t.Helper()
	node := apktest.ManifestNode(spec)
	if sc.manifest != nil {
		sc.manifest(node)
	}
	manifest, err := axml.Encode(node)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if sc.zip == nil && sc.extraFiles == nil {
		raw, err := apktest.BuildWithManifest(spec, manifest)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	files, err := apktest.Files(spec, manifest)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, sc.extraFiles...)
	opts := apktest.ZipOptions{Align: true}
	if sc.zip != nil {
		opts = *sc.zip
	}
	raw, err := apktest.WriteZip(files, opts)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func run(t *testing.T, sc scenario) Verdict {
	t.Helper()
	spec := apktest.Default()
	if sc.spec != nil {
		sc.spec(&spec)
	}
	raw := buildAPK(t, spec, sc)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	statement := provenance.Statement{
		Version: provenance.Version, Purpose: provenance.Purpose, JobID: jobID, Attempt: 1,
		TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", VersionCode: 46, VersionName: "1.3.16",
		CommitSHA: commitSHA, UnsignedSHA256: shaHex, UnsignedSize: int64(len(raw)), SBOMSHA256: sbomSHA,
		NativeFingerprint: apktest.DefaultNativeFingerprint, BuilderID: builderID, BuiltAt: "2026-09-16T08:00:00Z",
	}
	if sc.statement != nil {
		sc.statement(&statement)
	}
	key := builderPriv
	if sc.signWith != nil {
		key = sc.signWith
	}
	env, err := provenance.Sign(statement, key)
	if err != nil {
		t.Fatalf("sign statement: %v", err)
	}
	roots := apktest.DefaultRoots()
	roots, err = roots.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	in := Input{
		Version: InputVersion,
		Job: Job{ID: jobID, TenantSlug: "AnyFun", Version: "1.3.16", BuildNumber: 46, Attempt: 1, SignAttempt: 1,
			CommitSHA: commitSHA, UnsignedSHA256: shaHex, UnsignedSize: int64(len(raw)), SBOMSHA256: sbomSHA,
			NativeFingerprint: apktest.DefaultNativeFingerprint},
		Provenance: Provenance{Statement: env.Statement, Signature: env.Signature, BuilderID: builderID,
			BuilderPublicKey: base64.StdEncoding.EncodeToString(builderPub)},
		TrustedBuilders: []TrustedBuilder{{ID: builderID, Ed25519PublicKeySHA256: fingerprint.SHA256Hex(builderPub)}},
		Confirmed: Confirmed{TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", CertificateSHA256: certSHA,
			TrustRoots: roots, MinSDK: 24, TargetSDK: 35, FirstSignMaxVersionCode: 50},
		Signed:  Signed{HasMax: true, MaxVersionCode: 45},
		Limits:  Limits{MaxVersionCodeJump: 100, MaxVersionCode: 10_000_000},
		APKSize: int64(len(raw)),
	}
	if sc.input != nil {
		sc.input(&in)
	}
	if sc.replaceAPK != nil {
		raw = sc.replaceAPK(spec)
		in.APKSize = int64(len(raw))
	}
	path := filepath.Join(t.TempDir(), "unsigned.apk")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	v := EvaluateFile(in, path, apk.DefaultLimits())
	finalSum := sha256.Sum256(raw)
	if v.CheckedSHA256 != hex.EncodeToString(finalSum[:]) {
		t.Fatalf("checkedSha256 %q is not the evaluated file's sha256", v.CheckedSHA256)
	}
	// 结论必须能原样过线协议（JSON）
	if _, err := json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDefaultPackagePasses(t *testing.T) {
	v := run(t, scenario{})
	if !v.OK {
		t.Fatalf("default package rejected: %s %s", v.Code, v.Detail)
	}
	f := v.Facts
	roots, _ := apktest.DefaultRoots().Normalize()
	if f.PackageName != "com.anyfun.foundation" || f.VersionCode != 46 || f.VersionName != "1.3.16" || f.MinSDK != 24 || f.TargetSDK != 36 ||
		f.NativeFingerprint != apktest.DefaultNativeFingerprint || f.NativeFingerprintSource != NativeFingerprintSourceProvenance ||
		f.BuilderID != builderID || f.CommitSHA != commitSHA {
		t.Fatalf("facts: %+v", f)
	}
	// 包里没有 assets/fingerprint：以出处声明为准照常通过
	if v := run(t, scenario{spec: func(s *apktest.Spec) { s.NativeFingerprint = "" }}); !v.OK || v.Facts.NativeFingerprint != apktest.DefaultNativeFingerprint ||
		v.Facts.NativeFingerprintSource != NativeFingerprintSourceProvenance {
		t.Fatalf("package without assets/fingerprint: %+v", v)
	}
	if !trustroots.Equal(f.TrustRoots, roots) {
		t.Fatalf("facts trust roots %+v, want %+v", f.TrustRoots, roots)
	}
	if len(f.Permissions) != len(apktest.AnyfunPermissions)+1 || len(f.PermissionDefinitions) != 1 {
		t.Fatalf("facts permissions: %v / %v", f.Permissions, f.PermissionDefinitions)
	}
	// 首签：没有已签记录，versionCode 不超过首签上限即可
	if v := run(t, scenario{input: func(in *Input) { in.Signed = Signed{} }}); !v.OK {
		t.Fatalf("first signature rejected: %s %s", v.Code, v.Detail)
	}
}

func otherCertificatePEM(t *testing.T) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "evil OTA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func findChild(n *axml.Node, name string) *axml.Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func appConfig(mutate func(extra, updates map[string]any, root map[string]any)) func(*apktest.Spec) {
	return func(s *apktest.Spec) {
		raw, _ := json.Marshal(s.AppConfig)
		var cfg map[string]any
		_ = json.Unmarshal(raw, &cfg)
		mutate(cfg["extra"].(map[string]any), cfg["updates"].(map[string]any), cfg)
		s.AppConfig = cfg
	}
}

// expoMeta 在 <application> 下追加一条 expo-updates 的 meta-data。
func expoMeta(name string, value axml.Value) scenario {
	return scenario{manifest: func(n *axml.Node) {
		app := findChild(n, "application")
		app.Children = append(app.Children, &axml.Node{Name: "meta-data", Attrs: []axml.Attr{
			axml.AndroidAttr("name", axml.StringValue(name)), axml.AndroidAttr("value", value),
		}})
	}, expectCode: "OTA_CONFIGURATION_NOT_ALLOWED"}
}

// 允许列表里的 expo-updates 项，取安全的值时照常通过。
func TestExpoUpdatesAllowedValues(t *testing.T) {
	for name, value := range map[string]axml.Value{
		"expo.modules.updates.CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS": axml.BoolValue(false),
		"expo.modules.updates.DISABLE_ANTI_BRICKING_MEASURES":        axml.BoolValue(false),
		"expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH":          axml.StringValue("ERROR_RECOVERY_ONLY"),
		"expo.modules.updates.EXPO_UPDATES_LAUNCH_WAIT_MS":           axml.IntValue(0),
		"expo.modules.updates.ENABLE_BSDIFF_PATCH_SUPPORT":           axml.BoolValue(true),
		"expo.modules.updates.HAS_EMBEDDED_UPDATE":                   axml.BoolValue(true),
		"expo.modules.updates.EXPO_RUNTIME_VERSION":                  {Type: axml.TypeReference, Data: 0x7f110070},
	} {
		sc := expoMeta(name, value)
		if v := run(t, scenario{manifest: sc.manifest}); !v.OK {
			t.Errorf("%s: rejected %s (%s)", name, v.Code, v.Detail)
		}
	}
}

// 设计「测试 → 签名闸」列出的每一条拒签，外加其余规则。
func TestEveryRuleRejects(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := otherPriv.Public().(ed25519.PublicKey)
	cases := map[string]scenario{
		// ---- 来源（第 2、3 条）----
		"builder not trusted": {input: func(in *Input) { in.TrustedBuilders = nil }, expectCode: "BUILDER_NOT_TRUSTED"},
		"builder key not the pinned one": {input: func(in *Input) {
			in.Provenance.BuilderPublicKey = base64.StdEncoding.EncodeToString(otherPub)
		}, expectCode: "BUILDER_KEY_MISMATCH"},
		"provenance signed by another key": {signWith: otherPriv, expectCode: "PROVENANCE_SIGNATURE_INVALID"},
		"provenance signature tampered": {input: func(in *Input) {
			sig, _ := base64.StdEncoding.DecodeString(in.Provenance.Signature)
			sig[5] ^= 1
			in.Provenance.Signature = base64.StdEncoding.EncodeToString(sig)
		}, expectCode: "PROVENANCE_SIGNATURE_INVALID"},
		"provenance attempt differs from job": {input: func(in *Input) { in.Job.Attempt = 2 }, expectCode: "PROVENANCE_MISMATCH"},
		"provenance versionCode differs":      {statement: func(s *provenance.Statement) { s.VersionCode = 47 }, expectCode: "PROVENANCE_MISMATCH"},
		"provenance for another tenant":       {statement: func(s *provenance.Statement) { s.TenantSlug = "Other" }, expectCode: "PROVENANCE_MISMATCH"},
		"provenance native fingerprint":       {statement: func(s *provenance.Statement) { s.NativeFingerprint = strings.Repeat("a", 40) }, expectCode: "PROVENANCE_MISMATCH"},
		"downloaded package sha256 differs from provenance": {replaceAPK: func(spec apktest.Spec) []byte {
			spec.ExtraEntries = append(spec.ExtraEntries, apktest.File{Name: "assets/extra.txt", Data: []byte("swapped")})
			raw, _ := apktest.Build(spec)
			return raw
		}, expectCode: "UNSIGNED_SHA256_MISMATCH"},

		// ---- 包结构（第 4–6、9 条）----
		"input already has an APK Signing Block": {zip: &apktest.ZipOptions{Align: true, SigningBlock: true}, expectCode: "INPUT_ALREADY_SIGNED"},
		"input already has JAR signature files": {extraFiles: []apktest.File{
			{Name: "META-INF/MANIFEST.MF", Data: []byte("Manifest-Version: 1.0\r\n")},
			{Name: "META-INF/CERT.SF", Data: []byte("Signature-Version: 1.0\r\n")},
			{Name: "META-INF/CERT.RSA", Data: []byte{0x30, 0x00}},
		}, expectCode: "INPUT_ALREADY_SIGNED"},
		"duplicate zip entry":  {zip: &apktest.ZipOptions{Align: true, DuplicateName: "assets/app.config"}, expectCode: "ZIP_DUPLICATE_ENTRY"},
		"not aligned":          {zip: &apktest.ZipOptions{Align: true, Misalign: "resources.arsc"}, expectCode: "NOT_ALIGNED"},
		"native lib not paged": {zip: &apktest.ZipOptions{Align: true, Misalign: "lib/arm64-v8a/libx.so"}, expectCode: "NOT_ALIGNED"},
		"attribute name does not match its resource id": {manifest: func(n *axml.Node) {
			app := findChild(n, "application")
			for i := range app.Attrs {
				if app.Attrs[i].Name == "allowBackup" {
					app.Attrs[i].Name = "debuggable" // 资源 ID 仍是 allowBackup 的
				}
			}
		}, expectCode: "AXML_ATTRIBUTE_ID_MISMATCH"},
		"framework id hidden under an unrelated name": {manifest: func(n *axml.Node) {
			app := findChild(n, "application")
			app.Attrs = append(app.Attrs, axml.Attr{Namespace: axml.AndroidNS, Name: "harmless", ResourceID: axml.AttrDebuggable, Value: axml.BoolValue(true)})
		}, expectCode: "AXML_ATTRIBUTE_ID_MISMATCH"},

		// ---- 身份与版本（第 7、8 条）----
		"versionCodeMajor":             {spec: func(s *apktest.Spec) { s.VersionCodeMajor = true }, expectCode: "VERSION_CODE_MAJOR_PRESENT"},
		"package name not confirmed":   {input: func(in *Input) { in.Confirmed.PackageName = "com.anyfun.other" }, expectCode: "PROVENANCE_MISMATCH"},
		"manifest package differs":     {spec: func(s *apktest.Spec) { s.Package = "com.anyfun.evil" }, expectCode: "PACKAGE_NAME_MISMATCH"},
		"versionName differs":          {spec: func(s *apktest.Spec) { s.VersionName = "1.3.17" }, expectCode: "VERSION_NAME_MISMATCH"},
		"versionCode differs from job": {spec: func(s *apktest.Spec) { s.VersionCode = 47 }, expectCode: "VERSION_CODE_MISMATCH"},
		"versionCode jump too large": {input: func(in *Input) {
			in.Signed = Signed{HasMax: true, MaxVersionCode: 10}
			in.Limits.MaxVersionCodeJump = 20
		}, expectCode: "VERSION_CODE_JUMP_TOO_LARGE"},
		"versionCode above absolute limit": {input: func(in *Input) { in.Limits.MaxVersionCode = 40 }, expectCode: "VERSION_CODE_ABOVE_LIMIT"},
		"versionCode not increasing":       {input: func(in *Input) { in.Signed = Signed{HasMax: true, MaxVersionCode: 46} }, expectCode: "VERSION_CODE_NOT_INCREASING"},
		"first signature above the cap":    {input: func(in *Input) { in.Signed = Signed{}; in.Confirmed.FirstSignMaxVersionCode = 45 }, expectCode: "VERSION_CODE_ABOVE_FIRST_SIGN_LIMIT"},

		// ---- 关键属性（第 10、11 条）----
		"debuggable":                        {spec: func(s *apktest.Spec) { s.Debuggable = true }, expectCode: "DEBUGGABLE"},
		"testOnly":                          {spec: func(s *apktest.Spec) { s.TestOnly = true }, expectCode: "TEST_ONLY"},
		"allowBackup absent":                {spec: func(s *apktest.Spec) { s.AllowBackup = nil }, expectCode: "ALLOW_BACKUP_NOT_FALSE"},
		"allowBackup true":                  {spec: func(s *apktest.Spec) { v := true; s.AllowBackup = &v }, expectCode: "ALLOW_BACKUP_NOT_FALSE"},
		"cleartext traffic":                 {spec: func(s *apktest.Spec) { v := true; s.UsesCleartextTraffic = &v }, expectCode: "CLEARTEXT_TRAFFIC_ALLOWED"},
		"network security config":           {spec: func(s *apktest.Spec) { s.NetworkSecurityConfig = true }, expectCode: "NETWORK_SECURITY_CONFIG_PRESENT"},
		"sharedUserId":                      {spec: func(s *apktest.Spec) { s.SharedUserID = true }, expectCode: "SHARED_USER_ID_PRESENT"},
		"minSdk lowered below confirmed":    {input: func(in *Input) { in.Confirmed.MinSDK = 26; in.Confirmed.TargetSDK = 35 }, expectCode: "MIN_SDK_BELOW_CONFIRMED"},
		"targetSdk lowered below confirmed": {input: func(in *Input) { in.Confirmed.TargetSDK = 37 }, expectCode: "TARGET_SDK_BELOW_CONFIRMED"},

		// ---- 权限（第 12 条）----
		"permission outside the allow list": {spec: func(s *apktest.Spec) {
			s.Permissions = append(s.Permissions, "android.permission.READ_CONTACTS")
		}, expectCode: "PERMISSION_NOT_ALLOWED"},
		"system alert window": {spec: func(s *apktest.Spec) {
			s.Permissions = append(s.Permissions, "android.permission.SYSTEM_ALERT_WINDOW")
		}, expectCode: "PERMISSION_NOT_ALLOWED"},
		"direct-only permission on a store build": {input: func(in *Input) {
			in.Confirmed.TrustRoots.DistributionChannel = "store"
		}, spec: func(s *apktest.Spec) {
			extra := s.AppConfig["extra"].(map[string]any)
			extra["distributionChannel"] = "store"
		}, expectCode: "PERMISSION_NOT_ALLOWED"},
		"another package's dynamic receiver permission": {spec: func(s *apktest.Spec) {
			s.Permissions = append(s.Permissions, apktest.DynamicReceiverPermission("com.other.app"))
		}, expectCode: "PERMISSION_NOT_ALLOWED"},
		"permission definition outside the list": {spec: func(s *apktest.Spec) {
			s.PermissionDefs = append(s.PermissionDefs, apktest.PermissionDef{Name: "com.anyfun.foundation.EXTRA", ProtectionLevel: 2})
		}, expectCode: "PERMISSION_DEFINITION_NOT_ALLOWED"},
		"permission definition not signature-protected": {spec: func(s *apktest.Spec) {
			s.PermissionDefs[0].ProtectionLevel = 0
		}, expectCode: "PERMISSION_DEFINITION_NOT_ALLOWED"},

		// ---- 包内信任根（第 13–15 条）----
		"api base url in the package differs": {spec: appConfig(func(extra, _, _ map[string]any) {
			extra["apiBaseUrl"] = "https://api.evil.example"
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"confirmed api base url differs": {input: func(in *Input) {
			in.Confirmed.TrustRoots.APIBaseURL = "https://api2.anyfun.win"
		}, expectCode: "TRUST_ROOT_MISMATCH"},
		"bootstrap signer address differs": {spec: appConfig(func(extra, _, _ map[string]any) {
			extra["bootstrapSignerAddress"] = "0x" + strings.Repeat("1", 40)
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"bootstrap signer address missing": {spec: appConfig(func(extra, _, _ map[string]any) {
			delete(extra, "bootstrapSignerAddress")
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"application id differs": {spec: appConfig(func(extra, _, _ map[string]any) {
			extra["applicationId"] = "other-app"
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"updates url in app.config differs": {spec: appConfig(func(_, updates, _ map[string]any) {
			updates["url"] = "https://api.evil.example/v1/ota/manifest"
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"updates disabled in app.config": {spec: appConfig(func(_, updates, _ map[string]any) {
			updates["enabled"] = false
		}), expectCode: "TRUST_ROOT_MISMATCH"},
		"native update url meta-data differs": {spec: func(s *apktest.Spec) {
			s.UpdatesURL = "https://api.evil.example/v1/ota/manifest"
		}, expectCode: "TRUST_ROOT_MISMATCH"},
		"native updates disabled": {spec: func(s *apktest.Spec) { v := false; s.UpdatesEnabled = &v }, expectCode: "TRUST_ROOT_MISMATCH"},
		"embedded config missing": {spec: func(s *apktest.Spec) { s.AppConfig = nil }, expectCode: "EMBEDDED_CONFIG_MISSING"},
		"app.manifest expoClient points elsewhere": {extraFiles: nil, spec: func(s *apktest.Spec) {
			raw, _ := json.Marshal(s.AppConfig)
			var client map[string]any
			_ = json.Unmarshal(raw, &client)
			client["extra"].(map[string]any)["apiBaseUrl"] = "https://api.evil.example"
			manifest, _ := json.Marshal(map[string]any{"id": "x", "extra": map[string]any{"expoClient": client}})
			s.ExtraEntries = append(s.ExtraEntries, apktest.File{Name: "assets/app.manifest", Data: manifest, Deflate: true})
		}, expectCode: "TRUST_ROOT_MISMATCH"},
		"ota certificate replaced": {spec: func(s *apktest.Spec) {
			s.OTACertificatePEM = otherCertificatePEM(t)
		}, expectCode: "OTA_CERTIFICATE_MISMATCH"},
		"ota certificate missing": {spec: func(s *apktest.Spec) { s.OTACertificatePEM = "" }, expectCode: "OTA_CERTIFICATE_MISSING"},
		"ota certificate with trailing data": {spec: func(s *apktest.Spec) {
			pem, _ := apktest.DefaultOTACertificate()
			s.OTACertificatePEM = pem + "\nextra"
		}, expectCode: "OTA_CERTIFICATE_MISMATCH"},
		"extra app links host": {spec: func(s *apktest.Spec) {
			s.AppLinksHosts = append(s.AppLinksHosts, "evil.example.com")
		}, expectCode: "TRUST_ROOT_MISMATCH"},
		"app links host changed": {spec: func(s *apktest.Spec) { s.AppLinksHosts = []string{"api.evil.example"} }, expectCode: "TRUST_ROOT_MISMATCH"},
		"extra custom scheme": {spec: func(s *apktest.Spec) {
			s.CustomSchemes = append(s.CustomSchemes, "metamask")
		}, expectCode: "TRUST_ROOT_MISMATCH"},
		"confirmed scheme missing": {spec: func(s *apktest.Spec) { s.CustomSchemes = []string{"exp+anyfun-app"} }, expectCode: "TRUST_ROOT_MISMATCH"},
		"cleartext app link": {manifest: func(n *axml.Node) {
			app := findChild(n, "application")
			activity := findChild(app, "activity")
			filter := &axml.Node{Name: "intent-filter", Children: []*axml.Node{
				{Name: "action", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("android.intent.action.VIEW"))}},
				{Name: "data", Attrs: []axml.Attr{axml.AndroidAttr("scheme", axml.StringValue("http")), axml.AndroidAttr("host", axml.StringValue("api.anyfun.win"))}},
			}}
			activity.Children = append(activity.Children, filter)
		}, expectCode: "CLEARTEXT_APP_LINK"},

		// ---- 不改信任根、却能让它失效的配置 ----
		"upgrade key set": {manifest: func(n *axml.Node) {
			n.Children = append(n.Children, &axml.Node{Name: "key-sets", Children: []*axml.Node{
				{Name: "upgrade-key-set", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("evil"))}},
			}})
		}, expectCode: "MANIFEST_ELEMENT_NOT_ALLOWED"},
		"expo allows unsigned manifests": expoMeta("expo.modules.updates.CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS", axml.BoolValue(true)),
		"expo anti-bricking disabled":    expoMeta("expo.modules.updates.DISABLE_ANTI_BRICKING_MEASURES", axml.BoolValue(true)),
		"expo protocol v0 compatibility": expoMeta("expo.modules.updates.ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE", axml.BoolValue(true)),
		"expo scope key":                 expoMeta("expo.modules.updates.EXPO_SCOPE_KEY", axml.StringValue("https://api.evil.example")),
		"expo unknown key":               expoMeta("expo.modules.updates.SOMETHING_NEW", axml.BoolValue(false)),
		"expo flag as a string":          expoMeta("expo.modules.updates.DISABLE_ANTI_BRICKING_MEASURES", axml.StringValue("false")),
		"expo no embedded update":        expoMeta("expo.modules.updates.HAS_EMBEDDED_UPDATE", axml.BoolValue(false)),

		// ---- 原生指纹（第 16 条）----
		"native fingerprint differs": {spec: func(s *apktest.Spec) { s.NativeFingerprint = strings.Repeat("b", 40) }, expectCode: "NATIVE_FINGERPRINT_MISMATCH"},
		"native fingerprint not hex": {spec: func(s *apktest.Spec) { s.NativeFingerprint = "not-a-fingerprint" }, expectCode: "NATIVE_FINGERPRINT_INVALID"},

		// ---- 输入本身 ----
		"malformed policy input": {input: func(in *Input) { in.Confirmed.TrustRoots.BootstrapSignerAddress = "0xABC" }, expectCode: "POLICY_INPUT_INVALID"},
	}
	for name, sc := range cases {
		t.Run(name, func(t *testing.T) {
			v := run(t, sc)
			if v.OK {
				t.Fatalf("accepted; want %s", sc.expectCode)
			}
			if v.Kind != KindViolation || v.Code != sc.expectCode {
				t.Fatalf("got %s/%s (%s), want violation/%s", v.Kind, v.Code, v.Detail, sc.expectCode)
			}
			if v.Facts != nil {
				t.Fatal("a rejection carries facts")
			}
			if strings.ContainsAny(v.Detail, "\x1b\x00\n") {
				t.Fatalf("detail is not terminal-safe: %q", v.Detail)
			}
		})
	}
}

// 包里读出的字符串进入 detail 时必须转义：控制字符不能原样到达运维终端与控制台。
func TestDetailsQuoteHostileStrings(t *testing.T) {
	v := run(t, scenario{spec: func(s *apktest.Spec) {
		s.Permissions = append(s.Permissions, "android.permission.\x1b[2JEVIL")
	}})
	if v.OK || v.Code != "PERMISSION_NOT_ALLOWED" {
		t.Fatalf("got %+v", v)
	}
	if strings.Contains(v.Detail, "\x1b") || !strings.Contains(v.Detail, `\x1b`) {
		t.Fatalf("detail not escaped: %q", v.Detail)
	}
}

func TestPermissionListIsWellFormed(t *testing.T) {
	list, err := loadPermissions(permissionsJSON)
	if err != nil {
		t.Fatal(err)
	}
	direct := AllowedPermissions("com.anyfun.foundation", "direct")
	store := AllowedPermissions("com.anyfun.foundation", "store")
	if len(direct) != len(list.Allowed)+2 || len(store) != len(list.Allowed)+1 {
		t.Fatalf("direct %d / store %d / base %d", len(direct), len(store), len(list.Allowed))
	}
	for _, bad := range []string{
		`{"comment":"","format":"rn-signer-permissions/v1","allowed":["a","a"],"byChannel":{},"packageScoped":[],"definitions":[]}`,
		`{"comment":"","format":"rn-signer-permissions/v1","allowed":["a"],"byChannel":{},"packageScoped":["x.y"],"definitions":[]}`,
		`{"comment":"","format":"v0","allowed":["a"],"byChannel":{},"packageScoped":[],"definitions":[]}`,
		`{"comment":"","format":"rn-signer-permissions/v1","allowed":["a"],"extra":1}`,
	} {
		if _, err := loadPermissions([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// 允许列表必须与 RN-App 的 ALLOWED_PERMISSIONS / DIRECT_ONLY_PERMISSIONS 一致。
// 设了 RN_APP_DIR（RN-App 检出目录）时逐项核对。
func TestPermissionListMatchesRNApp(t *testing.T) {
	dir := os.Getenv("RN_APP_DIR")
	if dir == "" {
		t.Skip("RN_APP_DIR is not set; skipping the cross-repository permission list check")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "scripts", "lib", "android-release-identity.js"))
	if err != nil {
		t.Fatal(err)
	}
	extract := func(name string) []string {
		src := string(raw)
		start := strings.Index(src, "const "+name+" = [")
		if start < 0 {
			t.Fatalf("%s not found", name)
		}
		body := src[start:]
		body = body[:strings.Index(body, "];")]
		var out []string
		for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(body, -1) {
			out = append(out, m[1])
		}
		return out
	}
	if got, want := strings.Join(permissions.Allowed, ","), strings.Join(extract("ALLOWED_PERMISSIONS"), ","); got != want {
		t.Fatalf("allowed list differs from RN-App:\n signer: %s\n rn-app: %s", got, want)
	}
	if got, want := strings.Join(permissions.ByChannel["direct"], ","), strings.Join(extract("DIRECT_ONLY_PERMISSIONS"), ","); got != want {
		t.Fatalf("direct-only list differs from RN-App: %s vs %s", got, want)
	}
}

func TestValidateInputRejectsServerGarbage(t *testing.T) {
	base := run(t, scenario{})
	if !base.OK {
		t.Fatal("control failed")
	}
	good := Input{Version: InputVersion}
	if err := ValidateInput(good); err == nil {
		t.Fatal("empty input accepted")
	}
	// 确认值的 SDK 下限低于地板：检查进程不替主进程兜底一个过低的确认值
	for name, mutate := range map[string]func(*Input){
		"minSdk 23":    func(in *Input) { in.Confirmed.MinSDK = 23 },
		"targetSdk 27": func(in *Input) { in.Confirmed.TargetSDK = 27 },
		"target < min": func(in *Input) { in.Confirmed.MinSDK, in.Confirmed.TargetSDK = 30, 29 },
	} {
		if v := run(t, scenario{input: mutate}); v.OK || v.Code != "POLICY_INPUT_INVALID" {
			t.Errorf("%s: verdict %+v", name, v)
		}
	}
	if MinSDKFloor != records.MinConfirmedMinSDK || TargetSDKFloor != records.MinConfirmedTargetSDK {
		t.Fatal("policy SDK floors differ from the records floors")
	}
}
