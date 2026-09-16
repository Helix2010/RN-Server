package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// TestRealReleaseAgainstPolicy 用线上 anyfun 包（剥掉签名后当未签名包）跑完整策略，确认值取
// anyfun 的真实信任根。检查按规则顺序执行、第一处不过即返回；线上包没有 assets/fingerprint，
// 所以期望的唯一拒签是最后一条 NATIVE_FINGERPRINT_MISSING——它说明第 2–15 条（出处、结构、
// 对齐、身份、属性、34 个权限、内嵌配置、OTA 证书、App Links、scheme）对真实包全部通过。
func TestRealReleaseAgainstPolicy(t *testing.T) {
	path := os.Getenv("RN_SIGNING_TEST_APK")
	if path == "" {
		t.Skip("RN_SIGNING_TEST_APK is not set")
	}
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := apktest.StripSigningBlock(signed)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := apk.Parse(bytes.NewReader(raw), int64(len(raw)), apk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var otaPEM string
	for _, md := range pkg.Manifest.Application.MetaData {
		if md.Name == metaCodeSigningCertificate {
			otaPEM, _ = md.Value.Str()
		}
	}
	der, err := singleCertificate(otaPEM)
	if err != nil {
		t.Fatalf("the real OTA certificate does not parse: %v", err)
	}
	roots, err := trustroots.Roots{
		APIBaseURL: "https://api.anyfun.win", OTACertificateSHA256: fingerprint.SHA256Hex(der),
		BootstrapSignerAddress: "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17", AppLinksHosts: []string{"api.anyfun.win"},
		Scheme: "anyfun", DistributionChannel: "direct", ApplicationID: "dex-mobile",
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	fp := strings.Repeat("ab", 20)
	statement := provenance.Statement{Version: provenance.Version, Purpose: provenance.Purpose, JobID: jobID, Attempt: 1,
		TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", VersionCode: 46, VersionName: "1.3.16", CommitSHA: commitSHA,
		UnsignedSHA256: shaHex, UnsignedSize: int64(len(raw)), SBOMSHA256: sbomSHA, NativeFingerprint: fp, BuilderID: builderID,
		BuiltAt: "2026-09-16T08:00:00Z"}
	env, err := provenance.Sign(statement, priv)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{
		Version: InputVersion,
		Job: Job{ID: jobID, TenantSlug: "AnyFun", Version: "1.3.16", BuildNumber: 46, Attempt: 1, SignAttempt: 1, CommitSHA: commitSHA,
			UnsignedSHA256: shaHex, UnsignedSize: int64(len(raw)), SBOMSHA256: sbomSHA, NativeFingerprint: fp},
		Provenance:      Provenance{Statement: env.Statement, Signature: env.Signature, BuilderID: builderID, BuilderPublicKey: base64.StdEncoding.EncodeToString(pub)},
		TrustedBuilders: []TrustedBuilder{{ID: builderID, Ed25519PublicKeySHA256: fingerprint.SHA256Hex(pub)}},
		Confirmed: Confirmed{TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", CertificateSHA256: certSHA, TrustRoots: roots,
			MinSDK: 24, TargetSDK: 36, FirstSignMaxVersionCode: 100},
		Signed:  Signed{HasMax: true, MaxVersionCode: 45},
		Limits:  Limits{MaxVersionCodeJump: 100, MaxVersionCode: 10_000_000},
		APKSize: int64(len(raw)),
	}
	file := filepath.Join(t.TempDir(), "anyfun-unsigned.apk")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	v := EvaluateFile(in, file, apk.DefaultLimits())
	if v.OK || v.Code != "NATIVE_FINGERPRINT_MISSING" {
		t.Fatalf("real release: got ok=%v %s (%s); want only NATIVE_FINGERPRINT_MISSING", v.OK, v.Code, v.Detail)
	}
	t.Logf("real release passes rules 2-15; OTA certificate sha256 %s", roots.OTACertificateSHA256)

	// 对照：确认值改一项，就在对应规则上拒签
	for name, tc := range map[string]struct {
		mutate func(*Input)
		code   string
	}{
		"api origin":  {func(in *Input) { in.Confirmed.TrustRoots.APIBaseURL = "https://api2.anyfun.win" }, "TRUST_ROOT_MISMATCH"},
		"ota cert":    {func(in *Input) { in.Confirmed.TrustRoots.OTACertificateSHA256 = strings.Repeat("0", 64) }, "OTA_CERTIFICATE_MISMATCH"},
		"store build": {func(in *Input) { in.Confirmed.TrustRoots.DistributionChannel = "store" }, "PERMISSION_NOT_ALLOWED"},
		"min sdk":     {func(in *Input) { in.Confirmed.MinSDK = 26 }, "MIN_SDK_BELOW_CONFIRMED"},
	} {
		changed := in
		tc.mutate(&changed)
		if v := EvaluateFile(changed, file, apk.DefaultLimits()); v.Code != tc.code {
			t.Errorf("%s: got %s (%s), want %s", name, v.Code, v.Detail, tc.code)
		}
	}
}
