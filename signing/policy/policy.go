// Package policy 是签名闸的签名前检查（设计「签名前检查」第 1–17 条里由检查进程负责的部分）。
//
// Evaluate 是纯函数：输入是签名闸主进程按**本机记录**拼好的策略输入（确认过的包名、证书、
// 信任根、SDK 下限、首签上限、受信构建机、已签最大 versionCode、本机上限配置）加上服务端
// 派下来的任务字段与出处信封，以及检查进程自己解析出来的 APK。服务端给的值只用来和包、
// 和出处声明互相比对，决定"签不签"的基准全部来自本机。
//
// 结论只有两种：通过，或违规（任务终态失败）。"暂不能签"（本机未确认、信任根刚改、本机
// 是备）由主进程在拼输入之前判断，不进检查进程。
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// InputVersion 是 Input.Version 唯一允许的值。
const InputVersion = 1

// 确认值里 SDK 下限的最低取值，与 records.MinConfirmedMinSDK / MinConfirmedTargetSDK 一致。
// targetSdk >= 28 时 usesCleartextTraffic 默认 false，第 11 条靠它兜住没有显式声明的包。
const (
	MinSDKFloor    = 24
	TargetSDKFloor = 28
)

// NativeFingerprintSourceProvenance：Facts.NativeFingerprint 来自构建机出处声明。
const NativeFingerprintSourceProvenance = "builder-provenance"

// KindViolation 是检查结论唯一的拒签类型。检查进程不产生"暂不能签"：那由主进程按本机记录
// 判断；让检查进程能报 deferred，等于让一个被不可信 APK 打穿的检查进程把违规降级成无限重试。
const KindViolation = "violation"

// meta-data 名（expo-updates 读 AndroidManifest 里的这几项，不读 assets/app.config）。
const (
	metaCodeSigningCertificate = "expo.modules.updates.CODE_SIGNING_CERTIFICATE"
	metaCodeSigningMetadata    = "expo.modules.updates.CODE_SIGNING_METADATA"
	metaUpdateURL              = "expo.modules.updates.EXPO_UPDATE_URL"
	metaUpdatesEnabled         = "expo.modules.updates.ENABLED"
	metaRequestHeaders         = "expo.modules.updates.UPDATES_CONFIGURATION_REQUEST_HEADERS_KEY"

	// protectionLevel="signature"
	protectionSignature = 2

	expoUpdatesMetaPrefix = "expo.modules.updates."
)

// expoUpdatesMeta 是 expo-updates（android/.../UpdatesConfiguration.kt）读取的 meta-data 允许列表。
// 值为 nil 的项在上面的专门检查里核对；其余项给出允许的字面量。列表之外的
// expo.modules.updates.* 一律拒签：例如 CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS=true 让内嵌 OTA
// 证书形同虚设，DISABLE_ANTI_BRICKING_MEASURES=true 让 JS 在运行时改更新地址与请求头，
// EXPO_SCOPE_KEY 换掉更新的存储作用域。
var expoUpdatesMeta = map[string]func(apk.MetaData) bool{
	metaCodeSigningCertificate:                                                      nil,
	metaCodeSigningMetadata:                                                         nil,
	metaUpdateURL:                                                                   nil,
	metaUpdatesEnabled:                                                              nil,
	metaRequestHeaders:                                                              nil,
	"expo.modules.updates.EXPO_RUNTIME_VERSION":                                     func(md apk.MetaData) bool { return !md.HasResource || md.Value.Type == 0 },
	"expo.modules.updates.EXPO_UPDATES_CHECK_ON_LAUNCH":                             stringIn("ALWAYS", "WIFI_ONLY", "NEVER", "ERROR_RECOVERY_ONLY"),
	"expo.modules.updates.EXPO_UPDATES_LAUNCH_WAIT_MS":                              func(md apk.MetaData) bool { _, ok := md.Value.Int(); return ok && !md.HasResource },
	"expo.modules.updates.ENABLE_BSDIFF_PATCH_SUPPORT":                              literalBool(nil),
	"expo.modules.updates.HAS_EMBEDDED_UPDATE":                                      literalBool(ptrBool(true)),
	"expo.modules.updates.CODE_SIGNING_ALLOW_UNSIGNED_MANIFESTS":                    literalBool(ptrBool(false)),
	"expo.modules.updates.DISABLE_ANTI_BRICKING_MEASURES":                           literalBool(ptrBool(false)),
	"expo.modules.updates.ENABLE_EXPO_UPDATES_PROTOCOL_V0_COMPATIBILITY_MODE":       literalBool(ptrBool(false)),
	"expo.modules.updates.CODE_SIGNING_INCLUDE_MANIFEST_RESPONSE_CERTIFICATE_CHAIN": literalBool(ptrBool(false)),
}

func ptrBool(b bool) *bool { return &b }

// literalBool：布尔字面量；want 不为 nil 时还必须等于它。
func literalBool(want *bool) func(apk.MetaData) bool {
	return func(md apk.MetaData) bool {
		v, ok := md.Value.Bool()
		return ok && !md.HasResource && (want == nil || v == *want)
	}
}

func stringIn(values ...string) func(apk.MetaData) bool {
	return func(md apk.MetaData) bool {
		s, ok := md.Value.Str()
		if !ok || md.HasResource {
			return false
		}
		for _, v := range values {
			if s == v {
				return true
			}
		}
		return false
	}
}

var (
	nativeFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
	expoSlugPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Input 是主进程交给检查进程的策略输入（JSON 一行）。
type Input struct {
	Version         int              `json:"v"`
	Job             Job              `json:"job"`
	Provenance      Provenance       `json:"provenance"`
	TrustedBuilders []TrustedBuilder `json:"trustedBuilders"`
	Confirmed       Confirmed        `json:"confirmed"`
	Signed          Signed           `json:"signed"`
	Limits          Limits           `json:"limits"`
	APKSize         int64            `json:"apkSize"`
}

// Job 是服务端签名认领里的任务字段（不可信，只用于比对）。
type Job struct {
	ID                string `json:"id"`
	TenantSlug        string `json:"tenantSlug"`
	Version           string `json:"version"`
	BuildNumber       int64  `json:"buildNumber"`
	Attempt           int    `json:"attempt"`
	SignAttempt       int    `json:"signAttempt"`
	CommitSHA         string `json:"commitSha"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	UnsignedSize      int64  `json:"unsignedSize"`
	SBOMSHA256        string `json:"sbomSha256"`
	NativeFingerprint string `json:"nativeFingerprint"`
}

// Provenance 是认领里的出处信封与构建机公钥（公钥由本机 pin 的指纹核对）。
type Provenance struct {
	Statement        string `json:"statement"`
	Signature        string `json:"signature"`
	BuilderID        string `json:"builderId"`
	BuilderPublicKey string `json:"builderPublicKey"`
}

// TrustedBuilder 来自本机 trust.jsonl。
type TrustedBuilder struct {
	ID                     string `json:"id"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
}

// Confirmed 来自本机 trust.jsonl 里 (包名, 证书) 的最新确认。
type Confirmed struct {
	TenantSlug              string           `json:"tenantSlug"`
	PackageName             string           `json:"packageName"`
	CertificateSHA256       string           `json:"certificateSha256"`
	TrustRoots              trustroots.Roots `json:"trustRoots"`
	MinSDK                  int64            `json:"minSdk"`
	TargetSDK               int64            `json:"targetSdk"`
	FirstSignMaxVersionCode int64            `json:"firstSignMaxVersionCode"`
}

// Signed 来自本机 signed.jsonl。
type Signed struct {
	HasMax         bool  `json:"hasMax"`
	MaxVersionCode int64 `json:"maxVersionCode"`
}

// Limits 来自签名闸本机配置。
type Limits struct {
	MaxVersionCodeJump int64 `json:"maxVersionCodeJump"`
	MaxVersionCode     int64 `json:"maxVersionCode"`
}

// Verdict 是检查结论（JSON 一行）。
type Verdict struct {
	OK            bool   `json:"ok"`
	Kind          string `json:"kind,omitempty"`
	Code          string `json:"code,omitempty"`
	Detail        string `json:"detail,omitempty"`
	CheckedSHA256 string `json:"checkedSha256,omitempty"`
	Facts         *Facts `json:"facts,omitempty"`
}

// Facts 是检查进程从包里读出的事实。只在通过时完整。
type Facts struct {
	Size                  int64            `json:"size"`
	PackageName           string           `json:"packageName"`
	VersionCode           int64            `json:"versionCode"`
	VersionName           string           `json:"versionName"`
	MinSDK                int64            `json:"minSdk"`
	TargetSDK             int64            `json:"targetSdk"`
	Permissions           []string         `json:"permissions"`
	PermissionDefinitions []string         `json:"permissionDefinitions"`
	TrustRoots            trustroots.Roots `json:"trustRoots"`
	// NativeFingerprint 取自构建机出处声明（Ed25519 签名、已与任务行比对），complete 时原样上报。
	// 包里不一定有 assets/fingerprint（runtimeVersion 走 appVersion 策略时就没有），签名闸无法
	// 从 APK 独立算出原生指纹；包里有的话必须与出处值一致。
	NativeFingerprint       string `json:"nativeFingerprint"`
	NativeFingerprintSource string `json:"nativeFingerprintSource"`
	BuilderID               string `json:"builderId"`
	CommitSHA               string `json:"commitSha"`
}

func violation(code, format string, args ...any) Verdict {
	return Verdict{Kind: KindViolation, Code: code, Detail: fmt.Sprintf(format, args...)}
}

// parseFile 是 apk.ParseFile；测试替换它来确认"出处不过就不解析"。
var parseFile = apk.ParseFile

// EvaluateFile 计算文件 sha256，先核对出处签名与摘要，通过之后才解析 APK 并执行其余检查。
//
// 出处只依赖策略输入与文件摘要，不需要解析。服务端单独被攻破时拿不到受信构建机的签名，
// 它塞过来的任意字节在这里就被拒绝，解析器（最大的攻击面）一个字节都碰不到。
func EvaluateFile(in Input, path string, lim apk.Limits) Verdict {
	sum, size, err := hashFile(path, lim.MaxFileSize)
	if err != nil {
		return violation("APK_UNREADABLE", "the unsigned package could not be read: %v", err)
	}
	statement, v := checkBeforeParsing(in, sum, size)
	if !v.OK {
		v.CheckedSHA256 = sum
		return v
	}
	pkg, parseErr := parseFile(path, lim)
	if pkg != nil && (pkg.SHA256 != sum || pkg.Size != size) {
		// 文件在两次读取之间变了：检查进程自己的临时文件，只可能是故障
		v = violation("APK_UNREADABLE", "the package changed while it was being checked")
	} else {
		v = checkParsed(in, statement, size, pkg, parseErr)
	}
	v.CheckedSHA256 = sum
	return v
}

// Evaluate 对已经解析好的包执行检查（sha256 与大小取自 pkg）。
func Evaluate(in Input, pkg *apk.Package) Verdict {
	statement, v := checkBeforeParsing(in, pkg.SHA256, pkg.Size)
	if v.OK {
		v = checkParsed(in, statement, pkg.Size, pkg, nil)
	}
	v.CheckedSHA256 = pkg.SHA256
	return v
}

func hashFile(path string, limit int64) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	if n > limit {
		return "", n, fmt.Errorf("larger than %d bytes", limit)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// checkBeforeParsing：输入形状、第 2 条出处签名、第 3 条文件摘要与大小。只用策略输入与文件摘要。
func checkBeforeParsing(in Input, sum string, size int64) (provenance.Statement, Verdict) {
	if err := ValidateInput(in); err != nil {
		return provenance.Statement{}, violation("POLICY_INPUT_INVALID", "%v", err)
	}
	statement, v := checkProvenance(in)
	if !v.OK {
		return statement, v
	}
	if sum != statement.UnsignedSHA256 || sum != in.Job.UnsignedSHA256 {
		return statement, violation("UNSIGNED_SHA256_MISMATCH", "the downloaded package sha256 %s does not match the provenance statement (%s) or the job (%s)", sum, statement.UnsignedSHA256, in.Job.UnsignedSHA256)
	}
	if size != statement.UnsignedSize || size != in.Job.UnsignedSize || size != in.APKSize {
		return statement, violation("UNSIGNED_SIZE_MISMATCH", "the downloaded package is %d bytes; the provenance statement says %d and the job says %d", size, statement.UnsignedSize, in.Job.UnsignedSize)
	}
	return statement, pass
}

// checkParsed：出处与摘要通过之后，对解析结果执行其余检查。
func checkParsed(in Input, statement provenance.Statement, size int64, pkg *apk.Package, parseErr error) Verdict {
	// 第 5、9 条：结构（ZIP、二进制 XML）由解析器严格拒绝
	if parseErr != nil {
		var apkErr *apk.Error
		if errors.As(parseErr, &apkErr) {
			return violation(apkErr.Code, "%s", apkErr.Detail)
		}
		return violation("APK_UNPARSEABLE", "the package could not be parsed: %v", parseErr)
	}
	if pkg == nil || pkg.Manifest == nil {
		return violation("MANIFEST_MISSING", "the package has no AndroidManifest.xml")
	}
	facts := &Facts{Size: size, BuilderID: statement.BuilderID, CommitSHA: statement.CommitSHA,
		NativeFingerprint: statement.NativeFingerprint, NativeFingerprintSource: NativeFingerprintSourceProvenance}
	for _, check := range []func(Input, *apk.Package, *Facts) Verdict{
		checkStructure,         // 4、6
		checkIdentity,          // 7、8
		checkAttributes,        // 10、11
		checkPermissions,       // 12
		checkEmbeddedConfig,    // 13
		checkOTACertificate,    // 14
		checkLinks,             // 15
		checkNativeFingerprint, // 16
	} {
		if v := check(in, pkg, facts); !v.OK {
			return v
		}
	}
	return Verdict{OK: true, Facts: facts}
}

var pass = Verdict{OK: true}

// ValidateInput 检查策略输入的形状。主进程拼输入前已经校验过各字段；这里再挡一次，
// 检查进程不假设调用方没写错。
func ValidateInput(in Input) error {
	j := in.Job
	switch {
	case in.Version != InputVersion:
		return fmt.Errorf("input version must be %d", InputVersion)
	case !ident.ValidServerID(j.ID):
		return errors.New("job.id is malformed")
	case !ident.ValidTenantSlug(j.TenantSlug):
		return errors.New("job.tenantSlug is malformed")
	case j.Version == "" || len(j.Version) > 64 || !ident.PrintableASCII(j.Version) || strings.Contains(j.Version, " "):
		return errors.New("job.version is malformed")
	case j.BuildNumber < 1:
		return errors.New("job.buildNumber must be positive")
	case j.Attempt < 1 || j.SignAttempt < 1:
		return errors.New("job.attempt and job.signAttempt must be positive")
	case !fingerprint.Valid(j.UnsignedSHA256) || !fingerprint.Valid(j.SBOMSHA256):
		return errors.New("job sha256 fields are malformed")
	case j.UnsignedSize < 1 || in.APKSize < 1:
		return errors.New("sizes must be positive")
	case !ident.ValidServerID(in.Provenance.BuilderID):
		return errors.New("provenance.builderId is malformed")
	}
	c := in.Confirmed
	switch {
	case !ident.ValidTenantSlug(c.TenantSlug) || !ident.ValidPackageName(c.PackageName) || !fingerprint.Valid(c.CertificateSHA256):
		return errors.New("confirmed identity is malformed")
	case c.MinSDK < MinSDKFloor || c.TargetSDK < c.MinSDK || c.TargetSDK < TargetSDKFloor:
		return fmt.Errorf("confirmed SDK floors must be minSdk >= %d and targetSdk >= max(minSdk, %d)", MinSDKFloor, TargetSDKFloor)
	case c.FirstSignMaxVersionCode < 1:
		return errors.New("confirmed first-sign cap is malformed")
	case in.Limits.MaxVersionCodeJump < 1 || in.Limits.MaxVersionCode < 1:
		return errors.New("limits are malformed")
	case in.Signed.HasMax && in.Signed.MaxVersionCode < 1:
		return errors.New("signed max versionCode is malformed")
	}
	normalized, err := c.TrustRoots.Normalize()
	if err != nil {
		return fmt.Errorf("confirmed trust roots: %w", err)
	}
	if !trustroots.Equal(normalized, c.TrustRoots) {
		return errors.New("confirmed trust roots are not normalized")
	}
	for _, b := range in.TrustedBuilders {
		if !ident.ValidServerID(b.ID) || !fingerprint.Valid(b.Ed25519PublicKeySHA256) {
			return errors.New("trusted builder entry is malformed")
		}
	}
	return nil
}

// ---- 第 2 条：出处 ----

func checkProvenance(in Input) (provenance.Statement, Verdict) {
	var pinned string
	for _, b := range in.TrustedBuilders {
		if b.ID == in.Provenance.BuilderID {
			pinned = b.Ed25519PublicKeySHA256
		}
	}
	if pinned == "" {
		return provenance.Statement{}, violation("BUILDER_NOT_TRUSTED", "builder %s is not trusted on this signing gate (signer trust-builder)", in.Provenance.BuilderID)
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(in.Provenance.BuilderPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || fingerprint.SHA256Hex(pub) != pinned {
		return provenance.Statement{}, violation("BUILDER_KEY_MISMATCH", "the builder public key sent with the job is not the key pinned for builder %s", in.Provenance.BuilderID)
	}
	statement, err := provenance.Verify(provenance.Envelope{Statement: in.Provenance.Statement, Signature: in.Provenance.Signature}, ed25519.PublicKey(pub))
	switch {
	case errors.Is(err, provenance.ErrSignature):
		return statement, violation("PROVENANCE_SIGNATURE_INVALID", "the provenance signature does not verify with the pinned key of builder %s", in.Provenance.BuilderID)
	case err != nil:
		return statement, violation("PROVENANCE_STATEMENT_INVALID", "%v", err)
	}
	j, c := in.Job, in.Confirmed
	mismatch := func(field string) Verdict {
		return violation("PROVENANCE_MISMATCH", "provenance %s does not match the job or the confirmed identity", field)
	}
	switch {
	case statement.JobID != j.ID:
		return statement, mismatch("jobId")
	case statement.Attempt != j.Attempt:
		return statement, mismatch("attempt")
	case statement.TenantSlug != j.TenantSlug || statement.TenantSlug != c.TenantSlug:
		return statement, mismatch("tenantSlug")
	case statement.PackageName != c.PackageName:
		return statement, mismatch("packageName")
	case statement.VersionCode != j.BuildNumber:
		return statement, mismatch("versionCode")
	case statement.VersionName != j.Version:
		return statement, mismatch("versionName")
	case statement.CommitSHA != j.CommitSHA:
		return statement, mismatch("commitSha")
	case statement.UnsignedSHA256 != j.UnsignedSHA256:
		return statement, mismatch("unsignedSha256")
	case statement.UnsignedSize != j.UnsignedSize:
		return statement, mismatch("unsignedSize")
	case statement.SBOMSHA256 != j.SBOMSHA256:
		return statement, mismatch("sbomSha256")
	case statement.NativeFingerprint != j.NativeFingerprint:
		return statement, mismatch("nativeFingerprint")
	case statement.BuilderID != in.Provenance.BuilderID:
		return statement, mismatch("builderId")
	}
	return statement, pass
}

// ---- 第 4、6 条：没有签名、已对齐 ----

func checkStructure(_ Input, pkg *apk.Package, _ *Facts) Verdict {
	if pkg.SigningBlock {
		return violation("INPUT_ALREADY_SIGNED", "the input package carries an APK Signing Block; release builds must be unsigned (did the build fall back to debug signing?)")
	}
	if len(pkg.V1SignatureFiles) > 0 {
		return violation("INPUT_ALREADY_SIGNED", "the input package carries JAR signature files: %s", quoteList(pkg.V1SignatureFiles, 5))
	}
	if pkg.MisalignedCount > 0 {
		var names []string
		for _, m := range pkg.Misaligned {
			names = append(names, fmt.Sprintf("%s@%d/%d", quote(m.Name), m.DataOffset, m.Alignment))
			if len(names) == 5 {
				break
			}
		}
		return violation("NOT_ALIGNED", "%d stored entries are not aligned (zipalign -c -P 16 4): %s", pkg.MisalignedCount, strings.Join(names, ", "))
	}
	return pass
}

// ---- 第 7、8 条：身份与版本 ----

func checkIdentity(in Input, pkg *apk.Package, facts *Facts) Verdict {
	m := pkg.Manifest
	facts.PackageName = m.Package
	if m.Package != in.Confirmed.PackageName {
		return violation("PACKAGE_NAME_MISMATCH", "manifest package %s is not the confirmed package %s", quote(m.Package), in.Confirmed.PackageName)
	}
	if m.VersionName == nil || *m.VersionName != in.Job.Version {
		return violation("VERSION_NAME_MISMATCH", "manifest versionName %s is not the job version %s", quoteOptional(m.VersionName), in.Job.Version)
	}
	facts.VersionName = *m.VersionName
	if m.VersionCodeMajor {
		return violation("VERSION_CODE_MAJOR_PRESENT", "android:versionCodeMajor is not allowed (it moves the effective version beyond every versionCode check)")
	}
	if m.VersionCode == nil {
		return violation("VERSION_CODE_MISSING", "the manifest has no android:versionCode")
	}
	vc := *m.VersionCode
	facts.VersionCode = vc
	if vc != in.Job.BuildNumber {
		return violation("VERSION_CODE_MISMATCH", "manifest versionCode %d is not the job build number %d", vc, in.Job.BuildNumber)
	}
	if vc < 1 || vc > in.Limits.MaxVersionCode {
		return violation("VERSION_CODE_ABOVE_LIMIT", "versionCode %d exceeds this signing gate's absolute limit %d", vc, in.Limits.MaxVersionCode)
	}
	if in.Signed.HasMax {
		if vc <= in.Signed.MaxVersionCode {
			return violation("VERSION_CODE_NOT_INCREASING", "versionCode %d is not greater than %d, the highest already signed for %s with this certificate", vc, in.Signed.MaxVersionCode, in.Confirmed.PackageName)
		}
		if vc-in.Signed.MaxVersionCode > in.Limits.MaxVersionCodeJump {
			return violation("VERSION_CODE_JUMP_TOO_LARGE", "versionCode %d jumps %d past the last signed %d; this signing gate allows at most %d", vc, vc-in.Signed.MaxVersionCode, in.Signed.MaxVersionCode, in.Limits.MaxVersionCodeJump)
		}
	} else if vc > in.Confirmed.FirstSignMaxVersionCode {
		return violation("VERSION_CODE_ABOVE_FIRST_SIGN_LIMIT", "first signature for %s with this certificate: versionCode %d exceeds the cap %d entered at confirmation", in.Confirmed.PackageName, vc, in.Confirmed.FirstSignMaxVersionCode)
	}
	return pass
}

// ---- 第 10、11 条：关键属性与 SDK 下限 ----

func checkAttributes(in Input, pkg *apk.Package, facts *Facts) Verdict {
	m := pkg.Manifest
	app := m.Application
	switch {
	case app == nil:
		return violation("MANIFEST_APPLICATION_MISSING", "the manifest has no <application>")
	case app.Debuggable:
		return violation("DEBUGGABLE", "<application> declares android:debuggable")
	case app.TestOnly:
		return violation("TEST_ONLY", "<application> declares android:testOnly")
	case app.AllowBackup == nil || *app.AllowBackup:
		return violation("ALLOW_BACKUP_NOT_FALSE", "<application> must declare android:allowBackup=\"false\"")
	case app.UsesCleartextTraffic != nil && *app.UsesCleartextTraffic:
		return violation("CLEARTEXT_TRAFFIC_ALLOWED", "<application> declares android:usesCleartextTraffic=\"true\"")
	case app.NetworkSecurityConfig:
		return violation("NETWORK_SECURITY_CONFIG_PRESENT", "<application> declares android:networkSecurityConfig; confirm it on the signing gate before allowing it")
	case m.SharedUserID:
		return violation("SHARED_USER_ID_PRESENT", "<manifest> declares android:sharedUserId")
	}
	if m.MinSDK == nil {
		return violation("MIN_SDK_BELOW_CONFIRMED", "the manifest has no minSdkVersion (Android treats that as 1); the confirmed floor is %d", in.Confirmed.MinSDK)
	}
	minSDK := *m.MinSDK
	targetSDK := minSDK
	if m.TargetSDK != nil {
		targetSDK = *m.TargetSDK
	}
	facts.MinSDK, facts.TargetSDK = minSDK, targetSDK
	if minSDK < in.Confirmed.MinSDK {
		return violation("MIN_SDK_BELOW_CONFIRMED", "minSdkVersion %d is below the confirmed floor %d", minSDK, in.Confirmed.MinSDK)
	}
	if targetSDK < in.Confirmed.TargetSDK {
		return violation("TARGET_SDK_BELOW_CONFIRMED", "targetSdkVersion %d is below the confirmed floor %d", targetSDK, in.Confirmed.TargetSDK)
	}
	return pass
}

// ---- 第 12 条：权限允许列表 ----

func checkPermissions(in Input, pkg *apk.Package, facts *Facts) Verdict {
	m := pkg.Manifest
	allowed := allowedPermissionSet(permissions, in.Confirmed.PackageName, in.Confirmed.TrustRoots.DistributionChannel)
	names := map[string]bool{}
	var rejected []string
	for _, p := range m.UsesPermissions {
		names[p.Name] = true
		if !allowed[p.Name] {
			rejected = append(rejected, p.Name)
		}
	}
	for name := range names {
		facts.Permissions = append(facts.Permissions, name)
	}
	sort.Strings(facts.Permissions)
	if len(rejected) > 0 {
		sort.Strings(rejected)
		return violation("PERMISSION_NOT_ALLOWED", "permissions not on the signing gate allow list for channel %s: %s", in.Confirmed.TrustRoots.DistributionChannel, quoteList(rejected, 10))
	}
	if m.PermissionTrees > 0 || m.PermissionGroups > 0 {
		return violation("PERMISSION_DEFINITION_NOT_ALLOWED", "the manifest declares <permission-tree> or <permission-group>")
	}
	definitions := allowedDefinitionSet(permissions, in.Confirmed.PackageName)
	seen := map[string]bool{}
	for _, def := range m.Permissions {
		if !definitions[def.Name] || seen[def.Name] {
			return violation("PERMISSION_DEFINITION_NOT_ALLOWED", "permission definition %s is not allowed", quote(def.Name))
		}
		seen[def.Name] = true
		if def.ProtectionLevel == nil || *def.ProtectionLevel != protectionSignature {
			return violation("PERMISSION_DEFINITION_NOT_ALLOWED", "permission definition %s must use protectionLevel=\"signature\"", quote(def.Name))
		}
		facts.PermissionDefinitions = append(facts.PermissionDefinitions, def.Name)
	}
	sort.Strings(facts.PermissionDefinitions)
	return pass
}

// ---- 第 13 条：内嵌 Expo 配置 ----

func checkEmbeddedConfig(in Input, pkg *apk.Package, facts *Facts) Verdict {
	if pkg.AppConfig == nil {
		return violation("EMBEDDED_CONFIG_MISSING", "the package has no assets/app.config")
	}
	c := in.Confirmed
	if v := checkExpoConfig("assets/app.config", pkg.AppConfig, c); !v.OK {
		return v
	}
	if pkg.AppManifest != nil {
		if v := checkExpoConfig("assets/app.manifest extra.expoClient", pkg.AppManifest, c); !v.OK {
			return v
		}
	}
	cfg := pkg.AppConfig
	facts.TrustRoots.APIBaseURL = *cfg.APIBaseURL
	facts.TrustRoots.BootstrapSignerAddress = strings.ToLower(*cfg.BootstrapSignerAddress)
	facts.TrustRoots.ApplicationID = *cfg.ApplicationID
	facts.TrustRoots.DistributionChannel = *cfg.DistributionChannel
	facts.TrustRoots.Scheme = *cfg.Scheme

	// expo-updates 原生侧读的是 manifest meta-data，不是 assets/app.config
	meta, v := metaDataByName(pkg.Manifest)
	if !v.OK {
		return v
	}
	var names []string
	for name := range meta {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasPrefix(name, expoUpdatesMetaPrefix) {
			continue
		}
		check, known := expoUpdatesMeta[name]
		if !known {
			return violation("OTA_CONFIGURATION_NOT_ALLOWED", "meta-data %s is not on the signing gate's expo-updates allow list", quote(name))
		}
		if check != nil && !check(meta[name]) {
			return violation("OTA_CONFIGURATION_NOT_ALLOWED", "meta-data %s has a value the signing gate does not allow", quote(name))
		}
	}
	wantURL := trustroots.OTAManifestURL(c.TrustRoots.APIBaseURL)
	if got, ok := metaString(meta, metaUpdateURL); !ok || got != wantURL {
		return trustRootMismatch("meta-data " + metaUpdateURL)
	}
	if enabled, ok := metaBool(meta, metaUpdatesEnabled); !ok || !enabled {
		return trustRootMismatch("meta-data " + metaUpdatesEnabled)
	}
	if _, present := meta[metaRequestHeaders]; present {
		raw, ok := metaString(meta, metaRequestHeaders)
		if !ok {
			return trustRootMismatch("meta-data " + metaRequestHeaders)
		}
		var headers map[string]string
		if err := json.Unmarshal([]byte(raw), &headers); err != nil || headers["x-application-id"] != c.TrustRoots.ApplicationID {
			return trustRootMismatch("meta-data " + metaRequestHeaders + " x-application-id")
		}
	}
	return pass
}

func checkExpoConfig(where string, cfg *apk.ExpoConfig, c Confirmed) Verdict {
	want := c.TrustRoots
	eq := func(field string, got *string, expected string) Verdict {
		if got == nil || *got != expected {
			return trustRootMismatch(where + " " + field)
		}
		return pass
	}
	for _, check := range []func() Verdict{
		func() Verdict { return eq("extra.apiBaseUrl", cfg.APIBaseURL, want.APIBaseURL) },
		func() Verdict {
			if cfg.BootstrapSignerAddress == nil {
				return trustRootMismatch(where + " extra.bootstrapSignerAddress")
			}
			normalized, err := trustroots.NormalizeAddress(*cfg.BootstrapSignerAddress)
			if err != nil || normalized != want.BootstrapSignerAddress {
				return trustRootMismatch(where + " extra.bootstrapSignerAddress")
			}
			return pass
		},
		func() Verdict { return eq("extra.applicationId", cfg.ApplicationID, want.ApplicationID) },
		func() Verdict {
			return eq("extra.distributionChannel", cfg.DistributionChannel, want.DistributionChannel)
		},
		func() Verdict { return eq("updates.url", cfg.UpdatesURL, trustroots.OTAManifestURL(want.APIBaseURL)) },
		func() Verdict {
			if cfg.UpdatesEnabled == nil || !*cfg.UpdatesEnabled {
				return trustRootMismatch(where + " updates.enabled")
			}
			return pass
		},
		func() Verdict { return eq("scheme", cfg.Scheme, want.Scheme) },
		func() Verdict { return eq("android.package", cfg.AndroidPackage, c.PackageName) },
	} {
		if v := check(); !v.OK {
			return v
		}
	}
	return pass
}

func trustRootMismatch(field string) Verdict {
	return violation("TRUST_ROOT_MISMATCH", "%s does not match the trust roots confirmed on this signing gate", field)
}

func metaDataByName(m *apk.Manifest) (map[string]apk.MetaData, Verdict) {
	out := map[string]apk.MetaData{}
	if m.Application == nil {
		return out, pass
	}
	for _, md := range m.Application.MetaData {
		if _, dup := out[md.Name]; dup {
			return nil, violation("MANIFEST_META_DATA_DUPLICATE", "meta-data %s is declared more than once", quote(md.Name))
		}
		out[md.Name] = md
	}
	return out, pass
}

func metaString(meta map[string]apk.MetaData, name string) (string, bool) {
	md, ok := meta[name]
	if !ok || md.HasResource {
		return "", false
	}
	return md.Value.Str()
}

func metaBool(meta map[string]apk.MetaData, name string) (bool, bool) {
	md, ok := meta[name]
	if !ok || md.HasResource {
		return false, false
	}
	return md.Value.Bool()
}

// ---- 第 14 条：内嵌 OTA 证书 ----

func checkOTACertificate(in Input, pkg *apk.Package, facts *Facts) Verdict {
	meta, v := metaDataByName(pkg.Manifest)
	if !v.OK {
		return v
	}
	raw, ok := metaString(meta, metaCodeSigningCertificate)
	if !ok {
		if _, present := meta[metaCodeSigningCertificate]; present {
			return violation("OTA_CERTIFICATE_MISMATCH", "meta-data %s is not a literal string", metaCodeSigningCertificate)
		}
		return violation("OTA_CERTIFICATE_MISSING", "the package does not embed an OTA code-signing certificate (meta-data %s)", metaCodeSigningCertificate)
	}
	der, err := singleCertificate(raw)
	if err != nil {
		return violation("OTA_CERTIFICATE_MISMATCH", "the embedded OTA certificate is unusable: %v", err)
	}
	sum := fingerprint.SHA256Hex(der)
	facts.TrustRoots.OTACertificateSHA256 = sum
	if sum != in.Confirmed.TrustRoots.OTACertificateSHA256 {
		return violation("OTA_CERTIFICATE_MISMATCH", "the embedded OTA certificate sha256 %s is not the confirmed %s", sum, in.Confirmed.TrustRoots.OTACertificateSHA256)
	}
	if _, present := meta[metaCodeSigningMetadata]; present {
		rawMeta, ok := metaString(meta, metaCodeSigningMetadata)
		var parsed struct {
			Alg string `json:"alg"`
		}
		if !ok || json.Unmarshal([]byte(rawMeta), &parsed) != nil || parsed.Alg != "rsa-v1_5-sha256" {
			return violation("OTA_CERTIFICATE_MISMATCH", "meta-data %s must be JSON with alg rsa-v1_5-sha256", metaCodeSigningMetadata)
		}
	}
	return pass
}

// singleCertificate 严格解析：恰好一个 CERTIFICATE PEM 块、前后只有空白、DER 能被 x509 解析。
func singleCertificate(raw string) ([]byte, error) {
	rest := []byte(strings.TrimSpace(raw))
	block, rest := pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("not a PEM CERTIFICATE block")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("extra data after the certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, errors.New("the certificate does not parse")
	}
	return block.Bytes, nil
}

// ---- 第 15 条：App Links 与自定义 scheme ----

func checkLinks(in Input, pkg *apk.Package, facts *Facts) Verdict {
	want := in.Confirmed.TrustRoots
	hosts := map[string]bool{}
	schemes := map[string]bool{}
	for _, f := range pkg.Manifest.IntentFilters {
		web := false
		for _, s := range f.Schemes {
			switch s {
			case "http":
				return violation("CLEARTEXT_APP_LINK", "an intent-filter on %s accepts http links", quote(f.ComponentName))
			case "https":
				web = true
			default:
				schemes[s] = true
			}
		}
		if web {
			if len(f.Hosts) == 0 {
				return trustRootMismatch("an https intent-filter without a host on " + quote(f.ComponentName))
			}
			for _, h := range f.Hosts {
				hosts[h] = true
			}
		}
	}
	var gotHosts []string
	for h := range hosts {
		gotHosts = append(gotHosts, h)
	}
	sort.Strings(gotHosts)
	facts.TrustRoots.AppLinksHosts = gotHosts
	if strings.Join(gotHosts, "\n") != strings.Join(want.AppLinksHosts, "\n") {
		return violation("TRUST_ROOT_MISMATCH", "App Links hosts %s do not match the confirmed %s", quoteList(gotHosts, 8), quoteList(want.AppLinksHosts, 8))
	}
	if !schemes[want.Scheme] {
		return violation("TRUST_ROOT_MISMATCH", "no intent-filter declares the confirmed scheme %s", want.Scheme)
	}
	// expo prebuild 另外生成 exp+<slug>；除此之外不允许任何自定义 scheme
	allowedDevScheme := ""
	if slug := pkg.AppConfig.Slug; slug != nil && expoSlugPattern.MatchString(*slug) {
		allowedDevScheme = "exp+" + *slug
	}
	var extra []string
	for s := range schemes {
		if s != want.Scheme && s != allowedDevScheme {
			extra = append(extra, s)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return violation("TRUST_ROOT_MISMATCH", "custom schemes other than the confirmed %s: %s", want.Scheme, quoteList(extra, 8))
	}
	return pass
}

// ---- 第 16 条：原生指纹 ----
//
// 以出处声明为准（facts 在 evaluate 里已经填好）。设计原本要求从 assets/fingerprint 读出并复核，
// 但 runtimeVersion 走 appVersion 策略的包里没有这个文件，签名闸无法从 APK 独立算出原生指纹。
// 不再要求文件存在；存在时仍必须与出处值一致，不一致说明构建机上报的值和包的实际内容对不上。

func checkNativeFingerprint(_ Input, pkg *apk.Package, facts *Facts) Verdict {
	if pkg.NativeFingerprint == nil {
		return pass
	}
	got := *pkg.NativeFingerprint
	if !nativeFingerprintPattern.MatchString(got) {
		return violation("NATIVE_FINGERPRINT_INVALID", "assets/fingerprint is not a 32-128 character lowercase hex digest")
	}
	if got != facts.NativeFingerprint {
		return violation("NATIVE_FINGERPRINT_MISMATCH", "assets/fingerprint %s is not the native fingerprint in the builder's provenance statement %s", got, quote(facts.NativeFingerprint))
	}
	return pass
}

// ---- 输出清理：包里读出的字符串可能含终端控制字符 ----

func quote(s string) string {
	if len(s) > 128 {
		s = s[:128] + "…"
	}
	return fmt.Sprintf("%q", s)
}

func quoteOptional(s *string) string {
	if s == nil {
		return "(absent)"
	}
	return quote(*s)
}

func quoteList(list []string, max int) string {
	var out []string
	for i, s := range list {
		if i == max {
			out = append(out, fmt.Sprintf("… (%d more)", len(list)-max))
			break
		}
		out = append(out, quote(s))
	}
	if len(out) == 0 {
		return "(none)"
	}
	return strings.Join(out, ", ")
}
