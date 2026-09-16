// Package testfixture 为签名闸与检查进程的测试合成一次"构建机交付"：未签名 APK、
// 构建机出处密钥与签好的出处声明、以及与之一致的策略输入。只给测试用。
package testfixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/policy"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 固定值。
const (
	TenantSlug  = "AnyFun"
	PackageName = "com.anyfun.foundation"
	VersionName = "1.3.16"
	BuilderID   = "mch_builderFIXTUREFIXTURE"
	CommitSHA   = "0123456789abcdef0123456789abcdef01234567"
	SBOMSHA256  = "5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a5b0a"
)

// Builder 是一台构建机的出处密钥。
type Builder struct {
	ID   string
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// NewBuilder 生成出处密钥。
func NewBuilder(t testing.TB) Builder {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Builder{ID: BuilderID, Pub: pub, Priv: priv}
}

// SHA256 是构建机公钥指纹。
func (b Builder) SHA256() string { return fingerprint.SHA256Hex(b.Pub) }

// Build 是一次交付。
type Build struct {
	JobID       string
	Attempt     int
	VersionCode int64
	APK         []byte
	SHA256      string
	Statement   provenance.Statement
	Envelope    provenance.Envelope
	Builder     Builder
}

// NewBuild 合成 versionCode 为 vc 的包（mutate 可以改规格），并由 builder 签出处声明。
func NewBuild(t testing.TB, builder Builder, jobID string, vc int64, mutate func(*apktest.Spec)) Build {
	t.Helper()
	spec := apktest.Default()
	spec.VersionCode = vc
	if cfg, ok := spec.AppConfig["android"].(map[string]any); ok {
		cfg["versionCode"] = vc
	}
	if mutate != nil {
		mutate(&spec)
	}
	raw, err := apktest.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	shaHex := hex.EncodeToString(sum[:])
	statement := provenance.Statement{
		Version: provenance.Version, Purpose: provenance.Purpose, JobID: jobID, Attempt: 1,
		TenantSlug: TenantSlug, PackageName: PackageName, VersionCode: vc, VersionName: VersionName,
		CommitSHA: CommitSHA, UnsignedSHA256: shaHex, UnsignedSize: int64(len(raw)), SBOMSHA256: SBOMSHA256,
		NativeFingerprint: apktest.DefaultNativeFingerprint, BuilderID: builder.ID, BuiltAt: "2026-09-16T08:00:00Z",
	}
	env, err := provenance.Sign(statement, builder.Priv)
	if err != nil {
		t.Fatal(err)
	}
	return Build{JobID: jobID, Attempt: 1, VersionCode: vc, APK: raw, SHA256: shaHex, Statement: statement, Envelope: env, Builder: builder}
}

// Roots 是 apktest 默认包里的信任根（规范化后）。
func Roots(t testing.TB) trustroots.Roots {
	t.Helper()
	r, err := apktest.DefaultRoots().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Input 是与这次交付一致、确认值为默认信任根的策略输入。
func (b Build) Input(t testing.TB, certificateSHA256 string) policy.Input {
	t.Helper()
	return policy.Input{
		Version: policy.InputVersion,
		Job: policy.Job{ID: b.JobID, TenantSlug: TenantSlug, Version: VersionName, BuildNumber: b.VersionCode, Attempt: b.Attempt, SignAttempt: 1,
			CommitSHA: CommitSHA, UnsignedSHA256: b.SHA256, UnsignedSize: int64(len(b.APK)), SBOMSHA256: SBOMSHA256,
			NativeFingerprint: apktest.DefaultNativeFingerprint},
		Provenance: policy.Provenance{Statement: b.Envelope.Statement, Signature: b.Envelope.Signature, BuilderID: b.Builder.ID,
			BuilderPublicKey: base64.StdEncoding.EncodeToString(b.Builder.Pub)},
		TrustedBuilders: []policy.TrustedBuilder{{ID: b.Builder.ID, Ed25519PublicKeySHA256: b.Builder.SHA256()}},
		Confirmed: policy.Confirmed{TenantSlug: TenantSlug, PackageName: PackageName, CertificateSHA256: certificateSHA256,
			TrustRoots: Roots(t), MinSDK: 24, TargetSDK: 35, FirstSignMaxVersionCode: 100},
		Limits:  policy.Limits{MaxVersionCodeJump: 100, MaxVersionCode: 10_000_000},
		APKSize: int64(len(b.APK)),
	}
}

// MustJSON 序列化，失败即终止测试。
func MustJSON(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Hex64 返回由字符 c 重复构成的 64 位十六进制串。
func Hex64(c byte) string { return strings.Repeat(string(c), 64) }
