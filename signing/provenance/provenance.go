// Package provenance 是构建出处声明：构建控制进程用本机 Ed25519 出处密钥签名，
// 证明"这个未签名包是我这台受信构建机、在这次认领里交付的"。
//
// 服务端校验一次（签名、与任务行一致），签名闸再独立校验一次：签名闸只认本机 pin 过的
// 构建机公钥指纹，服务端库里登记了谁都不算数。
//
// 签名覆盖的是声明 JSON 的**原始字节**（信封里 base64 保存），不做规范化：验签的一方
// 不重新序列化，也就不存在"两边序列化结果不同"的问题。
package provenance

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

const (
	// Version 是 Statement.Version 唯一允许的值。
	Version = 1
	// Purpose 是 Statement.Purpose 唯一允许的值。
	Purpose = "rn-build-provenance"
	// signingPrefix 是签名输入的域分隔前缀，防止出处密钥签过的别的东西被当成出处声明。
	signingPrefix = "rn-build-provenance/v1\n"

	// MaxStatementSize 是声明原始 JSON 的上限。
	MaxStatementSize = 16 << 10
	maxVersionName   = 64
	maxJobIDLength   = 64
)

var (
	// ErrSignature：签名不对，或信封不是合法的 base64 / 长度。
	ErrSignature = errors.New("provenance: signature does not verify")
	// ErrStatement：签名对，但声明内容不合法。
	ErrStatement = errors.New("provenance: statement is invalid")

	commitPattern            = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	nativeFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// Statement 是出处声明。字段顺序即序列化顺序，JSON 字段名是跨组件契约。
type Statement struct {
	Version           int    `json:"v"`
	Purpose           string `json:"purpose"`
	JobID             string `json:"jobId"`
	Attempt           int    `json:"attempt"`
	TenantSlug        string `json:"tenantSlug"`
	PackageName       string `json:"packageName"`
	VersionCode       int64  `json:"versionCode"`
	VersionName       string `json:"versionName"`
	CommitSHA         string `json:"commitSha"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	UnsignedSize      int64  `json:"unsignedSize"`
	SBOMSHA256        string `json:"sbomSha256"`
	NativeFingerprint string `json:"nativeFingerprint"`
	BuilderID         string `json:"builderId"`
	BuiltAt           string `json:"builtAt"`
}

// Envelope 是签好的声明。
type Envelope struct {
	Statement string `json:"statement"` // base64 std，Statement 的 JSON 原始字节
	Signature string `json:"signature"` // base64 std，Ed25519 签 "rn-build-provenance/v1\n" || statement 原始字节
}

// Validate 检查声明每个字段的格式。
func (s Statement) Validate() error {
	switch {
	case s.Version != Version:
		return fmt.Errorf("v must be %d", Version)
	case s.Purpose != Purpose:
		return errors.New("purpose must be " + Purpose)
	case len(s.JobID) > maxJobIDLength || !ident.ValidServerID(s.JobID):
		return errors.New("jobId is malformed")
	case s.Attempt < 1:
		return errors.New("attempt must be at least 1")
	case !ident.ValidTenantSlug(s.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case !ident.ValidPackageName(s.PackageName):
		return errors.New("packageName is malformed")
	case s.VersionCode < 1 || s.VersionCode > 2100000000:
		return errors.New("versionCode must be between 1 and 2100000000")
	case !validVersionName(s.VersionName):
		return errors.New("versionName is malformed")
	case !commitPattern.MatchString(s.CommitSHA):
		return errors.New("commitSha must be a 40 or 64 character lowercase hex git object id")
	case !fingerprint.Valid(s.UnsignedSHA256):
		return errors.New("unsignedSha256 must be 64 lowercase hex characters")
	case s.UnsignedSize < 1:
		return errors.New("unsignedSize must be positive")
	case !fingerprint.Valid(s.SBOMSHA256):
		return errors.New("sbomSha256 must be 64 lowercase hex characters")
	case !nativeFingerprintPattern.MatchString(s.NativeFingerprint):
		return errors.New("nativeFingerprint must be 32-128 lowercase hex characters")
	case !ident.ValidServerID(s.BuilderID):
		return errors.New("builderId is malformed")
	case !ident.ValidRFC3339UTC(s.BuiltAt):
		return errors.New("builtAt must be an RFC3339 UTC timestamp")
	}
	return nil
}

// versionName 是给人看的版本号，例如 1.3.16。只收可打印 ASCII 且不含空白。
func validVersionName(v string) bool {
	if v == "" || len(v) > maxVersionName || !utf8.ValidString(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] <= 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// Sign 校验声明格式后签名。
func Sign(s Statement, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("provenance: private key must be 64 bytes")
	}
	if err := s.Validate(); err != nil {
		return Envelope{}, fmt.Errorf("provenance: %w", err)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, signingInput(raw))
	return Envelope{
		Statement: base64.StdEncoding.EncodeToString(raw),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify 先验签，再严格解析（未知字段、尾随数据都拒绝），最后校验 v、purpose 与各字段格式。
// 调用方还必须自己比对声明里的任务字段与实际任务、文件是否一致。
func Verify(e Envelope, pub ed25519.PublicKey) (Statement, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Statement{}, errors.New("provenance: public key must be 32 bytes")
	}
	if len(e.Statement) > base64.StdEncoding.EncodedLen(MaxStatementSize) {
		return Statement{}, ErrSignature
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(e.Statement)
	if err != nil || len(raw) == 0 {
		return Statement{}, ErrSignature
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Statement{}, ErrSignature
	}
	if !ed25519.Verify(pub, signingInput(raw), sig) {
		return Statement{}, ErrSignature
	}
	var s Statement
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Statement{}, fmt.Errorf("%w: trailing data after the statement", ErrStatement)
	}
	if err := s.Validate(); err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	return s, nil
}

func signingInput(raw []byte) []byte {
	out := make([]byte, 0, len(signingPrefix)+len(raw))
	out = append(out, signingPrefix...)
	return append(out, raw...)
}
