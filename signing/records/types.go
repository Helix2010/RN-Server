package records

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 记录类型（body.type）。
const (
	typeRole          = "role"
	typeBuilder       = "builder"
	typeBuilderRevoke = "builder-revoke"
	typeTenant        = "tenant"

	typeReserve  = "reserve"
	typeComplete = "complete"
	typeAbandon  = "abandon"
	typeImport   = "import"
	typeBaseline = "baseline"
)

// Role 是本机角色。没有任何角色记录时是备（备永远不签）。
type Role string

const (
	RolePrimary Role = "primary"
	RoleStandby Role = "standby"
)

// RoleChange 的来源。
const (
	RoleModeInitial    = "initial"     // 第一台主，之前没有主
	RoleModeImportFile = "import-file" // 导入了旧主的 signed.jsonl
	RoleModeManual     = "manual"      // 旧主目录没了，运维逐包输入已签最大 versionCode
)

// MaxVersionCode 是 Android versionCode 的上限（int32 正数，Play 的上限是 2100000000）。
const MaxVersionCode = 2100000000

var (
	operatorPattern  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// RoleChange 记录本机角色变化。
type RoleChange struct {
	Role                         Role   `json:"role"`
	Mode                         string `json:"mode"`
	PreviousPrimaryEd25519SHA256 string `json:"previousPrimaryEd25519Sha256"`
	Operator                     string `json:"operator"`
	Reason                       string `json:"reason"`
	At                           string `json:"-"`
}

func (r RoleChange) validate() error {
	if r.Role != RolePrimary && r.Role != RoleStandby {
		return errors.New("role must be primary or standby")
	}
	switch r.Mode {
	case RoleModeInitial, RoleModeManual:
		if r.PreviousPrimaryEd25519SHA256 != "" && !fingerprint.Valid(r.PreviousPrimaryEd25519SHA256) {
			return errors.New("previousPrimaryEd25519Sha256 is malformed")
		}
	case RoleModeImportFile:
		if !fingerprint.Valid(r.PreviousPrimaryEd25519SHA256) {
			return errors.New("previousPrimaryEd25519Sha256 is required when importing a file")
		}
	default:
		return errors.New("mode is unknown")
	}
	return validateOperatorReason(r.Operator, r.Reason)
}

// BuilderTrust 是一台受信构建机。
type BuilderTrust struct {
	BuilderID              string `json:"builderId"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
	Name                   string `json:"name"`
	Operator               string `json:"operator"`
	Note                   string `json:"note"`
	At                     string `json:"-"`
}

func (b BuilderTrust) validate() error {
	switch {
	case !ident.ValidServerID(b.BuilderID):
		return errors.New("builderId is malformed")
	case !fingerprint.Valid(b.Ed25519PublicKeySHA256):
		return errors.New("ed25519PublicKeySha256 must be 64 lowercase hex characters")
	case !ident.ValidMachineName(b.Name):
		return errors.New("name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	case !operatorPattern.MatchString(b.Operator):
		return errors.New("operator must match ^[A-Za-z0-9._@-]{1,64}$")
	case b.Note != "" && !validText(b.Note, 512):
		return errors.New("note must be at most 512 bytes without control characters")
	}
	return nil
}

type builderRevoke struct {
	BuilderID string `json:"builderId"`
	Operator  string `json:"operator"`
	Reason    string `json:"reason"`
}

func (b builderRevoke) validate() error {
	if !ident.ValidServerID(b.BuilderID) {
		return errors.New("builderId is malformed")
	}
	return validateOperatorReason(b.Operator, b.Reason)
}

// Confirmation 是运维对一个 (包名, 证书指纹) 的确认。同一 key 的新确认取代旧的，旧行留作历史。
type Confirmation struct {
	TenantSlug              string           `json:"tenantSlug"`
	PackageName             string           `json:"packageName"`
	CertificateSHA256       string           `json:"certificateSha256"`
	KeyAlias                string           `json:"keyAlias"`
	KeystoreVersion         int64            `json:"keystoreVersion"`
	TrustRoots              trustroots.Roots `json:"trustRoots"`
	TrustRootsDigest        string           `json:"trustRootsDigest"`
	MinSDK                  int64            `json:"minSdk"`
	TargetSDK               int64            `json:"targetSdk"`
	FirstSignMaxVersionCode int64            `json:"firstSignMaxVersionCode"`
	ConfirmedBy             string           `json:"confirmedBy"`
	ConfirmedAt             string           `json:"-"`
}

func (c Confirmation) validate() error {
	switch {
	case !ident.ValidTenantSlug(c.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case !ident.ValidPackageName(c.PackageName):
		return errors.New("packageName is malformed")
	case !fingerprint.Valid(c.CertificateSHA256):
		return errors.New("certificateSha256 must be 64 lowercase hex characters")
	case !ident.ValidKeyAlias(c.KeyAlias):
		return errors.New("keyAlias is malformed")
	case c.KeystoreVersion < 0:
		return errors.New("keystoreVersion must not be negative")
	case c.MinSDK < 1 || c.MinSDK > 1000:
		return errors.New("minSdk must be between 1 and 1000")
	case c.TargetSDK < c.MinSDK || c.TargetSDK > 1000:
		return errors.New("targetSdk must be between minSdk and 1000")
	case c.FirstSignMaxVersionCode < 1 || c.FirstSignMaxVersionCode > MaxVersionCode:
		return errors.New("firstSignMaxVersionCode must be between 1 and 2100000000")
	case !operatorPattern.MatchString(c.ConfirmedBy):
		return errors.New("confirmedBy must match ^[A-Za-z0-9._@-]{1,64}$")
	}
	normalized, err := c.TrustRoots.Normalize()
	if err != nil {
		return fmt.Errorf("trustRoots: %w", err)
	}
	if !trustroots.Equal(normalized, c.TrustRoots) {
		return errors.New("trustRoots must be stored in normalized form")
	}
	digest, err := trustroots.Digest(c.TrustRoots)
	if err != nil || digest != c.TrustRootsDigest {
		return errors.New("trustRootsDigest does not match trustRoots")
	}
	return nil
}

// Reservation 是 signed.jsonl 里一个 (包名, 证书, versionCode) 的当前状态。
type Reservation struct {
	JobID             string `json:"jobId"`
	SignAttempt       int    `json:"signAttempt"`
	TenantSlug        string `json:"tenantSlug"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	VersionCode       int64  `json:"versionCode"`
	UnsignedSHA256    string `json:"unsignedSha256"`

	// 以下由 complete / import 填写
	Status       string `json:"-"` // reserved | completed | abandoned
	SignedSHA256 string `json:"-"`
	ReleaseID    string `json:"-"`
	Source       string `json:"-"` // local | import
	ReservedAt   string `json:"-"`
	UpdatedAt    string `json:"-"`
}

// Reservation.Status 的取值。
const (
	StatusReserved  = "reserved"
	StatusCompleted = "completed"
	StatusAbandoned = "abandoned"
)

func (r Reservation) validateReserve() error {
	switch {
	case !ident.ValidServerID(r.JobID):
		return errors.New("jobId is malformed")
	case r.SignAttempt < 0:
		return errors.New("signAttempt must not be negative")
	case !ident.ValidTenantSlug(r.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case !ident.ValidPackageName(r.PackageName):
		return errors.New("packageName is malformed")
	case !fingerprint.Valid(r.CertificateSHA256):
		return errors.New("certificateSha256 must be 64 lowercase hex characters")
	case r.VersionCode < 1 || r.VersionCode > MaxVersionCode:
		return errors.New("versionCode is out of range")
	case !fingerprint.Valid(r.UnsignedSHA256):
		return errors.New("unsignedSha256 must be 64 lowercase hex characters")
	}
	return nil
}

type completeRecord struct {
	JobID             string `json:"jobId"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	VersionCode       int64  `json:"versionCode"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	SignedSHA256      string `json:"signedSha256"`
	ReleaseID         string `json:"releaseId"`
}

func (c completeRecord) validate() error {
	r := Reservation{JobID: c.JobID, TenantSlug: "x", PackageName: c.PackageName, CertificateSHA256: c.CertificateSHA256, VersionCode: c.VersionCode, UnsignedSHA256: c.UnsignedSHA256}
	if err := r.validateReserve(); err != nil {
		return err
	}
	if !fingerprint.Valid(c.SignedSHA256) {
		return errors.New("signedSha256 must be 64 lowercase hex characters")
	}
	if !releaseIDPattern.MatchString(c.ReleaseID) {
		return errors.New("releaseId is malformed")
	}
	return nil
}

type abandonRecord struct {
	JobID             string `json:"jobId"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	VersionCode       int64  `json:"versionCode"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	Operator          string `json:"operator"`
	Reason            string `json:"reason"`
}

func (a abandonRecord) validate() error {
	r := Reservation{JobID: a.JobID, TenantSlug: "x", PackageName: a.PackageName, CertificateSHA256: a.CertificateSHA256, VersionCode: a.VersionCode, UnsignedSHA256: a.UnsignedSHA256}
	if err := r.validateReserve(); err != nil {
		return err
	}
	return validateOperatorReason(a.Operator, a.Reason)
}

// importRecord 是从旧主签名闸 signed.jsonl 导入的一条仍然有效的预留或完成记录。
type importRecord struct {
	SourceEd25519SHA256 string `json:"sourceEd25519Sha256"`
	SourceSeq           uint64 `json:"sourceSeq"`
	JobID               string `json:"jobId"`
	SignAttempt         int    `json:"signAttempt"`
	TenantSlug          string `json:"tenantSlug"`
	PackageName         string `json:"packageName"`
	CertificateSHA256   string `json:"certificateSha256"`
	VersionCode         int64  `json:"versionCode"`
	UnsignedSHA256      string `json:"unsignedSha256"`
	Status              string `json:"status"`
	SignedSHA256        string `json:"signedSha256"`
	ReleaseID           string `json:"releaseId"`
	Operator            string `json:"operator"`
}

func (i importRecord) validate() error {
	if !fingerprint.Valid(i.SourceEd25519SHA256) {
		return errors.New("sourceEd25519Sha256 is malformed")
	}
	r := Reservation{JobID: i.JobID, SignAttempt: i.SignAttempt, TenantSlug: i.TenantSlug, PackageName: i.PackageName, CertificateSHA256: i.CertificateSHA256, VersionCode: i.VersionCode, UnsignedSHA256: i.UnsignedSHA256}
	if err := r.validateReserve(); err != nil {
		return err
	}
	switch i.Status {
	case StatusReserved:
		if i.SignedSHA256 != "" || i.ReleaseID != "" {
			return errors.New("a reserved import must not carry signedSha256 or releaseId")
		}
	case StatusCompleted:
		if !fingerprint.Valid(i.SignedSHA256) || !releaseIDPattern.MatchString(i.ReleaseID) {
			return errors.New("a completed import needs signedSha256 and releaseId")
		}
	default:
		return errors.New("status must be reserved or completed")
	}
	if !operatorPattern.MatchString(i.Operator) {
		return errors.New("operator is malformed")
	}
	return nil
}

// Baseline 是运维人工输入的"该 (包名, 证书) 已签过的最大 versionCode"（旧主目录丢失时用）。
type Baseline struct {
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	MaxVersionCode    int64  `json:"maxVersionCode"`
	Operator          string `json:"operator"`
	Note              string `json:"note"`
	At                string `json:"-"`
}

func (b Baseline) validate() error {
	switch {
	case !ident.ValidPackageName(b.PackageName):
		return errors.New("packageName is malformed")
	case !fingerprint.Valid(b.CertificateSHA256):
		return errors.New("certificateSha256 must be 64 lowercase hex characters")
	case b.MaxVersionCode < 1 || b.MaxVersionCode > MaxVersionCode:
		return errors.New("maxVersionCode is out of range")
	case !operatorPattern.MatchString(b.Operator):
		return errors.New("operator is malformed")
	case b.Note != "" && !validText(b.Note, 512):
		return errors.New("note must be at most 512 bytes without control characters")
	}
	return nil
}

func validateOperatorReason(operator, reason string) error {
	if !operatorPattern.MatchString(operator) {
		return errors.New("operator must match ^[A-Za-z0-9._@-]{1,64}$")
	}
	if len([]rune(reason)) < 3 || !validText(reason, 512) {
		return errors.New("reason must be 3-512 bytes without control characters")
	}
	return nil
}

// ValidOperator 判断运维名。
func ValidOperator(s string) bool { return operatorPattern.MatchString(s) }

// ValidReason 判断原因文字。
func ValidReason(s string) bool { return validateOperatorReason("x", s) == nil }

// ValidReleaseID 判断服务端返回的发布 id。
func ValidReleaseID(s string) bool { return releaseIDPattern.MatchString(s) }
