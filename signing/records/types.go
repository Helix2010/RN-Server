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
	typeRole           = "role"
	typeBuilder        = "builder"
	typeBuilderRevoke  = "builder-revoke"
	typeTenant         = "tenant"
	typePeer           = "peer"
	typePeerRevoke     = "peer-revoke"
	typeRecovery       = "recovery"
	typeRecoveryRevoke = "recovery-revoke"

	typeReserve  = "reserve"
	typeSigned   = "signed"
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
	// RoleModeEnroll：新机器 signer enroll 写在全新本机记录里的初始角色，一律是备。服务端（控制台）登记的
	// 主备只决定路由，不写进本机记录：主只由本机 signer promote 产生（--first、--import、--manual）。
	RoleModeEnroll = "enroll"
)

// EnrollOperator 是 signer enroll 写进记录的操作者。
const EnrollOperator = "signer-enroll"

// MaxVersionCode 是 Android versionCode 的上限（int32 正数，Play 的上限是 2100000000）。
const MaxVersionCode = 2100000000

var (
	operatorPattern  = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	releaseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	// 与 keystorebox.ValidGenerationRequestID 同一条规则（records 不依赖 keystorebox）
	generationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
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
	case RoleModeEnroll:
		if r.Role != RoleStandby {
			return errors.New("an enrollment role record must be standby: only signer promote on this machine makes it primary")
		}
		if r.PreviousPrimaryEd25519SHA256 != "" {
			return errors.New("an enrollment role record must not name a previous primary")
		}
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

// 信任签名闸与恢复公钥的来源（PeerTrust.Mode、RecoveryTrust.Mode）。
//
// 签名闸之间的信任只有运维在本机 trust-peer 这一个来源：signer enroll 不信任服务端给的任何签名闸。
// 修复之前的开发版本写过 mode "enroll-first-trust"（注册备时首次信任服务端给的主），这种记录现在校验不过。
const (
	// TrustModeOperator：运维在本机粘贴完整指纹，与服务端的值比对一致后写入。
	TrustModeOperator = "operator"
	// TrustModeEnroll：signer enroll 时按运维在安装命令里给的 --recovery-sha256 核对服务端的恢复公钥后写入（只用于恢复公钥）。
	TrustModeEnroll = "enroll"
)

// PeerTrust 是一台受信的签名闸（不含本机：本机默认信任自己）。主签名闸生成密钥时只加密给
// 本机与这些签名闸；备签名闸只接受这些签名闸（或本机）签过生成签名的密钥，主签名闸只接受本机签的。
type PeerTrust struct {
	Name                   string `json:"name"`
	X25519PublicKeySHA256  string `json:"x25519PublicKeySha256"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
	Mode                   string `json:"mode"`
	Operator               string `json:"operator"`
	Note                   string `json:"note"`
	At                     string `json:"-"`
}

func (p PeerTrust) validate() error {
	switch {
	case !ident.ValidMachineName(p.Name):
		return errors.New("name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	case !fingerprint.Valid(p.X25519PublicKeySHA256):
		return errors.New("x25519PublicKeySha256 must be 64 lowercase hex characters")
	case !fingerprint.Valid(p.Ed25519PublicKeySHA256):
		return errors.New("ed25519PublicKeySha256 must be 64 lowercase hex characters")
	case p.Mode != TrustModeOperator:
		return errors.New("mode must be operator (a signing gate is trusted only by signer trust-peer on this machine)")
	case !operatorPattern.MatchString(p.Operator):
		return errors.New("operator must match ^[A-Za-z0-9._@-]{1,64}$")
	case p.Note != "" && !validText(p.Note, 512):
		return errors.New("note must be at most 512 bytes without control characters")
	}
	return nil
}

type peerRevoke struct {
	Name     string `json:"name"`
	Operator string `json:"operator"`
	Reason   string `json:"reason"`
}

func (p peerRevoke) validate() error {
	if !ident.ValidMachineName(p.Name) {
		return errors.New("name is malformed")
	}
	return validateOperatorReason(p.Operator, p.Reason)
}

// RecoveryTrust 是一把受信的离线恢复公钥（只记指纹；公钥从服务端取，按指纹核对）。
type RecoveryTrust struct {
	Name                  string `json:"name"`
	X25519PublicKeySHA256 string `json:"x25519PublicKeySha256"`
	Mode                  string `json:"mode"`
	Operator              string `json:"operator"`
	Note                  string `json:"note"`
	At                    string `json:"-"`
}

func (r RecoveryTrust) validate() error {
	switch {
	case !ident.ValidMachineName(r.Name):
		return errors.New("name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	case !fingerprint.Valid(r.X25519PublicKeySHA256):
		return errors.New("x25519PublicKeySha256 must be 64 lowercase hex characters")
	case r.Mode != TrustModeOperator && r.Mode != TrustModeEnroll:
		return errors.New("mode must be operator or enroll")
	case !operatorPattern.MatchString(r.Operator):
		return errors.New("operator must match ^[A-Za-z0-9._@-]{1,64}$")
	case r.Note != "" && !validText(r.Note, 512):
		return errors.New("note must be at most 512 bytes without control characters")
	}
	return nil
}

type recoveryRevoke struct {
	X25519PublicKeySHA256 string `json:"x25519PublicKeySha256"`
	Operator              string `json:"operator"`
	Reason                string `json:"reason"`
}

func (r recoveryRevoke) validate() error {
	if !fingerprint.Valid(r.X25519PublicKeySHA256) {
		return errors.New("x25519PublicKeySha256 is malformed")
	}
	return validateOperatorReason(r.Operator, r.Reason)
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
	// 以下只有签名闸自动确认（签名闸生成的密钥）时才有；运维 confirm 写的记录没有这些字段，
	// 与旧版本写的记录逐字节同形。
	Mode                   string `json:"mode,omitempty"`
	GenerationRequestID    string `json:"generationRequestId,omitempty"`
	GeneratorName          string `json:"generatorName,omitempty"`
	GeneratorEd25519SHA256 string `json:"generatorEd25519Sha256,omitempty"`
	ConfirmedAt            string `json:"-"`
}

// Confirmation.Mode 的取值。空串是运维在本机 signer confirm。
const (
	// ConfirmModeFirstGeneration：本机（主）生成的密钥，这个包名在本机从没确认过，信任根首次取服务端的值。
	ConfirmModeFirstGeneration = "first-generation"
	// ConfirmModeRegenerated：本机（主）为已确认的包名生成新密钥，沿用原有信任根，只换证书。
	ConfirmModeRegenerated = "regenerated"
	// ConfirmModePeerGenerated：本机信任的另一台签名闸生成、生成签名验证通过的密钥（首次信任或沿用信任根）。
	ConfirmModePeerGenerated = "peer-generated"

	autoConfirmedByPrefix = "auto:"
)

// AutoConfirmedBy 返回自动确认写进 confirmedBy 的值：auto:first-generation、auto:regenerated、
// auto:peer-generated:<生成者机器名>。运维名不允许冒号，两者不会混淆。
func AutoConfirmedBy(mode, generatorName string) string {
	if mode == ConfirmModePeerGenerated {
		return autoConfirmedByPrefix + mode + ":" + generatorName
	}
	return autoConfirmedByPrefix + mode
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
	case c.MinSDK < MinConfirmedMinSDK || c.MinSDK > 1000:
		return fmt.Errorf("minSdk must be between %d and 1000", MinConfirmedMinSDK)
	case c.TargetSDK < c.MinSDK || c.TargetSDK < MinConfirmedTargetSDK || c.TargetSDK > 1000:
		return fmt.Errorf("targetSdk must be at least minSdk and %d, and at most 1000", MinConfirmedTargetSDK)
	case c.FirstSignMaxVersionCode < 1 || c.FirstSignMaxVersionCode > MaxVersionCode:
		return errors.New("firstSignMaxVersionCode must be between 1 and 2100000000")
	}
	switch c.Mode {
	case "":
		if !operatorPattern.MatchString(c.ConfirmedBy) {
			return errors.New("confirmedBy must match ^[A-Za-z0-9._@-]{1,64}$")
		}
		if c.GenerationRequestID != "" || c.GeneratorName != "" || c.GeneratorEd25519SHA256 != "" {
			return errors.New("an operator confirmation must not carry generation fields")
		}
	case ConfirmModeFirstGeneration, ConfirmModeRegenerated, ConfirmModePeerGenerated:
		switch {
		case !generationRequestIDPattern.MatchString(c.GenerationRequestID):
			return errors.New("generationRequestId is malformed")
		case !ident.ValidMachineName(c.GeneratorName):
			return errors.New("generatorName is malformed")
		case !fingerprint.Valid(c.GeneratorEd25519SHA256):
			return errors.New("generatorEd25519Sha256 must be 64 lowercase hex characters")
		case c.ConfirmedBy != AutoConfirmedBy(c.Mode, c.GeneratorName):
			return errors.New("confirmedBy does not match the automatic confirmation mode")
		}
	default:
		return errors.New("mode is unknown")
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

	// 以下由 signed / complete / import 填写
	Status       string `json:"-"` // reserved | signed | completed | abandoned
	SignedSHA256 string `json:"-"`
	ReleaseID    string `json:"-"`
	Source       string `json:"-"` // local | import
	ReservedAt   string `json:"-"`
	UpdatedAt    string `json:"-"`
}

// Reservation.Status 的取值。
//
//	reserved  预留已落盘，还没有签出任何东西（apksigner 可能跑过，但输出只在本机工作目录，
//	          启动时清空，从未离开本机）——可以释放
//	signed    已签名并复核，签名包 sha256 已落盘，随后才上传——不能释放：服务端可能已经拿到它
//	completed 服务端确认完成，记下发布 id
//	abandoned 已释放（运维 abandon，或签名闸在记下签名包之前失败时自动释放）
const (
	StatusReserved  = "reserved"
	StatusSigned    = "signed"
	StatusCompleted = "completed"
	StatusAbandoned = "abandoned"
)

// SDK 下限的最低值：签名闸关掉了 v1 签名，minSdk 低于 24 的设备装不上；targetSdk 不低于 28
// 时 usesCleartextTraffic 缺省即为 false，第 10 条"不允许明文流量"才对缺省值成立。
const (
	MinConfirmedMinSDK    = 24
	MinConfirmedTargetSDK = 28
)

// ReserveLimits 是预留时在本机记录的锁内复核的版本号上限（检查进程已经判过一次）。
type ReserveLimits struct {
	MaxVersionCode          int64 // 绝对上限
	MaxJump                 int64 // 比已签最大值最多跳多少
	FirstSignMaxVersionCode int64 // 该 (包名, 证书) 首次签名的上限
}

func (l ReserveLimits) validate() error {
	if l.MaxVersionCode < 1 || l.MaxJump < 1 || l.FirstSignMaxVersionCode < 1 {
		return errors.New("reserve limits must all be positive")
	}
	return nil
}

type signedRecord struct {
	JobID             string `json:"jobId"`
	PackageName       string `json:"packageName"`
	CertificateSHA256 string `json:"certificateSha256"`
	VersionCode       int64  `json:"versionCode"`
	UnsignedSHA256    string `json:"unsignedSha256"`
	SignedSHA256      string `json:"signedSha256"`
}

func (s signedRecord) validate() error {
	r := Reservation{JobID: s.JobID, TenantSlug: "x", PackageName: s.PackageName, CertificateSHA256: s.CertificateSHA256, VersionCode: s.VersionCode, UnsignedSHA256: s.UnsignedSHA256}
	if err := r.validateReserve(); err != nil {
		return err
	}
	if !fingerprint.Valid(s.SignedSHA256) {
		return errors.New("signedSha256 must be 64 lowercase hex characters")
	}
	return nil
}

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
	case StatusSigned:
		if !fingerprint.Valid(i.SignedSHA256) || i.ReleaseID != "" {
			return errors.New("a signed import needs signedSha256 and no releaseId")
		}
	case StatusCompleted:
		if !fingerprint.Valid(i.SignedSHA256) || !releaseIDPattern.MatchString(i.ReleaseID) {
			return errors.New("a completed import needs signedSha256 and releaseId")
		}
	default:
		return errors.New("status must be reserved, signed or completed")
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
