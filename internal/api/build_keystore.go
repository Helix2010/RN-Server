package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/gin-gonic/gin"
)

// Android 签名密钥（app_configs 租户级 build.keystore，设计「签名密钥记录与密文格式」、约定 4.3）。
//
// 密钥在离线机器上生成，离线工具只加密给离线 pin 文件里的签名闸（v3 密文，每台一份），
// 管理员经控制台上传的是离线工具产出的文件。服务端再用 STORAGE_MASTER_KEY 在外面包一层
// 落库——外层挡"只拿到一份数据库备份"的人；内层服务端、构建机都打不开，只有签名闸能开。
//
// 服务端对上传的文件能做的只有形状与归属：格式必须是 v3、租户对、包名与证书指纹与
// 登记的发布身份一致（同一事务写入，沿用 ADR-0016）、每份密文的收件人都是已登记的
// 签名闸。缺某台签名闸只提示不拒收（新增签名闸时要先改离线 pin 文件再重新 seal）；
// 多出一份给未登记公钥的密文直接拒收。
const buildKeystoreConfigKey = "build.keystore"

// buildKeystoreRecordFormat 是 build.keystore 的记录格式。旧记录（v1 口令封、v2 加密给打包机）
// 没有这个值，读出来一律当作"没有可用的签名密钥"，控制台提示重新上传。
const buildKeystoreRecordFormat = 3

type buildKeystoreRecord struct {
	Format            int      `json:"format"`
	Sealed            string   `json:"sealed"` // base64(secretbox(Upload JSON))
	KeyAlias          string   `json:"keyAlias"`
	CertificateSHA256 string   `json:"certificateSha256"`
	PackageName       string   `json:"packageName"`
	TenantSlug        string   `json:"tenantSlug"`
	Recipients        []string `json:"recipients"`
	// 下面三项只在密钥由主签名闸生成（POST /v1/signer/keystore-generations/:requestId）时有，离线导入的
	// 记录没有：生成者（交回时登记的主签名闸与它当时的 Ed25519 公钥）、它对
	// keystorebox.GenerationMessage(generationRequestId, Upload) 的签名。备签名闸凭它们判断"这份密钥
	// 是本机信任的签名闸生成的"，服务端只转交
	Generator           *keystoreGenerator `json:"generator,omitempty"`
	GenerationSignature string             `json:"generationSignature,omitempty"`
	GenerationRequestID string             `json:"generationRequestId,omitempty"`
	// SealKind 区分这份密钥是怎么落库的：空串（旧记录也读成空）是主签名闸生成，sealKindReseal 是主签名闸
	// 把同一张证书重新封装给新的收件人（POST /v1/signer/keystore-reseals）。备签名闸按它决定验哪种签名
	SealKind string `json:"sealKind,omitempty"`
}

// sealKindReseal 是 buildKeystoreRecord.SealKind 的"同证书重新封装"（生成是空串）。
const sealKindReseal = "reseal"

// sealKindOf 是下发给签名闸的 sealKind：旧记录没有这个字段，按"生成"读。
func sealKindOf(record buildKeystoreRecord) string {
	if record.SealKind == sealKindReseal {
		return sealKindReseal
	}
	return "generation"
}

// keystoreGenerator 是生成这份密钥的主签名闸（交回那一刻的登记）。
type keystoreGenerator struct {
	MachineID              string `json:"machineId"`
	Name                   string `json:"name"`
	Ed25519PublicKey       string `json:"ed25519PublicKey"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
}

// buildKeystoreState 是这个租户 build.keystore 那一行的状态。
type buildKeystoreState struct {
	Exists bool // 有这一行
	Legacy bool // 有这一行但不是 v3
	// Invalid 非空：是 v3 记录但用不了（记录本身损坏、外层解不开、索引字段与上传文件对不上），
	// 值是原因（只进日志）。不当成读库错误：一个租户的记录坏了不能让控制台、排队 500
	Invalid   string
	Record    buildKeystoreRecord // Invalid 因记录本身损坏时为零值
	Upload    *keystorebox.Upload // 只在 configured() 时有值
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

// configured：有可用的 v3 记录。
func (k buildKeystoreState) configured() bool { return k.Exists && !k.Legacy && k.Invalid == "" }

// v3Record：这一行是 v3 格式（不论能不能用），控制台按"已配置"显示。
func (k buildKeystoreState) v3Record() bool { return k.Exists && !k.Legacy }

func buildKeystoreAAD(tenant string) string { return "build-keystore/v3:" + tenant }

func (s *server) buildKeystoreStateFor(ctx context.Context, q rowQuerier, tenant string) (buildKeystoreState, error) {
	var state buildKeystoreState
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=?`,
		tenant, buildKeystoreConfigKey).Scan(&raw, &state.Version, &state.UpdatedBy, &state.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return buildKeystoreState{}, nil
	}
	if err != nil {
		return state, err
	}
	state.Exists = true
	return state, s.evaluateBuildKeystore(tenant, raw, &state)
}

// evaluateBuildKeystore 判断 build.keystore 这一行的值能不能用：旧格式标 Legacy，v3 记录损坏、外层
// 解不开或索引字段与上传文件对不上标 Invalid，都不是错误。给已经自己读到这一行（例如事务里带锁读）
// 的调用方用，判据与 buildKeystoreStateFor 一样。只有主密钥不可用才返回错误。
func (s *server) evaluateBuildKeystore(tenant string, raw []byte, state *buildKeystoreState) error {
	record, legacy, parseErr := parseBuildKeystoreValue(raw)
	state.Legacy = legacy
	switch {
	case legacy:
		return nil
	case parseErr != nil:
		state.Invalid = parseErr.Error()
		return nil
	}
	state.Record = record
	if s.secrets == nil {
		return errors.New("storage master key is unavailable")
	}
	upload, err := s.keystoreUploadFor(tenant, record)
	if err != nil {
		state.Invalid = err.Error()
		return nil
	}
	state.Upload = &upload
	return nil
}

// parseBuildKeystoreValue 解析 build.keystore 这一行的值。不是 format 3 的旧记录 legacy=true、不报错。
func parseBuildKeystoreValue(raw []byte) (record buildKeystoreRecord, legacy bool, err error) {
	var probe struct {
		Format int `json:"format"`
	}
	if json.Unmarshal(raw, &probe) != nil || probe.Format != buildKeystoreRecordFormat {
		return buildKeystoreRecord{}, true, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, false, fmt.Errorf("build.keystore v3 record is malformed: %w", err)
	}
	if err := record.validate(); err != nil {
		return record, false, fmt.Errorf("build.keystore v3 record is invalid: %w", err)
	}
	return record, false, nil
}

func (r buildKeystoreRecord) validate() error {
	switch {
	case r.Sealed == "":
		return errors.New("sealed is empty")
	case !ident.ValidKeyAlias(r.KeyAlias):
		return errors.New("keyAlias is malformed")
	case !fingerprint.Valid(r.CertificateSHA256):
		return errors.New("certificateSha256 is malformed")
	case !ident.ValidPackageName(r.PackageName):
		return errors.New("packageName is malformed")
	case !ident.ValidTenantSlug(r.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case len(r.Recipients) == 0:
		return errors.New("recipients is empty")
	}
	for _, recipient := range r.Recipients {
		if !fingerprint.Valid(recipient) {
			return errors.New("recipients contains a malformed fingerprint")
		}
	}
	generated := r.Generator != nil || r.GenerationSignature != "" || r.GenerationRequestID != ""
	if generated {
		signature, err := base64.StdEncoding.Strict().DecodeString(r.GenerationSignature)
		switch {
		case r.Generator == nil || !ident.ValidServerIDWithPrefix(r.Generator.MachineID, machineIDPrefix) || !ident.ValidMachineName(r.Generator.Name):
			return errors.New("generator is incomplete")
		case !fingerprint.Valid(r.Generator.Ed25519PublicKeySHA256):
			return errors.New("generator.ed25519PublicKeySha256 is malformed")
		case err != nil || len(signature) != ed25519.SignatureSize:
			return errors.New("generationSignature is malformed")
		case !keystorebox.ValidGenerationRequestID(r.GenerationRequestID):
			return errors.New("generationRequestId is malformed")
		}
		public, err := base64.StdEncoding.Strict().DecodeString(r.Generator.Ed25519PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize || fingerprint.SHA256Hex(public) != r.Generator.Ed25519PublicKeySHA256 {
			return errors.New("generator.ed25519PublicKey does not match its sha256")
		}
		// 重新封装的 id 另有前缀，签名也是另一种消息（keystorebox.ResealMessage）：备签名闸按 sealKind 选验哪种
		if (r.SealKind == sealKindReseal) != keystorebox.ValidResealID(r.GenerationRequestID) {
			return errors.New("sealKind does not match the shape of generationRequestId")
		}
	}
	switch {
	case r.SealKind != "" && r.SealKind != sealKindReseal:
		return errors.New("sealKind is unknown")
	case r.SealKind != "" && !generated:
		return errors.New("sealKind needs a generator")
	}
	return nil
}

// keystoreUploadFor 剥掉外层，取回离线工具产出的上传文件。里面每份密文服务端都打不开。
// 记录上的索引字段与文件内容对不上是数据事故，报错，不猜哪一边是对的。
func (s *server) keystoreUploadFor(tenant string, record buildKeystoreRecord) (keystorebox.Upload, error) {
	var upload keystorebox.Upload
	if s.secrets == nil {
		return upload, errors.New("storage master key is unavailable")
	}
	encrypted, err := base64.StdEncoding.DecodeString(record.Sealed)
	if err != nil {
		return upload, fmt.Errorf("build.keystore sealed is not base64: %w", err)
	}
	plaintext, err := s.secrets.Decrypt(encrypted, buildKeystoreAAD(tenant))
	if err != nil {
		return upload, fmt.Errorf("build.keystore cannot be unwrapped: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&upload); err != nil {
		return upload, fmt.Errorf("build.keystore upload is malformed: %w", err)
	}
	if err := upload.ValidateShape(); err != nil {
		return upload, fmt.Errorf("build.keystore upload is invalid: %w", err)
	}
	if upload.KeyAlias != record.KeyAlias || upload.CertificateSHA256 != record.CertificateSHA256 ||
		upload.PackageName != record.PackageName || upload.TenantSlug != record.TenantSlug ||
		strings.Join(uploadRecipients(upload), ",") != strings.Join(record.Recipients, ",") {
		return upload, errors.New("build.keystore record does not match the stored upload")
	}
	return upload, nil
}

// uploadRecipients 是上传文件里的收件人指纹，排序后返回。
func uploadRecipients(upload keystorebox.Upload) []string {
	out := make([]string, 0, len(upload.Boxes))
	for _, box := range upload.Boxes {
		out = append(out, box.RecipientSHA256)
	}
	sort.Strings(out)
	return out
}

func boxFor(upload keystorebox.Upload, recipient string) (keystorebox.Box, bool) {
	for _, box := range upload.Boxes {
		if recipient != "" && box.RecipientSHA256 == recipient {
			return box, true
		}
	}
	return keystorebox.Box{}, false
}

// ---- 管理端 ----

func (s *server) getBuildKeystore(c *gin.Context) {
	ctx := c.Request.Context()
	view, err := s.buildKeystoreView(ctx, tenantID(c))
	if err != nil {
		slog.Error("cannot compose the build keystore view", "tenant", tenantID(c), "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration cannot be read")
		return
	}
	c.JSON(http.StatusOK, view)
}

// buildKeystoreView 是 GET 与 PUT 共用的视图（约定 5.4）。收件人、签名闸、确认状态都是公开值，
// 租户管理员也看得到：没有它们，租户不知道自己的密钥卡在哪一步。但签名闸叫什么是平台的事：
// 名称一律换成角色（设计 tenant-console-accounts-and-sso §3.4；租户端只有租户会话）。
func (s *server) buildKeystoreView(ctx context.Context, tenant string) (gin.H, error) {
	readiness, err := s.signerReadinessFor(ctx, tenant, false)
	if err != nil {
		return nil, err
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		return nil, err
	}
	keystore := readiness.Keystore
	view := gin.H{
		"configured": keystore.v3Record(), "format": nil, "legacy": keystore.Legacy,
		"keyAlias": nil, "certificateSha256": nil, "packageName": nil,
		"version": keystore.Version, "updatedBy": nil, "updatedAt": nil,
		"recipients": []gin.H{}, "missingSigners": []gin.H{}, "signers": []gin.H{},
		"ready": readiness.Ready, "readinessProblems": readiness.problemList(), "trustRoots": nil, "trustRootsDigest": nil,
		"generationRequest": nil, "generator": nil, "recoveryRecipients": []string{}, "revokedRecoveryRecipients": []string{},
	}
	if readiness.Generation != nil {
		view["generationRequest"] = readiness.Generation.view()
	}
	if keystore.Exists {
		view["updatedBy"], view["updatedAt"] = nullableString(keystore.UpdatedBy), nullableTime(keystore.UpdatedAt)
	}
	if readiness.Roots != nil {
		view["trustRoots"], view["trustRootsDigest"] = readiness.Roots, readiness.Digest
	}
	recipients := map[string]bool{}
	// 记录能解析就把索引字段显示出来（即使外层解不开），便于看出是哪一份坏了
	if keystore.v3Record() && keystore.Record.Format == buildKeystoreRecordFormat {
		view["format"], view["keyAlias"] = keystore.Record.Format, keystore.Record.KeyAlias
		view["certificateSha256"], view["packageName"] = keystore.Record.CertificateSHA256, keystore.Record.PackageName
		if generator := keystore.Record.Generator; generator != nil {
			view["generator"] = gin.H{"machineId": generator.MachineID, "name": generator.Name, "ed25519PublicKeySha256": generator.Ed25519PublicKeySHA256}
		}
		recoveryKeys, err := readRecoveryKeys(ctx, s.db, false)
		if err != nil {
			return nil, err
		}
		// 恢复收件人：密钥里加密给了哪几把登记过的恢复公钥（吊销了的也算——密文已经发给它了）；其中已吊销的
		// 单独列出来，全部吊销了这把密钥就没有可用的离线恢复（导出也会被拒）
		recoveryRecipients, revokedRecoveryRecipients := []string{}, []string{}
		items := []gin.H{}
		for _, recipient := range keystore.Record.Recipients {
			if key, ok := recoveryKeys.Doc.anyBySHA256(recipient); ok {
				recoveryRecipients = append(recoveryRecipients, recipient)
				if key.revoked() {
					revokedRecoveryRecipients = append(revokedRecoveryRecipients, recipient)
				}
			}
			recipients[recipient] = true
			item := gin.H{"recipientSha256": recipient, "machineId": nil, "name": nil, "signerRole": nil}
			if signer, ok := registry.signerByRecipient(recipient); ok {
				item["machineId"], item["name"], item["signerRole"] = signer.ID, signer.Name, nullableString(string(signer.SignerRole))
			}
			items = append(items, item)
		}
		view["recipients"], view["recoveryRecipients"], view["revokedRecoveryRecipients"] = items, recoveryRecipients, revokedRecoveryRecipients
	}
	checks, err := s.keystoreChecksFor(ctx, s.db, tenant)
	if err != nil {
		return nil, err
	}
	missing, signers := []gin.H{}, []gin.H{}
	for _, m := range registry.Machines {
		if m.Role != machineRoleSigner || m.Status == machineStatusRevoked {
			continue
		}
		hasBox := m.PublicKeySHA256 != "" && recipients[string(m.PublicKeySHA256)]
		if keystore.configured() && m.Status == machineStatusActive && !hasBox {
			missing = append(missing, gin.H{"machineId": m.ID, "name": m.Name, "signerRole": nullableString(string(m.SignerRole))})
		}
		entry := gin.H{"machineId": m.ID, "name": m.Name, "signerRole": nullableString(string(m.SignerRole)), "status": m.Status,
			"publicKeySha256": nullableString(string(m.PublicKeySHA256)), "hasBox": hasBox, "check": nil}
		if check, ok := checks[m.ID]; ok {
			entry["check"] = gin.H{
				"keystoreVersion": check.KeystoreVersion, "decrypt": check.Decrypt, "confirmed": check.Confirmed,
				"trustRootsCurrent": readiness.Digest != "" && string(check.ConfirmedTrustRootsDigest) == readiness.Digest,
				"trialSign":         check.TrialSign, "checkedAt": check.CheckedAt, "error": nullableString(string(check.Error)),
			}
		}
		signers = append(signers, entry)
	}
	view["missingSigners"], view["signers"] = missing, signers
	anonymizeSigners(view)
	return view, nil
}

// anonymizeSigners 把视图里的签名闸名称换成角色。机器 id 是不透明的登记号，留着给界面对行。
func anonymizeSigners(view gin.H) {
	label := func(role any) string {
		switch role {
		case string(signerRolePrimary):
			return "主签名闸"
		case string(signerRoleStandby):
			return "备签名闸"
		}
		return "签名闸"
	}
	for _, key := range []string{"recipients", "missingSigners", "signers"} {
		items, _ := view[key].([]gin.H)
		for _, item := range items {
			if item["name"] != nil {
				item["name"] = label(item["signerRole"])
			}
		}
	}
	if generator, ok := view["generator"].(gin.H); ok {
		generator["name"] = "签名闸"
	}
}

// saveBuildKeystoreRequest 是 PUT /v1/admin/build-keystore 的请求体（约定 5.4）。
type saveBuildKeystoreRequest struct {
	Upload                         json.RawMessage `json:"upload"`
	PackageName                    string          `json:"packageName"`
	SignerSHA256                   string          `json:"signerSha256"`
	ExpectedVersion                *int            `json:"expectedVersion"`
	ReleaseIdentityExpectedVersion *int            `json:"releaseIdentityExpectedVersion"`
	Reason                         string          `json:"reason"`
	Confirm                        bool            `json:"confirm"`
}

// saveBuildKeystore 收下离线工具产出的 v3 上传文件，同一个事务里写发布身份（ADR-0016）：
// 不留"密钥换了、登记的指纹还是旧的"这个中间态。
func (s *server) saveBuildKeystore(c *gin.Context) {
	ctx := c.Request.Context()
	raw, err := readLimitedBody(c, 1<<20)
	if err != nil {
		problem(c, http.StatusBadRequest, "MALFORMED_BUILD_KEYSTORE", "Request body is missing or larger than 1 MiB")
		return
	}
	// 旧控制台发的是 {sealed, keyAlias, keystoreSha256, …}：那是 v1/v2 的形状，明确说不再支持，
	// 而不是报一句 unknown field 让人去猜
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) == nil {
		if _, legacy := probe["sealed"]; legacy {
			problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_FORMAT_UNSUPPORTED",
				"Only keystore files produced by the offline build-keystore tool in format "+keystorebox.UploadFormat+" are accepted; passphrase-sealed (v1) and build-agent (v2) boxes are retired")
			return
		}
	}
	var body saveBuildKeystoreRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		problem(c, http.StatusBadRequest, "MALFORMED_BUILD_KEYSTORE", "Request body was rejected: "+err.Error())
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if !body.Confirm || len([]rune(reason)) < 3 || body.ExpectedVersion == nil || *body.ExpectedVersion < 0 ||
		body.ReleaseIdentityExpectedVersion == nil || *body.ReleaseIdentityExpectedVersion < 0 || len(body.Upload) == 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE",
			"upload, packageName, signerSha256, expectedVersion, releaseIdentityExpectedVersion, reason and confirm=true are required")
		return
	}
	upload, status, code, detail := parseKeystoreUpload(body.Upload)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	identity := normalizeAndroidReleaseIdentity(androidReleaseIdentity{PackageName: body.PackageName, SignerSHA256: body.SignerSHA256})
	if err := validateAndroidReleaseIdentity(identity); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", err.Error())
		return
	}
	for _, digest := range []string{identity.SignerSHA256, upload.CertificateSHA256} {
		if code, detail := androidSignerRetirement(digest); code != "" {
			problem(c, http.StatusUnprocessableEntity, code, detail)
			return
		}
	}
	slug, err := s.tenantSlug(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to resolve this tenant")
		return
	}
	if upload.TenantSlug != slug {
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_TENANT_MISMATCH",
			fmt.Sprintf("This keystore file was generated for tenant %q, not for this tenant (%q)", upload.TenantSlug, slug))
		return
	}
	if upload.PackageName != identity.PackageName || upload.CertificateSHA256 != identity.SignerSHA256 {
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_IDENTITY_MISMATCH",
			"packageName and signerSha256 must equal the package name and certificate fingerprint inside the keystore file")
		return
	}
	if inUse, err := androidPackageUsedByAnotherTenant(ctx, s.db, tenantID(c), identity.PackageName); err != nil {
		slog.Error("cannot check whether another tenant uses the package name", "tenant", tenantID(c), "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to check the package name")
		return
	} else if inUse {
		androidPackageInUse(c)
		return
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	recoveryKeys, err := readRecoveryKeys(ctx, s.db, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
		return
	}
	// 离线导入不强制带恢复收件人（离线原件本身就是备份）；带了就必须是登记过、未吊销的恢复公钥
	if unknown, _ := classifyKeystoreRecipients(upload, registry, recoveryKeys.Doc); len(unknown) > 0 {
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_RECIPIENT_UNKNOWN", unknownRecipientsDetail(unknown))
		return
	}
	record, err := s.sealKeystoreRecord(tenantID(c), upload)
	if err != nil {
		slog.Error("cannot protect an uploaded keystore", "tenant", tenantID(c), "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to protect the keystore file")
		return
	}
	value, _ := json.Marshal(record)

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the keystore")
		return
	}
	defer tx.Rollback()
	var currentVersion int
	err = tx.QueryRowContext(ctx, `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? FOR UPDATE`, tenantID(c), buildKeystoreConfigKey).Scan(&currentVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the keystore")
		return
	}
	if currentVersion != *body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	var releaseVersion int
	err = tx.QueryRowContext(ctx, `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? FOR UPDATE`, tenantID(c), releaseAndroidIdentityConfigKey).Scan(&releaseVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	if releaseVersion != *body.ReleaseIdentityExpectedVersion {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}
	if affected, err := upsertAppConfig(c, tx, buildKeystoreConfigKey, value, currentVersion, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the keystore")
		return
	} else if affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	missing := []string{}
	for _, m := range registry.Machines {
		if m.Role == machineRoleSigner && m.Status == machineStatusActive && !containsString(record.Recipients, string(m.PublicKeySHA256)) {
			missing = append(missing, m.ID)
		}
	}
	// 审计记别名、指纹与收件人，绝不记密文
	event := newAudit(tenantID(c), actor(c), "build_keystore_update", "app-config", buildKeystoreConfigKey, reason, requestID(c),
		map[string]any{"format": buildKeystoreRecordFormat, "keyAlias": record.KeyAlias, "certificateSha256": record.CertificateSHA256,
			"packageName": record.PackageName, "recipients": record.Recipients, "missingSigners": missing, "databaseVersion": currentVersion + 1})
	if insertAudit(ctx, tx, event) != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the keystore")
		return
	}
	identityValue, _ := json.Marshal(identity)
	if affected, err := upsertAppConfig(c, tx, releaseAndroidIdentityConfigKey, identityValue, releaseVersion, now); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	} else if affected != 1 {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}
	identityEvent := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseAndroidIdentityConfigKey, reason, requestID(c),
		map[string]any{"packageName": identity.PackageName, "signerSha256": identity.SignerSHA256, "source": "build_keystore_update", "databaseVersion": releaseVersion + 1})
	if insertAudit(ctx, tx, identityEvent) != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	if tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the keystore")
		return
	}
	view, err := s.buildKeystoreView(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "The keystore was saved but cannot be read back")
		return
	}
	view["releaseIdentityVersion"] = releaseVersion + 1
	c.JSON(http.StatusOK, view)
}

// classifyKeystoreRecipients 把上传文件的收件人分成三类：已登记、未吊销签名闸已接受的 X25519 公钥；
// 登记过、未吊销的恢复公钥（返回个数）；都不是（返回列表）。
func classifyKeystoreRecipients(upload keystorebox.Upload, registry buildMachinesDoc, recoveryKeys recoveryKeysDoc) (unknown []string, recoveryRecipients int) {
	unknown = []string{}
	for _, box := range upload.Boxes {
		if _, ok := registry.signerByRecipient(box.RecipientSHA256); ok {
			continue
		}
		if _, ok := recoveryKeys.liveBySHA256(box.RecipientSHA256); ok {
			recoveryRecipients++
			continue
		}
		unknown = append(unknown, box.RecipientSHA256)
	}
	return unknown, recoveryRecipients
}

func unknownRecipientsDetail(unknown []string) string {
	return "These recipients are neither the accepted key of a registered signer that is not revoked nor a registered recovery key that is not revoked: " +
		strings.Join(unknown, ", ") + "。密钥只应加密给已在控制台接受公钥的签名闸与登记过的恢复公钥"
}

// sealKeystoreRecord 用 STORAGE_MASTER_KEY 在上传文件外面包一层，连同索引字段拼成 build.keystore 记录。
func (s *server) sealKeystoreRecord(tenant string, upload keystorebox.Upload) (buildKeystoreRecord, error) {
	if s.secrets == nil {
		return buildKeystoreRecord{}, errors.New("storage master key is unavailable")
	}
	uploadJSON, err := json.Marshal(upload)
	if err != nil {
		return buildKeystoreRecord{}, err
	}
	encrypted, err := s.secrets.Encrypt(string(uploadJSON), buildKeystoreAAD(tenant))
	if err != nil {
		return buildKeystoreRecord{}, err
	}
	return buildKeystoreRecord{
		Format: buildKeystoreRecordFormat, Sealed: base64.StdEncoding.EncodeToString(encrypted),
		KeyAlias: upload.KeyAlias, CertificateSHA256: upload.CertificateSHA256, PackageName: upload.PackageName,
		TenantSlug: upload.TenantSlug, Recipients: uploadRecipients(upload),
	}, nil
}

// exportBuildKeystore GET /v1/admin/build-keystore/export：下载当前密钥的上传文件给离线工具 build-keystore
// recover 用恢复私钥解开。只带发给未吊销恢复公钥的密文：发给签名闸的那几份不带——租户管理员都能导出，
// 带上的话，一台被吊销但没擦盘的签名闸私钥加上任何一次导出就能解开密钥。recover 只解发给恢复公钥的那份、
// 核对明文与外层字段，不校验生成签名，所以裁掉别的 box 不影响它。
//
// 审计与读密钥在同一个事务里，审计写不进去就不导出（导出的是密钥的密文，不能有没留痕的一次）。
func (s *server) exportBuildKeystore(c *gin.Context) {
	ctx := c.Request.Context()
	tenant := tenantID(c)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_EXPORT_FAILED", "Unable to export the keystore file")
		return
	}
	defer tx.Rollback()
	state, err := s.buildKeystoreStateFor(ctx, tx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration cannot be read")
		return
	}
	if !state.configured() {
		problem(c, http.StatusNotFound, "BUILD_KEYSTORE_NOT_CONFIGURED", "This tenant has no usable v3 signing keystore to export")
		return
	}
	recoveryKeys, err := readRecoveryKeys(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
		return
	}
	exported := *state.Upload
	exported.Boxes = []keystorebox.Box{}
	recipients := []string{}
	for _, box := range state.Upload.Boxes {
		if _, ok := recoveryKeys.Doc.liveBySHA256(box.RecipientSHA256); ok {
			exported.Boxes = append(exported.Boxes, box)
			recipients = append(recipients, box.RecipientSHA256)
		}
	}
	if len(exported.Boxes) == 0 {
		problem(c, http.StatusConflict, "BUILD_KEYSTORE_EXPORT_NO_RECOVERY_RECIPIENT",
			"The current key is not sealed to any registered, unrevoked offline recovery key, so there is nothing to export for offline recovery")
		return
	}
	raw, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_EXPORT_FAILED", "Unable to serialise the keystore file")
		return
	}
	event := newAudit(tenant, actor(c), "build_keystore_exported", "app-config", buildKeystoreConfigKey,
		"the sealed keystore file was exported for offline recovery", requestID(c),
		map[string]any{"keystoreVersion": state.Version, "keyAlias": state.Record.KeyAlias, "certificateSha256": state.Record.CertificateSHA256,
			"packageName": state.Record.PackageName, "recipients": recipients})
	if err := insertAudit(ctx, tx, event); err != nil {
		slog.Error("refusing to export a keystore whose audit cannot be written", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_EXPORT_FAILED", "Unable to record the export audit; nothing was exported")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_EXPORT_FAILED", "Unable to record the export audit; nothing was exported")
		return
	}
	fileName := fmt.Sprintf("%s-keystore-v%d.json", strings.ToLower(state.Record.TenantSlug), state.Version)
	c.Header("Content-Disposition", `attachment; filename="`+fileName+`"`)
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/json", append(raw, '\n'))
}

// parseKeystoreUpload 严格解析上传文件。非 v3（包括 v3 文件里夹着别的版本的密文）→ 422
// BUILD_KEYSTORE_FORMAT_UNSUPPORTED；形状不对 → 400 INVALID_BUILD_KEYSTORE。不解密。
func parseKeystoreUpload(raw json.RawMessage) (keystorebox.Upload, int, string, string) {
	var upload keystorebox.Upload
	var probe struct {
		Format string `json:"format"`
		Boxes  []struct {
			Version int `json:"v"`
		} `json:"boxes"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return upload, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "upload must be the JSON object produced by the offline build-keystore tool"
	}
	unsupported := probe.Format != keystorebox.UploadFormat
	for _, box := range probe.Boxes {
		unsupported = unsupported || box.Version != keystorebox.Version
	}
	if unsupported {
		return upload, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_FORMAT_UNSUPPORTED",
			"Only keystore files in format " + keystorebox.UploadFormat + " with v3 boxes are accepted; regenerate it with the offline build-keystore tool"
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&upload); err != nil {
		return upload, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "upload was rejected: " + err.Error()
	}
	if err := upload.ValidateShape(); err != nil {
		return upload, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", err.Error()
	}
	return upload, 0, "", ""
}

func readLimitedBody(c *gin.Context, limit int64) ([]byte, error) {
	if c.Request.Body == nil {
		return nil, errors.New("request body is missing")
	}
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(http.MaxBytesReader(c.Writer, c.Request.Body, limit)); err != nil {
		return nil, err
	}
	if buffer.Len() == 0 {
		return nil, errors.New("request body is empty")
	}
	return buffer.Bytes(), nil
}

// upsertAppConfig 写一行租户 app_configs 并带上乐观锁。expectedVersion 为 0 表示这一行
// 还不存在——INSERT 的 WHERE NOT EXISTS 挡住并发插入，返回 0 行让调用方报冲突。
func upsertAppConfig(c *gin.Context, tx *sql.Tx, key string, value []byte, expectedVersion int, now time.Time) (int64, error) {
	var result sql.Result
	var err error
	if expectedVersion == 0 {
		result, err = tx.ExecContext(c.Request.Context(),
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), key, value, actor(c), now, tenantID(c), key)
	} else {
		result, err = tx.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, tenantID(c), key, expectedVersion)
	}
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.New("cannot tell whether the write applied")
	}
	return affected, nil
}
