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
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/gin-gonic/gin"
)

// 控制台一键生成签名密钥（设计 android-signing-gate-automation-2026-09-16「3. 换密钥」、ADR-0020）。
//
//  1. 租户管理员 POST /v1/admin/build-keystore/generate：服务端只记一条生成请求（租户级 app_configs
//     build.keystore.request，每个租户同时最多一条未完成的），记下发起时 build.keystore 与 release.android
//     的版本。
//  2. 主签名闸在 GET /v1/signer/keystore-checks 里拿到 generationRequest（只下发给 active 的路由主签名闸），
//     在本机生成 RSA 4096 证书与 PKCS#12，加密给本机信任的签名闸与恢复公钥，用本机 Ed25519 对
//     keystorebox.GenerationMessage 签名，交回 POST /v1/signer/keystore-generations/:requestId。
//  3. 服务端一个事务：请求仍未完成且两个版本都没变；调用者是 active 的路由主签名闸、签名用它登记的
//     Ed25519 公钥验过；上传文件按导入的全部规则校验，收件人里至少一把登记的恢复公钥；写 build.keystore
//     （带生成者与签名）、release.android（ADR-0016 的同事务），请求标 done。
//
// 服务端被攻破时能做到的是"让签名闸无意义地换一把新密钥"（拒绝服务）与"新租户第一次生成时写入错误的
// 信任根"（首次信任）；拿不到密钥、也换不掉已有租户的证书（签名闸本机记录按包名记着证书与信任根）。
const buildKeystoreRequestConfigKey = "build.keystore.request"

const (
	generationRequestIDPrefix = "kgr"

	generationPending = "pending"
	generationDone    = "done"
	generationFailed  = "failed"

	// generationStaleCode 是服务端自己判出来的失败：发起之后签名密钥或发布身份被改过（导入、换身份），
	// 这次请求按发起时的版本生成出来也落不了库
	generationStaleCode      = "KEYSTORE_GENERATION_STALE"
	generationDetailMaxRunes = 500
	// generationAliasSuffix：别名默认 <slug 小写>-release
	generationAliasSuffix = "-release"
)

var generationAliasUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// errGenerationRequestInvalid：库里的 build.keystore.request 读不出来。这是数据事故，但它不能挡住这个租户
// 已有密钥的检查、就绪与签名：读路径记日志后按"没有请求"处理，发起新请求时覆盖它。
var errGenerationRequestInvalid = errors.New("build.keystore.request is unreadable")

// keystoreGenerationRequest 是 build.keystore.request 的值（约定 3.5）。
type keystoreGenerationRequest struct {
	RequestID              string                   `json:"requestId"`
	PackageName            string                   `json:"packageName"`
	Alias                  string                   `json:"alias"`
	RequestedBy            string                   `json:"requestedBy"`
	RequestedAt            string                   `json:"requestedAt"`
	KeystoreVersion        int                      `json:"keystoreVersion"`
	ReleaseIdentityVersion int                      `json:"releaseIdentityVersion"`
	Status                 string                   `json:"status"`
	Error                  *keystoreGenerationError `json:"error"`
	CompletedAt            optString                `json:"completedAt"`
}

type keystoreGenerationError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (r keystoreGenerationRequest) validate() error {
	switch {
	case !ident.ValidServerIDWithPrefix(r.RequestID, generationRequestIDPrefix) || !keystorebox.ValidGenerationRequestID(r.RequestID):
		return errors.New("requestId is malformed")
	case !ident.ValidPackageName(r.PackageName) || !ident.ValidKeyAlias(r.Alias):
		return errors.New("packageName or alias is malformed")
	case r.KeystoreVersion < 0 || r.ReleaseIdentityVersion < 0:
		return errors.New("versions are negative")
	case !oneOf(r.Status, generationPending, generationDone, generationFailed):
		return errors.New("status is unknown")
	case (r.Status == generationFailed) != (r.Error != nil):
		return errors.New("error must be set exactly when failed")
	}
	return nil
}

// effective 是这条请求现在的状态：发起之后 build.keystore 或 release.android 的版本变了，还挂着的请求
// 按发起时的版本交回必然 409，这里直接当作失败（KEYSTORE_GENERATION_STALE）。只在读取时推导，不回写：
// 下发、就绪、控制台、再次发起用的都是这一个判断。
func (r keystoreGenerationRequest) effective(keystoreVersion, identityVersion int) keystoreGenerationRequest {
	if r.Status == generationPending && (r.KeystoreVersion != keystoreVersion || r.ReleaseIdentityVersion != identityVersion) {
		r.Status = generationFailed
		r.Error = &keystoreGenerationError{Code: generationStaleCode, Detail: "发起生成之后签名密钥或发布身份被改过（导入了密钥或改了发布身份），这次生成作废；需要的话重新发起"}
	}
	return r
}

// view 是 GenerationRequestView。
func (r keystoreGenerationRequest) view() gin.H {
	var failure any
	if r.Error != nil {
		failure = gin.H{"code": r.Error.Code, "detail": r.Error.Detail}
	}
	return gin.H{
		"requestId": r.RequestID, "status": r.Status, "packageName": r.PackageName, "alias": r.Alias,
		"requestedBy": r.RequestedBy, "requestedAt": r.RequestedAt, "completedAt": nullableString(string(r.CompletedAt)), "error": failure,
	}
}

// configRowVersion 读一行租户配置的值与版本；没有这一行时 version=0、raw=nil。
func configRowVersion(ctx context.Context, q rowQuerier, tenant, key string, forUpdate bool) ([]byte, int, error) {
	var raw []byte
	var version int
	query := `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=?`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, tenant, key).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	return raw, version, err
}

func parseGenerationRequest(raw []byte) (*keystoreGenerationRequest, error) {
	if raw == nil {
		return nil, nil
	}
	var request keystoreGenerationRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("%w: %v", errGenerationRequestInvalid, err)
	}
	if err := request.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", errGenerationRequestInvalid, err)
	}
	return &request, nil
}

// generationRequestFor 读这个租户最近一次生成请求，按当前两个版本推导状态。没有请求、或者请求记录读不出来
// （记日志，见 errGenerationRequestInvalid）返回 nil。
func (s *server) generationRequestFor(ctx context.Context, q rowQuerier, tenant string) (*keystoreGenerationRequest, error) {
	raw, _, err := configRowVersion(ctx, q, tenant, buildKeystoreRequestConfigKey, false)
	if err != nil {
		return nil, err
	}
	request, err := parseGenerationRequest(raw)
	if errors.Is(err, errGenerationRequestInvalid) {
		slog.Error("ignoring an unreadable key generation request", "tenant", tenant, "error", err)
		return nil, nil
	}
	if err != nil || request == nil {
		return nil, err
	}
	_, keystoreVersion, err := configRowVersion(ctx, q, tenant, buildKeystoreConfigKey, false)
	if err != nil {
		return nil, err
	}
	_, identityVersion, err := configRowVersion(ctx, q, tenant, releaseAndroidIdentityConfigKey, false)
	if err != nil {
		return nil, err
	}
	effective := request.effective(keystoreVersion, identityVersion)
	return &effective, nil
}

// defaultGenerationAlias 是 <slug 小写>-release，规范成 ^[A-Za-z0-9._-]{1,64}$。
func defaultGenerationAlias(slug string) string {
	base := generationAliasUnsafe.ReplaceAllString(strings.ToLower(slug), "-")
	if limit := 64 - len(generationAliasSuffix); len(base) > limit {
		base = base[:limit]
	}
	if base == "" {
		base = "app"
	}
	return base + generationAliasSuffix
}

// writeTenantConfig 带乐观锁写一行租户配置（expectedVersion 为 0 表示这一行还不存在）。
func writeTenantConfig(ctx context.Context, tx *sql.Tx, tenant, key string, value []byte, expectedVersion int, actorID string, now time.Time) (bool, error) {
	var result sql.Result
	var err error
	if expectedVersion == 0 {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenant, key, value, actorID, now, tenant, key)
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actorID, now, tenant, key, expectedVersion)
	}
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, errors.New("cannot tell whether the write applied")
	}
	return affected == 1, nil
}

// ---- 管理端：发起 ----

func (s *server) generateBuildKeystore(c *gin.Context) {
	var body struct {
		PackageName                    string `json:"packageName"`
		ExpectedVersion                *int   `json:"expectedVersion"`
		ReleaseIdentityExpectedVersion *int   `json:"releaseIdentityExpectedVersion"`
		Reason                         string `json:"reason"`
		Confirm                        bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE_GENERATION", "packageName, expectedVersion, releaseIdentityExpectedVersion, reason and confirm=true are required")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	packageName := strings.TrimSpace(body.PackageName)
	if !body.Confirm || len([]rune(reason)) < 3 || body.ExpectedVersion == nil || *body.ExpectedVersion < 0 ||
		body.ReleaseIdentityExpectedVersion == nil || *body.ReleaseIdentityExpectedVersion < 0 || !ident.ValidPackageName(packageName) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE_GENERATION",
			"packageName (a lowercase Android application id), expectedVersion, releaseIdentityExpectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	ctx := c.Request.Context()
	tenant := tenantID(c)
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to resolve this tenant")
		return
	}
	identity, err := s.androidReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
		return
	}
	// 包名就是 App 身份：已经登记了发布身份的租户只能为它的包名生成（换包名等于换一个 App，不走这里）；
	// 第一次生成的租户还没有发布身份，包名取请求里的，交回时与证书一起写进发布身份
	if identity != nil && identity.Value.PackageName != packageName {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_PACKAGE_MISMATCH",
			fmt.Sprintf("packageName must be this tenant's Android package %q", identity.Value.PackageName))
		return
	}
	recoveryKeys, err := readRecoveryKeys(ctx, s.db, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
		return
	}
	if len(recoveryKeys.Doc.live()) == 0 {
		problem(c, http.StatusConflict, "RECOVERY_KEY_NOT_CONFIGURED", "The platform has no registered offline recovery public key; a platform administrator must register one before keys can be generated")
		return
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	if _, ok := registry.activePrimary(); !ok {
		problem(c, http.StatusConflict, "PRIMARY_SIGNER_MISSING", "There is no active primary signer to generate the key")
		return
	}
	// 主签名闸第一次为这个包名生成时，信任根直接取服务端的值（首次信任）；算不出来它就生成不了，现在就说
	if _, _, problems, err := s.trustRootsWith(ctx, tenant, packageName); err != nil {
		slog.Error("cannot compose trust roots for a key generation", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to compose the trust roots")
		return
	} else if len(problems) > 0 {
		details := make([]string, 0, len(problems))
		for _, p := range problems {
			details = append(details, p.Detail)
		}
		problem(c, http.StatusConflict, "KEYSTORE_TRUST_ROOTS_UNAVAILABLE", strings.Join(details, "；"))
		return
	}
	now := time.Now().UTC()
	request := keystoreGenerationRequest{
		RequestID: generationRequestIDPrefix + "_" + randomID(16), PackageName: packageName, Alias: defaultGenerationAlias(slug),
		RequestedBy: actor(c), RequestedAt: iso(now), KeystoreVersion: *body.ExpectedVersion, ReleaseIdentityVersion: *body.ReleaseIdentityExpectedVersion,
		Status: generationPending,
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	defer tx.Rollback()
	// 加锁顺序与 PUT /build-keystore、签名闸交回一致：build.keystore → release.android → build.keystore.request
	_, keystoreVersion, err := configRowVersion(ctx, tx, tenant, buildKeystoreConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	if keystoreVersion != *body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	_, identityVersion, err := configRowVersion(ctx, tx, tenant, releaseAndroidIdentityConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	if identityVersion != *body.ReleaseIdentityExpectedVersion {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}
	raw, requestVersion, err := configRowVersion(ctx, tx, tenant, buildKeystoreRequestConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	previous, err := parseGenerationRequest(raw)
	if err != nil {
		// 坏掉的请求记录不挡新的请求：覆盖它，留日志
		slog.Error("overwriting an unreadable build.keystore.request", "tenant", tenant, "error", err)
	} else if previous != nil && previous.effective(keystoreVersion, identityVersion).Status == generationPending {
		problem(c, http.StatusConflict, "KEYSTORE_GENERATION_IN_PROGRESS", "A key generation for this tenant is still waiting for the primary signer")
		return
	}
	value, _ := json.Marshal(request)
	if applied, err := writeTenantConfig(ctx, tx, tenant, buildKeystoreRequestConfigKey, value, requestVersion, actor(c), now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	} else if !applied {
		problem(c, http.StatusConflict, "KEYSTORE_GENERATION_IN_PROGRESS", "Another key generation request was recorded at the same time; refresh")
		return
	}
	summary := map[string]any{"requestId": request.RequestID, "packageName": request.PackageName, "alias": request.Alias,
		"keystoreVersion": request.KeystoreVersion, "releaseIdentityVersion": request.ReleaseIdentityVersion, "replacesExistingKeystore": keystoreVersion > 0}
	if previous != nil {
		summary["previousRequestId"] = previous.RequestID
	}
	if err := insertAudit(ctx, tx, newAudit(tenant, actor(c), "build_keystore_generation_request", "app-config", buildKeystoreRequestConfigKey, reason, requestID(c), summary)); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_FAILED", "Unable to record the generation request")
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"generationRequest": request.view()})
}

// ---- 签名闸：交回与失败 ----

// generationTenantFor 按请求 id 找租户。没有 = 不是任何租户当前的那条请求（已被新请求替换或根本不存在）。
func (s *server) generationTenantFor(ctx context.Context, requestID string) (string, bool, error) {
	var tenant string
	err := s.db.QueryRowContext(ctx,
		`SELECT tenant_id FROM app_configs WHERE config_key=? AND JSON_UNQUOTE(JSON_EXTRACT(config_value,'$.requestId'))=? LIMIT 1`,
		buildKeystoreRequestConfigKey, requestID).Scan(&tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return tenant, err == nil, err
}

func generationStale(c *gin.Context) {
	problem(c, http.StatusConflict, generationStaleCode,
		"This key generation request is no longer waiting for this key (completed, failed, replaced, or the keystore or release identity changed since); discard the generated key")
}

// requirePrimaryGenerator：生成者只能是 active 的路由主签名闸，而且就是调用者本机。
func requirePrimaryGenerator(registry buildMachinesDoc, self buildMachine, claimedID, claimedEd25519 string) (buildMachine, bool) {
	index, found := registry.find(self.ID)
	if !found {
		return buildMachine{}, false
	}
	current := registry.Machines[index]
	if !current.isActivePrimary() || claimedID != current.ID || (claimedEd25519 != "" && claimedEd25519 != string(current.Ed25519PublicKeySHA256)) {
		return buildMachine{}, false
	}
	return current, true
}

func generatorNotPrimary(c *gin.Context) {
	problem(c, http.StatusForbidden, "KEYSTORE_GENERATOR_NOT_PRIMARY", "Only the active primary signer can deliver a generated key, as itself")
}

// completeKeystoreGeneration POST /v1/signer/keystore-generations/:requestId。
func (s *server) completeKeystoreGeneration(c *gin.Context) {
	self, _ := machineFromContext(c)
	requestIDParam := c.Param("requestId")
	var body struct {
		Upload    json.RawMessage `json:"upload"`
		Generator *struct {
			MachineID              string `json:"machineId"`
			Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
		} `json:"generator"`
		Signature string `json:"signature"`
	}
	if decode(c, &body) != nil || len(body.Upload) == 0 || body.Generator == nil || body.Signature == "" ||
		!fingerprint.Valid(body.Generator.Ed25519PublicKeySHA256) {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_GENERATION", "upload, generator {machineId, ed25519PublicKeySha256} and signature are required")
		return
	}
	upload, status, code, detail := parseKeystoreUpload(body.Upload)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	ctx := c.Request.Context()
	if !keystorebox.ValidGenerationRequestID(requestIDParam) {
		generationStale(c)
		return
	}
	tenant, found, err := s.generationTenantFor(ctx, requestIDParam)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to look up the generation request")
		return
	}
	if !found {
		generationStale(c)
		return
	}
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to resolve the tenant")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	defer tx.Rollback()
	keystoreRaw, keystoreVersion, err := configRowVersion(ctx, tx, tenant, buildKeystoreConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	_, identityVersion, err := configRowVersion(ctx, tx, tenant, releaseAndroidIdentityConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	requestRaw, requestVersion, err := configRowVersion(ctx, tx, tenant, buildKeystoreRequestConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	request, err := parseGenerationRequest(requestRaw)
	if err != nil || request == nil || request.RequestID != requestIDParam {
		generationStale(c)
		return
	}
	// 鉴权只在请求开始时做过：事务里再读一次登记，调用者必须此刻仍是 active 的路由主签名闸
	registry, err := readMachineRegistry(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	generator, ok := requirePrimaryGenerator(registry.Doc, self, body.Generator.MachineID, body.Generator.Ed25519PublicKeySHA256)
	if !ok {
		generatorNotPrimary(c)
		return
	}
	// 签名闸没收到上一次的响应而重试：同一条请求、同一份签名已经落库，按成功返回
	if request.Status == generationDone {
		if record, legacy, err := parseBuildKeystoreValue(keystoreRaw); err == nil && !legacy &&
			record.GenerationRequestID == requestIDParam && record.GenerationSignature == body.Signature {
			c.JSON(http.StatusOK, gin.H{"keystoreVersion": keystoreVersion, "releaseIdentityVersion": identityVersion})
			return
		}
		generationStale(c)
		return
	}
	if request.Status != generationPending {
		generationStale(c)
		return
	}
	if request.KeystoreVersion != keystoreVersion || request.ReleaseIdentityVersion != identityVersion {
		failed := request.effective(keystoreVersion, identityVersion)
		failed.CompletedAt = optString(iso(now))
		if s.storeGenerationOutcome(ctx, c, tx, tenant, failed, requestVersion, generator, now) != nil || tx.Commit() != nil {
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to record the stale generation request")
			return
		}
		generationStale(c)
		return
	}
	public, err := base64.StdEncoding.Strict().DecodeString(string(generator.Ed25519PublicKey))
	if err != nil || len(public) != ed25519.PublicKeySize {
		problem(c, http.StatusInternalServerError, "MACHINE_REGISTRY_INVALID", "The primary signer's registered Ed25519 key cannot be read")
		return
	}
	if err := keystorebox.VerifyGeneration(ed25519.PublicKey(public), requestIDParam, upload, body.Signature); err != nil {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_GENERATION_SIGNATURE_INVALID",
			"signature is not a valid Ed25519 signature by the primary signer's registered key over this request and upload")
		return
	}
	switch {
	case upload.TenantSlug != slug:
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_TENANT_MISMATCH", fmt.Sprintf("The generated key is for tenant %q, not %q", upload.TenantSlug, slug))
		return
	case upload.PackageName != request.PackageName || upload.KeyAlias != request.Alias:
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_IDENTITY_MISMATCH", "The generated key's packageName and keyAlias must be the ones in the generation request")
		return
	}
	if code, detail := androidSignerRetirement(upload.CertificateSHA256); code != "" {
		problem(c, http.StatusUnprocessableEntity, code, detail)
		return
	}
	identity := androidReleaseIdentity{PackageName: upload.PackageName, SignerSHA256: upload.CertificateSHA256}
	if err := validateAndroidReleaseIdentity(identity); err != nil {
		problem(c, http.StatusUnprocessableEntity, "INVALID_RELEASE_IDENTITY", err.Error())
		return
	}
	recoveryKeys, err := readRecoveryKeys(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
		return
	}
	unknown, recoveryRecipients := classifyKeystoreRecipients(upload, registry.Doc, recoveryKeys.Doc)
	if len(unknown) > 0 {
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_RECIPIENT_UNKNOWN", unknownRecipientsDetail(unknown))
		return
	}
	if recoveryRecipients == 0 {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_RECOVERY_RECIPIENT_MISSING",
			"A generated key must also be sealed to at least one registered, unrevoked offline recovery key")
		return
	}
	record, err := s.sealKeystoreRecord(tenant, upload)
	if err != nil {
		slog.Error("cannot protect a generated keystore", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to protect the generated key")
		return
	}
	record.Generator = &keystoreGenerator{MachineID: generator.ID, Name: generator.Name,
		Ed25519PublicKey: string(generator.Ed25519PublicKey), Ed25519PublicKeySHA256: string(generator.Ed25519PublicKeySHA256)}
	record.GenerationSignature, record.GenerationRequestID = body.Signature, requestIDParam
	if err := record.validate(); err != nil {
		slog.Error("refusing to store an invalid generated keystore record", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	value, _ := json.Marshal(record)
	identityValue, _ := json.Marshal(identity)
	for _, write := range []struct {
		key     string
		value   []byte
		version int
	}{{buildKeystoreConfigKey, value, keystoreVersion}, {releaseAndroidIdentityConfigKey, identityValue, identityVersion}} {
		if applied, err := writeTenantConfig(ctx, tx, tenant, write.key, write.value, write.version, signerActor, now); err != nil || !applied {
			slog.Error("cannot store a generated keystore", "tenant", tenant, "key", write.key, "applied", applied, "error", err)
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
			return
		}
	}
	done := *request
	done.Status, done.CompletedAt = generationDone, optString(iso(now))
	if err := s.storeGenerationOutcome(ctx, c, tx, tenant, done, requestVersion, generator, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	// 审计记证书、别名、收件人与生成者，绝不记密文
	events := []auditEvent{
		newAudit(tenant, signerActor, "build_keystore_generated", "app-config", buildKeystoreConfigKey, "the primary signer generated and delivered a new signing key", requestID(c),
			map[string]any{"requestId": requestIDParam, "requestedBy": request.RequestedBy, "keyAlias": record.KeyAlias, "certificateSha256": record.CertificateSHA256,
				"packageName": record.PackageName, "recipients": record.Recipients, "generatorMachineId": generator.ID, "generatorName": generator.Name,
				"databaseVersion": keystoreVersion + 1}),
		newAudit(tenant, signerActor, "release_identity_update", "app-config", releaseAndroidIdentityConfigKey, "the primary signer generated and delivered a new signing key", requestID(c),
			map[string]any{"packageName": identity.PackageName, "signerSha256": identity.SignerSHA256, "source": "build_keystore_generated", "databaseVersion": identityVersion + 1}),
	}
	for _, event := range events {
		if err := insertAudit(ctx, tx, event); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to store the generated key")
		return
	}
	c.JSON(http.StatusOK, gin.H{"keystoreVersion": keystoreVersion + 1, "releaseIdentityVersion": identityVersion + 1})
}

// storeGenerationOutcome 在调用方的事务里写回请求的最终状态；失败时同时写审计 build_keystore_generation_failed。
func (s *server) storeGenerationOutcome(ctx context.Context, c *gin.Context, tx *sql.Tx, tenant string, request keystoreGenerationRequest, version int, generator buildMachine, now time.Time) error {
	value, _ := json.Marshal(request)
	applied, err := writeTenantConfig(ctx, tx, tenant, buildKeystoreRequestConfigKey, value, version, signerActor, now)
	if err != nil {
		return err
	}
	if !applied {
		return errors.New("the locked generation request did not accept the outcome")
	}
	if request.Status != generationFailed {
		return nil
	}
	return insertAudit(ctx, tx, newAudit(tenant, signerActor, "build_keystore_generation_failed", "app-config", buildKeystoreRequestConfigKey,
		"the key generation request failed", requestID(c),
		map[string]any{"requestId": request.RequestID, "code": request.Error.Code, "detail": request.Error.Detail,
			"signerMachineId": generator.ID, "signerName": generator.Name}))
}

// failKeystoreGeneration POST /v1/signer/keystore-generations/:requestId/fail：主签名闸报告这次生成做不了
// （信任根变了要先在本机确认、本机没有信任恢复公钥、本机不是主……）。请求标 failed，控制台就绪问题
// KEYSTORE_GENERATION_FAILED 带上原因。
func (s *server) failKeystoreGeneration(c *gin.Context) {
	self, _ := machineFromContext(c)
	requestIDParam := c.Param("requestId")
	var body struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if decode(c, &body) != nil || !signerCodePattern.MatchString(body.Code) {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_GENERATION_FAILURE", "code (UPPER_SNAKE_CASE, e.g. TRUST_ROOTS_CHANGED) and detail are required")
		return
	}
	ctx := c.Request.Context()
	if !keystorebox.ValidGenerationRequestID(requestIDParam) {
		generationStale(c)
		return
	}
	tenant, found, err := s.generationTenantFor(ctx, requestIDParam)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to look up the generation request")
		return
	}
	if !found {
		generationStale(c)
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to record the failure")
		return
	}
	defer tx.Rollback()
	raw, version, err := configRowVersion(ctx, tx, tenant, buildKeystoreRequestConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to record the failure")
		return
	}
	request, err := parseGenerationRequest(raw)
	if err != nil || request == nil || request.RequestID != requestIDParam || request.Status != generationPending {
		generationStale(c)
		return
	}
	registry, err := readMachineRegistry(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	generator, ok := requirePrimaryGenerator(registry.Doc, self, self.ID, "")
	if !ok {
		generatorNotPrimary(c)
		return
	}
	failed := *request
	failed.Status, failed.CompletedAt = generationFailed, optString(iso(now))
	failed.Error = &keystoreGenerationError{Code: body.Code, Detail: sanitizeSignerText(body.Detail, generationDetailMaxRunes)}
	if err := s.storeGenerationOutcome(ctx, c, tx, tenant, failed, version, generator, now); err != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_GENERATION_SAVE_FAILED", "Unable to record the failure")
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- 签名闸：peers ----

// signerPeers GET /v1/signer/peers：active 的签名闸与构建机的公钥、未吊销的恢复公钥。只给签名闸本机命令
// （trust-peer、trust-builder --builder、trust-recovery）显示用：运维粘贴本机抄来的完整指纹比对后才写本机记录，
// 签名闸不采信这里的内容。
func (s *server) signerPeers(c *gin.Context) {
	ctx := c.Request.Context()
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
	signers, builders, keys := []gin.H{}, []gin.H{}, []gin.H{}
	for _, m := range registry.Machines {
		if m.Status != machineStatusActive {
			continue
		}
		if m.Role == machineRoleSigner {
			peer := signerPeerKeys(m)
			peer["status"], peer["signerRole"] = m.Status, nullableString(string(m.SignerRole))
			signers = append(signers, peer)
			continue
		}
		builders = append(builders, gin.H{"machineId": m.ID, "name": m.Name, "status": m.Status,
			"publicKey": string(m.PublicKey), "publicKeySha256": string(m.PublicKeySHA256)})
	}
	for _, k := range recoveryKeys.Doc.live() {
		keys = append(keys, gin.H{"name": k.Name, "x25519PublicKey": k.X25519PublicKey, "x25519PublicKeySha256": k.X25519PublicKeySHA256, "revoked": false})
	}
	c.JSON(http.StatusOK, gin.H{"signers": signers, "builders": builders, "recoveryKeys": keys})
}
