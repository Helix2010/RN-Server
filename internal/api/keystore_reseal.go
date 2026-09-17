package api

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/gin-gonic/gin"
)

// 同证书重新封装：POST /v1/signer/keystore-reseals（设计「同证书重新封装」、ADR-0020）。
//
// 密钥只在生成（或离线导入）时加密给当时的收件人，后加或替换的签名闸拿不到已有租户的密钥，换证书又会让
// 老用户升不上去。主签名闸每轮检查时，把本机已确认的同一张证书重新加密给本机决定的收件人，用本机 Ed25519
// 对 keystorebox.ResealMessage 签名交回这个接口。
//
// 服务端这一层只做"不换东西"的把关：证书、包名、别名、租户与当前记录逐字段相同，收件人都是登记过的、含
// 主签名闸自己、至少一把未吊销的恢复公钥，签名用主签名闸登记的公钥验过。**收件人是谁由签名闸本机决定**，
// 服务端加不进任何本机没信任的公钥——它能做的只是不报或乱报机器状态，结果是不重新封装（拒绝服务）。
//
// 发布身份不动（证书没变）。有待处理的生成请求时拒绝：生成本来就会换掉收件人。
func (s *server) resealBuildKeystore(c *gin.Context) {
	self, _ := machineFromContext(c)
	var body struct {
		TenantSlug      string          `json:"tenantSlug"`
		KeystoreVersion int             `json:"keystoreVersion"`
		ResealID        string          `json:"resealId"`
		Upload          json.RawMessage `json:"upload"`
		Signature       string          `json:"signature"`
	}
	if decode(c, &body) != nil || len(body.Upload) == 0 || body.Signature == "" ||
		!ident.ValidTenantSlug(body.TenantSlug) || body.KeystoreVersion < 1 || !keystorebox.ValidResealID(body.ResealID) {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_RESEAL",
			"tenantSlug, keystoreVersion, resealId (rsl_…), upload and signature are required")
		return
	}
	upload, status, code, detail := parseKeystoreUpload(body.Upload)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	ctx := c.Request.Context()
	var tenant string
	switch err := s.db.QueryRowContext(ctx, `SELECT id FROM tenants WHERE slug=? LIMIT 1`, body.TenantSlug).Scan(&tenant); {
	case errors.Is(err, sql.ErrNoRows):
		problem(c, http.StatusNotFound, "TENANT_NOT_FOUND", "No tenant with this slug")
		return
	case err != nil:
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to resolve the tenant")
		return
	}
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	defer tx.Rollback()
	// 加锁顺序与交回生成一致：build.keystore → release.android → build.keystore.request
	keystoreRaw, keystoreVersion, err := configRowVersion(ctx, tx, tenant, buildKeystoreConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	_, identityVersion, err := configRowVersion(ctx, tx, tenant, releaseAndroidIdentityConfigKey, true)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	current, legacy, err := parseBuildKeystoreValue(keystoreRaw)
	if err != nil || legacy {
		problem(c, http.StatusConflict, "KEYSTORE_RESEAL_STALE", "This tenant has no usable v3 signing keystore to reseal")
		return
	}
	// 鉴权只在请求开始时做过：事务里再读一次登记，调用者必须此刻仍是 active 的路由主签名闸
	registry, err := readMachineRegistry(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "MACHINE_REGISTRY_UNAVAILABLE", "Machine registry cannot be read")
		return
	}
	generator, ok := requirePrimaryGenerator(registry.Doc, self, self.ID, string(self.Ed25519PublicKeySHA256))
	if !ok {
		generatorNotPrimary(c)
		return
	}
	// 签名闸没收到上一次的响应而重试：同一个 resealId、同一份签名已经落库，按成功返回
	if current.GenerationRequestID == body.ResealID && current.GenerationSignature == body.Signature {
		c.JSON(http.StatusOK, gin.H{"keystoreVersion": keystoreVersion})
		return
	}
	if body.KeystoreVersion != keystoreVersion {
		problem(c, http.StatusConflict, "KEYSTORE_RESEAL_STALE",
			"The signing keystore changed while it was being resealed; the signing gate reseals the new version next round")
		return
	}
	request, err := s.generationRequestFor(ctx, tx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to read the generation request")
		return
	}
	if request != nil && request.Status == generationPending {
		problem(c, http.StatusConflict, "KEYSTORE_GENERATION_IN_PROGRESS",
			"A key generation for this tenant is still waiting for the primary signer; that generation replaces the recipients anyway")
		return
	}
	// 重新封装只换收件人：证书、包名、别名、租户一个字都不能变
	if upload.CertificateSHA256 != current.CertificateSHA256 || upload.PackageName != current.PackageName ||
		upload.KeyAlias != current.KeyAlias || upload.TenantSlug != current.TenantSlug {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_RESEAL_MISMATCH",
			"A reseal must keep the current certificate, package name, key alias and tenant; use the generate flow to change the key")
		return
	}
	public, err := base64.StdEncoding.Strict().DecodeString(string(generator.Ed25519PublicKey))
	if err != nil || len(public) != ed25519.PublicKeySize {
		problem(c, http.StatusInternalServerError, "MACHINE_REGISTRY_INVALID", "The primary signer's registered Ed25519 key cannot be read")
		return
	}
	if err := keystorebox.VerifyReseal(ed25519.PublicKey(public), body.ResealID, upload, body.Signature); err != nil {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_RESEAL_SIGNATURE_INVALID",
			"signature is not a valid Ed25519 signature by the primary signer's registered key over this reseal and upload")
		return
	}
	recoveryKeys, err := readRecoveryKeys(ctx, tx, false)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "RECOVERY_KEYS_UNAVAILABLE", "Recovery keys cannot be read")
		return
	}
	unknown, recoveryRecipients := classifyKeystoreRecipients(upload, registry.Doc, recoveryKeys.Doc)
	switch {
	case len(unknown) > 0:
		problem(c, http.StatusUnprocessableEntity, "BUILD_KEYSTORE_RECIPIENT_UNKNOWN", unknownRecipientsDetail(unknown))
		return
	case recoveryRecipients == 0:
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_RECOVERY_RECIPIENT_MISSING",
			"A resealed key must also be sealed to at least one registered, unrevoked offline recovery key")
		return
	}
	if _, ok := boxFor(upload, string(generator.PublicKeySHA256)); !ok {
		problem(c, http.StatusUnprocessableEntity, "KEYSTORE_PRIMARY_RECIPIENT_MISSING",
			"A resealed key must be sealed to the resealing primary signer's own accepted X25519 key ("+string(generator.PublicKeySHA256)+")")
		return
	}
	record, err := s.sealKeystoreRecord(tenant, upload)
	if err != nil {
		slog.Error("cannot protect a resealed keystore", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to protect the resealed key")
		return
	}
	record.Generator = &keystoreGenerator{MachineID: generator.ID, Name: generator.Name,
		Ed25519PublicKey: string(generator.Ed25519PublicKey), Ed25519PublicKeySHA256: string(generator.Ed25519PublicKeySHA256)}
	record.GenerationSignature, record.GenerationRequestID, record.SealKind = body.Signature, body.ResealID, sealKindReseal
	if err := record.validate(); err != nil {
		slog.Error("refusing to store an invalid resealed keystore record", "tenant", tenant, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	value, _ := json.Marshal(record)
	if applied, err := writeTenantConfig(ctx, tx, tenant, buildKeystoreConfigKey, value, keystoreVersion, signerActor, now); err != nil || !applied {
		slog.Error("cannot store a resealed keystore", "tenant", tenant, "applied", applied, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	added, removed := recipientDelta(current.Recipients, record.Recipients)
	event := newAudit(tenant, signerActor, "build_keystore_resealed", "app-config", buildKeystoreConfigKey,
		"the primary signer resealed the current signing key to a new set of recipients", requestID(c),
		map[string]any{"resealId": body.ResealID, "keyAlias": record.KeyAlias, "certificateSha256": record.CertificateSHA256,
			"packageName": record.PackageName, "recipients": record.Recipients, "addedRecipients": added, "removedRecipients": removed,
			"generatorMachineId": generator.ID, "generatorName": generator.Name, "databaseVersion": keystoreVersion + 1})
	if err := insertAudit(ctx, tx, event); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_RESEAL_FAILED", "Unable to store the resealed key")
		return
	}
	slog.Info("a signing key was resealed to a new set of recipients", "tenant", tenant, "resealId", body.ResealID,
		"generator", generator.Name, "added", added, "removed", removed, "identityVersion", identityVersion)
	c.JSON(http.StatusOK, gin.H{"keystoreVersion": keystoreVersion + 1})
}

// recipientDelta 是新旧收件人的差集（都已排序），只进审计。
func recipientDelta(before, after []string) (added, removed []string) {
	was := make(map[string]bool, len(before))
	for _, r := range before {
		was[r] = true
	}
	is := make(map[string]bool, len(after))
	for _, r := range after {
		is[r] = true
		if !was[r] {
			added = append(added, r)
		}
	}
	for _, r := range before {
		if !is[r] {
			removed = append(removed, r)
		}
	}
	return added, removed
}
