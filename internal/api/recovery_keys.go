package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/recovery"
	"github.com/gin-gonic/gin"
)

// 平台离线恢复公钥（设计 android-signing-gate-automation-2026-09-16「1. 离线恢复密钥」、ADR-0020）。
//
// 整个平台一次：离线机器上生成 X25519 恢复密钥，私钥加密后进 U 盘，公钥文件由平台管理员在控制台
// 登记到 app_configs 平台级 build.recovery.recipients。主签名闸生成租户签名密钥时，除了加密给本机
// 信任的签名闸，还加密给本机信任的恢复公钥；服务端收密文时要求至少包含一把这里登记的、未吊销的恢复公钥。
//
// **签名闸不采信这份登记**：它本机 pin 的恢复公钥指纹由运维从密码管理器粘贴（安装命令的
// --recovery-sha256、signer trust-recovery）。这里只用于：新建签名闸的前提、machine-setup 与 peers
// 给本机命令取公钥原文、校验交回的密文里有恢复收件人、控制台展示。公钥不是机密，明文存。
const buildRecoveryRecipientsConfigKey = "build.recovery.recipients"

const (
	recoveryKeyIDPrefix       = "rck"
	maxRecoveryKeys           = 16
	recoveryKeyAuditTarget    = "build-recovery-key"
	recoveryKeyReasonMaxRunes = 500
)

// recoveryKey 是 build.recovery.recipients 里的一项。
type recoveryKey struct {
	ID                    string    `json:"id"`
	Name                  string    `json:"name"`
	X25519PublicKey       string    `json:"x25519PublicKey"`
	X25519PublicKeySHA256 string    `json:"x25519PublicKeySha256"`
	CreatedBy             string    `json:"createdBy"`
	CreatedAt             string    `json:"createdAt"`
	RevokedBy             optString `json:"revokedBy"`
	RevokedAt             optString `json:"revokedAt"`
	RevokeReason          optString `json:"revokeReason"`
}

func (k recoveryKey) revoked() bool { return k.RevokedAt != "" }

type recoveryKeysDoc struct {
	Keys []recoveryKey `json:"keys"`
}

// live 是未吊销的恢复公钥。
func (d recoveryKeysDoc) live() []recoveryKey {
	out := []recoveryKey{}
	for _, k := range d.Keys {
		if !k.revoked() {
			out = append(out, k)
		}
	}
	return out
}

// liveBySHA256 按公钥 sha256 找未吊销的恢复公钥。
func (d recoveryKeysDoc) liveBySHA256(digest string) (recoveryKey, bool) {
	for _, k := range d.Keys {
		if !k.revoked() && digest != "" && k.X25519PublicKeySHA256 == digest {
			return k, true
		}
	}
	return recoveryKey{}, false
}

// anyBySHA256 按公钥 sha256 找恢复公钥，吊销的也算（展示已有密文的收件人用）。
func (d recoveryKeysDoc) anyBySHA256(digest string) (recoveryKey, bool) {
	for _, k := range d.Keys {
		if digest != "" && k.X25519PublicKeySHA256 == digest {
			return k, true
		}
	}
	return recoveryKey{}, false
}

func (d recoveryKeysDoc) validate() error {
	if len(d.Keys) > maxRecoveryKeys {
		return fmt.Errorf("at most %d recovery keys can be registered", maxRecoveryKeys)
	}
	ids, digests := map[string]bool{}, map[string]bool{}
	for _, k := range d.Keys {
		raw, err := recovery.DecodePublicKey(k.X25519PublicKey)
		switch {
		case !ident.ValidServerIDWithPrefix(k.ID, recoveryKeyIDPrefix) || ids[k.ID]:
			return fmt.Errorf("recovery key id %q is malformed or duplicated", k.ID)
		case !recovery.ValidName(k.Name):
			return fmt.Errorf("recovery key %s has a malformed name", k.ID)
		case err != nil || fingerprint.SHA256Hex(raw) != k.X25519PublicKeySHA256:
			return fmt.Errorf("recovery key %s has a public key that does not match its sha256", k.ID)
		case digests[k.X25519PublicKeySHA256]:
			return fmt.Errorf("recovery key %s duplicates another key", k.ID)
		case k.revoked() != (k.RevokedBy != ""):
			return fmt.Errorf("recovery key %s is half revoked", k.ID)
		}
		ids[k.ID], digests[k.X25519PublicKeySHA256] = true, true
	}
	return nil
}

type recoveryKeysSnapshot struct {
	Doc     recoveryKeysDoc
	Version int
}

// readRecoveryKeys 读平台级 build.recovery.recipients。没有这一行 = 没有登记任何恢复公钥。
func readRecoveryKeys(ctx context.Context, q rowQuerier, forUpdate bool) (recoveryKeysSnapshot, error) {
	snapshot := recoveryKeysSnapshot{Doc: recoveryKeysDoc{Keys: []recoveryKey{}}}
	var raw []byte
	query := `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=?`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	err := q.QueryRowContext(ctx, query, platformTenantID, buildRecoveryRecipientsConfigKey).Scan(&raw, &snapshot.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return snapshot, nil
	}
	if err != nil {
		return snapshot, err
	}
	if err := json.Unmarshal(raw, &snapshot.Doc); err != nil {
		return snapshot, fmt.Errorf("build.recovery.recipients is not valid JSON: %w", err)
	}
	if snapshot.Doc.Keys == nil {
		snapshot.Doc.Keys = []recoveryKey{}
	}
	if err := snapshot.Doc.validate(); err != nil {
		return snapshot, fmt.Errorf("build.recovery.recipients is invalid: %w", err)
	}
	return snapshot, nil
}

func recoveryKeyView(k recoveryKey) gin.H {
	return gin.H{
		"id": k.ID, "name": k.Name, "x25519PublicKeySha256": k.X25519PublicKeySHA256, "x25519PublicKey": k.X25519PublicKey,
		"createdBy": k.CreatedBy, "createdAt": k.CreatedAt, "revokedBy": nullableString(string(k.RevokedBy)),
		"revokedAt": nullableString(string(k.RevokedAt)), "revokeReason": nullableString(string(k.RevokeReason)),
	}
}

func (s *server) listRecoveryKeys(c *gin.Context) {
	snapshot, err := readRecoveryKeys(c.Request.Context(), s.db, false)
	if err != nil {
		slog.Error("cannot read the recovery keys", "error", err)
		problem(c, http.StatusInternalServerError, "RECOVERY_KEYS_INVALID", "Stored build.recovery.recipients configuration cannot be read")
		return
	}
	items := make([]gin.H, 0, len(snapshot.Doc.Keys))
	for _, k := range snapshot.Doc.Keys {
		items = append(items, recoveryKeyView(k))
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "items": items})
}

// mutateRecoveryKeys 是写恢复公钥登记的公共部分：带锁读、校验版本、改、写、同一事务写审计。
func (s *server) mutateRecoveryKeys(c *gin.Context, expectedVersion int, mutate func(doc *recoveryKeysDoc, now time.Time) (int, string, string, *auditEvent)) (recoveryKeysSnapshot, bool) {
	ctx := c.Request.Context()
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RECOVERY_KEY_SAVE_FAILED", "Unable to save the recovery keys")
		return recoveryKeysSnapshot{}, false
	}
	defer tx.Rollback()
	snapshot, err := readRecoveryKeys(ctx, tx, true)
	if err != nil {
		slog.Error("cannot read the recovery keys", "error", err)
		problem(c, http.StatusInternalServerError, "RECOVERY_KEYS_INVALID", "Stored build.recovery.recipients configuration cannot be read")
		return snapshot, false
	}
	if snapshot.Version != expectedVersion {
		problem(c, http.StatusConflict, "RECOVERY_KEYS_VERSION_CONFLICT", "The recovery keys changed; refresh and retry")
		return snapshot, false
	}
	status, code, detail, event := mutate(&snapshot.Doc, now)
	if status != 0 {
		problem(c, status, code, detail)
		return snapshot, false
	}
	if err := snapshot.Doc.validate(); err != nil {
		slog.Error("refusing to write invalid recovery keys", "error", err)
		problem(c, http.StatusInternalServerError, "RECOVERY_KEY_SAVE_FAILED", "Unable to save the recovery keys")
		return snapshot, false
	}
	value, _ := json.Marshal(snapshot.Doc)
	var result sql.Result
	if snapshot.Version == 0 {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			platformTenantID, buildRecoveryRecipientsConfigKey, value, actor(c), now, platformTenantID, buildRecoveryRecipientsConfigKey)
	} else {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, platformTenantID, buildRecoveryRecipientsConfigKey, snapshot.Version)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RECOVERY_KEY_SAVE_FAILED", "Unable to save the recovery keys")
		return snapshot, false
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "RECOVERY_KEYS_VERSION_CONFLICT", "The recovery keys changed; refresh and retry")
		return snapshot, false
	}
	if insertAudit(ctx, tx, *event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "RECOVERY_KEY_SAVE_FAILED", "Unable to save the recovery keys")
		return snapshot, false
	}
	snapshot.Version++
	return snapshot, true
}

// createRecoveryKey 登记离线工具产出的 recovery-public.json。
func (s *server) createRecoveryKey(c *gin.Context) {
	var body struct {
		PublicFile json.RawMessage `json:"publicFile"`
		machineWriteCommon
	}
	if decode(c, &body) != nil || !body.valid() || len(body.PublicFile) == 0 {
		problem(c, http.StatusBadRequest, "INVALID_RECOVERY_KEY", "publicFile, expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	file, err := recovery.ParsePublic(body.PublicFile)
	if err != nil {
		problem(c, http.StatusUnprocessableEntity, "RECOVERY_KEY_INVALID",
			"publicFile must be the recovery-public.json written by the offline tool (build-keystore recovery-key create): "+err.Error())
		return
	}
	reason := strings.TrimSpace(body.Reason)
	var created recoveryKey
	snapshot, ok := s.mutateRecoveryKeys(c, *body.ExpectedVersion, func(doc *recoveryKeysDoc, now time.Time) (int, string, string, *auditEvent) {
		if _, exists := doc.anyBySHA256(file.X25519PublicKeySHA256); exists {
			return http.StatusConflict, "RECOVERY_KEY_EXISTS", "This recovery public key is already registered (a revoked key cannot be registered again)", nil
		}
		if len(doc.Keys) >= maxRecoveryKeys {
			return http.StatusConflict, "RECOVERY_KEY_LIMIT_REACHED", fmt.Sprintf("At most %d recovery keys can be registered, including revoked ones", maxRecoveryKeys), nil
		}
		created = recoveryKey{
			ID: recoveryKeyIDPrefix + "_" + randomID(16), Name: file.Name, X25519PublicKey: file.X25519PublicKey,
			X25519PublicKeySHA256: file.X25519PublicKeySHA256, CreatedBy: actor(c), CreatedAt: iso(now),
		}
		doc.Keys = append(doc.Keys, created)
		event := newAudit(platformTenantID, actor(c), "build_recovery_key_create", recoveryKeyAuditTarget, created.ID, reason, requestID(c),
			map[string]any{"recoveryKeyId": created.ID, "name": created.Name, "x25519PublicKeySha256": created.X25519PublicKeySHA256, "fileCreatedAt": file.CreatedAt})
		return 0, "", "", &event
	})
	if !ok {
		return
	}
	c.JSON(http.StatusCreated, gin.H{"version": snapshot.Version, "item": recoveryKeyView(created)})
}

// revokeRecoveryKey 吊销一把恢复公钥：此后交回的新密钥不能再只靠它满足"至少一把恢复公钥"，
// 签名闸取 peers 时也看不到它。已经加密给它的密文不受影响（服务端改不了密文）。
func (s *server) revokeRecoveryKey(c *gin.Context) {
	var body machineWriteCommon
	if decode(c, &body) != nil || !body.valid() {
		problem(c, http.StatusBadRequest, "INVALID_RECOVERY_KEY", "expectedVersion, reason (at least 3 characters) and confirm=true are required")
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	reason := clipRunes(strings.TrimSpace(body.Reason), recoveryKeyReasonMaxRunes)
	var revoked recoveryKey
	snapshot, ok := s.mutateRecoveryKeys(c, *body.ExpectedVersion, func(doc *recoveryKeysDoc, now time.Time) (int, string, string, *auditEvent) {
		for i := range doc.Keys {
			k := &doc.Keys[i]
			if k.ID != id {
				continue
			}
			if k.revoked() {
				return http.StatusConflict, "RECOVERY_KEY_ALREADY_REVOKED", "This recovery key is already revoked", nil
			}
			k.RevokedBy, k.RevokedAt, k.RevokeReason = optString(actor(c)), optString(iso(now)), optString(reason)
			revoked = *k
			event := newAudit(platformTenantID, actor(c), "build_recovery_key_revoke", recoveryKeyAuditTarget, k.ID, reason, requestID(c),
				map[string]any{"recoveryKeyId": k.ID, "name": k.Name, "x25519PublicKeySha256": k.X25519PublicKeySHA256, "remaining": len(doc.live())})
			return 0, "", "", &event
		}
		return http.StatusNotFound, "RECOVERY_KEY_NOT_FOUND", "Recovery key not found", nil
	})
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"version": snapshot.Version, "item": recoveryKeyView(revoked)})
}
