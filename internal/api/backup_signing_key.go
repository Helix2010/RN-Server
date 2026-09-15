package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/gin-gonic/gin"
)

// 打包机的**备份签名公钥**。它和 build.agent.recipient 那把是两把完全不同的钥匙：
//
//	build.agent.recipient   X25519，服务端用它把签名密钥封成盒子（服务端只有公钥）
//	build.agent.backup-sign Ed25519，打包机用它给备份包的内层密文签名
//
// 算法不同、指纹形式不同（前者 16 字符截断，后者 64 字符 DER SPKI），生命周期也不同。
// 所以是独立的一条 app_configs 记录，不是在那一条上多塞个字段。
//
// **旧公钥必须留档。** 恢复出来的机器会生成一把新的并重新登记，而桶里的历史包是旧
// 那把签的——不留档，那些包立刻变成验不了签的废物，而它们恰恰是你可能要用的。
const backupSigningKeyConfigKey = "build.agent.backup-sign"

type backupSigningKey struct {
	// PublicKey 是 base64 的 DER SubjectPublicKeyInfo（见 backupcontainer.EncodeSigningPublicKey）
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	Agent       string `json:"agent,omitempty"`
	At          string `json:"at,omitempty"`
}

type backupSigningKeyRecord struct {
	Current backupSigningKey `json:"current"`
	// Pending 是打包机报上来但还没被人接受的那把
	Pending *backupSigningKey `json:"pending,omitempty"`
	// Previous 是被换下来的那些。只增不删——历史包要靠它们验签（§4.3 第 3 条）
	Previous []backupSigningKey `json:"previous,omitempty"`
}

func (s *server) backupSigningKeyRecord(ctx context.Context) (*backupSigningKeyRecord, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, backupSigningKeyConfigKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record backupSigningKeyRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *server) saveBackupSigningKey(ctx context.Context, record backupSigningKeyRecord, actor string) error {
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=app_configs.version+1,updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		platformTenantID, backupSigningKeyConfigKey, value, actor, time.Now().UTC())
	return err
}

// registerBackupSigningKey 让打包机登记自己的备份签名公钥。
//
// 规则和 X25519 那把一模一样：**库里没有就自动接受，已有另一把就挂成待确认**。
// 自动接受等于偷到代理令牌的人换掉签名公钥，此后他伪造的备份包全都验得过——而
// 验签正是「连服务端一起被攻破也还成立」的那条防线，不能让它自动翻转。
func (s *server) registerBackupSigningKey(c *gin.Context) {
	var body struct {
		PublicKey string `json:"publicKey"`
		Agent     string `json:"agent"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.PublicKey) == "" {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SIGNING_KEY", "publicKey is required")
		return
	}
	encoded := strings.TrimSpace(body.PublicKey)
	pub, err := backupcontainer.ParseSigningPublicKey(encoded)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SIGNING_KEY",
			"publicKey must be the base64 of a DER SubjectPublicKeyInfo holding an Ed25519 key")
		return
	}
	fingerprint, err := backupcontainer.SigningFingerprint(pub)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SIGNING_KEY", "publicKey could not be fingerprinted")
		return
	}
	incoming := backupSigningKey{
		PublicKey:   encoded,
		Fingerprint: fingerprint,
		Agent:       clipRunes(strings.TrimSpace(body.Agent), 120),
		At:          iso(time.Now().UTC()),
	}

	record, err := s.backupSigningKeyRecord(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_SIGNING_KEY_QUERY_FAILED",
			"Unable to read the registered backup signing key")
		return
	}
	switch {
	case record == nil:
		if err := s.saveBackupSigningKey(c.Request.Context(),
			backupSigningKeyRecord{Current: incoming}, "build-agent"); err != nil {
			problem(c, http.StatusInternalServerError, "BACKUP_SIGNING_KEY_SAVE_FAILED",
				"Unable to register the backup signing key")
			return
		}
		s.auditNow(newAudit(platformTenantID, "build-agent", "backup_signing_key_register", "app-config",
			backupSigningKeyConfigKey, "first backup signing public key", requestID(c),
			map[string]any{"fingerprint": incoming.Fingerprint, "agent": incoming.Agent}))
		c.JSON(http.StatusOK, gin.H{"status": "registered", "fingerprint": incoming.Fingerprint})
	case record.Current.PublicKey == incoming.PublicKey:
		c.JSON(http.StatusOK, gin.H{"status": "unchanged", "fingerprint": incoming.Fingerprint})
	default:
		if record.Pending == nil || record.Pending.PublicKey != incoming.PublicKey {
			record.Pending = &incoming
			if err := s.saveBackupSigningKey(c.Request.Context(), *record, "build-agent"); err != nil {
				problem(c, http.StatusInternalServerError, "BACKUP_SIGNING_KEY_SAVE_FAILED",
					"Unable to record the new backup signing key")
				return
			}
			s.auditNow(newAudit(platformTenantID, "build-agent", "backup_signing_key_pending", "app-config",
				backupSigningKeyConfigKey, "a build agent reported a different backup signing key", requestID(c),
				map[string]any{"fingerprint": incoming.Fingerprint, "current": record.Current.Fingerprint,
					"agent": incoming.Agent}))
		}
		c.JSON(http.StatusOK, gin.H{"status": "pending_acceptance", "fingerprint": incoming.Fingerprint,
			"currentFingerprint": record.Current.Fingerprint})
	}
}

// getBackupSigningKey 给平台管理员看。控制台要把这个指纹**单独一个区块**显示：
// 它和三个恢复公钥、以及 X25519 那把打包机公钥的算法都不一样，排在一起不带标题
// 会让三个持有人核对错对象——而核对指纹是整套方案里唯一那个人工检查。
func (s *server) getBackupSigningKey(c *gin.Context) {
	record, err := s.backupSigningKeyRecord(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_SIGNING_KEY_QUERY_FAILED",
			"Unable to read the registered backup signing key")
		return
	}
	if record == nil {
		c.JSON(http.StatusOK, gin.H{"registered": false, "fingerprint": nil, "pending": nil, "previous": []any{}})
		return
	}
	previous := make([]gin.H, 0, len(record.Previous))
	for _, key := range record.Previous {
		previous = append(previous, gin.H{"fingerprint": key.Fingerprint, "retiredAt": nullableString(key.At)})
	}
	out := gin.H{
		"registered":  true,
		"fingerprint": record.Current.Fingerprint,
		"agent":       nullableString(record.Current.Agent),
		"at":          nullableString(record.Current.At),
		"pending":     nil,
		// previous 要显示出来：历史备份包是它们签的，验签对不上时人要能看到
		// 「哦，那个包是换钥匙之前产出的」，而不是以为包被伪造了
		"previous": previous,
	}
	if record.Pending != nil {
		out["pending"] = gin.H{
			"fingerprint": record.Pending.Fingerprint,
			"agent":       nullableString(record.Pending.Agent),
			"reportedAt":  nullableString(record.Pending.At),
		}
	}
	c.JSON(http.StatusOK, out)
}

// acceptBackupSigningKey 接受待确认的那把签名公钥。
//
// 和 X25519 那把不同的是：**旧的那把进 Previous，不删**。桶里的历史包是旧那把签的，
// 删掉就等于把它们变成验不了签的废物。
func (s *server) acceptBackupSigningKey(c *gin.Context) {
	var body struct {
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
		Confirm     bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_SIGNING_KEY_ACCEPT",
			"fingerprint, reason and confirm=true are required")
		return
	}
	record, err := s.backupSigningKeyRecord(c.Request.Context())
	if err != nil || record == nil || record.Pending == nil {
		problem(c, http.StatusConflict, "NO_PENDING_BACKUP_SIGNING_KEY",
			"There is no backup signing key waiting to be accepted")
		return
	}
	// 指纹要人抄一遍：这是「你确实核对过那台机器上是哪一把」的唯一证据
	if strings.TrimSpace(body.Fingerprint) != record.Pending.Fingerprint {
		problem(c, http.StatusConflict, "BACKUP_SIGNING_KEY_FINGERPRINT_MISMATCH",
			"The fingerprint does not match the key waiting to be accepted; check it on the build machine itself")
		return
	}
	retired := record.Current
	retired.At = iso(time.Now().UTC())
	record.Previous = append(record.Previous, retired)
	record.Current = *record.Pending
	record.Pending = nil
	if err := s.saveBackupSigningKey(c.Request.Context(), *record, actor(c)); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_SIGNING_KEY_SAVE_FAILED",
			"Unable to accept the backup signing key")
		return
	}
	s.auditNow(newAudit(platformTenantID, actor(c), "backup_signing_key_accept", "app-config",
		backupSigningKeyConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"fingerprint": record.Current.Fingerprint, "retired": retired.Fingerprint}))
	c.JSON(http.StatusOK, gin.H{"status": "accepted", "fingerprint": record.Current.Fingerprint,
		"retired": retired.Fingerprint})
}
