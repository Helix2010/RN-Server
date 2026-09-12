package api

// bootstrap 响应签名（安全评审 N3）。
//
// bootstrap 是一条**安全控制通道**：它决定 RPC 端点、预测平台域名与 scopeId、
// 更新策略、以及应用内直装的下载地址。在这之前它的真实性只到 TLS 为止，也就是
// 说控制了数据库、控制了 API、或者拿到一张被信任的恶意 CA 的人，可以在不碰 OTA
// 的情况下把设备指向自己的节点。
//
// 为什么用 secp256k1 而不是 RSA 或 Ed25519：两端的实现都已经在手上，而且都不是
// 新引入的信任。服务端这边 `internal/siwe` 已经在用它验 EIP-4361 登录签名；App
// 那边 ethers 的 verifyMessage 是这个钱包**已经拿用户资金在信任**的那份实现。
// 往最敏感的位置塞一个没人审过的 RSA 验证器或一条新曲线，换不来任何东西。
//
// 签的是**发出去的那串字节本身**，不是重新序列化一次的对象。OTA 验签那次已经
// 踩过这个坑：签完再序列化，某天一个字段顺序或一个转义差异就会让所有设备拒绝
// 启动，而那时候没有任何办法远程补救。

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/siwe"
)

// bootstrap.signing：每租户一把，存 app_configs。私钥用 storage master key 加密
// 后落库，明文不出这个文件，也不出任何 API 响应。
const bootstrapSigningConfigKey = "bootstrap.signing"

// 算法标识。这是我们自己的通道，不是 expo 的，所以取值由我们定：EIP-191 信封 +
// keccak256 + secp256k1 恢复式签名，正是 ethers verifyMessage 的判定。
const bootstrapSigningAlgorithm = "secp256k1-eip191-keccak256"

const bootstrapSigningDefaultKeyID = "main"

// 响应头。客户端可以在**解析之前**验证它收到的原始字节，不需要任何规范化约定。
const bootstrapSignatureHeaderName = "X-Bootstrap-Signature"

type bootstrapSigningKey struct {
	KeyID string `json:"keyId"`
	// PrivateKey 是加密后的 32 字节标量（base64）。任何时候都不出现在响应里。
	PrivateKey string `json:"privateKey"`
	// Address 是客户端要钉住的签名者地址（EIP-55）。公开信息，可以随便打印比对。
	Address string `json:"address"`
}

type bootstrapSigningRecord struct {
	Value     bootstrapSigningKey
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func bootstrapSigningAAD(tenant string) string { return "bootstrap-signing:" + tenant }

// bootstrapSignatureHeader 拼 RFC 8941 字典，与 OTA 那条头同形。三个值都是
// sf-string，必须带引号；base64 里的 `+` `/` `=` 在 sf-string 里合法，但 `"` 与
// `\` 要转义。
func bootstrapSignatureHeader(signature []byte, keyID string) string {
	escape := func(v string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
	}
	return fmt.Sprintf(`sig="%s", keyid="%s", alg="%s"`,
		escape(base64.StdEncoding.EncodeToString(signature)),
		escape(keyID),
		bootstrapSigningAlgorithm,
	)
}

func parseBootstrapSigningKey(raw []byte) (bootstrapSigningKey, error) {
	var v bootstrapSigningKey
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("bootstrap.signing is not valid JSON: %w", err)
	}
	if strings.TrimSpace(v.KeyID) == "" || strings.TrimSpace(v.PrivateKey) == "" {
		return v, errors.New("bootstrap.signing is missing keyId or privateKey")
	}
	return v, nil
}

func (s *server) bootstrapSigningRecord(ctx context.Context, tenant string) (*bootstrapSigningRecord, error) {
	var raw []byte
	var record bootstrapSigningRecord
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, bootstrapSigningConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Value, err = parseBootstrapSigningKey(raw); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *server) decodeBootstrapSigningKey(tenant, stored string) (*secp256k1.PrivateKey, error) {
	if s.secrets == nil {
		return nil, errors.New("storage master key is unavailable")
	}
	encrypted, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, fmt.Errorf("stored bootstrap signing key is not base64: %w", err)
	}
	plaintext, err := s.secrets.Decrypt(encrypted, bootstrapSigningAAD(tenant))
	if err != nil {
		return nil, fmt.Errorf("stored bootstrap signing key cannot be decrypted: %w", err)
	}
	scalar, err := hex.DecodeString(strings.TrimSpace(plaintext))
	if err != nil || len(scalar) != 32 {
		return nil, errors.New("stored bootstrap signing key is not a 32-byte scalar")
	}
	return secp256k1.PrivKeyFromBytes(scalar), nil
}

// signBootstrapBody 给这串字节算签名头。
//
// 没配密钥就返回空串，调用方照常下发**不带签名**的响应——这条链路要能分两个
// 版本上线：服务端先签，客户端先"有就验"，最后才改成"没有就拒"。反过来做会把
// 所有还没升级的设备当场锁在门外。
func (s *server) signBootstrapBody(ctx context.Context, tenant string, body []byte) string {
	if s.db == nil {
		return ""
	}
	record, err := s.bootstrapSigningRecord(ctx, tenant)
	if err != nil || record == nil {
		return ""
	}
	key, err := s.decodeBootstrapSigningKey(tenant, record.Value.PrivateKey)
	if err != nil {
		return ""
	}
	signature, err := siwe.SignPersonal(key, body)
	if err != nil {
		return ""
	}
	return bootstrapSignatureHeader(signature, record.Value.KeyID)
}

// ---- 管理端 ----

func bootstrapSigningView(record *bootstrapSigningRecord) gin.H {
	if record == nil {
		return gin.H{"configured": false, "keyId": nil, "address": nil, "algorithm": bootstrapSigningAlgorithm, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"keyId":      record.Value.KeyID,
		"address":    record.Value.Address,
		"algorithm":  bootstrapSigningAlgorithm,
		"version":    record.Version,
		"updatedBy":  nullableString(record.UpdatedBy),
		"updatedAt":  iso(record.UpdatedAt),
	}
}

func (s *server) getBootstrapSigningKey(c *gin.Context) {
	record, err := s.bootstrapSigningRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_CONFIG_INVALID", "Stored bootstrap.signing configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, bootstrapSigningView(record))
}

type bootstrapSigningGenerate struct {
	KeyID           string `json:"keyId"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// generateBootstrapSigningKey 在服务端生成密钥对。
//
// 与 OTA 那把同理：签每一份响应时服务端本来就要把明文私钥解出来，让它在这里
// 诞生并不扩大暴露面，却省掉了运维机上的明文文件、跨机搬运、以及靠人记得 shred
// 的纪律——那条链路上的每一环都真实地出过错。
//
// 这把密钥与 OTA 签名密钥**分开**：共用一把等于把两个信任域焊在一起，任何一边
// 泄露都同时毁掉另一边。
func (s *server) generateBootstrapSigningKey(c *gin.Context) {
	var body bootstrapSigningGenerate
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BOOTSTRAP_SIGNING_KEY", "expectedVersion, reason and confirm=true are required")
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Storage master key is unavailable")
		return
	}
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Unable to generate a signing key")
		return
	}
	keyID := strings.TrimSpace(body.KeyID)
	if keyID == "" {
		keyID = bootstrapSigningDefaultKeyID
	}
	scalar := key.Key.Bytes()
	encrypted, err := s.secrets.Encrypt(hex.EncodeToString(scalar[:]), bootstrapSigningAAD(tenantID(c)))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Unable to protect the signing key")
		return
	}
	value := bootstrapSigningKey{
		KeyID:      keyID,
		PrivateKey: base64.StdEncoding.EncodeToString(encrypted),
		Address:    siwe.AddressOf(key),
	}
	s.storeBootstrapSigningKey(c, value, body.ExpectedVersion, body.Reason)
}

func (s *server) storeBootstrapSigningKey(c *gin.Context, value bootstrapSigningKey, expectedVersion int, reason string) {
	current, err := s.bootstrapSigningRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_CONFIG_INVALID", "Stored bootstrap.signing configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != expectedVersion {
		problem(c, http.StatusConflict, "STALE_BOOTSTRAP_SIGNING_KEY", "Signing key changed; refresh and retry")
		return
	}
	raw, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if current != nil {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), bootstrapSigningConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), bootstrapSigningConfigKey, raw, actor(c), now, tenantID(c), bootstrapSigningConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_BOOTSTRAP_SIGNING_KEY", "Signing key changed; refresh and retry")
		return
	}
	// 审计里记 keyid 与地址，绝不记私钥
	event := newAudit(tenantID(c), actor(c), "bootstrap_signing_key_generate", "app-config", bootstrapSigningConfigKey, reason, requestID(c), map[string]any{"keyId": value.KeyID, "address": value.Address, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BOOTSTRAP_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	c.JSON(http.StatusOK, bootstrapSigningView(&bootstrapSigningRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}))
}

// writeSignedBootstrap 序列化一次、对这串字节签名、再把**同一串字节**写出去。
//
// 不用 c.JSON：那会再序列化一次，签的就不是客户端实际收到的东西，中间那点差异
// 会成为一个不被签名覆盖的缺口。
func (s *server) writeSignedBootstrap(c *gin.Context, tenant string, payload gin.H) {
	body, err := json.Marshal(payload)
	if err != nil {
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	if header := s.signBootstrapBody(c.Request.Context(), tenant, body); header != "" {
		c.Header(bootstrapSignatureHeaderName, header)
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
