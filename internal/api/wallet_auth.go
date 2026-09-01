package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/siwe"
	"github.com/gin-gonic/gin"
)

/*
钱包身份（Sign-In with Ethereum）。

设计要点：
  - **服务端构造整条 SIWE 消息**并连同 nonce 一起下发，客户端只负责签名。
    这样客户端无法自己编造 domain / 有效期，双方也不会因为拼接差异对不上。
  - nonce 由服务端持有、一次性核销，绑定租户 + 地址，防重放。
  - 地址即账号：首次 verify 成功即完成注册，无邮箱无密码。
  - 服务端永不接触私钥；令牌只存 SHA-256。
*/

const (
	walletNonceTTL      = 10 * time.Minute
	walletSessionTTL    = 7 * 24 * time.Hour
	walletSignStatement = "Sign in to continue. This request will not trigger a blockchain transaction or cost any gas fees."
)

var addressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

var chainIDByName = map[string]int{"eth": 1, "bsc": 56, "base": 8453}

type walletSessionRecord struct {
	ID        string
	UserID    uint64
	Address   string
	Connector string
	Chains    string
	ExpiresAt time.Time
}

func randomNonce() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func newWalletToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := "wtok_" + base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}

func normalizeChains(raw []string) []string {
	seen := map[string]bool{}
	chains := make([]string, 0, len(raw))
	for _, item := range raw {
		name := strings.ToLower(strings.TrimSpace(item))
		if _, ok := chainIDByName[name]; !ok || seen[name] {
			continue
		}
		seen[name] = true
		chains = append(chains, name)
	}
	if len(chains) == 0 {
		chains = []string{"bsc"}
	}
	return chains
}

// buildSIWEMessage renders an EIP-4361 message. Keep the field order and
// spacing exactly as the spec describes; clients only sign it verbatim.
func buildSIWEMessage(domain, address, nonce string, chainID int, issuedAt, expiresAt time.Time) string {
	return strings.Join([]string{
		fmt.Sprintf("%s wants you to sign in with your Ethereum account:", domain),
		address,
		"",
		walletSignStatement,
		"",
		fmt.Sprintf("URI: https://%s", domain),
		"Version: 1",
		fmt.Sprintf("Chain ID: %d", chainID),
		fmt.Sprintf("Nonce: %s", nonce),
		fmt.Sprintf("Issued At: %s", iso(issuedAt)),
		fmt.Sprintf("Expiration Time: %s", iso(expiresAt)),
	}, "\n")
}

func (s *server) walletAuthNonce(c *gin.Context) {
	var body struct {
		Address string   `json:"address"`
		Chains  []string `json:"chains"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_WALLET_AUTH", "Invalid authentication payload")
		return
	}
	body.Address = strings.TrimSpace(body.Address)
	if !addressPattern.MatchString(body.Address) {
		problem(c, 422, "INVALID_WALLET_ADDRESS", "Wallet address is invalid")
		return
	}
	address := siwe.ChecksumAddress(body.Address)
	chains := normalizeChains(body.Chains)
	nonce, err := randomNonce()
	if err != nil {
		problem(c, 500, "WALLET_NONCE_FAILED", "Unable to issue a challenge")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(walletNonceTTL)
	domain := requestDomain(c)
	message := buildSIWEMessage(domain, address, nonce, chainIDByName[chains[0]], now, expires)
	if _, err := s.db.ExecContext(c.Request.Context(),
		`INSERT INTO wallet_auth_nonce(nonce,tenant_id,address_key,domain,message,issued_at,expires_at) VALUES(?,?,?,?,?,?,?)`,
		nonce, tenantID(c), strings.ToLower(address), domain, message, now, expires); err != nil {
		slog.Error("wallet nonce insert failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "WALLET_NONCE_FAILED", "Unable to issue a challenge")
		return
	}
	// 顺手清理过期挑战，避免表无限增长
	_, _ = s.db.ExecContext(c.Request.Context(),
		`DELETE FROM wallet_auth_nonce WHERE expires_at < ? LIMIT 500`, now.Add(-time.Hour))
	c.JSON(http.StatusOK, gin.H{
		"nonce":     nonce,
		"message":   message,
		"issuedAt":  iso(now),
		"expiresAt": iso(expires),
	})
}

func (s *server) walletAuthVerify(c *gin.Context) {
	var body struct {
		Address   string   `json:"address"`
		Nonce     string   `json:"nonce"`
		Signature string   `json:"signature"`
		Connector string   `json:"connector"`
		Chains    []string `json:"chains"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_WALLET_AUTH", "Invalid authentication payload")
		return
	}
	body.Address, body.Nonce = strings.TrimSpace(body.Address), strings.TrimSpace(body.Nonce)
	signature, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(body.Signature), "0x"))
	if !addressPattern.MatchString(body.Address) || body.Nonce == "" || err != nil || len(signature) != 65 {
		problem(c, 422, "INVALID_WALLET_SIGNATURE", "Signature payload is invalid")
		return
	}
	address := siwe.ChecksumAddress(body.Address)
	now := time.Now().UTC()

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	defer tx.Rollback()

	var stored struct {
		AddressKey string
		Domain     string
		Message    string
		ExpiresAt  time.Time
		Consumed   sql.NullTime
	}
	// SELECT ... FOR UPDATE：同一个 nonce 的并发核销必须只有一个成功
	err = tx.QueryRowContext(c.Request.Context(),
		`SELECT address_key,domain,message,expires_at,consumed_at FROM wallet_auth_nonce WHERE nonce=? AND tenant_id=? FOR UPDATE`,
		body.Nonce, tenantID(c)).Scan(&stored.AddressKey, &stored.Domain, &stored.Message, &stored.ExpiresAt, &stored.Consumed)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 401, "WALLET_CHALLENGE_UNKNOWN", "Challenge is unknown; request a new one")
		return
	}
	if err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	if stored.Consumed.Valid {
		problem(c, 401, "WALLET_CHALLENGE_USED", "Challenge has already been used")
		return
	}
	if now.After(stored.ExpiresAt) {
		problem(c, 401, "WALLET_CHALLENGE_EXPIRED", "Challenge has expired; request a new one")
		return
	}
	if stored.AddressKey != strings.ToLower(address) {
		problem(c, 401, "WALLET_CHALLENGE_ADDRESS", "Challenge was issued for a different address")
		return
	}

	recovered, verifyErr := siwe.Verify(siwe.VerifyRequest{
		Message:   stored.Message,
		Signature: signature,
		Domain:    stored.Domain,
		Nonce:     body.Nonce,
		Now:       now,
		MaxAge:    walletNonceTTL,
	})
	if verifyErr != nil || !siwe.SameAddress(recovered, address) {
		// 失败也核销，避免用同一个挑战反复试签名
		_, _ = tx.ExecContext(c.Request.Context(),
			`UPDATE wallet_auth_nonce SET consumed_at=? WHERE nonce=?`, now, body.Nonce)
		_ = tx.Commit()
		problem(c, 401, "WALLET_SIGNATURE_INVALID", "Signature does not match this address")
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(),
		`UPDATE wallet_auth_nonce SET consumed_at=? WHERE nonce=? AND consumed_at IS NULL`, now, body.Nonce); err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}

	// 地址即账号：首次 verify 成功即注册
	result, err := tx.ExecContext(c.Request.Context(),
		`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,created_at,updated_at)
		 VALUES(?,?,?,?,?,1,'active',?,?)
		 ON DUPLICATE KEY UPDATE last_login_at=VALUES(last_login_at),login_count=login_count+1,address=VALUES(address),updated_at=VALUES(updated_at)`,
		tenantID(c), address, strings.ToLower(address), now, now, now, now)
	if err != nil {
		slog.Error("wallet user upsert failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	affected, _ := result.RowsAffected()
	registered := affected == 1 // MySQL: 1 = insert, 2 = update

	var userID uint64
	var status string
	if err := tx.QueryRowContext(c.Request.Context(),
		`SELECT id,status FROM wallet_user WHERE tenant_id=? AND address_key=?`,
		tenantID(c), strings.ToLower(address)).Scan(&userID, &status); err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	if status != "active" {
		problem(c, 403, "WALLET_USER_BLOCKED", "This wallet is not allowed to sign in")
		return
	}

	token, tokenHash, err := newWalletToken()
	if err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	chains := normalizeChains(body.Chains)
	connector := strings.ToLower(strings.TrimSpace(body.Connector))
	if connector == "" || len(connector) > 32 {
		connector = "embedded"
	}
	sessionExpires := now.Add(walletSessionTTL)
	if _, err := tx.ExecContext(c.Request.Context(),
		`INSERT INTO wallet_session(id,tenant_id,user_id,token_hash,connector,chains,issued_at,expires_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		"wses_"+randomID(16), tenantID(c), userID, tokenHash, connector, strings.Join(chains, ","), now, sessionExpires, now); err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, 500, "WALLET_VERIFY_FAILED", "Unable to verify the signature")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"address":      address,
		"connector":    connector,
		"chains":       chains,
		"sessionToken": token,
		"signedInAt":   iso(now),
		"expiresAt":    iso(sessionExpires),
		"registered":   registered,
	})
}

func (s *server) walletAuthSession(c *gin.Context) {
	record, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"address":   record.Address,
		"connector": record.Connector,
		"chains":    strings.Split(record.Chains, ","),
		"expiresAt": iso(record.ExpiresAt),
	})
}

func (s *server) walletAuthLogout(c *gin.Context) {
	record, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE wallet_session SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, now, record.ID); err != nil {
		problem(c, 500, "WALLET_LOGOUT_FAILED", "Unable to sign out")
		return
	}
	c.JSON(http.StatusOK, gin.H{"signedOut": true, "revokedAt": iso(now)})
}

// authenticateWalletSession resolves `Authorization: Wallet <token>` within the
// current tenant. Tokens are compared by hash in constant time.
func (s *server) authenticateWalletSession(c *gin.Context) (walletSessionRecord, bool) {
	var record walletSessionRecord
	header := strings.TrimSpace(c.GetHeader("Authorization"))
	token := strings.TrimSpace(strings.TrimPrefix(header, "Wallet "))
	if token == "" || token == header {
		problem(c, 401, "WALLET_SESSION_REQUIRED", "A wallet session token is required")
		return record, false
	}
	digest := sha256.Sum256([]byte(token))
	hashed := hex.EncodeToString(digest[:])
	var storedHash string
	var revoked sql.NullTime
	err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT s.id,s.user_id,u.address,s.connector,s.chains,s.expires_at,s.token_hash,s.revoked_at
		 FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id
		 WHERE s.tenant_id=? AND s.token_hash=? LIMIT 1`,
		tenantID(c), hashed).Scan(&record.ID, &record.UserID, &record.Address,
		&record.Connector, &record.Chains, &record.ExpiresAt, &storedHash, &revoked)
	if err != nil || revoked.Valid || record.ExpiresAt.Before(time.Now().UTC()) ||
		subtle.ConstantTimeCompare([]byte(storedHash), []byte(hashed)) != 1 {
		problem(c, 401, "WALLET_SESSION_INVALID", "Wallet session is invalid, expired or revoked")
		return record, false
	}
	_, _ = s.db.ExecContext(c.Request.Context(),
		`UPDATE wallet_session SET last_seen_at=? WHERE id=?`, time.Now().UTC(), record.ID)
	return record, true
}

// requestDomain is the host the mobile client actually reached, which is the
// tenant domain the SIWE message must name.
func requestDomain(c *gin.Context) string {
	host := c.Request.Host
	if forwarded := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); forwarded != "" {
		host = strings.Split(forwarded, ",")[0]
	}
	if normalized, err := normalizeHost(host); err == nil {
		return normalized
	}
	return strings.ToLower(strings.TrimSpace(host))
}
