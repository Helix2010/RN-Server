package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/cid"
	"github.com/gin-gonic/gin"
)

// 统一登录：接 ChainUp 认证中心（设计 tenant-console-accounts-and-sso-2026-09-25 §4）。
//
// 流程（浏览器都在 console.<租户域名> 上）：
//
//	GET /v1/admin/auth/cid/start?mode=login|bind&target=/xxx
//	    生成 state 与 PKCE，连同 mode、target、回调地址加密进临时 Cookie rn_cid_flow_<state 前 8 位>
//	    （Path=/client/v1/oauth/login，SameSite=Lax，10 分钟），302 去认证中心授权。
//	    mode=bind 必须来自一个待绑定账号的已登录会话，会话 id 的哈希也进 Cookie。
//	GET /client/v1/oauth/login?code&state     ← 认证中心固定的回调路径，不能自定义
//	    核 state、换令牌、查 userinfo（服务端直连，令牌用完即弃）。
//	    login：按 (租户, 统一认证账号) 找已绑定的账号，设会话 Cookie，回到 target；
//	    bind：把「要绑定的统一认证账号」加密进 rn_cid_bind（Path=/v1/admin/auth/cid，5 分钟），
//	          跳到控制台的确认页；本人确认后才落库（防绑定 CSRF，设计 §4.3「要防的」）。
//	GET  /v1/admin/auth/cid/bind            确认页取「将绑定到哪个账号」
//	POST /v1/admin/auth/cid/bind/confirm    落库：本地口令作废，账号变 active
//
// 回调与会话 Cookie 都在控制台域名上。nginx 转发 console.* 的请求时把 Host 改写成了 api.*，
// 所以控制台域名从 X-RN-Console-Host 头取（nginx 写的），并核对它与 Host 属于同一个租户；
// 就算有人伪造，拼出来的回调地址没在认证中心登记，认证中心也会拒绝。

const (
	cidConfigKey      = "auth.cid"
	cidCallbackPath   = "/client/v1/oauth/login"
	cidFlowCookie     = "rn_cid_flow_"
	cidBindCookie     = "rn_cid_bind"
	cidFlowTTL        = 10 * time.Minute
	cidBindTTL        = 5 * time.Minute
	consoleHostHeader = "X-RN-Console-Host"
)

func cidSecretAAD() string            { return "auth-cid:client-secret" }
func cidFlowAAD(tenant string) string { return "auth-cid:flow:" + tenant }
func cidBindAAD(tenant string) string { return "auth-cid:bind:" + tenant }

// cidStored 是 app_configs 平台级 auth.cid 的 config_value。客户端密钥整份加密。
type cidStored struct {
	AuthorizeURL          string `json:"authorizeUrl"`
	LogoutURL             string `json:"logoutUrl"`
	TokenURL              string `json:"tokenUrl"`
	UserinfoURL           string `json:"userinfoUrl"`
	ClientID              string `json:"clientId"`
	ClientSecretEncrypted string `json:"clientSecretEncrypted"`
}

type cidRecord struct {
	Value     cidStored
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func (s *server) cidRecord(ctx context.Context) (*cidRecord, error) {
	var raw []byte
	var record cidRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, cidConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return nil, err
	}
	return &record, nil
}

// cidClient 组客户端。没配返回 (nil, nil, nil)：统一登录没开不是错误。
func (s *server) cidClient(ctx context.Context) (*cid.Client, *cidRecord, error) {
	record, err := s.cidRecord(ctx)
	if err != nil || record == nil {
		return nil, record, err
	}
	if s.secrets == nil {
		return nil, record, errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(record.Value.ClientSecretEncrypted)
	if err != nil {
		return nil, record, errors.New("stored client secret is not valid base64")
	}
	secret, err := s.secrets.Decrypt(ciphertext, cidSecretAAD())
	if err != nil {
		return nil, record, errors.New("stored client secret cannot be decrypted")
	}
	client, err := cid.New(cid.Config{
		AuthorizeURL: record.Value.AuthorizeURL, LogoutURL: record.Value.LogoutURL,
		TokenURL: record.Value.TokenURL, UserinfoURL: record.Value.UserinfoURL,
		ClientID: record.Value.ClientID, ClientSecret: secret,
	})
	return client, record, err
}

// ---- 平台配置 ----

func cidConfigView(record *cidRecord) gin.H {
	if record == nil {
		return gin.H{"configured": false, "config": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"config": gin.H{
			"authorizeUrl": record.Value.AuthorizeURL,
			"logoutUrl":    record.Value.LogoutURL,
			"tokenUrl":     record.Value.TokenURL,
			"userinfoUrl":  record.Value.UserinfoURL,
			"clientId":     record.Value.ClientID,
			// 密钥永远不回给界面，只说有没有
			"hasClientSecret": record.Value.ClientSecretEncrypted != "",
		},
		"callbackPath": cidCallbackPath,
		"version":      record.Version,
		"updatedBy":    record.UpdatedBy,
		"updatedAt":    iso(record.UpdatedAt),
	}
}

func (s *server) getCIDConfig(c *gin.Context) {
	record, err := s.cidRecord(c.Request.Context())
	if err != nil {
		problem(c, 500, "CID_CONFIG_INVALID", "Stored "+cidConfigKey+" configuration is invalid")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, cidConfigView(record))
}

// updateCIDConfig 保存统一登录的客户端配置。clientSecret 留空表示沿用已存的那一把。
func (s *server) updateCIDConfig(c *gin.Context) {
	var body struct {
		AuthorizeURL    string `json:"authorizeUrl"`
		LogoutURL       string `json:"logoutUrl"`
		TokenURL        string `json:"tokenUrl"`
		UserinfoURL     string `json:"userinfoUrl"`
		ClientID        string `json:"clientId"`
		ClientSecret    string `json:"clientSecret"`
		ExpectedVersion int    `json:"expectedVersion"`
		Reason          string `json:"reason"`
	}
	if decodeLimited(c, &body, 16<<10) != nil || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, 400, "INVALID_CID_CONFIG", "authorizeUrl, logoutUrl, tokenUrl, userinfoUrl, clientId, expectedVersion and reason are required")
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "STORAGE_MASTER_KEY must be configured before saving the client secret")
		return
	}
	ctx := c.Request.Context()
	current, err := s.cidRecord(ctx)
	if err != nil {
		problem(c, 500, "CID_CONFIG_INVALID", "Stored "+cidConfigKey+" configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, 409, "STALE_CID_CONFIG", "The unified login configuration changed; reload and retry")
		return
	}
	secret := body.ClientSecret
	encrypted := ""
	if secret == "" {
		if current == nil {
			problem(c, 422, "INVALID_CID_CONFIG", "clientSecret is required")
			return
		}
		ciphertext, err := base64.RawStdEncoding.DecodeString(current.Value.ClientSecretEncrypted)
		if err != nil {
			problem(c, 500, "CID_CONFIG_INVALID", "Stored client secret is invalid; enter it again")
			return
		}
		if secret, err = s.secrets.Decrypt(ciphertext, cidSecretAAD()); err != nil {
			problem(c, 500, "CID_CONFIG_INVALID", "Stored client secret cannot be decrypted; enter it again")
			return
		}
		encrypted = current.Value.ClientSecretEncrypted
	}
	client, err := cid.New(cid.Config{AuthorizeURL: body.AuthorizeURL, LogoutURL: body.LogoutURL, TokenURL: body.TokenURL,
		UserinfoURL: body.UserinfoURL, ClientID: body.ClientID, ClientSecret: secret})
	if err != nil {
		problem(c, 422, "INVALID_CID_CONFIG", err.Error())
		return
	}
	if encrypted == "" {
		ciphertext, err := s.secrets.Encrypt(secret, cidSecretAAD())
		if err != nil {
			problem(c, 500, "CID_CONFIG_SAVE_FAILED", "Unable to encrypt the client secret")
			return
		}
		encrypted = base64.RawStdEncoding.EncodeToString(ciphertext)
	}
	cfg := client.Config()
	value := cidStored{AuthorizeURL: cfg.AuthorizeURL, LogoutURL: cfg.LogoutURL, TokenURL: cfg.TokenURL,
		UserinfoURL: cfg.UserinfoURL, ClientID: cfg.ClientID, ClientSecretEncrypted: encrypted}
	stored, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "CID_CONFIG_SAVE_FAILED", "Unable to save the unified login configuration")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	if currentVersion > 0 {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, actor(c), now, platformTenantID, cidConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			platformTenantID, cidConfigKey, stored, actor(c), now, platformTenantID, cidConfigKey)
	}
	if err != nil {
		problem(c, 500, "CID_CONFIG_SAVE_FAILED", "Unable to save the unified login configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "STALE_CID_CONFIG", "The unified login configuration changed; reload and retry")
		return
	}
	event := newAudit(platformTenantID, actor(c), "cid_config_update", "app-config", cidConfigKey, body.Reason, requestID(c),
		map[string]any{"authorizeUrl": cfg.AuthorizeURL, "logoutUrl": cfg.LogoutURL, "tokenUrl": cfg.TokenURL,
			"userinfoUrl": cfg.UserinfoURL, "clientId": cfg.ClientID, "secretChanged": body.ClientSecret != "", "databaseVersion": currentVersion + 1})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "CID_CONFIG_SAVE_FAILED", "Unable to save the unified login configuration")
		return
	}
	c.JSON(200, cidConfigView(&cidRecord{Value: value, Version: currentVersion + 1, UpdatedBy: actor(c), UpdatedAt: now}))
}

// deleteCIDConfig 关掉统一登录。已绑定的账号之后登不进来，直到重新配置；平台账号不受影响。
func (s *server) deleteCIDConfig(c *gin.Context) {
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) < 3 {
		problem(c, 400, "INVALID_CID_CONFIG", "reason is required")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "CID_CONFIG_DELETE_FAILED", "Unable to delete the unified login configuration")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, cidConfigKey)
	if err != nil {
		problem(c, 500, "CID_CONFIG_DELETE_FAILED", "Unable to delete the unified login configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 404, "CID_CONFIG_NOT_FOUND", "Unified login is not configured")
		return
	}
	event := newAudit(platformTenantID, actor(c), "cid_config_delete", "app-config", cidConfigKey, reason, requestID(c), map[string]any{})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "CID_CONFIG_DELETE_FAILED", "Unable to delete the unified login configuration")
		return
	}
	c.JSON(200, cidConfigView(nil))
}

// ---- 登录与绑定 ----

// consoleHost 是浏览器地址栏里的控制台域名。nginx 转发 console.* 时写 X-RN-Console-Host；
// 没有这个头（直连 api.*、本机调试）就用 Host。头里的域名必须与 Host 属于同一个租户，否则不采信。
func (s *server) consoleHost(c *gin.Context) string {
	host, err := normalizeHost(c.Request.Host)
	if err != nil {
		host = c.Request.Host
	}
	claimed := strings.TrimSpace(c.GetHeader(consoleHostHeader))
	if claimed == "" {
		return host
	}
	normalized, err := normalizeHost(claimed)
	if err != nil {
		return host
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	claimedTenant, err1 := s.tenant.resolve(ctx, normalized)
	hostTenant, err2 := s.tenant.resolve(ctx, host)
	if err1 != nil || err2 != nil || claimedTenant.ID != hostTenant.ID {
		return host
	}
	return normalized
}

// cidFlow 是临时 Cookie 里的发起状态。
type cidFlow struct {
	State       string    `json:"s"`
	Verifier    string    `json:"v"`
	Mode        string    `json:"m"`
	Target      string    `json:"t"`
	RedirectURI string    `json:"r"`
	SessionHash string    `json:"h,omitempty"`
	ExpiresAt   time.Time `json:"e"`
}

// cidPendingBind 是回调之后、本人确认之前的「要绑定哪个统一认证账号」。
type cidPendingBind struct {
	SessionHash string    `json:"h"`
	AccountID   string    `json:"a"`
	Subject     string    `json:"sub"`
	Email       string    `json:"email"`
	ExpiresAt   time.Time `json:"e"`
}

func (s *server) sealCookie(v any, aad string) (string, error) {
	if s.secrets == nil {
		return "", errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	ciphertext, err := s.secrets.Encrypt(string(raw), aad)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (s *server) openCookie(value, aad string, out any) error {
	if s.secrets == nil {
		return errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}
	plain, err := s.secrets.Decrypt(ciphertext, aad)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plain), out)
}

// safeConsoleTarget 只收本控制台的相对路径；拒绝 //、/\、/v1/、/client/ 开头与控制字符。
func safeConsoleTarget(raw string) string {
	if raw == "" || len(raw) > 512 || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") ||
		strings.HasPrefix(raw, "/v1/") || strings.HasPrefix(raw, "/client/") || strings.ContainsAny(raw, "\r\n\t\\") {
		return "/"
	}
	if parsed, err := url.Parse(raw); err != nil || parsed.Scheme != "" || parsed.Host != "" {
		return "/"
	}
	return raw
}

// cidFail 回到控制台首页并带一个错误码，由控制台显示原因。只放固定的码，不回显任何外部输入。
func cidFail(c *gin.Context, code string) {
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, "/?cidError="+url.QueryEscape(code))
}

func (s *server) startCIDLogin(c *gin.Context) {
	ctx := c.Request.Context()
	client, _, err := s.cidClient(ctx)
	if err != nil {
		slog.Error("unified login is misconfigured", "error", err)
		cidFail(c, "misconfigured")
		return
	}
	if client == nil {
		cidFail(c, "not_configured")
		return
	}
	flow := cidFlow{Mode: c.Query("mode"), Target: safeConsoleTarget(c.Query("target")), ExpiresAt: time.Now().UTC().Add(cidFlowTTL)}
	switch flow.Mode {
	case "login":
	case "bind":
		session, err := s.loadAdminSession(c)
		if err != nil {
			cidFail(c, "internal")
			return
		}
		if session == nil || !session.tenantScoped() || session.Account.Status != accountPendingBind {
			cidFail(c, "bind_not_allowed")
			return
		}
		flow.SessionHash = session.TokenHash
		flow.Target = "/"
	default:
		problem(c, 400, "INVALID_CID_MODE", "mode must be login or bind")
		return
	}
	host := s.consoleHost(c)
	flow.RedirectURI = "https://" + host + cidCallbackPath
	state, err := cid.NewState()
	if err != nil {
		cidFail(c, "internal")
		return
	}
	verifier, challenge, err := cid.NewPKCE()
	if err != nil {
		cidFail(c, "internal")
		return
	}
	flow.State, flow.Verifier = state, verifier
	sealed, err := s.sealCookie(flow, cidFlowAAD(tenantID(c)))
	if err != nil {
		cidFail(c, "internal")
		return
	}
	// 名字按 state 区分：多个标签页同时登录不会互相覆盖
	http.SetCookie(c.Writer, &http.Cookie{Name: cidFlowCookie + state[:8], Value: sealed, Path: cidCallbackPath,
		MaxAge: int(cidFlowTTL.Seconds()), HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteLaxMode})
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, client.AuthorizeURL(host, flow.RedirectURI, state, challenge))
}

func (s *server) cidCallback(c *gin.Context) {
	ctx := c.Request.Context()
	state := c.Query("state")
	if len(state) < 8 {
		cidFail(c, "state")
		return
	}
	cookieName := cidFlowCookie + state[:8]
	raw, err := c.Cookie(cookieName)
	// 不论成败都清掉：一次性
	http.SetCookie(c.Writer, &http.Cookie{Name: cookieName, Value: "", Path: cidCallbackPath, MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteLaxMode})
	var flow cidFlow
	if err != nil || s.openCookie(raw, cidFlowAAD(tenantID(c)), &flow) != nil || !constantEqual(flow.State, state) || time.Now().UTC().After(flow.ExpiresAt) {
		cidFail(c, "state")
		return
	}
	if c.Query("error") != "" {
		cidFail(c, "denied")
		return
	}
	code := c.Query("code")
	if code == "" {
		cidFail(c, "state")
		return
	}
	client, _, err := s.cidClient(ctx)
	if err != nil || client == nil {
		cidFail(c, "not_configured")
		return
	}
	accessToken, err := client.Exchange(ctx, code, flow.RedirectURI, flow.Verifier)
	if err != nil {
		slog.Warn("unified login code exchange failed", "error", err, "tenant", tenantID(c))
		cidFail(c, "exchange")
		return
	}
	user, err := client.UserInfo(ctx, accessToken)
	if err != nil {
		slog.Warn("unified login userinfo failed", "error", err, "tenant", tenantID(c))
		cidFail(c, "userinfo")
		return
	}
	if flow.Mode == "bind" {
		s.cidCallbackBind(c, flow, user)
		return
	}
	acc, err := s.tenantAccountBySubject(ctx, tenantID(c), user.Subject)
	if err != nil {
		cidFail(c, "internal")
		return
	}
	if acc == nil {
		cidFail(c, "unbound")
		return
	}
	if acc.Status != accountActive {
		cidFail(c, "disabled")
		return
	}
	_, token, err := s.createAdminSession(ctx, tenantActor(tenantID(c), acc.ID), tenantID(c), acc.ID, loginMethodCID)
	if err != nil {
		cidFail(c, "internal")
		return
	}
	s.touchTenantAccountLogin(ctx, acc.ID)
	s.setSessionCookie(c, token)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, flow.Target)
}

func (s *server) cidCallbackBind(c *gin.Context, flow cidFlow, user cid.User) {
	ctx := c.Request.Context()
	var accountID sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT account_id FROM admin_sessions WHERE token_hash=? AND tenant_id=? AND expires_at>? LIMIT 1`,
		flow.SessionHash, tenantID(c), time.Now().UTC()).Scan(&accountID)
	if err != nil || !accountID.Valid {
		cidFail(c, "bind_session")
		return
	}
	acc, err := s.tenantAccountByID(ctx, tenantID(c), accountID.String)
	if err != nil || acc == nil || acc.Status != accountPendingBind {
		cidFail(c, "bind_not_allowed")
		return
	}
	if other, err := s.tenantAccountBySubject(ctx, tenantID(c), user.Subject); err != nil {
		cidFail(c, "internal")
		return
	} else if other != nil {
		cidFail(c, "already_bound")
		return
	}
	sealed, err := s.sealCookie(cidPendingBind{SessionHash: flow.SessionHash, AccountID: acc.ID, Subject: user.Subject, Email: user.Email,
		ExpiresAt: time.Now().UTC().Add(cidBindTTL)}, cidBindAAD(tenantID(c)))
	if err != nil {
		cidFail(c, "internal")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: cidBindCookie, Value: sealed, Path: "/v1/admin/auth/cid",
		MaxAge: int(cidBindTTL.Seconds()), HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, "/cid/bind-confirm")
}

// pendingBindFor 读 rn_cid_bind，核对它属于当前会话与当前账号。
func (s *server) pendingBindFor(c *gin.Context) (*cidPendingBind, *adminSession) {
	session := currentAdminSession(c)
	if !session.tenantScoped() || session.Account.Status != accountPendingBind {
		return nil, session
	}
	raw, err := c.Cookie(cidBindCookie)
	if err != nil {
		return nil, session
	}
	var pending cidPendingBind
	if s.openCookie(raw, cidBindAAD(session.TenantID), &pending) != nil || time.Now().UTC().After(pending.ExpiresAt) ||
		!constantEqual(pending.SessionHash, session.TokenHash) || pending.AccountID != session.AccountID {
		return nil, session
	}
	return &pending, session
}

func (s *server) getPendingCIDBind(c *gin.Context) {
	pending, session := s.pendingBindFor(c)
	c.Header("Cache-Control", "no-store")
	if pending == nil {
		problem(c, 404, "CID_BIND_NOT_PENDING", "There is no unified login account waiting to be bound; start binding again")
		return
	}
	c.JSON(200, gin.H{"account": session.Account.sessionView(), "cid": gin.H{"email": nullableString(pending.Email)}, "expiresAt": iso(pending.ExpiresAt)})
}

func (s *server) confirmCIDBind(c *gin.Context) {
	pending, session := s.pendingBindFor(c)
	if pending == nil {
		problem(c, 404, "CID_BIND_NOT_PENDING", "There is no unified login account waiting to be bound; start binding again")
		return
	}
	ctx := c.Request.Context()
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "CID_BIND_FAILED", "Unable to bind the account")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx,
		`UPDATE tenant_admin_accounts SET idp=?,idp_subject=?,idp_email=?,status=?,password_hash=NULL,password_expires_at=NULL,bound_at=?,updated_at=? WHERE id=? AND tenant_id=? AND status=?`,
		idpChainupCID, pending.Subject, nullIfEmpty(pending.Email), accountActive, now, now, session.AccountID, session.TenantID, accountPendingBind)
	if isDuplicateEntry(err) {
		problem(c, 409, "CID_ACCOUNT_ALREADY_BOUND", "This unified login account is already bound to another account of this tenant")
		return
	}
	if err != nil {
		problem(c, 500, "CID_BIND_FAILED", "Unable to bind the account")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "CID_BIND_NOT_PENDING", "The account is no longer waiting to be bound")
		return
	}
	event := newAudit(session.TenantID, session.Actor, "tenant_account_bind", "tenant-account", session.AccountID, "绑定统一认证账号", requestID(c),
		map[string]any{"idp": idpChainupCID, "subject": pending.Subject, "email": nullableString(pending.Email), "loginName": session.Account.LoginName})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "CID_BIND_FAILED", "Unable to bind the account")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: cidBindCookie, Value: "", Path: "/v1/admin/auth/cid", MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	acc, err := s.tenantAccountByID(ctx, session.TenantID, session.AccountID)
	if err == nil && acc != nil {
		session.Account = acc
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, s.sessionView(c, session, "session"))
}
