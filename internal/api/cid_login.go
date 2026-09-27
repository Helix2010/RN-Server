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
	"regexp"
	"strings"
	"time"

	"github.com/Helix2010/authorization-go-sdk/cid"
	"github.com/gin-gonic/gin"
)

// 统一登录：接 ChainUp 认证中心（设计 tenant-console-accounts-and-sso-2026-09-25 §4）。
//
// 流程（浏览器都在 console.<租户域名> 上）：
//
//	GET /v1/admin/auth/cid/start?mode=login&target=/xxx
//	    生成 state 与 PKCE，连同 target、回调地址加密进临时 Cookie rn_cid_flow_<state 前 8 位>
//	    （Path=/client/v1/oauth/login，SameSite=Lax，10 分钟），302 去认证中心授权。
//	GET /client/v1/oauth/login?code&state     ← 认证中心固定的回调路径，不能自定义
//	    核 state、换令牌、查 userinfo（服务端直连，令牌用完即弃），按统一认证账号认人（accountForLogin），
//	    设会话 Cookie，回到 target。
//
// 账号由外部系统写进 tenant_admin_accounts，RN 不建号、不绑定、不自动开户
// （设计 console-accounts-external-maintenance-2026-09-27 §4.1）。
//
// 回调与会话 Cookie 都在控制台域名上。nginx 转发 console.* 的请求时把 Host 改写成了 api.*，
// 所以控制台域名从 X-RN-Console-Host 头取（nginx 写的），并核对它与 Host 属于同一个租户；
// 就算有人伪造，拼出来的回调地址没在认证中心登记，认证中心也会拒绝。

const (
	cidConfigKey      = "auth.cid"
	cidCallbackPath   = "/client/v1/oauth/login"
	cidFlowCookie     = "rn_cid_flow_"
	cidFlowTTL        = 10 * time.Minute
	consoleHostHeader = "X-RN-Console-Host"
)

// cidHTTPClient 给每次现组的 cid.Client 共用：配置能在运行中改，所以每个请求都重新 New，
// 共用一个客户端才复用得上连接（它自带 HTTP/2 心跳，SDK 另外保证不跟随重定向）。
var cidHTTPClient = cid.DefaultHTTPClient()

// cidSubjectPattern：认证中心的账号 id 是 uuid。对不上就拒绝，不猜——换了格式要先看清楚再放行。
var cidSubjectPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// cidSubject 从 userinfo 取统一认证账号 id，统一成小写（表里存的样子，CHECK 只收小写 uuid）。
// userinfo 里的邮箱不用：二次验证发到外部系统写在账号记录里的邮箱。
// SDK 只挡空白与控制字符，uuid 这条是 RN 自己的要求。错误里不带对方给的值。
func cidSubject(info *cid.User) (string, error) {
	if info == nil || !cidSubjectPattern.MatchString(info.Subject) {
		return "", errors.New("unified login returned an account id that is not a uuid")
	}
	return strings.ToLower(info.Subject), nil
}

func cidSecretAAD() string            { return "auth-cid:client-secret" }
func cidFlowAAD(tenant string) string { return "auth-cid:flow:" + tenant }

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
		Endpoints: cid.Endpoints{
			AuthorizeURL: record.Value.AuthorizeURL, LogoutURL: record.Value.LogoutURL,
			TokenURL: record.Value.TokenURL, UserInfoURL: record.Value.UserinfoURL,
		},
		ClientID: record.Value.ClientID, ClientSecret: secret, HTTPClient: cidHTTPClient,
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
	endpoints := cid.Endpoints{
		AuthorizeURL: strings.TrimSpace(body.AuthorizeURL), LogoutURL: strings.TrimSpace(body.LogoutURL),
		TokenURL: strings.TrimSpace(body.TokenURL), UserInfoURL: strings.TrimSpace(body.UserinfoURL),
	}
	clientID := strings.TrimSpace(body.ClientID)
	// 地址规则由 SDK 定：给浏览器的必须 https；服务端直连的只有本机、内网 IP 可以 http
	if _, err := cid.New(cid.Config{Endpoints: endpoints, ClientID: clientID, ClientSecret: secret}); err != nil {
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
	value := cidStored{AuthorizeURL: endpoints.AuthorizeURL, LogoutURL: endpoints.LogoutURL, TokenURL: endpoints.TokenURL,
		UserinfoURL: endpoints.UserInfoURL, ClientID: clientID, ClientSecretEncrypted: encrypted}
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
		map[string]any{"authorizeUrl": value.AuthorizeURL, "logoutUrl": value.LogoutURL, "tokenUrl": value.TokenURL,
			"userinfoUrl": value.UserinfoURL, "clientId": value.ClientID, "secretChanged": body.ClientSecret != "", "databaseVersion": currentVersion + 1})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "CID_CONFIG_SAVE_FAILED", "Unable to save the unified login configuration")
		return
	}
	c.JSON(200, cidConfigView(&cidRecord{Value: value, Version: currentVersion + 1, UpdatedBy: actor(c), UpdatedAt: now}))
}

// deleteCIDConfig 关掉统一登录。控制台只有统一登录，删了之后所有账号都登不进来（包括删的人自己），
// 只能靠自动化通道重新配置——所以只许自动化通道删，控制台会话一律 409；要换认证中心直接改（PUT）。
func (s *server) deleteCIDConfig(c *gin.Context) {
	if currentAdminSession(c) != nil {
		problem(c, 409, "CID_REQUIRED_FOR_CONSOLE_LOGIN", "Deleting the unified login configuration would lock every console account out, including yours; change it instead")
		return
	}
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
	Target      string    `json:"t"`
	RedirectURI string    `json:"r"`
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
	if c.Query("mode") != "login" {
		problem(c, 400, "INVALID_CID_MODE", "mode must be login")
		return
	}
	flow := cidFlow{Target: safeConsoleTarget(c.Query("target")), ExpiresAt: time.Now().UTC().Add(cidFlowTTL)}
	host := s.consoleHost(c)
	flow.RedirectURI = "https://" + host + cidCallbackPath
	// state 与 PKCE 由 SDK 生成；时效与「只认发起它的浏览器」仍由我们的加密 Cookie 管
	authorizeURL, started, err := client.Start(cid.StartOptions{RedirectURI: flow.RedirectURI, Host: host})
	if err != nil {
		cidFail(c, "internal")
		return
	}
	flow.State, flow.Verifier = started.State, started.CodeVerifier
	sealed, err := s.sealCookie(flow, cidFlowAAD(tenantID(c)))
	if err != nil {
		cidFail(c, "internal")
		return
	}
	// 名字按 state 区分：多个标签页同时登录不会互相覆盖
	http.SetCookie(c.Writer, &http.Cookie{Name: cidFlowCookie + flow.State[:8], Value: sealed, Path: cidCallbackPath,
		MaxAge: int(cidFlowTTL.Seconds()), HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteLaxMode})
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, authorizeURL)
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
	// 令牌只在这里用一次；认证中心同时发的 refresh_token 直接丢掉，我们不代表用户长期访问认证中心
	exchanged, err := client.Exchange(ctx, code, flow.RedirectURI, flow.Verifier)
	if err != nil {
		slog.Warn("unified login code exchange failed", "error", err, "tenant", tenantID(c))
		cidFail(c, "exchange")
		return
	}
	info, err := client.UserInfo(ctx, exchanged.AccessToken)
	var subject string
	if err == nil {
		subject, err = cidSubject(info)
	}
	if err != nil {
		slog.Warn("unified login userinfo failed", "error", err, "tenant", tenantID(c))
		cidFail(c, "userinfo")
		return
	}
	accounts, err := s.accountsBySubject(ctx, subject)
	if err != nil {
		cidFail(c, "internal")
		return
	}
	acc, refused := accountForLogin(accounts, tenantID(c))
	if refused == "identity_conflict" {
		ids := make([]string, 0, len(accounts))
		for _, a := range accounts {
			ids = append(ids, a.Scope+":"+a.ID)
		}
		slog.Warn("unified login refused: the account is both a platform administrator and a tenant member", "subject", subject, "accounts", ids, "tenant", tenantID(c))
	}
	if refused != "" {
		cidFail(c, refused)
		return
	}
	// 平台管理员的会话不属于任何租户（tenant_id 为 NULL），在任何控制台域名上都有效
	_, token, err := s.createAdminSession(ctx, acc.actor(), acc.TenantID, acc.ID, acc.IDPSubject)
	if err != nil {
		cidFail(c, "internal")
		return
	}
	s.touchTenantAccountLogin(ctx, acc.ID)
	s.setSessionCookie(c, token)
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, flow.Target)
}

// accountForLogin 按统一认证账号的全部记录决定这次登录用哪个身份（设计 console-accounts-external-maintenance §4.1）：
//   - 既有平台记录又有任何一条租户记录 → identity_conflict（外部系统写错了，不猜）；
//   - 只有平台记录 → 平台管理员；
//   - 有当前域名所属租户的记录 → 这个租户的成员；
//   - 其余 → no_access。
//
// 选中的账号不是 active → disabled。
func accountForLogin(accounts []*tenantAccount, tenant string) (*tenantAccount, string) {
	var platform, here *tenantAccount
	members := 0
	for _, a := range accounts {
		if a.platform() {
			platform = a
			continue
		}
		members++
		if a.TenantID == tenant {
			here = a
		}
	}
	acc := here
	switch {
	case platform != nil && members > 0:
		return nil, "identity_conflict"
	case platform != nil:
		acc = platform
	case here == nil:
		return nil, "no_access"
	}
	if acc.Status != accountActive {
		return nil, "disabled"
	}
	return acc, ""
}
