package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 管理端会话分平台 / 租户（设计 tenant-console-accounts-and-sso-2026-09-25 §3.3）。
//
//   - 平台会话：环境变量里那一个管理员账号（ADMIN_USERNAME）登出来的，admin_sessions.tenant_id 为 NULL。
//     能不能进平台页照旧看 PLATFORM_ADMIN_USERNAMES。
//   - 租户会话：tenant_admin_accounts 里的账号登出来的，记下租户与账号。
//     **只在这个租户的域名上有效**：请求域名的租户与会话租户不一致，一律当没登录；
//     每个请求都回表查账号状态，停用立即生效；永远不是平台管理员，不管它的 actor 长什么样。
//   - 待绑定（pending_bind）的租户账号只能查会话、登出、走绑定那几条接口，别的一律 403 BIND_REQUIRED。
//
// 自动化通道（x-admin-key）不落会话，身份来自配置，按平台会话处理（与改动之前一致）。

const (
	adminSessionCookie = "rn_admin_session"
	loginMethodCID     = "cid"
	loginMethodLocal   = "password"
)

// adminSession 是一次请求带来的会话。
type adminSession struct {
	TokenHash   string
	Actor       string
	ExpiresAt   time.Time
	TenantID    string // 空 = 平台会话
	AccountID   string // 空 = 平台会话
	LoginMethod string
	Account     *tenantAccount // 租户会话才有
}

func (a *adminSession) tenantScoped() bool { return a != nil && a.TenantID != "" }

// tenantActor 是租户账号在审计里的 actor。带冒号，与 ADMIN_USERNAME 的取值空间分开。
func tenantActor(tenant, account string) string { return "tenant:" + tenant + ":" + account }

// pendingBindRoutes 是待绑定账号能走的接口（c.FullPath() 模板）。其余一律 403。
var pendingBindRoutes = map[string]bool{
	"GET /v1/admin/auth/session":           true,
	"POST /v1/admin/auth/logout":           true,
	"GET /v1/admin/auth/cid/bind":          true,
	"POST /v1/admin/auth/cid/bind/code":    true,
	"POST /v1/admin/auth/cid/bind/confirm": true,
}

// loadAdminSession 读并校验请求带的会话 Cookie。没有、过期、租户对不上、账号停用都返回 nil。
// 出库错误单独返回，调用方按 500 处理，不要当成「没登录」把人踢回登录页。
func (s *server) loadAdminSession(c *gin.Context) (*adminSession, error) {
	cookie, err := c.Cookie(adminSessionCookie)
	if err != nil || cookie == "" {
		return nil, nil
	}
	ctx := c.Request.Context()
	session := adminSession{TokenHash: sha256Hex(cookie)}
	var tenant, account, method sql.NullString
	err = s.db.QueryRowContext(ctx,
		`SELECT actor_id, expires_at, tenant_id, account_id, login_method FROM admin_sessions WHERE token_hash=? AND expires_at>? LIMIT 1`,
		session.TokenHash, time.Now().UTC()).Scan(&session.Actor, &session.ExpiresAt, &tenant, &account, &method)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	session.LoginMethod = loginMethodLocal
	if method.Valid && method.String != "" {
		session.LoginMethod = method.String
	}
	if !tenant.Valid || tenant.String == "" {
		return &session, nil
	}
	session.TenantID, session.AccountID = tenant.String, account.String
	host, err := s.tenant.resolve(ctx, c.Request.Host)
	if err != nil || host.ID != session.TenantID {
		// 别的租户的会话拿到这个域名上来：当没登录，而不是 403——对这个域名来说它确实没登录
		return nil, nil
	}
	acc, err := s.tenantAccountByID(ctx, session.TenantID, session.AccountID)
	if err != nil {
		return nil, err
	}
	if acc == nil || acc.Status == accountDisabled {
		return nil, nil
	}
	session.Account = acc
	return &session, nil
}

func (s *server) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := s.loadAdminSession(c)
		if err != nil {
			problem(c, http.StatusInternalServerError, "SESSION_LOOKUP_FAILED", "Unable to verify the admin session")
			c.Abort()
			return
		}
		if session != nil {
			if !safeMethod(c.Request.Method) && !s.adminOriginAllowed(c) {
				problem(c, 403, "UNTRUSTED_ORIGIN", "Untrusted admin request origin")
				c.Abort()
				return
			}
			if session.tenantScoped() && session.Account.Status == accountPendingBind &&
				!pendingBindRoutes[c.Request.Method+" "+c.FullPath()] {
				problem(c, http.StatusForbidden, "BIND_REQUIRED", "Bind a unified login account before using the console")
				c.Abort()
				return
			}
			c.Set("adminSession", session)
			c.Set("actorId", session.Actor)
			c.Set("authMethod", "session")
			c.Set("expiresAt", iso(session.ExpiresAt))
			c.Next()
			return
		}
		// x-admin-key 自动化通道：身份来自配置里绑定的 actor，不是请求自报的 x-admin-id。
		// 自报身份任何持钥者都能随便写，写进 audit_events 的 actor 就成了攻击者可控的字段，
		// 事后追责等于没有依据（安全评审 N17）。请求仍然可以带那个头，只是不再被采纳。
		if key := c.GetHeader("x-admin-key"); s.cfg.AdminAPIKey != "" && constantEqual(key, s.cfg.AdminAPIKey) {
			// 密钥对了还要看来源：这把密钥长期有效、没有账号绑定，泄露之后
			// 唯一还能拦住它的就是"不是从我们的机器发出来的"（安全评审 N17）
			if !s.adminIPs.allows(c.ClientIP()) {
				slog.Warn("admin api key used from an address outside the allowlist", "clientIp", c.ClientIP(), "path", c.Request.URL.Path)
				problem(c, http.StatusForbidden, "ADMIN_SOURCE_NOT_ALLOWED", "This automation credential is not accepted from this address")
				c.Abort()
				return
			}
			if claimed := strings.TrimSpace(c.GetHeader("x-admin-id")); claimed != "" && claimed != s.cfg.AdminAPIActor {
				slog.Warn("ignoring self-declared admin identity on api-key request", "claimed", claimed, "actor", s.cfg.AdminAPIActor, "path", c.Request.URL.Path)
			}
			c.Set("actorId", s.cfg.AdminAPIActor)
			c.Set("authMethod", "api-key")
			c.Set("expiresAt", nil)
			c.Next()
			return
		}
		problem(c, 401, "ADMIN_AUTH_REQUIRED", "Admin authentication required")
		c.Abort()
	}
}

// currentAdminSession 取 authenticate 放进上下文的会话；自动化通道没有会话，返回 nil。
func currentAdminSession(c *gin.Context) *adminSession {
	v, ok := c.Get("adminSession")
	if !ok {
		return nil
	}
	session, _ := v.(*adminSession)
	return session
}

// platformAdminRequest：租户会话永远不是平台管理员；其余照旧看 PLATFORM_ADMIN_USERNAMES。
func (s *server) platformAdminRequest(c *gin.Context) bool {
	if currentAdminSession(c).tenantScoped() {
		return false
	}
	return s.isPlatformAdmin(actor(c))
}

// adminOriginAllowed 是改状态的管理请求的来源检查（设计 §3.3 最后一条）。
//
// 以前任何租户域名都算可信来源，于是 A 租户控制台页面上的脚本能对 B 租户的域名发改动请求。
// 现在 Origin 必须与请求域名属于**同一个租户**。CORS_ORIGINS 里显式配的来源（本机调试的
// http://localhost:5173 这类）照旧放行：那是运维写进配置的，不经过租户域名表。
func (s *server) adminOriginAllowed(c *gin.Context) bool {
	origin := c.GetHeader("Origin")
	for _, allowed := range s.cfg.CORSOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	originTenant, ok := s.originTenant(origin)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()
	host, err := s.tenant.resolve(ctx, c.Request.Host)
	return err == nil && host.ID == originTenant
}

// originTenant 把 Origin 解析成租户 id；只认 https、不带路径的正常 Origin。
func (s *server) originTenant(origin string) (string, bool) {
	if s.tenant == nil || origin == "" {
		return "", false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	item, err := s.tenant.resolve(ctx, parsed.Hostname())
	if err != nil {
		return "", false
	}
	return item.ID, true
}

// login 两条路：用户名等于 ADMIN_USERNAME 走平台账号（与改动之前一致）；否则按请求域名的租户找租户账号，
// 只有待绑定的账号能用初始口令登录，已绑定的要走统一登录。
func (s *server) login(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(c, &input); err != nil || input.Username == "" || input.Password == "" || len(input.Password) > 1024 || len(input.Username) > 120 {
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	if s.rateLimited(c.ClientIP()) {
		problem(c, 429, "LOGIN_RATE_LIMITED", "Too many login attempts")
		return
	}
	username := strings.TrimSpace(input.Username)
	if s.cfg.AdminUsername != "" && constantEqual(username, s.cfg.AdminUsername) {
		if !verifyPassword(input.Password, s.cfg.AdminPasswordHash) {
			s.failedLogin(c.ClientIP())
			problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
			return
		}
		s.clearLoginFailures(c.ClientIP())
		session, token, err := s.createAdminSession(c.Request.Context(), s.cfg.AdminUsername, "", "", loginMethodLocal)
		if err != nil {
			problem(c, 500, "SESSION_CREATE_FAILED", "Unable to create admin session")
			return
		}
		s.setSessionCookie(c, token)
		c.Header("Cache-Control", "no-store")
		c.JSON(200, s.sessionView(c, session, "session"))
		return
	}
	s.tenantAccountLogin(c, strings.ToLower(username), input.Password)
}

func (s *server) tenantAccountLogin(c *gin.Context, loginName, password string) {
	ctx := c.Request.Context()
	fail := func() {
		s.failedLogin(c.ClientIP())
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
	}
	tenant, err := s.tenant.resolve(ctx, c.Request.Host)
	if err != nil {
		verifyPassword(password, dummyPasswordHash())
		fail()
		return
	}
	acc, hash, err := s.tenantAccountForLogin(ctx, tenant.ID, loginName)
	if err != nil {
		problem(c, 500, "SESSION_CREATE_FAILED", "Unable to create admin session")
		return
	}
	if acc == nil || acc.Status == accountDisabled {
		verifyPassword(password, dummyPasswordHash())
		fail()
		return
	}
	if acc.Status == accountActive {
		// 已绑定的账号本地口令已经作废。记一次失败，免得有人拿这个回答批量探登录名
		s.failedLogin(c.ClientIP())
		problem(c, http.StatusConflict, "ACCOUNT_BOUND_USE_CID", "This account is bound to a unified login account; sign in with unified login")
		return
	}
	if hash == "" || !verifyPassword(password, hash) {
		fail()
		return
	}
	if acc.PasswordExpiresAt == nil || !time.Now().UTC().Before(*acc.PasswordExpiresAt) {
		problem(c, 401, "INITIAL_PASSWORD_EXPIRED", "The initial password has expired; ask a platform administrator to reset it")
		return
	}
	s.clearLoginFailures(c.ClientIP())
	session, token, err := s.createAdminSession(ctx, tenantActor(tenant.ID, acc.ID), tenant.ID, acc.ID, loginMethodLocal)
	if err != nil {
		problem(c, 500, "SESSION_CREATE_FAILED", "Unable to create admin session")
		return
	}
	s.touchTenantAccountLogin(ctx, acc.ID)
	session.Account = acc
	s.setSessionCookie(c, token)
	c.Header("Cache-Control", "no-store")
	c.JSON(200, s.sessionView(c, session, "session"))
}

func (s *server) createAdminSession(ctx context.Context, actorID, tenant, account, method string) (*adminSession, string, error) {
	token := randomID(32)
	now := time.Now().UTC()
	expires := now.Add(time.Duration(s.cfg.AdminSessionTTL) * time.Second)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (token_hash,actor_id,tenant_id,account_id,login_method,expires_at,created_at) VALUES (?,?,?,?,?,?,?)`,
		sha256Hex(token), actorID, nullIfEmpty(tenant), nullIfEmpty(account), method, expires, now); err != nil {
		return nil, "", err
	}
	return &adminSession{TokenHash: sha256Hex(token), Actor: actorID, ExpiresAt: expires, TenantID: tenant, AccountID: account, LoginMethod: method}, token, nil
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *server) setSessionCookie(c *gin.Context, token string) {
	http.SetCookie(c.Writer, &http.Cookie{Name: adminSessionCookie, Value: token, Path: "/v1/admin", MaxAge: s.cfg.AdminSessionTTL, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
}

func (s *server) clearLoginFailures(ip string) {
	s.mu.Lock()
	delete(s.attempts, ip)
	s.mu.Unlock()
}

// sessionView 是 login、session 与统一登录回调共用的会话形状。
func (s *server) sessionView(c *gin.Context, session *adminSession, method string) gin.H {
	view := gin.H{
		"authenticated": true,
		"method":        method,
		"loginMethod":   nil,
		"expiresAt":     nil,
		"actorId":       actor(c),
		"platformAdmin": false,
		"tenantId":      nil,
		"account":       nil,
		"bindRequired":  false,
	}
	if session == nil {
		// 自动化通道
		view["platformAdmin"] = s.isPlatformAdmin(actor(c))
		return view
	}
	view["actorId"] = session.Actor
	view["expiresAt"] = iso(session.ExpiresAt)
	view["loginMethod"] = session.LoginMethod
	if !session.tenantScoped() {
		view["platformAdmin"] = s.isPlatformAdmin(session.Actor)
		return view
	}
	view["tenantId"] = session.TenantID
	if session.Account != nil {
		view["account"] = session.Account.sessionView()
		view["bindRequired"] = session.Account.Status == accountPendingBind
	}
	return view
}

func (s *server) session(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(200, s.sessionView(c, currentAdminSession(c), valueFromString(c, "authMethod")))
}

func valueFromString(c *gin.Context, key string) string {
	v, _ := c.Get(key)
	text, _ := v.(string)
	return text
}

// logout 删会话。租户会话且配了统一登录时，一并给出认证中心的退出地址，控制台跳过去把那边也退掉
// （设计 §4.4）；平台会话不走统一登录，不给。
func (s *server) logout(c *gin.Context) {
	if token, err := c.Cookie(adminSessionCookie); err == nil {
		_, _ = s.db.ExecContext(c.Request.Context(), `DELETE FROM admin_sessions WHERE token_hash=?`, sha256Hex(token))
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/v1/admin", MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	body := gin.H{"authenticated": false, "cidLogoutUrl": nil}
	if currentAdminSession(c).tenantScoped() {
		if client, _, err := s.cidClient(c.Request.Context()); err == nil && client != nil {
			host := s.consoleHost(c)
			body["cidLogoutUrl"] = client.LogoutURL(host, "https://"+host+"/")
		}
	}
	c.JSON(200, body)
}

// authMethods 是登录页要知道的：统一登录开没开。免登录，不泄露任何配置细节。
func (s *server) authMethods(c *gin.Context) {
	client, _, err := s.cidClient(c.Request.Context())
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"password": true, "cid": err == nil && client != nil})
}

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// dummyPasswordHash 给「账号不存在」那条路陪算一次 scrypt，免得靠响应时间就能分出登录名存不存在。
func dummyPasswordHash() string {
	dummyHashOnce.Do(func() {
		dummyHash, _ = hashPassword(randomID(18))
	})
	return dummyHash
}

// requireAdminSessionTenant 用在 current 组里：租户会话的租户必须等于请求域名的租户。
// loadAdminSession 已经按 Host 校验过一次；这里对着 domainTenantScope 解析出的租户再核一遍，
// 两处任何一处将来被改动，另一处还挡着。
func requireAdminSessionTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		if session := currentAdminSession(c); session.tenantScoped() && session.TenantID != tenantID(c) {
			problem(c, http.StatusForbidden, "TENANT_MISMATCH", "This session belongs to another tenant")
			c.Abort()
			return
		}
		c.Next()
	}
}

// parseAccountID 只接受正整数 id。
func parseAccountID(raw string) (string, bool) {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		return "", false
	}
	return strconv.FormatUint(n, 10), true
}
