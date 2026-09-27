package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 管理端会话分平台 / 租户（设计 tenant-console-accounts-and-sso-2026-09-25 §3.3、
// platform-accounts-and-console-login-2026-09-27 §3.2、console-accounts-external-maintenance-2026-09-27 §4.2）。
// 会话只有统一登录一个来源，每个会话都属于 tenant_admin_accounts 里的一个账号（设计 §10 删掉了环境变量账号）。
//
//   - 平台会话：平台管理员账号（scope=platform）登出来的，admin_sessions.tenant_id 为 NULL，actor 是 platform:<id>，
//     在任何租户的控制台域名上都有效。
//   - 租户会话：租户成员登出来的，记下租户与账号。
//     **只在这个租户的域名上有效**：请求域名的租户与会话租户不一致，一律当没登录；
//     永远不是平台管理员，不管它的 actor 长什么样。
//   - 账号会话每个请求都回表：账号要是 active，统一认证账号 id 要等于登录时记下的那个。账号由外部系统维护，
//     停用、删除、换人、改 scope 都在下一个请求生效。
//
// 自动化通道（x-admin-key）不落会话，身份来自配置（ADMIN_API_ACTOR），按平台会话处理。

const adminSessionCookie = "rn_admin_session"

// adminSession 是一次请求带来的会话。
type adminSession struct {
	TokenHash string
	Actor     string
	ExpiresAt time.Time
	TenantID  string // 空 = 平台会话
	AccountID string
	// Subject 是登录时账号的统一认证账号 id；每个请求核对账号当前的 idp_subject
	Subject string
	Account *tenantAccount
	// SecondFactorAt 是这个会话最近一次通过邮箱二次验证的时间，零值 = 没验过（second_factor.go）
	SecondFactorAt time.Time
}

func (a *adminSession) tenantScoped() bool { return a != nil && a.TenantID != "" }

// auditTenant 是这个会话的审计记在哪个租户下：平台会话记在平台（0）。
func (a *adminSession) auditTenant() string {
	if a.tenantScoped() {
		return a.TenantID
	}
	return platformTenantID
}

// isPlatformSession：平台会话（平台管理员账号、管理密钥）看得到平台的基础设施与别的租户；租户会话
// 只看自己租户的东西（设计 tenant-console-accounts-and-sso §3.4）。
func isPlatformSession(c *gin.Context) bool { return !currentAdminSession(c).tenantScoped() }

// requirePlatformSession 挂在只给平台会话的租户路由上（判据同 isPlatformSession）。
func requirePlatformSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isPlatformSession(c) {
			c.Next()
			return
		}
		problem(c, http.StatusForbidden, "PLATFORM_ADMIN_REQUIRED", "Only the platform administrator can do this")
		c.Abort()
	}
}

// tenantActor 是租户账号在审计里的 actor。带冒号，与 ADMIN_API_ACTOR 的取值空间分开。
func tenantActor(tenant, account string) string { return "tenant:" + tenant + ":" + account }

// platformActor 是平台管理员账号在审计里的 actor。
func platformActor(account string) string { return "platform:" + account }

// loadAdminSession 读并校验请求带的会话 Cookie。没有、过期、租户对不上、账号不可用或换了人都返回 nil。
// 出库错误单独返回，调用方按 500 处理，不要当成「没登录」把人踢回登录页。
func (s *server) loadAdminSession(c *gin.Context) (*adminSession, error) {
	cookie, err := c.Cookie(adminSessionCookie)
	if err != nil || cookie == "" {
		return nil, nil
	}
	ctx := c.Request.Context()
	session := adminSession{TokenHash: sha256Hex(cookie)}
	var tenant sql.NullString
	var secondFactor sql.NullTime
	err = s.db.QueryRowContext(ctx,
		`SELECT actor_id, expires_at, tenant_id, account_id, idp_subject, second_factor_at FROM admin_sessions WHERE token_hash=? AND expires_at>? LIMIT 1`,
		session.TokenHash, time.Now().UTC()).Scan(&session.Actor, &session.ExpiresAt, &tenant, &session.AccountID, &session.Subject, &secondFactor)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if secondFactor.Valid {
		session.SecondFactorAt = secondFactor.Time.UTC()
	}
	if !tenant.Valid || tenant.String == "" {
		// 平台管理员账号：任何控制台域名都有效，但每个请求都回表
		acc, err := platformAccountByID(ctx, s.db, session.AccountID)
		if err != nil {
			return nil, err
		}
		if !session.accountStillValid(acc) {
			return nil, nil
		}
		session.Account = acc
		return &session, nil
	}
	session.TenantID = tenant.String
	host, err := s.tenant.resolve(ctx, c.Request.Host)
	if err != nil || host.ID != session.TenantID {
		// 别的租户的会话拿到这个域名上来：当没登录，而不是 403——对这个域名来说它确实没登录
		return nil, nil
	}
	acc, err := s.tenantAccountByID(ctx, session.TenantID, session.AccountID)
	if err != nil {
		return nil, err
	}
	if !session.accountStillValid(acc) {
		return nil, nil
	}
	session.Account = acc
	return &session, nil
}

// accountStillValid：账号还在（按会话的类型查得到）、是 active、统一认证账号 id 没被外部系统换掉。
func (a *adminSession) accountStillValid(acc *tenantAccount) bool {
	return acc != nil && acc.Status == accountActive && strings.EqualFold(acc.IDPSubject, a.Subject)
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

// platformAdminRequest：租户会话永远不是平台管理员；平台会话要是可用的平台管理员账号；
// 自动化通道（没有会话）看它的 actor 在不在 PLATFORM_ADMIN_USERNAMES 里。
func (s *server) platformAdminRequest(c *gin.Context) bool {
	return s.platformAdminSession(currentAdminSession(c), actor(c))
}

func (s *server) platformAdminSession(session *adminSession, actorID string) bool {
	switch {
	case session == nil:
		return s.isPlatformAdmin(actorID)
	case session.tenantScoped():
		return false
	default:
		return session.Account.platform() && session.Account.Status == accountActive
	}
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

// createAdminSession 落一条统一登录的会话：租户（平台管理员为空）、账号与登录时的统一认证账号 id。
func (s *server) createAdminSession(ctx context.Context, actorID, tenant, account, subject string) (*adminSession, string, error) {
	token := randomID(32)
	now := time.Now().UTC()
	expires := now.Add(time.Duration(s.cfg.AdminSessionTTL) * time.Second)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_sessions (token_hash,actor_id,tenant_id,account_id,idp_subject,expires_at,created_at) VALUES (?,?,?,?,?,?,?)`,
		sha256Hex(token), actorID, nullIfEmpty(tenant), account, subject, expires, now); err != nil {
		return nil, "", err
	}
	return &adminSession{TokenHash: sha256Hex(token), Actor: actorID, ExpiresAt: expires, TenantID: tenant, AccountID: account, Subject: subject}, token, nil
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

// sessionView 是会话接口的形状（会话与自动化通道共用）。
func (s *server) sessionView(c *gin.Context, session *adminSession, method string) gin.H {
	view := gin.H{
		"authenticated": true,
		"method":        method,
		"expiresAt":     nil,
		"actorId":       actor(c),
		"platformAdmin": false,
		// 租户会话的租户；平台会话为 null。控制台据此把平台级设置做成只读（use-platform-session.ts）
		"tenantId": nil,
		"account":  nil,
		// 邮箱二次验证在这个时间之前有效；null = 没验过或已过期（自动化通道不用）
		"secondFactorUntil": nil,
	}
	if session == nil {
		// 自动化通道
		view["platformAdmin"] = s.isPlatformAdmin(actor(c))
		return view
	}
	view["actorId"] = session.Actor
	view["expiresAt"] = iso(session.ExpiresAt)
	view["platformAdmin"] = s.platformAdminSession(session, session.Actor)
	if session.tenantScoped() {
		view["tenantId"] = session.TenantID
	}
	if until := session.SecondFactorAt.Add(secondFactorWindow); !session.SecondFactorAt.IsZero() && time.Now().Before(until) {
		view["secondFactorUntil"] = iso(until)
	}
	view["account"] = session.Account.sessionView()
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

// logout 删会话。配了统一登录时一并给出认证中心的退出地址，控制台跳过去把那边也退掉（设计 §4.4）；
// 不然下次打开控制台会凭认证中心的登录态直接进来。
func (s *server) logout(c *gin.Context) {
	if token, err := c.Cookie(adminSessionCookie); err == nil {
		_, _ = s.db.ExecContext(c.Request.Context(), `DELETE FROM admin_sessions WHERE token_hash=?`, sha256Hex(token))
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/v1/admin", MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	body := gin.H{"authenticated": false, "cidLogoutUrl": nil}
	if currentAdminSession(c) != nil {
		if client, _, err := s.cidClient(c.Request.Context()); err == nil && client != nil {
			host := s.consoleHost(c)
			body["cidLogoutUrl"] = client.LogoutURL("https://"+host+"/", host)
		}
	}
	c.JSON(200, body)
}

// authMethods 是登录页要知道的：统一登录开没开（开了就直接跳过去，没开就说明原因）。
// 免登录，不泄露任何配置细节。
func (s *server) authMethods(c *gin.Context) {
	client, _, err := s.cidClient(c.Request.Context())
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"cid": err == nil && client != nil})
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
