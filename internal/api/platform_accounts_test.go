package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 平台管理员进账号表、走统一登录（设计 platform-accounts-and-console-login-2026-09-27）。
// 过渡期：环境变量账号还在（发布 1），用它配统一登录与发信、建租户成员。
func TestDBPlatformAccounts(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	// 平台账号、auth.cid、mail.smtp 都是平台级的，测试库又是持久的：只有本测试写平台账号，开始前与结束后都清掉
	clear := func() {
		_, _ = db.Exec(`DELETE s FROM admin_sessions s JOIN tenant_admin_accounts a ON a.id=s.account_id WHERE a.scope='platform'`)
		_, _ = db.Exec(`DELETE FROM tenant_admin_accounts WHERE scope='platform'`)
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key IN (?,?)`, platformTenantID, cidConfigKey, mailConfigKey)
	}
	clear()
	t.Cleanup(clear)
	tenantA := accountsTestTenantRow(t, db, "pa")
	tenantB := accountsTestTenantRow(t, db, "pb")
	envUser := "platform-env-" + uniqueSuffix()
	envHash, err := hashPassword("Platform-Pass-2026!")
	if err != nil {
		t.Fatal(err)
	}
	router := New(config.Config{
		Environment:            "test",
		StorageMasterKey:       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:      10,
		AdminUsername:          envUser,
		AdminPasswordHash:      envHash,
		PlatformAdminUsernames: []string{envUser},
		AdminSessionTTL:        3600,
		AdminLoginMax:          1000,
		AdminLoginWindow:       900,
	}, &store.Store{DB: db})
	cidServer := newFakeCIDServer(t)
	smtpServer := startTestSMTP(t)
	newBrowser := func(tenant accountsTestTenant) *browser {
		return &browser{router: router, tenant: tenant, cookies: map[string]string{}}
	}
	sfx := uniqueSuffix()
	rootLogin, rootEmail := "root."+sfx, "root-"+sfx+"@example.com"
	platformSubject := "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	memberSubject := "8b2c3d4e-5f6a-4b7c-9d8e-0f1a2b3c4d5e"

	env := newBrowser(tenantA)
	env.mustCode(t, env.do("POST", "/v1/admin/auth/login", map[string]string{"username": envUser, "password": "Platform-Pass-2026!"}, nil), 200)
	env.mustCode(t, env.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
		"authorizeUrl": "https://{baseHost}/auth/v1/oauth/authorize", "logoutUrl": "https://{baseHost}/auth/v1/logout",
		"tokenUrl": cidServer.URL + "/auth/v1/oauth/token", "userinfoUrl": cidServer.URL + "/internal/v1/userinfo",
		"clientId": "rn-client", "clientSecret": "rn-secret", "expectedVersion": 0, "reason": "接统一登录",
	}, nil), 200)
	env.mustCode(t, env.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("二次验证要发信", 0), nil), 200)

	// markVerified 把会话记成刚过了二次验证：同一个账号 1 分钟只能发一次码，测试里不等
	markVerified := func(b *browser) {
		t.Helper()
		if _, err := db.Exec(`UPDATE admin_sessions SET second_factor_at=? WHERE token_hash=?`, time.Now().UTC(), sha256Hex(b.cookies[adminSessionCookie])); err != nil {
			t.Fatal(err)
		}
	}
	// startBind 从「待绑定、已登录、已过二次验证」走到认证中心回调，返回回调之后跳去哪
	startBind := func(b *browser, subject, cidEmail string) string {
		t.Helper()
		authorize := location(t, b.do("GET", "/v1/admin/auth/cid/start?mode=bind", nil, nil))
		// 控制台登录页：授权地址里的 {baseHost} 换成了浏览器所在的控制台域名
		if !strings.HasPrefix(authorize, "https://"+b.tenant.console+"/auth/v1/oauth/authorize?") {
			t.Fatalf("authorize url = %s", authorize)
		}
		code, state := cidServer.approve(t, authorize, subject, cidEmail)
		return location(t, b.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil))
	}
	confirmBind := func(b *browser, cidEmail string) *httptest.ResponseRecorder {
		t.Helper()
		sent := b.mustCode(t, b.do("POST", "/v1/admin/auth/cid/bind/code", map[string]any{}, nil), 200)
		token, _ := sent["codeToken"].(string)
		return b.do("POST", "/v1/admin/auth/cid/bind/confirm", map[string]any{"codeToken": token, "code": mailCode(t, smtpServer.last(t, cidEmail))}, nil)
	}
	cidLogin := func(tenant accountsTestTenant, subject, cidEmail string) *browser {
		t.Helper()
		b := newBrowser(tenant)
		authorize := location(t, b.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state := cidServer.approve(t, authorize, subject, cidEmail)
		if got := location(t, b.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/" {
			t.Fatalf("login callback redirected to %s", got)
		}
		return b
	}

	var rootPassword, memberPassword string
	t.Run("建号命令建第一个平台管理员，登录名不与任何账号重名", func(t *testing.T) {
		issued, err := CreatePlatformAccount(ctx, db, strings.ToUpper(rootLogin), rootEmail, "平台一号", "cli@test-host", envUser)
		if err != nil || issued.LoginName != rootLogin || len(issued.InitialPassword) != initialPasswordLen {
			t.Fatalf("create = %+v, %v", issued, err)
		}
		rootPassword = issued.InitialPassword
		var scope, status string
		var tenant any
		if err := db.QueryRow(`SELECT scope, tenant_id, status FROM tenant_admin_accounts WHERE id=?`, issued.ID).Scan(&scope, &tenant, &status); err != nil ||
			scope != scopePlatform || tenant != nil || status != accountPendingBind {
			t.Fatalf("row = %s %v %s %v", scope, tenant, status, err)
		}
		var summary, auditActor string
		if err := db.QueryRow(`SELECT summary, actor_id FROM audit_events WHERE tenant_id=? AND action='platform_account_create' AND target_id=?`, platformTenantID, issued.ID).Scan(&summary, &auditActor); err != nil ||
			auditActor != "cli@test-host" || strings.Contains(summary, rootPassword) {
			t.Fatalf("create audit = %q %q %v", summary, auditActor, err)
		}
		var failure *accountError
		if _, err := CreatePlatformAccount(ctx, db, rootLogin, "x@example.com", "重复", "cli@test-host", envUser); !errors.As(err, &failure) || failure.code != "LOGIN_NAME_TAKEN" {
			t.Fatalf("duplicate = %v", err)
		}
		if _, err := CreatePlatformAccount(ctx, db, envUser, "x@example.com", "撞环境变量账号", "cli@test-host", envUser); !errors.As(err, &failure) || failure.code != "INVALID_LOGIN_NAME" {
			t.Fatalf("reserved = %v", err)
		}
		// 与租户成员互不重名：初始口令登录先找平台账号，重名就会挡掉那个成员
		body := env.mustCode(t, env.do("POST", "/v1/admin/tenant-accounts", map[string]string{"displayName": "成员", "loginName": "member." + sfx, "email": "member-" + sfx + "@example.com"}, nil), 201)
		memberPassword, _ = body["initialPassword"].(string)
		if _, err := CreatePlatformAccount(ctx, db, "member."+sfx, "x@example.com", "撞成员", "cli@test-host", envUser); !errors.As(err, &failure) || failure.code != "LOGIN_NAME_TAKEN" {
			t.Fatalf("clash with a tenant member = %v", err)
		}
		wantProblem(t, env.do("POST", "/v1/admin/tenant-accounts", map[string]string{"displayName": "撞平台", "loginName": rootLogin, "email": "x@example.com"}, nil), 409, "LOGIN_NAME_TAKEN")
	})

	root := newBrowser(tenantB)
	t.Run("初始口令在任何控制台域名上都能登，登录后只能去绑定", func(t *testing.T) {
		view := root.mustCode(t, root.do("POST", "/v1/admin/auth/login", map[string]string{"username": rootLogin, "password": rootPassword}, nil), 200)
		account := object(view["account"])
		if view["tenantId"] != nil || view["bindRequired"] != true || view["platformAdmin"] != false || account["scope"] != scopePlatform {
			t.Fatalf("pending platform session = %v", view)
		}
		wantProblem(t, root.do("GET", "/v1/admin/platform/accounts", nil, nil), 403, "BIND_REQUIRED")
		wantProblem(t, root.do("GET", "/v1/admin/tenant", nil, nil), 403, "BIND_REQUIRED")
		// 在另一个租户的域名上也认这个会话（平台会话不属于任何租户）
		elsewhere := newBrowser(tenantA)
		elsewhere.cookies[adminSessionCookie] = root.cookies[adminSessionCookie]
		elsewhere.mustCode(t, elsewhere.do("GET", "/v1/admin/auth/session", nil, nil), 200)
	})

	t.Run("绑定：二次验证 → 认证中心 → 统一账号邮箱收码 → 落库", func(t *testing.T) {
		if got := location(t, root.do("GET", "/v1/admin/auth/cid/start?mode=bind", nil, nil)); got != "/?cidError=second_factor_required" {
			t.Fatalf("bind start without the second factor redirected to %s", got)
		}
		passSecondFactor(t, root, smtpServer, rootEmail)
		var verifiedAt int
		// 平台级审计在持久的测试库里跨次累积：按这个账号过滤
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='platform_account_second_factor_verified' AND target_id=?`, platformTenantID, accountIDOf(t, db, rootLogin)).Scan(&verifiedAt); err != nil || verifiedAt != 1 {
			t.Fatalf("second factor audit = %d %v", verifiedAt, err)
		}
		if got := startBind(root, platformSubject, "root@chainup.test"); got != "/cid/bind-confirm" {
			t.Fatalf("bind callback redirected to %s", got)
		}
		view := root.mustCode(t, confirmBind(root, "root@chainup.test"), 200)
		if view["bindRequired"] != false || view["platformAdmin"] != true || object(view["account"])["status"] != accountActive {
			t.Fatalf("confirm = %v", view)
		}
		var bound int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='platform_account_bind' AND target_id=?`, platformTenantID, accountIDOf(t, db, rootLogin)).Scan(&bound); err != nil || bound != 1 {
			t.Fatalf("bind audit = %d %v", bound, err)
		}
		wantProblem(t, newBrowser(tenantA).do("POST", "/v1/admin/auth/login", map[string]string{"username": rootLogin, "password": rootPassword}, nil), 409, "ACCOUNT_BOUND_USE_CID")
	})

	var rootCID *browser
	var secondID string
	t.Run("统一登录回来是平台会话，写操作要 15 分钟内的二次验证", func(t *testing.T) {
		rootCID = cidLogin(tenantA, platformSubject, "root@chainup.test")
		view := rootCID.mustCode(t, rootCID.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		if view["platformAdmin"] != true || view["tenantId"] != nil || view["loginMethod"] != loginMethodCID || view["secondFactorUntil"] != nil {
			t.Fatalf("platform cid session = %v", view)
		}
		rootCID.mustCode(t, rootCID.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 200)
		rootCID.mustCode(t, rootCID.do("GET", "/v1/admin/platform/accounts", nil, nil), 200)
		wantProblem(t, rootCID.do("POST", "/v1/admin/platform/accounts", map[string]string{"displayName": "二号", "loginName": "second." + sfx, "email": "second-" + sfx + "@example.com"}, nil), 403, "SECOND_FACTOR_REQUIRED")
		wantProblem(t, rootCID.do("POST", "/v1/admin/tenant-accounts", map[string]string{"displayName": "成员二", "loginName": "member2." + sfx, "email": "m2@example.com"}, nil), 403, "SECOND_FACTOR_REQUIRED")
		wantProblem(t, rootCID.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("改发信", 1), nil), 403, "SECOND_FACTOR_REQUIRED")
		markVerified(rootCID)
		body := rootCID.mustCode(t, rootCID.do("POST", "/v1/admin/platform/accounts", map[string]string{"displayName": "二号", "loginName": "second." + sfx, "email": "second-" + sfx + "@example.com"}, nil), 201)
		secondID, _ = object(body["account"])["id"].(string)
		var createdBy string
		if err := db.QueryRow(`SELECT created_by FROM tenant_admin_accounts WHERE id=?`, secondID).Scan(&createdBy); err != nil || !strings.HasPrefix(createdBy, "platform:") {
			t.Fatalf("created_by = %q %v", createdBy, err)
		}
		// 环境变量账号没有邮箱，不做二次验证
		env.mustCode(t, env.do("GET", "/v1/admin/platform/accounts", nil, nil), 200)
	})

	t.Run("同一个统一账号不能既是平台管理员又是租户成员", func(t *testing.T) {
		member := newBrowser(tenantA)
		member.mustCode(t, member.do("POST", "/v1/admin/auth/login", map[string]string{"username": "member." + sfx, "password": memberPassword}, nil), 200)
		markVerified(member)
		if got := startBind(member, platformSubject, "root@chainup.test"); got != "/?cidError=already_platform" {
			t.Fatalf("binding a member to a platform administrator's account redirected to %s", got)
		}
		if got := startBind(member, memberSubject, "member@chainup.test"); got != "/cid/bind-confirm" {
			t.Fatalf("member bind redirected to %s", got)
		}
		member.mustCode(t, confirmBind(member, "member@chainup.test"), 200)
		// 反过来：二号平台管理员想绑一个已经是租户成员的统一账号
		second := newBrowser(tenantB)
		reset := rootCID.mustCode(t, rootCID.do("POST", "/v1/admin/platform/accounts/"+secondID+"/reset", map[string]string{"reason": "拿一个新的初始口令"}, nil), 200)
		secondPassword, _ := reset["initialPassword"].(string)
		second.mustCode(t, second.do("POST", "/v1/admin/auth/login", map[string]string{"username": "second." + sfx, "password": secondPassword}, nil), 200)
		markVerified(second)
		if got := startBind(second, memberSubject, "member@chainup.test"); got != "/?cidError=already_member" {
			t.Fatalf("binding a platform administrator to a member's account redirected to %s", got)
		}
		// 确认时在事务里加锁再查一遍：回调时还没人绑，确认之前被别人抢先绑成了平台管理员
		late := "9c3d4e5f-6a7b-4c8d-8e9f-1a2b3c4d5e6f"
		other := newBrowser(tenantA)
		otherBody := env.mustCode(t, env.do("POST", "/v1/admin/tenant-accounts", map[string]string{"displayName": "成员三", "loginName": "member3." + sfx, "email": "m3-" + sfx + "@example.com"}, nil), 201)
		otherPassword, _ := otherBody["initialPassword"].(string)
		other.mustCode(t, other.do("POST", "/v1/admin/auth/login", map[string]string{"username": "member3." + sfx, "password": otherPassword}, nil), 200)
		markVerified(other)
		if got := startBind(other, late, "late@chainup.test"); got != "/cid/bind-confirm" {
			t.Fatalf("member3 bind redirected to %s", got)
		}
		if got := startBind(second, late, "late@chainup.test"); got != "/cid/bind-confirm" {
			t.Fatalf("second bind redirected to %s", got)
		}
		second.mustCode(t, confirmBind(second, "late@chainup.test"), 200)
		wantProblem(t, confirmBind(other, "late@chainup.test"), 409, "CID_ACCOUNT_IS_PLATFORM_ADMIN")
	})

	t.Run("不能停用、重置自己，不能让最后一个平台管理员失效", func(t *testing.T) {
		wantProblem(t, rootCID.do("POST", "/v1/admin/platform/accounts/"+accountIDOf(t, db, rootLogin)+"/disable", map[string]string{"reason": "停用自己"}, nil), 409, "CANNOT_CHANGE_OWN_ACCOUNT")
		secondSession := cidLogin(tenantB, "9c3d4e5f-6a7b-4c8d-8e9f-1a2b3c4d5e6f", "late@chainup.test")
		rootCID.mustCode(t, rootCID.do("POST", "/v1/admin/platform/accounts/"+secondID+"/disable", map[string]string{"reason": "二号离职"}, nil), 200)
		// 停用立即生效
		wantProblem(t, secondSession.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		// 现在一号是最后一个可用的平台管理员
		wantProblem(t, env.do("POST", "/v1/admin/platform/accounts/"+accountIDOf(t, db, rootLogin)+"/disable", map[string]string{"reason": "停用最后一个"}, nil), 409, "LAST_PLATFORM_ADMIN")
		wantProblem(t, env.do("POST", "/v1/admin/platform/accounts/"+accountIDOf(t, db, rootLogin)+"/reset", map[string]string{"reason": "重置最后一个"}, nil), 409, "LAST_PLATFORM_ADMIN")
		wantProblem(t, env.do("POST", "/v1/admin/platform/accounts/"+accountIDOf(t, db, "member."+sfx)+"/disable", map[string]string{"reason": "拿成员当平台账号"}, nil), 404, "PLATFORM_ACCOUNT_NOT_FOUND")
	})

	t.Run("有平台管理员时不能删发信配置", func(t *testing.T) {
		wantProblem(t, env.do("DELETE", "/v1/admin/platform/mail?reason="+url.QueryEscape("删发信"), nil, nil), 409, "MAIL_REQUIRED_FOR_SECOND_FACTOR")
	})

	t.Run("建号命令重置：解绑、回到待绑定、会话作废", func(t *testing.T) {
		issued, err := ResetPlatformAccount(ctx, db, rootLogin, "找回", "cli@test-host")
		if err != nil || issued.InitialPassword == "" {
			t.Fatalf("reset = %+v %v", issued, err)
		}
		wantProblem(t, rootCID.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		view := newBrowser(tenantA).mustCode(t, newBrowser(tenantA).do("POST", "/v1/admin/auth/login", map[string]string{"username": rootLogin, "password": issued.InitialPassword}, nil), 200)
		if view["bindRequired"] != true {
			t.Fatalf("after reset = %v", view)
		}
		var failure *accountError
		if _, err := ResetPlatformAccount(ctx, db, "nobody."+sfx, "找回", "cli@test-host"); !errors.As(err, &failure) || failure.code != "PLATFORM_ACCOUNT_NOT_FOUND" {
			t.Fatalf("unknown = %v", err)
		}
	})

	t.Run("租户会话进不了平台管理员账号的接口", func(t *testing.T) {
		member := cidLogin(tenantA, memberSubject, "member@chainup.test")
		markVerified(member)
		wantProblem(t, member.do("GET", "/v1/admin/platform/accounts", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
		wantProblem(t, member.do("POST", "/v1/admin/platform/accounts", map[string]string{"displayName": "越权", "loginName": "evil." + sfx, "email": "e@example.com"}, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})
}

func accountIDOf(t *testing.T, db *sql.DB, loginName string) string {
	t.Helper()
	var id string
	if err := db.QueryRow(`SELECT id FROM tenant_admin_accounts WHERE login_name=? LIMIT 1`, loginName).Scan(&id); err != nil {
		t.Fatalf("account id of %s: %v", loginName, err)
	}
	return id
}
