package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 平台管理员也在账号表里、走统一登录（设计 platform-accounts-and-console-login-2026-09-27），
// 记录由外部系统写（设计 console-accounts-external-maintenance-2026-09-27）。
// 统一登录与发信用自动化通道（管理密钥）配：第一个平台管理员登进来之前，只有它能改平台配置。
func TestDBPlatformAccounts(t *testing.T) {
	db := openTestDB(t)
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
	automationKey := "platform-accounts-test-key-" + uniqueSuffix()
	router := New(config.Config{
		Environment:            "test",
		StorageMasterKey:       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:      10,
		AdminAPIKey:            automationKey,
		AdminAPIActor:          "automation@test",
		PlatformAdminUsernames: []string{"automation@test"},
		AdminSessionTTL:        3600,
	}, &store.Store{DB: db})
	cidServer := newFakeCIDServer(t)
	smtpServer := startTestSMTP(t)
	newBrowser := func(tenant accountsTestTenant) *browser {
		return &browser{router: router, tenant: tenant, cookies: map[string]string{}}
	}
	rootSubject := testSubject()
	rootEmail := "root-" + uniqueSuffix() + "@example.com"

	automation := newBrowser(tenantA)
	automation.headers = map[string]string{"x-admin-key": automationKey}
	automation.mustCode(t, automation.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
		"authorizeUrl": "https://{baseHost}/auth/v1/oauth/authorize", "logoutUrl": "https://{baseHost}/auth/v1/logout",
		"tokenUrl": cidServer.URL + "/auth/v1/oauth/token", "userinfoUrl": cidServer.URL + "/internal/v1/userinfo",
		"clientId": "rn-client", "clientSecret": "rn-secret", "expectedVersion": 0, "reason": "接统一登录",
	}, nil), 200)
	automation.mustCode(t, automation.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("二次验证要发信", 0), nil), 200)

	// markVerified 把会话记成刚过了二次验证：同一个账号 1 分钟只能发一次码，测试里不等
	markVerified := func(b *browser) {
		t.Helper()
		if _, err := db.Exec(`UPDATE admin_sessions SET second_factor_at=? WHERE token_hash=?`, time.Now().UTC(), sha256Hex(b.cookies[adminSessionCookie])); err != nil {
			t.Fatal(err)
		}
	}
	// cidLogin 在某个租户的控制台上统一登录，返回浏览器与回调之后跳去哪
	cidLogin := func(tenant accountsTestTenant, subject string) (*browser, string) {
		t.Helper()
		b := newBrowser(tenant)
		authorize := location(t, b.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		// 控制台登录页：授权地址里的 {baseHost} 换成了浏览器所在的控制台域名
		if !strings.HasPrefix(authorize, "https://"+tenant.console+"/auth/v1/oauth/authorize?") {
			t.Fatalf("authorize url = %s", authorize)
		}
		code, state := cidServer.approve(t, authorize, subject, "someone@chainup.test")
		return b, location(t, b.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil))
	}

	rootID := externalAccount(t, db, "", rootSubject, rootEmail)
	var root *browser
	t.Run("平台记录：统一登录回来是平台会话，任何控制台域名都认", func(t *testing.T) {
		var got string
		root, got = cidLogin(tenantB, rootSubject)
		if got != "/" {
			t.Fatalf("login callback redirected to %s", got)
		}
		view := root.mustCode(t, root.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		if view["platformAdmin"] != true || view["tenantId"] != nil || view["actorId"] != platformActor(rootID) || view["secondFactorUntil"] != nil ||
			object(view["account"])["id"] != rootID || object(view["account"])["email"] != rootEmail {
			t.Fatalf("platform cid session = %v", view)
		}
		elsewhere := newBrowser(tenantA)
		elsewhere.cookies[adminSessionCookie] = root.cookies[adminSessionCookie]
		elsewhere.mustCode(t, elsewhere.do("GET", "/v1/admin/tenant", nil, nil), 200)
	})

	t.Run("写操作要 15 分钟内的二次验证，验证码发到记录里的邮箱", func(t *testing.T) {
		root.mustCode(t, root.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 200)
		wantProblem(t, root.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("改发信", 1), nil), 403, "SECOND_FACTOR_REQUIRED")
		passSecondFactor(t, root, smtpServer, rootEmail)
		var verified int
		// 平台级审计在持久的测试库里跨次累积：按这个账号过滤
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='platform_account_second_factor_verified' AND target_id=?`, platformTenantID, rootID).Scan(&verified); err != nil || verified != 1 {
			t.Fatalf("second factor audit = %d %v", verified, err)
		}
		root.mustCode(t, root.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("改发信", 1), nil), 200)
		// 自动化通道没有会话、没有邮箱，不做二次验证
		automation.mustCode(t, automation.do("GET", "/v1/admin/platform/accounts", nil, nil), 200)
	})

	t.Run("平台管理员只有只读列表", func(t *testing.T) {
		list := root.mustCode(t, root.do("GET", "/v1/admin/platform/accounts", nil, nil), 200)
		items, _ := list["items"].([]any)
		if len(items) != 1 || object(items[0])["id"] != rootID || object(items[0])["subject"] != rootSubject || object(items[0])["status"] != accountActive {
			t.Fatalf("platform accounts = %v", list)
		}
		markVerified(root)
		if got := root.do("POST", "/v1/admin/platform/accounts", map[string]string{"displayName": "二号", "email": "second@example.com"}, nil).Code; got != http.StatusNotFound {
			t.Fatalf("creating a platform account must be gone, got %d", got)
		}
	})

	t.Run("控制台会话不能删统一登录配置（删了谁都登不进来），只有自动化通道能删", func(t *testing.T) {
		markVerified(root)
		wantProblem(t, root.do("DELETE", "/v1/admin/platform/auth/cid?reason="+url.QueryEscape("删统一登录"), nil, nil), 409, "CID_REQUIRED_FOR_CONSOLE_LOGIN")
		root.mustCode(t, root.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 200)
	})

	t.Run("有可用的平台管理员时不能删发信配置", func(t *testing.T) {
		wantProblem(t, automation.do("DELETE", "/v1/admin/platform/mail?reason="+url.QueryEscape("删发信"), nil, nil), 409, "MAIL_REQUIRED_FOR_SECOND_FACTOR")
	})

	t.Run("同一个统一账号既有平台记录又有租户记录：拒绝登录，哪个域名都一样", func(t *testing.T) {
		externalAccount(t, db, tenantA.id, rootSubject, "root-member@example.com")
		for _, tenant := range []accountsTestTenant{tenantA, tenantB} {
			if _, got := cidLogin(tenant, rootSubject); got != "/?cidError=identity_conflict" {
				t.Fatalf("conflicting records on %s redirected to %s", tenant.console, got)
			}
		}
		// 冲突只在登录时查：已经登录的平台会话不受影响，要立刻踢人就把记录停用（下一条）
		root.mustCode(t, root.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		if _, err := db.Exec(`DELETE FROM tenant_admin_accounts WHERE scope=? AND tenant_id=? AND idp_subject=?`, scopeTenant, tenantA.id, rootSubject); err != nil {
			t.Fatal(err)
		}
		if _, got := cidLogin(tenantA, rootSubject); got != "/" {
			t.Fatalf("after the conflict is fixed, login redirected to %s", got)
		}
	})

	t.Run("停用平台记录：会话下一个请求就失效，登录报停用", func(t *testing.T) {
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET status='disabled' WHERE id=?`, rootID); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, root.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		if _, got := cidLogin(tenantA, rootSubject); got != "/?cidError=disabled" {
			t.Fatalf("disabled platform account redirected to %s", got)
		}
		// 没有可用的平台管理员了，发信配置可以删
		automation.mustCode(t, automation.do("DELETE", "/v1/admin/platform/mail?reason="+url.QueryEscape("删发信"), nil, nil), 200)
	})

	t.Run("租户会话进不了平台管理员账号的接口", func(t *testing.T) {
		memberSubject := testSubject()
		externalAccount(t, db, tenantA.id, memberSubject, "member@example.com")
		member, got := cidLogin(tenantA, memberSubject)
		if got != "/" {
			t.Fatalf("member login redirected to %s", got)
		}
		markVerified(member)
		wantProblem(t, member.do("GET", "/v1/admin/platform/accounts", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})
}
