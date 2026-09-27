package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
)

// 平台控制台（platform.*，设计 service-and-console-split-2026-09-27 §4.2–§4.4）：不在任何租户域名上，
// 统一登录不按租户、只认平台记录；两个控制台的会话与流程 Cookie 互不通用；改动请求只认它自己这个来源；
// 装机命令里的服务端地址用 MACHINE_API_ORIGIN，不用平台控制台的域名。
func TestDBPlatformConsole(t *testing.T) {
	db := openTestDB(t)
	tenantA := accountsTestTenantRow(t, db, "pc")
	platformHost := "platform-" + uniqueSuffix() + ".test"
	cfg := config.Config{
		Environment:         "test",
		StorageMasterKey:    base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:   10,
		AdminSessionTTL:     3600,
		PlatformConsoleHost: platformHost,
	}
	clearCID := func() {
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, cidConfigKey)
	}
	clearCID()
	t.Cleanup(clearCID)
	// 不带角色的全量进程按 Host 分两个控制台；平台端进程收到的都算平台控制台
	all := New(cfg, &store.Store{DB: db})
	platformOnly := NewForRole(cfg, &store.Store{DB: db}, RolePlatform)
	tenantOnly := NewForRole(cfg, &store.Store{DB: db}, RoleTenant)
	cidServer := newFakeCIDServer(t)
	onPlatform := func(router http.Handler) *browser {
		return &browser{router: router, tenant: tenantA, cookies: map[string]string{}, host: platformHost}
	}
	onTenant := func(router http.Handler) *browser {
		return &browser{router: router, tenant: tenantA, cookies: map[string]string{}}
	}
	cidLogin := func(b *browser, subject string) (string, string) {
		t.Helper()
		authorize := location(t, b.do("GET", "/v1/admin/auth/cid/start?mode=login&target="+url.QueryEscape("/build-machines"), nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "someone@chainup.test")
		return authorize, location(t, b.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil))
	}

	// 统一登录没配：平台控制台的登录页看到没开
	if got := onPlatform(all).mustCode(t, onPlatform(all).do("GET", "/v1/admin/auth/methods", nil, nil), 200)["cid"]; got != false {
		t.Fatalf("methods before configuring = %v", got)
	}
	platformToken, _, _ := activePlatformSession(t, db)
	admin := onPlatform(all)
	admin.cookies[adminSessionCookie] = platformToken
	admin.mustCode(t, admin.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
		"authorizeUrl": "https://login.test/auth/v1/oauth/authorize", "logoutUrl": "https://login.test/auth/v1/logout",
		"tokenUrl": cidServer.URL + "/auth/v1/oauth/token", "userinfoUrl": cidServer.URL + "/internal/v1/userinfo",
		"clientId": "rn-client", "clientSecret": "rn-secret", "expectedVersion": 0, "reason": "平台控制台接统一登录",
	}, nil), 200)

	t.Run("平台管理员在平台控制台登录，会话不属于任何租户", func(t *testing.T) {
		if got := onPlatform(all).mustCode(t, onPlatform(all).do("GET", "/v1/admin/auth/methods", nil, nil), 200)["cid"]; got != true {
			t.Fatalf("methods = %v", got)
		}
		subject := testSubject()
		platformRecord(t, db, subject, "pc-admin@chainup.test")
		for name, router := range map[string]http.Handler{"全量进程按 Host": all, "平台端进程": platformOnly} {
			b := onPlatform(router)
			authorize, landed := cidLogin(b, subject)
			if landed != "/build-machines" {
				t.Fatalf("%s: landed on %s", name, landed)
			}
			redirect, _ := url.Parse(authorize)
			if got := redirect.Query().Get("redirect_uri"); got != "https://"+platformHost+cidCallbackPath {
				t.Fatalf("%s: redirect_uri = %s", name, got)
			}
			view := b.mustCode(t, b.do("GET", "/v1/admin/auth/session", nil, nil), 200)
			if view["platformAdmin"] != true || view["tenantId"] != nil {
				t.Fatalf("%s: session = %v", name, view)
			}
			// 退出地址回到平台控制台
			out := b.mustCode(t, b.do("POST", "/v1/admin/auth/logout", map[string]any{}, nil), 200)
			if logout, _ := out["cidLogoutUrl"].(string); !strings.Contains(logout, platformHost) || strings.Contains(logout, tenantA.console) {
				t.Fatalf("%s: logout url = %v", name, out["cidLogoutUrl"])
			}
		}
	})

	t.Run("租户成员进不了平台控制台", func(t *testing.T) {
		subject := testSubject()
		externalAccount(t, db, tenantA.id, subject, "pc-member@chainup.test")
		if _, landed := cidLogin(onPlatform(all), subject); landed != "/?cidError=no_access" {
			t.Fatalf("a tenant member landed on %s", landed)
		}
		// 在自己的租户控制台照常
		member := onTenant(all)
		if _, landed := cidLogin(member, subject); landed != "/build-machines" {
			t.Fatalf("member on its own console landed on %s", landed)
		}
		// 租户会话拿到平台控制台（平台端进程也一样）：当没登录
		for name, router := range map[string]http.Handler{"全量进程": all, "平台端进程": platformOnly} {
			b := onPlatform(router)
			b.cookies[adminSessionCookie] = member.cookies[adminSessionCookie]
			if got := b.do("GET", "/v1/admin/auth/session", nil, nil); got.Code != http.StatusUnauthorized {
				t.Fatalf("%s: a tenant session was accepted on the platform console: %d %s", name, got.Code, got.Body.String())
			}
		}
	})

	t.Run("流程 Cookie 绑控制台：租户控制台发起的流程在平台控制台的回调上解不开", func(t *testing.T) {
		subject := testSubject()
		platformRecord(t, db, subject, "pc-cross@chainup.test")
		tenantSide := onTenant(tenantOnly)
		authorize := location(t, tenantSide.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "someone@chainup.test")
		platformSide := onPlatform(platformOnly)
		for name, value := range tenantSide.cookies {
			platformSide.cookies[name] = value
		}
		if got := location(t, platformSide.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=state" {
			t.Fatalf("a tenant-console flow finished on the platform console: %s", got)
		}
	})

	t.Run("平台控制台的改动请求只认它自己这个来源", func(t *testing.T) {
		// 会话已过二次验证（activePlatformSession），来源对了就走到业务校验（空请求体 400），不对就 403
		if got := admin.do("POST", "/v1/admin/platform/recovery-keys", map[string]any{}, nil); got.Code != http.StatusBadRequest {
			t.Fatalf("the platform console's own origin was refused: %s", got.Body.String())
		}
		wantProblem(t, admin.do("POST", "/v1/admin/platform/recovery-keys", map[string]any{}, map[string]string{"Origin": "https://" + tenantA.console}), 403, "UNTRUSTED_ORIGIN")
		wantProblem(t, admin.do("POST", "/v1/admin/platform/recovery-keys", map[string]any{}, map[string]string{"Origin": "https://evil.test"}), 403, "UNTRUSTED_ORIGIN")
	})

	t.Run("平台端进程没配平台控制台的域名：不发起统一登录", func(t *testing.T) {
		bare := cfg
		bare.PlatformConsoleHost = ""
		router := NewForRole(bare, &store.Store{DB: db}, RolePlatform)
		b := &browser{router: router, tenant: tenantA, cookies: map[string]string{}, host: platformHost}
		if got := b.mustCode(t, b.do("GET", "/v1/admin/auth/methods", nil, nil), 200)["cid"]; got != false {
			t.Fatalf("methods without PLATFORM_CONSOLE_HOST = %v", got)
		}
		if got := location(t, b.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil)); got != "/?cidError=misconfigured" {
			t.Fatalf("start without PLATFORM_CONSOLE_HOST redirected to %s", got)
		}
	})
}

// platformRecord 放一条平台管理员记录，测试结束连同它的会话一起删掉：测试库是持久的，留下的平台记录会挡住
// 别的用例删发信配置（MAIL_REQUIRED_FOR_SECOND_FACTOR）。
func platformRecord(t *testing.T, db *sql.DB, subject, email string) string {
	t.Helper()
	id := externalAccount(t, db, "", subject, email)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM admin_sessions WHERE account_id=?`, id)
		_, _ = db.Exec(`DELETE FROM tenant_admin_accounts WHERE id=?`, id)
	})
	return id
}

// 装机命令里的服务端地址：配了 MACHINE_API_ORIGIN 用它（平台控制台的请求源是 platform.*），没配沿用请求的源。
func TestEnrollmentCommandUsesMachineAPIOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := buildMachine{Role: machineRoleBuilder, Enrollment: &machineEnrollment{ExpiresAt: "2026-09-27T00:00:00Z"}}
	command := func(cfg config.Config, host string) string {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/admin/platform/machines", nil)
		c.Request.Host = host
		s := &server{cfg: cfg}
		return s.enrollmentView(c, m, "ABCD-EFGH")["installCommand"].(string)
	}
	withOrigin := command(config.Config{Environment: "production", MachineAPIOrigin: "https://api.anyfun.win"}, "platform.anyfun.win")
	if !strings.Contains(withOrigin, "--server https://api.anyfun.win ") || strings.Contains(withOrigin, "platform.anyfun.win") {
		t.Fatalf("install command = %s", withOrigin)
	}
	if fallback := command(config.Config{Environment: "production"}, "api.predict.kim"); !strings.Contains(fallback, "--server https://api.predict.kim ") {
		t.Fatalf("install command without MACHINE_API_ORIGIN = %s", fallback)
	}
}
