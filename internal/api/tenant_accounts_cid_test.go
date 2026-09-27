package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 控制台账号与统一登录走真实路由的回归（设计 tenant-console-accounts-and-sso-2026-09-25 §3、§4，
// console-accounts-external-maintenance-2026-09-27）。账号由外部系统写进 tenant_admin_accounts，测试里用
// externalAccount 直接写库来模拟。两个租户、各自 console.* 与 api.* 两个域名（nginx 把 console.* 的 Host
// 改写成 api.*，并写 X-RN-Console-Host）；认证中心用本地假实现，按真实形状应答（出错时 HTTP 200 + {code,msg}）。

type accountsTestTenant struct {
	id      string
	console string
	api     string
}

func accountsTestTenantRow(t *testing.T, db *sql.DB, label string) accountsTestTenant {
	t.Helper()
	now := time.Now().UTC()
	sfx := uniqueSuffix()
	result, err := db.Exec(`INSERT INTO tenants(slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,1,?,?,0,?,?)`,
		"acct-"+label+"-"+sfx, now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	id, _ := result.LastInsertId()
	tenant := accountsTestTenant{console: "console." + label + "-" + sfx + ".test", api: "api." + label + "-" + sfx + ".test"}
	for i, domain := range []string{tenant.console, tenant.api} {
		if _, err := db.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at) VALUES(?,?,?,'active',0,?,?)`,
			id, domain, i == 0, now, now); err != nil {
			t.Fatalf("insert tenant domain: %v", err)
		}
	}
	tenant.id = strconv.FormatInt(id, 10)
	return tenant
}

// testSubject 是一个随机的统一认证账号 id（小写 uuid）：测试库是持久的，平台记录按账号 id 唯一。
func testSubject() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// externalAccount 模拟外部系统写一行账号：只写契约里外部系统要写的列，其余靠数据库默认值
// （设计 console-accounts-external-maintenance §3）。tenant 为空 = 平台管理员。
func externalAccount(t *testing.T, db *sql.DB, tenant, subject, email string) string {
	t.Helper()
	scope := scopeTenant
	if tenant == "" {
		scope = scopePlatform
	}
	result, err := db.Exec(`INSERT INTO tenant_admin_accounts (scope,tenant_id,idp_subject,email,display_name,created_by) VALUES (?,?,?,?,?,?)`,
		scope, nullIfEmpty(tenant), subject, email, "外部-"+subject[:8], "ext-ops")
	if err != nil {
		t.Fatalf("insert %s account: %v", scope, err)
	}
	id, _ := result.LastInsertId()
	return strconv.FormatInt(id, 10)
}

// fakeCIDServer 模拟认证中心的换令牌与 userinfo。grant 登记「用户在认证中心登录成功后发出的授权码」。
type fakeCIDServer struct {
	*httptest.Server
	mu     sync.Mutex
	codes  map[string]fakeCIDGrant
	tokens map[string]fakeCIDGrant
}

type fakeCIDGrant struct {
	subject, email, challenge, redirectURI string
}

func newFakeCIDServer(t *testing.T) *fakeCIDServer {
	t.Helper()
	f := &fakeCIDServer{codes: map[string]fakeCIDGrant{}, tokens: map[string]fakeCIDGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		grant, known := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || id != "rn-client" || secret != "rn-secret" {
			_, _ = w.Write([]byte(`{"code":"401","msg":"Client authentication failed: client_secret"}`))
			return
		}
		if !known || base64.RawURLEncoding.EncodeToString(sum[:]) != grant.challenge || r.Form.Get("redirect_uri") != grant.redirectURI {
			_, _ = w.Write([]byte(`{"code":"401","msg":"Client authentication failed: code"}`))
			return
		}
		token := "at-" + uniqueSuffix()
		f.tokens[token] = grant
		_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer","refresh_token":"rt","expires_in":599}`))
	})
	mux.HandleFunc("/internal/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		grant, ok := f.tokens[r.Form.Get("access_token")]
		f.mu.Unlock()
		if !ok {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		raw, _ := json.Marshal(map[string]string{"username": grant.subject, "email": grant.email})
		_, _ = w.Write(raw)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// approve 模拟「用户在认证中心登录成功」：按授权地址里的 challenge 与回调地址发一个授权码。
func (f *fakeCIDServer) approve(t *testing.T, authorizeURL, subject, email string) (code, state string) {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("authorize url: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "rn-client" || q.Get("response_mode") != "query" {
		t.Fatalf("unexpected authorize request %s", authorizeURL)
	}
	code = "code-" + uniqueSuffix()
	f.mu.Lock()
	f.codes[code] = fakeCIDGrant{subject: subject, email: email, challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri")}
	f.mu.Unlock()
	return code, q.Get("state")
}

// browser 是一个 cookie jar：只按名字存（服务端按名字读），Max-Age<0 删除。
type browser struct {
	router  http.Handler
	tenant  accountsTestTenant
	cookies map[string]string
}

func (b *browser) do(method, target string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, target, reader)
	// nginx 把 console.* 的 Host 改写成 api.*，并写下原来的控制台域名
	request.Host = b.tenant.api
	request.Header.Set(consoleHostHeader, b.tenant.console)
	request.Header.Set("content-type", "application/json")
	if !safeMethod(method) {
		request.Header.Set("Origin", "https://"+b.tenant.console)
	}
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	for name, value := range b.cookies {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	recorder := httptest.NewRecorder()
	b.router.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(b.cookies, cookie.Name)
		} else {
			b.cookies[cookie.Name] = cookie.Value
		}
	}
	return recorder
}

func (b *browser) mustCode(t *testing.T, recorder *httptest.ResponseRecorder, want int) map[string]any {
	t.Helper()
	if recorder.Code != want {
		t.Fatalf("want HTTP %d, got %d: %s", want, recorder.Code, recorder.Body.String())
	}
	if recorder.Body.Len() == 0 || !strings.HasPrefix(strings.TrimSpace(recorder.Body.String()), "{") {
		return nil
	}
	return decodeBody(t, recorder)
}

func wantProblem(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status || problemCode(t, recorder) != code {
		t.Fatalf("want %d %s, got %d %s", status, code, recorder.Code, recorder.Body.String())
	}
}

func location(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	if recorder.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Header().Get("Location")
}

// passSecondFactor 走一遍邮箱二次验证：发码、从收到的信里取码、验证。
func passSecondFactor(t *testing.T, b *browser, smtpServer *testSMTP, email string) {
	t.Helper()
	sent := b.mustCode(t, b.do("POST", "/v1/admin/auth/second-factor/code", map[string]any{}, nil), 200)
	token, _ := sent["codeToken"].(string)
	code := mailCode(t, smtpServer.last(t, email))
	verified := b.mustCode(t, b.do("POST", "/v1/admin/auth/second-factor/verify", map[string]any{"codeToken": token, "code": code}, nil), 200)
	if verified["secondFactorUntil"] == nil {
		t.Fatalf("verify = %v", verified)
	}
}

func TestDBTenantAccountsAndUnifiedLogin(t *testing.T) {
	db := openTestDB(t)
	tenantA := accountsTestTenantRow(t, db, "a")
	tenantB := accountsTestTenantRow(t, db, "b")
	platformUser := "platform-root-" + uniqueSuffix()
	platformHash, err := hashPassword("Platform-Pass-2026!")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Environment:            "test",
		StorageMasterKey:       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:      10,
		AdminUsername:          platformUser,
		AdminPasswordHash:      platformHash,
		PlatformAdminUsernames: []string{platformUser},
		AdminSessionTTL:        3600,
		AdminLoginMax:          1000,
		AdminLoginWindow:       900,
	}
	// auth.cid 是平台级的一份，测试库又是持久的：上一次运行留下的配置指向早已关掉的假认证中心。
	// 这个键只有本测试写，开始前与结束后都清掉
	clearCID := func() {
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, cidConfigKey)
	}
	clearCID()
	t.Cleanup(clearCID)
	router := New(cfg, &store.Store{DB: db})
	cidServer := newFakeCIDServer(t)
	newBrowser := func(tenant accountsTestTenant) *browser {
		return &browser{router: router, tenant: tenant, cookies: map[string]string{}}
	}
	// cidLogin 从发起走到回调，返回回调之后跳去哪
	cidLogin := func(b *browser, subject, target string) string {
		t.Helper()
		start := "/v1/admin/auth/cid/start?mode=login"
		if target != "" {
			start += "&target=" + url.QueryEscape(target)
		}
		authorize := location(t, b.do("GET", start, nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "someone@chainup.test")
		return location(t, b.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil))
	}
	subject := testSubject()

	platform := newBrowser(tenantA)
	view := platform.mustCode(t, platform.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
	if view["platformAdmin"] != true || view["tenantId"] != nil {
		t.Fatalf("platform session view = %v", view)
	}

	t.Run("平台管理员配置统一登录，密钥不回显", func(t *testing.T) {
		// 没配之前：登录页看到统一登录没开，发起直接回首页报原因。口令登录只剩环境变量账号，配了才显示
		methods := platform.mustCode(t, newBrowser(tenantA).do("GET", "/v1/admin/auth/methods", nil, nil), 200)
		if methods["cid"] != false || methods["password"] != true {
			t.Fatalf("methods = %v", methods)
		}
		if got := location(t, newBrowser(tenantA).do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil)); got != "/?cidError=not_configured" {
			t.Fatalf("start without config redirected to %s", got)
		}
		body := platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
			"authorizeUrl": "https://login.test/auth/v1/oauth/authorize", "logoutUrl": "https://login.test/auth/v1/logout",
			"tokenUrl": cidServer.URL + "/auth/v1/oauth/token", "userinfoUrl": cidServer.URL + "/internal/v1/userinfo",
			"clientId": "rn-client", "clientSecret": "rn-secret", "expectedVersion": 0, "reason": "接统一登录",
		}, nil), 200)
		if strings.Contains(platform.do("GET", "/v1/admin/platform/auth/cid", nil, nil).Body.String(), "rn-secret") ||
			object(body["config"])["hasClientSecret"] != true {
			t.Fatalf("the client secret must never be returned: %v", body)
		}
		// 留空密钥 = 沿用；版本不对 = 409
		platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
			"authorizeUrl": "https://login.test/auth/v1/oauth/authorize", "logoutUrl": "https://login.test/auth/v1/logout",
			"tokenUrl": cidServer.URL + "/auth/v1/oauth/token", "userinfoUrl": cidServer.URL + "/internal/v1/userinfo",
			"clientId": "rn-client", "expectedVersion": 1, "reason": "只改地址",
		}, nil), 200)
		wantProblem(t, platform.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
			"authorizeUrl": "https://login.test/a", "logoutUrl": "https://login.test/l", "tokenUrl": cidServer.URL + "/t",
			"userinfoUrl": cidServer.URL + "/u", "clientId": "rn-client", "expectedVersion": 1, "reason": "过期版本",
		}, nil), 409, "STALE_CID_CONFIG")
		wantProblem(t, platform.do("PUT", "/v1/admin/platform/auth/cid", map[string]any{
			"authorizeUrl": "http://login.test/a", "logoutUrl": "https://login.test/l", "tokenUrl": cidServer.URL + "/t",
			"userinfoUrl": cidServer.URL + "/u", "clientId": "rn-client", "expectedVersion": 2, "reason": "明文授权地址",
		}, nil), 422, "INVALID_CID_CONFIG")
		if newBrowser(tenantA).mustCode(t, newBrowser(tenantA).do("GET", "/v1/admin/auth/methods", nil, nil), 200)["cid"] != true {
			t.Fatal("methods must report cid=true once configured")
		}
	})

	t.Run("没有记录就进不来，不自动开户", func(t *testing.T) {
		if got := cidLogin(newBrowser(tenantA), subject, ""); got != "/?cidError=no_access" {
			t.Fatalf("subject without any record redirected to %s", got)
		}
		// RN 不再建号、不再绑定
		if got := newBrowser(tenantA).do("POST", "/v1/admin/tenant-accounts", map[string]string{"displayName": "张三", "email": "zs@example.com"}, nil).Code; got != http.StatusNotFound {
			t.Fatalf("creating a member must be gone, got %d", got)
		}
		wantProblem(t, platform.do("GET", "/v1/admin/auth/cid/start?mode=bind", nil, nil), 400, "INVALID_CID_MODE")
		if got := platform.do("POST", "/v1/admin/auth/cid/bind/confirm", map[string]any{}, nil).Code; got != http.StatusNotFound {
			t.Fatalf("bind confirm must be gone, got %d", got)
		}
	})

	var memberID string
	member := newBrowser(tenantA)
	t.Run("外部系统写了记录，统一登录回来就是这个租户的会话", func(t *testing.T) {
		memberID = externalAccount(t, db, tenantA.id, subject, "zs@example.com")
		if got := cidLogin(member, subject, "/build/ios?tab=1"); got != "/build/ios?tab=1" {
			t.Fatalf("login callback redirected to %s", got)
		}
		view := member.mustCode(t, member.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		account := object(view["account"])
		if view["loginMethod"] != loginMethodCID || view["tenantId"] != tenantA.id || view["platformAdmin"] != false ||
			account["id"] != memberID || account["email"] != "zs@example.com" || account["scope"] != scopeTenant {
			t.Fatalf("cid session = %v", view)
		}
		if _, ok := view["bindRequired"]; ok {
			t.Fatalf("bindRequired must be gone: %v", view)
		}
		member.mustCode(t, member.do("GET", "/v1/admin/tenant", nil, nil), 200)
		// RN 只写 last_login_at，不动外部系统的 updated_at
		var lastLogin sql.NullTime
		var created, updated time.Time
		if err := db.QueryRow(`SELECT last_login_at, created_at, updated_at FROM tenant_admin_accounts WHERE id=?`, memberID).Scan(&lastLogin, &created, &updated); err != nil ||
			!lastLogin.Valid || !updated.Equal(created) {
			t.Fatalf("last_login_at=%v created=%v updated=%v err=%v", lastLogin, created, updated, err)
		}
		// 开放跳转：target 只收本站相对路径
		if got := cidLogin(newBrowser(tenantA), subject, "//evil.example/x"); got != "/" {
			t.Fatalf("unsafe target must fall back to /, got %s", got)
		}
		// 授权码只能用一次；state 对不上拒绝
		fresh := newBrowser(tenantA)
		authorize := location(t, fresh.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "zs@chainup.test")
		if got := location(t, fresh.do("GET", cidCallbackPath+"?code="+code+"&state=forged-state-value", nil, nil)); got != "/?cidError=state" {
			t.Fatalf("forged state redirected to %s", got)
		}
		if got := location(t, newBrowser(tenantA).do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=state" {
			t.Fatalf("replayed callback without the flow cookie redirected to %s", got)
		}
		// 控制台账号没有本地口令：拿显示名、邮箱当用户名都登不进
		wantProblem(t, newBrowser(tenantA).do("POST", "/v1/admin/auth/login", map[string]string{"username": "zs@example.com", "password": "anything-at-all"}, nil), 401, "INVALID_CREDENTIALS")
	})

	t.Run("同一个统一账号在别的租户要另有记录，会话不跨租户", func(t *testing.T) {
		elsewhere := newBrowser(tenantB)
		elsewhere.cookies = map[string]string{adminSessionCookie: member.cookies[adminSessionCookie]}
		wantProblem(t, elsewhere.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		if got := cidLogin(newBrowser(tenantB), subject, ""); got != "/?cidError=no_access" {
			t.Fatalf("subject without a record in tenant B redirected to %s", got)
		}
		externalAccount(t, db, tenantB.id, subject, "zs-b@example.com")
		inB := newBrowser(tenantB)
		if got := cidLogin(inB, subject, ""); got != "/" {
			t.Fatalf("login in tenant B redirected to %s", got)
		}
		if view := inB.mustCode(t, inB.do("GET", "/v1/admin/auth/session", nil, nil), 200); view["tenantId"] != tenantB.id || object(view["account"])["email"] != "zs-b@example.com" {
			t.Fatalf("tenant B session = %v", view)
		}
		// A 的会话照旧只认 A
		member.mustCode(t, member.do("GET", "/v1/admin/tenant", nil, nil), 200)
	})

	t.Run("租户会话永远不是平台管理员，只读列表只给平台管理员", func(t *testing.T) {
		wantProblem(t, member.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
		wantProblem(t, member.do("GET", "/v1/admin/tenant-accounts", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
		list := platform.mustCode(t, platform.do("GET", "/v1/admin/tenant-accounts", nil, nil), 200)
		items, _ := list["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("list = %v", list)
		}
		item := object(items[0])
		if item["id"] != memberID || item["subject"] != subject || item["tenantId"] != tenantA.id || item["createdBy"] != "ext-ops" || item["lastLoginAt"] == nil {
			t.Fatalf("list item = %v", item)
		}
	})

	t.Run("退出时给出认证中心的退出地址", func(t *testing.T) {
		out := newBrowser(tenantA)
		if got := cidLogin(out, subject, ""); got != "/" {
			t.Fatalf("login redirected to %s", got)
		}
		body := out.mustCode(t, out.do("POST", "/v1/admin/auth/logout", map[string]any{}, nil), 200)
		want := "https://login.test/auth/v1/logout?back=" + url.QueryEscape("https://"+tenantA.console+"/")
		if body["cidLogoutUrl"] != want {
			t.Fatalf("cidLogoutUrl = %v, want %s", body["cidLogoutUrl"], want)
		}
		wantProblem(t, out.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		// 环境变量账号不走统一登录，不给退出地址
		p := newBrowser(tenantA)
		p.mustCode(t, p.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
		if p.mustCode(t, p.do("POST", "/v1/admin/auth/logout", map[string]any{}, nil), 200)["cidLogoutUrl"] != nil {
			t.Fatal("env admin logout must not bounce through unified login")
		}
	})

	t.Run("外部系统换人：旧会话下一个请求就失效，新的人能登", func(t *testing.T) {
		successor := testSubject()
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET idp_subject=? WHERE id=?`, successor, memberID); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		if got := cidLogin(newBrowser(tenantA), subject, ""); got != "/?cidError=no_access" {
			t.Fatalf("the replaced person redirected to %s", got)
		}
		member = newBrowser(tenantA)
		if got := cidLogin(member, successor, ""); got != "/" {
			t.Fatalf("the successor redirected to %s", got)
		}
		subject = successor
	})

	t.Run("外部系统停用、改成别的租户、删掉：会话都在下一个请求失效", func(t *testing.T) {
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET status=? WHERE id=?`, accountDisabled, memberID); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		if got := cidLogin(newBrowser(tenantA), subject, ""); got != "/?cidError=disabled" {
			t.Fatalf("disabled account redirected to %s", got)
		}
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET status=? WHERE id=?`, accountActive, memberID); err != nil {
			t.Fatal(err)
		}
		member = newBrowser(tenantA)
		cidLogin(member, subject, "")
		member.mustCode(t, member.do("GET", "/v1/admin/tenant", nil, nil), 200)
		// 挪到别的租户：按会话的租户回表查不到
		other := accountsTestTenantRow(t, db, "c")
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET tenant_id=? WHERE id=?`, other.id, memberID); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET tenant_id=? WHERE id=?`, tenantA.id, memberID); err != nil {
			t.Fatal(err)
		}
		member = newBrowser(tenantA)
		cidLogin(member, subject, "")
		if _, err := db.Exec(`DELETE FROM tenant_admin_accounts WHERE id=?`, memberID); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
	})

	t.Run("数据库挡住外部系统写错的行", func(t *testing.T) {
		for name, insert := range map[string][]any{
			"大写的账号 id": {scopeTenant, tenantA.id, strings.ToUpper(testSubject()), "a@example.com", accountActive},
			"不是 uuid":  {scopeTenant, tenantA.id, "fuyu", "a@example.com", accountActive},
			"平台记录带租户":  {scopePlatform, tenantA.id, testSubject(), "a@example.com", accountActive},
			"租户记录没有租户": {scopeTenant, nil, testSubject(), "a@example.com", accountActive},
			"不认识的状态":   {scopeTenant, tenantA.id, testSubject(), "a@example.com", "pending_bind"},
			"邮箱不像邮箱":   {scopeTenant, tenantA.id, testSubject(), "nobody", accountActive},
		} {
			if _, err := db.Exec(`INSERT INTO tenant_admin_accounts (scope,tenant_id,idp_subject,email,status) VALUES (?,?,?,?,?)`, insert...); err == nil {
				t.Fatalf("%s: the row must be rejected", name)
			}
		}
		// 同一个统一账号在同一个租户里只能有一条
		dup := testSubject()
		externalAccount(t, db, tenantA.id, dup, "d@example.com")
		if _, err := db.Exec(`INSERT INTO tenant_admin_accounts (scope,tenant_id,idp_subject,email) VALUES (?,?,?,?)`, scopeTenant, tenantA.id, dup, "d2@example.com"); err == nil {
			t.Fatal("a second record of the same subject in one tenant must be rejected")
		}
	})
}
