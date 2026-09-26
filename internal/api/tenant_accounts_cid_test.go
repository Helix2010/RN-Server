package api

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

// 租户控制台账号与统一登录走真实路由的回归（设计 tenant-console-accounts-and-sso-2026-09-25 §3、§4）。
// 两个租户、各自 console.* 与 api.* 两个域名（nginx 把 console.* 的 Host 改写成 api.*，并写 X-RN-Console-Host）；
// 认证中心用本地假实现，按真实形状应答（出错时 HTTP 200 + {code,msg}）。

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
	subject := "3f1a2b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"

	platform := newBrowser(tenantA)
	view := platform.mustCode(t, platform.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
	if view["platformAdmin"] != true || view["tenantId"] != nil {
		t.Fatalf("platform session view = %v", view)
	}

	var memberPassword, memberID string
	t.Run("平台管理员建成员拿到一次性的初始口令", func(t *testing.T) {
		body := platform.mustCode(t, platform.do("POST", "/v1/admin/tenant-accounts",
			map[string]string{"displayName": "张三", "loginName": "Zhang.San", "email": "zs@example.com"}, nil), 201)
		memberPassword, _ = body["initialPassword"].(string)
		account := object(body["account"])
		memberID, _ = account["id"].(string)
		if len(memberPassword) != initialPasswordLen || account["status"] != accountPendingBind || account["loginName"] != "zhang.san" {
			t.Fatalf("create = %v", body)
		}
		wantProblem(t, platform.do("POST", "/v1/admin/tenant-accounts",
			map[string]string{"displayName": "重复", "loginName": "zhang.san", "email": "x@example.com"}, nil), 409, "LOGIN_NAME_TAKEN")
		wantProblem(t, platform.do("POST", "/v1/admin/tenant-accounts",
			map[string]string{"displayName": "撞名", "loginName": platformUser, "email": "x@example.com"}, nil), 422, "INVALID_LOGIN_NAME")
		list := platform.mustCode(t, platform.do("GET", "/v1/admin/tenant-accounts", nil, nil), 200)
		if items, _ := list["items"].([]any); len(items) != 1 {
			t.Fatalf("list = %v", list)
		}
		// 审计不带口令
		var summary string
		if err := db.QueryRow(`SELECT summary FROM audit_events WHERE tenant_id=? AND action='tenant_account_create' ORDER BY created_at DESC LIMIT 1`, tenantA.id).Scan(&summary); err != nil {
			t.Fatalf("audit: %v", err)
		}
		if strings.Contains(summary, memberPassword) {
			t.Fatal("the initial password must not reach the audit log")
		}
	})

	member := newBrowser(tenantA)
	t.Run("初始口令登录后只能去绑定", func(t *testing.T) {
		view := member.mustCode(t, member.do("POST", "/v1/admin/auth/login", map[string]string{"username": "ZHANG.SAN", "password": memberPassword}, nil), 200)
		if view["bindRequired"] != true || view["platformAdmin"] != false || view["tenantId"] != tenantA.id || view["loginMethod"] != loginMethodLocal {
			t.Fatalf("member session view = %v", view)
		}
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 403, "BIND_REQUIRED")
		wantProblem(t, member.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 403, "BIND_REQUIRED")
		member.mustCode(t, member.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		wantProblem(t, member.do("POST", "/v1/admin/auth/login", map[string]string{"username": "zhang.san", "password": "wrong-password"}, nil), 401, "INVALID_CREDENTIALS")
	})

	t.Run("会话与账号都不跨租户", func(t *testing.T) {
		elsewhere := newBrowser(tenantB)
		elsewhere.cookies = map[string]string{adminSessionCookie: member.cookies[adminSessionCookie]}
		wantProblem(t, elsewhere.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		wantProblem(t, elsewhere.do("POST", "/v1/admin/auth/login", map[string]string{"username": "zhang.san", "password": memberPassword}, nil), 401, "INVALID_CREDENTIALS")
	})

	t.Run("平台管理员配置统一登录，密钥不回显", func(t *testing.T) {
		// 没配之前：登录页看到统一登录没开，发起直接回首页报原因
		methods := member.mustCode(t, member.do("GET", "/v1/admin/auth/methods", nil, nil), 200)
		if methods["cid"] != false {
			t.Fatalf("methods = %v", methods)
		}
		if got := location(t, member.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil)); got != "/?cidError=not_configured" {
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
		if member.mustCode(t, member.do("GET", "/v1/admin/auth/methods", nil, nil), 200)["cid"] != true {
			t.Fatal("methods must report cid=true once configured")
		}
	})

	t.Run("绑定：回调之后本人确认才落库", func(t *testing.T) {
		authorize := location(t, member.do("GET", "/v1/admin/auth/cid/start?mode=bind", nil, nil))
		if !strings.HasPrefix(authorize, "https://login.test/auth/v1/oauth/authorize?") ||
			!strings.Contains(authorize, url.QueryEscape("https://"+tenantA.console+cidCallbackPath)) {
			t.Fatalf("authorize url = %s", authorize)
		}
		code, state := cidServer.approve(t, authorize, subject, "zs@chainup.test")
		// state 对不上（别的标签页、伪造的回调）：拒绝
		if got := location(t, member.do("GET", cidCallbackPath+"?code="+code+"&state=forged-state-value", nil, nil)); got != "/?cidError=state" {
			t.Fatalf("forged state redirected to %s", got)
		}
		if got := location(t, member.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/cid/bind-confirm" {
			t.Fatalf("bind callback redirected to %s", got)
		}
		// 回调只是记下「要绑哪个」，账号还没变
		wantProblem(t, member.do("GET", "/v1/admin/tenant", nil, nil), 403, "BIND_REQUIRED")
		pending := member.mustCode(t, member.do("GET", "/v1/admin/auth/cid/bind", nil, nil), 200)
		if object(pending["cid"])["email"] != "zs@chainup.test" {
			t.Fatalf("pending bind = %v", pending)
		}
		// 别的租户的页面不能替他确认
		wantProblem(t, member.do("POST", "/v1/admin/auth/cid/bind/confirm", map[string]any{}, map[string]string{"Origin": "https://" + tenantB.console}), 403, "UNTRUSTED_ORIGIN")
		view := member.mustCode(t, member.do("POST", "/v1/admin/auth/cid/bind/confirm", map[string]any{}, nil), 200)
		account := object(view["account"])
		if view["bindRequired"] != false || account["status"] != accountActive || account["boundEmail"] != "zs@chainup.test" {
			t.Fatalf("confirm = %v", view)
		}
		member.mustCode(t, member.do("GET", "/v1/admin/tenant", nil, nil), 200)
		wantProblem(t, member.do("GET", "/v1/admin/auth/cid/bind", nil, nil), 404, "CID_BIND_NOT_PENDING")
	})

	t.Run("绑定之后本地口令作废，只能统一登录", func(t *testing.T) {
		wantProblem(t, newBrowser(tenantA).do("POST", "/v1/admin/auth/login", map[string]string{"username": "zhang.san", "password": memberPassword}, nil), 409, "ACCOUNT_BOUND_USE_CID")
		fresh := newBrowser(tenantA)
		authorize := location(t, fresh.do("GET", "/v1/admin/auth/cid/start?mode=login&target="+url.QueryEscape("/build/ios?tab=1"), nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "zs@chainup.test")
		if got := location(t, fresh.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/build/ios?tab=1" {
			t.Fatalf("login callback redirected to %s", got)
		}
		view := fresh.mustCode(t, fresh.do("GET", "/v1/admin/auth/session", nil, nil), 200)
		if view["loginMethod"] != loginMethodCID || view["tenantId"] != tenantA.id || view["platformAdmin"] != false {
			t.Fatalf("cid session = %v", view)
		}
		// 授权码只能用一次
		if got := location(t, newBrowser(tenantA).do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=state" {
			t.Fatalf("replayed callback without the flow cookie redirected to %s", got)
		}
		// 开放跳转：target 只收本站相对路径
		evil := newBrowser(tenantA)
		authorize = location(t, evil.do("GET", "/v1/admin/auth/cid/start?mode=login&target="+url.QueryEscape("//evil.example/x"), nil, nil))
		code, state = cidServer.approve(t, authorize, subject, "zs@chainup.test")
		if got := location(t, evil.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/" {
			t.Fatalf("unsafe target must fall back to /, got %s", got)
		}
		// 统一认证账号没绑本租户：拒绝，不自动开户
		stranger := newBrowser(tenantA)
		authorize = location(t, stranger.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state = cidServer.approve(t, authorize, "99999999-aaaa-4bbb-8ccc-dddddddddddd", "who@chainup.test")
		if got := location(t, stranger.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=unbound" {
			t.Fatalf("unbound subject redirected to %s", got)
		}
		// 同一个统一认证账号在 B 租户没有账号：B 的控制台照样进不去
		other := newBrowser(tenantB)
		authorize = location(t, other.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state = cidServer.approve(t, authorize, subject, "zs@chainup.test")
		if got := location(t, other.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=unbound" {
			t.Fatalf("subject without an account in tenant B redirected to %s", got)
		}
		member.cookies = fresh.cookies
	})

	t.Run("租户会话永远不是平台管理员", func(t *testing.T) {
		wantProblem(t, member.do("GET", "/v1/admin/platform/auth/cid", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
		wantProblem(t, member.do("GET", "/v1/admin/tenant-accounts", nil, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})

	t.Run("同一个统一认证账号不能绑同租户两个成员", func(t *testing.T) {
		body := platform.mustCode(t, platform.do("POST", "/v1/admin/tenant-accounts",
			map[string]string{"displayName": "李四", "loginName": "lisi", "email": "ls@example.com"}, nil), 201)
		second := newBrowser(tenantA)
		second.mustCode(t, second.do("POST", "/v1/admin/auth/login", map[string]string{"username": "lisi", "password": body["initialPassword"].(string)}, nil), 200)
		authorize := location(t, second.do("GET", "/v1/admin/auth/cid/start?mode=bind", nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "zs@chainup.test")
		if got := location(t, second.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil)); got != "/?cidError=already_bound" {
			t.Fatalf("second bind of the same subject redirected to %s", got)
		}
	})

	t.Run("退出时给出认证中心的退出地址", func(t *testing.T) {
		out := newBrowser(tenantA)
		out.cookies = map[string]string{adminSessionCookie: member.cookies[adminSessionCookie]}
		body := out.mustCode(t, out.do("POST", "/v1/admin/auth/logout", map[string]any{}, nil), 200)
		want := "https://login.test/auth/v1/logout?back=" + url.QueryEscape("https://"+tenantA.console+"/")
		if body["cidLogoutUrl"] != want {
			t.Fatalf("cidLogoutUrl = %v, want %s", body["cidLogoutUrl"], want)
		}
		wantProblem(t, out.do("GET", "/v1/admin/auth/session", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		// 平台会话不走统一登录，不给退出地址
		p := newBrowser(tenantA)
		p.mustCode(t, p.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
		if p.mustCode(t, p.do("POST", "/v1/admin/auth/logout", map[string]any{}, nil), 200)["cidLogoutUrl"] != nil {
			t.Fatal("platform logout must not bounce through unified login")
		}
	})

	t.Run("停用立即生效，重置后回到待绑定", func(t *testing.T) {
		fresh := newBrowser(tenantA)
		authorize := location(t, fresh.do("GET", "/v1/admin/auth/cid/start?mode=login", nil, nil))
		code, state := cidServer.approve(t, authorize, subject, "zs@chainup.test")
		location(t, fresh.do("GET", cidCallbackPath+"?code="+code+"&state="+url.QueryEscape(state), nil, nil))
		fresh.mustCode(t, fresh.do("GET", "/v1/admin/tenant", nil, nil), 200)

		wantProblem(t, platform.do("POST", "/v1/admin/tenant-accounts/"+memberID+"/disable", map[string]any{"reason": " "}, nil), 400, "REASON_REQUIRED")
		platform.mustCode(t, platform.do("POST", "/v1/admin/tenant-accounts/"+memberID+"/disable", map[string]any{"reason": "离职停用"}, nil), 200)
		wantProblem(t, fresh.do("GET", "/v1/admin/tenant", nil, nil), 401, "ADMIN_AUTH_REQUIRED")
		wantProblem(t, platform.do("POST", "/v1/admin/tenant-accounts/"+memberID+"/disable", map[string]any{"reason": "离职停用"}, nil), 409, "TENANT_ACCOUNT_ALREADY_DISABLED")

		body := platform.mustCode(t, platform.do("POST", "/v1/admin/tenant-accounts/"+memberID+"/reset", map[string]any{"reason": "换绑统一账号"}, nil), 200)
		account := object(body["account"])
		if account["status"] != accountPendingBind || account["bound"] != false || account["boundSubject"] != nil {
			t.Fatalf("reset = %v", body)
		}
		again := newBrowser(tenantA)
		view := again.mustCode(t, again.do("POST", "/v1/admin/auth/login", map[string]string{"username": "zhang.san", "password": body["initialPassword"].(string)}, nil), 200)
		if view["bindRequired"] != true {
			t.Fatalf("after reset the member must bind again: %v", view)
		}
		wantProblem(t, platform.do("POST", "/v1/admin/tenant-accounts/"+memberID+"/disable", map[string]any{"reason": "离职停用"}, map[string]string{"Origin": "https://" + tenantB.console}), 403, "UNTRUSTED_ORIGIN")
		wantProblem(t, newBrowser(tenantB).do("POST", "/v1/admin/tenant-accounts/"+memberID+"/reset", map[string]any{"reason": "换绑统一账号"}, nil), 401, "ADMIN_AUTH_REQUIRED")
	})

	t.Run("初始口令过期就登不进", func(t *testing.T) {
		body := platform.mustCode(t, platform.do("POST", "/v1/admin/tenant-accounts",
			map[string]string{"displayName": "王五", "loginName": "wangwu", "email": "ww@example.com"}, nil), 201)
		id := object(body["account"])["id"]
		if _, err := db.Exec(`UPDATE tenant_admin_accounts SET password_expires_at=? WHERE id=?`, time.Now().UTC().Add(-time.Minute), id); err != nil {
			t.Fatal(err)
		}
		wantProblem(t, newBrowser(tenantA).do("POST", "/v1/admin/auth/login", map[string]string{"username": "wangwu", "password": body["initialPassword"].(string)}, nil), 401, "INITIAL_PASSWORD_EXPIRED")
	})
}
