package cid

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testSubject = "1c9670fc-87c8-4655-9366-d8eebbea7c74"

// fakeCID 按认证中心的真实形状应答：出错时 HTTP 200 + {code,msg}。
func fakeCID(t *testing.T, wantVerifier *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		// 和 Spring Authorization Server 的 ClientSecretBasicAuthenticationConverter 一样先按表单解码
		rawID, rawSecret, ok := r.BasicAuth()
		id, _ := url.QueryUnescape(rawID)
		secret, _ := url.QueryUnescape(rawSecret)
		if !ok || id != "client-1" || secret != "s3cret&x" {
			_, _ = w.Write([]byte(`{"code":"401","msg":"Client authentication failed: client_secret","data":null}`))
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "good-code" ||
			r.Form.Get("redirect_uri") != "https://console.example.com/client/v1/oauth/login" ||
			(wantVerifier != nil && r.Form.Get("code_verifier") != *wantVerifier) {
			_, _ = w.Write([]byte(`{"code":"401","msg":"Client authentication failed: code","data":null}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer","expires_in":599,"refresh_token":"rt-1","scope":"profile"}`))
	})
	mux.HandleFunc("/internal/v1/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			_, _ = w.Write([]byte(`{"code":"401","msg":"Full authentication is required"}`))
			return
		}
		_ = r.ParseForm()
		switch r.Form.Get("access_token") {
		case "at-1":
			_, _ = w.Write([]byte(`{"username":"` + strings.ToUpper(testSubject) + `","email":"a@example.com"}`))
		case "at-weird":
			_, _ = w.Write([]byte(`{"username":"admin","email":"a@example.com"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(Config{
		AuthorizeURL: "https://{baseHost}/auth/v1/oauth/authorize",
		LogoutURL:    "https://login.example.com/auth/v1/logout",
		TokenURL:     base + "/auth/v1/oauth/token",
		UserinfoURL:  base + "/internal/v1/userinfo",
		ClientID:     "client-1",
		ClientSecret: "s3cret&x",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPKCEChallengeIsS256OfVerifier(t *testing.T) {
	verifier, challenge, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier) < 43 {
		t.Fatalf("verifier too short: %d", len(verifier))
	}
	sum := sha256.Sum256([]byte(verifier))
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge is not S256(verifier)")
	}
}

func TestAuthorizeAndLogoutURLs(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1")
	raw := c.AuthorizeURL("console.example.com", "https://console.example.com/client/v1/oauth/login", "st", "ch")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "console.example.com" || u.Path != "/auth/v1/oauth/authorize" {
		t.Fatalf("unexpected authorize url %s", raw)
	}
	q := u.Query()
	for k, v := range map[string]string{"response_type": "code", "response_mode": "query", "client_id": "client-1", "scope": "profile",
		"state": "st", "code_challenge": "ch", "code_challenge_method": "S256", "redirect_uri": "https://console.example.com/client/v1/oauth/login"} {
		if q.Get(k) != v {
			t.Fatalf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	logout := c.LogoutURL("console.example.com", "https://console.example.com/")
	if logout != "https://login.example.com/auth/v1/logout?back=https%3A%2F%2Fconsole.example.com%2F" {
		t.Fatalf("unexpected logout url %s", logout)
	}
}

func TestExchangeAndUserInfo(t *testing.T) {
	verifier := "v-123"
	srv := fakeCID(t, &verifier)
	c := newTestClient(t, srv.URL)
	ctx := context.Background()
	redirect := "https://console.example.com/client/v1/oauth/login"

	at, err := c.Exchange(ctx, "good-code", redirect, verifier)
	if err != nil || at != "at-1" {
		t.Fatalf("exchange = %q, %v", at, err)
	}
	user, err := c.UserInfo(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	if user.Subject != testSubject || user.Email != "a@example.com" {
		t.Fatalf("user = %+v", user)
	}

	// 认证中心出错时回 HTTP 200：必须按 body 判断，而且错误里不能出现令牌或密钥
	if _, err := c.Exchange(ctx, "bad-code", redirect, verifier); err == nil || !strings.Contains(err.Error(), "code") {
		t.Fatalf("bad code should fail with the CID reason, got %v", err)
	}
	if _, err := c.Exchange(ctx, "good-code", redirect, "wrong-verifier"); err == nil {
		t.Fatal("wrong verifier should fail")
	}
	if _, err := c.UserInfo(ctx, "at-unknown"); err == nil {
		t.Fatal("empty userinfo should fail")
	}
	if _, err := c.UserInfo(ctx, "at-weird"); err == nil || strings.Contains(err.Error(), "admin") {
		t.Fatalf("non-uuid subject should be rejected without echoing it, got %v", err)
	}

	bad, _ := New(Config{AuthorizeURL: "https://x/a", LogoutURL: "https://x/l", TokenURL: srv.URL + "/auth/v1/oauth/token",
		UserinfoURL: srv.URL + "/internal/v1/userinfo", ClientID: "client-1", ClientSecret: "nope"})
	if _, err := bad.Exchange(ctx, "good-code", redirect, verifier); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatalf("wrong secret should fail without echoing it, got %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{
		AuthorizeURL: "https://login.example.com/auth/v1/oauth/authorize",
		LogoutURL:    "https://login.example.com/auth/v1/logout",
		TokenURL:     "http://172.17.19.2:9098/auth/v1/oauth/token",
		UserinfoURL:  "http://127.0.0.1:9099/internal/v1/userinfo",
		ClientID:     "id",
		ClientSecret: "secret",
	}
	if _, err := New(base); err != nil {
		t.Fatalf("intranet http for server-side endpoints should be allowed: %v", err)
	}
	cases := map[string]func(*Config){
		"browser http":          func(c *Config) { c.AuthorizeURL = "http://login.example.com/a" },
		"browser private http":  func(c *Config) { c.LogoutURL = "http://10.0.0.1/l" },
		"server public http":    func(c *Config) { c.TokenURL = "http://login.example.com/t" },
		"server placeholder":    func(c *Config) { c.UserinfoURL = "https://{baseHost}/internal/v1/userinfo" },
		"missing secret":        func(c *Config) { c.ClientSecret = "" },
		"relative url":          func(c *Config) { c.TokenURL = "/auth/v1/oauth/token" },
		"credentials in url":    func(c *Config) { c.TokenURL = "https://u:p@login.example.com/t" },
		"unsupported scheme":    func(c *Config) { c.AuthorizeURL = "javascript:alert(1)" },
		"placeholder elsewhere": func(c *Config) { c.TokenURL = "https://{baseHost}/t" },
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
