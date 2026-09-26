// Package cid 是 ChainUp 认证中心（下称认证中心）的最小客户端。
//
// 认证中心不是 OIDC：协议是 OAuth2 授权码 + PKCE（S256），scope 只有 profile，没有 id_token 与 JWKS。
// 身份靠「服务端直连换令牌、再查 userinfo」保证——这是机密客户端的标准做法，令牌不经过浏览器。
//
//   - 换令牌：POST 令牌端点，客户端认证 client_secret_basic；
//   - userinfo：认证中心自己的 POST /internal/v1/userinfo，表单里放 access_token，同样带客户端 Basic；
//     返回 {"username": <账号 uuid>, "email": ...}，没有 account 字段；
//   - 出错时认证中心常常回 HTTP 200，错误码放在 JSON 的 code 里，所以不能只看状态码。
//
// 授权与退出地址是给浏览器的，可以带 {baseHost} 占位符（认证中心挂在应用域名下的部署方式）；
// 集中登录域名（如 https://login.dexfun.win）就直接写死。设计见 RN-Server
// docs/design/tenant-console-accounts-and-sso-2026-09-25.md §4.7、§4.9。
package cid

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Config 是一个应用在认证中心的登记与四个端点。
type Config struct {
	// AuthorizeURL 与 LogoutURL 给浏览器用，可以带 {baseHost}
	AuthorizeURL string `json:"authorizeUrl"`
	LogoutURL    string `json:"logoutUrl"`
	// TokenURL 与 UserinfoURL 由服务端直连，可以是内网地址
	TokenURL     string `json:"tokenUrl"`
	UserinfoURL  string `json:"userinfoUrl"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"-"`
}

// User 是 userinfo 回答的「这个人是谁」。
type User struct {
	// Subject 是认证中心的账号 uuid（userinfo 的 username），永久不变，绑定时存它
	Subject string
	// Email 只用于显示，不作身份依据：认证中心那边能改
	Email string
}

// Client 是一个应用的客户端。零值不可用，用 New。
type Client struct {
	cfg  Config
	http *http.Client
}

const baseHostPlaceholder = "{baseHost}"

// subjectPattern：认证中心的账号 id 是 uuid。对不上就拒绝，不猜——换了格式要先看清楚再放行。
var subjectPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// New 校验配置。浏览器端点必须是 https（本机调试的 localhost 除外）；服务端端点允许 http，
// 但只能是本机或内网地址——换令牌时要带客户端密钥，明文走公网等于公开它。
func New(cfg Config) (*Client, error) {
	cfg.AuthorizeURL = strings.TrimSpace(cfg.AuthorizeURL)
	cfg.LogoutURL = strings.TrimSpace(cfg.LogoutURL)
	cfg.TokenURL = strings.TrimSpace(cfg.TokenURL)
	cfg.UserinfoURL = strings.TrimSpace(cfg.UserinfoURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("clientId 与 clientSecret 都是必填")
	}
	for name, raw := range map[string]string{"authorizeUrl": cfg.AuthorizeURL, "logoutUrl": cfg.LogoutURL} {
		if err := checkURL(raw, false); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, raw := range map[string]string{"tokenUrl": cfg.TokenURL, "userinfoUrl": cfg.UserinfoURL} {
		if strings.Contains(raw, baseHostPlaceholder) {
			return nil, fmt.Errorf("%s: 服务端直连的地址不能带 %s", name, baseHostPlaceholder)
		}
		if err := checkURL(raw, true); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Config 返回配置（不含密钥之外的东西都能给人看）。
func (c *Client) Config() Config { return c.cfg }

func checkURL(raw string, serverSide bool) error {
	if raw == "" {
		return errors.New("必填")
	}
	parsed, err := url.Parse(strings.ReplaceAll(raw, baseHostPlaceholder, "placeholder.invalid"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("不是一个合法的绝对地址")
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		host := parsed.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || (serverSide && ip.IsPrivate())) {
			return nil
		}
		if serverSide {
			return errors.New("明文 http 只允许本机或内网地址")
		}
		return errors.New("给浏览器的地址必须是 https")
	default:
		return errors.New("只支持 https（本机或内网可以 http）")
	}
}

// NewPKCE 生成 code_verifier 与对应的 S256 code_challenge。
func NewPKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// NewState 生成一次性的 state。
func NewState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// AuthorizeURL 拼浏览器要去的授权地址。baseHost 只替换 {baseHost} 占位符。
// 固定 response_mode=query：发起时的临时 Cookie 是 SameSite=Lax，form_post 回来的跨站 POST 带不上它。
func (c *Client) AuthorizeURL(baseHost, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "profile")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return withQuery(strings.ReplaceAll(c.cfg.AuthorizeURL, baseHostPlaceholder, baseHost), q)
}

// LogoutURL 拼浏览器退出认证中心的地址，退完回到 back。
func (c *Client) LogoutURL(baseHost, back string) string {
	q := url.Values{}
	q.Set("back", back)
	return withQuery(strings.ReplaceAll(c.cfg.LogoutURL, baseHostPlaceholder, baseHost), q)
}

func withQuery(base string, q url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + q.Encode()
}

// Exchange 用授权码换 access token。令牌只在内存里用一次，调用方不要存、不要打日志。
// 认证中心同时会发 refresh_token，这里直接丢掉：我们不代表用户长期访问认证中心。
func (c *Client) Exchange(ctx context.Context, code, redirectURI, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		cidError
	}
	if err := c.post(ctx, c.cfg.TokenURL, form, &body); err != nil {
		return "", fmt.Errorf("换令牌: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("换令牌被拒绝: %s", body.describe())
	}
	return body.AccessToken, nil
}

// UserInfo 查这个令牌是谁。
func (c *Client) UserInfo(ctx context.Context, accessToken string) (User, error) {
	form := url.Values{}
	form.Set("access_token", accessToken)
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		cidError
	}
	if err := c.post(ctx, c.cfg.UserinfoURL, form, &body); err != nil {
		return User{}, fmt.Errorf("查用户信息: %w", err)
	}
	if body.Username == "" {
		return User{}, fmt.Errorf("查用户信息被拒绝: %s", body.describe())
	}
	if !subjectPattern.MatchString(body.Username) {
		return User{}, errors.New("认证中心返回的账号 id 不是 uuid，拒绝")
	}
	email := strings.TrimSpace(body.Email)
	if len(email) > 255 {
		email = ""
	}
	return User{Subject: strings.ToLower(body.Username), Email: email}, nil
}

// cidError 兼容两种错误形状：认证中心自己的 {code,msg} 与 OAuth2 标准的 {error,error_description}。
type cidError struct {
	Code             string `json:"code"`
	Msg              string `json:"msg"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e cidError) describe() string {
	parts := []string{}
	for _, v := range []string{e.Code, e.Msg, e.Error, e.ErrorDescription} {
		if v = strings.TrimSpace(v); v != "" {
			if len(v) > 200 {
				v = v[:200]
			}
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return "认证中心没有给出原因"
	}
	return strings.Join(parts, " / ")
}

func (c *Client) post(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 §2.3.1：Basic 的用户名与口令先按表单编码
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	resp, err := c.http.Do(req)
	if err != nil {
		// 错误里只有地址与网络原因，不会带表单内容
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 500 {
		return fmt.Errorf("认证中心返回 HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("认证中心返回的不是 JSON（HTTP %d）", resp.StatusCode)
	}
	return nil
}
