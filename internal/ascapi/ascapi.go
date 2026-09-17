// Package ascapi 是 App Store Connect API 的只读客户端。
//
// 用途只有一个：回答"这个租户的 iOS 包在 Apple 那边是什么状态"——App 记录在不在、
// 最新的 build 是哪一个、什么时候过期、外部测试组开没开公开链接（设计
// docs/design/ios-testflight-distribution-2026-09-17.md §4.6）。
//
// **这个包不写 Apple 侧的任何状态，也不该写。** 提交 Beta App Review、开关公开链接、
// 增删测试员这三件事永远由人在管理端点、且二次确认：它们直接改变对外可见状态，而且
// 失败后果不对称——多开一个公开链接是把内测包发给全世界，少开一个只是没人能装
// （§4.6.6）。所以这里连 POST 的能力都没有。
//
// 凭证的保管与 pushcreds 同构：issuerId / keyId 是 ASC 页面上公开显示的标识，明文存；
// .p8 私钥用 STORAGE_MASTER_KEY 封存，AAD 绑租户。见 internal/api/ios_asc.go。
package ascapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL 是 Apple 的正式地址。测试用别的地址注入。
const DefaultBaseURL = "https://api.appstoreconnect.apple.com"

// tokenTTL 取 15 分钟。Apple 的上限是 20 分钟，留一点余量给两侧的时钟差——
// 超过上限时 Apple 回的是 401，读起来像"密钥无效"，会把人引到完全错误的方向。
const tokenTTL = 15 * time.Minute

// requestTimeout 单次请求的上限。保存凭证时人在等这条请求的结果。
const requestTimeout = 20 * time.Second

// Key 是一把 App Store Connect API 团队密钥。
//
// PrivateKeyPEM 是机密：这个类型的 String / LogValue 都不打印它，新加字段默认不出现
// （与 pushcreds.ServiceAccount 同一条纪律）。
type Key struct {
	IssuerID      string
	KeyID         string
	PrivateKeyPEM string
}

func (k Key) safeSummary() string {
	sealed := "unset"
	if k.PrivateKeyPEM != "" {
		sealed = fmt.Sprintf("<set,%d chars>", len(k.PrivateKeyPEM))
	}
	return fmt.Sprintf("ascKey{issuer=%s keyId=%s privateKey=%s}", k.IssuerID, k.KeyID, sealed)
}

func (k Key) String() string       { return k.safeSummary() }
func (k Key) GoString() string     { return k.safeSummary() }
func (k Key) LogValue() slog.Value { return slog.StringValue(k.safeSummary()) }

// ErrKeyRejected：Apple 不认这把钥匙（401/403）。与"网络不通"分开，因为处置完全不同。
var ErrKeyRejected = errors.New("App Store Connect 拒绝了这把密钥")

// ParsePrivateKey 校验 .p8 的形状：必须是一把 PKCS#8 里的 EC 私钥。
//
// 挡在这里的每一条，放过去都会变成保存成功、之后每次同步一句看不懂的 401。
// 最常见的拿错是 APNs 密钥——它和 ASC 密钥在同一个页面上下载，长得一模一样，
// 但 Apple 不接受它签的 ASC 令牌。那件事这里看不出来，只有真调一次接口才知道，
// 所以保存时一定要验证（Verify）。
func ParsePrivateKey(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil {
		return nil, errors.New("这不是一份 PEM：文件应该以 -----BEGIN PRIVATE KEY----- 开头")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("这不是一把 PKCS#8 私钥：%w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("这不是一把椭圆曲线私钥；App Store Connect 的 .p8 是 ES256（P-256）")
	}
	return key, nil
}

// token 签一个 ES256 JWT。
//
// 签名必须是 raw r||s（IEEE P1363），**不是** DER。Go 的 ecdsa.SignASN1 给的是 DER，
// 用它签出来的令牌 Apple 一律 401，而错误信息与"密钥无效"完全一样——这是这条链路上
// 最容易踩、又最难看出来的一个坑。
func (k Key) token(now time.Time) (string, error) {
	key, err := ParsePrivateKey(k.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": k.KeyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": k.IssuerID,
		"iat": now.Unix(),
		"exp": now.Add(tokenTTL).Unix(),
		"aud": "appstoreconnect-v1",
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*size)
	r.FillBytes(signature[:size])
	s.FillBytes(signature[size:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Client 是一个租户的只读 ASC 客户端。
type Client struct {
	Key     Key
	BaseURL string
	HTTP    *http.Client
	Now     func() time.Time
}

func (c Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: requestTimeout}
}

func (c Client) baseURL() string {
	if strings.TrimSpace(c.BaseURL) != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return DefaultBaseURL
}

// get 发一次 GET 并把 data 解成 out。只做 GET：见包注释。
func (c Client) get(ctx context.Context, path string, query url.Values, out any) error {
	token, err := c.Key.token(c.now())
	if err != nil {
		return err
	}
	target := c.baseURL() + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.httpClient().Do(request)
	if err != nil {
		// 错误里可能带着完整 URL，但绝不会带令牌：它只在请求头里
		return fmt.Errorf("连不上 App Store Connect：%w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读 App Store Connect 的响应失败：%w", err)
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w：%s（%d）。确认 Issuer ID、Key ID 与 .p8 属于同一把团队密钥，且这把密钥没有被吊销",
			ErrKeyRejected, appleErrorDetail(body), response.StatusCode)
	case response.StatusCode >= 300:
		return fmt.Errorf("App Store Connect 返回 %d：%s", response.StatusCode, appleErrorDetail(body))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("App Store Connect 的响应不是预期的 JSON：%w", err)
	}
	return nil
}

// appleErrorDetail 取 Apple 错误体里的第一条 detail，取不到就回状态描述。
// 不把整个响应体回显出去：它可能很长，而且对使用者没有帮助。
func appleErrorDetail(body []byte) string {
	var parsed struct {
		Errors []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Errors) > 0 {
		first := parsed.Errors[0]
		if strings.TrimSpace(first.Detail) != "" {
			return first.Detail
		}
		if strings.TrimSpace(first.Title) != "" {
			return first.Title
		}
	}
	return "没有可读的错误说明"
}

// App 是 ASC 上的一条 App 记录。
type App struct {
	ID       string
	Name     string
	BundleID string
	SKU      string
}

// ErrAppNotFound：这把钥匙看得见的 App 里没有这个 bundle id。
var ErrAppNotFound = errors.New("这把密钥下没有这个 bundle id 的 App 记录")

// FindApp 按 bundle id 找 App，必须**恰好**命中一条。
//
// 恰好一条这个要求不是洁癖：命中 0 条说明 Key 属于另一个团队、或 App 记录还没建；
// 命中多条说明 bundle id 填错了（filter 是精确匹配，理论上不会多条，真出现就是
// Apple 那边的语义和我们理解的不一样）。两种都不该被当成"配好了"。
func (c Client) FindApp(ctx context.Context, bundleID string) (App, error) {
	var body struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name     string `json:"name"`
				BundleID string `json:"bundleId"`
				SKU      string `json:"sku"`
			} `json:"attributes"`
		} `json:"data"`
	}
	query := url.Values{"filter[bundleId]": {bundleID}, "limit": {"2"}}
	if err := c.get(ctx, "/v1/apps", query, &body); err != nil {
		return App{}, err
	}
	if len(body.Data) != 1 {
		return App{}, fmt.Errorf("%w（命中 %d 条）：确认这把密钥属于持有 %s 的团队，且 App Store Connect 上已经建好这条 App 记录",
			ErrAppNotFound, len(body.Data), bundleID)
	}
	item := body.Data[0]
	return App{ID: item.ID, Name: item.Attributes.Name, BundleID: item.Attributes.BundleID, SKU: item.Attributes.SKU}, nil
}

// Build 是一个已上传的 build。Version 是 CFBundleVersion（Apple 管它叫 version）。
type Build struct {
	ID              string
	Version         string
	ProcessingState string
	Expired         bool
	ExpirationDate  *time.Time
	UploadedDate    *time.Time
}

// LatestBuilds 取最近的几个 build，最新在前。
func (c Client) LatestBuilds(ctx context.Context, appID string, limit int) ([]Build, error) {
	if limit < 1 || limit > 50 {
		limit = 10
	}
	var body struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Version         string     `json:"version"`
				ProcessingState string     `json:"processingState"`
				Expired         bool       `json:"expired"`
				ExpirationDate  *time.Time `json:"expirationDate"`
				UploadedDate    *time.Time `json:"uploadedDate"`
			} `json:"attributes"`
		} `json:"data"`
	}
	query := url.Values{
		"filter[app]": {appID},
		"sort":        {"-uploadedDate"},
		"limit":       {fmt.Sprint(limit)},
	}
	if err := c.get(ctx, "/v1/builds", query, &body); err != nil {
		return nil, err
	}
	builds := make([]Build, 0, len(body.Data))
	for _, item := range body.Data {
		builds = append(builds, Build{
			ID: item.ID, Version: item.Attributes.Version, ProcessingState: item.Attributes.ProcessingState,
			Expired: item.Attributes.Expired, ExpirationDate: item.Attributes.ExpirationDate,
			UploadedDate: item.Attributes.UploadedDate,
		})
	}
	return builds, nil
}

// BetaGroup 是一个测试组。公开链接只有外部组才有。
type BetaGroup struct {
	ID                string
	Name              string
	IsInternal        bool
	PublicLinkEnabled bool
	PublicLink        string
	PublicLinkLimit   int
}

// BetaGroups 列出这个 App 的测试组。
func (c Client) BetaGroups(ctx context.Context, appID string) ([]BetaGroup, error) {
	var body struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Name              string `json:"name"`
				IsInternalGroup   bool   `json:"isInternalGroup"`
				PublicLinkEnabled bool   `json:"publicLinkEnabled"`
				PublicLink        string `json:"publicLink"`
				PublicLinkLimit   int    `json:"publicLinkLimit"`
			} `json:"attributes"`
		} `json:"data"`
	}
	query := url.Values{"filter[app]": {appID}, "limit": {"50"}}
	if err := c.get(ctx, "/v1/betaGroups", query, &body); err != nil {
		return nil, err
	}
	groups := make([]BetaGroup, 0, len(body.Data))
	for _, item := range body.Data {
		groups = append(groups, BetaGroup{
			ID: item.ID, Name: item.Attributes.Name, IsInternal: item.Attributes.IsInternalGroup,
			PublicLinkEnabled: item.Attributes.PublicLinkEnabled, PublicLink: item.Attributes.PublicLink,
			PublicLinkLimit: item.Attributes.PublicLinkLimit,
		})
	}
	return groups, nil
}

// Verify 用这把钥匙真查一次这个 bundle id 的 App 记录。
//
// 这一步不能省，理由与 pushcreds.Verify 同一条：ParsePrivateKey 只在本地解析，
// 不联网——密钥在 Apple 后台被吊销之后，本地解析照样成功，直到第一次真同步才炸。
// 而且这里走的正是之后每次同步会走的那条路，"验证通过"才证明得了东西。
func (c Client) Verify(ctx context.Context, bundleID string) (App, error) {
	return c.FindApp(ctx, bundleID)
}
