package ascapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) Key {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return Key{
		IssuerID:      "57246542-96fe-1a63-e053-0824d011072a",
		KeyID:         "8WQNTAY7MP",
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
	}
}

// 令牌的形状。**签名必须恰好 64 字节**：Apple 要 raw r||s（IEEE P1363），而 Go 的
// ecdsa.SignASN1 给的是 DER——用 DER 签出来的令牌一律 401，错误信息和"密钥无效"
// 一模一样，是这条链路上最难看出来的一个坑。
func TestTokenIsES256WithRawSignature(t *testing.T) {
	key := testKey(t)
	now := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	token, err := key.token(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("a JWT has three parts, got %d", len(parts))
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &header) != nil || header.Alg != "ES256" || header.Kid != key.KeyID || header.Typ != "JWT" {
		t.Fatalf("unexpected header: %s", raw)
	}
	var payload struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	raw, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &payload) != nil || payload.Iss != key.IssuerID || payload.Aud != "appstoreconnect-v1" {
		t.Fatalf("unexpected payload: %s", raw)
	}
	// Apple 的上限是 20 分钟；超过它回的是 401，读起来像"密钥无效"
	if payload.Exp-payload.Iat > 1200 || payload.Exp <= payload.Iat {
		t.Fatalf("token lifetime out of range: iat=%d exp=%d", payload.Iat, payload.Exp)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != 64 {
		t.Fatalf("ES256 signatures are 64 raw bytes (r||s), got %d — this looks like DER", len(signature))
	}
}

func TestParsePrivateKeyRejectsThingsThatAreNotAnASCKey(t *testing.T) {
	if _, err := ParsePrivateKey(testKey(t).PrivateKeyPEM); err != nil {
		t.Fatalf("a real P-256 PKCS#8 key must be accepted: %v", err)
	}
	for name, text := range map[string]string{
		"空的":        "",
		"不是 PEM":    "AuthKey_8WQNTAY7MP",
		"PEM 但不是密钥": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})),
	} {
		if _, err := ParsePrivateKey(text); err == nil {
			t.Fatalf("%s: expected a rejection", name)
		}
	}
}

// 私钥不能出现在日志、错误、格式化输出里。一次 %v 就够把这把钥匙交出去。
func TestKeyNeverPrintsThePrivateKey(t *testing.T) {
	key := testKey(t)
	// 这里就是要走 fmt 的各个动词，验的是"随手一个 %v/%s/%#v 也不会漏"，
	// 所以不能换成 key.String()——那会绕开被测的那条路径。
	//lint:ignore S1025 走的就是 fmt 动词这条路径，换成 String() 就不是这个测试了
	viaVerbS := fmt.Sprintf("%s", key)
	for _, rendered := range []string{
		fmt.Sprintf("%v", key), viaVerbS, fmt.Sprintf("%#v", key),
		key.LogValue().String(),
	} {
		if strings.Contains(rendered, "PRIVATE KEY") || strings.Contains(rendered, key.PrivateKeyPEM) {
			t.Fatalf("the private key leaked into %q", rendered)
		}
		if !strings.Contains(rendered, key.KeyID) {
			t.Fatalf("the summary should still name the key id: %q", rendered)
		}
	}
}

func fakeASC(t *testing.T, handler http.HandlerFunc) (Client, *[]*http.Request) {
	t.Helper()
	seen := &[]*http.Request{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Clone(context.Background()))
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return Client{Key: testKey(t), BaseURL: server.URL}, seen
}

func TestFindAppRequiresExactlyOneMatch(t *testing.T) {
	client, seen := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":[{"id":"6811004741","attributes":{"name":"AnyFun","bundleId":"com.anyfun.foundation","sku":"anyfun"}}]}`)
	})
	app, err := client.FindApp(context.Background(), "com.anyfun.foundation")
	if err != nil {
		t.Fatal(err)
	}
	if app.ID != "6811004741" || app.BundleID != "com.anyfun.foundation" || app.Name != "AnyFun" {
		t.Fatalf("unexpected app: %#v", app)
	}
	request := (*seen)[0]
	if got := request.URL.Query().Get("filter[bundleId]"); got != "com.anyfun.foundation" {
		t.Fatalf("the bundle id must be filtered server-side, got %q", got)
	}
	if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
		t.Fatalf("missing bearer token: %q", request.Header.Get("Authorization"))
	}

	// 命中 0 条 = 密钥属于别的团队，或 App 记录还没建。两种都不是"配好了"
	empty, _ := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	})
	if _, err := empty.FindApp(context.Background(), "com.anyfun.foundation"); !errors.Is(err, ErrAppNotFound) {
		t.Fatalf("expected ErrAppNotFound, got %v", err)
	}
	many, _ := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"1"},{"id":"2"}]}`)
	})
	if _, err := many.FindApp(context.Background(), "com.anyfun.foundation"); !errors.Is(err, ErrAppNotFound) {
		t.Fatalf("expected ErrAppNotFound for multiple matches, got %v", err)
	}
}

// 401/403 与"网络不通"必须分得开：处置完全不同（换钥匙 vs 查网络）
func TestRejectedKeyIsDistinguishable(t *testing.T) {
	client, _ := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"status":"401","title":"Authentication credentials are missing or invalid","detail":"NOT_AUTHORIZED"}]}`)
	})
	_, err := client.FindApp(context.Background(), "com.anyfun.foundation")
	if !errors.Is(err, ErrKeyRejected) {
		t.Fatalf("expected ErrKeyRejected, got %v", err)
	}
	if !strings.Contains(err.Error(), "NOT_AUTHORIZED") {
		t.Fatalf("Apple's own wording should survive: %v", err)
	}
}

func TestLatestBuildsAndBetaGroups(t *testing.T) {
	client, seen := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/builds":
			fmt.Fprint(w, `{"data":[{"id":"b1","attributes":{"version":"9","processingState":"VALID","expired":false,"expirationDate":"2026-12-16T08:00:00Z","uploadedDate":"2026-09-17T08:00:00Z"}}]}`)
		case "/v1/betaGroups":
			fmt.Fprint(w, `{"data":[{"id":"g1","attributes":{"name":"Public","isInternalGroup":false,"publicLinkEnabled":true,"publicLink":"https://testflight.apple.com/join/ABCD1234","publicLinkLimit":500}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	builds, err := client.LatestBuilds(context.Background(), "6811004741", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(builds) != 1 || builds[0].Version != "9" || builds[0].Expired {
		t.Fatalf("unexpected builds: %#v", builds)
	}
	// 90 天时钟的来源：过期日必须真的解出来，不能是零值
	if builds[0].ExpirationDate == nil || !builds[0].ExpirationDate.Equal(time.Date(2026, 12, 16, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("expiration date must be parsed: %#v", builds[0].ExpirationDate)
	}
	if got := (*seen)[0].URL.Query().Get("sort"); got != "-uploadedDate" {
		t.Fatalf("builds must come back newest first, got sort=%q", got)
	}
	groups, err := client.BetaGroups(context.Background(), "6811004741")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].IsInternal || !groups[0].PublicLinkEnabled ||
		groups[0].PublicLink != "https://testflight.apple.com/join/ABCD1234" {
		t.Fatalf("unexpected groups: %#v", groups)
	}
}

// 这个包只读。出现任何写方法都要在这里显式改一次——那不是一次顺手的重构
// （设计 §4.6.6：提审、开关公开链接、增删测试员永远由人点）。
func TestClientOnlyEverIssuesGET(t *testing.T) {
	client, seen := fakeASC(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":"1","attributes":{"bundleId":"com.anyfun.foundation"}}]}`)
	})
	ctx := context.Background()
	_, _ = client.FindApp(ctx, "com.anyfun.foundation")
	_, _ = client.LatestBuilds(ctx, "1", 5)
	_, _ = client.BetaGroups(ctx, "1")
	if len(*seen) != 3 {
		t.Fatalf("expected three requests, got %d", len(*seen))
	}
	for _, request := range *seen {
		if request.Method != http.MethodGet {
			t.Fatalf("%s %s: this client must never write to Apple", request.Method, request.URL.Path)
		}
	}
}

// http.Client.Timeout 连响应体一起算：设了它，一块几十 MB 的分块上传会被掐死在 20 秒上，
// 而 UploadPart 自己给的是 15 分钟。时限只能按请求给。
func TestDefaultHTTPClientHasNoOverallTimeout(t *testing.T) {
	if timeout := (Client{}).httpClient().Timeout; timeout != 0 {
		t.Fatalf("default client timeout = %s; it would cut off long part uploads", timeout)
	}
}
