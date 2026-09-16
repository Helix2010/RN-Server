package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/Helix2010/RN-Server/signing/trustroots"
	"github.com/gin-gonic/gin"
)

// App Links host 按 RN-App app.config.ts 的规则派生：new URL(apiBaseUrl).host。
// WHATWG URL 去掉 https 的默认端口 443，保留别的端口；显式写了 :443 的由 trustroots 直接拒绝。
func TestAppLinksHostsFollowTheRNAppRule(t *testing.T) {
	for apiBaseURL, want := range map[string]string{
		"https://api.anyfun.win":       "api.anyfun.win",
		"https://api.example.com:8443": "api.example.com:8443",
		"https://a.b.example.org":      "a.b.example.org",
	} {
		hosts, problem := appLinksHostsFor(apiBaseURL)
		if problem != "" || len(hosts) != 1 || hosts[0] != want {
			t.Fatalf("%s: hosts=%v problem=%q, want %s", apiBaseURL, hosts, problem, want)
		}
	}
	for _, apiBaseURL := range []string{"https://api.example.com:443", "http://api.example.com", "https://API.example.com", "https://api.example.com/", "https://localhost"} {
		if hosts, problem := appLinksHostsFor(apiBaseURL); problem == "" {
			t.Fatalf("%s should not yield App Links hosts, got %v", apiBaseURL, hosts)
		}
	}
}

// 不就绪原因的枚举控制台是照 OpenAPI 做的：服务端的全集与契约里的 enum 必须一模一样。
func TestReadinessProblemCodesMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Code struct {
				Enum []string `json:"enum"`
			} `json:"code"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(contract.Components.Schemas["SignerReadinessProblem"], &schema); err != nil {
		t.Fatal(err)
	}
	enum := schema.Properties.Code.Enum
	if strings.Join(enum, ",") != strings.Join(readinessProblemCodes, ",") {
		t.Fatalf("OpenAPI SignerReadinessProblem.code enum %v differs from the server %v", enum, readinessProblemCodes)
	}
}

// 保存打包配置时就按签名闸的同一个函数校验 apiBaseUrl：显式默认端口 :443、大写域名、IP、带路径的
// 一律当场拒绝，而不是存进去之后在就绪判断里才说不行。首尾空白与结尾的 / 去掉后再判。
func TestAPIBaseURLIsValidatedWithTheSignerRuleOnWrite(t *testing.T) {
	for _, ok := range []string{"https://api.anyfun.win", "https://api.example.com:8443", " https://api.example.com/ "} {
		if err := validateAPIBaseURL(ok); err != nil {
			t.Fatalf("%q was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "https://api.example.com:443", "https://API.example.com", "http://api.example.com",
		"https://api.example.com/v1", "https://10.0.0.1", "https://localhost", "https://api.example.com?x=1"} {
		if err := validateAPIBaseURL(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
	if got := canonicalAPIBaseURL(" https://api.example.com/ "); got != "https://api.example.com" {
		t.Fatalf("canonical form: %q", got)
	}
}

// 服务端算信任根摘要用的是合成的 tenant.json 与当前 OTA 证书，与签名闸拿同样的值调
// trustroots.Digest 得到的结果一致。
func TestDBTrustRootsComeFromTheComposedManifest(t *testing.T) {
	f := newGateFixture(t, 91)
	roots, digest, problems, err := f.s.trustRootsFor(context.Background(), f.tenant)
	if err != nil || len(problems) != 0 || roots == nil {
		t.Fatalf("trust roots: %v %v", err, problems)
	}
	record, _ := f.s.otaSigningRecord(context.Background(), f.tenant)
	certificate, _ := certificateFingerprint(record.Value.Certificate)
	independent, err := trustroots.Digest(trustroots.Roots{
		APIBaseURL: "https://api.seeded.example", OTACertificateSHA256: certificate,
		BootstrapSignerAddress: "0x9269ca361b9f0427ac883e89cd5b5fe113bbad17", AppLinksHosts: []string{"api.seeded.example"},
		Scheme: "seeded", DistributionChannel: tenantDistributionChannel, ApplicationID: tenantApplicationID,
	})
	if err != nil || digest != independent {
		t.Fatalf("server digest %s, independent digest %s (%v)", digest, independent, err)
	}
	if roots.BootstrapSignerAddress != "0x9269ca361b9f0427ac883e89cd5b5fe113bbad17" || roots.AppLinksHosts[0] != "api.seeded.example" {
		t.Fatalf("normalized roots: %+v", roots)
	}
}

// 旧指纹永久拒绝，四处：登记发布身份、登记签名密钥（见 build_keystore_test）、
// 上传门禁、签名闸完成（见 signer_test）。
func TestRetiredSignersAreRefusedAtTheUploadGate(t *testing.T) {
	for digest := range retiredAndroidSigners {
		apk := apkinspect.Metadata{PackageName: "com.anyfun.wallet", SignerSHA256: strings.ToUpper(digest)}
		pin := &androidReleaseIdentity{PackageName: "com.anyfun.wallet", SignerSHA256: digest}
		if code, _ := checkAndroidReleaseIdentity(apk, pin, true); code != "RELEASE_SIGNER_RETIRED" {
			t.Fatalf("an APK signed with the retired key %s passed the upload gate: %q", digest, code)
		}
		if code, _ := androidSignerRetirement(colonize(digest)); code != "RELEASE_SIGNER_RETIRED" {
			t.Fatalf("the colon form of %s is not recognised as retired", digest)
		}
	}
	if code, _ := androidSignerRetirement(strings.Repeat("a", 64)); code != "" {
		t.Fatal("an ordinary fingerprint was treated as retired")
	}
}

func colonize(digest string) string {
	parts := []string{}
	for i := 0; i < len(digest); i += 2 {
		parts = append(parts, strings.ToUpper(digest[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func TestDBRetiredSignersCannotBeRegisteredAsTheReleaseIdentity(t *testing.T) {
	f := newGateFixture(t, 92)
	_, identityVersion := f.keystoreVersions()
	for digest := range retiredAndroidSigners {
		c, recorder := testContext(t, f.tenant, http.MethodPut, "/v1/admin/release-identity/android", map[string]any{
			"packageName": f.packageName, "signerSha256": digest, "expectedVersion": identityVersion, "reason": "roll back to the old key", "confirm": true,
		})
		f.s.updateAndroidReleaseIdentity(c)
		if recorder.Code != http.StatusUnprocessableEntity || problemCode(t, recorder) != "RELEASE_SIGNER_RETIRED" {
			t.Fatalf("registering the retired key %s: %d %s", digest, recorder.Code, recorder.Body.String())
		}
	}
}

// 管理端直接上传热更新包的接口已经删除：热更新只能来自 kind=ota 的构建任务。
// upload-sessions 的 uploadType=ota 一并收掉。
func TestOTAAdminUploadRoutesAreGone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := New(config.Config{Environment: "test", AdminAPIKey: "k-secret", AdminAPIActor: "release-bot"}, &store.Store{})
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v1/admin/ota/artifacts/uploads"},
		{http.MethodPut, "/v1/admin/ota/artifacts/upload"},
		{http.MethodDelete, "/v1/admin/ota/artifacts/upload"},
		{http.MethodPost, "/v1/admin/ota/releases"},
		{http.MethodPost, "/v1/admin/build-keystore/generate"},
		{http.MethodGet, "/v1/admin/platform/build-agent/public-key"},
		{http.MethodPost, "/v1/admin/platform/build-agent/public-key/accept"},
		{http.MethodGet, "/v1/build-agent/keystore-checks"},
		{http.MethodPost, "/v1/build-agent/keystore-checks"},
	} {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
		request.Header.Set("x-admin-key", "k-secret")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s still answers: %d", route.method, route.path, recorder.Code)
		}
	}

	s := &server{cfg: config.Config{ArtifactMaxSizeBytes: 1 << 30}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/admin/upload-sessions", strings.NewReader(`{"uploadType":"ota","fileName":"update.zip","contentType":"application/zip","size":10485760}`))
	c.Request.Header.Set("content-type", "application/json")
	c.Set("requestId", "req_test")
	// db 与存储都是 nil：走到它们就 panic，证明拒绝发生在校验阶段
	s.createUploadSession(c)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an OTA upload session was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 数据库超时豁免按路由模板精确匹配：热更新包代理上传与签名闸完成不挂 10 秒超时，
// 同前缀的别的接口照挂；把路径参数写成 /upload 也骗不过去。
func TestDatabaseTimeoutExemptsExactlyTwoLongRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{MySQLQueryTimeout: 10}}
	router := gin.New()
	router.Use(s.databaseTimeout())
	deadline := func(c *gin.Context) {
		if _, has := c.Request.Context().Deadline(); has {
			c.String(http.StatusOK, "deadline")
			return
		}
		c.String(http.StatusOK, "none")
	}
	router.PUT("/v1/build-agent/jobs/:id/ota-artifact", deadline)
	router.POST("/v1/build-agent/jobs/:id/ota-release", deadline)
	router.POST("/v1/signer/jobs/:id/complete", deadline)
	router.POST("/v1/signer/jobs/:id/heartbeat", deadline)
	router.PUT("/v1/signer/jobs/:id/signed/upload", deadline)
	router.GET("/v1/signer/jobs/:id/unsigned/download", deadline)
	router.POST("/v1/build-agent/jobs/:id/complete", deadline)
	for _, tc := range []struct {
		method, path, want string
	}{
		{http.MethodPut, "/v1/build-agent/jobs/bld_1/ota-artifact", "none"},
		{http.MethodPost, "/v1/signer/jobs/bld_1/complete", "none"},
		{http.MethodPut, "/v1/signer/jobs/bld_1/signed/upload", "none"},
		{http.MethodGet, "/v1/signer/jobs/bld_1/unsigned/download", "none"},
		{http.MethodPost, "/v1/build-agent/jobs/bld_1/ota-release", "deadline"},
		{http.MethodPost, "/v1/signer/jobs/bld_1/heartbeat", "deadline"},
		{http.MethodPost, "/v1/build-agent/jobs/bld_1/complete", "deadline"},
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		if recorder.Body.String() != tc.want {
			t.Fatalf("%s %s: %s, want %s", tc.method, tc.path, recorder.Body.String(), tc.want)
		}
	}
}
