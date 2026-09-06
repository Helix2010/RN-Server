package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/scan"
)

func TestRequirePlatformAdminGatesByConfiguredUsernames(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(usernames []string, actorName string) int {
		s := &server{cfg: config.Config{PlatformAdminUsernames: usernames}}
		router := gin.New()
		router.Use(func(c *gin.Context) { c.Set("actorId", actorName) })
		router.GET("/platform", s.requirePlatformAdmin(), func(c *gin.Context) { c.Status(200) })
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/platform", nil))
		return recorder.Code
	}
	if code := run(nil, "admin"); code != 403 {
		t.Fatalf("empty list must reject: %d", code)
	}
	if code := run([]string{"ops"}, "admin"); code != 403 {
		t.Fatalf("unlisted account must reject: %d", code)
	}
	if code := run([]string{"ops", "admin"}, "admin"); code != 200 {
		t.Fatalf("listed account must pass: %d", code)
	}
}

func TestResolveEndpointsKeepsStoredURLByHash(t *testing.T) {
	current := []scan.Endpoint{{URL: "https://rpc.example/v1/secret-key-0123456789", Label: "primary", RPS: 5}}
	resolved, err := resolveEndpoints([]scanEndpointInput{
		{URLHash: urlHash(current[0].URL), Label: "primary renamed", RPS: 8},
		{URL: "https://backup.example", Label: "backup", RPS: 2},
	}, current)
	if err != nil {
		t.Fatal(err)
	}
	if resolved[0].URL != current[0].URL || resolved[0].Label != "primary renamed" || resolved[0].RPS != 8 || resolved[1].URL != "https://backup.example" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if _, err := resolveEndpoints([]scanEndpointInput{{URLHash: "deadbeef", Label: "x", RPS: 1}}, current); err == nil {
		t.Fatal("unknown hash without url must fail")
	}
}

func TestScanConfigViewMasksSecrets(t *testing.T) {
	view := scanConfigViewOf(scan.ChainConfig{Chain: "monad", Endpoints: []scan.Endpoint{{URL: "https://rpc.example/v1/0123456789abcdef0123", Label: "p", RPS: 3}}, NativeMode: scan.NativeModeBalance, Version: 4})
	if view.Endpoints[0].URLMasked != "https://rpc.example/v1/…" || !view.Endpoints[0].HasSecret || view.Endpoints[0].URLHash == "" || view.Version != 4 {
		t.Fatalf("view = %+v", view.Endpoints[0])
	}
}
