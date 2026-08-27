package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCorsAllowsReleaseArtifactTokenHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	s := &server{}
	s.cfg.CORSOrigins = []string{"https://console.anyfun.win"}
	r.Use(s.cors())
	r.OPTIONS("/v1/admin/release-artifacts/upload", func(c *gin.Context) {})

	req := httptest.NewRequest(http.MethodOptions, "/v1/admin/release-artifacts/upload", strings.NewReader(""))
	req.Header.Set("Origin", "https://console.anyfun.win")
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-release-artifact-token")
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.Code, http.StatusNoContent)
	}
	if got := resp.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "x-release-artifact-token") {
		t.Fatalf("Access-Control-Allow-Headers = %q, missing artifact token header", got)
	}
}
