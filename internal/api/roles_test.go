package api

import (
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 每个角色只注册自己的路由；拆开之后一条都不少（设计 service-and-console-split-2026-09-27 §3.2）。
func TestRoleRoutes(t *testing.T) {
	s := &server{cfg: config.Config{Environment: "test", MySQLQueryTimeout: 10}}
	routes := func(role Role) map[string]bool {
		set := map[string]bool{}
		for _, route := range s.routesFor(role).Routes() {
			set[route.Method+" "+route.Path] = true
		}
		return set
	}
	app, tenant, platform, all := routes(RoleApp), routes(RoleTenant), routes(RolePlatform), routes(RoleAll)
	hasPrefix := func(set map[string]bool, prefix string) bool {
		for route := range set {
			if strings.HasPrefix(strings.SplitN(route, " ", 2)[1], prefix) {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name     string
		set      map[string]bool
		must     []string
		mustNot  []string
		prefixes []string
	}{
		{"app", app,
			[]string{"GET /v1/mobile/bootstrap", "GET /v1/ota/manifest", "GET /app/download", "GET /.well-known/assetlinks.json", "GET /v1/public/releases/latest", "GET /health/ready"},
			nil, []string{"/v1/admin", "/client/", "/v1/build-agent", "/v1/signer", "/v1/machine-setup"}},
		{"tenant", tenant,
			[]string{"GET /v1/admin/tenant", "GET /v1/admin/releases", "GET /v1/admin/auth/session", "GET /client/v1/oauth/login", "GET /v1/admin/auth/cid/start", "GET /health/ready"},
			nil, []string{"/v1/admin/platform", "/v1/mobile", "/v1/public", "/v1/ota", "/app/", "/v1/build-agent", "/v1/signer", "/v1/machine-setup"}},
		{"platform", platform,
			[]string{"GET /v1/admin/platform/machines", "POST /v1/build-agent/claim", "POST /v1/signer/claim", "POST /v1/machine-setup/enroll", "GET /v1/admin/auth/session", "GET /health/ready"},
			[]string{"GET /v1/admin/tenant", "GET /v1/admin/releases"}, []string{"/v1/mobile", "/v1/public", "/v1/ota", "/app/"}},
	} {
		for _, route := range tc.must {
			if !tc.set[route] {
				t.Errorf("%s must serve %s", tc.name, route)
			}
		}
		for _, route := range tc.mustNot {
			if tc.set[route] {
				t.Errorf("%s must not serve %s", tc.name, route)
			}
		}
		for _, prefix := range tc.prefixes {
			if hasPrefix(tc.set, prefix) {
				t.Errorf("%s must not serve anything under %s", tc.name, prefix)
			}
		}
	}
	// nginx 按路径前缀分流（deploy/amos/nginx-snippet-api.inc、nginx-snippet-console.inc）：只在平台端的路由
	// 必须落在转给平台端的前缀下，租户端的路由必须落在控制台转给租户端的路径下，否则上线后访问不到
	for route := range platform {
		path := strings.SplitN(route, " ", 2)[1]
		if tenant[route] || strings.HasPrefix(path, "/health/") {
			continue
		}
		if !strings.HasPrefix(path, "/v1/admin/platform/") && !strings.HasPrefix(path, "/v1/build-agent/") &&
			!strings.HasPrefix(path, "/v1/signer/") && !strings.HasPrefix(path, "/v1/machine-setup/") {
			t.Errorf("platform route %s is outside the paths nginx sends to the platform service", route)
		}
	}
	for route := range tenant {
		path := strings.SplitN(route, " ", 2)[1]
		if !strings.HasPrefix(path, "/v1/") && path != cidCallbackPath && !strings.HasPrefix(path, "/health/") {
			t.Errorf("tenant route %s is outside the paths the console sends to the tenant service", route)
		}
	}
	for route := range all {
		if !app[route] && !tenant[route] && !platform[route] {
			t.Errorf("%s is served by no role", route)
		}
	}
	for _, set := range []map[string]bool{app, tenant, platform} {
		for route := range set {
			if !all[route] {
				t.Errorf("%s is served by a role but not by the all-in-one process", route)
			}
		}
	}
}
