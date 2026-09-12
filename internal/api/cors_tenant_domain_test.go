package api

import (
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 加租户不该需要改配置文件再重启。这几条守住"从域名表推导"这条路的边界。
func TestOriginAllowedFallsBackToTenantDomains(t *testing.T) {
	// resolver 为 nil（比如单元测试里裸建的 server）时不能 panic，只能是不放行
	s := &server{cfg: config.Config{CORSOrigins: []string{"https://console.anyfun.win"}}}
	if !s.originAllowed("https://console.anyfun.win") {
		t.Fatal("配置里写死的来源被拒了")
	}
	if s.originAllowed("https://evil.example") {
		t.Fatal("没有 resolver 时不该放行任何未配置来源")
	}
}

// Origin 头的形状不对就不要去猜。带路径、带查询、非 https 的一律不查库——
// 这条通道会带 Access-Control-Allow-Credentials，放宽一点就是把会话交出去
func TestOriginIsTenantDomainRejectsMalformedOrigins(t *testing.T) {
	s := &server{}
	for name, origin := range map[string]string{
		"明文":      "http://console.anyfun.win",
		"带路径":     "https://console.anyfun.win/admin",
		"带查询":     "https://console.anyfun.win?x=1",
		"空":       "",
		"不是 URL":  "://",
		"没有主机":    "https://",
		"null 来源": "null",
	} {
		if s.originIsTenantDomain(origin) {
			t.Fatalf("%s 被放行了: %q", name, origin)
		}
	}
}

// 配置里的通配符仍然生效（开发环境用），但生产环境 config 那层会拒绝纯 "*"
func TestOriginAllowedStillHonoursWildcard(t *testing.T) {
	s := &server{cfg: config.Config{CORSOrigins: []string{"*"}}}
	if !s.originAllowed("https://anything.example") {
		t.Fatal("通配符没生效")
	}
}
