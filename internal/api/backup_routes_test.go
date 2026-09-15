package api

import (
	"net/http"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// gin 的路由树在同一层混用静态段和通配符（/backup-requests/claim 和
// /backup-requests/:id/payload）时，老版本会直接 panic。
//
// 这条测试让那种 panic 在 CI 里出现，而不是在启动线上服务时出现——后者的表现是
// 整个后端起不来，而且报错离改动很远。
func TestRouterBuildsWithTheBackupRoutes(t *testing.T) {
	db := openTestDB(t)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("注册备份路由让 gin 的路由树炸了: %v", r)
		}
	}()
	handler := New(config.Config{
		Environment: "test", Port: "0", MySQLQueryTimeout: 10,
		AdminSessionTTL: 3600, AdminLoginMax: 5, AdminLoginWindow: 900,
	}, &store.Store{DB: db})
	if handler == nil {
		t.Fatal("New 返回了 nil")
	}
	var _ http.Handler = handler
}
