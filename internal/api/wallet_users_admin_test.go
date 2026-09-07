package api

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 三档活跃度（设计 §3）：没有有效会话=未登录；有会话且设备 7 天内有心跳=当前活跃；
// 有会话但心跳过期=会话有效·设备不活跃（已卸载的设备不能算活跃）
func TestInstallationActivityThreeLevels(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	current := &currentSession{ID: "wses_a", UserID: 1, Address: "0xabc", LastSeenAt: now}
	if got := installationActivity(nil, now, now); got != "signed_out" {
		t.Fatalf("no session must be signed_out, got %s", got)
	}
	if got := installationActivity(current, now.Add(-6*24*time.Hour), now); got != "active" {
		t.Fatalf("recent heartbeat must be active, got %s", got)
	}
	if got := installationActivity(current, now.Add(-8*24*time.Hour), now); got != "session_active_device_idle" {
		t.Fatalf("stale heartbeat must be session_active_device_idle, got %s", got)
	}
}

// 登录态对账只标差异，不判定：客户端说已登录但服务端没有会话 / 客户端说未登录但服务端有会话
func TestSessionMismatchOnlyFlagsDisagreement(t *testing.T) {
	current := &currentSession{ID: "wses_a"}
	signedIn := sql.NullString{String: "signed_in", Valid: true}
	signedOut := sql.NullString{String: "signed_out", Valid: true}
	if got := sessionMismatch(sql.NullString{}, current); got != "" {
		t.Fatalf("unreported client state must not flag: %q", got)
	}
	if got := sessionMismatch(signedIn, current); got != "" {
		t.Fatalf("agreement must not flag: %q", got)
	}
	if got := sessionMismatch(signedIn, nil); got != "client_signed_in_only" {
		t.Fatalf("expected client_signed_in_only, got %q", got)
	}
	if got := sessionMismatch(signedOut, current); got != "server_session_only" {
		t.Fatalf("expected server_session_only, got %q", got)
	}
}

func TestParseWalletUserListFilter(t *testing.T) {
	now := time.Now().UTC()
	for _, query := range []string{"q=abc", "status=banned", "activeWithin=2d", "limit=0", "cursor=!!"} {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		context.Request = httptest.NewRequest(http.MethodGet, "/v1/admin/wallet/users?"+query, nil)
		if _, invalid := parseWalletUserListFilter(context, now); invalid == "" {
			t.Fatalf("query %q must be rejected", query)
		}
	}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/v1/admin/wallet/users?q=0x98&status=active&activeWithin=30d&limit=10", nil)
	filter, invalid := parseWalletUserListFilter(context, now)
	if invalid != "" {
		t.Fatalf("valid query rejected: %s", invalid)
	}
	where, args := filter.where("100000001")
	for _, fragment := range []string{"u.tenant_id=?", "u.address_key LIKE ?", "u.status=?", "u.last_login_at>=?"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("where clause missing %s: %s", fragment, where)
		}
	}
	if len(args) != 4 || args[1] != "0x98%" {
		t.Fatalf("unexpected args %v", args)
	}
}

// 登录替代旧会话与结束会话的 SQL 只动同租户、同安装实例、仍有效的行
func TestSessionLifecycleSQLScopes(t *testing.T) {
	for _, fragment := range []string{"ended_reason='superseded'", "tenant_id=?", "installation_id=?", "id<>?", "revoked_at IS NULL"} {
		if !strings.Contains(supersedeSessionsSQL, fragment) {
			t.Fatalf("supersede SQL missing %s", fragment)
		}
	}
	if !strings.HasSuffix(endSessionsSQL, "revoked_at IS NULL AND ") {
		t.Fatalf("end sessions SQL must only touch live sessions: %s", endSessionsSQL)
	}
	if !strings.Contains(walletUserInstallationUpsertSQL, "login_count=login_count+1") {
		t.Fatal("login history upsert must increment login_count")
	}
}
