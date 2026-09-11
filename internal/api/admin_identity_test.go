package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// x-admin-key 这条自动化通道的审计身份必须来自配置，不能来自请求自报的 x-admin-id
// （安全评审 N17）：持钥者能把 actor 写成任何人，audit_events 里的追责链就没了依据。
// 走真实路由，不碰数据库——没有 cookie 时 authenticate() 不查库，session 处理函数也不查。
func TestAdminAPIKeyIdentityComesFromConfig(t *testing.T) {
	router := New(config.Config{Environment: "test", AdminAPIKey: "k-secret", AdminAPIActor: "release-bot"}, &store.Store{})

	call := func(headers map[string]string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/auth/session", nil)
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder
	}
	identity := func(t *testing.T, recorder *httptest.ResponseRecorder) (string, string) {
		t.Helper()
		var body struct {
			ActorID string `json:"actorId"`
			Method  string `json:"method"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode session response: %v (%s)", err, recorder.Body.String())
		}
		return body.ActorID, body.Method
	}

	t.Run("自报身份被忽略", func(t *testing.T) {
		recorder := call(map[string]string{"x-admin-key": "k-secret", "x-admin-id": "ceo@example.com"})
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
		}
		actorID, method := identity(t, recorder)
		if actorID != "release-bot" || method != "api-key" {
			t.Fatalf("self-declared identity leaked into the audit actor: %q (%s)", actorID, method)
		}
	})

	t.Run("不带自报身份也能通过", func(t *testing.T) {
		recorder := call(map[string]string{"x-admin-key": "k-secret"})
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
		}
		if actorID, _ := identity(t, recorder); actorID != "release-bot" {
			t.Fatalf("unexpected actor: %q", actorID)
		}
	})

	t.Run("错误的 key 仍然 401", func(t *testing.T) {
		recorder := call(map[string]string{"x-admin-key": "k-wrong", "x-admin-id": "release-bot"})
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
		}
	})
}

// 没有配置 ADMIN_API_KEY 时这条通道整体关闭：空 key 不能被空请求头配上。
func TestAdminAPIKeyDisabledWhenUnset(t *testing.T) {
	router := New(config.Config{Environment: "test", AdminAPIActor: "release-bot"}, &store.Store{})
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/auth/session", nil)
	request.Header.Set("x-admin-key", "")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
