package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 处理函数 panic 时，日志里要有能定位问题的东西（panic 值、路由、request id、堆栈），但不能有请求头：
// gin 自带的 Recovery 在 debug 模式下把整份请求头原样打进日志，只遮 Authorization，x-enrollment-code、
// x-machine-token、x-admin-key、Cookie 都会出现在日志里。走真实路由表（routes 挂的中间件），用 debug 模式
// ——最容易泄漏的那种——验证；gin 自己的错误输出与 slog 收进同一个缓冲区一起查。
func TestPanicRecoveryLogsNoRequestHeaders(t *testing.T) {
	var logs bytes.Buffer
	previousLogger, previousErrorWriter, previousWriter, previousMode := slog.Default(), gin.DefaultErrorWriter, gin.DefaultWriter, gin.Mode()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	gin.DefaultErrorWriter, gin.DefaultWriter = &logs, io.Discard
	gin.SetMode(gin.DebugMode)
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		gin.DefaultErrorWriter, gin.DefaultWriter = previousErrorWriter, previousWriter
		gin.SetMode(previousMode)
	})

	s := &server{}
	router := s.routes()
	router.GET("/v1/test/panic/:id", func(c *gin.Context) { panic("sentinel panic value") })

	sentinels := map[string]string{
		enrollmentCodeHeader: "rne_SENTINELenrollmentCODE0000000000000000000",
		machineTokenHeader:   "rnm_SENTINELmachineTOKEN",
		"x-admin-key":        "SENTINEL-admin-key",
		"Authorization":      "Bearer SENTINEL-bearer",
		"Cookie":             "rn_admin_session=SENTINEL-session",
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/test/panic/SENTINEL-path-value?token=SENTINEL-query", nil)
	for name, value := range sentinels {
		request.Header.Set(name, value)
	}
	request.Header.Set("x-request-id", "req_panic_sentinel_test")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	logged := logs.String()
	for _, want := range []string{"sentinel panic value", "/v1/test/panic/:id", "req_panic_sentinel_test", "panic_recovery_test.go"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("the panic log must contain %q:\n%s", want, logged)
		}
	}
	for name, value := range sentinels {
		if strings.Contains(logged, value) || strings.Contains(logged, strings.TrimPrefix(value, "Bearer ")) {
			t.Fatalf("the panic log leaks the %s header:\n%s", name, logged)
		}
	}
	for _, leaked := range []string{"SENTINEL-query", "SENTINEL-path-value"} {
		if strings.Contains(logged, leaked) {
			t.Fatalf("the panic log leaks the raw URL (%s):\n%s", leaked, logged)
		}
	}

	var body map[string]any
	if recorder.Code != http.StatusInternalServerError || json.Unmarshal(recorder.Body.Bytes(), &body) != nil ||
		body["code"] != "INTERNAL_SERVER_ERROR" || body["requestId"] != "req_panic_sentinel_test" ||
		!strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("a panicking handler must answer a 500 problem: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "sentinel panic value") || strings.Contains(recorder.Body.String(), "goroutine") {
		t.Fatalf("the response leaks the panic: %s", recorder.Body.String())
	}
}
