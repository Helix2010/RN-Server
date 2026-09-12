package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func filterFor(t *testing.T, query string) installationListFilter {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/v1/admin/installations?"+query, nil)
	f, invalid := parseInstallationListFilter(c, time.Now().UTC())
	if invalid != "" {
		t.Fatalf("unexpected rejection: %s", invalid)
	}
	return f
}

// 没有锁屏的设备照常能用钱包，但必须能被数出来（安全评审 N10）
func TestScreenLockFilterFindsDevicesWithoutALockScreen(t *testing.T) {
	where, args := filterFor(t, "integrity.screenLock=no").where("100000001")

	if !strings.Contains(where, "JSON_EXTRACT(i.device_integrity,?)=FALSE") {
		t.Fatalf("expected a JSON predicate, got %s", where)
	}
	if !containsArg(args, "$.screenLock") {
		t.Fatalf("expected the screenLock path in args, got %v", args)
	}
}

func TestIntegrityFilterSeparatesUnreportedFromFalse(t *testing.T) {
	where, _ := filterFor(t, "integrity.rooted=unknown").where("100000001")

	// "没报过"和"报了 false"是两件事：老版本 App 不报，折成 false 会让统计变成假的
	if !strings.Contains(where, "IS NULL") {
		t.Fatalf("unknown must match unreported rows, got %s", where)
	}
	if strings.Contains(where, "=FALSE") {
		t.Fatalf("unknown must not be treated as false, got %s", where)
	}
}

func TestIntegrityFilterAcceptsSeveralSignalsAtOnce(t *testing.T) {
	where, args := filterFor(t, "integrity.rooted=yes&integrity.emulator=no").where("100000001")

	if strings.Count(where, "JSON_EXTRACT") != 2 {
		t.Fatalf("expected both signals in the predicate, got %s", where)
	}
	if !containsArg(args, "$.rooted") || !containsArg(args, "$.emulator") {
		t.Fatalf("expected both paths, got %v", args)
	}
}

// 字段名会拼进 JSON 路径，所以只能来自白名单
func TestIntegrityFilterIgnoresUnknownSignalNames(t *testing.T) {
	where, _ := filterFor(t, "integrity.$.injected=yes&integrity.nonsense=no").where("100000001")

	if strings.Contains(where, "JSON_EXTRACT") {
		t.Fatalf("only whitelisted signals may reach the query, got %s", where)
	}
}

func TestIntegrityFilterRejectsAnUnknownValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/v1/admin/installations?integrity.rooted=maybe", nil)

	if _, invalid := parseInstallationListFilter(c, time.Now().UTC()); invalid == "" {
		t.Fatal("expected a 422-worthy rejection")
	}
}

func containsArg(args []any, want string) bool {
	for _, a := range args {
		if s, ok := a.(string); ok && s == want {
			return true
		}
	}
	return false
}
