package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func buildListContext(rawQuery string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/v1/admin/builds?"+rawQuery, nil)
	return c
}

func TestParseBuildJobListFilter(t *testing.T) {
	filter, invalid := parseBuildJobListFilter(buildListContext("kind=ota&platform=android&status=failed&version=1.3.15&q=bld_&limit=25"))
	if invalid != "" {
		t.Fatalf("valid filter rejected: %s", invalid)
	}
	if filter.kind != "ota" || filter.platform != "android" || filter.status != "failed" || filter.limit != 25 || filter.version != "1.3.15" || filter.query != "bld_" {
		t.Fatalf("unexpected filter: %+v", filter)
	}
	for _, query := range []string{"kind=zip", "platform=web", "status=unknown", "limit=0", "limit=101", "cursor=!!"} {
		if _, invalid := parseBuildJobListFilter(buildListContext(query)); invalid == "" {
			t.Fatalf("invalid query %q was accepted", query)
		}
	}
}

func TestBuildCursorRoundTripPreservesNanoseconds(t *testing.T) {
	at := time.Date(2026, 9, 14, 1, 2, 3, 456789000, time.UTC)
	cursor := encodeBuildCursor(at, "bld_test")
	decodedAt, id, err := decodeBuildCursor(cursor)
	if err != nil || id != "bld_test" || !decodedAt.Equal(at) {
		t.Fatalf("cursor round trip failed: %s %q %v", decodedAt, id, err)
	}
}
