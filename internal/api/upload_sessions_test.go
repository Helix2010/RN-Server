package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestUploadSessionPartsRequireExactETagAndSize(t *testing.T) {
	s := &server{}
	parts := []uploadPartState{{PartNumber: 1, ETag: `"etag-1"`, Size: 16}, {PartNumber: 2, ETag: `"etag-2"`, Size: 8}}
	if !s.partMatches(parts, uploadPartState{PartNumber: 1, ETag: `"etag-1"`, Size: 16}) {
		t.Fatal("expected matching part to be accepted")
	}
	if s.partMatches(parts, uploadPartState{PartNumber: 1, ETag: `"other"`, Size: 16}) || s.partMatches(parts, uploadPartState{PartNumber: 1, ETag: `"etag-1"`, Size: 15}) {
		t.Fatal("expected mismatched ETag or size to be rejected")
	}
}

func TestUploadSessionJSONIncludesUploadedParts(t *testing.T) {
	s := &server{}
	now := time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC)
	view := s.uploadSessionJSON(uploadSessionView{ID: "upl_1", UploadType: "apk", FileName: "app.apk", ContentType: "application/vnd.android.package-archive", ExpectedSize: 24, PartSize: 16, TotalParts: 2, Status: "active", ExpiresAt: now, Parts: []uploadPartState{{PartNumber: 1, ETag: "etag", Size: 16}}})
	if view["totalParts"] != 2 || view["status"] != "active" {
		t.Fatalf("unexpected session view: %#v", view)
	}
	if len(view["uploadedParts"].([]uploadPartState)) != 1 {
		t.Fatal("uploadedParts should expose resumable progress")
	}
}

func TestDatabaseTimeoutDoesNotCancelUploadSessionStorageOperations(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{}
	s.cfg.MySQLQueryTimeout = 1
	tests := []struct {
		method string
		path   string
	}{{http.MethodPut, "/v1/admin/upload-sessions/upl_1/parts/1"}}
	for _, item := range tests {
		t.Run(item.method+" "+item.path, func(t *testing.T) {
			router := gin.New()
			router.Use(s.databaseTimeout())
			router.Handle(item.method, item.path, func(c *gin.Context) {
				_, hasDeadline := c.Request.Context().Deadline()
				c.JSON(http.StatusOK, gin.H{"hasDeadline": hasDeadline})
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(item.method, item.path, nil))
			if response.Body.String() != "{\"hasDeadline\":false}" {
				t.Fatalf("unexpected database timeout behavior: %s", response.Body.String())
			}
		})
	}
}
