package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// 服务端（S2）实际返回的错误码：哪些是"等会儿再来"，哪些是明确拒绝
func TestServerErrorCodesAreClassified(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		retry  bool
	}{
		{http.StatusConflict, "BUILDER_CLAIM_IN_PROGRESS", true},
		{http.StatusBadRequest, "UPLOAD_INTERRUPTED", true},
		{http.StatusFailedDependency, "UPLOAD_STORAGE_FAILED", true},
		{http.StatusConflict, "MACHINES_VERSION_CONFLICT", true},
		{http.StatusBadGateway, "", true},
		{http.StatusTooManyRequests, "", true},
		{http.StatusUnsupportedMediaType, "UPLOAD_CONTENT_TYPE_INVALID", false},
		{http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE", false},
		{http.StatusBadRequest, "UPLOAD_EMPTY", false},
		{http.StatusBadRequest, "INVALID_BUILD_ATTEMPT", false},
		{http.StatusUnprocessableEntity, "BUILD_SBOM_INVALID", false},
		{http.StatusUnprocessableEntity, "BUILD_PROVENANCE_INVALID", false},
		{http.StatusConflict, "BUILD_KIND_MISMATCH", false},
		{http.StatusConflict, "BUILD_ATTEMPT_STALE", false},
		{http.StatusForbidden, "MACHINE_KEY_NOT_ACCEPTED", false},
	} {
		payload, _ := json.Marshal(map[string]any{"status": tc.status, "code": tc.code, "detail": "d"})
		err := newAPIError("/x", tc.status, payload)
		if worthRetrying(err) != tc.retry {
			t.Errorf("%d %s: retry=%t, want %t", tc.status, tc.code, worthRetrying(err), tc.retry)
		}
		if errorCode(err) != tc.code {
			t.Errorf("%d %s: code read as %q", tc.status, tc.code, errorCode(err))
		}
	}
	stale := newAPIError("/x", http.StatusConflict, []byte(`{"code":"BUILD_ATTEMPT_STALE"}`))
	if !isStale(errors.Join(errors.New("wrapped"), stale)) {
		t.Fatal("a wrapped BUILD_ATTEMPT_STALE is not recognised")
	}
}

// 上传遇到对象存储失败、请求体被截断：重传，最后照常交付
func TestTransientUploadErrorsAreRetried(t *testing.T) {
	rig := newRig(t)
	rig.server.failOnce("/unsigned/upload", http.StatusFailedDependency, "UPLOAD_STORAGE_FAILED")
	rig.server.failOnce("/unsigned/upload", http.StatusBadRequest, "UPLOAD_INTERRUPTED")
	rig.server.failOnce("/sbom/upload", http.StatusFailedDependency, "UPLOAD_STORAGE_FAILED")
	rig.server.queueClaim(claimBody("bld_retryUPLOAD1", "apk"))
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("a transient upload error failed the job: %s", fails[0].Body)
	}
	if n := len(rig.server.callsTo("/unsigned/upload")); n != 3 {
		t.Fatalf("unsigned upload attempts = %d, want 3", n)
	}
	if n := len(rig.server.callsTo("/sbom/upload")); n != 2 {
		t.Fatalf("SBOM upload attempts = %d, want 2", n)
	}
	if len(rig.server.callsTo("/built")) != 1 {
		t.Fatal("not delivered after the retries")
	}
}

// 明确拒绝：不重试，带原因（含错误码）报失败，不交付
func TestUploadAndDeliveryRejectionsFailTheJobWithoutRetrying(t *testing.T) {
	for _, tc := range []struct {
		suffix string
		status int
		code   string
	}{
		{"/unsigned/upload", http.StatusUnsupportedMediaType, "UPLOAD_CONTENT_TYPE_INVALID"},
		{"/unsigned/upload", http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE"},
		{"/unsigned/upload", http.StatusBadRequest, "UPLOAD_EMPTY"},
		{"/unsigned/upload", http.StatusBadRequest, "INVALID_BUILD_ATTEMPT"},
		{"/sbom/upload", http.StatusUnprocessableEntity, "BUILD_SBOM_INVALID"},
		{"/sbom/upload", http.StatusConflict, "BUILD_KIND_MISMATCH"},
		{"/built", http.StatusUnprocessableEntity, "BUILD_PROVENANCE_INVALID"},
	} {
		t.Run(tc.code+tc.suffix, func(t *testing.T) {
			rig := newRig(t)
			rig.server.failOnce(tc.suffix, tc.status, tc.code)
			rig.server.queueClaim(claimBody("bld_rejectJOB001", "apk"))
			if !rig.agent.pollOnce(context.Background()) {
				t.Fatal("no job")
			}
			if n := len(rig.server.callsTo(tc.suffix)); n != 1 {
				t.Fatalf("%s was called %d times; a rejection must not be retried", tc.suffix, n)
			}
			fails := rig.server.callsTo("/fail")
			if len(fails) != 1 || !strings.Contains(string(fails[0].Body), tc.code) {
				t.Fatalf("the rejection was not reported with its code: %+v", fails)
			}
			if tc.suffix != "/built" && len(rig.server.callsTo("/built")) != 0 {
				t.Fatal("a rejected upload was still delivered")
			}
			if left := jobRootEntries(t, rig.agent); len(left) != 0 {
				t.Fatalf("job directories left behind: %v", left)
			}
		})
	}
}

// 并发认领 409 BUILDER_CLAIM_IN_PROGRESS：不是任务，不报失败，下一轮照常领；领取请求带非空的 platforms / kinds
func TestClaimInProgressIsRetriedLater(t *testing.T) {
	rig := newRig(t)
	rig.server.queueProblem(http.StatusConflict, "BUILDER_CLAIM_IN_PROGRESS", nil)
	rig.server.queueClaim(claimBody("bld_afterBUSY001", "apk"))
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("a busy claim was reported as work")
	}
	if len(rig.server.callsTo("/fail")) != 0 {
		t.Fatal("a busy claim was reported as a failure")
	}
	if !rig.agent.pollOnce(context.Background()) || len(rig.server.callsTo("/built")) != 1 {
		t.Fatal("the next claim did not go through")
	}
	for _, call := range rig.server.callsTo("/claim") {
		decoder := json.NewDecoder(strings.NewReader(string(call.Body)))
		decoder.DisallowUnknownFields()
		var strict struct {
			Platforms []string `json:"platforms"`
			Kinds     []string `json:"kinds"`
		}
		if err := decoder.Decode(&strict); err != nil || len(strict.Platforms) == 0 || len(strict.Kinds) == 0 {
			t.Fatalf("claim body %s does not carry non-empty platforms and kinds (%v)", call.Body, err)
		}
		if call.Attempt != "" {
			t.Fatal("a claim carried x-build-attempt")
		}
	}
}
