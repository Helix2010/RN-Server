package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/provenance"
)

// 过期编号一律 409：任务被回收重排、或被同一台机器重新认领之后，拿着旧编号的上报
// （心跳、失败、上传、交付、热更新那几条）都改不了它。
func TestDBBuilderReportsWithAStaleAttemptAreRefused(t *testing.T) {
	f := newGateFixture(t, 61)
	jobID := f.queueBuild("1.0.0", 1)
	job := f.claimBuild()
	headers := attemptHeaders(buildAttemptHeader, 1)
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", f.builder.Token, headers, map[string]any{"logTail": []string{"step 1"}}); r.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", r.Code, r.Body.String())
	}
	if f.jobStatus(jobID).Status != jobRunning {
		t.Fatal("a heartbeat did not move the job to running")
	}
	// 心跳停了 11 分钟：回收定时器把它退回排队
	f.setJob(jobID, "heartbeat_at=?", time.Now().UTC().Add(-11*time.Minute))
	if result := f.s.reapBuildJobs(context.Background(), time.Now().UTC()); len(result.Requeued) != 1 || result.Requeued[0] != jobID {
		t.Fatalf("reap: %+v", result)
	}
	stale := func(method, path string, body any) {
		t.Helper()
		r := f.do(method, "/v1/build-agent/jobs/"+jobID+path, f.builder.Token, headers, body)
		if r.Code != http.StatusConflict || problemCode(t, r) != "BUILD_ATTEMPT_STALE" {
			t.Fatalf("%s %s with a stale attempt: %d %s", method, path, r.Code, r.Body.String())
		}
	}
	stale(http.MethodPost, "/heartbeat", map[string]any{"logTail": []string{}})
	stale(http.MethodPost, "/fail", map[string]any{"failureReason": "late", "commitSha": "", "logTail": []string{}})
	stale(http.MethodPut, "/unsigned/upload", f.unsignedAPK("1.0.0", 1))
	stale(http.MethodPut, "/sbom/upload", []byte(`{"bomFormat":"CycloneDX"}`))
	stale(http.MethodPost, "/built", map[string]any{"commitSha": strings.Repeat("c", 40), "nativeFingerprint": gateNativeFingerprint, "provenance": map[string]any{"statement": "e30=", "signature": "e30="}, "logTail": []string{}})
	stale(http.MethodGet, "/icons/icon.png", nil)
	// 同一台机器重新认领：编号变成 2，旧编号 1 的上报仍然过期
	again := f.claimBuild()
	if again["id"] != jobID || again["attempt"] != float64(2) {
		t.Fatalf("re-claim: %v", again)
	}
	stale(http.MethodPost, "/heartbeat", map[string]any{"logTail": []string{}})
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", f.builder.Token, attemptHeaders(buildAttemptHeader, 2), map[string]any{"logTail": []string{}}); r.Code != http.StatusNoContent {
		t.Fatalf("the current attempt was refused: %d %s", r.Code, r.Body.String())
	}
	// 另一台构建机拿着正确的编号也不行：不是它认领的
	other := newGateMachine(t, machineRoleBuilder, "builder-other-"+uniqueSuffix())
	f.writeMachines(f.builder.record(""), other.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", other.Token, attemptHeaders(buildAttemptHeader, 2), map[string]any{"logTail": []string{}}); r.Code != http.StatusConflict {
		t.Fatalf("another builder reported on this job: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", f.builder.Token, nil, map[string]any{"logTail": []string{}}); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_BUILD_ATTEMPT" {
		t.Fatalf("a report without x-build-attempt: %d %s", r.Code, r.Body.String())
	}
	_ = job
}

// 未签名包与 SBOM：对象键带认领编号、服务端自己算 sha256、只收 octet-stream、只收安装包任务。
func TestDBBuilderDeliveryUploads(t *testing.T) {
	f := newGateFixture(t, 62)
	jobID := f.queueBuild("1.1.0", 2)
	f.claimBuild()
	headers := attemptHeaders(buildAttemptHeader, 1)
	unsigned := f.unsignedAPK("1.1.0", 2)
	upload := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/unsigned/upload", f.builder.Token, headers, unsigned)
	if upload.Code != http.StatusOK {
		t.Fatalf("unsigned upload: %d %s", upload.Code, upload.Body.String())
	}
	if body := decodeBody(t, upload); body["sha256"] != sha256HexBytes(unsigned) || body["size"] != float64(len(unsigned)) {
		t.Fatalf("unsigned upload response: %v", body)
	}
	job := f.jobStatus(jobID)
	if !strings.HasSuffix(job.UnsignedObjectKey.String, "tenants/"+f.tenant+"/build-jobs/"+jobID+"/a1/app-release-unsigned.apk") || job.UnsignedSHA256.String != sha256HexBytes(unsigned) {
		t.Fatalf("unsigned columns: %+v", job)
	}
	if stored, ok := f.store.objects[job.UnsignedObjectKey.String]; !ok || sha256HexBytes(stored.body) != sha256HexBytes(unsigned) {
		t.Fatal("the unsigned package is not in storage")
	}
	request := func(contentType string, body []byte) int {
		t.Helper()
		r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/sbom/upload", f.builder.Token, map[string]string{buildAttemptHeader: "1", "content-type": contentType}, body)
		return r.Code
	}
	if code := request("application/json", []byte(`{"bomFormat":"CycloneDX"}`)); code != http.StatusUnsupportedMediaType {
		t.Fatalf("a JSON content type was accepted: %d", code)
	}
	if code := request(octetStream, []byte(`{"bomFormat":"SPDX"}`)); code != http.StatusUnprocessableEntity {
		t.Fatalf("a non-CycloneDX SBOM was accepted: %d", code)
	}
	if code := request(octetStream, nil); code != http.StatusBadRequest {
		t.Fatalf("an empty SBOM was accepted: %d", code)
	}
	if code := request(octetStream, []byte(`{"bomFormat":"CycloneDX","components":[]}`)); code != http.StatusOK {
		t.Fatalf("a CycloneDX SBOM was refused: %d", code)
	}
	if !strings.Contains(f.jobStatus(jobID).SBOMObjectKey.String, "/a1/sbom.cdx.json") {
		t.Fatal("the SBOM key does not carry the attempt")
	}
	f.s.cfg.ArtifactMaxSizeBytes = int64(len(unsigned) - 1)
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/unsigned/upload", f.builder.Token, headers, unsigned); r.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized upload: %d %s", r.Code, r.Body.String())
	}
}

// /built：出处签名用本机登记的公钥验过，声明逐项与任务行、请求、已上传的文件一致。
func TestDBBuilderDeliveryVerifiesProvenance(t *testing.T) {
	f := newGateFixture(t, 63)
	jobID := f.queueBuild("1.2.0", 3)
	f.claimBuild()
	headers := attemptHeaders(buildAttemptHeader, 1)
	unsigned := f.unsignedAPK("1.2.0", 3)
	sbom := []byte(`{"bomFormat":"CycloneDX"}`)
	commit := strings.Repeat("d", 40)
	statement := provenance.Statement{
		Version: provenance.Version, Purpose: provenance.Purpose, JobID: jobID, Attempt: 1, TenantSlug: f.slug, PackageName: f.packageName,
		VersionCode: 3, VersionName: "1.2.0", CommitSHA: commit, UnsignedSHA256: sha256HexBytes(unsigned), UnsignedSize: int64(len(unsigned)),
		SBOMSHA256: sha256HexBytes(sbom), NativeFingerprint: gateNativeFingerprint, BuilderID: f.builder.ID, BuiltAt: "2026-09-16T00:00:00Z",
	}
	deliver := func(s provenance.Statement, signer gateMachine, requestCommit, native string) (int, string, string) {
		t.Helper()
		envelope, err := provenance.Sign(s, signer.Ed25519)
		if err != nil {
			t.Fatal(err)
		}
		r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/built", f.builder.Token, headers, map[string]any{
			"commitSha": requestCommit, "nativeFingerprint": native, "provenance": envelope, "logTail": []string{"done"},
		})
		if r.Code == http.StatusNoContent {
			return r.Code, "", ""
		}
		return r.Code, problemCode(t, r), r.Body.String()
	}
	if code, problem, body := deliver(statement, f.builder, commit, gateNativeFingerprint); code != http.StatusUnprocessableEntity || problem != "BUILD_PROVENANCE_INVALID" || !strings.Contains(body, "uploaded") {
		t.Fatalf("delivery before uploading: %d %s %s", code, problem, body)
	}
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/unsigned/upload", f.builder.Token, headers, unsigned); r.Code != http.StatusOK {
		t.Fatal(r.Body.String())
	}
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/sbom/upload", f.builder.Token, headers, sbom); r.Code != http.StatusOK {
		t.Fatal(r.Body.String())
	}
	impostor := newGateMachine(t, machineRoleBuilder, "impostor")
	if code, problem, _ := deliver(statement, impostor, commit, gateNativeFingerprint); code != http.StatusUnprocessableEntity || problem != "BUILD_PROVENANCE_INVALID" {
		t.Fatalf("a statement signed by another key: %d %s", code, problem)
	}
	mutations := map[string]func(s *provenance.Statement){
		"jobId":          func(s *provenance.Statement) { s.JobID = "bld_someotherjob" },
		"attempt":        func(s *provenance.Statement) { s.Attempt = 2 },
		"tenantSlug":     func(s *provenance.Statement) { s.TenantSlug = "other-tenant" },
		"packageName":    func(s *provenance.Statement) { s.PackageName = "com.evil.app" },
		"versionCode":    func(s *provenance.Statement) { s.VersionCode = 4 },
		"versionName":    func(s *provenance.Statement) { s.VersionName = "9.9.9" },
		"unsignedSha256": func(s *provenance.Statement) { s.UnsignedSHA256 = strings.Repeat("e", 64) },
		"unsignedSize":   func(s *provenance.Statement) { s.UnsignedSize++ },
		"sbomSha256":     func(s *provenance.Statement) { s.SBOMSHA256 = strings.Repeat("e", 64) },
		"builderId":      func(s *provenance.Statement) { s.BuilderID = "mch_someoneelse" },
	}
	for field, mutate := range mutations {
		changed := statement
		mutate(&changed)
		if code, problem, body := deliver(changed, f.builder, commit, gateNativeFingerprint); code != http.StatusUnprocessableEntity || problem != "BUILD_PROVENANCE_INVALID" || !strings.Contains(body, field) {
			t.Fatalf("a statement with a different %s: %d %s %s", field, code, problem, body)
		}
	}
	if code, _, body := deliver(statement, f.builder, strings.Repeat("a", 40), gateNativeFingerprint); code != http.StatusUnprocessableEntity || !strings.Contains(body, "commitSha") {
		t.Fatalf("a request commit that differs from the statement: %d %s", code, body)
	}
	if code, _, body := deliver(statement, f.builder, commit, strings.Repeat("1", 40)); code != http.StatusUnprocessableEntity || !strings.Contains(body, "nativeFingerprint") {
		t.Fatalf("a request fingerprint that differs from the statement: %d %s", code, body)
	}
	if job := f.jobStatus(jobID); job.Status != jobClaimed || job.Provenance != nil {
		t.Fatalf("a refused delivery changed the job: %+v", job)
	}
	if code, problem, body := deliver(statement, f.builder, commit, gateNativeFingerprint); code != http.StatusNoContent {
		t.Fatalf("a valid delivery: %d %s %s", code, problem, body)
	}
	job := f.jobStatus(jobID)
	var record buildProvenanceRecord
	if err := json.Unmarshal(job.Provenance, &record); err != nil || record.BuilderID != f.builder.ID || record.BuilderPublicKeySHA256 != string(f.builder.record("").PublicKeySHA256) {
		t.Fatalf("stored provenance: %s %v", job.Provenance, err)
	}
	if job.Status != jobBuilt || job.CommitSHA.String != commit || job.NativeFingerprint.String != gateNativeFingerprint {
		t.Fatalf("after delivery: %+v", job)
	}
	// 交付之后不能再改：状态已经不是 claimed/running
	if code, _, _ := deliver(statement, f.builder, commit, gateNativeFingerprint); code != http.StatusConflict {
		t.Fatalf("a second delivery: %d", code)
	}
}

// 安装包任务不能再走旧的产物交付路径（那条会由构建机直接落发布记录）；热更新专用接口
// 对安装包任务同样拒绝。
func TestDBAPKJobsCannotUseTheRetiredArtifactRoutes(t *testing.T) {
	f := newGateFixture(t, 64)
	jobID := f.queueBuild("1.3.0", 5)
	f.claimBuild()
	headers := attemptHeaders(buildAttemptHeader, 1)
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/complete", map[string]any{"commitSha": strings.Repeat("a", 40), "artifactSha256": strings.Repeat("b", 64), "releaseId": "rel_x", "logTail": []string{}}},
		{http.MethodPost, "/artifact-uploads", map[string]any{"fileName": "app.apk", "contentType": "application/vnd.android.package-archive", "size": 10}},
		{http.MethodPut, "/artifact", []byte("apk")},
		{http.MethodPost, "/release", map[string]any{"artifactToken": "x"}},
		{http.MethodPost, "/ota-uploads", map[string]any{"fileName": "ota.zip", "size": 10}},
		{http.MethodPost, "/ota-release", map[string]any{"artifactToken": "x", "sourceCommitSha": ""}},
	} {
		r := f.do(request.method, "/v1/build-agent/jobs/"+jobID+request.path, f.builder.Token, headers, request.body)
		if r.Code != http.StatusConflict || problemCode(t, r) != "BUILD_KIND_MISMATCH" {
			t.Fatalf("%s %s on an apk job: %d %s", request.method, request.path, r.Code, r.Body.String())
		}
	}
	if job := f.jobStatus(jobID); job.Status != jobClaimed || job.ReleaseID.Valid {
		t.Fatalf("a retired route changed the job: %+v", job)
	}
}
