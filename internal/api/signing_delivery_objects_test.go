package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// hookedObjectStore 在读出对象之后、交给调用方之前跑一次钩子，用来把"复核期间发生的事"
// 插进 complete 的事务外阶段。
type hookedObjectStore struct {
	*fakeObjectStore
	once  sync.Once
	onGet func(key string)
}

func (h *hookedObjectStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	body, err := h.fakeObjectStore.Get(ctx, key)
	if err == nil && h.onGet != nil && strings.HasSuffix(key, "/"+signedAPKObjectName) {
		h.once.Do(func() { h.onGet(key) })
	}
	return body, err
}

// lateUpload 模拟一个在状态变化之前就通过了任务作用域检查、这时才收完请求体的上传：
// 直接调处理函数，上下文里放的是进门那一刻的任务快照。
func (f *gateFixture) lateUpload(handler gin.HandlerFunc, jobContextKey string, job buildJob, machine buildMachine, body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPut, "/late-upload", bytes.NewReader(body))
	c.Request.Header.Set("content-type", octetStream)
	c.Set("requestId", "req_late")
	c.Set(machineContextKey, machine)
	c.Set(jobContextKey, job)
	handler(c)
	return recorder
}

func (f *gateFixture) objectsUnderJob(jobID string) []string {
	keys := []string{}
	for key := range f.store.objects {
		if strings.Contains(key, "/build-jobs/"+jobID+"/") {
			keys = append(keys, key)
		}
	}
	return keys
}

// 迟到的上传只能删掉自己写的那个对象。对象键只由编号决定时，同一次认领里一个在反向代理那里
// 超时、被客户端重传顶替的请求，会在任务已经往前走之后才写完：覆盖发布记录引用的包，又因为
// 改不到行把它删掉。每次上传一个新键之后，两件事都做不到。
func TestDBLateUploadsCannotTouchReferencedObjects(t *testing.T) {
	f := newGateFixture(t, 93)
	jobID := f.queueBuild("8.0.0", 90)
	claimed := f.claimBuild()
	enteredWhileClaimed := f.jobStatus(jobID)
	delivered := f.deliverBuild(claimed)
	built := f.jobStatus(jobID)

	objects := len(f.objectsUnderJob(jobID))
	late := f.lateUpload(f.s.uploadUnsignedArtifact, "buildJob", enteredWhileClaimed, f.builder.record(""), delivered.unsigned)
	if late.Code != http.StatusConflict || problemCode(t, late) != "BUILD_ATTEMPT_STALE" {
		t.Fatalf("a late unsigned upload after /built: %d %s", late.Code, late.Body.String())
	}
	if _, ok := f.store.objects[built.UnsignedObjectKey.String]; !ok || f.jobStatus(jobID).UnsignedObjectKey != built.UnsignedObjectKey {
		t.Fatal("a late unsigned upload removed or replaced the package the signer is about to download")
	}
	if got := len(f.objectsUnderJob(jobID)); got != objects {
		t.Fatalf("a late unsigned upload left %d objects, want %d", got, objects)
	}

	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	enteredWhileSigning := f.jobStatus(jobID)
	signed := f.signAndUpload(jobID, 1, "8.0.0", 90)
	complete := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, attemptHeaders(signAttemptHeader, 1), f.completeBody(signed, delivered.unsigned))
	if complete.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", complete.Code, complete.Body.String())
	}
	var releaseKey, releaseETag string
	if err := f.db.QueryRow(`SELECT object_key,JSON_UNQUOTE(JSON_EXTRACT(file_metadata,'$.objectEtag')) FROM app_releases WHERE id=?`, decodeBody(t, complete)["releaseId"]).
		Scan(&releaseKey, &releaseETag); err != nil {
		t.Fatal(err)
	}
	objects = len(f.objectsUnderJob(jobID))
	late = f.lateUpload(f.s.uploadSignedArtifact, "signingJob", enteredWhileSigning, f.primary.record(signerRolePrimary), signed)
	if late.Code != http.StatusConflict || problemCode(t, late) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("a late signed upload after complete: %d %s", late.Code, late.Body.String())
	}
	stored, ok := f.store.objects[releaseKey]
	if !ok || stored.etag != releaseETag || sha256HexBytes(stored.body) != sha256HexBytes(signed) {
		t.Fatal("a late signed upload removed or overwrote the released package")
	}
	if got := len(f.objectsUnderJob(jobID)); got != objects {
		t.Fatalf("a late signed upload left %d objects, want %d", got, objects)
	}
}

// 同一次认领里重传：任务行指向新对象，旧对象删掉；complete 只从任务行记下的键取包。
func TestDBReuploadsInTheSameClaimReplaceTheirObject(t *testing.T) {
	f := newGateFixture(t, 94)
	jobID := f.queueBuild("8.1.0", 91)
	claimed := f.claimBuild()
	headers := attemptHeaders(buildAttemptHeader, 1)
	unsigned := f.unsignedAPK("8.1.0", 91)
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/unsigned/upload", f.builder.Token, headers, unsigned); r.Code != http.StatusOK {
		t.Fatalf("first upload: %d %s", r.Code, r.Body.String())
	}
	first := f.jobStatus(jobID).UnsignedObjectKey.String
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/unsigned/upload", f.builder.Token, headers, unsigned); r.Code != http.StatusOK {
		t.Fatalf("second upload: %d %s", r.Code, r.Body.String())
	}
	second := f.jobStatus(jobID).UnsignedObjectKey.String
	if first == second || !matchesDeliveryKey(second, f.tenant, jobID, "a1", unsignedAPKObjectName) {
		t.Fatalf("a re-upload reused its key: %s / %s", first, second)
	}
	if _, ok := f.store.objects[first]; ok {
		t.Fatal("the replaced unsigned package was not deleted")
	}
	if _, ok := f.store.objects[second]; !ok {
		t.Fatal("the current unsigned package is missing")
	}
	delivered := f.deliverBuild(claimed)

	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	headers = attemptHeaders(signAttemptHeader, 1)
	early := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(unsigned, delivered.unsigned))
	if early.Code != http.StatusConflict || problemCode(t, early) != "SIGNED_ARTIFACT_MISSING" {
		t.Fatalf("complete before any signed upload: %d %s", early.Code, early.Body.String())
	}
	f.signAndUpload(jobID, 1, "8.1.0", 91)
	firstSigned := f.jobStatus(jobID).SignedObjectKey.String
	signed := f.signAndUpload(jobID, 1, "8.1.0", 91)
	current := f.jobStatus(jobID).SignedObjectKey.String
	if firstSigned == current || !matchesDeliveryKey(current, f.tenant, jobID, "s1", signedAPKObjectName) {
		t.Fatalf("a signed re-upload reused its key: %s / %s", firstSigned, current)
	}
	if _, ok := f.store.objects[firstSigned]; ok {
		t.Fatal("the replaced signed package was not deleted")
	}
	complete := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned))
	if complete.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", complete.Code, complete.Body.String())
	}
	var objectKey string
	if err := f.db.QueryRow(`SELECT object_key FROM app_releases WHERE id=?`, decodeBody(t, complete)["releaseId"]).Scan(&objectKey); err != nil {
		t.Fatal(err)
	}
	if objectKey != current {
		t.Fatalf("the release points at %s, the last signed upload is %s", objectKey, current)
	}
}

// complete 在事务外复核包可能要几分钟：这期间签名闸重传了（复核的对象已被删），或者签名闸被
// 吊销了，事务里都要再核对一次，不落发布记录。
func TestDBSignCompleteRechecksKeyAndMachineInsideTheTransaction(t *testing.T) {
	f := newGateFixture(t, 95)
	jobID := f.queueBuild("8.2.0", 92)
	delivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	headers := attemptHeaders(signAttemptHeader, 1)
	firstSigned := f.signAndUpload(jobID, 1, "8.2.0", 92)
	hooked := &hookedObjectStore{fakeObjectStore: f.store}
	f.s.objects = fixedObjectFactory{client: hooked}
	var secondSigned []byte
	hooked.onGet = func(string) { secondSigned = f.signAndUpload(jobID, 1, "8.2.0", 92) }
	replaced := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(firstSigned, delivered.unsigned))
	if replaced.Code != http.StatusConflict || problemCode(t, replaced) != "SIGNED_ARTIFACT_REPLACED" {
		t.Fatalf("complete over a package replaced during verification: %d %s", replaced.Code, replaced.Body.String())
	}
	countReleases := func() int {
		var n int
		_ = f.db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=?`, f.tenant).Scan(&n)
		return n
	}
	if countReleases() != 0 || f.jobStatus(jobID).Status != jobSigning {
		t.Fatal("a completion over a replaced package was recorded")
	}

	revoked := f.primary.record(signerRolePrimary)
	revoked.Status, revoked.RevokedBy, revoked.RevokedAt, revoked.RevokeReason = machineStatusRevoked, "tester@example.com", optString(iso(time.Now().UTC())), "lost"
	hooked.once = sync.Once{}
	hooked.onGet = func(string) { f.writeMachines(f.builder.record(""), revoked, f.standby.record(signerRoleStandby)) }
	gone := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(secondSigned, delivered.unsigned))
	if gone.Code != http.StatusUnauthorized || problemCode(t, gone) != "MACHINE_REVOKED" {
		t.Fatalf("complete by a signer revoked during verification: %d %s", gone.Code, gone.Body.String())
	}
	if countReleases() != 0 || f.jobStatus(jobID).Status != jobSigning {
		t.Fatal("a signer revoked during verification still recorded a release")
	}
}

// 构建期间有人手工传了不低于它的版本（在途门禁只挡 built/signing）：这条任务签出来也入不了库，
// 签名闸却会在本机记录里占掉这个 versionCode。派活前判失败，不派。
func TestDBSignClaimFailsBuildsOvertakenByAManualRelease(t *testing.T) {
	f := newGateFixture(t, 96)
	jobID := f.queueBuild("9.0.0", 100)
	claimed := f.claimBuild()

	signer := f.apkSigner
	apk := buildSignedAPK(t, apkSpec{PackageName: f.packageName, VersionCode: 101, VersionName: "9.0.1", MinSDK: 24, ApplicationID: tenantApplicationID}, &signer)
	token, err := f.s.encodeReleaseArtifactToken(releaseArtifactToken{ID: "art_overtake", TenantID: f.tenant, ObjectKey: "manual/overtake.apk", FileName: "app.apk",
		ContentType: apkContentType, Size: int64(len(apk)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.store.put("manual/overtake.apk", apk, "etag-overtake")
	c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/releases", map[string]any{
		"artifactToken": token, "platform": "android", "version": "9.0.1", "buildNumber": 101, "releaseNotes": map[string]any{},
	})
	f.s.createReleaseFromArtifact(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("a manual release while the build is only claimed: %d %s", recorder.Code, recorder.Body.String())
	}

	f.deliverBuild(claimed)
	if got := f.claimSign(f.primary); got != nil {
		t.Fatalf("a build overtaken by a newer release was dispatched: %v", got["job"])
	}
	job := f.jobStatus(jobID)
	if job.Status != jobFailed || job.SignAttempt != 0 || !strings.Contains(job.FailureReason.String, "9.0.1") {
		t.Fatalf("the overtaken build: status=%s signAttempt=%d reason=%q", job.Status, job.SignAttempt, job.FailureReason.String)
	}
	var audits int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='build_job_sign_overtaken' AND target_id=?`, f.tenant, jobID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("overtaken audit rows: %d %v", audits, err)
	}
}
