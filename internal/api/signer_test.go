package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/gin-gonic/gin"
)

// 一次安装包发布走完全程：排队 → 构建机领取、交付未签名包与出处 → 主签名闸领取（只拿到发给
// 本机的密文与出处）→ 下载未签名包 → 交回已签名包 → 单事务完成 → 幂等重试拿到同一个 releaseId。
func TestDBSigningGateEndToEnd(t *testing.T) {
	f := newGateFixture(t, 41)
	jobID := f.queueBuild("1.5.0", 50)
	job := f.claimBuild()
	if job["id"] != jobID {
		t.Fatalf("claimed %v, queued %s", job["id"], jobID)
	}
	delivered := f.deliverBuild(job)
	built := f.jobStatus(jobID)
	if built.Status != jobBuilt || !matchesDeliveryKey(built.UnsignedObjectKey.String, f.tenant, jobID, "a1", unsignedAPKObjectName) ||
		!matchesDeliveryKey(built.SBOMObjectKey.String, f.tenant, jobID, "a1", sbomObjectName) || built.NativeFingerprint.String != gateNativeFingerprint {
		t.Fatalf("after delivery: %+v", built)
	}

	// 备签名闸领不到：只有主签名闸领签名任务
	if claimed := f.claimSign(f.standby); claimed != nil {
		t.Fatalf("the standby signer was dispatched a job: %v", claimed)
	}
	claimed := f.claimSign(f.primary)
	if claimed == nil {
		t.Fatal("the primary signer got nothing to sign")
	}
	claimedJob := claimed["job"].(map[string]any)
	if claimedJob["id"] != jobID || claimedJob["signAttempt"] != float64(1) || claimedJob["attempt"] != float64(1) ||
		claimedJob["unsignedSha256"] != sha256HexBytes(delivered.unsigned) || claimedJob["nativeFingerprint"] != gateNativeFingerprint {
		t.Fatalf("sign claim job: %v", claimedJob)
	}
	prov := claimed["provenance"].(map[string]any)
	if prov["statement"] != delivered.envelope.Statement || prov["builderId"] != f.builder.ID || prov["builderPublicKeySha256"] != string(f.builder.record("").PublicKeySHA256) {
		t.Fatalf("sign claim provenance: %v", prov)
	}
	// 签名闸能用服务端给的出处公钥验过（它自己只信本机 pin，这里验的是服务端没有改坏）
	if _, err := provenance.Verify(provenance.Envelope{Statement: prov["statement"].(string), Signature: prov["signature"].(string)}, f.builder.ed25519Public()); err != nil {
		t.Fatalf("the provenance handed to the signer does not verify: %v", err)
	}
	keystore := claimed["keystore"].(map[string]any)
	rawBox, _ := json.Marshal(keystore["box"])
	var box keystorebox.Box
	if err := json.Unmarshal(rawBox, &box); err != nil || box.RecipientSHA256 != f.primary.recipient() {
		t.Fatalf("the primary did not get its own box: %s", rawBox)
	}
	if _, err := keystorebox.Open(box, f.primary.X25519.Bytes()); err != nil {
		t.Fatalf("the primary cannot open the box it was sent: %v", err)
	}
	if claimed["trustRootsDigest"] != f.currentDigest() {
		t.Fatalf("trustRootsDigest = %v", claimed["trustRootsDigest"])
	}
	signing := f.jobStatus(jobID)
	if signing.Status != jobSigning || signing.SigningMachineID.String != f.primary.ID || !signing.SigningClaimedAt.Valid {
		t.Fatalf("after sign claim: %+v", signing)
	}

	headers := attemptHeaders(signAttemptHeader, 1)
	download := f.do(http.MethodGet, "/v1/signer/jobs/"+jobID+"/unsigned/download", f.primary.Token, headers, nil)
	if download.Code != http.StatusOK || download.Header().Get("x-content-sha256") != sha256HexBytes(delivered.unsigned) ||
		sha256HexBytes(download.Body.Bytes()) != sha256HexBytes(delivered.unsigned) {
		t.Fatalf("download: %d %s", download.Code, download.Header())
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/heartbeat", f.primary.Token, headers, nil); r.Code != http.StatusNoContent {
		t.Fatalf("sign heartbeat: %d %s", r.Code, r.Body.String())
	}
	signed := f.signAndUpload(jobID, 1, "1.5.0", 50)
	complete := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned))
	if complete.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", complete.Code, complete.Body.String())
	}
	releaseID := decodeBody(t, complete)["releaseId"].(string)

	done := f.jobStatus(jobID)
	if done.Status != jobSucceeded || done.ReleaseID.String != releaseID || done.ArtifactSHA256.String != sha256HexBytes(signed) {
		t.Fatalf("after complete: %+v", done)
	}
	var status, objectKey, sha, createdBy string
	var rawMetadata []byte
	if err := f.db.QueryRow(`SELECT status,object_key,sha256,created_by,file_metadata FROM app_releases WHERE id=?`, releaseID).
		Scan(&status, &objectKey, &sha, &createdBy, &rawMetadata); err != nil {
		t.Fatal(err)
	}
	if status != "verified" || !matchesDeliveryKey(objectKey, f.tenant, jobID, "s1", signedAPKObjectName) || objectKey != done.SignedObjectKey.String || sha != sha256HexBytes(signed) || createdBy != signerActor {
		t.Fatalf("release row: %s %s %s %s", status, objectKey, sha, createdBy)
	}
	var metadata map[string]any
	_ = json.Unmarshal(rawMetadata, &metadata)
	for key, want := range map[string]any{
		"unsignedSha256": sha256HexBytes(delivered.unsigned), "commitSha": delivered.commit, "commitSelfReported": true,
		"buildJobId": jobID, "builderId": f.builder.ID, "signerMachineId": f.primary.ID, "nativeFingerprint": gateNativeFingerprint,
		"signerSha256": f.apkSigner.sha256(), "packageName": f.packageName, "sha256": sha256HexBytes(signed),
	} {
		if metadata[key] != want {
			t.Fatalf("file_metadata[%s] = %#v, want %#v (%s)", key, metadata[key], want, rawMetadata)
		}
	}
	if sbom, _ := metadata["sbom"].(map[string]any); sbom["sha256"] != sha256HexBytes(delivered.sbom) {
		t.Fatalf("file_metadata.sbom = %v", metadata["sbom"])
	}
	// 库里记着哪台构建机、哪台签名闸；租户控制台的发布记录里不给（设计 service-and-console-split-2026-09-27 §5）
	c, detail := testContext(t, f.tenant, http.MethodGet, "/v1/admin/releases/"+releaseID, nil)
	c.Params = gin.Params{{Key: "id", Value: releaseID}}
	f.s.releaseDetail(c)
	if detail.Code != http.StatusOK || strings.Contains(detail.Body.String(), f.builder.ID) || strings.Contains(detail.Body.String(), f.primary.ID) ||
		!strings.Contains(detail.Body.String(), jobID) {
		t.Fatalf("tenant release view: %d %s", detail.Code, detail.Body.String())
	}

	// 签名闸没收到响应重试：同一个包，同一个 releaseId，不多落一条
	again := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned))
	if again.Code != http.StatusOK || decodeBody(t, again)["releaseId"] != releaseID {
		t.Fatalf("idempotent complete: %d %s", again.Code, again.Body.String())
	}
	var releases int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=?`, f.tenant).Scan(&releases)
	if releases != 1 {
		t.Fatalf("%d releases after a retried complete", releases)
	}
	var audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND actor_id='system-signer' AND action IN ('build_job_signed','release_create')`, f.tenant).Scan(&audits)
	if audits != 2 {
		t.Fatalf("signing audit events: %d", audits)
	}
}

// 签名认领只派同租户同平台在途任务里 build 号最小的那条，只派给就绪的主签名闸，而且
// 签名闸报上来的就绪项必须与服务端当前值完全一致。
func TestDBSignClaimDispatchRules(t *testing.T) {
	f := newGateFixture(t, 42)
	lowID := f.queueBuild("1.0.0", 10)
	highID := f.queueBuild("1.0.1", 11)
	f.deliverBuild(f.claimBuild())
	// 10 已交付；11 还在排队。10 是最小的在途号，可以派
	// 先把 11 也交付，然后让 10 回到排队：这时 11 是 built 却不是最小在途号
	f.setJob(lowID, "status='queued',claimed_machine_id=NULL")
	f.setJob(highID, "status='built',unsigned_sha256=?,unsigned_size=1,sbom_sha256=?,native_fingerprint=?,commit_sha=?,provenance=?",
		strings.Repeat("a", 64), strings.Repeat("b", 64), gateNativeFingerprint, strings.Repeat("c", 40), `{"statement":"x","signature":"y"}`)
	if claimed := f.claimSign(f.primary); claimed != nil {
		t.Fatalf("a higher build number was dispatched while a lower one is in flight: %v", claimed["job"])
	}
	// 10 走完签名（改成 failed 放出去），11 就是最小的了——但就绪项对不上（摘要不同）时不派
	f.setJob(lowID, "status='failed'")
	stale := f.readyItem()
	stale["trustRootsDigest"] = strings.Repeat("0", 64)
	if claimed := f.claimSign(f.primary, stale); claimed != nil {
		t.Fatalf("a job was dispatched against a stale ready item: %v", claimed["job"])
	}
	wrongCert := f.readyItem()
	wrongCert["certificateSha256"] = strings.Repeat("e", 64)
	if claimed := f.claimSign(f.primary, wrongCert); claimed != nil {
		t.Fatalf("a job was dispatched against a ready item for another certificate: %v", claimed["job"])
	}
	// 主签名闸没有试签通过：不就绪，不派
	f.reportCheck(f.primary, true, "pending")
	if claimed := f.claimSign(f.primary); claimed != nil {
		t.Fatalf("a job was dispatched to a primary that has not passed its trial signing: %v", claimed["job"])
	}
	f.reportCheck(f.primary, true, "ok")
	// 主签名闸被切成备：不派
	f.writeMachines(f.builder.record(""), f.primary.record(signerRoleStandby), f.standby.record(signerRolePrimary))
	if claimed := f.claimSign(f.primary); claimed != nil {
		t.Fatalf("a job was dispatched to a signer that is no longer primary: %v", claimed["job"])
	}
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	claimed := f.claimSign(f.primary)
	if claimed == nil || claimed["job"].(map[string]any)["id"] != highID {
		t.Fatalf("the lowest ready build was not dispatched: %v", claimed)
	}
	// 同一条不会被派第二次
	if again := f.claimSign(f.primary); again != nil {
		t.Fatalf("a signing job was dispatched twice: %v", again["job"])
	}
}

// 完成事务的原子性：崩在写完发布记录之前、之后、改完任务之后，回滚后重试结果一致；
// 崩在提交之后（响应丢了），重试按幂等返回同一个 releaseId。
func TestDBSignCompleteIsAtomicUnderInjectedCrashes(t *testing.T) {
	f := newGateFixture(t, 43)
	jobID := f.queueBuild("2.0.0", 20)
	delivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	signed := f.signAndUpload(jobID, 1, "2.0.0", 20)
	headers := attemptHeaders(signAttemptHeader, 1)
	body := f.completeBody(signed, delivered.unsigned)
	countReleases := func() int {
		var n int
		_ = f.db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=?`, f.tenant).Scan(&n)
		return n
	}
	for _, point := range []string{faultBeforeReleaseInsert, faultAfterReleaseInsert, faultAfterJobUpdate} {
		f.s.signCompleteFault = func(at string) error {
			if at == point {
				return errors.New("injected crash at " + at)
			}
			return nil
		}
		r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body)
		if r.Code != http.StatusInternalServerError {
			t.Fatalf("%s: expected 500, got %d %s", point, r.Code, r.Body.String())
		}
		if n := countReleases(); n != 0 {
			t.Fatalf("%s: %d releases survived a rolled-back completion", point, n)
		}
		if job := f.jobStatus(jobID); job.Status != jobSigning || job.ReleaseID.Valid {
			t.Fatalf("%s: job after rollback: %+v", point, job)
		}
	}
	f.s.signCompleteFault = func(at string) error {
		if at == faultAfterCommit {
			return errors.New("injected crash after commit")
		}
		return nil
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body); r.Code != http.StatusInternalServerError {
		t.Fatalf("after-commit crash: %d %s", r.Code, r.Body.String())
	}
	if n := countReleases(); n != 1 {
		t.Fatalf("the committed completion left %d releases", n)
	}
	committed := f.jobStatus(jobID)
	f.s.signCompleteFault = nil
	retry := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body)
	if retry.Code != http.StatusOK || decodeBody(t, retry)["releaseId"] != committed.ReleaseID.String {
		t.Fatalf("retry after a lost response: %d %s (committed %s)", retry.Code, retry.Body.String(), committed.ReleaseID.String)
	}
	if n := countReleases(); n != 1 {
		t.Fatalf("the retry created another release: %d", n)
	}
	// 同一次签名认领交来另一个包（sha 不同）完成一个已经 succeeded 的任务：不是幂等重试，是结果冲突，
	// 已经落库的发布记录不会被替换
	other := f.completeBody(append(append([]byte{}, signed...), 0), delivered.unsigned)
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, other); r.Code != http.StatusConflict || problemCode(t, r) != "SIGN_RESULT_CONFLICT" {
		t.Fatalf("a different package completed a succeeded job: %d %s", r.Code, r.Body.String())
	}
}

// 完成时服务端自己核对交回的包：证书、sha256、交付记录都要对上。
func TestDBSignCompleteRejectsMismatches(t *testing.T) {
	f := newGateFixture(t, 44)
	jobID := f.queueBuild("3.0.0", 30)
	delivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	headers := attemptHeaders(signAttemptHeader, 1)
	complete := func(body map[string]any) (int, string) {
		r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body)
		return r.Code, problemCode(t, r)
	}
	// 用另一把密钥签的包：apkinspect 读出的签名者不是登记的证书
	rogue := newAPKSigner(t)
	rogueSigned := buildSignedAPK(t, apkSpec{PackageName: f.packageName, VersionCode: 30, VersionName: "3.0.0", MinSDK: 24, ApplicationID: tenantApplicationID, Fingerprint: gateNativeFingerprint}, &rogue)
	if r := f.do(http.MethodPut, "/v1/signer/jobs/"+jobID+"/signed/upload", f.primary.Token, headers, rogueSigned); r.Code != http.StatusOK {
		t.Fatalf("upload: %d", r.Code)
	}
	if code, problem := complete(f.completeBody(rogueSigned, delivered.unsigned)); code != http.StatusUnprocessableEntity || problem != "RELEASE_SIGNER_MISMATCH" {
		t.Fatalf("a package signed with another key: %d %s", code, problem)
	}
	signed := f.signAndUpload(jobID, 1, "3.0.0", 30)
	body := f.completeBody(signed, delivered.unsigned)
	body["certificateSha256"] = strings.Repeat("f", 64)
	if code, problem := complete(body); code != http.StatusUnprocessableEntity || problem != "RELEASE_SIGNER_MISMATCH" {
		t.Fatalf("a reported certificate that is not the registered one: %d %s", code, problem)
	}
	body = f.completeBody(signed, delivered.unsigned)
	body["certificateSha256"] = "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694"
	if code, problem := complete(body); code != http.StatusUnprocessableEntity || problem != "RELEASE_SIGNER_RETIRED" {
		t.Fatalf("a retired certificate: %d %s", code, problem)
	}
	body = f.completeBody(signed, delivered.unsigned)
	body["signedSha256"] = strings.Repeat("0", 64)
	if code, problem := complete(body); code != http.StatusUnprocessableEntity || problem != "SIGNED_ARTIFACT_MISMATCH" {
		t.Fatalf("a reported sha256 that is not the stored package: %d %s", code, problem)
	}
	body = f.completeBody(signed, delivered.unsigned)
	body["nativeFingerprint"] = strings.Repeat("9", 40)
	if code, problem := complete(body); code != http.StatusUnprocessableEntity || problem != "SIGN_RESULT_MISMATCH" {
		t.Fatalf("a native fingerprint that differs from the delivery: %d %s", code, problem)
	}
	// 编号过期：换一个签名编号
	stale := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, attemptHeaders(signAttemptHeader, 2), f.completeBody(signed, delivered.unsigned))
	if stale.Code != http.StatusConflict || problemCode(t, stale) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("a stale sign attempt completed: %d %s", stale.Code, stale.Body.String())
	}
	if job := f.jobStatus(jobID); job.Status != jobSigning {
		t.Fatalf("a rejected completion changed the job: %s", job.Status)
	}
	var rejected int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND actor_id='system-signer' AND action='release_rejected'`, f.tenant).Scan(&rejected)
	if rejected < 4 {
		t.Fatalf("rejected completions must be audited, got %d", rejected)
	}
}

// 拒签的三种结果：暂不能签退回 built 不计次；违规终态失败并审计；临时错误计次，到 2 判失败。
func TestDBSignerReleaseAndReject(t *testing.T) {
	f := newGateFixture(t, 45)
	jobID := f.queueBuild("4.0.0", 40)
	f.deliverBuild(f.claimBuild())
	claimAndExpect := func(attempt int) {
		t.Helper()
		claimed := f.claimSign(f.primary)
		if claimed == nil || claimed["job"].(map[string]any)["signAttempt"] != float64(attempt) {
			t.Fatalf("sign claim %d: %v", attempt, claimed)
		}
	}
	claimAndExpect(1)
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/release", f.primary.Token, attemptHeaders(signAttemptHeader, 1),
		map[string]any{"code": "TENANT_NOT_CONFIRMED", "detail": "本机还没有确认\n这个租户"}); r.Code != http.StatusNoContent {
		t.Fatalf("release: %d %s", r.Code, r.Body.String())
	}
	job := f.jobStatus(jobID)
	var outcome buildJobSignOutcome
	_ = json.Unmarshal(job.SignOutcome, &outcome)
	if job.Status != jobBuilt || job.SignFailures != 0 || outcome.Kind != "deferred" || outcome.MachineID != f.primary.ID || strings.Contains(outcome.Detail, "\n") {
		t.Fatalf("after release: %s failures=%d outcome=%s", job.Status, job.SignFailures, job.SignOutcome)
	}
	// 迟到的上报按编号拒绝
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/heartbeat", f.primary.Token, attemptHeaders(signAttemptHeader, 1), nil); r.Code != http.StatusConflict || problemCode(t, r) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("a heartbeat after release: %d %s", r.Code, r.Body.String())
	}
	f.ageSignOutcome(jobID)
	claimAndExpect(2)
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 2),
		map[string]any{"kind": "transient", "code": "SERVER_UNAVAILABLE", "detail": "5xx"}); r.Code != http.StatusNoContent {
		t.Fatalf("transient reject: %d %s", r.Code, r.Body.String())
	}
	if job = f.jobStatus(jobID); job.Status != jobBuilt || job.SignFailures != 1 {
		t.Fatalf("after one transient failure: %s %d", job.Status, job.SignFailures)
	}
	claimAndExpect(3)
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 3),
		map[string]any{"kind": "transient", "code": "RELEASE_SEQUENCE_BUSY", "detail": "busy"}); r.Code != http.StatusNoContent {
		t.Fatalf("second transient reject: %d %s", r.Code, r.Body.String())
	}
	if job = f.jobStatus(jobID); job.Status != jobFailed || job.SignFailures != 2 || !job.FailureReason.Valid {
		t.Fatalf("two transient failures must fail the job: %s %d %v", job.Status, job.SignFailures, job.FailureReason)
	}

	violationID := f.queueBuild("4.0.1", 41)
	f.deliverBuild(f.claimBuild())
	claimed := f.claimSign(f.primary)
	if claimed == nil || claimed["job"].(map[string]any)["id"] != violationID {
		t.Fatalf("violation job claim: %v", claimed)
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+violationID+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 1),
		map[string]any{"kind": "violation", "code": "PERMISSION_NOT_ALLOWED", "detail": "android.permission.READ_SMS"}); r.Code != http.StatusNoContent {
		t.Fatalf("violation reject: %d %s", r.Code, r.Body.String())
	}
	violated := f.jobStatus(violationID)
	if violated.Status != jobFailed || !strings.Contains(violated.FailureReason.String, "PERMISSION_NOT_ALLOWED") || violated.SignFailures != 0 {
		t.Fatalf("after a violation: %+v", violated)
	}
	var audited int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='build_job_sign_rejected' AND target_id=? AND actor_id='system-signer'`, f.tenant, violationID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("a violation must be audited once, got %d", audited)
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+violationID+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 1),
		map[string]any{"kind": "sideways", "code": "X", "detail": ""}); r.Code != http.StatusConflict && r.Code != http.StatusBadRequest {
		t.Fatalf("an unknown reject kind: %d", r.Code)
	}
}

// 签名闸只拿得到发给本机的密文；上报按机器 id 分键，两台签名闸并发写互不覆盖。
func TestDBSignerKeystoreChecksAreScopedPerMachine(t *testing.T) {
	f := newGateFixture(t, 46)
	list := func(machine gateMachine) []any {
		r := f.do(http.MethodGet, "/v1/signer/keystore-checks", machine.Token, nil, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("keystore checks for %s: %d %s", machine.Name, r.Code, r.Body.String())
		}
		body := decodeBody(t, r)
		if body["machineId"] != machine.ID {
			t.Fatalf("machineId = %v", body["machineId"])
		}
		return body["items"].([]any)
	}
	for _, machine := range []gateMachine{f.primary, f.standby} {
		items := list(machine)
		found := false
		for _, raw := range items {
			item := raw.(map[string]any)
			if item["tenantSlug"] != f.slug {
				continue
			}
			found = true
			box := item["box"].(map[string]any)
			if box["recipientSha256"] != machine.recipient() || item["trustRootsDigest"] != f.currentDigest() {
				t.Fatalf("%s got a box that is not its own: %v", machine.Name, item)
			}
		}
		if !found {
			t.Fatalf("%s does not see this tenant's keystore", machine.Name)
		}
	}
	// 只加密给主签名闸：备签名闸看不到这个租户
	f.uploadKeystore(f.primary)
	for _, raw := range list(f.standby) {
		if raw.(map[string]any)["tenantSlug"] == f.slug {
			t.Fatal("the standby sees a keystore that was not sealed to it")
		}
	}
	f.uploadKeystore(f.primary, f.standby)
	f.reportCheck(f.primary, true, "ok")
	f.reportCheck(f.standby, true, "pending")
	checks, err := f.s.keystoreChecksFor(t.Context(), f.db, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	keystoreVersion, _ := f.keystoreVersions()
	if checks[f.primary.ID].TrialSign != "ok" || checks[f.standby.ID].TrialSign != "pending" ||
		checks[f.primary.ID].KeystoreVersion != keystoreVersion || checks[f.standby.ID].KeystoreVersion != keystoreVersion {
		t.Fatalf("per-machine checks overwrote each other: %+v", checks)
	}
	// 旧版本的结论不写：密钥在检查期间被重新上传
	stale := map[string]any{"tenantSlug": f.slug, "keystoreVersion": keystoreVersion - 1, "decrypt": "failed", "confirmed": false,
		"confirmedTrustRootsDigest": nil, "trialSign": "failed", "error": "old"}
	if r := f.do(http.MethodPost, "/v1/signer/keystore-checks", f.primary.Token, nil, map[string]any{"localRole": "primary", "trust": f.localTrust(), "items": []any{stale,
		map[string]any{"tenantSlug": "no-such-tenant-" + uniqueSuffix(), "keystoreVersion": 1, "decrypt": "ok", "confirmed": false, "confirmedTrustRootsDigest": nil, "trialSign": "pending", "error": nil}}}); r.Code != http.StatusNoContent {
		t.Fatalf("stale check: %d %s", r.Code, r.Body.String())
	}
	checks, _ = f.s.keystoreChecksFor(t.Context(), f.db, f.tenant)
	if checks[f.primary.ID].TrialSign != "ok" {
		t.Fatalf("a check for an old keystore version overwrote the current one: %+v", checks[f.primary.ID])
	}
	// 旧格式的检查记录（打包机时代）当作空，覆盖写成 format 2
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value='{"version":3,"ok":true,"agent":"old"}' WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreCheckConfigKey); err != nil {
		t.Fatal(err)
	}
	if checks, _ = f.s.keystoreChecksFor(t.Context(), f.db, f.tenant); len(checks) != 0 {
		t.Fatalf("a legacy check record was read as current: %+v", checks)
	}
	f.reportCheck(f.primary, true, "ok")
	if checks, _ = f.s.keystoreChecksFor(t.Context(), f.db, f.tenant); checks[f.primary.ID].TrialSign != "ok" {
		t.Fatalf("a report over a legacy record: %+v", checks)
	}
}

// 手工上传 Android 发布记录时，该租户有待签名或签名中的任务就 409。
func TestDBManualReleaseUploadWaitsForSigningInFlight(t *testing.T) {
	f := newGateFixture(t, 47)
	jobID := f.queueBuild("5.0.0", 60)
	f.deliverBuild(f.claimBuild())
	upload := func() (int, string) {
		c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/releases", map[string]any{
			"artifactToken": "irrelevant", "platform": "android", "version": "5.0.1", "buildNumber": 61, "releaseNotes": map[string]any{},
		})
		f.s.createReleaseFromArtifact(c)
		return recorder.Code, problemCode(t, recorder)
	}
	for _, status := range []string{jobBuilt, jobSigning} {
		f.setJob(jobID, "status=?", status)
		if code, problem := upload(); code != http.StatusConflict || problem != "RELEASE_SIGNING_IN_FLIGHT" {
			t.Fatalf("manual upload while %s: %d %s", status, code, problem)
		}
	}
	f.setJob(jobID, "status='canceled'")
	if code, problem := upload(); problem == "RELEASE_SIGNING_IN_FLIGHT" {
		t.Fatalf("a canceled job still blocks manual uploads: %d %s", code, problem)
	}

	// 带着一个有效的包走完整条路：在途时被挡，放掉之后同一个包能正常入库
	signer := f.apkSigner
	apk := buildSignedAPK(t, apkSpec{PackageName: f.packageName, VersionCode: 61, VersionName: "5.0.1", MinSDK: 24, ApplicationID: tenantApplicationID}, &signer)
	token, err := f.s.encodeReleaseArtifactToken(releaseArtifactToken{ID: "art_manual", TenantID: f.tenant, ObjectKey: "manual/app.apk", FileName: "app.apk",
		ContentType: apkContentType, Size: int64(len(apk)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.store.put("manual/app.apk", apk, "etag-manual")
	f.setJob(jobID, "status='built'")
	c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/releases", map[string]any{
		"artifactToken": token, "platform": "android", "version": "5.0.1", "buildNumber": 61, "releaseNotes": map[string]any{},
	})
	f.s.createReleaseFromArtifact(c)
	if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "RELEASE_SIGNING_IN_FLIGHT" {
		t.Fatalf("a manual release with a valid package while signing is in flight: %d %s", recorder.Code, recorder.Body.String())
	}
	f.setJob(jobID, "status='canceled'")
	c, recorder = testContext(t, f.tenant, http.MethodPost, "/v1/admin/releases", map[string]any{
		"artifactToken": token, "platform": "android", "version": "5.0.1", "buildNumber": 61, "releaseNotes": map[string]any{},
	})
	f.s.createReleaseFromArtifact(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("the manual release path itself is broken: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 「签名中」只能强制判失败；之后签名闸的迟到上报全部按状态拒绝。
func TestDBForceFailStopsTheSigner(t *testing.T) {
	f := newGateFixture(t, 48)
	jobID := f.queueBuild("6.0.0", 70)
	delivered := f.deliverBuild(f.claimBuild())
	forceFail := func() (int, string) {
		c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds/"+jobID+"/force-fail", map[string]any{"reason": "signer is stuck", "confirm": true})
		c.Params = append(c.Params, ginParam("id", jobID))
		f.s.forceFailBuildJob(c)
		return recorder.Code, problemCode(t, recorder)
	}
	if code, problem := forceFail(); code != http.StatusConflict || problem != "BUILD_JOB_NOT_FORCE_FAILABLE" {
		t.Fatalf("force-failing a built job: %d %s", code, problem)
	}
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	signed := f.signAndUpload(jobID, 1, "6.0.0", 70)
	if code, _ := forceFail(); code != http.StatusOK {
		t.Fatalf("force-failing a signing job: %d", code)
	}
	if job := f.jobStatus(jobID); job.Status != jobFailed || !strings.Contains(job.FailureReason.String, "signer is stuck") {
		t.Fatalf("after force-fail: %+v", job)
	}
	headers := attemptHeaders(signAttemptHeader, 1)
	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "/v1/signer/jobs/" + jobID + "/heartbeat"},
		{http.MethodGet, "/v1/signer/jobs/" + jobID + "/unsigned/download"},
		{http.MethodPost, "/v1/signer/jobs/" + jobID + "/release"},
	} {
		var body any
		if request.path[len(request.path)-7:] == "release" {
			body = map[string]any{"code": "LATE", "detail": "late"}
		}
		if r := f.do(request.method, request.path, f.primary.Token, headers, body); r.Code != http.StatusConflict {
			t.Fatalf("%s after force-fail: %d %s", request.path, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned)); r.Code != http.StatusConflict {
		t.Fatalf("complete after force-fail: %d %s", r.Code, r.Body.String())
	}
	var audited int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='build_job_force_fail' AND target_id=?`, f.tenant, jobID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("force-fail audit: %d", audited)
	}
}

// 检查清单被截断时不许回 200。
//
// 这条接口按"平台上所有配了密钥的租户"线性展开，而每个请求最多只能跑
// MYSQL_QUERY_TIMEOUT_SECONDS 秒（databaseTimeout）。租户够多的时候它跑不完，
// 而跑不完时回一份**残缺**的清单，在签名闸那边与"没事可做"完全一样：密钥不换、
// 检查结论不报、生成请求领不走，两边日志都干净。宁可 503 让它下一轮重试。
func TestDBSignerKeystoreChecksRefuseToAnswerWithAPartialList(t *testing.T) {
	f := newGateFixture(t, 146)
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/signer/keystore-checks", nil)
	c.Set(machineContextKey, f.primary.record(signerRolePrimary))
	cut, cancel := context.WithCancel(c.Request.Context())
	cancel()
	c.Request = c.Request.WithContext(cut)

	f.s.signerKeystoreChecks(c)
	if recorder.Code == http.StatusOK {
		t.Fatalf("a request that was cut short still answered with a list: %s", recorder.Body.String())
	}
	if recorder.Code != http.StatusServiceUnavailable || problemCode(t, recorder) != "BUILD_KEYSTORE_CHECK_INCOMPLETE" {
		t.Fatalf("cut short: %d %s", recorder.Code, recorder.Body.String())
	}
}
