package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 复核期间发布身份被改（换了登记的证书指纹）：事务里带锁重读，对不上就 409，不落发布记录；
// 改回去之后同一个包能正常完成。
func TestDBSignCompleteRefusesAnIdentityReplacedDuringVerification(t *testing.T) {
	f := newGateFixture(t, 101)
	jobID := f.queueBuild("10.0.0", 1000)
	delivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	signed := f.signAndUpload(jobID, 1, "10.0.0", 1000)
	var original []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseAndroidIdentityConfigKey).Scan(&original); err != nil {
		t.Fatal(err)
	}
	replaced := strings.Replace(string(original), f.apkSigner.sha256(), strings.Repeat("c", 64), 1)
	if replaced == string(original) {
		t.Fatalf("the fixture identity does not carry the signer fingerprint: %s", original)
	}
	// 事务外的复核已经用旧身份通过，进事务之前管理员换了登记的证书指纹
	f.s.signCompleteFault = func(point string) error {
		if point == faultAfterVerification {
			if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`, replaced, f.tenant, releaseAndroidIdentityConfigKey); err != nil {
				t.Error(err)
			}
		}
		return nil
	}
	headers := attemptHeaders(signAttemptHeader, 1)
	r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned))
	if r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_IDENTITY_CHANGED" {
		t.Fatalf("complete over a replaced identity: %d %s", r.Code, r.Body.String())
	}
	var releases, audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=?`, f.tenant).Scan(&releases)
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='release_rejected' AND target_id=? AND JSON_EXTRACT(summary,'$.code')='RELEASE_IDENTITY_CHANGED'`, f.tenant, jobID).Scan(&audits)
	if releases != 0 || audits != 1 || f.jobStatus(jobID).Status != jobSigning {
		t.Fatalf("after the refusal: releases=%d audits=%d status=%s", releases, audits, f.jobStatus(jobID).Status)
	}
	f.s.signCompleteFault = nil
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`, original, f.tenant, releaseAndroidIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned)); r.Code != http.StatusOK {
		t.Fatalf("complete after the identity was restored: %d %s", r.Code, r.Body.String())
	}
}

// complete 一开始就刷新签名心跳：大包复核期间回收器跑一轮，任务不会被退回待签名。
// 幂等快路径只认同一台签名闸、同一次签名认领；发布记录的原生指纹注明来自出处声明。
func TestDBSignCompleteKeepsTheClaimAliveAndScopesIdempotency(t *testing.T) {
	f := newGateFixture(t, 102)
	jobID := f.queueBuild("10.1.0", 1010)
	delivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	signed := f.signAndUpload(jobID, 1, "10.1.0", 1010)
	f.setJob(jobID, "signing_heartbeat_at=?", time.Now().UTC().Add(-(signJobHeartbeatTimeout + time.Minute)))
	hooked := &hookedObjectStore{fakeObjectStore: f.store}
	f.s.objects = fixedObjectFactory{client: hooked}
	var reaped reapResult
	hooked.onGet = func(string) { reaped = f.s.reapBuildJobs(t.Context(), time.Now().UTC()) }
	headers := attemptHeaders(signAttemptHeader, 1)
	body := f.completeBody(signed, delivered.unsigned)
	complete := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body)
	if complete.Code != http.StatusOK || len(reaped.SignBack)+len(reaped.SignFailed) != 0 {
		t.Fatalf("complete with a stale heartbeat: %d %s (reaped %+v)", complete.Code, complete.Body.String(), reaped)
	}
	releaseID := decodeBody(t, complete)["releaseId"]
	var source, native string
	if err := f.db.QueryRow(`SELECT JSON_UNQUOTE(JSON_EXTRACT(file_metadata,'$.nativeFingerprintSource')),JSON_UNQUOTE(JSON_EXTRACT(file_metadata,'$.nativeFingerprint')) FROM app_releases WHERE id=?`, releaseID).
		Scan(&source, &native); err != nil || source != "builder-provenance" || native != gateNativeFingerprint {
		t.Fatalf("native fingerprint provenance in the release: %q %q (%v)", source, native, err)
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.standby.Token, headers, body); r.Code != http.StatusConflict || problemCode(t, r) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("another signer replaying the completion: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, attemptHeaders(signAttemptHeader, 2), body); r.Code != http.StatusConflict || problemCode(t, r) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("a different sign attempt replaying the completion: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, headers, body); r.Code != http.StatusOK || decodeBody(t, r)["releaseId"] != releaseID {
		t.Fatalf("the real retry: %d %s", r.Code, r.Body.String())
	}
	// 签名闸带来的原生指纹与出处声明不一致：422
	other := f.queueBuild("10.2.0", 1020)
	otherDelivered := f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	otherSigned := f.signAndUpload(other, 1, "10.2.0", 1020)
	mismatch := f.completeBody(otherSigned, otherDelivered.unsigned)
	mismatch["nativeFingerprint"] = strings.Repeat("9", 40)
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+other+"/complete", f.primary.Token, headers, mismatch); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "SIGN_RESULT_MISMATCH" {
		t.Fatalf("a native fingerprint that differs from the provenance: %d %s", r.Code, r.Body.String())
	}
}

// 任务被放弃或重新认领时，行上不再有人引用的交付对象从存储里删掉；删不掉不挡状态变化。
func TestDBAbandonedDeliveriesAreDeleted(t *testing.T) {
	f := newGateFixture(t, 103)
	exists := func(key string) bool {
		_, ok := f.store.objects[key]
		return ok
	}
	// 构建机报失败：未签名包与 SBOM 删掉
	failing := f.queueBuild("11.0.0", 1100)
	f.claimBuild()
	unsigned := f.unsignedAPK("11.0.0", 1100)
	builderHeaders := attemptHeaders(buildAttemptHeader, 1)
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+failing+"/unsigned/upload", f.builder.Token, builderHeaders, unsigned); r.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", r.Code, r.Body.String())
	}
	uploaded := f.jobStatus(failing).UnsignedObjectKey.String
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+failing+"/fail", f.builder.Token, builderHeaders, map[string]any{"failureReason": "gradle died", "logTail": []string{}}); r.Code != http.StatusNoContent {
		t.Fatalf("fail: %d %s", r.Code, r.Body.String())
	}
	if exists(uploaded) || f.jobStatus(failing).UnsignedObjectKey.Valid {
		t.Fatal("a failed build kept its unsigned package")
	}

	// 回收重排：这一次认领的交付删掉；重新认领时再清一次行上留下的键
	requeued := f.queueBuild("11.1.0", 1110)
	f.claimBuild()
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+requeued+"/unsigned/upload", f.builder.Token, builderHeaders, f.unsignedAPK("11.1.0", 1110)); r.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", r.Code, r.Body.String())
	}
	uploaded = f.jobStatus(requeued).UnsignedObjectKey.String
	f.setJob(requeued, "heartbeat_at=?,claimed_at=?", time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(-time.Hour))
	if result := f.s.reapBuildJobs(t.Context(), time.Now().UTC()); len(result.Requeued) != 1 {
		t.Fatalf("reap: %+v", result)
	}
	if exists(uploaded) || f.jobStatus(requeued).UnsignedObjectKey.Valid {
		t.Fatal("a requeued build kept the delivery of the abandoned claim")
	}
	leftover := "tenants/" + f.tenant + "/build-jobs/" + requeued + "/a1/leftover/sbom.cdx.json"
	f.store.put(leftover, []byte("{}"), "e")
	f.setJob(requeued, "sbom_object_key=?", leftover)
	job := f.claimBuild()
	if job["id"] != requeued || exists(leftover) || f.jobStatus(requeued).SBOMObjectKey.Valid {
		t.Fatalf("re-claiming did not delete the previous claim's object: %v", job["id"])
	}
	f.deliverBuild(job)
	built := f.jobStatus(requeued)

	// 签名闸暂不能签：交回的包删掉，未签名包与 SBOM 留着给下一次签
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	f.signAndUpload(requeued, 1, "11.1.0", 1110)
	signedKey := f.jobStatus(requeued).SignedObjectKey.String
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+requeued+"/release", f.primary.Token, attemptHeaders(signAttemptHeader, 1), map[string]any{"code": "NOT_CONFIRMED", "detail": "x"}); r.Code != http.StatusNoContent {
		t.Fatalf("release: %d %s", r.Code, r.Body.String())
	}
	if exists(signedKey) || !exists(built.UnsignedObjectKey.String) || !exists(built.SBOMObjectKey.String) {
		t.Fatal("a deferred signing must drop only the signed package")
	}
	// 重新签名认领时清掉行上残留的已签名包（先越过暂不能签的冷却期）
	f.ageSignOutcome(requeued)
	stale := "tenants/" + f.tenant + "/build-jobs/" + requeued + "/s1/stale/app-release.apk"
	f.store.put(stale, []byte("signed"), "e")
	f.setJob(requeued, "signed_object_key=?", stale)
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign again")
	}
	if exists(stale) || f.jobStatus(requeued).SignedObjectKey.Valid {
		t.Fatal("a new signing claim kept the previous claim's signed package")
	}
	// 临时错误（没到上限）：只删已签名包
	f.signAndUpload(requeued, 2, "11.1.0", 1110)
	signedKey = f.jobStatus(requeued).SignedObjectKey.String
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+requeued+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 2), map[string]any{"kind": "transient", "code": "NETWORK", "detail": "x"}); r.Code != http.StatusNoContent {
		t.Fatalf("transient: %d %s", r.Code, r.Body.String())
	}
	if exists(signedKey) || !exists(built.UnsignedObjectKey.String) {
		t.Fatal("a transient rejection must drop only the signed package")
	}
	// 违规：全部删掉。删除失败不挡状态
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign a third time")
	}
	f.signAndUpload(requeued, 3, "11.1.0", 1110)
	f.store.deleteErr = errors.New("access denied")
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+requeued+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 3), map[string]any{"kind": "violation", "code": "POLICY", "detail": "x"}); r.Code != http.StatusNoContent {
		t.Fatalf("violation with a failing delete: %d %s", r.Code, r.Body.String())
	}
	f.store.deleteErr = nil
	rejected := f.jobStatus(requeued)
	if rejected.Status != jobFailed || rejected.UnsignedObjectKey.Valid || rejected.SBOMObjectKey.Valid || rejected.SignedObjectKey.Valid {
		t.Fatalf("a violation must fail the job and drop every delivery key even when storage refuses: %+v", rejected)
	}

	// 取消 built、强制判失败 signing：交付全部删掉
	canceled := f.queueBuild("11.2.0", 1120)
	f.deliverBuild(f.claimBuild())
	cancelKeys := f.jobStatus(canceled)
	c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds/"+canceled+"/cancel", map[string]any{"reason": "not needed", "confirm": true})
	c.Params = append(c.Params, ginParam("id", canceled))
	f.s.cancelBuildJob(c)
	if recorder.Code != http.StatusOK || exists(cancelKeys.UnsignedObjectKey.String) || exists(cancelKeys.SBOMObjectKey.String) {
		t.Fatalf("cancel: %d %s", recorder.Code, recorder.Body.String())
	}
	forced := f.queueBuild("11.3.0", 1130)
	f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign for force-fail")
	}
	f.signAndUpload(forced, f.jobStatus(forced).SignAttempt, "11.3.0", 1130)
	forceKeys := f.jobStatus(forced)
	c, recorder = testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds/"+forced+"/force-fail", map[string]any{"reason": "signer is stuck", "confirm": true})
	c.Params = append(c.Params, ginParam("id", forced))
	f.s.forceFailBuildJob(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("force-fail: %d %s", recorder.Code, recorder.Body.String())
	}
	for _, key := range []string{forceKeys.UnsignedObjectKey.String, forceKeys.SBOMObjectKey.String, forceKeys.SignedObjectKey.String} {
		if key == "" || exists(key) {
			t.Fatalf("force-fail kept %q", key)
		}
	}
}

// 签名认领不会被排在前面、长期不就绪的租户饿死：候选按租户取各自最小的在途任务，不截前 N 条。
func TestDBSignClaimIsNotStarvedByTenantsThatAreNotReady(t *testing.T) {
	f := newGateFixture(t, 104)
	ready := []map[string]any{}
	past := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < 60; i++ {
		tenant := testTenant(200 + i)
		slug := "starve-" + tenant
		if _, err := f.db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`, tenant, slug); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(`INSERT INTO build_jobs(id,tenant_id,platform,kind,git_ref,version,build_number,status,log_tail,reason,created_by,created_at,updated_at)
			VALUES(?,?,'android','apk','main','1.0.0',?,'built',JSON_ARRAY(),'starvation','tester',?,?)`, "bld_starve"+strconv.Itoa(i)+uniqueSuffix(), tenant, 1+i, past, past); err != nil {
			t.Fatal(err)
		}
		// 签名闸说这些租户就绪（它本机确认过），但服务端这边它们没有签名密钥，派不出去
		ready = append(ready, map[string]any{"tenantSlug": slug, "packageName": "com.starve.app", "certificateSha256": strings.Repeat("a", 64), "trustRootsDigest": strings.Repeat("b", 64)})
	}
	jobID := f.queueBuild("12.0.0", 1200)
	f.deliverBuild(f.claimBuild())
	ready = append(ready, f.readyItem())
	claimed := f.claimSign(f.primary, ready...)
	if claimed == nil || claimed["job"].(map[string]any)["id"] != jobID {
		t.Fatalf("the ready tenant was starved by 60 older candidates that cannot be dispatched: %v", claimed)
	}
}

// 签名闸每轮都会报一遍检查结论：没变就不写库、不加 version。
func TestDBUnchangedKeystoreChecksAreNotRewritten(t *testing.T) {
	f := newGateFixture(t, 105)
	version := func() (int, string) {
		var v int
		var updatedAt time.Time
		if err := f.db.QueryRow(`SELECT version,updated_at FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreCheckConfigKey).Scan(&v, &updatedAt); err != nil {
			t.Fatal(err)
		}
		return v, updatedAt.String()
	}
	before, beforeAt := version()
	for i := 0; i < 3; i++ {
		f.reportCheck(f.primary, true, "ok")
	}
	if after, afterAt := version(); after != before || afterAt != beforeAt {
		t.Fatalf("an unchanged check was rewritten: version %d -> %d", before, after)
	}
	f.reportCheck(f.primary, true, "pending")
	if after, _ := version(); after != before+1 {
		t.Fatalf("a changed check was not written: version %d -> %d", before, after)
	}
}

// "暂不能签"之后冷却：冷却期内同一台签名闸领不到这条任务，别的签名闸照常能领，冷却过了再派回来。
func TestDBDeferredSigningCoolsDownForThatSignerOnly(t *testing.T) {
	f := newGateFixture(t, 106)
	jobID := f.queueBuild("13.0.0", 1300)
	f.deliverBuild(f.claimBuild())
	release := func(machine gateMachine, attempt int) {
		t.Helper()
		if r := f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/release", machine.Token, attemptHeaders(signAttemptHeader, attempt),
			map[string]any{"code": "TENANT_NOT_CONFIRMED", "detail": "not confirmed here"}); r.Code != http.StatusNoContent {
			t.Fatalf("release: %d %s", r.Code, r.Body.String())
		}
	}
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	release(f.primary, 1)
	for i := 0; i < 3; i++ {
		if claimed := f.claimSign(f.primary); claimed != nil {
			t.Fatalf("the signer that just deferred got the job back inside the cooldown: %v", claimed["job"])
		}
	}
	if job := f.jobStatus(jobID); job.SignAttempt != 1 || job.Status != jobBuilt {
		t.Fatalf("the cooldown must not burn sign attempts: %+v", job)
	}
	// 另一台签名闸（切成主）不受这台的冷却影响
	f.writeMachines(f.builder.record(""), f.primary.record(signerRoleStandby), f.standby.record(signerRolePrimary))
	f.reportCheck(f.standby, true, "ok")
	claimed := f.claimSign(f.standby)
	if claimed == nil || claimed["job"].(map[string]any)["id"] != jobID {
		t.Fatalf("another signer was blocked by the first signer's cooldown: %v", claimed)
	}
	release(f.standby, 2)
	if again := f.claimSign(f.standby); again != nil {
		t.Fatalf("the second signer got the job back inside its own cooldown: %v", again["job"])
	}
	f.ageSignOutcome(jobID)
	if after := f.claimSign(f.standby); after == nil || after["job"].(map[string]any)["signAttempt"] != float64(3) {
		t.Fatalf("the job was not dispatched again after the cooldown: %v", after)
	}
}

// build.keystore 记录用不了（只改了外层索引、外层解不开、记录本身损坏）：控制台照常返回、标成
// 不就绪并给出 KEYSTORE_RECORD_INVALID；排队 409 SIGNER_NOT_READY；签名闸检查接口不下发这个租户。
func TestDBUnusableKeystoreRecordIsANotReadyProblem(t *testing.T) {
	f := newGateFixture(t, 107)
	var original []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreConfigKey).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corruptions := map[string]func(){
		"outer certificate changed": func() {
			f.setKeystoreValue(`JSON_SET(config_value,'$.certificateSha256',?)`, strings.Repeat("e", 64))
		},
		"outer box cannot be opened": func() {
			f.setKeystoreValue(`JSON_SET(config_value,'$.sealed',?)`, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		"record malformed": func() {
			f.setKeystoreValue(`JSON_SET(config_value,'$.unexpected',?)`, "field")
		},
	}
	for name, corrupt := range corruptions {
		f.setKeystoreValue(`?`, string(original))
		corrupt()
		c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
		f.s.getBuildKeystore(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: GET build-keystore %d %s", name, recorder.Code, recorder.Body.String())
		}
		view := decodeBody(t, recorder)
		if view["configured"] != true || view["ready"] != false || !strings.Contains(recorder.Body.String(), `"code":"KEYSTORE_RECORD_INVALID"`) {
			t.Fatalf("%s: view %s", name, recorder.Body.String())
		}
		c, recorder = testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": "14.0.0", "buildNumber": 1400, "reason": "corrupt keystore", "confirm": true,
			"releaseNotes": map[string]any{"zh-CN": []string{"测试"}},
		})
		f.s.createBuildJob(c)
		if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "SIGNER_NOT_READY" || !strings.Contains(recorder.Body.String(), "KEYSTORE_RECORD_INVALID") {
			t.Fatalf("%s: queue %d %s", name, recorder.Code, recorder.Body.String())
		}
		checks := f.do(http.MethodGet, "/v1/signer/keystore-checks", f.primary.Token, nil, nil)
		if checks.Code != http.StatusOK || strings.Contains(checks.Body.String(), `"tenantSlug":"`+f.slug+`"`) {
			t.Fatalf("%s: the signer was sent an unusable keystore: %d %s", name, checks.Code, checks.Body.String())
		}
	}
	f.setKeystoreValue(`?`, string(original))
	if checks := f.do(http.MethodGet, "/v1/signer/keystore-checks", f.primary.Token, nil, nil); !strings.Contains(checks.Body.String(), `"tenantSlug":"`+f.slug+`"`) {
		t.Fatalf("the restored keystore is not sent to the signer: %s", checks.Body.String())
	}
}

// 吊销的机器认得出自己被吊销：401 MACHINE_REVOKED（令牌查无仍是 MACHINE_AUTH_REQUIRED）；
// 吊销签名闸时主备角色清空。
func TestDBRevokedMachinesAreToldTheyAreRevoked(t *testing.T) {
	f := newGateFixture(t, 108)
	unknown := newGateMachine(t, machineRoleBuilder, "unknown")
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", unknown.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusUnauthorized || problemCode(t, r) != "MACHINE_AUTH_REQUIRED" {
		t.Fatalf("an unknown token: %d %s", r.Code, r.Body.String())
	}
	revoke := func(id string) map[string]any {
		t.Helper()
		r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+id+"/revoke", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "retired", "confirm": true})
		if r.Code != http.StatusOK {
			t.Fatalf("revoke %s: %d %s", id, r.Code, r.Body.String())
		}
		return decodeBody(t, r)["machine"].(map[string]any)
	}
	if view := revoke(f.primary.ID); view["status"] != machineStatusRevoked || view["signerRole"] != nil {
		t.Fatalf("a revoked signer kept its signer role: %v", view)
	}
	revoke(f.builder.ID)
	for name, r := range map[string]*httptest.ResponseRecorder{
		"signer":                        f.do(http.MethodPost, "/v1/signer/claim", f.primary.Token, nil, map[string]any{"ready": []any{f.readyItem()}}),
		"builder":                       f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}),
		"builder on the signer channel": f.do(http.MethodGet, "/v1/signer/keystore-checks", f.builder.Token, nil, nil),
	} {
		if r.Code != http.StatusUnauthorized || problemCode(t, r) != "MACHINE_REVOKED" {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	// 切换主备之后登记里只有一条 primary
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+f.standby.ID+"/signer-role", map[string]any{
		"signerRole": "primary", "expectedVersion": registryVersion(t, f), "reason": "promote", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("promote: %d %s", r.Code, r.Body.String())
	}
	primaries := 0
	for _, item := range decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil))["items"].([]any) {
		if item.(map[string]any)["signerRole"] == signerRolePrimary {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("%d machines are listed as primary after revoking the old primary and promoting the standby", primaries)
	}
}

// 签名闸每轮检查上报都带本机角色：服务端记进登记（只在变化时写），控制台上的主签名闸本机不是主
// （从未上报、仍是备）时不就绪，是主时就绪。缺了 localRole 是 400。
func TestDBSignerLocalRoleIsRecordedAndChecked(t *testing.T) {
	f := newGateFixture(t, 109)
	keystoreVersion, _ := f.keystoreVersions()
	item := map[string]any{"tenantSlug": f.slug, "keystoreVersion": keystoreVersion, "decrypt": "ok", "confirmed": true,
		"confirmedTrustRootsDigest": f.currentDigest(), "trialSign": "ok", "error": nil}
	report := func(body map[string]any) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/signer/keystore-checks", f.primary.Token, nil, body)
	}
	for name, body := range map[string]map[string]any{
		"missing":  {"items": []any{item}},
		"null":     {"localRole": nil, "items": []any{item}},
		"unknown":  {"localRole": "leader", "items": []any{item}},
		"no items": {"items": []any{}},
	} {
		if r := report(body); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_KEYSTORE_CHECK" {
			t.Fatalf("localRole %s: %d %s", name, r.Code, r.Body.String())
		}
	}
	codes := func() []string {
		t.Helper()
		r, err := f.s.signerReadinessFor(t.Context(), f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, p := range r.Problems {
			out = append(out, p.Code)
		}
		return out
	}
	primaryView := func() map[string]any {
		t.Helper()
		for _, entry := range decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil))["items"].([]any) {
			if view := entry.(map[string]any); view["id"] == f.primary.ID {
				return view
			}
		}
		t.Fatal("the primary is not listed")
		return nil
	}

	// 从未上报
	unreported := f.primary.record(signerRolePrimary)
	unreported.ReportedLocalRole, unreported.ReportedLocalRoleAt = "", ""
	f.writeMachines(f.builder.record(""), unreported, f.standby.record(signerRoleStandby))
	if got := codes(); strings.Join(got, ",") != readinessPrimaryLocalRole {
		t.Fatalf("a primary that never reported its local role: %v", got)
	}
	if view := primaryView(); view["reportedLocalRole"] != nil || view["reportedLocalRoleAt"] != nil {
		t.Fatalf("view of an unreported local role: %v", view)
	}
	// 本机仍是备
	if r := report(map[string]any{"localRole": "standby", "trust": f.localTrust(), "items": []any{item}}); r.Code != http.StatusNoContent {
		t.Fatalf("report standby: %d %s", r.Code, r.Body.String())
	}
	if got := codes(); strings.Join(got, ",") != readinessPrimaryLocalRole {
		t.Fatalf("a primary whose local record says standby: %v", got)
	}
	view := primaryView()
	if view["reportedLocalRole"] != "standby" || view["reportedLocalRoleAt"] == nil {
		t.Fatalf("view after a standby report: %v", view)
	}
	c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds", map[string]any{
		"platform": "android", "gitRef": "main", "version": "15.0.0", "buildNumber": 1500, "reason": "local role", "confirm": true,
		"releaseNotes": map[string]any{"zh-CN": []string{"测试"}},
	})
	f.s.createBuildJob(c)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), readinessPrimaryLocalRole) {
		t.Fatalf("queueing while the primary is locally a standby: %d %s", recorder.Code, recorder.Body.String())
	}
	// 同一个值再报不写库
	version := registryVersion(t, f)
	for i := 0; i < 3; i++ {
		if r := report(map[string]any{"localRole": "standby", "trust": f.localTrust(), "items": []any{item}}); r.Code != http.StatusNoContent {
			t.Fatalf("repeat report: %d %s", r.Code, r.Body.String())
		}
	}
	if after := registryVersion(t, f); after != version {
		t.Fatalf("an unchanged local role bumped the registry version %d -> %d", version, after)
	}
	// 本机 promote 之后是主：就绪
	if r := report(map[string]any{"localRole": "primary", "trust": f.localTrust(), "items": []any{item}}); r.Code != http.StatusNoContent {
		t.Fatalf("report primary: %d %s", r.Code, r.Body.String())
	}
	if after := registryVersion(t, f); after != version+1 {
		t.Fatalf("a changed local role must be written once: version %d -> %d", version, after)
	}
	if got := codes(); len(got) != 0 {
		t.Fatalf("a primary that reports primary locally: %v", got)
	}
	if view := primaryView(); view["reportedLocalRole"] != "primary" {
		t.Fatalf("view after a primary report: %v", view)
	}
	var audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=0 AND action='build_machine_local_role_report' AND target_id=?`, f.primary.ID).Scan(&audits)
	if audits != 2 {
		t.Fatalf("local role changes audited %d times, want 2", audits)
	}
}
