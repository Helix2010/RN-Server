package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 状态表本身：每条边只引用已知状态；终态没有出边；可取消的是 queued/claimed/running/built，
// 能强制判失败的只有 signing；在途集合与迁移 54 的生成列一致。
func TestBuildJobTransitionTable(t *testing.T) {
	for _, transition := range buildJobTransitions {
		for _, status := range append(append([]string{}, transition.From...), transition.To...) {
			if !containsString(buildJobStatuses, status) {
				t.Fatalf("%s references unknown status %q", transition.Event, status)
			}
		}
		for _, from := range transition.From {
			if containsString(buildJobTerminalStatuses, from) {
				t.Fatalf("%s leaves the terminal status %s", transition.Event, from)
			}
		}
	}
	if got := buildJobEventFrom(eventAdminCancel, jobKindAPK); strings.Join(got, ",") != "queued,claimed,running,built" {
		t.Fatalf("cancelable apk statuses: %v", got)
	}
	if got := buildJobEventFrom(eventAdminCancel, jobKindOTA); strings.Join(got, ",") != "queued,claimed,running" {
		t.Fatalf("cancelable ota statuses: %v", got)
	}
	if got := buildJobEventFrom(eventAdminForceFail, ""); strings.Join(got, ",") != "signing" {
		t.Fatalf("force-failable statuses: %v", got)
	}
	if buildJobTransitionAllowed(eventSignerClaim, jobKindOTA, jobBuilt) || buildJobTransitionAllowed(eventBuilderBuilt, jobKindOTA, jobRunning) {
		t.Fatal("OTA jobs must never enter the signing stages")
	}
	if sqlInFlight != "'queued','claimed','running','built','signing'" {
		t.Fatalf("in-flight statuses: %s", sqlInFlight)
	}
	// 每个非终态都至少有一条出边，否则任务会永远卡在那里
	for _, status := range buildJobStatuses {
		if containsString(buildJobTerminalStatuses, status) {
			continue
		}
		leaves := false
		for _, transition := range buildJobTransitions {
			if containsString(transition.From, status) && !(len(transition.To) == 1 && transition.To[0] == status) {
				leaves = true
			}
		}
		if !leaves {
			t.Fatalf("status %s has no way out", status)
		}
	}
}

// 每个非法转移都是 409。对每个会改状态或要求状态的接口，把任务摆到它不允许的每一个状态上
// （编号与机器都对得上，所以 409 只能是因为状态），再从允许的状态里挑一个证明接口本身是通的。
func TestDBEveryIllegalBuildJobTransitionIsAConflict(t *testing.T) {
	f := newGateFixture(t, 71)
	jobID := f.queueBuild("7.0.0", 700)
	// 已签名包的键摆上一个（完成要求本次签名认领交回过包），对象不在存储里：允许的状态上完成会
	// 因为读不到包而失败，但不是 409
	place := func(status string) {
		f.setJob(jobID, `status=?,attempt=1,claimed_machine_id=?,sign_attempt=1,sign_failures=0,signing_machine_id=?,
			unsigned_object_key=NULL,unsigned_size=NULL,unsigned_sha256=NULL,sbom_sha256=NULL,release_id=NULL,artifact_sha256=NULL,
			signed_object_key=?`,
			status, f.builder.ID, f.primary.ID, "tenants/"+f.tenant+"/build-jobs/"+jobID+"/s1/placed/app-release.apk")
	}
	type operation struct {
		name  string
		event string
		call  func() *httptest.ResponseRecorder
	}
	builder := attemptHeaders(buildAttemptHeader, 1)
	signer := attemptHeaders(signAttemptHeader, 1)
	adminCall := func(action string) func() *httptest.ResponseRecorder {
		return func() *httptest.ResponseRecorder {
			c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds/"+jobID+"/"+action, map[string]any{"reason": "transition table", "confirm": true})
			c.Params = append(c.Params, ginParam("id", jobID))
			if action == "cancel" {
				f.s.cancelBuildJob(c)
			} else {
				f.s.forceFailBuildJob(c)
			}
			return recorder
		}
	}
	operations := []operation{
		{"builder heartbeat", eventBuilderHeartbeat, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", f.builder.Token, builder, map[string]any{"logTail": []string{}})
		}},
		{"builder fail", eventBuilderFail, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/fail", f.builder.Token, builder, map[string]any{"failureReason": "x", "commitSha": "", "logTail": []string{}})
		}},
		{"builder upload", eventBuilderUpload, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPut, "/v1/build-agent/jobs/"+jobID+"/sbom/upload", f.builder.Token, builder, []byte(`{"bomFormat":"CycloneDX"}`))
		}},
		{"admin cancel", eventAdminCancel, adminCall("cancel")},
		{"admin force-fail", eventAdminForceFail, adminCall("force-fail")},
		{"signer heartbeat", eventSignerHeartbeat, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/heartbeat", f.primary.Token, signer, nil)
		}},
		{"signer upload", eventSignerUpload, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPut, "/v1/signer/jobs/"+jobID+"/signed/upload", f.primary.Token, signer, []byte("signed"))
		}},
		{"signer release", eventSignerRelease, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/release", f.primary.Token, signer, map[string]any{"code": "NOT_CONFIRMED", "detail": "x"})
		}},
		{"signer violation", eventSignerViolation, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/reject", f.primary.Token, signer, map[string]any{"kind": "violation", "code": "POLICY", "detail": "x"})
		}},
		{"signer transient", eventSignerTransient, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/reject", f.primary.Token, signer, map[string]any{"kind": "transient", "code": "NETWORK", "detail": "x"})
		}},
		{"signer complete", eventSignerComplete, func() *httptest.ResponseRecorder {
			return f.do(http.MethodPost, "/v1/signer/jobs/"+jobID+"/complete", f.primary.Token, signer, map[string]any{
				"signedSha256": strings.Repeat("1", 64), "signedSize": 10, "certificateSha256": f.apkSigner.sha256(),
				"unsignedSha256": strings.Repeat("2", 64), "nativeFingerprint": gateNativeFingerprint})
		}},
	}
	for _, op := range operations {
		allowed := buildJobEventFrom(op.event, jobKindAPK)
		for _, status := range buildJobStatuses {
			place(status)
			recorder := op.call()
			if containsString(allowed, status) {
				// 允许的状态上不能是 409（可能是别的校验失败，例如完成时文件不在存储里）
				if recorder.Code == http.StatusConflict {
					t.Fatalf("%s from %s is allowed but got 409 %s", op.name, status, recorder.Body.String())
				}
				continue
			}
			if recorder.Code != http.StatusConflict {
				t.Fatalf("%s from %s must be 409, got %d %s", op.name, status, recorder.Code, recorder.Body.String())
			}
		}
	}
	// 心跳从 claimed 真的能走通：证明上面的 409 不是因为接口本身坏了
	place(jobClaimed)
	if r := operations[0].call(); r.Code != http.StatusNoContent {
		t.Fatalf("a legal heartbeat: %d %s", r.Code, r.Body.String())
	}
	place(jobBuilt)
	if r := adminCall("cancel")(); r.Code != http.StatusOK || f.jobStatus(jobID).Status != jobCanceled {
		t.Fatalf("canceling a built job: %d %s", r.Code, r.Body.String())
	}
}

// 所有按状态判断的地方覆盖新状态：列表筛选、搜索、下限、回收、手工上传门禁。
func TestDBStatusDrivenQueriesKnowTheSigningStates(t *testing.T) {
	f := newGateFixture(t, 72)
	jobID := f.queueBuild("8.0.0", 800)
	f.setJob(jobID, "status='signing',claimed_machine_id=?,signing_machine_id=?,signing_heartbeat_at=?", f.builder.ID, f.primary.ID, time.Now().UTC())
	for _, status := range []string{"built", "signing"} {
		c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/builds?status="+status, nil)
		f.s.listBuildJobs(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("filtering by %s: %d %s", status, recorder.Code, recorder.Body.String())
		}
	}
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/builds?status=signing", nil)
	f.s.listBuildJobs(c)
	items := decodeBody(t, recorder)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["status"] != jobSigning {
		t.Fatalf("signing filter: %v", items)
	}
	// 租户控制台看不到机器，也不能按机器 id 搜出任务（试探机器名）
	for _, query := range []string{f.primary.ID, f.builder.ID} {
		c, recorder = testContext(t, f.tenant, http.MethodGet, "/v1/admin/builds?q="+query, nil)
		f.s.listBuildJobs(c)
		if got := decodeBody(t, recorder)["items"].([]any); len(got) != 0 {
			t.Fatalf("searching by machine id %s: %v", query, got)
		}
	}
	c, recorder = testContext(t, f.tenant, http.MethodGet, "/v1/admin/builds?status=pending", nil)
	f.s.listBuildJobs(c)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown status filter: %d", recorder.Code)
	}
	// 签名中的任务回收只看签名心跳，不看构建心跳
	f.setJob(jobID, "heartbeat_at=?", time.Now().UTC().Add(-time.Hour))
	if result := f.s.reapBuildJobs(context.Background(), time.Now().UTC()); len(result.Requeued)+len(result.Failed)+len(result.SignBack)+len(result.SignFailed) != 0 {
		t.Fatalf("a signing job with a fresh signing heartbeat was reaped: %+v", result)
	}
	// markBuildJobFailed 只改认领那一刻的任务
	f.s.markBuildJobFailed(context.Background(), f.jobStatus(jobID), "should not apply")
	if f.jobStatus(jobID).Status != jobSigning {
		t.Fatal("markBuildJobFailed touched a signing job")
	}
}

// 运行中的任务可以取消，而且取消之后构建机真的会停：它下一次心跳拿到 409 BUILD_ATTEMPT_STALE
// （打包机据此给执行进程发 SIGTERM，见 cmd/build-agent/agent.go runJob），交付也一样是 409。
func TestDBCancelingARunningBuildStopsTheBuilderAtItsNextHeartbeat(t *testing.T) {
	f := newGateFixture(t, 73)
	jobID := f.queueBuild("7.3.0", 730)
	f.setJob(jobID, `status='running',attempt=1,claimed_machine_id=?`, f.builder.ID)

	c, recorder := testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds/"+jobID+"/cancel", map[string]any{"reason": "pnpm install hung", "confirm": true})
	c.Params = append(c.Params, ginParam("id", jobID))
	f.s.cancelBuildJob(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("canceling a running build: %d %s", recorder.Code, recorder.Body.String())
	}
	if status := f.jobStatus(jobID).Status; status != jobCanceled {
		t.Fatalf("status after cancel = %s", status)
	}
	builder := attemptHeaders(buildAttemptHeader, 1)
	heartbeat := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/heartbeat", f.builder.Token, builder, map[string]any{"logTail": []string{}})
	if heartbeat.Code != http.StatusConflict || !strings.Contains(heartbeat.Body.String(), "BUILD_ATTEMPT_STALE") {
		t.Fatalf("the builder's next heartbeat must tell it to stop: %d %s", heartbeat.Code, heartbeat.Body.String())
	}
	fail := f.do(http.MethodPost, "/v1/build-agent/jobs/"+jobID+"/fail", f.builder.Token, builder, map[string]any{"failureReason": "x", "commitSha": "", "logTail": []string{}})
	if fail.Code != http.StatusConflict {
		t.Fatalf("a canceled build must not be reported over: %d %s", fail.Code, fail.Body.String())
	}
	if status := f.jobStatus(jobID).Status; status != jobCanceled {
		t.Fatalf("status changed after cancel: %s", status)
	}
}

// 平台控制台「打包机与签名闸」看机器手上的任务：租户控制台看不到是哪台机器领的
// （设计 service-and-console-split-2026-09-27 §5）。签名中的算签名闸的，认领、构建中的算构建机的。
func TestDBMachineListShowsCurrentJobs(t *testing.T) {
	f := newGateFixture(t, 73)
	jobID := f.queueBuild("8.1.0", 810)
	currentJobs := func(machineID string) []any {
		t.Helper()
		r := f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil)
		if r.Code != http.StatusOK {
			t.Fatalf("machines: %d %s", r.Code, r.Body.String())
		}
		for _, raw := range decodeBody(t, r)["items"].([]any) {
			if item := raw.(map[string]any); item["id"] == machineID {
				return item["currentJobs"].([]any)
			}
		}
		t.Fatalf("machine %s is missing", machineID)
		return nil
	}
	f.setJob(jobID, "status='claimed',claimed_machine_id=?", f.builder.ID)
	if jobs := currentJobs(f.builder.ID); len(jobs) != 1 || jobs[0].(map[string]any)["id"] != jobID || jobs[0].(map[string]any)["tenantId"] != f.tenant {
		t.Fatalf("builder jobs = %v", jobs)
	}
	f.setJob(jobID, "status='signing',signing_machine_id=?,signing_heartbeat_at=?", f.primary.ID, time.Now().UTC())
	if jobs := currentJobs(f.primary.ID); len(jobs) != 1 || jobs[0].(map[string]any)["status"] != jobSigning {
		t.Fatalf("signer jobs = %v", jobs)
	}
	if jobs := currentJobs(f.builder.ID); len(jobs) != 0 {
		t.Fatalf("the builder no longer holds a job being signed: %v", jobs)
	}
}
