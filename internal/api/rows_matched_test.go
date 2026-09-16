package api

import (
	"net/http"
	"testing"
	"time"
)

// 同一毫秒里的两次写、SET 的值完全相同：MySQL 的 RowsAffected 是 0，而条件满足。rowsMatched 按条件复查，
// 在事务内外都分得清"没有变化"与"条件不满足"。时间用固定值，不靠机器快慢。
func TestDBRowsMatchedTellsUnchangedFromNotMatched(t *testing.T) {
	f := newGateFixture(t, 140)
	jobID := f.queueBuild("14.0.0", 1400)
	at := time.Date(2026, 9, 16, 12, 0, 0, 123_000_000, time.UTC)
	guard := `id=? AND status='queued'`
	exec := func() (bool, error) {
		result, err := f.db.Exec(`UPDATE build_jobs SET updated_at=? WHERE `+guard, at, jobID)
		if err != nil {
			t.Fatal(err)
		}
		return rowsMatched(t.Context(), f.db, result, "build_jobs", guard, jobID)
	}
	for i := 0; i < 3; i++ {
		if matched, err := exec(); err != nil || !matched {
			t.Fatalf("write #%d with the same values: matched=%v err=%v", i, matched, err)
		}
	}
	// 事务里：UPDATE 锁住了命中的行，复查读到的是最新值
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	result, err := tx.Exec(`UPDATE build_jobs SET updated_at=? WHERE `+guard, at, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := rowsMatched(t.Context(), tx, result, "build_jobs", guard, jobID); err != nil || !matched {
		t.Fatalf("an unchanged write in a transaction: matched=%v err=%v", matched, err)
	}
	_ = tx.Rollback()
	// 条件不满足：仍然是没命中
	wrong := `id=? AND status='running'`
	result, err = f.db.Exec(`UPDATE build_jobs SET updated_at=? WHERE `+wrong, at, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := rowsMatched(t.Context(), f.db, result, "build_jobs", wrong, jobID); err != nil || matched {
		t.Fatalf("a guard that does not hold: matched=%v err=%v", matched, err)
	}
}

// 构建机与签名闸在同一毫秒里重复心跳（日志尾部也相同）不是编号过期；编号真的不对时仍是 409。
// 签名完成前刷新心跳也走同一条路：心跳与完成落在同一毫秒时照样能完成。
func TestDBSameMillisecondHeartbeatsAreNotStale(t *testing.T) {
	f := newGateFixture(t, 141)
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 456_000_000, time.UTC)
	f.s.clock = func() time.Time { return fixed }
	f.queueBuild("14.1.0", 1410)
	job := f.claimBuild()
	id := job["id"].(string)
	attempt := int(job["attempt"].(float64))
	for i := 0; i < 3; i++ {
		r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/heartbeat", f.builder.Token, attemptHeaders(buildAttemptHeader, attempt), map[string]any{"logTail": []string{"gradle: assembling"}})
		if r.Code != http.StatusNoContent {
			t.Fatalf("builder heartbeat #%d in the same millisecond: %d %s", i, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/heartbeat", f.builder.Token, attemptHeaders(buildAttemptHeader, attempt+1), map[string]any{"logTail": []string{"gradle: assembling"}}); r.Code != http.StatusConflict || problemCode(t, r) != "BUILD_ATTEMPT_STALE" {
		t.Fatalf("a heartbeat with a stale attempt: %d %s", r.Code, r.Body.String())
	}
	if got := f.jobStatus(id); got.Status != jobRunning || !got.HeartbeatAt.Valid || !got.HeartbeatAt.Time.Equal(fixed) {
		t.Fatalf("job after same-millisecond heartbeats: status=%s heartbeat=%v", got.Status, got.HeartbeatAt)
	}

	delivered := f.deliverBuild(job)
	if claimed := f.claimSign(f.primary); claimed == nil {
		t.Fatal("the primary could not claim the build to sign")
	}
	headers := attemptHeaders(signAttemptHeader, 1)
	signed := f.signAndUpload(id, 1, "14.1.0", 1410)
	for i := 0; i < 3; i++ {
		if r := f.do(http.MethodPost, "/v1/signer/jobs/"+id+"/heartbeat", f.primary.Token, headers, nil); r.Code != http.StatusNoContent {
			t.Fatalf("signing heartbeat #%d in the same millisecond: %d %s", i, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+id+"/heartbeat", f.primary.Token, attemptHeaders(signAttemptHeader, 2), nil); r.Code != http.StatusConflict || problemCode(t, r) != "SIGN_ATTEMPT_STALE" {
		t.Fatalf("a signing heartbeat with a stale attempt: %d %s", r.Code, r.Body.String())
	}
	// 完成先刷新签名心跳：与上一次心跳同一毫秒
	complete := f.do(http.MethodPost, "/v1/signer/jobs/"+id+"/complete", f.primary.Token, headers, f.completeBody(signed, delivered.unsigned))
	if complete.Code != http.StatusOK {
		t.Fatalf("complete in the same millisecond as the last heartbeat: %d %s", complete.Code, complete.Body.String())
	}
}

// 管理端在同一毫秒里重复提交同一个值（自动化重试、双击）：第二次不是"状态已变"。
func TestDBRepeatedReleaseFlagInTheSameMillisecondIsNotAConflict(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	fixed := time.Date(2026, 9, 16, 12, 0, 1, 789_000_000, time.UTC)
	s.clock = func() time.Time { return fixed }
	tenant := testTenant(142)
	id := "rel_flag_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, id, "3.0.0", 300, "verified", nil, false)
	for i := 0; i < 2; i++ {
		if r := runReleaseAction(t, s, tenant, id, "set-mandatory", map[string]any{"reason": "force the upgrade", "confirm": true, "mandatory": true}); r.Code != http.StatusCreated {
			t.Fatalf("set-mandatory #%d in the same millisecond: %d %s", i, r.Code, r.Body.String())
		}
	}
}
