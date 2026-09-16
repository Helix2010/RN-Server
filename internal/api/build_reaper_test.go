package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// 回收规则：构建心跳超时的安装包任务退回排队，第 3 次认领之后判失败；热更新任务直接判失败；
// 签名心跳超时退回待签名并计一次签名失败，到 2 判失败；心跳还新鲜的一概不动。
func TestDBReaperRules(t *testing.T) {
	f := newGateFixture(t, 81)
	now := time.Now().UTC()
	stale := now.Add(-11 * time.Minute)
	fresh := now.Add(-time.Minute)
	insert := func(kind, status string, build int, set string, args ...any) string {
		t.Helper()
		id := "bld_reap" + uniqueSuffix() + randomID(4)
		if _, err := f.db.Exec(`INSERT INTO build_jobs(id,tenant_id,platform,kind,base_release_id,channel,apply_strategy,git_ref,version,build_number,status,log_tail,reason,created_by,created_at,updated_at)
			VALUES(?,?,'android',?,?,?,?,'main','1.0.0',?,?,JSON_ARRAY(),'reaper test','tester',?,?)`,
			id, f.tenant, kind, nullIfAPK(kind, "rel_base"), nullIfAPK(kind, "production"), nullIfAPK(kind, "next_launch"), build, status, now, now); err != nil {
			t.Fatal(err)
		}
		f.setJob(id, set, args...)
		return id
	}
	firstAttempt := insert("apk", jobRunning, 901, "attempt=1,claimed_machine_id=?,claimed_at=?,heartbeat_at=?", f.builder.ID, stale, stale)
	lastAttempt := insert("apk", jobClaimed, 902, "attempt=3,claimed_machine_id=?,claimed_at=?,heartbeat_at=?", f.builder.ID, stale, stale)
	otaStale := insert("ota", jobRunning, 903, "attempt=1,claimed_machine_id=?,claimed_at=?,heartbeat_at=?", f.builder.ID, stale, stale)
	stillBuilding := insert("apk", jobRunning, 904, "attempt=1,claimed_machine_id=?,claimed_at=?,heartbeat_at=?", f.builder.ID, stale, fresh)
	signBack := insert("apk", jobSigning, 905, "sign_attempt=1,sign_failures=0,signing_machine_id=?,signing_claimed_at=?,signing_heartbeat_at=?", f.primary.ID, stale, now.Add(-6*time.Minute))
	signFail := insert("apk", jobSigning, 906, "sign_attempt=2,sign_failures=1,signing_machine_id=?,signing_claimed_at=?,signing_heartbeat_at=?", f.primary.ID, stale, now.Add(-6*time.Minute))
	stillSigning := insert("apk", jobSigning, 907, "sign_attempt=1,signing_machine_id=?,signing_claimed_at=?,signing_heartbeat_at=?", f.primary.ID, stale, now.Add(-4*time.Minute))
	waiting := insert("apk", jobBuilt, 908, "updated_at=?", now.Add(-24*time.Hour))

	result := f.s.reapBuildJobs(context.Background(), now)
	expect := func(id, status string) buildJob {
		t.Helper()
		job := f.jobStatus(id)
		if job.Status != status {
			t.Fatalf("job %s: %s, want %s (%+v)", id, job.Status, status, result)
		}
		return job
	}
	requeued := expect(firstAttempt, jobQueued)
	if requeued.Attempt != 1 || requeued.ClaimedMachineID.String != f.builder.ID || requeued.HeartbeatAt.Valid {
		t.Fatalf("a requeued job keeps its attempt and last claimer, and loses its heartbeat: %+v", requeued)
	}
	if failed := expect(lastAttempt, jobFailed); !failed.FailureReason.Valid {
		t.Fatal("a job that ran out of attempts has no failure reason")
	}
	expect(otaStale, jobFailed)
	expect(stillBuilding, jobRunning)
	back := expect(signBack, jobBuilt)
	var outcome buildJobSignOutcome
	if back.SignFailures != 1 || json.Unmarshal(back.SignOutcome, &outcome) != nil || outcome.Kind != "transient" || outcome.Code != "SIGNER_HEARTBEAT_TIMEOUT" || outcome.MachineID != f.primary.ID {
		t.Fatalf("a signing job whose signer went silent: failures=%d outcome=%s", back.SignFailures, back.SignOutcome)
	}
	if exhausted := expect(signFail, jobFailed); exhausted.SignFailures != 2 {
		t.Fatalf("sign failures after the second timeout: %d", exhausted.SignFailures)
	}
	expect(stillSigning, jobSigning)
	expect(waiting, jobBuilt)
	if len(result.Requeued) != 1 || len(result.Failed) != 2 || len(result.SignBack) != 1 || len(result.SignFailed) != 1 {
		t.Fatalf("reap result: %+v", result)
	}
	// 第二轮什么都不做：条件更新不会把同一条再处理一次
	if again := f.s.reapBuildJobs(context.Background(), now); len(again.Requeued)+len(again.Failed)+len(again.SignBack)+len(again.SignFailed) != 0 {
		t.Fatalf("a second round reaped again: %+v", again)
	}
	var audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action IN ('build_job_requeued','build_job_reaped','build_job_sign_failed')`, f.tenant).Scan(&audits)
	if audits != 4 {
		t.Fatalf("reaper audit events: %d", audits)
	}
}

func nullIfAPK(kind, value string) any {
	if kind == jobKindAPK {
		return nil
	}
	return value
}

// 重排上限走完整条路：认领 → 心跳停 → 回收重排，三次之后判失败，号放出来。
func TestDBReaperRequeuesAtMostTwice(t *testing.T) {
	f := newGateFixture(t, 82)
	jobID := f.queueBuild("9.0.0", 900)
	for attempt := 1; attempt <= maxBuildAttempts; attempt++ {
		job := f.claimBuild()
		if job["id"] != jobID || job["attempt"] != float64(attempt) {
			t.Fatalf("claim %d: %v", attempt, job)
		}
		f.setJob(jobID, "claimed_at=?,heartbeat_at=?", time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(-time.Hour))
		f.s.reapBuildJobs(context.Background(), time.Now().UTC())
	}
	if job := f.jobStatus(jobID); job.Status != jobFailed || job.Attempt != maxBuildAttempts {
		t.Fatalf("after %d silent claims: %s attempt=%d", maxBuildAttempts, job.Status, job.Attempt)
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusNoContent {
		t.Fatalf("a failed job was dispatched again: %d %s", r.Code, r.Body.String())
	}
	// 号放出来了：同一个 build 号可以重新排
	f.queueBuild("9.0.0", 900)
}

// 回收循环：启动就跑一轮，之后按间隔跑，上下文结束就退出。
func TestBuildJobReaperLoopRunsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	const interval = 10 * time.Millisecond
	var rounds atomic.Int32
	var deadlineMissing atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		runReaperLoop(ctx, interval, func(roundCtx context.Context) {
			// 每一轮的 ctx 必须有期限且不超过一个周期：一轮卡住不能叠到下一轮上
			if deadline, ok := roundCtx.Deadline(); !ok || time.Until(deadline) > interval {
				deadlineMissing.Store(true)
			}
			rounds.Add(1)
		})
	}()
	deadline := time.After(5 * time.Second)
	for rounds.Load() < 3 {
		select {
		case <-deadline:
			t.Fatalf("the reaper loop ran %d rounds in 5 seconds", rounds.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper loop did not stop when its context ended")
	}
	if deadlineMissing.Load() {
		t.Fatal("a reaper round ran without a deadline of at most one interval")
	}
	stopped := rounds.Load()
	time.Sleep(3 * interval)
	if rounds.Load() != stopped {
		t.Fatal("the reaper loop kept running after it returned")
	}
}
