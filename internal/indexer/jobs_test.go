package indexer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

func addJob(t *testing.T, store *memStore, job scan.Job) {
	t.Helper()
	if _, err := store.MutateJobs(context.Background(), "op-sepolia", func(jobs []scan.Job) ([]scan.Job, error) {
		return append(jobs, job), nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRescanJobRestoresRowsWithoutMovingTheCursor(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBlocks)
	for number := uint64(11); number <= 20; number++ {
		chain.mine(number)
	}
	chain.transfer(12, tokenUSDC, carol, alice, 1_500_000, 3)
	chain.mine(21, rpcTx{From: carol, To: alice, Value: "0x64"})
	chain.mine(22)
	chain.mine(23)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	if len(store.rows) != 2 {
		t.Fatalf("rows = %+v", store.rows)
	}
	// 模拟丢了记录（比如误删），管理端建重扫任务；区间超出已确认块的部分要等追上
	store.rows = nil
	addJob(t, store, scan.Job{ID: "job_rescan", Kind: scan.JobRescan, FromBlock: 11, ToBlock: 30, ProgressBlock: 10, State: scan.JobPending, CreatedBy: "ops", Reason: "test", CreatedAt: time.Now()})

	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("job round: %v", err)
	}
	if len(store.rows) != 2 {
		t.Fatalf("rescan must restore both rows, got %+v", store.rows)
	}
	state := store.states["op-sepolia"]
	if state.ScannedToBlock != 21 {
		t.Fatalf("rescan must not move the cursor: %d", state.ScannedToBlock)
	}
	if len(state.Jobs) != 1 || state.Jobs[0].State != scan.JobRunning || state.Jobs[0].ProgressBlock != 21 {
		t.Fatalf("job must wait for the cursor beyond 21: %+v", state.Jobs)
	}
	// 链头推进到 30 以上：任务收尾、移出数组、写审计
	for number := uint64(24); number <= 32; number++ {
		chain.mine(number)
	}
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("final round: %v", err)
	}
	if jobs := store.states["op-sepolia"].Jobs; len(jobs) != 0 {
		t.Fatalf("finished job must be removed: %+v", jobs)
	}
	if !containsAudit(store.audits, "chain_scan.job_done") {
		t.Fatalf("audits = %v", store.audits)
	}
	// 重扫是幂等的：同一笔不重复
	if len(store.rows) != 2 {
		t.Fatalf("rows after final round = %+v", store.rows)
	}
}

func TestAttributeJobReplacesUnattributedRowsWithLocatedTransfers(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBalance)
	for number := uint64(11); number <= 20; number++ {
		chain.mine(number)
	}
	chain.setBalance(alice, 0, 0)
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("first round: %v", err)
	}
	// 大缺口：区块 60 有一笔 700 的普通转账，其余 299 是合约内部转账（全区块也扫不到）
	for number := uint64(21); number <= 120; number++ {
		if number == 60 {
			chain.mine(number, rpcTx{From: carol, To: alice, Value: "0x2bc"})
			continue
		}
		chain.mine(number)
	}
	chain.setBalance(alice, 60, 999)
	// 先把任务预算关掉，看余额轮只记差额、建任务
	worker.jobBudget = 0
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("second round: %v", err)
	}
	if len(store.rows) != 1 || store.rows[0].Attribution != "unattributed" || store.rows[0].AmountRaw != "999" {
		t.Fatalf("rows after balance round = %+v", store.rows)
	}
	if jobs := store.states["op-sepolia"].Jobs; len(jobs) != 1 || jobs[0].State != scan.JobPending {
		t.Fatalf("jobs = %+v", jobs)
	}
	// 第三轮没有新块，只跑任务：定位到 700，未归属余额降到 299
	worker.jobBudget = jobBudget
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("job round: %v", err)
	}
	var located, unattributed int
	for _, row := range store.rows {
		switch row.Attribution {
		case "tx":
			located++
			if row.AmountRaw != "700" || row.BlockNumber != 60 || row.Counterparty != carol {
				t.Fatalf("located row = %+v", row)
			}
		default:
			unattributed++
			if row.AmountRaw != "299" {
				t.Fatalf("remainder row = %+v", row)
			}
		}
	}
	if located != 1 || unattributed != 1 {
		t.Fatalf("located=%d unattributed=%d rows=%+v", located, unattributed, store.rows)
	}
	if jobs := store.states["op-sepolia"].Jobs; len(jobs) != 0 {
		t.Fatalf("finished attribute job must be removed: %+v", jobs)
	}
	if !containsAudit(store.audits, "chain_scan.job_done") {
		t.Fatalf("audits = %v", store.audits)
	}
}

func TestCancelledJobStopsAndSaveStateDoesNotResurrectIt(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBlocks)
	for number := uint64(11); number <= 23; number++ {
		chain.mine(number)
	}
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	addJob(t, store, scan.Job{ID: "job_a", Kind: scan.JobRescan, FromBlock: 11, ToBlock: 15, ProgressBlock: 10, State: scan.JobPending, CreatedBy: "ops", CreatedAt: time.Now()})
	// worker 已把上一轮的状态（不含 job_a）留在内存里；管理端刚建的任务不能被 SaveState 抹掉
	if err := worker.save(context.Background()); err != nil {
		t.Fatal(err)
	}
	if jobs := store.states["op-sepolia"].Jobs; len(jobs) != 1 {
		t.Fatalf("SaveState must leave jobs alone: %+v", jobs)
	}
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("job round: %v", err)
	}
	if jobs := store.states["op-sepolia"].Jobs; len(jobs) != 0 {
		t.Fatalf("job within confirmed range must finish in one round: %+v", jobs)
	}
}

func TestJobFailureIsRecordedAndAlerted(t *testing.T) {
	chain, store, worker := setup(t, scan.NativeModeBlocks)
	for number := uint64(11); number <= 23; number++ {
		chain.mine(number)
	}
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round: %v", err)
	}
	var notified []string
	worker.WithNotifier(func(_ context.Context, chain string, alert scan.Alert, resolved bool) error {
		notified = append(notified, string(alert.Kind)+"/"+map[bool]string{false: "raised", true: "resolved"}[resolved])
		return nil
	})
	addJob(t, store, scan.Job{ID: "job_bad", Kind: scan.JobKind("bogus"), FromBlock: 11, ToBlock: 15, ProgressBlock: 10, State: scan.JobPending, CreatedBy: "ops", CreatedAt: time.Now()})
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round with bad job must not fail the round: %v", err)
	}
	jobs := store.states["op-sepolia"].Jobs
	if len(jobs) != 1 || jobs[0].State != scan.JobFailed || !strings.Contains(jobs[0].LastError, "bogus") {
		t.Fatalf("jobs = %+v", jobs)
	}
	if alert := openAlert(store, scan.AlertJobFailed); alert == nil || alert.WebhookSentAt == nil {
		t.Fatalf("job_failed alert must be open and sent: %+v", store.states["op-sepolia"].OpenAlerts)
	}
	if len(notified) != 1 || notified[0] != "job_failed/raised" {
		t.Fatalf("notified = %v", notified)
	}
	// 管理端取消失败任务后告警恢复
	if _, err := store.MutateJobs(context.Background(), "op-sepolia", func([]scan.Job) ([]scan.Job, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := worker.Round(context.Background()); err != nil {
		t.Fatalf("round after cancel: %v", err)
	}
	if alert := openAlert(store, scan.AlertJobFailed); alert != nil {
		t.Fatalf("alert must resolve once the failed job is gone: %+v", alert)
	}
	if len(notified) != 2 || notified[1] != "job_failed/resolved" {
		t.Fatalf("notified = %v", notified)
	}
}

func TestWebhookNotifierPostsSlackCompatibleJSON(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(415)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	notify := WebhookNotifier(server.URL, server.Client())
	raised := time.Date(2026, 9, 6, 5, 0, 0, 0, time.UTC)
	if err := notify(context.Background(), "monad", scan.Alert{Kind: scan.AlertStalled, Message: "all endpoints unavailable", RaisedAt: raised}, false); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "[chain-scan][ALERT] monad stalled: all endpoints unavailable" || got["chain"] != "monad" || got["kind"] != "stalled" || got["raisedAt"] != "2026-09-06T05:00:00Z" || got["resolved"] != false {
		t.Fatalf("payload = %v", got)
	}
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer failing.Close()
	if err := WebhookNotifier(failing.URL, failing.Client())(context.Background(), "monad", scan.Alert{Kind: scan.AlertStalled}, true); err == nil {
		t.Fatal("non-2xx must surface as an error")
	}
}

func openAlert(store *memStore, kind scan.AlertKind) *scan.Alert {
	state := store.states["op-sepolia"]
	return state.Alert(kind)
}

func containsAudit(audits []string, action string) bool {
	for _, item := range audits {
		if item == action {
			return true
		}
	}
	return false
}
