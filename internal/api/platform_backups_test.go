package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func backupServer(t *testing.T) *server {
	t.Helper()
	db := openTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatalf("清掉上一轮的记录: %v", err)
	}
	return &server{db: db}
}

func mustCreate(t *testing.T, s *server, reason string) backupRun {
	t.Helper()
	run, err := s.createBackupRun(context.Background(), "manual", "tester", reason)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return run
}

// 已有在途时再建必须是 errBackupInFlight，调用方据此翻 409。
// 冒成普通错误的话控制台上看到的是「服务器错误」而不是「已经有一条在跑」
func TestDBSecondBackupRequestIsInFlightNotAnError(t *testing.T) {
	s := backupServer(t)
	first := mustCreate(t, s, "first")

	_, err := s.createBackupRun(context.Background(), "manual", "tester", "second")
	if !errors.Is(err, errBackupInFlight) {
		t.Fatalf("第二条必须是 errBackupInFlight（好翻 409），得到：%v", err)
	}
	// 409 要能告诉运维是哪一条占着——他没有别的出口
	live, err := s.liveBackupRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if live.ID != first.ID || live.Status != backupStatusPending {
		t.Fatalf("在途那条应当是第一条：%+v", live)
	}
}

// 并发建：只有一条成功，其余全是 errBackupInFlight，不能有别的错误类型漏出来
func TestDBConcurrentCreateYieldsExactlyOneRun(t *testing.T) {
	s := backupServer(t)
	const n = 6
	var wg sync.WaitGroup
	results := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, results[i] = s.createBackupRun(context.Background(), "manual", "tester", "race")
		}(i)
	}
	wg.Wait()

	created, inFlight := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, errBackupInFlight):
			inFlight++
		default:
			t.Fatalf("意料之外的错误（会变成 500）：%v", err)
		}
	}
	if created != 1 || inFlight != n-1 {
		t.Fatalf("应当恰好一条成功、其余在途：created=%d inFlight=%d", created, inFlight)
	}
}

// 并发认领：只有一个拿到。两个都拿到的话，两边都会去解开全部租户的签名密钥、
// 打 tar、上传——损害在 409 之前就发生了
func TestDBConcurrentClaimGivesTheRunToExactlyOneAgent(t *testing.T) {
	s := backupServer(t)
	mustCreate(t, s, "claim race")

	const n = 5
	var wg sync.WaitGroup
	claimed := make([]bool, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, err := s.claimBackupRun(context.Background(), "builder")
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			claimed[i] = ok
		}(i)
	}
	wg.Wait()

	count := 0
	for _, ok := range claimed {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("应当恰好一个打包机认领成功，得到 %d", count)
	}
}

// 没有待办时认领返回 (false, nil)，不是错误——打包机每 10 秒问一次，
// 每次都记一条 error 会把日志淹掉，然后没人再看它
func TestDBClaimWithNothingPendingIsNotAnError(t *testing.T) {
	s := backupServer(t)
	_, ok, err := s.claimBackupRun(context.Background(), "builder")
	if err != nil || ok {
		t.Fatalf("空队列应当是 (false, nil)，得到 (%v, %v)", ok, err)
	}
}

// 超时扫描先判了 failed，之后姗姗来迟的收尾**不能**把它翻成 succeeded。
// 没有 CAS 的话，一条本该 failed 的记录会变成 succeeded 而 failure_reason 还留着
func TestDBFinishingAfterTheReaperGaveUpChangesNothing(t *testing.T) {
	s := backupServer(t)
	run := mustCreate(t, s, "late finish")
	if _, _, err := s.claimBackupRun(context.Background(), "builder"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.failBackupRun(context.Background(), run.ID, "reaped"); err != nil || !ok {
		t.Fatalf("判死失败: ok=%v err=%v", ok, err)
	}

	ok, err := s.finishBackupRun(context.Background(), run.ID,
		[]backupObject{{Pair: "AB", ObjectKey: "k", SHA256: "s", SizeBytes: 1}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("对一条已经判死的记录收尾竟然成功了：CAS 没起作用")
	}
	after, err := s.backupRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != backupStatusFailed || len(after.Objects) != 0 {
		t.Fatalf("已经判死的记录被改写了：%+v", after)
	}
}

// 反过来：已经 succeeded 之后迟到的 /fail 不能把它翻回去
func TestDBFailingAfterSuccessChangesNothing(t *testing.T) {
	s := backupServer(t)
	run := mustCreate(t, s, "late fail")
	if _, _, err := s.claimBackupRun(context.Background(), "builder"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.finishBackupRun(context.Background(), run.ID, []backupObject{{Pair: "AB"}}, 3); err != nil || !ok {
		t.Fatalf("收尾失败: ok=%v err=%v", ok, err)
	}
	ok, err := s.failBackupRun(context.Background(), run.ID, "agent gave up")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("对一条已经成功的记录判死竟然成功了")
	}
}

// 认领超时只看 created_at，产出超时只看 COALESCE(payload_received_at, claimed_at)。
// 判据里不许有任何内存状态——回滚窗口里停在 running 的那条，滚回新版本之后
// 这个扫描必须自己收拾掉，否则它永久占着 live_slot，此后每次备份都 409
func TestDBReaperJudgesPurelyFromTimeColumns(t *testing.T) {
	s := backupServer(t)
	ctx := context.Background()

	// 一条超时未被认领的 pending
	stale := mustCreate(t, s, "stale pending")
	if _, err := s.db.Exec(`UPDATE platform_backups SET created_at=? WHERE id=?`,
		time.Now().UTC().Add(-backupClaimTimeout-time.Minute), stale.ID); err != nil {
		t.Fatal(err)
	}
	n, err := s.reapBackupRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("超时的 pending 应当被判死一条，得到 %d", n)
	}
	after, _ := s.backupRunByID(ctx, stale.ID)
	if after.Status != backupStatusFailed || after.FailureReason == "" {
		t.Fatalf("判死要带可读原因：%+v", after)
	}

	// 一条认领了但半路没了的 running：payload_received_at 仍是 NULL，
	// 所以按 claimed_at 算——「只传上来一份就断了」落在这一条里
	half := mustCreate(t, s, "half done")
	if _, _, err := s.claimBackupRun(ctx, "builder"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE platform_backups SET claimed_at=? WHERE id=?`,
		time.Now().UTC().Add(-backupProduceTimeout-time.Minute), half.ID); err != nil {
		t.Fatal(err)
	}
	if n, err = s.reapBackupRuns(ctx); err != nil || n != 1 {
		t.Fatalf("卡住的 running 应当被判死：n=%d err=%v", n, err)
	}

	// 刚建的那条不该被碰
	fresh := mustCreate(t, s, "fresh")
	if n, err = s.reapBackupRuns(ctx); err != nil || n != 0 {
		t.Fatalf("新鲜的记录不该被判死：n=%d err=%v", n, err)
	}
	if got, _ := s.backupRunByID(ctx, fresh.ID); got.Status != backupStatusPending {
		t.Fatalf("新鲜的记录状态被改了：%s", got.Status)
	}
}

// payload 到齐之后时钟才往后推，此后产出超时按新的时间算
func TestDBPayloadCompletionPushesTheProduceDeadline(t *testing.T) {
	s := backupServer(t)
	ctx := context.Background()
	run := mustCreate(t, s, "payload clock")
	if _, _, err := s.claimBackupRun(ctx, "builder"); err != nil {
		t.Fatal(err)
	}
	// 认领时间推到很早，但 payload 刚刚到齐
	if _, err := s.db.Exec(`UPDATE platform_backups SET claimed_at=? WHERE id=?`,
		time.Now().UTC().Add(-backupProduceTimeout-time.Minute), run.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.markBackupPayloadComplete(ctx, run.ID); err != nil || !ok {
		t.Fatalf("标记 payload 到齐失败: ok=%v err=%v", ok, err)
	}
	n, err := s.reapBackupRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("payload 刚到齐就被判死了：产出超时没有用 COALESCE(payload_received_at, claimed_at)")
	}
}

// 连续失败次数是推导出来的，不是某个计数器列。加计数器要在四个写方里同步维护，
// 而它随时可能和实际记录对不上，那时分不清是真的连挂了还是计数器坏了
func TestDBConsecutiveFailuresAreDerivedFromTheRows(t *testing.T) {
	s := backupServer(t)
	ctx := context.Background()
	finishOne := func(status string) {
		run := mustCreate(t, s, status)
		if _, _, err := s.claimBackupRun(ctx, "builder"); err != nil {
			t.Fatal(err)
		}
		var err error
		if status == backupStatusSucceeded {
			_, err = s.finishBackupRun(ctx, run.ID, nil, 3)
		} else {
			_, err = s.failBackupRun(ctx, run.ID, "nope")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	finishOne(backupStatusFailed)
	finishOne(backupStatusSucceeded)
	finishOne(backupStatusFailed)
	finishOne(backupStatusFailed)

	count, err := s.consecutiveBackupFailures(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("最近一条 succeeded 之后有 2 次失败，得到 %d", count)
	}
}

// 定时的「到点了吗」由库回答，不是进程里的 ticker 相位。
// ticker 的相位从进程启动算起：24 小时间隔 + 每天一次部署 = 一次都不会跑，
// 而控制台上「上次成功时间」一直是空的，没人会把它和部署节奏联系起来
func TestDBLastScheduledBackupComesFromTheDatabase(t *testing.T) {
	s := backupServer(t)
	ctx := context.Background()
	at, err := s.lastScheduledBackupAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !at.IsZero() {
		t.Fatal("一条定时记录都没有时应当返回零值")
	}
	if _, err := s.createBackupRun(ctx, "schedule", backupScheduleActor, backupScheduleReason); err != nil {
		t.Fatal(err)
	}
	at, err = s.lastScheduledBackupAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if at.IsZero() {
		t.Fatal("建了定时记录之后应当返回它的时间")
	}
}
