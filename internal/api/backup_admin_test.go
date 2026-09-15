package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

// 逃生口：SIGKILL 换二进制之后记录停在 running、闸被占，运维必须有一个动作
// 能把它收掉。没有它的话 30 分钟内一次备份都做不了，而他手上什么都做不了
func TestDBForceFailFreesTheInFlightSlot(t *testing.T) {
	s := backupServer(t)
	s.cfg = config.Config{}
	run := mustCreate(t, s, "stuck")
	if _, _, err := s.claimBackupRun(context.Background(), "builder"); err != nil {
		t.Fatal(err)
	}
	// 闸被占着，再建必须撞 409
	if _, err := s.createBackupRun(context.Background(), "manual", "tester", "again"); err == nil {
		t.Fatal("闸应当是占着的")
	}

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/1/force-fail",
		map[string]any{"reason": "the agent was SIGKILLed during a binary swap", "confirm": true})
	c.Params = gin.Params{{Key: "seq", Value: itoa(run.Seq)}}
	s.forceFailBackup(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("强制判失败应当成功: %d %s", recorder.Code, recorder.Body.String())
	}
	// 收掉之后立刻能建下一条
	if _, err := s.createBackupRun(context.Background(), "manual", "tester", "after force-fail"); err != nil {
		t.Fatalf("强制判失败之后闸应当放开: %v", err)
	}
}

// 强制判失败对一条已经结束的记录要 409，不能把 succeeded 翻回去
func TestDBForceFailRefusesAFinishedBackup(t *testing.T) {
	s := backupServer(t)
	s.cfg = config.Config{}
	run := mustCreate(t, s, "done")
	if _, _, err := s.claimBackupRun(context.Background(), "builder"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.finishBackupRun(context.Background(), run.ID, nil, 1); err != nil {
		t.Fatal(err)
	}
	c, recorder := testContext(t, platformTenantID, "POST", "/x",
		map[string]any{"reason": "changed my mind about this one", "confirm": true})
	c.Params = gin.Params{{Key: "seq", Value: itoa(run.Seq)}}
	s.forceFailBackup(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("对已经结束的记录应当 409，得到 %d", recorder.Code)
	}
}

// 409 必须带上占着闸那条的 seq——运维没有别的出口去看是哪一条
func TestDBRunNowTellsYouWhichBackupIsHoldingTheSlot(t *testing.T) {
	s := backupServer(t)
	s.cfg = config.Config{Backup: config.Backup{Bucket: config.BackupBucket{Bucket: "b"}}}
	first := mustCreate(t, s, "already running")

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/run",
		map[string]any{"reason": "please run one now", "confirm": true})
	s.runBackupNow(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("应当 409，得到 %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if body["seq"] == nil {
		t.Fatalf("409 必须带上占着闸那条的 seq: %v", body)
	}
	if int(body["seq"].(float64)) != int(first.Seq) {
		t.Fatalf("seq 不对: %v", body)
	}
}

// 备份没配就不该能点。返回 412 而不是建一条注定失败的待办
func TestDBRunNowRefusesWhenBackupsAreNotConfigured(t *testing.T) {
	s := backupServer(t)
	s.cfg = config.Config{}
	c, recorder := testContext(t, platformTenantID, "POST", "/x",
		map[string]any{"reason": "try it anyway", "confirm": true})
	s.runBackupNow(c)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("没配备份时应当 412，得到 %d", recorder.Code)
	}
}

// 下载：未知 seq、未知 pair 都要 404，且**不产生任何对象读**
func TestDBDownloadRefusesUnknownSeqAndPair(t *testing.T) {
	s := backupServer(t)
	s.cfg = config.Config{}
	run := mustCreate(t, s, "for download")
	if _, _, err := s.claimBackupRun(context.Background(), "builder"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.finishBackupRun(context.Background(), run.ID,
		[]backupObject{{Pair: "AB", ObjectKey: "k/ab", SHA256: "s", SizeBytes: 1}}, 1); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		seq, pair string
		want      int
	}{
		{"999999", "AB", http.StatusNotFound},
		{itoa(run.Seq), "AC", http.StatusNotFound}, // 这一次只产出了 AB
		{"0", "AB", http.StatusBadRequest},
		{"../etc", "AB", http.StatusBadRequest},
	} {
		c, recorder := testContext(t, platformTenantID, "GET", "/x", nil)
		c.Params = gin.Params{{Key: "seq", Value: tc.seq}, {Key: "pair", Value: tc.pair}}
		s.downloadBackup(c)
		if recorder.Code != tc.want {
			t.Fatalf("seq=%s pair=%s 期望 %d，得到 %d", tc.seq, tc.pair, tc.want, recorder.Code)
		}
	}
}

// 跨源请求必须被挡下。authenticate 的 Origin 闸只管非安全方法，而 originAllowed
// 会回落去查 tenant_domain 表——不补的话，「谁能读平台备份」由那张表决定
func TestBackupRoutesRefuseCrossOriginButAllowSameOrigin(t *testing.T) {
	s := &server{cfg: config.Config{CORSOrigins: []string{"https://console.example"}}}
	gate := s.requireBackupSameOrigin()

	cases := []struct {
		name, origin, host string
		blocked            bool
	}{
		{"没有 Origin（同源 GET）", "", "api.example", false},
		{"同源", "https://api.example", "api.example", false},
		{"显式允许的控制台", "https://console.example", "api.example", false},
		{"租户域名", "https://api.acme.example", "api.example", true},
		{"完全无关的站点", "https://evil.example", "api.example", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest("GET", "/v1/admin/platform/backup", nil)
			c.Request.Host = tc.host
			if tc.origin != "" {
				c.Request.Header.Set("Origin", tc.origin)
			}
			gate(c)
			if tc.blocked && recorder.Code != http.StatusForbidden {
				t.Fatalf("应当被挡下，得到 %d", recorder.Code)
			}
			if !tc.blocked && c.IsAborted() {
				t.Fatalf("不该被挡下: %d", recorder.Code)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("备份响应必须 no-store，得到 %q", got)
			}
		})
	}
}

// 到点了没有由**库**回答，不是 ticker 的相位。相位从进程启动算起，
// 24 小时间隔 + 每天一次部署 = 一次都不会跑
func TestDBSchedulerDecidesFromTheDatabaseNotTheTickerPhase(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backup: config.Backup{
		InstanceID: "test-1", IntervalHours: 24,
		Bucket: config.BackupBucket{Bucket: "b", Region: "r"},
	}}
	scheduler := NewBackupScheduler(cfg, db)
	ctx := context.Background()

	// 第一次：库里一条定时记录都没有 → 应当建一条
	scheduler.maybeSchedule(ctx)
	runs, err := scheduler.server.listBackupRuns(ctx, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("第一次应当建一条，得到 %d 条 (%v)", len(runs), err)
	}
	if runs[0].TriggerBy != "schedule" || runs[0].Reason != backupScheduleReason {
		t.Fatalf("定时触发的 trigger_by/reason 不对: %+v", runs[0])
	}

	// 立刻再跑一轮：还没到点，而且闸也占着——都不该再建
	scheduler.maybeSchedule(ctx)
	runs, _ = scheduler.server.listBackupRuns(ctx, 10)
	if len(runs) != 1 {
		t.Fatalf("没到点不该再建，得到 %d 条", len(runs))
	}

	// 把那条结掉并让它「看起来是 25 小时前建的」→ 到点了，应当再建一条。
	// 这一步就是在模拟「进程重启了很多次」：判据只看库，不看进程活了多久
	if _, err := db.Exec(`UPDATE platform_backups SET status='succeeded', created_at=? WHERE seq=?`,
		time.Now().UTC().Add(-25*time.Hour), runs[0].Seq); err != nil {
		t.Fatal(err)
	}
	scheduler.maybeSchedule(ctx)
	runs, _ = scheduler.server.listBackupRuns(ctx, 10)
	if len(runs) != 2 {
		t.Fatalf("到点了应当再建一条，得到 %d 条", len(runs))
	}
}

// 间隔为 0 = 关闭定时，只留手动
func TestDBSchedulerDoesNothingWhenTheIntervalIsZero(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	scheduler := NewBackupScheduler(config.Config{Backup: config.Backup{
		InstanceID: "test-1", IntervalHours: 0, Bucket: config.BackupBucket{Bucket: "b"},
	}}, db)
	scheduler.maybeSchedule(context.Background())
	runs, _ := scheduler.server.listBackupRuns(context.Background(), 10)
	if len(runs) != 0 {
		t.Fatalf("关掉定时之后不该有任何记录，得到 %d 条", len(runs))
	}
}

func itoa(seq uint64) string { return strconv.FormatUint(seq, 10) }
