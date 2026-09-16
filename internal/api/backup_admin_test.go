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
	s.cfg = withBackupRecipients(t, config.Config{})
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
	s.cfg = withBackupRecipients(t, config.Config{})
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
	s.cfg = withBackupRecipients(t, config.Config{
		AdminPasswordHash: testAdminPasswordHash,
		Backup:            config.Backup{Bucket: config.BackupBucket{Bucket: "b"}},
	})
	first := mustCreate(t, s, "already running")

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/run",
		map[string]any{"reason": "please run one now", "confirm": true,
			"password": testAdminPassword})
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
	s.cfg = withBackupRecipients(t, config.Config{AdminPasswordHash: testAdminPasswordHash})
	c, recorder := testContext(t, platformTenantID, "POST", "/x",
		map[string]any{"reason": "try it anyway", "confirm": true,
			"password": testAdminPassword})
	s.runBackupNow(c)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("没配备份时应当 412，得到 %d", recorder.Code)
	}
}

// 下载：未知 seq、未知 pair 都要 404，且**不产生任何对象读**
func TestDBDownloadRefusesUnknownSeqAndPair(t *testing.T) {
	s := backupServer(t)
	s.cfg = withBackupRecipients(t, config.Config{})
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
// 控制台是从**租户域名**提供的，备份页必须能从那里访问。
//
// 这条是一次真实故障的回归测试：设计 §6 要求「对平台组关掉 tenant_domain 回退」，
// 我照做了，结果任何生产部署上这一页都必然 403——因为备份页就挂在那个租户控制台
// 里（平台管理员多看见几个菜单而已），而生产的 CORS_ORIGINS 按设计就是空的
// （deploy/amos/rn-foundation.env.example:94：「租户控制台的来源已由 tenant_domain
// 表推导，不必再列一遍」）。关掉回退等于关掉控制台自己。
//
// 真正的授权边界是 requirePlatformAdmin：要有已登录会话、且操作者在平台管理员
// 白名单里。Origin 这一层挡的是「别的站点拿你的 cookie 跨源读走响应」。
func TestDBBackupRoutesAllowTheConsoleServedFromATenantDomain(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(61)
	slug := "origin-" + uniqueSuffix()
	domain := slug + ".example.com"
	if _, err := db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at)
		VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		tenant, slug); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at)
		VALUES(?,?,1,'active',0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`, tenant, domain); err != nil {
		t.Fatal(err)
	}

	s := &server{db: db, tenant: newTenantResolver(db)}
	gate := s.requireBackupSameOrigin()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("GET", "/v1/admin/platform/backup", nil)
	c.Request.Host = "api.example"
	c.Request.Header.Set("Origin", "https://"+domain)
	gate(c)
	if c.IsAborted() {
		t.Fatalf("控制台所在的租户域名被挡下了（%d）——这一页在生产上就打不开了", recorder.Code)
	}

	// 但一个解析不出来的域名仍然要挡下
	recorder2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(recorder2)
	c2.Request = httptest.NewRequest("GET", "/v1/admin/platform/backup", nil)
	c2.Request.Host = "api.example"
	c2.Request.Header.Set("Origin", "https://not-a-tenant.example")
	gate(c2)
	if !c2.IsAborted() {
		t.Error("一个不属于任何租户的来源不该放行")
	}
}

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
		// 没有租户解析器时解析不出来，所以挡下。带解析器的情形见下面那条测试
		{"解析不出的域名", "https://api.acme.example", "api.example", true},
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
	cfg := withBackupRecipients(t, config.Config{Backup: config.Backup{
		InstanceID: "test-1", IntervalHours: 24,
		Bucket: config.BackupBucket{Bucket: "b", Region: "r"},
	}})
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

// 恢复之后必须把每个租户的校验结果作废：待验清单会跳过「这一版已经验过」的租户，
// 而恢复场景里数据库一个字都没动——于是控制台显示「正常」，看的却是灾难前那台
// 机器写下的记录，真相要等到第一次构建才暴露
func TestDBResetKeystoreChecksClearsEveryTenantRecord(t *testing.T) {
	s := backupServer(t)
	s.cfg = withBackupRecipients(t, config.Config{})
	ctx := context.Background()
	for _, tenant := range []string{"100000001", "100000002"} {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
			 VALUES(?,?,'{"version":1,"ok":true}',1,'test',UTC_TIMESTAMP(3))
			 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
			tenant, buildKeystoreCheckConfigKey); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = s.db.Exec(`DELETE FROM app_configs WHERE config_key=?`, buildKeystoreCheckConfigKey)
	})

	c, recorder := testContext(t, platformTenantID, "POST",
		"/v1/admin/platform/build-agent/keystore-checks/reset",
		map[string]any{"reason": "restored onto a new build machine", "confirm": true})
	s.resetKeystoreChecks(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("重置应当成功: %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if int(body["cleared"].(float64)) < 2 {
		t.Fatalf("两个租户的记录都该被清掉: %v", body)
	}
	var left int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_configs WHERE config_key=?`, buildKeystoreCheckConfigKey).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("还剩 %d 条校验记录没清", left)
	}
}

// 没有 confirm 或原因太短时不执行：这条动作会让全平台的密钥状态一起变成「待验」
func TestDBResetKeystoreChecksNeedsConfirmAndReason(t *testing.T) {
	s := backupServer(t)
	s.cfg = withBackupRecipients(t, config.Config{})
	for _, body := range []map[string]any{
		{"reason": "restored onto a new build machine"},
		{"confirm": true},
		{"reason": "x", "confirm": true},
	} {
		c, recorder := testContext(t, platformTenantID, "POST", "/x", body)
		s.resetKeystoreChecks(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%v 应当被拒绝，得到 %d", body, recorder.Code)
		}
	}
}
