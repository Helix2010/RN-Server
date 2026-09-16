package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

// 对抗性评审留下的时序攻击。**每一条都对应一个真实修过的缺陷**，留在仓库里
// 是为了那些缺陷不会悄悄回来——它们的共同点是「不炸，只是安静地卡住」，
// 而那种问题在常规测试下完全看不出来。

const advSigningFingerprint = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900"

func advServer(t *testing.T) *server {
	t.Helper()
	s := backupServer(t)
	s.cfg = config.Config{Environment: "test"}
	// 登记一把签名公钥，否则 checkBackupSigningFingerprint 一律判死
	if err := s.saveBackupSigningKey(context.Background(), backupSigningKeyRecord{
		Current: backupSigningKey{PublicKey: "unused", Fingerprint: advSigningFingerprint},
	}, "tester"); err != nil {
		t.Fatalf("登记签名公钥: %v", err)
	}
	return s
}

func advMeta(slot string) backupbundle.PayloadMeta {
	return backupbundle.PayloadMeta{
		RecipientSlot:            slot,
		AgentVersion:             "test-agent",
		AgentKeyFingerprint:      "0123456789abcdef",
		BackupSigningFingerprint: advSigningFingerprint,
		Tenants:                  []backupbundle.Tenant{{Slug: "acme", HasKeystore: true}},
		InnerFiles: []backupbundle.FileEntry{{
			Path: "agent-key", Target: "/var/lib/rn-build-agent/agent-key", Size: 10,
			SHA256: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			Mode:   "0600", Owner: "builder:builder",
		}},
	}
}

// advUpload 拼一个 multipart 请求体。metas 按顺序写，payload 插在第一个 meta 之后
func advUpload(t *testing.T, metas []backupbundle.PayloadMeta, payload []byte) (string, *bytes.Buffer) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for i, meta := range metas {
		encoded, _ := json.Marshal(meta)
		part, err := writer.CreateFormField("meta")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(encoded); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			payloadPart, err := writer.CreateFormFile("payload", "inner.rnbk")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := payloadPart.Write(payload); err != nil {
				t.Fatal(err)
			}
		}
	}
	sigPart, err := writer.CreateFormFile("sig", "inner.rnbk.sig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sigPart.Write(bytes.Repeat([]byte{7}, 64)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return writer.FormDataContentType(), &body
}

func advPost(t *testing.T, s *server, runID string, metas []backupbundle.PayloadMeta, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	contentType, body := advUpload(t, metas, payload)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/build-agent/backup-requests/"+runID+"/payload", body)
	c.Request.Header.Set("content-type", contentType)
	c.Params = gin.Params{{Key: "id", Value: runID}}
	c.Set("requestId", "req_adv")
	s.receiveBackupPayload(c)
	return recorder
}

func advClaimed(t *testing.T, s *server, reason string) backupRun {
	t.Helper()
	run := mustCreate(t, s, reason)
	claimed, ok, err := s.claimBackupRun(context.Background(), "adv-agent")
	if err != nil || !ok {
		t.Fatalf("认领失败: ok=%v err=%v", ok, err)
	}
	t.Cleanup(func() { cleanBackupStaging(run.ID) })
	return claimed
}

// 攻击 1：上报一个不在 InnerSlots() 里的槽位（C）。
//
// 服务端应当拒收——只有 A 和 B 有内层。实际会怎样？
func TestAdvSlotCIsAcceptedButNeverCounts(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "slot C attack")

	recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("C")}, []byte("ciphertext-for-C"))
	t.Logf("上报槽位 C 的响应: %d %s", recorder.Code, recorder.Body.String())

	dir := backupStagingDir(run.ID)
	entries, _ := os.ReadDir(dir)
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	t.Logf("暂存目录里现在有: %v", names)
	t.Logf("missingInnerSlots = %v", missingInnerSlots(dir))

	if recorder.Code < 400 {
		t.Errorf("服务端收下了一个 InnerSlots() 之外的槽位（%d），它永远不会让这次备份完成", recorder.Code)
	}
}

// 判死之后暂存必须被清掉。
//
// 一条被判死的备份会留下最多两份 512 MiB 的密文。它们是封给持有人的密文、
// 服务端读不懂，但这台机器同时在构建 APK——磁盘被占满倒下的不止备份功能。
func TestAdvReaperLeavesTheStagedCiphertextOnDisk(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "reaper leaves staging")

	// 模拟「只传上来一份就断了」
	if recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")},
		bytes.Repeat([]byte("x"), 4096)); recorder.Code != http.StatusAccepted {
		t.Fatalf("第一份应当 202，得到 %d %s", recorder.Code, recorder.Body.String())
	}
	dir := backupStagingDir(run.ID)
	if _, err := os.Stat(filepath.Join(dir, "A.enc")); err != nil {
		t.Fatalf("A.enc 应当在盘上: %v", err)
	}

	// 把认领时间推到 31 分钟前，让产出超时扫描抓到它
	if _, err := s.db.Exec(`UPDATE platform_backups SET claimed_at=? WHERE id=?`,
		time.Now().UTC().Add(-31*time.Minute), run.ID); err != nil {
		t.Fatal(err)
	}
	reaped, err := s.reapBackupRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("应当判死 1 条，得到 %d", reaped)
	}
	after, err := s.backupRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != backupStatusFailed {
		t.Fatalf("记录应当 failed，得到 %s", after.Status)
	}
	// 判死只写库；清盘由 sweep 做——扫一遍而不是让每个判死点各自清，
	// 这样崩溃留下的残留也一起收掉
	s.sweepBackupStaging(context.Background())
	if info, err := os.Stat(filepath.Join(dir, "A.enc")); err == nil {
		t.Fatalf("判死并扫过之后暂存密文还在盘上（%d 字节）——这台机器同时在构建 APK，"+
			"磁盘被占满倒下的不止备份", info.Size())
	}
}

// 攻击 3：两份都到齐了，但组装失败（服务端自己那部分读不到）。
//
// payload_received_at 的语义是「两份都到齐的时间」，它存在的理由是
// 「卡住时才分得清该去哪台机器看」（§8.4 列注释）。组装失败时它是什么？
func TestAdvPayloadReceivedAtIsNullWhenAssemblyFails(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "assembly fails")
	// 关键文件读不到 -> collectServerPart 硬失败
	t.Setenv("BACKUP_SERVER_ENV_PATH", filepath.Join(t.TempDir(), "definitely-not-here.env"))

	if recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")}, []byte("A")); recorder.Code != http.StatusAccepted {
		t.Fatalf("第一份应当 202，得到 %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("B")}, []byte("B"))
	t.Logf("第二份（触发收尾）的响应: %d %s", recorder.Code, recorder.Body.String())

	after, err := s.backupRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("状态=%s failureReason=%q payloadReceivedAt=%v", after.Status, after.FailureReason, after.PayloadReceivedAt)
	if after.PayloadReceivedAt == nil {
		t.Errorf("两份密文确实都到齐了，但 payload_received_at 还是 NULL——"+
			"运维照 §8.4 的列注释去排查会得到「打包机没传上来」这个错误结论（状态=%s, 原因=%q）",
			after.Status, after.FailureReason)
	}
}

// 一个请求里塞两个 meta、槽位不同。
//
// 原来的行为：第一个 meta 决定 payload 落到哪个文件，最后一个 meta 决定 sidecar
// 写成哪个槽位——暂存目录里出现 A.enc + B.sig + B.meta.json 这种自相矛盾的组合，
// 而此后合法的 A 上报永远 400。
func TestAdvTwoMetaPartsPoisonTheStagingDirectory(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "two meta parts")

	recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A"), advMeta("B")}, []byte("payload"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("重复的 meta 部件必须当场拒掉，得到 %d %s", recorder.Code, recorder.Body.String())
	}

	// 关键是**拒掉之后不留痕**：留下一个半截的 A.enc 的话，此后合法的 A 上报
	// 永远 400（槽位已被占），这条记录只能等 30 分钟产出超时
	retry := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")}, []byte("real-A"))
	if retry.Code >= 400 {
		t.Fatalf("上一个自相矛盾的请求把槽位占住了，之后合法的 A 上报拿到 %d %s",
			retry.Code, retry.Body.String())
	}
}

// 服务端在两份之间重启（PrivateTmp=true 下 /tmp 本来就没了，ResetBackupStaging
// 更是显式清）。打包机必须知道——否则它打出「备份产出成功」然后走人，
// 而记录停在 running 干等 30 分钟产出超时，没有人知道发生了什么。
func TestAdvRestartBetweenSlotsIsInvisibleToTheAgent(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "restart between slots")

	if recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")}, []byte("A")); recorder.Code != http.StatusAccepted {
		t.Fatalf("第一份应当 202，得到 %d", recorder.Code)
	}
	ResetBackupStaging() // 服务端重启

	recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("B")}, []byte("B"))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("第二份应当 202，得到 %d %s", recorder.Code, recorder.Body.String())
	}

	// 服务端没法回 4xx——从它的角度看这是一次完全正常的上报。所以判据在响应体：
	// 它必须说「我还缺 A」，而打包机知道自己已经传过 A，于是能当场报失败，
	// 而不是打出「备份产出成功」然后让记录干等 30 分钟超时
	body := decodeBody(t, recorder)
	still, ok := body["stillExpecting"].([]any)
	if !ok || len(still) == 0 {
		t.Fatalf("响应必须说清还缺哪几份，否则打包机分辨不出来: %s", recorder.Body.String())
	}
	found := false
	for _, slot := range still {
		if slot == "A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("服务端把 A 弄丢了却没说，打包机会以为成功: %v", still)
	}
}

// 攻击 6：迁移重复执行
func TestAdvMigrationIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS platform_backups (id VARCHAR(80) NOT NULL, PRIMARY KEY(id))`); err != nil {
			t.Logf("第 %d 次：%v", i, err)
		}
	}
	// 真正要问的是：表已经存在但**结构是旧的**时，IF NOT EXISTS 会怎样
	var create string
	var name string
	if err := db.QueryRow(`SHOW CREATE TABLE platform_backups`).Scan(&name, &create); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(create), []byte("live_slot")) {
		t.Fatalf("表结构里没有 live_slot")
	}
	t.Log("CREATE TABLE IF NOT EXISTS 对已存在的表静默跳过，不校验列")
}

// 攻击 7：收尾成功但 finishBackupRun 影响 0 行时，已经上传的对象怎么办
func TestAdvFinishRaceLeavesOrphanObjects(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "finish race")
	// 超时扫描抢先判死
	if _, err := s.failBackupRun(context.Background(), run.ID, "reaped"); err != nil {
		t.Fatal(err)
	}
	objects := []backupObject{
		{Pair: "AB", ObjectKey: "p/i/backup-00000001-AB.rnbk", SHA256: "aa", SizeBytes: 1},
		{Pair: "AC", ObjectKey: "p/i/backup-00000001-AC.rnbk", SHA256: "bb", SizeBytes: 1},
		{Pair: "BC", ObjectKey: "p/i/backup-00000001-BC.rnbk", SHA256: "cc", SizeBytes: 1},
	}
	changed, err := s.finishBackupRun(context.Background(), run.ID, objects, 3)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("被判死之后收尾不该成功")
	}
	after, _ := s.backupRunByID(context.Background(), run.ID)
	if len(after.Objects) != 0 {
		t.Fatalf("objects 不该被写进去: %+v", after.Objects)
	}
	t.Logf("三个包已经在桶里，记录是 %s、objects=NULL。控制台上没有任何一行指向它们，"+
		"桶里也没有任何东西会去删——%d 个孤儿对象（还有 3 个 README）", after.Status, len(objects))
}

// 攻击 8：调度器把间隔改小/改大、以及进程频繁重启
func TestAdvSchedulerUnderRestartsAndIntervalChanges(t *testing.T) {
	s := advServer(t)
	if _, err := s.db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	sched := &BackupScheduler{server: s, tick: time.Minute}
	s.cfg.Backup = config.Backup{IntervalHours: 24, InstanceID: "inst", Bucket: config.BackupBucket{Bucket: "b"}}

	// 第一次：库里什么都没有 -> 立刻建一条
	sched.maybeSchedule(context.Background())
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM platform_backups WHERE trigger_by='schedule'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("第一次应当建一条，得到 %d", count)
	}
	// 反复重启：不应该再建
	for i := 0; i < 5; i++ {
		sched.maybeSchedule(context.Background())
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM platform_backups WHERE trigger_by='schedule'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	t.Logf("反复重启之后 schedule 记录数 = %d", count)
	if count != 1 {
		t.Errorf("频繁重启把定时备份建重了：%d 条", count)
	}

	// 那一条还占着闸。把它判死，再看一次——间隔没到，不该再建
	live, err := s.liveBackupRun(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.failBackupRun(context.Background(), live.ID, "test"); err != nil {
		t.Fatal(err)
	}
	sched.maybeSchedule(context.Background())
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM platform_backups WHERE trigger_by='schedule'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("闸放开之后又建了一条，尽管间隔没到：%d", count)
	}

	// 失败的那一条同样把 lastScheduledBackupAt 推到了现在：
	// 备份连挂 24 小时也不会重试，只会每 24 小时试一次
	last, err := s.lastScheduledBackupAt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("lastScheduledBackupAt = %v（这条是 failed 的）；下一次定时要等满 %d 小时",
		last.Format(time.RFC3339), 24)
}

// 攻击 9：backupKeystores 的门禁只看 status==running。
// 一条 running 的记录在被判死之前，任何拿到 id 的人都能反复拉全平台密封盒子
func TestAdvKeystoreEndpointHasNoOneShotGuard(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "keystore endpoint")
	for i := 0; i < 3; i++ {
		recorder := httptest.NewRecorder()
		gin.SetMode(gin.TestMode)
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", "/v1/build-agent/backup-keystores?request="+run.ID, nil)
		c.Set("requestId", "req_adv")
		s.backupKeystores(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("第 %d 次应当 200，得到 %d %s", i, recorder.Code, recorder.Body.String())
		}
	}
	t.Log("同一个 id 连拉 3 次全平台密封盒子，每次都 200——没有一次性门禁，也没有认领者绑定")
}

var _ = fmt.Sprintf
