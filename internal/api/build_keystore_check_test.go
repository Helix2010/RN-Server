package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 验证结果是**绑在某一版盒子上**的。密钥被重写之后，上一版的"打包机能打开"不能
// 再拿来给新盒子背书——那正好是最危险的一次：人换了密钥，控制台却还显示绿的。
func TestKeystoreCheckGoesStaleWhenTheKeystoreChanges(t *testing.T) {
	check := &keystoreCheck{Version: 3, OK: true, Agent: "amos-builder-1", CheckedAt: iso(time.Now().UTC())}
	if view := keystoreCheckView(check, 3); view["status"] != "ok" {
		t.Fatalf("同一版应当是 ok：%v", view)
	}
	if view := keystoreCheckView(check, 4); view["status"] != "pending" {
		t.Fatalf("盒子换过之后必须退回 pending，得到 %v", view)
	}
	if view := keystoreCheckView(nil, 1); view["status"] != "pending" {
		t.Fatalf("没验过就是 pending：%v", view)
	}
	failed := &keystoreCheck{Version: 1, OK: false, Error: "口令不对"}
	if view := keystoreCheckView(failed, 1); view["status"] != "failed" || view["error"] != "口令不对" {
		t.Fatalf("失败要带上原因：%v", view)
	}
}

// 代理报结果时如果密钥已经被重写，这条结果就不该写进去：它验的是上一版。
func TestDBKeystoreCheckIgnoresAResultForAnOldVersion(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(11)
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`,
		tenant, buildKeystoreConfigKey, `{"sealed":"x","keyAlias":"a","keystoreSha256":"b"}`, 7, "tester", now); err != nil {
		t.Fatalf("种子: %v", err)
	}

	report := func(version int, ok bool) map[string]any {
		c, recorder := testContext(t, tenant, "POST", "/v1/build-agent/keystore-checks", map[string]any{
			"tenant": tenant, "version": version, "ok": ok, "error": "", "agent": "amos-builder-1",
		})
		s.reportKeystoreCheck(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("上报失败: %d %s", recorder.Code, recorder.Body.String())
		}
		return decodeBody(t, recorder)
	}

	if out := report(6, true); out["stored"] != false {
		t.Fatalf("旧版本的结果不该写进去：%v", out)
	}
	if out := report(7, true); out["stored"] != true {
		t.Fatalf("当前版本的结果应当写进去：%v", out)
	}
	stored, err := s.keystoreCheckFor(context.Background(), tenant)
	if err != nil || stored == nil || !stored.OK || stored.Version != 7 {
		t.Fatalf("存下来的结果不对：%+v %v", stored, err)
	}
}

// 代理报回来的文字会显示在控制台上：换行和超长都要截掉，别让它把版面搅乱
func TestDBKeystoreCheckTrimsTheReportedReason(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(12)
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`,
		tenant, buildKeystoreConfigKey, `{"sealed":"x"}`, 1, "tester", now); err != nil {
		t.Fatalf("种子: %v", err)
	}
	long := ""
	for range 40 {
		long += "一二三四五六七八九十"
	}
	c, recorder := testContext(t, tenant, "POST", "/v1/build-agent/keystore-checks", map[string]any{
		"tenant": tenant, "version": 1, "ok": false, "error": "第一行\n第二行" + long, "agent": "amos-builder-1",
	})
	s.reportKeystoreCheck(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("上报失败: %d", recorder.Code)
	}
	stored, err := s.keystoreCheckFor(context.Background(), tenant)
	if err != nil || stored == nil {
		t.Fatalf("没存下来: %v", err)
	}
	// 限的是**字符**数不是字节数：按字节切会把一个中文字切成两半，JSON 编码时那半个
	// 字变成三字节的 U+FFFD，反而比切掉的更长——"限长 300"存进去 304 字节就是这么来的
	if runes := len([]rune(stored.Error)); runes > 300 {
		t.Fatalf("原因没有截断：%d 个字符", runes)
	}
	if !utf8.ValidString(stored.Error) {
		t.Fatalf("截断把字符切坏了：%q", stored.Error)
	}
	if stored.Error == "" {
		t.Fatal("原因被清空了")
	}
	for _, r := range stored.Error {
		if r == '\n' {
			t.Fatal("原因里还有换行")
		}
	}
}

// 控制台要按"全平台已经有几个租户封了密钥"说不同的话：0 个时随便定一个口令，
// 之后必须填已有的那一个。这个数字服务端数得出来，而且不需要打开任何盒子。
func TestDBSealedKeystoreTenantCountOnlyCountsRows(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	before, err := s.sealedKeystoreTenantCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, seed := range []int{13, 14} {
		if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,?,?)`,
			testTenant(seed), buildKeystoreConfigKey, `{"sealed":"x"}`, "tester", now); err != nil {
			t.Fatalf("种子: %v", err)
		}
	}
	after, err := s.sealedKeystoreTenantCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after != before+2 {
		t.Fatalf("数出来 %d，应当是 %d", after, before+2)
	}
}

// 打包机已经说过打不开的密钥，构建不该排进队列：它注定在解盒那一步失败，而那之前
// 已经 git fetch、建了 worktree、占了机器。2026-09-13 实测过这条路，代理报 failed
// 之后 69 秒还是排进了一个任务。
func TestDBBuildJobQueueRefusesAKeystoreTheMachineCannotOpen(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(15)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,?,?,?)`,
		tenant, buildKeystoreConfigKey, `{"sealed":"x","keyAlias":"release","keystoreSha256":"b"}`, 4, "tester", now); err != nil {
		t.Fatalf("种子: %v", err)
	}

	// 每次换一组号：build 号和版本号那两道闸排在密钥闸前面，重号的话先被它们挡下
	next := 0
	queue := func() (int, map[string]any) {
		next++
		c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": fmt.Sprintf("1.0.%d", next),
			"buildNumber": next, "reason": "测试密钥闸", "confirm": true,
		})
		s.createBuildJob(c)
		return recorder.Code, decodeBody(t, recorder)
	}

	report := func(version int, ok bool, reason string) {
		c, recorder := testContext(t, tenant, "POST", "/v1/build-agent/keystore-checks", map[string]any{
			"tenant": tenant, "version": version, "ok": ok, "error": reason, "agent": "amos-builder-1",
		})
		s.reportKeystoreCheck(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("上报失败: %d", recorder.Code)
		}
	}

	// 还没验过（pending）：不拦。代理没跑、或者刚存完密钥都会落在这个态上，
	// 拿它挡构建等于把一个正常状态当成故障
	if code, out := queue(); code != http.StatusCreated {
		t.Fatalf("pending 不该被拦：%d %v", code, out)
	}

	report(4, false, "打包机上的 BUILD_KEYSTORE_PASSPHRASE 打不开这个盒子")
	code, out := queue()
	if code != http.StatusConflict || out["code"] != "BUILD_KEYSTORE_UNUSABLE" {
		t.Fatalf("打不开的密钥仍然排进了队列：%d %v", code, out)
	}
	if detail, _ := out["detail"].(string); !strings.Contains(detail, "打不开这个盒子") {
		t.Fatalf("没把打包机给的原因带出来：%v", out["detail"])
	}

	// 换了一把新密钥（version 变了）之后，旧结论立刻作废，不该再拦着
	if _, err := db.Exec(`UPDATE app_configs SET version=5 WHERE tenant_id=? AND config_key=?`, tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	if code, out := queue(); code != http.StatusCreated {
		t.Fatalf("换了密钥之后旧结论还在拦：%d %v", code, out)
	}

	// 验过并且能打开：当然放行
	report(5, true, "")
	if code, out := queue(); code != http.StatusCreated {
		t.Fatalf("验证通过却被拦：%d %v", code, out)
	}
}

// 心跳停了太久的任务要被收掉。2026-09-13 两条任务因为代理解不开领取响应而卡在
// claimed，13 分钟后还在那儿，而且占着各自的 build 号——那句"会被心跳超时慢慢回收"
// 写在代码注释里，但回收这件事根本没人做。
func TestDBStaleBuildJobsAreReaped(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(16)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)
	now := time.Now().UTC()

	number := 0
	insert := func(id, status string, beat time.Time) {
		number++
		if _, err := db.Exec(`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,version,build_number,status,reason,release_notes,created_by,claimed_by,claimed_at,heartbeat_at,created_at,updated_at) VALUES(?,?,'android','main','1.0.0',?,?,'测试','{}','tester','amos-builder-1',?,?,?,?)`,
			id, tenant, number, status, beat, beat, beat, beat); err != nil {
			t.Fatalf("种子 %s: %v", id, err)
		}
	}
	// 刚领走的不该被动；心跳停了 20 分钟的要被收掉
	insert("bld_fresh_"+uniqueSuffix(), "claimed", now.Add(-time.Minute))
	staleID := "bld_stale_" + uniqueSuffix()
	insert(staleID, "claimed", now.Add(-20*time.Minute))
	runningID := "bld_run_" + uniqueSuffix()
	insert(runningID, "running", now.Add(-20*time.Minute))

	s.reapStaleBuildJobs(context.Background())

	for _, id := range []string{staleID, runningID} {
		var status, reason string
		if err := db.QueryRow(`SELECT status,COALESCE(failure_reason,'') FROM build_jobs WHERE id=?`, id).Scan(&status, &reason); err != nil {
			t.Fatal(err)
		}
		if status != "failed" {
			t.Fatalf("%s 还是 %s，没被收掉", id, status)
		}
		// 原因要让人知道该去看哪台机器，以及号已经放出来了
		if !strings.Contains(reason, "没有回报进度") || !strings.Contains(reason, "build 号已经释放") {
			t.Fatalf("失败原因没说清楚：%q", reason)
		}
	}
	var fresh int
	if err := db.QueryRow(`SELECT COUNT(*) FROM build_jobs WHERE tenant_id=? AND status='claimed'`, tenant).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if fresh != 1 {
		t.Fatalf("刚领走的那条也被收了：还剩 %d 条 claimed", fresh)
	}
}

// 合成身份要对准"正在分发的那一版"。OTA 包在导出时把 appVersion / buildNumber 烧进
// manifest，App 应用之后读的就是那一份——对不上就会拿一个倒退的版本号去问服务端要不
// 要升级。
func TestDBAppIdentityTracksTheActiveRelease(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(17)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)

	c, recorder := testContext(t, tenant, "GET", "/v1/admin/app-identity", nil)
	s.getAppIdentity(c)
	// 还没有在分发的版本时要说清楚，而不是合成一个假的版本号
	if recorder.Code != 409 || !strings.Contains(recorder.Body.String(), "APP_IDENTITY_NO_ACTIVE_RELEASE") {
		t.Fatalf("没有已发布版本时应该 409：%d %s", recorder.Code, recorder.Body.String())
	}

	insert := func(id, version string, build int, status string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,file_metadata,mandatory,created_by,created_at,updated_at)
			VALUES(?,?,'android',?,?,?,?,'{}','k','f','application/vnd.android.package-archive',1,1,'sha','{}',0,'test',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
			id, tenant, version, build, version, status); err != nil {
			t.Fatalf("种子 %s: %v", id, err)
		}
	}
	insert("rel_old_"+uniqueSuffix(), "1.0.0", 1, "active")
	insert("rel_new_"+uniqueSuffix(), "1.0.1", 2, "active")
	// 还没激活的那一版不算：设备上跑的不是它
	insert("rel_draft_"+uniqueSuffix(), "1.0.2", 3, "verified")

	c, recorder = testContext(t, tenant, "GET", "/v1/admin/app-identity", nil)
	s.getAppIdentity(c)
	if recorder.Code != 200 {
		t.Fatalf("取合成身份失败：%d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	release, _ := body["release"].(map[string]any)
	if release["version"] != "1.0.1" || release["buildNumber"].(float64) != 2 {
		t.Fatalf("没有对准在分发的那一版：%v", release)
	}
	manifest, _ := body["manifest"].(map[string]any)
	if manifest["version"] != "1.0.1" || manifest["androidVersionCode"].(float64) != 2 {
		t.Fatalf("合成身份里的版本号不对：%v", manifest)
	}
	// 私钥一个都不许出现在这条响应里
	if strings.Contains(recorder.Body.String(), "unused-in-this-path") ||
		strings.Contains(strings.ToLower(recorder.Body.String()), "privatekey") {
		t.Fatal("合成身份里带出了私钥")
	}
}
