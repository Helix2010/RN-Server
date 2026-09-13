package api

import (
	"context"
	"net/http"
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
