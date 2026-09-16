package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 「测试连接」必须顺带校验 versioning（设计 §6.1、§8.2）。
//
// 没开 versioning 不是小瑕疵：Put 对一个已存在的键在没开的时候**就是删除**。
// 设计 §4.3 那条伪造攻击的入口正是桶写权限——攻击者覆盖掉真包之后，原件再也
// 取不回来，控制台上那行 sha256 只剩报丧的功能，不能让你取回真的。
//
// 此前这个接口只 Put 一个探针键就返回绿色，运维据此认为桶配对了。
// .env.example 和 CONFIGURATION.md 都照抄了 s3:GetBucketVersioning 这条权限
// 要求，而没有一行代码调它。
func TestBackupBucketTestChecksVersioning(t *testing.T) {
	run := func(t *testing.T, store *fakeObjectStore) map[string]any {
		t.Helper()
		s := advServer(t)
		s.cfg.Backup = config.Backup{
			InstanceID: "inst",
			Bucket:     config.BackupBucket{Bucket: "b", Region: "r"},
		}
		s.objects = fixedObjectFactory{client: store}
		c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/storage/test", nil)
		s.testBackupBucket(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("接口本身不该失败: %d %s", recorder.Code, recorder.Body.String())
		}
		var view map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
			t.Fatalf("响应不是合法 JSON: %v", err)
		}
		return view
	}

	t.Run("没开versioning必须报不通过", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = false
		view := run(t, store)
		if view["ok"] == true {
			t.Error("桶没开 versioning，却报了绿色——运维会以为配对了")
		}
		if detail, _ := view["versioningDetail"].(string); !strings.Contains(detail, "版本控制") {
			t.Errorf("没有说清问题出在哪: %v", view["versioningDetail"])
		}
	})

	t.Run("开了就通过", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = true
		view := run(t, store)
		if view["ok"] != true {
			t.Errorf("桶开了 versioning 却没通过: %v", view)
		}
		if view["versioning"] != true {
			t.Errorf("versioning 状态没回报: %v", view)
		}
	})

	t.Run("读不到状态也要报不通过", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = true
		store.versioningErr = errors.New("AccessDenied")
		view := run(t, store)
		if view["ok"] == true {
			t.Error("凭据缺 s3:GetBucketVersioning，却报了绿色")
		}
	})
}

// 三项权限分别报：写对象、读对象、读版本控制状态。
//
// 读对象以前没测：测试连接只 Put，而真备份上传完要从桶里取回来重算 sha256。
// 于是会出现「测试通过、第一次真备份在回读那一步失败」。
func TestBackupBucketTestReportsEachPermission(t *testing.T) {
	type view struct {
		OK       bool   `json:"ok"`
		ProbeKey string `json:"probeKey"`
		Checks   []struct {
			Action     string `json:"action"`
			Permission string `json:"permission"`
			OK         bool   `json:"ok"`
			Detail     string `json:"detail"`
		} `json:"checks"`
	}
	run := func(t *testing.T, bucket config.BackupBucket, store *fakeObjectStore) view {
		t.Helper()
		s := advServer(t)
		s.cfg.Backup = config.Backup{InstanceID: "inst", Bucket: bucket}
		s.objects = fixedObjectFactory{client: store}
		c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/storage/test", nil)
		s.testBackupBucket(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("接口本身不该失败: %d %s", recorder.Code, recorder.Body.String())
		}
		var out view
		if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Checks) != 3 {
			t.Fatalf("应当固定三项，得到 %d: %+v", len(out.Checks), out.Checks)
		}
		return out
	}
	base := config.BackupBucket{Provider: "s3", Bucket: "b", Region: "r", Prefix: "prod/"}

	t.Run("缺读对象权限要单独指出来", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = true
		store.getErr = errors.New("AccessDenied")
		out := run(t, base, store)
		if out.OK {
			t.Fatal("读不了对象却报了通过——第一次真备份会在回读那一步失败")
		}
		if !out.Checks[0].OK || out.Checks[1].OK || !out.Checks[2].OK {
			t.Errorf("三项结果不对: %+v", out.Checks)
		}
		if out.Checks[1].Permission != "s3:GetObject" {
			t.Errorf("没说清缺的是哪一条: %+v", out.Checks[1])
		}
	})

	t.Run("写失败时读跳过，但版本控制照样去问", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = true
		store.putErr = errors.New("AccessDenied")
		out := run(t, base, store)
		if out.Checks[0].OK || out.Checks[1].OK {
			t.Errorf("写失败时读不该算通过: %+v", out.Checks)
		}
		if !strings.Contains(out.Checks[1].Detail, "先解决写对象") {
			t.Errorf("读那一项没说清为什么没测: %+v", out.Checks[1])
		}
		if !out.Checks[2].OK {
			t.Errorf("版本控制是独立的一项，写失败不该连它也不测: %+v", out.Checks[2])
		}
	})

	t.Run("华为云报的是 OBS 的权限名", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningErr = errors.New("AccessDenied")
		obs := base
		obs.Provider, obs.Endpoint = "obs", "https://obs.cn-north-4.myhuaweicloud.com"
		out := run(t, obs, store)
		want := []string{"obs:object:PutObject", "obs:object:GetObject", "obs:bucket:GetBucketVersioning"}
		for i, check := range out.Checks {
			if check.Permission != want[i] {
				t.Errorf("第 %d 项权限名 %q，应为 %q——报 s3:* 给用华为云的人，他在 OBS 策略里搜不到", i, check.Permission, want[i])
			}
		}
	})

	t.Run("全通过，探针在生效前缀下的 _probe 里", func(t *testing.T) {
		store := newFakeObjectStore()
		store.versioningEnabled = true
		out := run(t, base, store)
		if !out.OK {
			t.Fatalf("三项都有却没通过: %+v", out.Checks)
		}
		if !strings.HasPrefix(out.ProbeKey, "prod/inst/_probe/") {
			t.Errorf("探针应当在生效前缀下的 _probe/ 里（凭据不给删除权限，要靠生命周期规则清）: %s", out.ProbeKey)
		}
	})
}

// 前缀和实例 ID 都为空时，拼出来的键不能以 / 开头：那在控制台里显示成一个名字为空的
// 目录，有的兼容存储还会把 / 当成字面量，同一个包在两家存储上的键就对不上了。
// amos 上第一次跑 backup-bucket-test 时探针就落在了 "/_probe/…"。
func TestBackupObjectKeysNeverStartWithASlash(t *testing.T) {
	cases := map[string]string{
		backupObjectKey("", "", 1, "AB", ".rnbk"):          "backup-00000001-AB.rnbk",
		backupObjectKey("prod/", "inst", 1, "AB", ".rnbk"): "prod/inst/backup-00000001-AB.rnbk",
		backupObjectKey("/prod/", "", 2, "BC", ".rnbk"):    "prod/backup-00000002-BC.rnbk",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("对象键 %q，应为 %q", got, want)
		}
	}
	if probe := backupProbeKey("", ""); strings.HasPrefix(probe, "/") || !strings.HasPrefix(probe, "_probe/") {
		t.Errorf("探针键不该以 / 开头: %q", probe)
	}
}
