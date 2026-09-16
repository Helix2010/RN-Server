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
