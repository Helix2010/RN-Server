package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupbundle"

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
		backupObjectKey("", "", "backup-x-AB.rnbk"):          "backup-x-AB.rnbk",
		backupObjectKey("prod/", "inst", "backup-x-AB.rnbk"): "prod/inst/backup-x-AB.rnbk",
		backupObjectKey("/prod/", "", "backup-x-BC.rnbk"):    "prod/backup-x-BC.rnbk",
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

// **上传前先确认键不存在，存在就拒绝。** 名字里带了产出时间，正常情况下不会重名；
// 真撞上了是配置出错（两套环境配成同一个前缀、时钟被拨回去）。覆盖一个已经存在的包，
// 在桶没开版本控制时就等于把它删了——宁可这一次备份失败。
func TestBackupPackageUploadRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/pkg.rnbk"
	body := "sealed package bytes"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	pkg := backupbundle.Package{Pair: "AB", SHA256: hex.EncodeToString(sum[:]),
		Size: int64(len(body)), ReadmeFirst: "readme"}
	ctx := context.Background()

	t.Run("键不存在就正常传", func(t *testing.T) {
		store := newFakeObjectStore()
		if err := uploadBackupPackage(ctx, store, "k.rnbk", "k.README.txt", path, pkg); err != nil {
			t.Fatalf("全新的键应当能传: %v", err)
		}
		if _, ok := store.objects["k.README.txt"]; !ok {
			t.Error("README 没写——它是「这一组传完了」的提交标记")
		}
	})

	t.Run("键已存在就拒绝，原来的包一个字节都不动", func(t *testing.T) {
		store := newFakeObjectStore()
		store.put("k.rnbk", []byte("the real package from yesterday"), "etag")
		err := uploadBackupPackage(ctx, store, "k.rnbk", "k.README.txt", path, pkg)
		if err == nil || !strings.Contains(err.Error(), "已经存在") {
			t.Fatalf("覆盖了一个已经存在的包: %v", err)
		}
		if got := string(store.objects["k.rnbk"].body); got != "the real package from yesterday" {
			t.Errorf("原来的包被改掉了: %q", got)
		}
		if _, ok := store.objects["k.README.txt"]; ok {
			t.Error("拒绝了却还写了 README")
		}
	})

	t.Run("读不了就不敢写", func(t *testing.T) {
		store := newFakeObjectStore()
		store.statErr = errors.New("AccessDenied")
		if err := uploadBackupPackage(ctx, store, "k.rnbk", "k.README.txt", path, pkg); err == nil {
			t.Fatal("确认不了键存不存在，却照样写了——403 被当成了「不存在」")
		}
		if _, ok := store.objects["k.rnbk"]; ok {
			t.Error("确认不了还是写进去了")
		}
	})
}

// 恢复清单要和实机布局对得上。2026-09-16 第一次真实备份：以 rnfoundation 跑的服务端读不到
// 0600 root 的 env；二进制的恢复路径写死在 bin/ 底下，和 unit 的 ExecStart 对不上——照包恢复，
// 服务起不来
func TestBackupServerFilesMatchHowTheServerActuallyRuns(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files := func() map[string]backupServerFile {
		found := map[string]backupServerFile{}
		for _, file := range (&server{}).backupServerFiles() {
			found[file.Path] = file
		}
		return found
	}

	t.Setenv("BACKUP_SERVER_ENV_PATH", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	env := files()["rn-foundation.env"]
	if env.Source != "/etc/rn-foundation.env" || env.Mode != "0600" || env.Owner != "root:root" || !env.Critical {
		t.Errorf("没有 systemd 凭据时读原文件，恢复时按 0600 root:root 放回: %+v", env)
	}
	if binary := files()["bin/rn-server"]; binary.Target != self || binary.Source != self {
		t.Errorf("二进制要放回它现在所在的位置 %s，得到 %+v", self, binary)
	}

	// unit 里的 LoadCredential 把文件交给本服务：优先读那一份，原文件保持 root 独读
	t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/rn-foundation-server.service")
	if got := files()["rn-foundation.env"].Source; got != "/run/credentials/rn-foundation-server.service/rn-foundation.env" {
		t.Errorf("有 systemd 凭据时应当读凭据目录里那份，得到 %s", got)
	}
	// 显式配了路径就听它的
	t.Setenv("BACKUP_SERVER_ENV_PATH", "/srv/custom.env")
	if got := files()["rn-foundation.env"].Source; got != "/srv/custom.env" {
		t.Errorf("BACKUP_SERVER_ENV_PATH 应当优先，得到 %s", got)
	}
}
