package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
)

type fixedObjectFactory struct{ client objectstore.Client }

func (f fixedObjectFactory) New(objectstore.Config) (objectstore.Client, error) { return f.client, nil }

// purgeServer 在 testServer 之上接一个假对象存储，并写好这个租户的 release.storage 配置
// （不带任何加密凭据，storageClient 就不需要主密钥）。
func purgeServer(t *testing.T, db *sql.DB, tenant string, store *fakeObjectStore) *server {
	t.Helper()
	s := testServer(db)
	s.cfg = config.Config{Environment: "test"}
	s.objects = fixedObjectFactory{client: store}
	value, _ := json.Marshal(storedReleaseStorage{Provider: "s3", Region: "us-east-1", Bucket: "rn-test"})
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`, tenant, releaseStorageConfigKey, value, time.Now().UTC()); err != nil {
		t.Fatalf("seed release storage config: %v", err)
	}
	return s
}

func insertPurgeRelease(t *testing.T, db *sql.DB, tenant, id, version string, build int, status, runtime, objectKey string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,created_by,created_at,updated_at) VALUES(?,?,'android',?,?,?,?,'{}',?,'application.apk','application/vnd.android.package-archive',1,1,?,'tester',?,?)`,
		id, tenant, version, build, runtime, status, objectKey, strings.Repeat("a", 64), now, now)
	if err != nil {
		t.Fatalf("seed release %s: %v", id, err)
	}
}

func insertPurgeOTA(t *testing.T, db *sql.DB, tenant, id, baseID, runtime, status, manifestKey string, revision int) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.Exec(`INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,apply_strategy,status,manifest_key,manifest_sha256,release_notes,created_by,created_at,updated_at) VALUES(?,?,?,'android','production',?,?,?,'immediate',?,?,?,'{}','tester',?,?)`,
		id, tenant, baseID, runtime, revision, id+"-update", status, manifestKey, strings.Repeat("b", 64), now, now)
	if err != nil {
		t.Fatalf("seed ota %s: %v", id, err)
	}
}

func purgeOTA(t *testing.T, s *server, tenant, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodDelete, "/v1/admin/ota/releases/"+id, bytes.NewBufferString(body))
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("tenantId", tenant)
	c.Set("actorId", "tester@example.com")
	c.Set("requestId", "req-purge")
	s.purgeOTARelease(c)
	return recorder
}

func purgeApp(t *testing.T, s *server, tenant, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodDelete, "/v1/admin/releases/"+id, bytes.NewBufferString(body))
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Set("tenantId", tenant)
	c.Set("actorId", "tester@example.com")
	c.Set("requestId", "req-purge")
	s.purgeRelease(c)
	return recorder
}

const purgeBody = `{"reason":"cleanup historical builds","confirm":true}`

// app_releases / ota_releases 的主键不带租户，所以测试里的 id 要跟着租户走，
// 否则第二次跑就撞上一次留下的行。
func scoped(tenant, name string) string { return name + "_" + tenant }

// 旧记录没有 object_metadata，桶里那些 bundle 只能靠列前缀找出来。这条用例就是它：
// 数据库里只有 manifest_key，同目录下的资源必须一起消失。
func TestDBPurgeOTARemovesEveryObjectUnderThePrefix(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(70)
	store := newFakeObjectStore()
	s := purgeServer(t, db, tenant, store)

	base, old := scoped(tenant, "rel_base_a"), scoped(tenant, "ota_old")
	insertPurgeRelease(t, db, tenant, base, "1.2.0", 20, "completed", "1.2.0", "tenants/"+tenant+"/releases/"+base+"/application.apk")
	manifest := "tenants/" + tenant + "/ota/production/android/1.2.0/" + old + "/manifest.json"
	insertPurgeOTA(t, db, tenant, old, base, "1.2.0", "superseded", manifest, 1)
	store.put(manifest, []byte("{}"), "e1")
	store.put(path.Join(path.Dir(manifest), "bundles/index.hbc"), []byte("bundle"), "e2")
	store.put(path.Join(path.Dir(manifest), "assets/logo.png"), []byte("png"), "e3")
	other := "tenants/" + tenant + "/ota/production/android/1.2.0/ota_other/manifest.json"
	store.put(other, []byte("{}"), "e4")

	if recorder := purgeOTA(t, s, tenant, old, purgeBody); recorder.Code != http.StatusOK {
		t.Fatalf("purge must succeed, got %d %s", recorder.Code, recorder.Body.String())
	}
	for key := range store.objects {
		if strings.HasPrefix(key, path.Dir(manifest)+"/") {
			t.Fatalf("object survived the purge: %s", key)
		}
	}
	if _, ok := store.objects[other]; !ok {
		t.Fatal("purging one OTA must not touch a sibling release's objects")
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ota_releases WHERE tenant_id=? AND id=?`, tenant, old).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("row must be gone, got %d (%v)", rows, err)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ota_release_purge' AND target_id=?`, tenant, old).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("purge must be audited, got %d (%v)", audits, err)
	}
}

// 正在给当前出货版本下发的那条 OTA 删不掉；同一时刻更老运行时线上的 active 可以删——
// 那些设备收到的是全量升级，不是 OTA。
func TestDBPurgeOTAProtectsOnlyTheShippingRuntime(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(71)
	store := newFakeObjectStore()
	s := purgeServer(t, db, tenant, store)

	relLive, relOld := scoped(tenant, "rel_live"), scoped(tenant, "rel_old")
	otaLive, otaStale := scoped(tenant, "ota_live"), scoped(tenant, "ota_stale")
	insertPurgeRelease(t, db, tenant, relLive, "1.3.9", 38, "active", "1.3.9", "tenants/"+tenant+"/releases/"+relLive+"/application.apk")
	insertPurgeRelease(t, db, tenant, relOld, "1.2.9", 23, "completed", "1.2.9", "tenants/"+tenant+"/releases/"+relOld+"/application.apk")
	live := "tenants/" + tenant + "/ota/production/android/1.3.9/" + otaLive + "/manifest.json"
	stale := "tenants/" + tenant + "/ota/production/android/1.2.9/" + otaStale + "/manifest.json"
	insertPurgeOTA(t, db, tenant, otaLive, relLive, "1.3.9", "active", live, 1)
	insertPurgeOTA(t, db, tenant, otaStale, relOld, "1.2.9", "active", stale, 1)
	store.put(live, []byte("{}"), "e1")
	store.put(stale, []byte("{}"), "e2")

	recorder := purgeOTA(t, s, tenant, otaLive, purgeBody)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "OTA_RELEASE_IN_USE") {
		t.Fatalf("the shipping OTA must be protected, got %d %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.objects[live]; !ok {
		t.Fatal("a refused purge must not delete anything")
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ota_releases WHERE tenant_id=? AND id=?`, tenant, otaLive).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("refused purge must keep the row, got %d (%v)", rows, err)
	}

	if recorder = purgeOTA(t, s, tenant, otaStale, purgeBody); recorder.Code != http.StatusOK {
		t.Fatalf("an older runtime's active OTA is purgeable, got %d %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.objects[stale]; ok {
		t.Fatal("the purged OTA's manifest is still in the bucket")
	}
}

// 顺序是固定的：先 OTA 再基线包。基线先没了，剩下的 OTA 行永远校验不过去。
func TestDBPurgeReleaseRefusesWhileServingOrAnchoringOTA(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(72)
	store := newFakeObjectStore()
	s := purgeServer(t, db, tenant, store)

	serving, anchor := scoped(tenant, "rel_serving"), scoped(tenant, "rel_anchor")
	insertPurgeRelease(t, db, tenant, serving, "1.3.9", 38, "active", "1.3.9", "tenants/"+tenant+"/releases/"+serving+"/application.apk")
	insertPurgeRelease(t, db, tenant, anchor, "1.2.9", 23, "completed", "1.2.9", "tenants/"+tenant+"/releases/"+anchor+"/application.apk")
	insertPurgeOTA(t, db, tenant, scoped(tenant, "ota_on_anchor"), anchor, "1.2.9", "superseded", "tenants/"+tenant+"/ota/production/android/1.2.9/ota_on_anchor/manifest.json", 1)

	recorder := purgeApp(t, s, tenant, serving, purgeBody)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "RELEASE_IN_USE") {
		t.Fatalf("the active release must be protected, got %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = purgeApp(t, s, tenant, anchor, purgeBody)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "RELEASE_HAS_OTA") {
		t.Fatalf("a base release with OTAs on it must be protected, got %d %s", recorder.Code, recorder.Body.String())
	}
}

// 清掉一个历史全量包：对象、记录、审计，以及指回它的构建任务。
func TestDBPurgeReleaseDeletesObjectAndDetachesBuildJob(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(73)
	store := newFakeObjectStore()
	s := purgeServer(t, db, tenant, store)

	history, job := scoped(tenant, "rel_history"), scoped(tenant, "bld_history")
	key := "tenants/" + tenant + "/release-uploads/art_old/application.apk"
	insertPurgeRelease(t, db, tenant, history, "1.2.4", 18, "completed", "1.2.4", key)
	store.put(key, []byte("apk"), "e1")
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,commit_sha,version,build_number,status,release_id,reason,created_by,created_at,updated_at) VALUES(?,?,'android','main','abc','1.2.4',18,'succeeded',?,'fixture','tester',?,?)`, job, tenant, history, now, now); err != nil {
		t.Fatalf("seed build job: %v", err)
	}

	if recorder := purgeApp(t, s, tenant, history, purgeBody); recorder.Code != http.StatusOK {
		t.Fatalf("purge must succeed, got %d %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.objects[key]; ok {
		t.Fatal("the APK is still in the bucket")
	}
	var release sql.NullString
	if err := db.QueryRow(`SELECT release_id FROM build_jobs WHERE tenant_id=? AND id=?`, tenant, job).Scan(&release); err != nil || release.Valid {
		t.Fatalf("build job must be detached, got %v (%v)", release, err)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='release_purge' AND target_id=?`, tenant, history).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("purge must be audited, got %d (%v)", audits, err)
	}
}

// 存储凭据没有删除权限时，记录照删（它已经不该存在了），但响应必须把删不掉的对象
// 条数报出来——只写日志的话界面上是"删除成功"，桶里一个字节都没少。
func TestDBPurgeReportsObjectsItCouldNotDelete(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(75)
	store := newFakeObjectStore()
	store.deleteErr = errors.New("access denied")
	s := purgeServer(t, db, tenant, store)

	id := scoped(tenant, "rel_orphan")
	key := "tenants/" + tenant + "/release-uploads/art_orphan/application.apk"
	insertPurgeRelease(t, db, tenant, id, "1.2.4", 18, "completed", "1.2.4", key)
	store.put(key, []byte("apk"), "e1")

	recorder := purgeApp(t, s, tenant, id, purgeBody)
	if recorder.Code != http.StatusOK {
		t.Fatalf("the row must still be deleted, got %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"objectsFailed":1`) {
		t.Fatalf("the response must admit the object survived: %s", recorder.Body.String())
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("row must be gone, got %d (%v)", rows, err)
	}
	// 对象键留在审计里：权限修好之后照着扫孤儿对象就靠它
	var stored string
	if err := db.QueryRow(`SELECT JSON_UNQUOTE(JSON_EXTRACT(summary,'$.objectKey')) FROM audit_events WHERE tenant_id=? AND target_id=?`, tenant, id).Scan(&stored); err != nil || stored != key {
		t.Fatalf("audit must keep the object key, got %q (%v)", stored, err)
	}
}

// 列不出对象就不动数据库：删了行就再也不知道该删哪些对象了。
func TestDBPurgeOTAKeepsTheRowWhenListingFails(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(76)
	store := newFakeObjectStore()
	store.listErr = errors.New("access denied")
	s := purgeServer(t, db, tenant, store)

	base, ota := scoped(tenant, "rel_base_l"), scoped(tenant, "ota_unlistable")
	insertPurgeRelease(t, db, tenant, base, "1.2.0", 20, "completed", "1.2.0", "tenants/"+tenant+"/releases/"+base+"/application.apk")
	manifest := "tenants/" + tenant + "/ota/production/android/1.2.0/" + ota + "/manifest.json"
	insertPurgeOTA(t, db, tenant, ota, base, "1.2.0", "superseded", manifest, 1)
	store.put(manifest, []byte("{}"), "e1")

	recorder := purgeOTA(t, s, tenant, ota, purgeBody)
	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), "STORAGE_LIST_FAILED") {
		t.Fatalf("listing failure must abort the purge, got %d %s", recorder.Code, recorder.Body.String())
	}
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ota_releases WHERE tenant_id=? AND id=?`, tenant, ota).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("the row must survive, got %d (%v)", rows, err)
	}
	if _, ok := store.objects[manifest]; !ok {
		t.Fatal("nothing may be deleted when the listing failed")
	}
}

// 破坏性动作必须写理由：没有 confirm / 理由太短的请求什么都不该删。
func TestDBPurgeRequiresConfirmationAndReason(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(74)
	store := newFakeObjectStore()
	s := purgeServer(t, db, tenant, store)

	guard := scoped(tenant, "rel_guard")
	key := "tenants/" + tenant + "/release-uploads/art_guard/application.apk"
	insertPurgeRelease(t, db, tenant, guard, "1.2.4", 18, "completed", "1.2.4", key)
	store.put(key, []byte("apk"), "e1")

	for _, body := range []string{`{"reason":"cleanup","confirm":false}`, `{"reason":"x","confirm":true}`} {
		recorder := purgeApp(t, s, tenant, guard, body)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("body %s must be rejected, got %d", body, recorder.Code)
		}
	}
	if _, ok := store.objects[key]; !ok {
		t.Fatal("a rejected purge must not delete the object")
	}
}
