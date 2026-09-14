package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

// 排一条热更新构建任务要过的闸。每一条都对应一种"排进去也一定白跑"的情况——
// 队列是跨租户的，注定失败的任务占的是所有人的打包机。
func TestDBOTABuildJobQueueGuards(t *testing.T) {
	db := openTestDB(t)
	s := otaTestServer(t, db)
	tenant := testTenant(18)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)

	queue := func(base string) (int, string) {
		t.Helper()
		c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
			"kind": "ota", "baseReleaseId": base, "applyStrategy": "next_launch",
			"reason": "测试热更新构建", "confirm": true,
			"releaseNotes": map[string]any{"zh-CN": []string{"改了个文案"}},
		})
		s.createBuildJob(c)
		return recorder.Code, recorder.Body.String()
	}

	// 基线不存在
	if code, body := queue("rel_nope"); code != 404 || !strings.Contains(body, "OTA_BASE_RELEASE_NOT_FOUND") {
		t.Fatalf("不存在的基线应该 404：%d %s", code, body)
	}

	// 没有 runtimeVersion 的老包不能当基线：热更新按它匹配设备
	noRuntime := "rel_nort_" + uniqueSuffix()
	seedRelease(t, db, tenant, noRuntime, "1.0.0", 1, "", "active")
	if code, body := queue(noRuntime); code != 422 || !strings.Contains(body, "OTA_BASE_RELEASE_INVALID") {
		t.Fatalf("没有 runtimeVersion 的基线应该 422：%d %s", code, body)
	}

	// 指纹功能上线之前构建的包不能当基线：上传那一步一定会被 otaFingerprintMismatch
	// 拒掉，而那时打包机已经白跑了一整趟。2026-09-14 anyfun 就是这么失败的。
	noFingerprint := "rel_nofp_" + uniqueSuffix()
	seedReleaseWithMetadata(t, db, tenant, noFingerprint, "1.0.0", 2, "1.0.0", "active", `{"sha256":"x"}`)
	if code, body := queue(noFingerprint); code != 422 || !strings.Contains(body, "没有记录原生指纹") {
		t.Fatalf("没有原生指纹的基线应该在排队时就被挡下：%d %s", code, body)
	}

	base := "rel_ok_" + uniqueSuffix()
	seedRelease(t, db, tenant, base, "1.0.1", 3, "1.0.1", "active")

	// 没有 OTA 签名密钥：设备会静默拒绝这次更新，构建出来也是白费
	if code, body := queue(base); code != 409 || !strings.Contains(body, "OTA_SIGNING_KEY_MISSING") {
		t.Fatalf("缺签名密钥应该 409：%d %s", code, body)
	}
	seedOTASigningKey(t, s, tenant)

	if code, body := queue(base); code != 201 {
		t.Fatalf("应该排得进去：%d %s", code, body)
	}
	// 同租户同平台同时只允许一条：不加这道闸，一个租户连点十下就占满跨租户的队列
	if code, body := queue(base); code != 409 || !strings.Contains(body, "OTA_BUILD_ALREADY_QUEUED") {
		t.Fatalf("第二条应该被挡下：%d %s", code, body)
	}

	// 热更新任务不参与 build 号唯一性：它和产生基线的那条 APK 任务用同一个号
	var kind, channel, strategy string
	var liveBuild any
	if err := db.QueryRow(`SELECT kind,channel,apply_strategy,live_build_number FROM build_jobs WHERE tenant_id=? AND kind='ota'`,
		tenant).Scan(&kind, &channel, &strategy, &liveBuild); err != nil {
		t.Fatal(err)
	}
	if kind != "ota" || channel != "production" || strategy != "next_launch" || liveBuild != nil {
		t.Fatalf("任务行不对：kind=%s channel=%s strategy=%s liveBuildNumber=%v", kind, channel, strategy, liveBuild)
	}
}

// 认领热更新任务时不下发签名密钥：它不需要，就不该拿到。
func TestDBOTAClaimCarriesNoKeystore(t *testing.T) {
	db := openTestDB(t)
	s := otaTestServer(t, db)
	tenant := testTenant(19)
	slug := seedBuildTenant(t, s, tenant)
	seedBuildIdentity(t, db, tenant, slug)
	seedOTASigningKey(t, s, tenant)
	base := "rel_claim_" + uniqueSuffix()
	seedRelease(t, db, tenant, base, "2.0.0", 7, "2.0.0", "active")

	c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
		"kind": "ota", "baseReleaseId": base, "applyStrategy": "immediate",
		"reason": "测试认领", "confirm": true,
		"releaseNotes": map[string]any{"zh-CN": []string{"改了个文案"}},
	})
	s.createBuildJob(c)
	if recorder.Code != 201 {
		t.Fatalf("排队失败：%d %s", recorder.Code, recorder.Body.String())
	}

	c, recorder = testContext(t, tenant, "POST", "/v1/build-agent/claim", map[string]any{
		"agent": "test-builder", "platforms": []string{"android"},
	})
	s.claimBuildJob(c)
	if recorder.Code != 200 {
		t.Fatalf("认领失败：%d %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["kind"] != "ota" || payload["runtimeVersion"] != "2.0.0" || payload["applyStrategy"] != "immediate" {
		t.Fatalf("下发的参数不对：%v", payload)
	}
	if payload["sealedKeystore"] != nil || payload["keyAlias"] != nil {
		t.Fatal("热更新任务拿到了签名密钥")
	}
	// 身份仍然要下发：热更新包会把它烧进 manifest
	if payload["tenantFile"] == nil {
		t.Fatal("没有下发合成身份")
	}
}

func otaTestServer(t *testing.T, db *sql.DB) *server {
	t.Helper()
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	return &server{db: db, secrets: box, cfg: config.Config{Environment: "development"}}
}

func seedRelease(t *testing.T, db *sql.DB, tenant, id, version string, build int, runtime, status string) {
	t.Helper()
	seedReleaseWithMetadata(t, db, tenant, id, version, build, runtime, status,
		`{"nativeFingerprint":"`+testBaseFingerprint+`"}`)
}

// testBaseFingerprint 是种子基线的原生指纹。打包机编 APK 时算出来的那个值，
// 没有它的基线一律不能挂热更新（见 otaJobBaseFor）。
const testBaseFingerprint = "1111111111111111111111111111111111111111"

func seedReleaseWithMetadata(t *testing.T, db *sql.DB, tenant, id, version string, build int, runtime, status, metadata string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,file_metadata,mandatory,created_by,created_at,updated_at)
		VALUES(?,?,'android',?,?,?,?,'{}','k','f','application/vnd.android.package-archive',1,1,'sha',?,0,'test',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		id, tenant, version, build, runtime, status, metadata); err != nil {
		t.Fatalf("种子发布 %s: %v", id, err)
	}
}

// seedOTASigningKey 走真正的生成接口：这条路径上的加密、存库、版本号都和线上一致。
func seedOTASigningKey(t *testing.T, s *server, tenant string) {
	t.Helper()
	c, recorder := testContext(t, tenant, "POST", "/v1/admin/ota/signing-key/generate", map[string]any{
		"expectedVersion": 0, "reason": "测试用签名密钥", "confirm": true, "keySize": 2048, "years": 1,
	})
	s.generateOTASigningKey(c)
	if recorder.Code != 200 && recorder.Code != 201 {
		t.Fatalf("生成 OTA 签名密钥失败：%d %s", recorder.Code, recorder.Body.String())
	}
}
