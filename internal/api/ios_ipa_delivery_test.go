package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 自助上传的 .ipa（设计 ios-tenant-delivery-tiers-2026-09-24 §3.4–§3.6）：交回时服务端解包核对，
// 对得上才存；收尾要求就是这一份；控制台鉴权下载、支持续传、每次记审计；公开下载挡住；
// 任务被取消时交付件跟着删。需要真实 MySQL（RN_TEST_MYSQL_DSN），否则整组跳过。

// fakeIPA 造一个 App Store 形状的 .ipa。getTaskAllow=true 就是开发包。
func fakeIPA(t *testing.T, team, bundle, version string, build int, getTaskAllow bool) []byte {
	t.Helper()
	allow := "<false/>"
	if getTaskAllow {
		allow = "<true/>"
	}
	entries := map[string]string{
		"Payload/Pool.app/Info.plist": `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
			<key>CFBundleIdentifier</key><string>` + bundle + `</string>
			<key>CFBundleShortVersionString</key><string>` + version + `</string>
			<key>CFBundleVersion</key><string>` + strconv.Itoa(build) + `</string></dict></plist>`,
		"Payload/Pool.app/embedded.mobileprovision": "\x30\x82cms" + `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
			<key>ExpirationDate</key><date>2027-09-20T03:03:38Z</date>
			<key>TeamIdentifier</key><array><string>` + team + `</string></array>
			<key>Entitlements</key><dict>
				<key>application-identifier</key><string>` + team + `.` + bundle + `</string>
				<key>get-task-allow</key>` + allow + `
			</dict></dict></plist>` + "\x00sig",
		"Payload/Pool.app/Pool": "mach-o",
		"Symbols/A.symbols":     "symbols",
	}
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for name, body := range entries {
		entry, err := archive.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// claimIPAJob 把租户切到自助上传、排一条、让能交回 .ipa 的 Mac 领走，返回任务 id 与认领头。
func claimIPAJob(t *testing.T, f *gateFixture, mac gateMachine, version string, build int) (string, map[string]string) {
	t.Helper()
	if recorder := ipaCapableClaim(f, mac, noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := queueIOS(f, version, build); recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	claimed := ipaCapableClaim(f, mac, noKeyReport(poolTeamA, poolBundle))
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim the job: %d %s", claimed.Code, claimed.Body.String())
	}
	job := decodeBody(t, claimed)
	return job["id"].(string), map[string]string{buildAttemptHeader: strconv.Itoa(int(job["attempt"].(float64)))}
}

func downloadIPA(f *gateFixture, id string, headers map[string]string) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodGet, "/v1/admin/builds/"+id+"/ipa/download", nil)
	c.Params = append(c.Params, ginParam("id", id))
	for key, value := range headers {
		c.Request.Header.Set(key, value)
	}
	f.s.downloadIOSPackage(c)
	return recorder
}

func TestDBIOSIPAIsVerifiedStoredAndDownloadable(t *testing.T) {
	f, macs := newIOSPool(t, 76, 1)
	switchToIPA(f)
	id, headers := claimIPAJob(t, f, macs[0], "3.0.0", 3000)
	upload := func(body []byte) *httptest.ResponseRecorder {
		return f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/upload", macs[0].Token, headers, body)
	}

	// 开发包（能调试、能直接装机）不收
	if recorder := upload(fakeIPA(t, poolTeamA, poolBundle, "3.0.0", 3000, true)); problemCode(t, recorder) != "IOS_IPA_INVALID" {
		t.Fatalf("a development build was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	// 不是这条任务的包不收：build 号、Team 都要对
	if recorder := upload(fakeIPA(t, poolTeamA, poolBundle, "3.0.0", 2999, false)); problemCode(t, recorder) != "IOS_ARTIFACT_MISMATCH" {
		t.Fatalf("another build number was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := upload(fakeIPA(t, poolTeamB, poolBundle, "3.0.0", 3000, false)); problemCode(t, recorder) != "IOS_ARTIFACT_MISMATCH" {
		t.Fatalf("another team's profile was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(f.store.objects) != 0 {
		t.Fatalf("refused packages must not reach storage: %d objects", len(f.store.objects))
	}

	good := fakeIPA(t, poolTeamA, poolBundle, "3.0.0", 3000, false)
	sum := sha256.Sum256(good)
	digest := hex.EncodeToString(sum[:])
	recorder := upload(good)
	if recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["sha256"] != digest || body["size"] != float64(len(good)) {
		t.Fatalf("upload response: %v", body)
	}
	// 同一次认领重传：旧对象删掉，只留一份
	if recorder := upload(good); recorder.Code != http.StatusOK || len(f.store.objects) != 1 {
		t.Fatalf("a re-upload must replace the object: %d objects, %d %s", len(f.store.objects), recorder.Code, recorder.Body.String())
	}

	// 下载只给成功了的任务
	if recorder := downloadIPA(f, id, nil); problemCode(t, recorder) != "IOS_IPA_NOT_AVAILABLE" {
		t.Fatalf("a running build's package was handed out: %d %s", recorder.Code, recorder.Body.String())
	}
	report := map[string]any{
		"commitSha": strings.Repeat("a", 40), "ipaSha256": digest, "ipaSize": len(good),
		"bundleId": poolBundle, "shortVersion": "3.0.0", "buildNumber": 3000,
		"uploadedToAppStoreConnect": false, "toolchain": "Xcode 26.0", "logTail": []string{},
	}
	wrong := map[string]any{}
	for key, value := range report {
		wrong[key] = value
	}
	wrong["ipaSha256"] = strings.Repeat("c", 64)
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, wrong); problemCode(t, recorder) != "IOS_IPA_NOT_DELIVERED" {
		t.Fatalf("completion with another digest was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	completed := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report)
	if completed.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", completed.Code, completed.Body.String())
	}
	releaseID := decodeBody(t, completed)["releaseId"].(string)

	// 发布记录：交付件，不是分发产物。分发列不填，公开下载挡住
	var raw []byte
	var sha any
	if err := f.db.QueryRow(`SELECT file_metadata,sha256 FROM app_releases WHERE id=?`, releaseID).Scan(&raw, &sha); err != nil {
		t.Fatal(err)
	}
	var metadata map[string]any
	_ = json.Unmarshal(raw, &metadata)
	if metadata["hosted"] != iosHostedTenantUpload || metadata["delivery"] != iosDeliveryIPA || metadata["ipaSha256"] != digest {
		t.Fatalf("release metadata: %v", metadata)
	}
	// 激活发布要求 sha256 非空：这一列空着，这条记录就不会被激活、不会触发推送与强更
	if sha != nil {
		t.Fatalf("a self-upload release must not carry a distribution sha256: %v", sha)
	}
	if !iosHostedReleaseMetadata(raw) {
		t.Fatal("the public download must treat a self-upload release as hosted elsewhere")
	}

	full := downloadIPA(f, id, nil)
	if full.Code != http.StatusOK || !bytes.Equal(full.Body.Bytes(), good) {
		t.Fatalf("download: %d, %d bytes", full.Code, full.Body.Len())
	}
	if full.Header().Get("ETag") != `"`+digest+`"` || !strings.Contains(full.Header().Get("Content-Disposition"), poolBundle+"-3.0.0-build3000.ipa") {
		t.Fatalf("download headers: %v", full.Header())
	}
	partial := downloadIPA(f, id, map[string]string{"Range": "bytes=10-19"})
	if partial.Code != http.StatusPartialContent || !bytes.Equal(partial.Body.Bytes(), good[10:20]) {
		t.Fatalf("range download: %d %q", partial.Code, partial.Body.String())
	}
	var downloads int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_ipa_download' AND target_id=?`, f.tenant, id).Scan(&downloads); err != nil || downloads != 2 {
		t.Fatalf("every download must be audited: %d %v", downloads, err)
	}
	// 存储里的对象被改写了就不发
	for key, object := range f.store.objects {
		object.body = append(object.body, 'x')
		f.store.objects[key] = object
	}
	if recorder := downloadIPA(f, id, nil); problemCode(t, recorder) != "IOS_IPA_OBJECT_CHANGED" {
		t.Fatalf("a changed object was handed out: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 全托管的任务没有 .ipa 可交；自助上传的任务被取消时，已经交回的 .ipa 跟着删。
func TestDBIOSIPADeliveryBelongsToSelfUploadJobsOnly(t *testing.T) {
	f, macs := newIOSPool(t, 77, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	queueIOS(f, "3.1.0", 3100)
	claimed := decodeBody(t, iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)))
	id := claimed["id"].(string)
	headers := map[string]string{buildAttemptHeader: strconv.Itoa(int(claimed["attempt"].(float64)))}
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/upload", macs[0].Token, headers, fakeIPA(t, poolTeamA, poolBundle, "3.1.0", 3100, false)); problemCode(t, recorder) != "BUILD_KIND_MISMATCH" {
		t.Fatalf("a fully managed build handed back an .ipa: %d %s", recorder.Code, recorder.Body.String())
	}
	cancelJob(f, id)

	switchToIPA(f)
	id, headers = claimIPAJob(t, f, macs[0], "3.2.0", 3200)
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/upload", macs[0].Token, headers, fakeIPA(t, poolTeamA, poolBundle, "3.2.0", 3200, false)); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(f.store.objects) != 1 {
		t.Fatalf("objects after upload: %d", len(f.store.objects))
	}
	cancelJob(f, id)
	if len(f.store.objects) != 0 {
		t.Fatalf("a canceled build must not leave its .ipa behind: %d objects", len(f.store.objects))
	}
}

// deliverIPA 走完一条自助上传任务：交回 .ipa、报完成。返回任务 id。
func deliverIPA(t *testing.T, f *gateFixture, mac gateMachine, version string, build int) string {
	t.Helper()
	id, headers := claimIPAJob(t, f, mac, version, build)
	body := fakeIPA(t, poolTeamA, poolBundle, version, build, false)
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/upload", mac.Token, headers, body); recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", recorder.Code, recorder.Body.String())
	}
	sum := sha256.Sum256(body)
	report := map[string]any{
		"commitSha": strings.Repeat("a", 40), "ipaSha256": hex.EncodeToString(sum[:]), "ipaSize": len(body),
		"bundleId": poolBundle, "shortVersion": version, "buildNumber": build,
		"uploadedToAppStoreConnect": false, "toolchain": "Xcode 26.0", "logTail": []string{},
	}
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", mac.Token, headers, report); recorder.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", recorder.Code, recorder.Body.String())
	}
	return id
}

func markIPA(f *gateFixture, id string, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	payload := map[string]any{"reason": "ios ipa status test", "confirm": true}
	for key, value := range body {
		payload[key] = value
	}
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/builds/"+id+"/ipa/status", payload)
	c.Params = append(c.Params, ginParam("id", id))
	f.s.markIOSIPAStatus(c)
	return recorder
}

func buildDetail(f *gateFixture, id string) map[string]any {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodGet, "/v1/admin/builds/"+id, nil)
	c.Params = append(c.Params, ginParam("id", id))
	f.s.buildJobDetail(c)
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("detail: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(f.t, recorder)
}

// 平台看不到 Apple 那边：进展靠租户标记。更新的构建出来之后，旧交付件标成"已被取代"。
func TestDBIOSIPAStatusMarksAndSupersession(t *testing.T) {
	f, macs := newIOSPool(t, 78, 1)
	switchToIPA(f)
	first := deliverIPA(t, f, macs[0], "3.3.0", 3300)

	delivery, _ := buildDetail(f, first)["ipaDelivery"].(map[string]any)
	if delivery["available"] != true || delivery["superseded"] != false || delivery["testflightExpiresNoEarlierThan"] == nil || delivery["retainedUntil"] == nil {
		t.Fatalf("a fresh delivery: %v", delivery)
	}
	if recorder := markIPA(f, first, map[string]any{"status": iosIPAStatusRejected}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("a rejection without Apple's message was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := markIPA(f, first, map[string]any{"status": iosIPAStatusInstallable}); recorder.Code != http.StatusOK {
		t.Fatalf("mark installable: %d %s", recorder.Code, recorder.Body.String())
	}
	delivery, _ = buildDetail(f, first)["ipaDelivery"].(map[string]any)
	// 能装了当然也传上去了；传上去之后交付件只再留 7 天
	if delivery["installableAt"] == nil || delivery["uploadedAt"] == nil {
		t.Fatalf("installable implies uploaded: %v", delivery)
	}
	recorder := markIPA(f, first, map[string]any{"status": iosIPAStatusRejected, "rejection": "ITMS-90683: Missing purpose string in Info.plist"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("mark rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	delivery, _ = decodeBody(t, recorder)["ipaDelivery"].(map[string]any)
	if delivery["installableAt"] != nil || !strings.Contains(delivery["rejection"].(string), "ITMS-90683") {
		t.Fatalf("a rejection must withdraw installable and keep Apple's words: %v", delivery)
	}

	second := deliverIPA(t, f, macs[0], "3.3.1", 3301)
	if delivery, _ := buildDetail(f, first)["ipaDelivery"].(map[string]any); delivery["superseded"] != true {
		t.Fatalf("an older delivery must be marked superseded once a newer build exists: %v", delivery)
	}
	if delivery, _ := buildDetail(f, second)["ipaDelivery"].(map[string]any); delivery["superseded"] != false {
		t.Fatalf("the newest delivery is not superseded: %v", delivery)
	}
	// 全托管的构建没有这些
	if detail := buildDetail(f, second); detail["delivery"] != iosDeliveryIPA {
		t.Fatalf("delivery: %v", detail["delivery"])
	}
}

// 交付件过了保留期只删对象、留记录；下载说"过了保留期"。
func TestDBIOSIPARetention(t *testing.T) {
	f, macs := newIOSPool(t, 79, 1)
	switchToIPA(f)
	old := deliverIPA(t, f, macs[0], "3.4.0", 3400)
	uploaded := deliverIPA(t, f, macs[0], "3.4.1", 3401)
	fresh := deliverIPA(t, f, macs[0], "3.4.2", 3402)
	if len(f.store.objects) != 3 {
		t.Fatalf("objects: %d", len(f.store.objects))
	}
	now := time.Now().UTC()
	// 第一条出包 31 天了；第二条出包 10 天、租户 8 天前标了已上传；第三条出包 10 天、没标
	if _, err := f.db.Exec(`UPDATE build_jobs SET heartbeat_at=? WHERE id=?`, now.Add(-31*24*time.Hour), old); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE build_jobs SET heartbeat_at=?,delivery_state=? WHERE id=?`, now.Add(-10*24*time.Hour),
		`{"uploadedAt":"`+now.Add(-8*24*time.Hour).Format(time.RFC3339)+`"}`, uploaded); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE build_jobs SET heartbeat_at=? WHERE id=?`, now.Add(-10*24*time.Hour), fresh); err != nil {
		t.Fatal(err)
	}
	purged := f.s.purgeExpiredIPADeliveries(context.Background(), now)
	if len(purged) != 2 || !containsString(purged, old) || !containsString(purged, uploaded) {
		t.Fatalf("purged %v, want %s and %s", purged, old, uploaded)
	}
	if len(f.store.objects) != 1 {
		t.Fatalf("only the fresh delivery may stay in storage: %d objects", len(f.store.objects))
	}
	delivery, _ := buildDetail(f, old)["ipaDelivery"].(map[string]any)
	if delivery["available"] != false || delivery["purgedAt"] == nil || delivery["sha256"] == nil {
		t.Fatalf("a purged delivery keeps its record but is no longer available: %v", delivery)
	}
	// 清理只补 purgedAt，租户已经做的标记不被冲掉
	if delivery, _ := buildDetail(f, uploaded)["ipaDelivery"].(map[string]any); delivery["uploadedAt"] == nil || delivery["purgedAt"] == nil {
		t.Fatalf("the purge overwrote the tenant's marks: %v", delivery)
	}
	if recorder := downloadIPA(f, old, nil); problemCode(t, recorder) != "IOS_IPA_NOT_AVAILABLE" {
		t.Fatalf("a purged package was served: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := downloadIPA(f, fresh, nil); recorder.Code != http.StatusOK {
		t.Fatalf("the fresh package must still download: %d %s", recorder.Code, recorder.Body.String())
	}
	// 再跑一轮什么都不做
	if again := f.s.purgeExpiredIPADeliveries(context.Background(), now); len(again) != 0 {
		t.Fatalf("a second round purged %v", again)
	}
}

// 自助上传的租户：iOS 最低支持版本不能调过标了"已可安装"的版本，否则用户被锁在 TestFlight 外面。
func TestDBIOSMinVersionWaitsForAnInstallableBuild(t *testing.T) {
	f, macs := newIOSPool(t, 80, 1)
	var stored map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &stored); err != nil {
		t.Fatal(err)
	}
	stored["modules"] = map[string]any{"predict": false, "dex": true}
	raw, _ := json.Marshal(stored)
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,1,'test',UTC_TIMESTAMP(3))
		ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=1`, f.tenant, raw); err != nil {
		t.Fatal(err)
	}
	version := 1
	save := func(iosMin string) *httptest.ResponseRecorder {
		t.Helper()
		config := map[string]any{}
		for key, value := range stored {
			config[key] = value
		}
		config["updatePolicy"] = map[string]any{
			"minSupportedVersion": map[string]any{"android": "0.9.0", "ios": iosMin},
			"latestVersion":       map[string]any{"android": "1.1.0", "ios": "9.9.9"},
			"otaChannel":          "production",
		}
		c, recorder := testContext(t, f.tenant, http.MethodPatch, "/v1/admin/app-config", map[string]any{
			"config": config, "expectedVersion": version, "reason": "raise the iOS minimum", "confirm": true,
		})
		f.s.updateAppConfig(c)
		if recorder.Code == http.StatusOK {
			version++
		}
		return recorder
	}
	// 全托管的租户不受这条限制（平台传上去的就在 TestFlight 上）
	if recorder := save("1.0.0"); recorder.Code != http.StatusOK {
		t.Fatalf("a fully managed tenant: %d %s", recorder.Code, recorder.Body.String())
	}
	switchToIPA(f)
	id := deliverIPA(t, f, macs[0], "3.5.0", 3500)
	if recorder := save("3.5.0"); problemCode(t, recorder) != "IOS_MIN_VERSION_NOT_INSTALLABLE" {
		t.Fatalf("raised the minimum past anything installable: %d %s", recorder.Code, recorder.Body.String())
	}
	// 调低、不动都不查
	if recorder := save("1.0.0"); recorder.Code != http.StatusOK {
		t.Fatalf("an unchanged minimum was refused: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := markIPA(f, id, map[string]any{"status": iosIPAStatusInstallable}); recorder.Code != http.StatusOK {
		t.Fatalf("mark: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := save("3.5.0"); recorder.Code != http.StatusOK {
		t.Fatalf("an installable version must be allowed: %d %s", recorder.Code, recorder.Body.String())
	}
}
