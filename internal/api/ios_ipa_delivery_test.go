package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
