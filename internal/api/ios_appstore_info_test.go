package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 自助上传的任务把 AppStoreInfo.plist 和 .ipa 一起交回（设计 ios-tenant-delivery-tiers-2026-09-24 §3.3）：
// Windows / Linux 上的 iTMSTransporter 上传要带它。它可有可无（旧版打包机不交），但交了就要和 .ipa
// 一样核对、落任务行、鉴权下载、跟着任务与保留期一起清理。需要真实 MySQL（RN_TEST_MYSQL_DSN）。

const fakeAppStoreInfo = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>bundle-identifier</key><string>` + poolBundle + `</string></dict></plist>`

func downloadAppStoreInfo(f *gateFixture, id string) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodGet, "/v1/admin/builds/"+id+"/ipa/appstore-info/download", nil)
	c.Params = append(c.Params, ginParam("id", id))
	f.s.downloadIOSAppStoreInfo(c)
	return recorder
}

func TestDBIOSAppStoreInfoIsStoredAndDownloadable(t *testing.T) {
	f, macs := newIOSPool(t, 159, 1)
	switchToIPA(f)
	id, headers := claimIPAJob(t, f, macs[0], "3.6.0", 3600)
	upload := func(body []byte) *httptest.ResponseRecorder {
		return f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/appstore-info/upload", macs[0].Token, headers, body)
	}

	// 不是 plist、空字典都不收，也不进存储
	for _, bad := range [][]byte{[]byte("not a plist"), []byte(`<plist version="1.0"><dict></dict></plist>`)} {
		if recorder := upload(bad); problemCode(t, recorder) != "IOS_APPSTORE_INFO_INVALID" {
			t.Fatalf("%q was accepted: %d %s", bad, recorder.Code, recorder.Body.String())
		}
	}
	if len(f.store.objects) != 0 {
		t.Fatalf("refused files must not reach storage: %d objects", len(f.store.objects))
	}

	info := []byte(fakeAppStoreInfo)
	sum := sha256.Sum256(info)
	digest := hex.EncodeToString(sum[:])
	recorder := upload(info)
	if recorder.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["sha256"] != digest || body["size"] != float64(len(info)) {
		t.Fatalf("upload response: %v", body)
	}
	// 同一次认领重传：旧对象删掉，只留一份
	if recorder := upload(info); recorder.Code != http.StatusOK || len(f.store.objects) != 1 {
		t.Fatalf("a re-upload must replace the object: %d objects, %d %s", len(f.store.objects), recorder.Code, recorder.Body.String())
	}

	// .ipa 交回、报完成之前不给下载
	pkg := fakeIPA(t, poolTeamA, poolBundle, "3.6.0", 3600, false)
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/ipa/upload", macs[0].Token, headers, pkg); recorder.Code != http.StatusOK {
		t.Fatalf("ipa upload: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := downloadAppStoreInfo(f, id); problemCode(t, recorder) != "IOS_APPSTORE_INFO_NOT_AVAILABLE" {
		t.Fatalf("a running build's plist was handed out: %d %s", recorder.Code, recorder.Body.String())
	}
	pkgSum := sha256.Sum256(pkg)
	report := map[string]any{
		"commitSha": strings.Repeat("a", 40), "ipaSha256": hex.EncodeToString(pkgSum[:]), "ipaSize": len(pkg),
		"bundleId": poolBundle, "shortVersion": "3.6.0", "buildNumber": 3600,
		"uploadedToAppStoreConnect": false, "toolchain": "Xcode 26.0", "logTail": []string{},
	}
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report); recorder.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", recorder.Code, recorder.Body.String())
	}

	// 构建列表上标出有这份文件，给出摘要与大小
	delivery, _ := buildDetail(f, id)["ipaDelivery"].(map[string]any)
	appStoreInfo, _ := delivery["appStoreInfo"].(map[string]any)
	if appStoreInfo["sha256"] != digest || appStoreInfo["size"] != float64(len(info)) {
		t.Fatalf("appStoreInfo view: %v", delivery["appStoreInfo"])
	}

	full := downloadAppStoreInfo(f, id)
	if full.Code != http.StatusOK || !bytes.Equal(full.Body.Bytes(), info) {
		t.Fatalf("download: %d %q", full.Code, full.Body.String())
	}
	if !strings.Contains(full.Header().Get("Content-Disposition"), poolBundle+"-3.6.0-build3600.AppStoreInfo.plist") || full.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download headers: %v", full.Header())
	}
	var downloads int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_appstore_info_download' AND target_id=?`, f.tenant, id).Scan(&downloads); err != nil || downloads != 1 {
		t.Fatalf("every download must be audited: %d %v", downloads, err)
	}
	// 存储里的对象被改写了就不发
	for key, object := range f.store.objects {
		if strings.HasSuffix(key, ".AppStoreInfo.plist") {
			object.body = append(object.body, 'x')
			f.store.objects[key] = object
		}
	}
	if recorder := downloadAppStoreInfo(f, id); problemCode(t, recorder) != "IOS_APPSTORE_INFO_OBJECT_CHANGED" {
		t.Fatalf("a changed object was handed out: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 全托管的任务不收；自助上传的任务被取消、过了保留期时，plist 跟 .ipa 一起删。没交 plist 的构建照样完成。
func TestDBIOSAppStoreInfoFollowsThePackage(t *testing.T) {
	f, macs := newIOSPool(t, 160, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	queueIOS(f, "3.7.0", 3700)
	claimed := decodeBody(t, iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)))
	managed := claimed["id"].(string)
	managedHeaders := map[string]string{buildAttemptHeader: strconv.Itoa(int(claimed["attempt"].(float64)))}
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+managed+"/ipa/appstore-info/upload", macs[0].Token, managedHeaders, []byte(fakeAppStoreInfo)); problemCode(t, recorder) != "BUILD_KIND_MISMATCH" {
		t.Fatalf("a fully managed build handed back an AppStoreInfo.plist: %d %s", recorder.Code, recorder.Body.String())
	}
	cancelJob(f, managed)

	switchToIPA(f)
	id, headers := claimIPAJob(t, f, macs[0], "3.7.1", 3701)
	for path, body := range map[string][]byte{
		"/ipa/upload":               fakeIPA(t, poolTeamA, poolBundle, "3.7.1", 3701, false),
		"/ipa/appstore-info/upload": []byte(fakeAppStoreInfo),
	} {
		if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+path, macs[0].Token, headers, body); recorder.Code != http.StatusOK {
			t.Fatalf("upload %s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	if len(f.store.objects) != 2 {
		t.Fatalf("objects after upload: %d", len(f.store.objects))
	}
	cancelJob(f, id)
	if len(f.store.objects) != 0 {
		t.Fatalf("a canceled build must not leave its plist behind: %d objects", len(f.store.objects))
	}

	// 旧版打包机：只交 .ipa。构建照样完成，列表上 appStoreInfo 是 null
	without := deliverIPA(t, f, macs[0], "3.7.2", 3702)
	if delivery, _ := buildDetail(f, without)["ipaDelivery"].(map[string]any); delivery["available"] != true || delivery["appStoreInfo"] != nil {
		t.Fatalf("a build without a plist: %v", delivery)
	}
	if recorder := downloadAppStoreInfo(f, without); problemCode(t, recorder) != "IOS_APPSTORE_INFO_NOT_AVAILABLE" {
		t.Fatalf("a build without a plist served one: %d %s", recorder.Code, recorder.Body.String())
	}

	// 交了 plist 的构建过了保留期：.ipa 与 plist 一起删，记录留着
	withInfo, headers := claimIPAJob(t, f, macs[0], "3.7.3", 3703)
	pkg := fakeIPA(t, poolTeamA, poolBundle, "3.7.3", 3703, false)
	for path, body := range map[string][]byte{"/ipa/upload": pkg, "/ipa/appstore-info/upload": []byte(fakeAppStoreInfo)} {
		if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+withInfo+path, macs[0].Token, headers, body); recorder.Code != http.StatusOK {
			t.Fatalf("upload %s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
	pkgSum := sha256.Sum256(pkg)
	report := map[string]any{
		"commitSha": strings.Repeat("a", 40), "ipaSha256": hex.EncodeToString(pkgSum[:]), "ipaSize": len(pkg),
		"bundleId": poolBundle, "shortVersion": "3.7.3", "buildNumber": 3703,
		"uploadedToAppStoreConnect": false, "toolchain": "Xcode 26.0", "logTail": []string{},
	}
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+withInfo+"/ios-release", macs[0].Token, headers, report); recorder.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", recorder.Code, recorder.Body.String())
	}
	before := len(f.store.objects)
	now := time.Now().UTC()
	if _, err := f.db.Exec(`UPDATE build_jobs SET heartbeat_at=? WHERE id=?`, now.Add(-31*24*time.Hour), withInfo); err != nil {
		t.Fatal(err)
	}
	if purged := f.s.purgeExpiredIPADeliveries(context.Background(), now); !containsString(purged, withInfo) {
		t.Fatalf("purged %v, want %s", purged, withInfo)
	}
	if after := len(f.store.objects); after != before-2 {
		t.Fatalf("the purge must delete both the .ipa and the plist: %d objects before, %d after", before, after)
	}
	var key any
	if err := f.db.QueryRow(`SELECT appstore_info_object_key FROM build_jobs WHERE id=?`, withInfo).Scan(&key); err != nil || key != nil {
		t.Fatalf("the plist key must be cleared with the purge: %v %v", key, err)
	}
	if recorder := downloadAppStoreInfo(f, withInfo); problemCode(t, recorder) != "IOS_APPSTORE_INFO_NOT_AVAILABLE" {
		t.Fatalf("a purged plist was served: %d %s", recorder.Code, recorder.Body.String())
	}
}
