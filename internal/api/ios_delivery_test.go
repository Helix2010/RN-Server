package api

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// iOS 交付方式（设计 ios-tenant-delivery-tiers-2026-09-24.md）。这一组钉住：
//
//   - 交付方式在排队时抄进任务；全托管要有上传 Key 可用的机器，自助上传要有能交回 .ipa 的机器；
//   - 认领按交付方式派，并且同租户按排队顺序——卡住的那条挡住后面的，build 号不会乱；
//   - 有没跑完的任务不许切换；从全托管切到自助上传要确认已吊销 Key，服务端存的 App Manager Key 一起删；
//   - 收尾：全托管报"没上传"拒收，自助上传没交回 .ipa 拒收；iOS 不能走 /unsigned/upload。
//
// 需要真实 MySQL（RN_TEST_MYSQL_DSN），否则整组跳过。

// ipaCapableClaim 是一台升级过、能把 .ipa 交回服务端的 Mac 的认领。
func ipaCapableClaim(f *gateFixture, machine gateMachine, teams []appleTeamReport) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(http.MethodPost, "/v1/build-agent/claim", machine.Token, nil, map[string]any{
		"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
		"agentCommit": "1111111111111111111111111111111111111111", "os": machineOSDarwin,
		"appleTeams": teams, "freeGb": 120, "capabilities": []string{machineCapabilityIPADelivery},
	})
}

// noKeyReport 是一台没装这个 Team 上传 Key 的 Mac 的自报。
func noKeyReport(teamID string, bundleIDs ...string) []appleTeamReport {
	return []appleTeamReport{{TeamID: teamID, BundleIDs: bundleIDs, ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeMissing}}
}

func getDelivery(f *gateFixture) map[string]any {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodGet, "/v1/admin/ios/delivery", nil)
	f.s.getIOSDelivery(c)
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("get delivery: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(f.t, recorder)
}

func putDelivery(f *gateFixture, body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	payload := map[string]any{"reason": "ios delivery test", "confirm": true}
	for key, value := range body {
		payload[key] = value
	}
	c, recorder := testContext(f.t, f.tenant, http.MethodPut, "/v1/admin/ios/delivery", payload)
	f.s.updateIOSDelivery(c)
	return recorder
}

func cancelJob(f *gateFixture, id string) {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/builds/"+id+"/cancel", map[string]any{"reason": "ios delivery test", "confirm": true})
	c.Params = append(c.Params, ginParam("id", id))
	f.s.cancelBuildJob(c)
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("cancel %s: %d %s", id, recorder.Code, recorder.Body.String())
	}
}

func switchToIPA(f *gateFixture) {
	f.t.Helper()
	version := int(getDelivery(f)["version"].(float64))
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": version, "acknowledgeKeysRevoked": true}); recorder.Code != http.StatusOK {
		f.t.Fatalf("switch to ipa: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 全托管的任务只排得进、只派得给上传 Key 可用的机器。没装 Key 的 Mac 报上来的只算"有签名材料"。
func TestDBIOSTestFlightJobNeedsAnUploader(t *testing.T) {
	f, macs := newIOSPool(t, 71, 1)
	if recorder := iosClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := queueIOS(f, "2.0.0", 2000); recorder.Code != http.StatusConflict || problemCode(t, recorder) != "NO_UPLOADER_FOR_TEAM" {
		t.Fatalf("queued a TestFlight build no machine can upload: %d %s", recorder.Code, recorder.Body.String())
	}
	// 同一台机器装上 Key 之后排得进去；任务记下了交付方式
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := queueIOS(f, "2.0.0", 2000)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	if queued := decodeBody(t, recorder); queued["delivery"] != iosDeliveryTestFlight {
		t.Fatalf("the job must carry its delivery mode: %v", queued["delivery"])
	}
	// Key 又没了（被删、被吊销）：这条任务不派给它
	if recorder := iosClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("a machine without the upload key got a TestFlight job: %d %s", recorder.Code, recorder.Body.String())
	}
	// 装着 Key 但探不通（多半是代理断了）仍然派：让它在上传那一步重试，比排不出去好
	flaky := []appleTeamReport{{TeamID: poolTeamA, BundleIDs: []string{poolBundle}, UploadProbe: uploadProbeError}}
	if claimed := iosClaim(f, macs[0], flaky); claimed.Code != http.StatusOK {
		t.Fatalf("a machine whose probe failed transiently must still get the job: %d %s", claimed.Code, claimed.Body.String())
	} else if job := decodeBody(t, claimed); job["delivery"] != iosDeliveryTestFlight {
		t.Fatalf("the claim must tell the machine how to deliver: %v", job["delivery"])
	}
}

// 自助上传的任务要等能交回 .ipa 的打包机程序上线才排得进去，也只派给它。
func TestDBIOSIPAJobNeedsACapableBuilder(t *testing.T) {
	f, macs := newIOSPool(t, 72, 1)
	switchToIPA(f)
	// 旧版代理：有签名材料、没有这个能力
	if recorder := iosClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := queueIOS(f, "2.1.0", 2100); recorder.Code != http.StatusConflict || problemCode(t, recorder) != "NO_IPA_BUILDER_FOR_TEAM" {
		t.Fatalf("queued a self-upload build before any builder can deliver an .ipa: %d %s", recorder.Code, recorder.Body.String())
	}
	// 升级之后：没装上传 Key 也排得进去——自助上传本来就不交 Key
	if recorder := ipaCapableClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if live := readLiveness(t, f, macs[0].ID); !containsString(live.Capabilities, machineCapabilityIPADelivery) {
		t.Fatalf("the self-reported capability was not recorded: %+v", live.Capabilities)
	}
	recorder := queueIOS(f, "2.1.0", 2100)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	queued := decodeBody(t, recorder)
	if queued["delivery"] != iosDeliveryIPA {
		t.Fatalf("the job must carry its delivery mode: %v", queued["delivery"])
	}
	// 同一台机器降回旧版（不报能力）：哪怕装着上传 Key，也不能领自助上传的任务——它会按全托管去传
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("an old agent got a self-upload job: %d %s", recorder.Code, recorder.Body.String())
	}
	claimed := ipaCapableClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle))
	if claimed.Code != http.StatusOK {
		t.Fatalf("the capable machine did not get the job: %d %s", claimed.Code, claimed.Body.String())
	}
	if job := decodeBody(t, claimed); job["id"] != queued["id"] || job["delivery"] != iosDeliveryIPA {
		t.Fatalf("claimed the wrong job or lost the delivery mode: %v", job)
	}
}

// 同租户按排队顺序：全托管的 N 号没有机器能传时，自助上传的 N+1 号不能先打完落库——
// 否则 N 号之后传进 TestFlight，却在 /ios-release 被版本递增拒掉，包撤不回来。
func TestDBIOSClaimFollowsQueueOrderPerTenant(t *testing.T) {
	f, macs := newIOSPool(t, 73, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	first := decodeBody(t, queueIOS(f, "2.2.0", 2200))
	second := decodeBody(t, queueIOS(f, "2.2.1", 2201))
	// 两条交付方式不同的任务同时排着（切换检查挡住了正常路径，这里直接改库，等于撞上了那个窗口）
	if _, err := f.db.Exec(`UPDATE build_jobs SET delivery=? WHERE id=?`, iosDeliveryIPA, second["id"]); err != nil {
		t.Fatal(err)
	}
	// 能交回 .ipa、但没有上传 Key 的机器：第二条是它能干的，但第一条还排着，谁都不派
	if recorder := ipaCapableClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("a later job jumped the queue: %d %s", recorder.Code, recorder.Body.String())
	}
	// 能上传的机器领走第一条
	claimed := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle))
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim the first job: %d %s", claimed.Code, claimed.Body.String())
	}
	if job := decodeBody(t, claimed); job["id"] != first["id"] {
		t.Fatalf("claimed %v, want the earliest job %v", job["id"], first["id"])
	}
}

// 有没跑完的任务不许切换；切到自助上传要确认已吊销 Key，平台存的 App Manager Key 一起删。
func TestDBIOSDeliverySwitch(t *testing.T) {
	f, macs := newIOSPool(t, 74, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	initial := getDelivery(f)
	if initial["mode"] != iosDeliveryTestFlight || initial["configured"] != false {
		t.Fatalf("a tenant that never chose is fully managed: %v", initial)
	}
	readiness, _ := initial["readiness"].(map[string]any)
	if managed, _ := readiness[iosDeliveryTestFlight].(map[string]any); managed["ready"] != true {
		t.Fatalf("an uploader is reported, TestFlight delivery must be ready: %v", readiness)
	}
	if self, _ := readiness[iosDeliveryIPA].(map[string]any); self["ready"] != false || self["code"] != "NO_IPA_BUILDER_FOR_TEAM" {
		t.Fatalf("no builder can deliver an .ipa yet: %v", readiness)
	}

	queued := decodeBody(t, queueIOS(f, "2.3.0", 2300))
	recorder := putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 0, "acknowledgeKeysRevoked": true})
	if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "IOS_DELIVERY_SWITCH_BLOCKED" {
		t.Fatalf("switched with a build still queued: %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), queued["id"].(string)) {
		t.Fatalf("the refusal must name the unfinished build: %s", recorder.Body.String())
	}
	cancelJob(f, queued["id"].(string))

	// 平台这边存着一把 App Manager Key
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',UTC_TIMESTAMP(3))`,
		f.tenant, iosASCConfigKey, `{"sealed":"x"}`); err != nil {
		t.Fatal(err)
	}
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 0}); recorder.Code != http.StatusConflict || problemCode(t, recorder) != "IOS_DELIVERY_KEYS_NOT_REVOKED" {
		t.Fatalf("switched to self-upload without confirming the keys were revoked: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder = putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 0, "acknowledgeKeysRevoked": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("switch to ipa: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["mode"] != iosDeliveryIPA || body["ascKeyDeleted"] != true || body["version"] != float64(1) {
		t.Fatalf("switch response: %v", body)
	}
	var stored int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, iosASCConfigKey).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the stored App Manager key must go with the switch: %d %v", stored, err)
	}
	var audits int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_delivery_update'`, f.tenant).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("the switch must be audited once: %d %v", audits, err)
	}
	// 过期的版本号、没变的方式都拒
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryTestFlight, "expectedVersion": 0}); problemCode(t, recorder) != "STALE_IOS_DELIVERY" {
		t.Fatalf("a stale version was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 1}); problemCode(t, recorder) != "IOS_DELIVERY_UNCHANGED" {
		t.Fatalf("an unchanged mode was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
	// 切回全托管不用再确认什么
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryTestFlight, "expectedVersion": 1}); recorder.Code != http.StatusOK {
		t.Fatalf("switch back: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := putDelivery(f, map[string]any{"mode": "adhoc", "expectedVersion": 2}); recorder.Code != http.StatusBadRequest {
		t.Fatalf("an unknown mode was accepted: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 收尾按交付方式判"做完"：全托管报没上传拒收；自助上传没交回 .ipa 拒收；iOS 不能走 /unsigned/upload。
func TestDBIOSReleaseDependsOnTheDeliveryMode(t *testing.T) {
	f, macs := newIOSPool(t, 75, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	queueIOS(f, "2.4.0", 2400)
	claimed := decodeBody(t, iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)))
	id := claimed["id"].(string)
	headers := map[string]string{buildAttemptHeader: strconv.Itoa(int(claimed["attempt"].(float64)))}
	report := func(uploaded bool) map[string]any {
		return map[string]any{
			"commitSha": strings.Repeat("a", 40), "ipaSha256": strings.Repeat("b", 64), "ipaSize": 1024,
			"bundleId": poolBundle, "shortVersion": "2.4.0", "buildNumber": 2400,
			"uploadedToAppStoreConnect": uploaded, "toolchain": "Xcode 26.0", "logTail": []string{},
		}
	}
	if recorder := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/unsigned/upload", macs[0].Token, headers, []byte("not an apk")); problemCode(t, recorder) != "BUILD_PLATFORM_MISMATCH" {
		t.Fatalf("an iOS job wrote an unverified file through /unsigned/upload: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report(false)); problemCode(t, recorder) != "IOS_UPLOAD_MISSING" {
		t.Fatalf("a fully managed build completed without reaching TestFlight: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report(true)); recorder.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", recorder.Code, recorder.Body.String())
	}

	// 自助上传：没交回 .ipa 就报完成，拒收
	switchToIPA(f)
	if recorder := ipaCapableClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := queueIOS(f, "2.5.0", 2500); recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	claimed = decodeBody(t, ipaCapableClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)))
	id = claimed["id"].(string)
	headers = map[string]string{buildAttemptHeader: strconv.Itoa(int(claimed["attempt"].(float64)))}
	body := report(false)
	body["shortVersion"], body["buildNumber"] = "2.5.0", 2500
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, body); problemCode(t, recorder) != "IOS_IPA_NOT_DELIVERED" {
		t.Fatalf("a self-upload build completed without delivering its .ipa: %d %s", recorder.Code, recorder.Body.String())
	}
	body["uploadedToAppStoreConnect"] = true
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, body); problemCode(t, recorder) != "IOS_DELIVERY_MISMATCH" {
		t.Fatalf("a self-upload build claimed to have uploaded to TestFlight: %d %s", recorder.Code, recorder.Body.String())
	}
}
