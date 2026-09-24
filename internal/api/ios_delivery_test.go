package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// iOS 交付方式（设计 ios-tenant-delivery-tiers-2026-09-24.md）。这一组钉住：
//
//   - 交付方式在排队时抄进任务；全托管要有上传 Key 可用的机器，自助上传要有能交回 .ipa 的机器；
//   - 认领按交付方式派，并且同租户按排队顺序——卡住的那条挡住后面的，build 号不会乱；
//   - 有没跑完的任务不许切换；从全托管切到自助上传要确认已吊销平台拿着的 Key，服务端存的 App Manager Key 一起删；
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
	completed := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report(true))
	if completed.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", completed.Code, completed.Body.String())
	}
	// 回应在路上丢了、构建机再报一次：同一份结果回原来那条记录，不是"认领过期"
	again := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, report(true))
	if again.Code != http.StatusOK || decodeBody(t, again)["releaseId"] != decodeBody(t, completed)["releaseId"] {
		t.Fatalf("a repeated report of the same result: %d %s", again.Code, again.Body.String())
	}
	// 同一次认领报了另一份包：说"这条已经有结果了"，不改记录
	different := report(true)
	different["ipaSha256"] = strings.Repeat("c", 64)
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/ios-release", macs[0].Token, headers, different); problemCode(t, recorder) != "IOS_RESULT_CONFLICT" {
		t.Fatalf("a different result for a completed claim: %d %s", recorder.Code, recorder.Body.String())
	}
	// 别的上报仍然只认在跑的任务：成功之后的心跳是过期的
	if recorder := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/heartbeat", macs[0].Token, headers, map[string]any{"logTail": []string{}}); problemCode(t, recorder) != "BUILD_ATTEMPT_STALE" {
		t.Fatalf("a heartbeat after success: %d %s", recorder.Code, recorder.Body.String())
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

// 排太久的告警按任务自己的交付方式说原因：全托管卡在"没有能上传的机器"，和"没人在线""没人有材料"
// 要做的处理都不一样。
func TestDBIOSStalledQueueNamesTheMissingUploader(t *testing.T) {
	f, macs := newIOSPool(t, 81, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	id := decodeBody(t, queueIOS(f, "4.0.0", 4000))["id"].(string)
	// 排进去之后上传 Key 没了
	if recorder := iosClaim(f, macs[0], noKeyReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("a machine without the upload key got the job: %d %s", recorder.Code, recorder.Body.String())
	}
	f.setJob(id, "created_at=?", time.Now().UTC().Add(-7*time.Hour))
	if result := f.s.reapBuildJobs(t.Context(), time.Now().UTC()); len(result.QueueStalled) != 1 {
		t.Fatalf("no alert: %+v", result)
	}
	var reason string
	if err := f.db.QueryRow(`SELECT reason FROM audit_events WHERE target_id=? AND action=? LIMIT 1`, id, buildQueueStalledAction).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, "全托管") || !strings.Contains(reason, "上传 Key") {
		t.Fatalf("the alert does not name the missing uploader: %s", reason)
	}
}

func seedUploadKeyMaterial(t *testing.T, f *gateFixture, team string) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO ios_signing_material(kind,team_id,scope,purpose,recipient_sha256,version,ciphertext,uploaded_by,uploaded_at)
		VALUES('upload-key',?,'','ios-uploader-material',?,1,?,'tester',UTC_TIMESTAMP(3))
		ON DUPLICATE KEY UPDATE version=version+1`, team, strings.Repeat("a", 64), []byte(`{"pretend":"ciphertext"}`)); err != nil {
		t.Fatal(err)
	}
}

func uploadKeyStored(t *testing.T, f *gateFixture, team string) bool {
	t.Helper()
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM ios_signing_material WHERE kind='upload-key' AND team_id=?`, team).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count > 0
}

func keysToRevoke(t *testing.T, f *gateFixture) (appManagerKey, uploadKey bool) {
	t.Helper()
	keys, ok := getDelivery(f)["keysToRevoke"].(map[string]any)
	if !ok {
		t.Fatal("the delivery view must say which keys a switch to self-upload asks to revoke")
	}
	return keys["appManagerKey"] == true, keys["uploadKey"] == true
}

// 切到自助上传只要求确认吊销平台真拿着、切过去也不该再拿着的 Key：
//
//   - 同一个 Team 下还有别的全托管租户：这个 Team 的上传 Key 不撤，也不能让人去吊销（Team Key 限不了
//     App，吊销了那些租户就传不了）——只问 App Manager Key，并且明说别吊销上传 Key；
//   - 平台什么都没拿着：不用确认，否则审计里记下的是一句不真实的"已吊销"；
//   - 上传 Key 只有这个租户在用：要确认吊销，切过去就撤下（打包机据此删本机那份）。
func TestDBIOSDeliverySwitchWithdrawsTheTeamUploadKey(t *testing.T) {
	f, _ := newIOSPool(t, 82, 1)
	// 测试库是共用的，别的用例留下的租户都在 poolTeamA 下：这里用一个只属于本用例的 Team
	team := "Q" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	seedGateIOSIdentity(t, f, team, poolBundle)
	seedUploadKeyMaterial(t, f, team)
	// 同一个 Team 下另一个租户，全托管
	other := testTenant(83)
	seedBuildTenant(t, f.s, other)
	raw, _ := json.Marshal(iosReleaseIdentity{AppleTeamID: team, BundleID: "com.pool.other"})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))
		ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`, other, releaseIOSIdentityConfigKey, raw); err != nil {
		t.Fatal(err)
	}
	if appManager, upload := keysToRevoke(t, f); appManager || upload {
		t.Fatalf("nothing of this tenant's is held by the platform, nothing to revoke: appManager=%v upload=%v", appManager, upload)
	}
	recorder := putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 0})
	if recorder.Code != http.StatusOK {
		t.Fatalf("a switch with nothing to revoke must not ask for a revocation: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["uploadKeyWithdrawn"] != false || !strings.Contains(body["reminder"].(string), "不要在 App Store Connect 吊销") {
		t.Fatalf("a shared team keeps its upload key and warns against revoking it: %v", body)
	}
	if !uploadKeyStored(t, f, team) {
		t.Fatal("the upload key of a team another fully managed tenant uses was withdrawn")
	}

	// 切回去，平台存上这个租户的 App Manager Key：只问这一把，并且提醒别吊销上传 Key
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryTestFlight, "expectedVersion": 1}); recorder.Code != http.StatusOK {
		t.Fatalf("switch back: %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',UTC_TIMESTAMP(3))`,
		f.tenant, iosASCConfigKey, `{"sealed":"x"}`); err != nil {
		t.Fatal(err)
	}
	if appManager, upload := keysToRevoke(t, f); !appManager || upload {
		t.Fatalf("only the App Manager key is this tenant's to revoke: appManager=%v upload=%v", appManager, upload)
	}
	recorder = putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 2})
	if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "IOS_DELIVERY_KEYS_NOT_REVOKED" {
		t.Fatalf("a stored App Manager key must be confirmed revoked: %d %s", recorder.Code, recorder.Body.String())
	}
	if detail := recorder.Body.String(); !strings.Contains(detail, "吊销交给平台的App Manager Key") || !strings.Contains(detail, "不要在 App Store Connect 吊销它") {
		t.Fatalf("the refusal must ask for the App Manager key only and warn against revoking the shared upload key: %s", detail)
	}
	recorder = putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 2, "acknowledgeKeysRevoked": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("switch with the App Manager key revoked: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["ascKeyDeleted"] != true || body["uploadKeyWithdrawn"] != false {
		t.Fatalf("the App Manager key goes, the shared upload key stays: %v", body)
	}

	// 那个租户也不用这个 Team 了：上传 Key 成了只有这个租户在用的，要确认吊销，切过去就撤下
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, other, releaseIOSIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	if recorder := putDelivery(f, map[string]any{"mode": iosDeliveryTestFlight, "expectedVersion": 3}); recorder.Code != http.StatusOK {
		t.Fatalf("switch back: %d %s", recorder.Code, recorder.Body.String())
	}
	if appManager, upload := keysToRevoke(t, f); appManager || !upload {
		t.Fatalf("the team's upload key is now this tenant's alone to revoke: appManager=%v upload=%v", appManager, upload)
	}
	recorder = putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 4})
	if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "IOS_DELIVERY_KEYS_NOT_REVOKED" {
		t.Fatalf("an upload key only this tenant uses must be confirmed revoked: %d %s", recorder.Code, recorder.Body.String())
	}
	if detail := recorder.Body.String(); !strings.Contains(detail, "吊销交给平台的上传 Key，") || strings.Contains(detail, "App Manager Key") {
		t.Fatalf("the refusal must name exactly the upload key: %s", detail)
	}
	recorder = putDelivery(f, map[string]any{"mode": iosDeliveryIPA, "expectedVersion": 4, "acknowledgeKeysRevoked": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("switch again: %d %s", recorder.Code, recorder.Body.String())
	}
	if body := decodeBody(t, recorder); body["uploadKeyWithdrawn"] != true || !strings.Contains(body["reminder"].(string), "撤下") {
		t.Fatalf("the team's upload key must be withdrawn: %v", body)
	}
	if uploadKeyStored(t, f, team) {
		t.Fatal("the upload key material is still stored")
	}
}
