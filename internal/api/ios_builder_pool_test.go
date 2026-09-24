package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// iOS 打包机是一个池子：每台 Mac 都应该能打任何租户的包，所以"这台能打哪些 Team"
// 不在登记里，而是机器每次认领时自报的盘点（设计
// ios-mac-builders-home-network-2026-09-18 §5.2、§5.4）。这一组用例钉住三件事：
//
//   - 认领只会拿到本机手上有签名材料的那些租户的 iOS 任务；
//   - 排队时没有任何机器报过这个 Team 就当场 409，报过但都不在线**照常排队**只给提示；
//   - 同一个租户同时只有一条 iOS 任务在途。
//
// 需要真实 MySQL（RN_TEST_MYSQL_DSN），否则整组跳过。

const (
	poolTeamA  = "AB12CD34EF"
	poolTeamB  = "ZZ99YY88XX"
	poolBundle = "com.pool.wallet"
)

// seedIOSIdentity 给租户登记 iOS 发布身份。排队与认领都按它和机器的自报盘点比对。
// seedGateIOSIdentity 写这个租户的 release.ios 身份。名字带 Gate 是为了和
// push_credentials_apns_test.go 里那个同名辅助分开：那一个按 *server 与租户写，
// 这一个走 gateFixture 并且 Team 可以指定（打包机路由要按 Team 分流）。
func seedGateIOSIdentity(t *testing.T, f *gateFixture, teamID, bundleID string) {
	t.Helper()
	raw, err := json.Marshal(iosReleaseIdentity{AppleTeamID: teamID, BundleID: bundleID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=version+1`,
		f.tenant, releaseIOSIdentityConfigKey, raw); err != nil {
		t.Fatalf("seed release.ios: %v", err)
	}
}

// iosClaim 发一次认领，带上自报的盘点。teams 为空表示"这台机器手上一个 Team 都没有"。
func iosClaim(f *gateFixture, machine gateMachine, teams []appleTeamReport) *httptest.ResponseRecorder {
	f.t.Helper()
	if teams == nil {
		teams = []appleTeamReport{}
	}
	return f.do(http.MethodPost, "/v1/build-agent/claim", machine.Token, nil, map[string]any{
		"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
		"agentCommit": "1111111111111111111111111111111111111111", "os": machineOSDarwin,
		"appleTeams": teams, "freeGb": 120,
	})
}

// teamReport 是一台开着上传、这个 Team 的上传 Key 探测通过的 Mac 的自报——生产里 mac-01 就是这样。
// 全托管的任务只派给上传 Key 可用的机器（ios_delivery.go），所以默认带上 ok。
func teamReport(teamID string, bundleIDs ...string) []appleTeamReport {
	return []appleTeamReport{{TeamID: teamID, BundleIDs: bundleIDs, ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeOK}}
}

// queueIOS 以运营的身份排一条 iOS 任务。
func queueIOS(f *gateFixture, version string, buildNumber int) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/builds", map[string]any{
		"platform": buildPlatformIOS, "gitRef": "main", "version": version, "buildNumber": buildNumber,
		"reason": "ios builder pool test", "confirm": true,
	})
	f.s.createBuildJob(c)
	return recorder
}

// newIOSPool 建一个只有 Mac 的池子：登记里 machines 台 iOS 构建机，租户有 iOS 发布身份。
func newIOSPool(t *testing.T, seed, machines int) (*gateFixture, []gateMachine) {
	t.Helper()
	f := newGateFixture(t, seed)
	records := []buildMachine{f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby)}
	macs := []gateMachine{}
	for i := 0; i < machines; i++ {
		mac := newGateMachine(t, machineRoleBuilder, "mac-"+uniqueSuffix())
		record := mac.record("")
		record.Platforms = []string{buildPlatformIOS}
		records = append(records, record)
		macs = append(macs, mac)
	}
	f.writeMachines(records...)
	seedGateIOSIdentity(t, f, poolTeamA, poolBundle)
	return f, macs
}

// 一台报了别的 Team 的 Mac 领不走这个租户的 iOS 任务；报对了才领得走。
// 顺带钉住"队列空时也要记下这台机器还活着"——认领路径上绝大多数请求都是空转，
// 而在线状态只有那些空转能证明。
func TestDBIOSClaimOnlyGoesToAMachineHoldingTheSigningMaterial(t *testing.T) {
	f, macs := newIOSPool(t, 61, 1)
	mac := macs[0]

	// 还没有任何机器报过这个 Team：排进去的任务永远没人领，当场说出来
	if recorder := queueIOS(f, "1.0.0", 1001); recorder.Code != http.StatusConflict || problemCode(t, recorder) != "NO_BUILDER_FOR_TEAM" {
		t.Fatalf("queued an iOS build nobody can sign: %d %s", recorder.Code, recorder.Body.String())
	}

	// 报了别的 Team：在线状态记下了，但这个租户仍然没有人能打
	if recorder := iosClaim(f, mac, teamReport(poolTeamB, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim on an empty queue: %d %s", recorder.Code, recorder.Body.String())
	}
	live := readLiveness(t, f, mac.ID)
	if !live.online(time.Now().UTC()) || live.AgentCommit == "" || live.OS != machineOSDarwin {
		t.Fatalf("an empty-queue claim did not record liveness: %+v", live)
	}
	if recorder := queueIOS(f, "1.0.0", 1001); problemCode(t, recorder) != "NO_BUILDER_FOR_TEAM" {
		t.Fatalf("the wrong team counted as coverage: %d %s", recorder.Code, recorder.Body.String())
	}

	// 报对了 Team 与 bundle id：排得进去，也领得走
	if recorder := iosClaim(f, mac, teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim on an empty queue: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := queueIOS(f, "1.0.0", 1001)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue iOS: %d %s", recorder.Code, recorder.Body.String())
	}
	queued := decodeBody(t, recorder)
	// warnings 恒为数组：管理端按 z.array 解析，null 会让整页读不出来
	if warnings, ok := queued["warnings"].([]any); !ok || len(warnings) != 0 {
		t.Fatalf("an online pool must queue without warnings: %v", queued["warnings"])
	}

	// 同一台机器改口说手上只有别的 Team 了：这条任务就不该再派给它
	if recorder := iosClaim(f, mac, teamReport(poolTeamB, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("a machine without the material got the job: %d %s", recorder.Code, recorder.Body.String())
	}
	// 一个 Team 都没报：同样领不到，而且不是 409——登记没错，是材料没装
	if recorder := iosClaim(f, mac, nil); recorder.Code != http.StatusNoContent {
		t.Fatalf("a machine with no material at all: %d %s", recorder.Code, recorder.Body.String())
	}
	// 描述文件不是这个 bundle id 的：签不出来，同样领不到
	if recorder := iosClaim(f, mac, teamReport(poolTeamA, "com.pool.other")); recorder.Code != http.StatusNoContent {
		t.Fatalf("a machine without this bundle id got the job: %d %s", recorder.Code, recorder.Body.String())
	}

	claimed := iosClaim(f, mac, teamReport(poolTeamA, poolBundle))
	if claimed.Code != http.StatusOK {
		t.Fatalf("the machine holding the material did not get the job: %d %s", claimed.Code, claimed.Body.String())
	}
	job := decodeBody(t, claimed)
	if job["id"] != queued["id"] || job["platform"] != buildPlatformIOS {
		t.Fatalf("claimed the wrong job: %v", job)
	}
}

// Mac 掉线不拦队列：家里的机器合上盖子就没了，任务要能排进去等它回来，
// 响应里只多一条提示。这是已定的决策，不是尽力而为。
func TestDBIOSQueueStillAcceptsJobsWhileEveryMacIsOffline(t *testing.T) {
	f, macs := newIOSPool(t, 62, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	// 把"最近在线"推到掉线线之外：等于合上了盖子
	if _, err := f.db.Exec(`UPDATE build_machine_liveness SET last_seen_at=? WHERE machine_id=?`,
		time.Now().UTC().Add(-machineOfflineAfter-time.Minute), macs[0].ID); err != nil {
		t.Fatal(err)
	}
	recorder := queueIOS(f, "1.1.0", 1101)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("an offline pool must not block the queue: %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	warnings, _ := body["warnings"].([]any)
	if len(warnings) != 1 || warnings[0] != "no_ios_builder_online" {
		t.Fatalf("the queue must say that nothing is online: %v", body["warnings"])
	}
}

// 同租户同时只有一条 iOS 任务在途：两条并行跑完，高号先落库，低号的 /ios-release
// 会被 RELEASE_VERSION_NOT_INCREASING 拒掉——而它的 .ipa 已经进了 App Store Connect。
func TestDBIOSClaimKeepsOneJobPerTenantInFlight(t *testing.T) {
	f, macs := newIOSPool(t, 63, 2)
	for _, mac := range macs {
		if recorder := iosClaim(f, mac, teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
			t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
		}
	}
	for _, spec := range []struct {
		version string
		number  int
	}{{"1.2.0", 1200}, {"1.2.1", 1201}} {
		if recorder := queueIOS(f, spec.version, spec.number); recorder.Code != http.StatusCreated {
			t.Fatalf("queue %s: %d %s", spec.version, recorder.Code, recorder.Body.String())
		}
	}
	first := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle))
	if first.Code != http.StatusOK {
		t.Fatalf("first claim: %d %s", first.Code, first.Body.String())
	}
	if second := iosClaim(f, macs[1], teamReport(poolTeamA, poolBundle)); second.Code != http.StatusNoContent {
		t.Fatalf("a second Mac took the same tenant in parallel: %d %s", second.Code, second.Body.String())
	}
}

// 自报不合法就当场 400，不进库：认领是每 10 秒一次的高频路径。
func TestDBIOSClaimRejectsAMalformedSelfReport(t *testing.T) {
	f, macs := newIOSPool(t, 64, 1)
	for name, body := range map[string]map[string]any{
		"short team":  {"appleTeams": []map[string]any{{"teamId": "SHORT", "bundleIds": []string{poolBundle}}}},
		"bad bundle":  {"appleTeams": []map[string]any{{"teamId": poolTeamA, "bundleIds": []string{"not a bundle"}}}},
		"bad expiry":  {"appleTeams": []map[string]any{{"teamId": poolTeamA, "bundleIds": []string{poolBundle}, "expiresAt": "soon"}}},
		"bad os":      {"os": "windows"},
		"bad commit":  {"agentCommit": "HEAD"},
		"negative gb": {"freeGb": -1},
	} {
		payload := map[string]any{"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK}}
		for key, value := range body {
			payload[key] = value
		}
		recorder := f.do(http.MethodPost, "/v1/build-agent/claim", macs[0].Token, nil, payload)
		if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_BUILD_CLAIM" {
			t.Fatalf("%s: %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

func readLiveness(t *testing.T, f *gateFixture, machineID string) machineLiveness {
	t.Helper()
	rows, err := f.s.machineLivenessByID(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	live, ok := rows[machineID]
	if !ok {
		t.Fatalf("no liveness row for %s", machineID)
	}
	return live
}

// 排队太久的 iOS 任务发一条告警，只发一条，而且**不动它的状态**：Mac 掉线时队列不停
// 是已定的决策，任务要能等它回来（设计 §5.4）。
func TestDBIOSStalledQueueRaisesExactlyOneAlert(t *testing.T) {
	f, macs := newIOSPool(t, 65, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := queueIOS(f, "1.3.0", 1300)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	id := decodeBody(t, recorder)["id"].(string)
	queuedAt := time.Now().UTC().Add(-7 * time.Hour)
	f.setJob(id, "created_at=?", queuedAt)

	now := time.Now().UTC()
	if result := f.s.reapBuildJobs(t.Context(), now); len(result.QueueStalled) != 1 || result.QueueStalled[0] != id {
		t.Fatalf("a job queued for 7 hours raised no alert: %+v", result)
	}
	// 告警不是回收：任务还在队列里等那台 Mac 回来
	if job := f.jobStatus(id); job.Status != jobQueued {
		t.Fatalf("the alert changed the job status to %s", job.Status)
	}
	// 每分钟一轮的回收循环不能每轮都写一条审计
	if result := f.s.reapBuildJobs(t.Context(), now.Add(time.Minute)); len(result.QueueStalled) != 0 {
		t.Fatalf("the same job was reported twice: %+v", result)
	}
	var reason string
	if err := f.db.QueryRow(
		`SELECT reason FROM audit_events WHERE target_type='build-job' AND target_id=? AND action=? LIMIT 1`,
		id, buildQueueStalledAction).Scan(&reason); err != nil {
		t.Fatalf("no audit event for the stuck job: %v", err)
	}
	// 在线的 Mac 手上有材料，所以原因该说"没人在线"，不该说"没人有材料"
	if !strings.Contains(reason, "没有能打这个租户 iOS 包的打包机在线") {
		t.Fatalf("the alert does not say why nobody claimed it: %s", reason)
	}
}

// 排队之后有人改了租户的 Apple Team：这条任务再没有任何一台机器能领，而回收器只管
// claimed/running，它会一直排着。告警要把这件事指出来，而不是笼统说"没人在线"。
func TestDBIOSStalledQueueNamesAChangedTeam(t *testing.T) {
	f, macs := newIOSPool(t, 66, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := queueIOS(f, "1.4.0", 1400)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	id := decodeBody(t, recorder)["id"].(string)
	f.setJob(id, "created_at=?", time.Now().UTC().Add(-7*time.Hour))
	// 排队之后运营把 Team 换成了另一个，而没有任何一台 Mac 装着它的材料
	seedGateIOSIdentity(t, f, poolTeamB, poolBundle)

	if result := f.s.reapBuildJobs(t.Context(), time.Now().UTC()); len(result.QueueStalled) != 1 {
		t.Fatalf("no alert for a job whose team was changed: %+v", result)
	}
	var reason string
	if err := f.db.QueryRow(
		`SELECT reason FROM audit_events WHERE target_type='build-job' AND target_id=? AND action=? LIMIT 1`,
		id, buildQueueStalledAction).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, poolTeamB) || !strings.Contains(reason, "没有任何一台打包机报告过") {
		t.Fatalf("the alert must name the team nobody holds: %s", reason)
	}
}

// 报了 paused 的机器仍然算在线，但不派活。让它干脆别来问的话，控制台只能看到"离线"，
// 而磁盘满和关机需要的处理完全不同（设计 §6.2）。
func TestDBPausedMachineStaysOnlineButGetsNoJob(t *testing.T) {
	f, macs := newIOSPool(t, 67, 1)
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := queueIOS(f, "1.5.0", 1500); recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	paused := f.do(http.MethodPost, "/v1/build-agent/claim", macs[0].Token, nil, map[string]any{
		"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
		"appleTeams": teamReport(poolTeamA, poolBundle), "freeGb": 3,
		"paused": true, "pausedReason": "only 3 GiB free, below BUILD_AGENT_MIN_FREE_GB=40",
	})
	if paused.Code != http.StatusNoContent {
		t.Fatalf("a paused machine was handed a job: %d %s", paused.Code, paused.Body.String())
	}
	live := readLiveness(t, f, macs[0].ID)
	if !live.online(time.Now().UTC()) {
		t.Fatal("a paused machine must still count as online")
	}
	if !strings.Contains(live.PausedReason, "BUILD_AGENT_MIN_FREE_GB") || live.FreeGB.Int64 != 3 {
		t.Fatalf("the pause reason and free space were not recorded: %+v", live)
	}
	// 任务还在队列里等着，没有被派掉
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusOK {
		t.Fatalf("the job was not still queued for a machine that resumed: %d %s", recorder.Code, recorder.Body.String())
	}
}

// macOS 打包机装的是另一组安装包（设计 §5.5、§8 的 S4）。
//
// 一台登记成 macOS 的机器下 linux 那一组，只会在第一次启动时以"这不是本机架构的
// 可执行文件"失败，而那条错误读起来完全不像"下错了包"。所以按登记里的 os 决定给哪一组，
// 并且拿另一组的注册码去下要当场拒。
func TestDBMacBuilderInstallsTheDarwinBundle(t *testing.T) {
	f := newGateFixture(t, 68)
	archives := f.installBundles()
	mac := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{
		"role": machineRoleBuilder, "name": "mac-" + uniqueSuffix(), "signerRole": nil,
		"platforms": []string{buildPlatformIOS}, "os": machineOSDarwin,
		"expectedVersion": registryVersion(t, f), "reason": "add a mac builder", "confirm": true,
	})
	if mac.Code != http.StatusCreated {
		t.Fatalf("create a macOS builder: %d %s", mac.Code, mac.Body.String())
	}
	created := decodeBody(t, mac)
	if created["machine"].(map[string]any)["os"] != machineOSDarwin {
		t.Fatalf("the machine view must say which OS it runs: %v", created["machine"])
	}
	code := created["enrollment"].(map[string]any)["code"].(string)

	// 还没签：一个字节都不给。这台机器将要持有全部租户的签名材料，不该在"清单还没签"的
	// 窗口里装上一份没人背书的程序
	if r := f.describe(code); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unsigned bundle was offered to a new Mac: %d %s", r.Code, r.Body.String())
	}
	public := signStagedBundles(t, f, 4)

	described := decodeBody(t, f.describe(code))
	// 装机只让人带一个带外核对值，其余摘要都从这份验过签的清单里取
	// 公钥按 OpenSSH 的一行给出去：装机脚本拿它当场生成 allowed_signers 喂给 ssh-keygen -Y verify
	if described["releaseKeyPub"] != bundlesig.SSHPublicKeyLine(public, "rn-release-key") {
		t.Fatalf("describe must hand over the release key: %v", described["releaseKeyPub"])
	}
	signature, _ := described["manifestSignature"].(map[string]any)
	if signature == nil || signature["publicKeySha256"] != bundlesig.PublicKeySHA256(public) {
		t.Fatalf("describe must hand over the manifest signature: %v", described["manifestSignature"])
	}
	if raw, _ := described["manifestBase64"].(string); raw == "" {
		t.Fatal("describe must hand over the manifest bytes the signature covers")
	}
	bundle, _ := described["bundle"].(map[string]any)
	if described["os"] != machineOSDarwin || bundle["archive"] != machineBundleBuilderDarwin+".tar.gz" {
		t.Fatalf("a macOS builder was told to install %v", bundle)
	}
	download := func(archive string) *httptest.ResponseRecorder {
		return f.do(http.MethodGet, "/v1/machine-setup/bundle/"+archive, "",
			map[string]string{enrollmentCodeHeader: code}, nil)
	}
	if r := download(machineBundleBuilderDarwin + ".tar.gz"); r.Code != http.StatusOK ||
		!bytes.Equal(r.Body.Bytes(), archives[machineBundleBuilderDarwin]) {
		t.Fatalf("download the darwin bundle: %d", r.Code)
	}
	if r := download("builder.tar.gz"); r.Code != http.StatusForbidden {
		t.Fatalf("a macOS builder downloaded the linux bundle: %d %s", r.Code, r.Body.String())
	}
}

// 一台 Mac 建出来却只勾 android，是一台永远领不到活的机器；签名闸没有 macOS 版。
func TestDBMacBuilderMustBeAbleToBuildIOS(t *testing.T) {
	f := newGateFixture(t, 69)
	for name, body := range map[string]map[string]any{
		"android only": {"role": machineRoleBuilder, "name": "mac-" + uniqueSuffix(), "signerRole": nil,
			"platforms": []string{buildPlatformAndroid}, "os": machineOSDarwin},
		"a signer on macOS": {"role": machineRoleSigner, "name": "sgn-" + uniqueSuffix(), "signerRole": signerRoleStandby,
			"os": machineOSDarwin},
		"unknown os": {"role": machineRoleBuilder, "name": "mac-" + uniqueSuffix(), "signerRole": nil,
			"platforms": []string{buildPlatformIOS}, "os": "windows"},
		// 反过来那一半：Linux 上勾 ios。这种机器代理在非 darwin 上直接启动失败，
		// 而不拦的话错误要等到装机装了一半才出现，注册码已经消耗掉了
		"ios on linux": {"role": machineRoleBuilder, "name": "lin-" + uniqueSuffix(), "signerRole": nil,
			"platforms": []string{buildPlatformIOS}, "os": machineOSLinux},
		"ios without an os": {"role": machineRoleBuilder, "name": "lin-" + uniqueSuffix(), "signerRole": nil,
			"platforms": []string{buildPlatformIOS}},
	} {
		body["expectedVersion"] = registryVersion(t, f)
		body["reason"] = "should be refused"
		body["confirm"] = true
		if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", body); r.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
}

// 改平台那条路也得守同一条规矩：给机房那台 Linux 构建机加上 ios，它下次启动就挂
// （BUILD_AGENT_PLATFORMS=ios 在非 darwin 上直接失败），而控制台上看着一切正常。
func TestDBOnlyAMacCanBeGivenIOS(t *testing.T) {
	f := newGateFixture(t, 147)
	set := func(id string, platforms []string) *httptest.ResponseRecorder {
		return f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+id+"/platforms", map[string]any{
			"platforms": platforms, "expectedVersion": registryVersion(t, f),
			"reason": "change the platforms", "confirm": true,
		})
	}
	if r := set(f.builder.ID, []string{buildPlatformAndroid, buildPlatformIOS}); r.Code != http.StatusConflict ||
		problemCode(t, r) != "MACHINE_NOT_MACOS" {
		t.Fatalf("a linux builder was given ios: %d %s", r.Code, r.Body.String())
	}
	// 本来就该有的那条改动照常
	if r := set(f.builder.ID, []string{buildPlatformAndroid}); r.Code != http.StatusOK {
		t.Fatalf("android on a linux builder: %d %s", r.Code, r.Body.String())
	}
}

// 机器列表要把"登记"与"现在的样子"一起给出来：控制台上那张卡片要回答的是
// "这台机器活着没有、手上有哪些 Team 的材料、缺谁的"，而这三件事分在两处存
// （设计 §5.2、§5.4）。
func TestDBMachineListCarriesLivenessAndTheSigningGap(t *testing.T) {
	f, macs := newIOSPool(t, 75, 1)
	// 另一个租户也登记了 iOS 身份，但这台 Mac 没有它的材料：差集要把它列出来
	other := testTenant(76)
	if _, err := f.db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at)
		VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		other, "bld-"+other); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(iosReleaseIdentity{AppleTeamID: poolTeamB, BundleID: "com.other.app"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`, other, releaseIOSIdentityConfigKey, raw); err != nil {
		t.Fatal(err)
	}
	if recorder := iosClaim(f, macs[0], teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}

	listed := f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list machines: %d %s", listed.Code, listed.Body.String())
	}
	body := decodeBody(t, listed)
	if _, present := body["approvedAgentCommit"]; !present {
		t.Fatal("the machine list must say which agent version is approved")
	}
	items, _ := body["items"].([]any)
	var mac map[string]any
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if entry["id"] == macs[0].ID {
			mac = entry
		}
	}
	if mac == nil {
		t.Fatalf("the Mac is not in the list: %v", items)
	}
	live, _ := mac["liveness"].(map[string]any)
	if live == nil || live["online"] != true || live["lastSeenAt"] == nil {
		t.Fatalf("liveness: %v", live)
	}
	teams, _ := live["appleTeams"].([]any)
	if len(teams) != 1 {
		t.Fatalf("self-reported teams: %v", live["appleTeams"])
	}
	// 差集是跨租户算的（测试库里还有别的用例留下的租户），只断言该在的在、不该在的不在
	missing, _ := live["missingTenants"].([]any)
	var gapForOther map[string]any
	for _, item := range missing {
		gap, _ := item.(map[string]any)
		if gap["tenantId"] == other {
			gapForOther = gap
		}
		if gap["tenantId"] == f.tenant {
			t.Fatalf("a tenant this machine can build was listed as a gap: %v", gap)
		}
	}
	if gapForOther == nil || gapForOther["teamId"] != poolTeamB || gapForOther["bundleId"] != "com.other.app" {
		t.Fatalf("the signing gap must name the tenant this machine cannot build: %v", missing)
	}
	if gapForOther["slug"] == "" {
		t.Fatalf("a gap must name the tenant, not just its id: %v", gapForOther)
	}
	// 签名闸与只打 Android 的机器没有"缺哪个 Team"这个概念：给它们算差集只会在控制台上
	// 铺一片与它们无关的黄色
	for _, item := range items {
		entry, _ := item.(map[string]any)
		if entry["id"] == macs[0].ID {
			continue
		}
		entryLive, _ := entry["liveness"].(map[string]any)
		if entryLive == nil {
			t.Fatalf("every machine must carry a liveness block: %v", entry)
		}
		if gaps, _ := entryLive["missingTenants"].([]any); len(gaps) != 0 {
			t.Fatalf("a non-iOS machine was given a signing gap: %v", entry)
		}
	}
}
