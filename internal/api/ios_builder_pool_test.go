package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
func seedIOSIdentity(t *testing.T, f *gateFixture, teamID, bundleID string) {
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

func teamReport(teamID string, bundleIDs ...string) []appleTeamReport {
	return []appleTeamReport{{TeamID: teamID, BundleIDs: bundleIDs, ExpiresAt: "2027-03-01T00:00:00Z"}}
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
	seedIOSIdentity(t, f, poolTeamA, poolBundle)
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
