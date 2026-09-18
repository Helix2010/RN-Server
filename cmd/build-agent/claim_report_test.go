package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// 认领时自报什么（设计 ios-mac-builders-home-network-2026-09-18 §5.2、§5.4、§6.2）。
//
// 空队列上的认领是这台机器唯一的生命迹象——服务端就是靠这些空转的请求知道它还活着、
// 手上有哪些 Team 的材料。所以"认领体里带什么"本身是契约的一部分。

func lastClaimBody(t *testing.T, rig *testRig) map[string]any {
	t.Helper()
	calls := rig.server.callsTo("/claim")
	if len(calls) == 0 {
		t.Fatal("the agent did not claim")
	}
	var body map[string]any
	if err := json.Unmarshal(calls[len(calls)-1].Body, &body); err != nil {
		t.Fatalf("claim body is not JSON: %v", err)
	}
	return body
}

func TestClaimCarriesTheSigningInventory(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"ios"}
	rig.agent.iosScan = fakeIOSInventory

	// 队列空：这一次认领什么都领不到，但自报照样要发出去
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent claimed a job that was not queued")
	}
	body := lastClaimBody(t, rig)
	teams, _ := body["appleTeams"].([]any)
	if len(teams) != 1 {
		t.Fatalf("the claim did not carry the signing inventory: %v", body["appleTeams"])
	}
	team, _ := teams[0].(map[string]any)
	if team["teamId"] != "AB12CD34EF" || team["uploadProbe"] != "ok" {
		t.Fatalf("self-reported team: %v", team)
	}
	bundles, _ := team["bundleIds"].([]any)
	if len(bundles) != 1 || bundles[0] != "com.anyfun.foundation" {
		t.Fatalf("self-reported bundle ids: %v", team["bundleIds"])
	}
	if team["expiresAt"] == "" || team["expiresAt"] == nil {
		t.Fatal("the claim must carry when this team's material expires")
	}
	if body["os"] == "" || body["paused"] == true {
		t.Fatalf("a healthy machine must not report itself paused: %v", body)
	}
}

// 空闲空间不够就不领活，但**仍然来报到**：让它干脆别来问的话，控制台只能看到"离线"，
// 而磁盘满和关机需要的处理完全不同（§6.2）。
func TestClaimPausesItselfWhenTheDiskIsTooFull(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	// 没有哪台机器有这么多空间：等于"永远低于阈值"
	rig.agent.cfg.MinFreeGB = 1 << 30
	rig.server.queueClaim(claimBody("bld_shouldNotRun", "apk"))

	// 假服务端不看 paused，照样派了一条过来（真服务端看到 paused 就回 204）。
	// 代理必须自己不去做它
	rig.agent.pollOnce(context.Background())
	body := lastClaimBody(t, rig)
	if body["paused"] != true {
		t.Fatalf("the claim did not say the machine is paused: %v", body)
	}
	reason, _ := body["pausedReason"].(string)
	if reason == "" {
		t.Fatal("a paused claim must say why")
	}
	if calls := rig.server.callsTo("/built"); len(calls) != 0 {
		t.Fatal("a paused agent worked on a job anyway")
	}
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || !strings.Contains(string(fails[0].Body), "BUILD_AGENT_MIN_FREE_GB") {
		t.Fatalf("a job dispatched to a paused machine must fail with the reason: %v", fails)
	}
}

// 服务端说"先升级"（409 AGENT_UPGRADE_REQUIRED）：写停机标记、以 75 退出。
//
// 标记是给 launchd 看的：它不认退出码（systemd 有 RestartPreventExitStatus），不写标记的话
// 一台要求升级的机器会变成每秒重启一次。root 的升级程序换完二进制删掉标记，launchd 随即
// 把新版拉起来。
func TestUpgradeRequiredWritesTheHaltMarkerAndExits75(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	const approved = "3333333333333333333333333333333333333333"
	rig.server.queueProblem(http.StatusConflict, "AGENT_UPGRADE_REQUIRED", map[string]any{"agentCommit": approved})
	// 队列里还有一条任务：要求升级的时候服务端不派活，代理也不该去做它
	rig.server.queueClaim(claimBody("bld_notWhileUpgrading", "apk"))

	if code := rig.agent.serve(context.Background()); code != exitUpgradeRequired {
		t.Fatalf("exit %d, want %d", code, exitUpgradeRequired)
	}
	raw, err := os.ReadFile(haltPath(rig.agent.cfg.StateDir))
	if err != nil {
		t.Fatalf("no halt marker: %v", err)
	}
	if strings.TrimSpace(string(raw)) != upgradeHaltReason(approved) {
		t.Fatalf("halt marker says %q", strings.TrimSpace(string(raw)))
	}
	if calls := rig.server.callsTo("/built"); len(calls) != 0 {
		t.Fatal("the agent took a job after it was told to upgrade")
	}
}

// 上一次升级失败过：启动时读出来，随认领报给服务端——控制台不然只能看到
// "这台机器的版本一直追不上审批值"。
func TestClaimReportsALastFailedUpgrade(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	if err := writeUpgradeFailure(rig.agent.cfg.StateDir, "4444444444444444444444444444444444444444",
		errors.New("the archive does not match the digest in the signed manifest"), time.Now()); err != nil {
		t.Fatal(err)
	}
	failure, failed := readUpgradeFailure(rig.agent.cfg.StateDir)
	if !failed {
		t.Fatal("the failure was not read back")
	}
	rig.agent.upgradeError = failure.summary()
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent claimed a job that was not queued")
	}
	body := lastClaimBody(t, rig)
	reported, _ := body["upgradeError"].(string)
	if !strings.Contains(reported, "4444444444444444444444444444444444444444") ||
		!strings.Contains(reported, "does not match the digest") {
		t.Fatalf("the claim did not carry why the upgrade failed: %q", reported)
	}
}
