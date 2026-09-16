package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/fakebuild"
	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/provenance"
)

// 安装包任务从领取到交付：执行进程出未签名包与 SBOM，控制进程传上去、签出处声明、调 /built。
// 出处声明必须能被 provenance.Verify 用本机公钥验过，字段取任务行与控制进程自己算的值。
func TestAPKJobDeliversAnUnsignedPackageWithVerifiableProvenance(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.server.queueClaim(claimBody("bld_e2eAPK000001", "apk"))

	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent did not work on the claimed job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("the job failed: %s", fails[0].Body)
	}
	built := rig.server.callsTo("/built")
	if len(built) != 1 {
		t.Fatalf("expected one /built call, got %d; calls: %+v", len(built), rig.server.allCalls())
	}
	var delivery struct {
		CommitSHA         string              `json:"commitSha"`
		NativeFingerprint string              `json:"nativeFingerprint"`
		Provenance        provenance.Envelope `json:"provenance"`
		LogTail           []string            `json:"logTail"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(built[0].Body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&delivery); err != nil {
		t.Fatalf("the /built body does not match the contract: %v\n%s", err, built[0].Body)
	}
	statement, err := provenance.Verify(delivery.Provenance, rig.agent.keys.current.public)
	if err != nil {
		t.Fatalf("the provenance does not verify with this machine's key: %v", err)
	}
	unsignedSum := sha256.Sum256(rig.server.uploads["unsigned"])
	sbomSum := sha256.Sum256(rig.server.uploads["sbom"])
	want := provenance.Statement{
		Version: provenance.Version, Purpose: provenance.Purpose,
		JobID: "bld_e2eAPK000001", Attempt: 2, TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation",
		VersionCode: 33, VersionName: "1.3.7", CommitSHA: rig.commit,
		UnsignedSHA256: hex.EncodeToString(unsignedSum[:]), UnsignedSize: int64(len(rig.tools.APK)),
		SBOMSHA256: hex.EncodeToString(sbomSum[:]), NativeFingerprint: fakebuild.NativeFingerprint,
		BuilderID: testMachineID, BuiltAt: statement.BuiltAt,
	}
	if statement != want {
		t.Fatalf("provenance statement\n got %+v\nwant %+v", statement, want)
	}
	if string(rig.server.uploads["unsigned"]) != string(rig.tools.APK) {
		t.Fatal("the uploaded unsigned package is not what the runner built")
	}
	if delivery.CommitSHA != rig.commit || delivery.NativeFingerprint != fakebuild.NativeFingerprint {
		t.Fatalf("delivery commit/fingerprint = %s/%s", delivery.CommitSHA, delivery.NativeFingerprint)
	}
	// 每个任务接口都带本机令牌与认领编号
	for _, call := range rig.server.allCalls() {
		if strings.Contains(call.Path, "/jobs/") && call.Attempt != "2" {
			t.Errorf("%s %s did not carry x-build-attempt: %q", call.Method, call.Path, call.Attempt)
		}
		if call.Token != testToken {
			t.Errorf("%s %s did not carry the machine token", call.Method, call.Path)
		}
	}
	// 执行进程的子进程拿不到令牌
	for _, step := range []string{"install", "fingerprint", "android-release", "sbom"} {
		if env := strings.Join(rig.tools.RecordedEnv(t, step), "\n"); strings.Contains(env, testToken) || strings.Contains(env, "BUILD_AGENT_") {
			t.Fatalf("step %s saw the controller environment:\n%s", step, env)
		}
	}
	// 任务目录（连同每任务的 GRADLE_USER_HOME）与 spool 副本都删掉了
	gradleHome := jobspec.EnvValue(rig.tools.RecordedEnv(t, "android-release"), "GRADLE_USER_HOME")
	if gradleHome == "" || !strings.HasPrefix(gradleHome, rig.agent.cfg.Workspace+"/") {
		t.Fatalf("GRADLE_USER_HOME %q is not inside the job directory", gradleHome)
	}
	if _, err := os.Stat(gradleHome); !os.IsNotExist(err) {
		t.Fatalf("the per-job GRADLE_USER_HOME survived: %v", err)
	}
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
	if _, err := os.Stat(filepath.Join(rig.agent.cfg.StateDir, spoolDirName, "bld_e2eAPK000001")); !os.IsNotExist(err) {
		t.Fatalf("the spool copy survived: %v", err)
	}
}

// 热更新任务：走原来那几条接口（带编号头），子进程环境与安装包任务一致
func TestOTAJobUsesTheSameEnvironmentAsTheAPKJob(t *testing.T) {
	rig := newRig(t)
	rig.server.queueClaim(claimBody("bld_e2eAPK000002", "apk"))
	rig.server.queueClaim(claimBody("bld_e2eOTA000002", "ota"))

	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no apk job")
	}
	apkEnv := strings.ReplaceAll(strings.Join(rig.tools.RecordedEnv(t, "install"), "\n"),
		filepath.Join(rig.agent.cfg.Workspace, "bld_e2eAPK000002"), "<job>")
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no ota job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("a job failed: %s", fails[0].Body)
	}
	otaDir := filepath.Join(rig.agent.cfg.Workspace, "bld_e2eOTA000002")
	for _, step := range []string{"install", "ota-build"} {
		otaEnv := strings.ReplaceAll(strings.Join(rig.tools.RecordedEnv(t, step), "\n"), otaDir, "<job>")
		if otaEnv != apkEnv {
			t.Fatalf("OTA step %s saw a different environment than the APK build:\napk:\n%s\nota:\n%s", step, apkEnv, otaEnv)
		}
	}
	complete := rig.server.callsTo("/complete")
	if len(complete) != 1 || complete[0].Attempt != "2" {
		t.Fatalf("the OTA job was not completed with its attempt: %+v", complete)
	}
	var body map[string]any
	_ = json.Unmarshal(complete[0].Body, &body)
	otaSum := sha256.Sum256(rig.tools.OTA)
	if body["releaseId"] != "ota_rel0001" || body["artifactSha256"] != hex.EncodeToString(otaSum[:]) || body["commitSha"] != rig.commit {
		t.Fatalf("complete body = %v", body)
	}
	for _, call := range rig.server.callsTo("/ota-artifact") {
		if call.Attempt != "2" || call.Token != testToken {
			t.Fatalf("the OTA artifact PUT to the server did not carry token and attempt: %+v", call)
		}
	}
	if len(rig.server.callsTo("/built")) != 1 {
		t.Fatal("the OTA job must not call /built")
	}
}

// 心跳收到 409 BUILD_ATTEMPT_STALE：立刻中止执行进程、清理任务目录，不再上报任何东西
func TestStaleHeartbeatAbortsTheBuildAndCleansUp(t *testing.T) {
	rig := newRig(t)
	if err := os.WriteFile(rig.tools.Sleep, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rig.server.heartbeatCode = codeAttemptStale
	rig.server.queueClaim(claimBody("bld_staleJOB0001", "apk"))

	started := time.Now()
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no job")
	}
	if elapsed := time.Since(started); elapsed > 60*time.Second {
		t.Fatalf("aborting took %s; the fake install sleeps 120s, so it was not stopped", elapsed)
	}
	for _, suffix := range []string{"/fail", "/built", "/complete", "/unsigned/upload"} {
		if calls := rig.server.callsTo(suffix); len(calls) != 0 {
			t.Fatalf("a stale attempt still reported %s", suffix)
		}
	}
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
}

// 领取结果里出现签名材料字段：整条任务拒收并报失败，磁盘上什么都不写
func TestClaimCarryingSigningMaterialIsRefused(t *testing.T) {
	for _, field := range []string{"sealedKeystore", "keyAlias", "storePassword"} {
		t.Run(field, func(t *testing.T) {
			rig := newRig(t)
			body := claimBody("bld_sealedJOB001", "apk")
			body[field] = map[string]any{"v": 2, "ct": "AAAA"}
			rig.server.queueClaim(body)
			if !rig.agent.pollOnce(context.Background()) {
				t.Fatal("the refused claim was not handled")
			}
			fails := rig.server.callsTo("/fail")
			if len(fails) != 1 || fails[0].Attempt != "2" || !strings.Contains(string(fails[0].Body), field) {
				t.Fatalf("the refusal was not reported with the attempt and the field: %+v", fails)
			}
			if left := jobRootEntries(t, rig.agent); len(left) != 0 {
				t.Fatalf("a refused job touched the disk: %v", left)
			}
			if len(rig.server.callsTo("/built")) != 0 {
				t.Fatal("a refused job was delivered")
			}
		})
	}
	// 嵌套在别的字段里也算
	if field := forbiddenClaimField(map[string]any{"tenantFile": map[string]any{"keystorePassword": "x"}}, ""); field != "tenantFile.keystorePassword" {
		t.Fatalf("nested field not found: %q", field)
	}
}

// 启动时服务端说本机还有在途任务：判它失败（带服务端给的编号），然后继续领
func TestActiveJobFromAnEarlierRunIsReportedFailed(t *testing.T) {
	rig := newRig(t)
	rig.server.queueProblem(http.StatusConflict, codeBuilderHasActiveJob, map[string]any{"jobId": "bld_orphanJOB001", "attempt": 3})
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("the active job was not handled")
	}
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || !strings.Contains(fails[0].Path, "bld_orphanJOB001") || fails[0].Attempt != "3" {
		t.Fatalf("the orphan was not failed with its attempt: %+v", fails)
	}
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("an empty queue was reported as work")
	}
}

// 服务端下发的 gitRef 不是 main：不检出、判失败
func TestJobOnAnotherBranchIsRefused(t *testing.T) {
	rig := newRig(t)
	body := claimBody("bld_branchJOB001", "apk")
	body["gitRef"] = "evil"
	rig.server.queueClaim(body)
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("no job")
	}
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || !strings.Contains(string(fails[0].Body), "git ref") {
		t.Fatalf("the branch was not refused: %+v", fails)
	}
}

// 公钥没被接受之前不领任务
func TestPendingKeyMeansNoClaims(t *testing.T) {
	rig := newRig(t)
	rig.server.keyStatus = "pending_key"
	rig.server.queueClaim(claimBody("bld_pendingJOB01", "apk"))
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("worked while the key was pending")
	}
	if claims := rig.server.callsTo("/claim"); len(claims) != 0 {
		t.Fatal("claimed while the key was pending")
	}
	registrations := rig.server.callsTo("/public-key")
	if len(registrations) != 1 {
		t.Fatalf("registrations: %d", len(registrations))
	}
	var body map[string]any
	_ = json.Unmarshal(registrations[0].Body, &body)
	if body["rotationSignature"] != nil || body["publicKey"] != rig.agent.keys.current.publicBase64() {
		t.Fatalf("registration body = %v", body)
	}
	rig.server.acceptPending(rig.agent.keys.current.public)
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("did not work after the key was accepted")
	}
}

// 已 active 的机器换钥：用当前私钥签换钥证明登记下一把；控制台接受之后换上它
func TestKeyRotationIsProvenAndPromotedAfterAcceptance(t *testing.T) {
	rig := newRig(t)
	next, created, err := createNextKey(rig.agent.cfg.StateDir)
	if err != nil || !created {
		t.Fatalf("createNextKey: %v %v", created, err)
	}
	rig.agent.keys.next = &next
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("an empty queue was reported as work")
	}
	rig.server.mu.Lock()
	pending := rig.server.pendingSHA
	rig.server.mu.Unlock()
	if pending != next.sha256 {
		t.Fatalf("the rotation key was not registered with a valid proof (pending %q)", pending)
	}
	if rig.agent.keys.current.sha256 == next.sha256 {
		t.Fatal("the rotation key was put in place before acceptance")
	}

	rig.server.acceptPending(next.public)
	rig.agent.keyActive = false
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("an empty queue was reported as work")
	}
	if rig.agent.keys.current.sha256 != next.sha256 || rig.agent.keys.next != nil {
		t.Fatal("the accepted rotation key was not promoted")
	}
	if _, err := os.Stat(filepath.Join(rig.agent.cfg.StateDir, provenanceNextKeyFile)); !os.IsNotExist(err) {
		t.Fatal("the rotation key file is still there")
	}
	reloaded, err := loadOrCreateKeyring(rig.agent.cfg.StateDir)
	if err != nil || reloaded.current.sha256 != next.sha256 {
		t.Fatalf("after a restart the machine would use another key: %v", err)
	}
}

// 服务端不给 machineId 时不能签换钥证明，就不换
func TestRotationNeedsTheMachineID(t *testing.T) {
	rig := newRig(t)
	rig.server.omitMachineID = true
	next, _, err := createNextKey(rig.agent.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	rig.agent.keys.next = &next
	rig.agent.pollOnce(context.Background())
	for _, call := range rig.server.callsTo("/public-key") {
		if strings.Contains(string(call.Body), next.publicBase64()) {
			t.Fatal("a rotation was proposed without knowing the machine id")
		}
	}
}

// 构建失败：原因来自执行进程最后一行，带编号报 /fail，任务目录照样清掉
func TestRunnerFailureIsReportedWithTheRunnerReason(t *testing.T) {
	rig := newRig(t)
	if err := os.WriteFile(filepath.Join(rig.tools.Bin, "node"), []byte("#!/bin/sh\necho 'syft: command not found' >&2\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rig.server.queueClaim(claimBody("bld_failingJOB01", "apk"))
	rig.agent.pollOnce(context.Background())
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || fails[0].Attempt != "2" {
		t.Fatalf("fail calls: %+v", fails)
	}
	var body struct {
		FailureReason string   `json:"failureReason"`
		CommitSHA     string   `json:"commitSha"`
		LogTail       []string `json:"logTail"`
	}
	if err := json.Unmarshal(fails[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.FailureReason, "SBOM") || body.CommitSHA != rig.commit {
		t.Fatalf("fail body = %+v", body)
	}
	if !strings.Contains(strings.Join(body.LogTail, "\n"), "syft: command not found") {
		t.Fatal("the runner output did not reach the log tail")
	}
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
}

// 启动时任务根目录里残留的任务目录（含执行进程改成 000 的目录）被清掉
func TestPruneOrphansEmptiesTheJobsRoot(t *testing.T) {
	rig := newRig(t)
	layout, _ := jobspec.NewLayout(rig.agent.cfg.Workspace, "bld_orphanDIR001")
	locked := filepath.Join(layout.Work(), "gradle-home", "init.d")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout.Out(), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rig.agent.cfg.Workspace, "stray-file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(rig.agent.cfg.StateDir, spoolDirName, "bld_old"), 0o700); err != nil {
		t.Fatal(err)
	}
	rig.agent.pruneOrphans()
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if _, err := os.Stat(filepath.Join(rig.agent.cfg.StateDir, spoolDirName)); !os.IsNotExist(err) {
		t.Fatal("old spool copies survived")
	}
}

func TestCheckRunnerInDirectModeRunsTheSelfCheck(t *testing.T) {
	rig := newRig(t)
	if err := rig.agent.checkRunner(context.Background()); err != nil {
		t.Fatalf("self-check failed: %v", err)
	}
	// 分用户模式下，执行进程二进制必须属于 root：测试里编出来的这个属于当前用户
	rig.agent.cfg.RunnerUser = "builder"
	if err := rig.agent.checkRunner(context.Background()); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("a runner binary the agent user could replace was accepted: %v", err)
	}
}

// 分用户模式下经 sudo 启动，给 sudo 的环境里没有令牌
func TestRunnerCommandUsesSudoWithAMinimalEnvironment(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	a := &agent{cfg: config{Runner: "/opt/rn-build-agent/build-runner", RunnerUser: "builder"}}
	cmd := a.runnerCommand(context.Background(), "build", "--jobs-root", "/var/lib/rn-build-jobs", "--job", "bld_abcd1234", "--kind", "apk")
	want := []string{sudoPath, "-n", "-u", "builder", "--", "/opt/rn-build-agent/build-runner", "build", "--jobs-root", "/var/lib/rn-build-jobs", "--job", "bld_abcd1234", "--kind", "apk"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v", cmd.Args)
	}
	if env := strings.Join(cmd.Env, "\n"); strings.Contains(env, testToken) || len(cmd.Env) > 2 {
		t.Fatalf("the runner command environment is not minimal: %v", cmd.Env)
	}
	a.cfg.RunnerUser = directRunner
	if direct := a.runnerCommand(context.Background(), "cleanup"); direct.Path != "/opt/rn-build-agent/build-runner" {
		t.Fatalf("direct mode did not execute the runner itself: %v", direct.Args)
	}
}
