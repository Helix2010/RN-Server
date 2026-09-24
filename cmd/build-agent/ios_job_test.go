package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/fakebuild"
)

// iOS 安装包任务从领取到交付（自助上传：.ipa 交回服务端，租户自己传 TestFlight）。
//
// 三条和 Android 不一样的地方，每一条都来自"iOS 的签名与构建分不开"（设计
// ios-testflight-distribution-2026-09-17 §4.2）：不走未签名包那条交付、没有出处声明、
// 一步到 succeeded（/ios-release 而不是 /built）。交回的 .ipa 是交给租户的交付件
// （设计 ios-tenant-delivery-tiers-2026-09-24 §3.5），这台机器没开上传也照样能做。
func TestIOSJobReportsTheReleaseWithoutUploadingTheArtifact(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"android", "ios"}
	rig.agent.iosScan = fakeIOSInventory
	body := claimBody("bld_e2eIOS000001", "apk")
	body["platform"] = "ios"
	body["delivery"] = "ipa"
	rig.server.queueClaim(body)

	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent did not work on the claimed job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("the job failed: %s", fails[0].Body)
	}
	// 产物不上传：TestFlight 的包在 Apple 那边，而且不是这一份
	for _, suffix := range []string{"/unsigned/upload", "/sbom/upload", "/built"} {
		if calls := rig.server.callsTo(suffix); len(calls) != 0 {
			t.Fatalf("an ios job must not call %s", suffix)
		}
	}
	released := rig.server.callsTo("/ios-release")
	if len(released) != 1 {
		t.Fatalf("expected one /ios-release call, got %d; calls: %+v", len(released), rig.server.allCalls())
	}
	var report struct {
		CommitSHA                 string   `json:"commitSha"`
		IPASHA256                 string   `json:"ipaSha256"`
		IPASize                   int64    `json:"ipaSize"`
		BundleID                  string   `json:"bundleId"`
		ShortVersion              string   `json:"shortVersion"`
		BuildNumber               int      `json:"buildNumber"`
		UploadedToAppStoreConnect bool     `json:"uploadedToAppStoreConnect"`
		UploadedByEarlierAttempt  bool     `json:"uploadedByEarlierAttempt"`
		Toolchain                 string   `json:"toolchain"`
		LogTail                   []string `json:"logTail"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(released[0].Body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("the /ios-release body does not match the contract: %v\n%s", err, released[0].Body)
	}
	sum := sha256.Sum256(rig.tools.IPA)
	if report.IPASHA256 != hex.EncodeToString(sum[:]) || report.IPASize != int64(len(rig.tools.IPA)) {
		t.Fatalf("the digest must be of the ipa the runner handed over: %+v", report)
	}
	// 身份取服务端下发的那份 tenant.json，服务端会拿它和任务行、release.ios 再对一遍
	if report.BundleID != "com.anyfun.foundation" || report.ShortVersion != "1.3.7" || report.BuildNumber != 33 {
		t.Fatalf("unexpected identity: %+v", report)
	}
	if report.CommitSHA != rig.commit {
		t.Fatalf("commit %s, want %s", report.CommitSHA, rig.commit)
	}
	// 自助上传：包交回了服务端，没往 App Store Connect 推
	if report.UploadedToAppStoreConnect {
		t.Fatal("a self-upload job must not report an App Store Connect upload")
	}
	if handed := rig.server.uploads["ipa"]; string(handed) != string(rig.tools.IPA) {
		t.Fatalf("the .ipa handed back is not the one the runner built (%d bytes)", len(handed))
	}
	// 几台 Mac 装同一个 Xcode 是人工维护的约定，版本漂移只有记下来才看得见
	if report.Toolchain != fakebuild.XcodeVersion+" (16C5032a)" {
		t.Fatalf("the toolchain was not reported: %q", report.Toolchain)
	}
	// 构建脚本拿到的是签名目录，不是 --upload：执行进程一把 App Store Connect Key 都没有
	if dir := readRecorded(t, rig, "ios-signing-dir.txt"); dir == "" {
		t.Fatal("the build script was not told where the provisioning profiles are")
	}
}

// 全托管的任务要传 TestFlight：这台机器没开上传就不能装作做完了——服务端只把这种任务派给
// 上传 Key 可用的机器，走到这里说明两边对不上，要失败并说清原因。
func TestIOSTestFlightJobFailsOnAMachineThatDoesNotUpload(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"ios"}
	rig.agent.iosScan = fakeIOSInventory
	body := claimBody("bld_e2eIOS000003", "apk")
	body["platform"] = "ios"
	body["delivery"] = "testflight"
	rig.server.queueClaim(body)
	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent did not work on the claimed job")
	}
	fails := rig.server.callsTo("/fail")
	if len(fails) != 1 || !strings.Contains(string(fails[0].Body), "BUILD_AGENT_IOS_UPLOAD") {
		t.Fatalf("expected one failure naming the upload switch, got %+v", fails)
	}
	if calls := rig.server.callsTo("/ios-release"); len(calls) != 0 {
		t.Fatal("a TestFlight job that was not uploaded must not be reported as released")
	}
	if calls := rig.server.callsTo("/ipa/upload"); len(calls) != 0 {
		t.Fatal("a TestFlight job must not hand its .ipa back")
	}
}

// 开了上传开关的机器才传，而且这件事要如实报给服务端——"包打出来了"和
// "TestFlight 上有这一版"是两件事。
func TestIOSJobUploadsOnlyWhenTheMachineIsConfiguredTo(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"ios"}
	rig.agent.cfg.IOSUpload = true
	rig.agent.cfg.IOSUploader = fakeUploader(t, rig, `{"uploaded":true,"uploadedByEarlierAttempt":false,"detail":"uploaded","probe":""}`)
	rig.agent.iosScan = fakeIOSInventory
	body := claimBody("bld_e2eIOS000002", "apk")
	body["platform"] = "ios"
	rig.server.queueClaim(body)

	if !rig.agent.pollOnce(context.Background()) {
		t.Fatal("the agent did not work on the claimed job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("the job failed: %s", fails[0].Body)
	}
	released := rig.server.callsTo("/ios-release")
	if len(released) != 1 {
		t.Fatalf("expected one /ios-release call, got %d", len(released))
	}
	if !strings.Contains(string(released[0].Body), `"uploadedToAppStoreConnect":true`) {
		t.Fatalf("the upload must be reported: %s", released[0].Body)
	}
	// 上传由**另一个程序**做，控制进程只把核对过身份的包交给它。它收到的是包的内容
	// （标准输入）与期望的身份，不是一条能读到状态目录的路径
	args := readRecorded(t, rig, "ios-upload.args")
	for _, want := range []string{"--team AB12CD34EF", "--expect-bundle-id com.anyfun.foundation",
		"--expect-version 1.3.7", "--expect-build 33"} {
		if !strings.Contains(args, want) {
			t.Fatalf("the uploader was not told %q: %s", want, args)
		}
	}
	sum := sha256.Sum256(rig.tools.IPA)
	if got := readRecorded(t, rig, "ios-upload.sha256"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("the uploader did not receive the package that was built: %s", got)
	}
}

// fakeUploader 造一个假的上传程序：把收到的参数与包的摘要记下来，打印给定的一行 JSON。
func fakeUploader(t *testing.T, rig *testRig, outcome string) string {
	t.Helper()
	path := filepath.Join(rig.tools.Bin, "ios-upload")
	script := "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" > " + rig.tools.Record + "/ios-upload.args\n" +
		"sha256sum - | cut -d' ' -f1 | tr -d '\\n' > " + rig.tools.Record + "/ios-upload.sha256\n" +
		"printf '%s\\n' '" + outcome + "'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func readRecorded(t *testing.T, rig *testRig, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rig.tools.Record, name))
	if err != nil {
		t.Fatalf("the fake build recorded nothing at %s: %v", name, err)
	}
	return strings.TrimSpace(string(raw))
}
