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
)

// iOS 安装包任务从领取到交付。
//
// 三条和 Android 不一样的地方，每一条都来自"iOS 的签名与构建分不开"（设计
// ios-testflight-distribution-2026-09-17 §4.2）：不上传产物、没有出处声明、
// 一步到 succeeded（/ios-release 而不是 /built）。
func TestIOSJobReportsTheReleaseWithoutUploadingTheArtifact(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"android", "ios"}
	body := claimBody("bld_e2eIOS000001", "apk")
	body["platform"] = "ios"
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
	// 这台机器没开上传开关：出了包，但没往 App Store Connect 推
	if report.UploadedToAppStoreConnect {
		t.Fatal("this machine has BUILD_AGENT_IOS_UPLOAD off; it must not report an upload")
	}
	if upload := readRecorded(t, rig, "ios-upload.txt"); upload != "no" {
		t.Fatalf("the build script must not have been told to upload, got %q", upload)
	}
}

// 开了上传开关的机器才传，而且这件事要如实报给服务端——"包打出来了"和
// "TestFlight 上有这一版"是两件事。
func TestIOSJobUploadsOnlyWhenTheMachineIsConfiguredTo(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.Platforms = []string{"ios"}
	rig.agent.cfg.IOSUpload = true
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
	if upload := readRecorded(t, rig, "ios-upload.txt"); upload != "yes" {
		t.Fatalf("the build script must have been told to upload, got %q", upload)
	}
}

func readRecorded(t *testing.T, rig *testRig, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rig.tools.Record, name))
	if err != nil {
		t.Fatalf("the fake build recorded nothing at %s: %v", name, err)
	}
	return strings.TrimSpace(string(raw))
}
