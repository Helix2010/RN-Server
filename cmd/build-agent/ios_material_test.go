package main

// 材料自动装配：控制进程只搬密文，装是两个角色账户的事（设计 §6.2）。
//
// 这一组盯三件：该装的装上、已经装到这一版的不重复装、以及**控制进程手里那份始终是密文**
// ——它解不开，也不该解得开。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// materialRig 把假的 build-runner 与 ios-upload 摆好：它们只把收到的标准输入原样存下来，
// 再回一行 {"installed":true}。真正的解密在它们那一侧，另有用例。
func materialRig(t *testing.T) (*agent, *fakeServer, string) {
	t.Helper()
	rig := newRig(t)
	a := rig.agent
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > " + dir + "/$(basename $0).stdin\nprintf '%s' '{\"installed\":true}'\n"
	for _, name := range []string{"build-runner", "ios-upload"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	a.cfg.Runner, a.cfg.RunnerUser = filepath.Join(dir, "build-runner"), directRunner
	a.cfg.IOSUploader, a.cfg.IOSUploadUser = filepath.Join(dir, "ios-upload"), directRunner
	a.cfg.IOSUploadKeys = filepath.Join(dir, "upload")
	if a.cfg.MachineEnv == nil {
		a.cfg.MachineEnv = map[string]string{}
	}
	a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] = filepath.Join(dir, "signing")
	a.cfg.MachineEnv["PATH"] = "/usr/bin:/bin"
	return a, rig.server, dir
}

func listEntry(kind, team, scope, purpose string, version int64) map[string]any {
	return map[string]any{
		"kind": kind, "teamId": team, "scope": scope, "purpose": purpose,
		"recipientSha256": strings.Repeat("a", 64), "version": version,
		"uploadedBy": "admin", "uploadedAt": "2026-09-19T00:00:00Z",
	}
}

func TestAgentInstallsMaterialItDoesNotHaveYet(t *testing.T) {
	a, server, dir := materialRig(t)
	server.material = []map[string]any{
		listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 3),
		listEntry("upload-key", "J4JDFC8LCC", "mch_x", iosmaterial.PurposeUploader, 1),
	}
	server.materialBoxes = map[string][]byte{
		"certificate/J4JDFC8LCC/":     []byte(`{"pretend":"certificate ciphertext"}`),
		"upload-key/J4JDFC8LCC/mch_x": []byte(`{"pretend":"upload key ciphertext"}`),
	}

	a.syncIOSMaterial(context.Background())

	// 证书交给了执行账户那个程序，上传 Key 交给了上传账户那个——各回各家
	runnerStdin, err := os.ReadFile(filepath.Join(dir, "build-runner.stdin"))
	if err != nil || !strings.Contains(string(runnerStdin), "certificate ciphertext") {
		t.Fatalf("the certificate did not reach the build user: %q %v", runnerStdin, err)
	}
	uploaderStdin, err := os.ReadFile(filepath.Join(dir, "ios-upload.stdin"))
	if err != nil || !strings.Contains(string(uploaderStdin), "upload key ciphertext") {
		t.Fatalf("the upload key did not reach the upload user: %q %v", uploaderStdin, err)
	}
	// 记下来了：下一轮不该再装一遍
	installed := readInstalledMaterial(a.cfg.StateDir)
	if installed["certificate/J4JDFC8LCC/"] != 3 || installed["upload-key/J4JDFC8LCC/mch_x"] != 1 {
		t.Fatalf("versions were not recorded: %v", installed)
	}
}

func TestAgentSkipsMaterialItAlreadyHas(t *testing.T) {
	a, server, dir := materialRig(t)
	server.material = []map[string]any{
		listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 3),
	}
	server.materialBoxes = map[string][]byte{
		"certificate/J4JDFC8LCC/": []byte(`{"pretend":"ciphertext"}`),
	}
	if err := writeInstalledMaterial(a.cfg.StateDir, map[string]int64{
		"certificate/J4JDFC8LCC/": 3,
	}); err != nil {
		t.Fatal(err)
	}

	a.syncIOSMaterial(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "build-runner.stdin")); err == nil {
		t.Fatal("a material that is already installed was installed again")
	}

	// 版本往上走了就要再装一遍：换证书走的就是这条路
	a.lastMaterialSync = a.lastMaterialSync.Add(-iosMaterialSyncEvery)
	server.material = []map[string]any{
		listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 4),
	}
	a.syncIOSMaterial(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "build-runner.stdin")); err != nil {
		t.Fatalf("a newer version was not installed: %v", err)
	}
}

// 装不上一份不该挡住别的：证书失败时描述文件照样该放好，缺的是哪一片控制台上看得见。
func TestAgentKeepsGoingWhenOneMaterialFails(t *testing.T) {
	a, server, dir := materialRig(t)
	failing := "#!/bin/sh\ncat >/dev/null\necho 'boom' >&2\nexit 1\n"
	if err := os.WriteFile(a.cfg.Runner, []byte(failing), 0o755); err != nil {
		t.Fatal(err)
	}
	server.material = []map[string]any{
		listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 1),
		listEntry("upload-key", "J4JDFC8LCC", "mch_x", iosmaterial.PurposeUploader, 1),
	}
	server.materialBoxes = map[string][]byte{
		"certificate/J4JDFC8LCC/":     []byte(`{"a":1}`),
		"upload-key/J4JDFC8LCC/mch_x": []byte(`{"b":2}`),
	}

	a.syncIOSMaterial(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "ios-upload.stdin")); err != nil {
		t.Fatalf("a failing certificate stopped the upload key from being installed: %v", err)
	}
	installed := readInstalledMaterial(a.cfg.StateDir)
	if _, recorded := installed["certificate/J4JDFC8LCC/"]; recorded {
		t.Error("a material that failed to install was recorded as installed; it would never be retried")
	}
	if installed["upload-key/J4JDFC8LCC/mch_x"] != 1 {
		t.Errorf("the one that worked was not recorded: %v", installed)
	}
}

// 两次之间有节流：认领每 10 秒一次，而材料几个月才动一次。
func TestAgentDoesNotAskForTheMaterialListEveryClaim(t *testing.T) {
	a, server, _ := materialRig(t)
	server.material = nil
	a.syncIOSMaterial(context.Background())
	before := len(server.callsTo("/v1/build-agent/ios-material"))
	a.syncIOSMaterial(context.Background())
	if got := len(server.callsTo("/v1/build-agent/ios-material")); got != before {
		t.Fatalf("the list was fetched again right away: %d → %d", before, got)
	}
}

// 坏掉的本机记录当作什么都没装：重装是幂等的，而拿着一份坏记录会永远跳过。
func TestAgentTreatsABrokenRecordAsNothingInstalled(t *testing.T) {
	a, _, _ := materialRig(t)
	if err := os.WriteFile(filepath.Join(a.cfg.StateDir, installedMaterialFile),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readInstalledMaterial(a.cfg.StateDir); len(got) != 0 {
		t.Fatalf("a broken record was trusted: %v", got)
	}
}

// 装不上的时候，执行进程说了什么必须跟着错误一起出来。
//
// build-runner 把失败原因写在**标准输出**（"build-runner: error: …"），标准错误是空的。
// 只读标准错误的那一版里，这条错退化成一句 "exit status 1:"——2026-09-20 真机上证书
// 装不上就是这样，security import 到底说了什么被整条丢掉，只能上机器手工复现才知道。
func TestAgentCarriesTheRunnerReasonOutOfAFailedInstall(t *testing.T) {
	a, server, _ := materialRig(t)
	failing := "#!/bin/sh\ncat >/dev/null\n" +
		"echo 'build-runner: error: security import: exit status 1: MAC verification failed'\nexit 1\n"
	if err := os.WriteFile(a.cfg.Runner, []byte(failing), 0o755); err != nil {
		t.Fatal(err)
	}
	server.material = []map[string]any{listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 1)}
	server.materialBoxes = map[string][]byte{"certificate/J4JDFC8LCC/": []byte(`{"a":1}`)}

	err := a.installMaterial(context.Background(), materialEntry{
		Kind: "certificate", TeamID: "J4JDFC8LCC", Purpose: iosmaterial.PurposeBuilder, Version: 1,
	})
	if err == nil {
		t.Fatal("a failing runner was reported as a successful install")
	}
	if !strings.Contains(err.Error(), "MAC verification failed") {
		t.Errorf("the runner's own reason did not reach the error: %v", err)
	}
}

// 墓碑：本机从清单装过的上传 Key，清单里这个 Team 没有了（租户切到自助上传、Key 被撤下），
// 就请上传账户删掉本机那一份。服务端删材料只删它自己的密文，打包机上那份要靠这一步。
// 同一个 Team 换了 scope（还在清单里）不删；装机时手工放、不在本机记录里的 Key 不碰。
func TestAgentRemovesUploadKeysTheServerWithdrew(t *testing.T) {
	a, server, dir := materialRig(t)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + dir + "/ios-upload.calls\n" +
		"case \"$*\" in *--remove-key*) printf '%s' '{\"removed\":true,\"existed\":true}';; *) cat >/dev/null; printf '%s' '{\"installed\":true}';; esac\n"
	if err := os.WriteFile(filepath.Join(dir, "ios-upload"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeInstalledMaterial(a.cfg.StateDir, map[string]int64{
		"certificate/J4JDFC8LCC/":     3,
		"upload-key/J4JDFC8LCC/":      2, // 清单里没有了：删
		"upload-key/ZZ99YY88XX/mch_x": 1, // 清单里这个 Team 换成了 Team Key：不删
	}); err != nil {
		t.Fatal(err)
	}
	server.material = []map[string]any{
		listEntry("certificate", "J4JDFC8LCC", "", iosmaterial.PurposeBuilder, 3),
		listEntry("upload-key", "ZZ99YY88XX", "", iosmaterial.PurposeUploader, 1),
	}
	server.materialBoxes = map[string][]byte{"upload-key/ZZ99YY88XX/": []byte(`{"pretend":"team key"}`)}

	a.syncIOSMaterial(context.Background())

	calls, err := os.ReadFile(filepath.Join(dir, "ios-upload.calls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(calls), "--remove-key --team J4JDFC8LCC") {
		t.Fatalf("the withdrawn key was not removed: %s", calls)
	}
	if strings.Contains(string(calls), "--remove-key --team ZZ99YY88XX") {
		t.Fatalf("a team still in the list lost its key: %s", calls)
	}
	installed := readInstalledMaterial(a.cfg.StateDir)
	if _, still := installed["upload-key/J4JDFC8LCC/"]; still {
		t.Fatalf("the removed key is still recorded as installed: %v", installed)
	}
	if installed["certificate/J4JDFC8LCC/"] != 3 {
		t.Fatalf("signing material must not be touched: %v", installed)
	}
}

// 清单被截断（服务端 LIMIT）时"清单里没有"不等于"撤下了"：一把 Key 都不删。
func TestAgentKeepsUploadKeysWhenTheListIsTruncated(t *testing.T) {
	a, server, dir := materialRig(t)
	if err := writeInstalledMaterial(a.cfg.StateDir, map[string]int64{"upload-key/J4JDFC8LCC/": 2}); err != nil {
		t.Fatal(err)
	}
	server.material = []map[string]any{}
	server.materialTruncated = true
	a.syncIOSMaterial(context.Background())
	if _, err := os.Stat(filepath.Join(dir, "ios-upload.stdin")); err == nil {
		t.Fatal("the uploader was called although nothing needed installing")
	}
	if readInstalledMaterial(a.cfg.StateDir)["upload-key/J4JDFC8LCC/"] != 2 {
		t.Fatal("a key was treated as withdrawn from a truncated list")
	}
}
