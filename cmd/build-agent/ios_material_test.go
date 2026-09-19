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
