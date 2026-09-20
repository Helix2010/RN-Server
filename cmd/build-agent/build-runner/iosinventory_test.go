package main

// ios-inventory：控制进程读不到签名区（0700 _rnbuilder），由这里以执行账户的身份把原文
// 取出来。真机上的表现很安静——控制进程只打一行
// "cannot read /var/rn-build-signing/profiles: permission denied"，然后一个 Team 都不报，
// 控制台上这台机器永远"缺材料"，iOS 任务永远派不过来。

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

func signingDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rn-build-signing")
	if err := os.MkdirAll(filepath.Join(dir, jobspec.IOSProfilesDirName, "AB12CD34EF"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func decodeMaterial(t *testing.T, out string) jobspec.IOSMaterial {
	t.Helper()
	var material jobspec.IOSMaterial
	if err := json.Unmarshal([]byte(out), &material); err != nil {
		t.Fatalf("ios-inventory did not answer with JSON: %v\n%s", err, out)
	}
	return material
}

func TestIOSInventoryHandsBackTheProfilesVerbatim(t *testing.T) {
	dir := signingDir(t)
	body := []byte("cms-noise<?xml version=\"1.0\"?><plist></plist>trailer")
	path := filepath.Join(dir, jobspec.IOSProfilesDirName, "AB12CD34EF", "wallet"+jobspec.IOSProfileSuffix)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	code, out := runRunner(t, func(string) string { return "" }, "ios-inventory", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	material := decodeMaterial(t, out)
	got, ok := material.Profiles["AB12CD34EF/wallet"+jobspec.IOSProfileSuffix]
	if !ok {
		t.Fatalf("the profile is missing from the answer: %+v", material)
	}
	if string(got) != string(body) {
		t.Errorf("the profile came back changed: %q", got)
	}
	// 解析与判断留在控制进程那一侧：这里不该替它得出任何结论
	if strings.Contains(out, "expired") || strings.Contains(out, "teams") {
		t.Errorf("ios-inventory drew a conclusion instead of handing over the raw material: %s", out)
	}
	// 这台机器上没有 /usr/bin/security（Linux）时要把失败说出来，不能装作钥匙串是空的：
	// 空钥匙串意味着"这台机器一个 Team 都签不了"，与"读不到钥匙串"是两回事
	if material.Identities == "" && material.IdentitiesError == "" {
		t.Error("neither the identities nor a reason came back; an empty keychain and an unreadable one must not look alike")
	}
}

func TestIOSInventoryRefusesADirectoryThatIsNotTheBuildUsers(t *testing.T) {
	dir := signingDir(t)
	cases := map[string]string{
		"relative": "var/rn-build-signing",
		"unclean":  dir + "/../" + filepath.Base(dir),
		"missing":  filepath.Join(dir, "nope"),
		"world-writable": func() string {
			open := filepath.Join(t.TempDir(), "open")
			if err := os.MkdirAll(open, 0o777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(open, 0o777); err != nil {
				t.Fatal(err)
			}
			return open
		}(),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := runRunner(t, func(string) string { return "" }, "ios-inventory", "--signing-dir", path)
			if code != exitUsage {
				t.Fatalf("exit %d for %q, expected %d: %s", code, path, exitUsage, out)
			}
			if !strings.HasPrefix(out, errorPrefix) {
				t.Errorf("no reason on screen: %s", out)
			}
		})
	}
}

// 描述文件目录不在（还没放材料的新机器）不是错：报空，不报问题。
func TestIOSInventoryIsQuietOnAMachineWithNoMaterialYet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rn-build-signing")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out := runRunner(t, func(string) string { return "" }, "ios-inventory", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	material := decodeMaterial(t, out)
	if len(material.Profiles) != 0 {
		t.Errorf("profiles: %v", material.Profiles)
	}
	for _, problem := range material.Problems {
		if strings.Contains(problem, jobspec.IOSProfilesDirName) {
			t.Errorf("a machine that has not been given any material yet reported a problem: %s", problem)
		}
	}
}

// 设搜索列表与问身份必须在同一个 security 进程里。
//
// find-identity -v 的 -v 要做一次信任评估，而中间证书（Apple 的 WWDR）是按钥匙串搜索
// 列表找的。两条命令分成两次调用，链就建不起来——报 0 个有效身份，**而且不报错**。
// 2026-09-20 真机上三张证书都在钥匙串里、verify-cert 说链没问题，盘点却一个 Team 都不报。
func TestIOSInventoryAsksForIdentitiesInTheProcessThatSetTheSearchList(t *testing.T) {
	dir := signingDir(t)
	record := filepath.Join(t.TempDir(), "security-stdin")
	restore := securityInteractive
	securityInteractive = func(ctx context.Context) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "cat > "+record+"; printf 'pretend identities'")
	}
	t.Cleanup(func() { securityInteractive = restore })

	code, out := runRunner(t, func(string) string { return "" }, "ios-inventory", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if material := decodeMaterial(t, out); material.Identities != "pretend identities" {
		t.Errorf("the identities did not come from the interactive call: %q / %q",
			material.Identities, material.IdentitiesError)
	}
	script, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("security -i was never started: %v", err)
	}
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	search := strings.Index(string(script), "list-keychains -s "+keychain)
	identities := strings.Index(string(script), "find-identity -v -p codesigning "+keychain)
	switch {
	case search < 0:
		t.Errorf("the search list was never set; the intermediate certificate cannot be found: %s", script)
	case identities < 0:
		t.Errorf("the identities were not asked for in this process: %s", script)
	case search > identities:
		t.Errorf("the search list was set after the question, which is too late: %s", script)
	}
}
