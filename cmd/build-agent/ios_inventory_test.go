package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// 签名材料盘点：这台 Mac 现在能签哪些 (Team, bundle id)。
//
// 这组用例不需要一台 Mac：钥匙串那两次 `security` 调用是函数字段，描述文件是真的文件、
// 用真的解析器读。要守住的规则是"报上去的每一项都真的能签出包"——多报一个，服务端就会
// 把那个租户的任务派过来，失败三次、烧掉一个 build 号。

// writeProfile 写一份描述文件：CMS 签名块里包着一份 XML plist，这里只造出后者，
// 前后各加一段二进制噪声，与真文件的形状一致（解析按 <?xml … </plist> 取）。
func writeProfile(t *testing.T, dir, name, teamID, bundleID string, expires time.Time) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Name</key><string>` + bundleID + ` App Store</string>
	<key>TeamIdentifier</key><array><string>` + teamID + `</string></array>
	<key>ExpirationDate</key><date>` + expires.UTC().Format(time.RFC3339) + `</date>
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key><string>` + teamID + `.` + bundleID + `</string>
		<key>get-task-allow</key><false/>
	</dict>
</dict>
</plist>`
	body := append([]byte("\x30\x82\x0b\x2a\x06\x09cms-noise"), []byte(plist)...)
	body = append(body, []byte("\x00\x01signature-noise")...)
	if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// profileBytes 造一份描述文件的原文，不落盘：经 build-runner 取回来的就是这样一串字节。
func profileBytes(t *testing.T, teamID, bundleID string, expires time.Time) []byte {
	t.Helper()
	dir := t.TempDir()
	writeProfile(t, dir, "x"+profileSuffix, teamID, bundleID, expires)
	raw, err := os.ReadFile(filepath.Join(dir, "x"+profileSuffix))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testScanner(t *testing.T, teams map[string]bool) iosScanner {
	t.Helper()
	root := t.TempDir()
	return iosScanner{
		SigningDir: root,
		UploadKeys: filepath.Join(root, "upload"),
		Now:        time.Now,
		Identities: func(context.Context, string) (map[string]bool, error) { return teams, nil },
	}
}

func TestIOSInventoryReportsOnlyTeamsItCanActuallySign(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true, "NOPROFILE1": true})
	profiles := filepath.Join(scanner.SigningDir, profilesDirName)
	future := time.Now().Add(200 * 24 * time.Hour)
	writeProfile(t, filepath.Join(profiles, "AB12CD34EF"), "wallet"+profileSuffix, "AB12CD34EF", "com.anyfun.foundation", future)
	writeProfile(t, filepath.Join(profiles, "AB12CD34EF"), "second"+profileSuffix, "AB12CD34EF", "com.anyfun.other", future.Add(48*time.Hour))
	// 过期的描述文件：签出来的包 Apple 直接拒，报上去只会把任务引过来再失败
	writeProfile(t, filepath.Join(profiles, "AB12CD34EF"), "old"+profileSuffix, "AB12CD34EF", "com.anyfun.expired", time.Now().Add(-time.Hour))
	// 钥匙串里没有证书的 Team：有描述文件也签不了
	writeProfile(t, filepath.Join(profiles, "NOCERTTEAM"), "x"+profileSuffix, "NOCERTTEAM", "com.other.app", future)

	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 1 || inventory.Teams[0].TeamID != "AB12CD34EF" {
		t.Fatalf("inventory reported %+v", inventory.Teams)
	}
	team := inventory.Teams[0]
	if strings.Join(team.BundleIDs, ",") != "com.anyfun.foundation,com.anyfun.other" {
		t.Fatalf("bundle ids: %v", team.BundleIDs)
	}
	// 最早到期的那一份说了算：控制台按它提前一个月标黄
	if !team.ExpiresAt.Equal(future.UTC().Truncate(time.Second)) {
		t.Fatalf("expiry %s, want %s", team.ExpiresAt, future.UTC())
	}
	// 用不了的东西不进自报，但要进日志：少报一个 Team 的时候人得知道少的是哪一片
	problems := strings.Join(inventory.Problems, "\n")
	for _, want := range []string{"old" + profileSuffix + " expired on", "NOCERTTEAM", "NOPROFILE1"} {
		if !strings.Contains(problems, want) {
			t.Fatalf("problems do not mention %s: %s", want, problems)
		}
	}
	if !inventory.covers("AB12CD34EF", "com.anyfun.foundation") || inventory.covers("AB12CD34EF", "com.anyfun.expired") ||
		inventory.covers("NOCERTTEAM", "com.other.app") {
		t.Fatalf("covers() disagrees with the report: %+v", inventory.Teams)
	}
}

// 证书比描述文件先到期时，报的是证书那个日子。
func TestIOSInventoryTakesTheEarliestExpiryOfCertificateAndProfile(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true})
	certificateExpiry := time.Now().Add(20 * 24 * time.Hour).UTC().Truncate(time.Second)
	scanner.Certificates = func(context.Context, string) (map[string]time.Time, error) {
		return map[string]time.Time{"AB12CD34EF": certificateExpiry}, nil
	}
	writeProfile(t, filepath.Join(scanner.SigningDir, profilesDirName, "AB12CD34EF"), "w"+profileSuffix,
		"AB12CD34EF", "com.anyfun.foundation", time.Now().Add(300*24*time.Hour))
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 1 || !inventory.Teams[0].ExpiresAt.Equal(certificateExpiry) {
		t.Fatalf("inventory did not take the certificate expiry: %+v", inventory.Teams)
	}
}

// 开着上传的机器缺上传 Key 就不报这个 Team：报了会领到任务，一路打完包在最后一步传不上去。
// 关着上传时不要求——那种机器本来就是"出包，由人去传"。
func TestIOSInventoryRequiresAnUploadKeyOnlyWhenUploadsAreOn(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true})
	writeProfile(t, filepath.Join(scanner.SigningDir, profilesDirName, "AB12CD34EF"), "w"+profileSuffix,
		"AB12CD34EF", "com.anyfun.foundation", time.Now().Add(100*24*time.Hour))
	if inventory := scanner.scan(context.Background()); len(inventory.Teams) != 1 {
		t.Fatalf("a machine that does not upload must still report what it can sign: %+v", inventory)
	}
	scanner.RequireUploadKey = true
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 0 {
		t.Fatalf("a team without an upload key was reported: %+v", inventory.Teams)
	}
	if err := os.MkdirAll(filepath.Join(scanner.UploadKeys, "AB12CD34EF"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanner.UploadKeys, "AB12CD34EF", uploadKeyFileName), []byte(`{"issuerId":"x","keyId":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if inventory := scanner.scan(context.Background()); len(inventory.Teams) != 1 {
		t.Fatalf("a team with an upload key was not reported: %+v", inventory)
	}
}

// 通配描述文件（`TEAMID.*`）签不出一个确定的 App：把它报上去等于谎报能力。
func TestIOSInventoryRejectsWildcardProfiles(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true})
	dir := filepath.Join(scanner.SigningDir, profilesDirName, "AB12CD34EF")
	writeProfile(t, dir, "wild"+profileSuffix, "AB12CD34EF", "*", time.Now().Add(100*24*time.Hour))
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 0 {
		t.Fatalf("a wildcard profile was reported as a signable bundle id: %+v", inventory.Teams)
	}
}

// 描述文件放错目录不影响归类：Team 按文件里的 application-identifier 定，不按目录名。
func TestIOSInventoryTrustsTheProfileNotTheDirectoryName(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true})
	writeProfile(t, filepath.Join(scanner.SigningDir, profilesDirName, "WRONGDIR12"), "w"+profileSuffix,
		"AB12CD34EF", "com.anyfun.foundation", time.Now().Add(100*24*time.Hour))
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 1 || inventory.Teams[0].TeamID != "AB12CD34EF" {
		t.Fatalf("the profile was not filed under the team inside it: %+v", inventory.Teams)
	}
}

// 钥匙串读不出来时报空，而不是报一个猜出来的列表：控制台上"什么都没有"是要让人看见的状态。
func TestIOSInventoryReportsNothingWhenTheKeychainCannotBeRead(t *testing.T) {
	scanner := testScanner(t, nil)
	scanner.Identities = func(context.Context, string) (map[string]bool, error) {
		return nil, os.ErrPermission
	}
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 0 || len(inventory.Problems) != 1 {
		t.Fatalf("inventory: %+v", inventory)
	}
}

// 生产形态：签名区是 0700 _rnbuilder，控制进程连目录都 stat 不了，材料经 build-runner
// 取回来。真机上没有这一步时它只打一行 "permission denied"，然后一个 Team 都不报——
// 机器看着在线、控制台上永远缺材料、iOS 任务永远派不过来。
func TestIOSInventoryTakesTheMaterialFromTheBuildRunner(t *testing.T) {
	dir := t.TempDir()
	runner := filepath.Join(dir, "build-runner")
	answer := `{"identities":"  1) AA \"Apple Distribution: Anyfun (RUNNERTEAM)\"\n","profiles":{"RUNNERTEAM/a.mobileprovision":"` +
		base64.StdEncoding.EncodeToString(profileBytes(t, "RUNNERTEAM", "com.anyfun.fromrunner", time.Now().Add(100*24*time.Hour))) + `"}}`
	script := "#!/bin/sh\nprintf '%s' '" + answer + "'\n"
	if err := os.WriteFile(runner, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	a := &agent{cfg: config{
		Runner:     runner,
		RunnerUser: directRunner,
		MachineEnv: map[string]string{jobspec.IOSSigningDirEnv: dir, "PATH": "/usr/bin:/bin"},
	}}
	material, err := a.iosMaterial(context.Background())
	if err != nil {
		t.Fatalf("iosMaterial: %v", err)
	}

	// 控制进程自己那份签名区里放的是**另一个** Team：报出来的必须是执行账户交回来的那份，
	// 否则说明它还在读本地文件系统——而生产里那条路是读不通的
	scanner := testScanner(t, nil)
	writeProfile(t, filepath.Join(scanner.SigningDir, profilesDirName, "LOCALTEAM1"),
		"local"+profileSuffix, "LOCALTEAM1", "com.anyfun.local", time.Now().Add(100*24*time.Hour))
	scanner.Material = func(context.Context) (jobspec.IOSMaterial, error) { return material, nil }

	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 1 || inventory.Teams[0].TeamID != "RUNNERTEAM" {
		t.Fatalf("inventory reported %+v; it must come from the build runner, not from the control process's own view "+
			"of the signing area (which is unreadable in production)", inventory.Teams)
	}
	if strings.Join(inventory.Teams[0].BundleIDs, ",") != "com.anyfun.fromrunner" {
		t.Errorf("bundle ids: %v", inventory.Teams[0].BundleIDs)
	}
}

// 取不到材料：这一轮什么都不报，并把原因说出来。装作"钥匙串是空的"会让人去查证书，
// 而实际上是 sudo 或执行进程的问题。
func TestIOSInventoryReportsNothingWhenTheRunnerFails(t *testing.T) {
	scanner := testScanner(t, map[string]bool{"AB12CD34EF": true})
	writeProfile(t, filepath.Join(scanner.SigningDir, profilesDirName, "AB12CD34EF"),
		"x"+profileSuffix, "AB12CD34EF", "com.anyfun.app", time.Now().Add(100*24*time.Hour))
	scanner.Material = func(context.Context) (jobspec.IOSMaterial, error) {
		return jobspec.IOSMaterial{}, errors.New("sudo: a password is required")
	}
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 0 {
		t.Fatalf("a machine whose signing material could not be read reported %+v", inventory.Teams)
	}
	if len(inventory.Problems) != 1 || !strings.Contains(inventory.Problems[0], "sudo: a password is required") {
		t.Errorf("the reason is not on screen: %v", inventory.Problems)
	}
}

// 钥匙串读不出来与钥匙串是空的，不是一回事。
func TestIOSInventorySeparatesAnUnreadableKeychainFromAnEmptyOne(t *testing.T) {
	scanner := testScanner(t, nil)
	scanner.Material = func(context.Context) (jobspec.IOSMaterial, error) {
		return jobspec.IOSMaterial{IdentitiesError: "security find-identity: exit status 1"}, nil
	}
	inventory := scanner.scan(context.Background())
	if len(inventory.Teams) != 0 {
		t.Fatalf("teams: %+v", inventory.Teams)
	}
	if len(inventory.Problems) == 0 || !strings.Contains(strings.Join(inventory.Problems, " "), "find-identity") {
		t.Errorf("an unreadable keychain was reported as an empty one: %v", inventory.Problems)
	}
}

// 接线：控制进程每次盘点都必须走 build-runner。少了这一行，机器在生产里会安静地
// 一个 Team 都不报——而所有单元测试照样绿，因为它们自己喂材料。
func TestAgentInventoryGoesThroughTheRunner(t *testing.T) {
	rig := newRig(t)
	a := rig.agent
	runner := filepath.Join(t.TempDir(), "build-runner")
	answer := `{"identities":"  1) AA \"Apple Distribution: Anyfun (WIREDTEAM1)\"\n","profiles":{"WIREDTEAM1/a.mobileprovision":"` +
		base64.StdEncoding.EncodeToString(profileBytes(t, "WIREDTEAM1", "com.anyfun.wired", time.Now().Add(100*24*time.Hour))) + `"}}`
	if err := os.WriteFile(runner, []byte("#!/bin/sh\nprintf '%s' '"+answer+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.cfg.Runner, a.cfg.RunnerUser = runner, directRunner
	a.cfg.IOSUpload = false
	if a.cfg.MachineEnv == nil {
		a.cfg.MachineEnv = map[string]string{}
	}
	a.cfg.MachineEnv[jobspec.IOSSigningDirEnv] = t.TempDir()
	a.cfg.MachineEnv["PATH"] = "/usr/bin:/bin"

	inventory := a.iosInventory(context.Background())
	if len(inventory.Teams) != 1 || inventory.Teams[0].TeamID != "WIREDTEAM1" {
		t.Fatalf("the agent reported %+v; the signing area is 0700 _rnbuilder in production, so the only way "+
			"to see any material is through build-runner", inventory.Teams)
	}
}
