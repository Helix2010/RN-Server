package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/fakebuild"
	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

const testJobID = "bld_runnerTEST0001"

// noSudo 模拟不经 sudo 的本地测试形态
func noSudo(string) string { return "" }

// prepareJobDir 按控制进程的做法准备一个任务目录（不经控制进程，直接写 spec 与 src）。
func prepareJobDir(t *testing.T, root, jobID string, kind jobspec.Kind, tools fakebuild.Tools) (jobspec.Layout, jobspec.Spec) {
	t.Helper()
	layout, err := jobspec.NewLayout(root, jobID)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{layout.Dir(), layout.Work(), layout.Out()} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	bare, commit := fakebuild.SourceRepo(t, t.TempDir(), "anyfun")
	fakebuild.Git(t, root, "clone", "-q", bare, layout.Src())
	tenantDir := filepath.Join(layout.Src(), "tenants", "anyfun")
	if err := os.MkdirAll(tenantDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tenantDir, "tenant.json"), []byte("{\n  \"version\": \"1.3.7\",\n  \"androidVersionCode\": 33\n}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout.Src(), "ota-certificate.pem"), []byte(fakebuild.CertificatePEM), 0o640); err != nil {
		t.Fatal(err)
	}
	env, err := jobspec.BuildEnv(layout, map[string]string{"PATH": tools.PATH(), "LANG": "C.UTF-8"},
		jobspec.TaskEnv{TenantDirectory: "anyfun", APIBaseURL: "https://api.anyfun.win"})
	if err != nil {
		t.Fatal(err)
	}
	spec := jobspec.Spec{Version: jobspec.SpecVersion, JobID: jobID, Kind: kind, Platform: jobspec.PlatformAndroid, TenantDirectory: "anyfun",
		AppVersion: "1.3.7", BuildNumber: 33, CommitSHA: commit, Env: env}
	if kind == jobspec.KindOTA {
		spec.OTA = &jobspec.OTAArgs{Channel: "production", ApplyStrategy: "next_launch", RuntimeVersion: "1.3.7",
			APIBaseURL: "https://api.anyfun.win", ApplicationID: "dex-mobile"}
	}
	raw, err := jobspec.EncodeSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.Spec(), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	return layout, spec
}

func runRunner(t *testing.T, getenv func(string) string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), args, &out, getenv)
	return code, out.String()
}

// 执行进程经一条不限参数的 sudoers 规则启动，参数只能靠它自己挡
func TestRunnerRefusesMalformedArguments(t *testing.T) {
	root := t.TempDir()
	for name, args := range map[string][]string{
		"no arguments":       {},
		"unknown subcommand": {"sh", "-c", "id"},
		"missing job":        {"build", "--jobs-root", root, "--kind", "apk"},
		"relative root":      {"build", "--jobs-root", "jobs", "--job", testJobID, "--kind", "apk"},
		"root with dotdot":   {"build", "--jobs-root", root + "/../etc", "--job", testJobID, "--kind", "apk"},
		"job escapes":        {"build", "--jobs-root", root, "--job", "../../etc", "--kind", "apk"},
		"job with slash":     {"build", "--jobs-root", root, "--job", "bld_abcd/efgh", "--kind", "apk"},
		"bad kind":           {"build", "--jobs-root", root, "--job", testJobID, "--kind", "shell"},
		"repeated flag":      {"build", "--jobs-root", root, "--job", testJobID, "--job", "bld_otherJOB0002", "--kind", "apk"},
		"positional":         {"cleanup", "--jobs-root", root, "--job", testJobID, "extra"},
		"job dir missing":    {"build", "--jobs-root", root, "--job", testJobID, "--kind", "apk"},
	} {
		code, out := runRunner(t, noSudo, args...)
		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d\n%s", name, code, exitUsage, out)
		}
		if !strings.Contains(out, errorPrefix) {
			t.Errorf("%s: no error line for the controller to pick up:\n%s", name, out)
		}
	}
}

// 经 sudo 运行（分离模式）时，任务目录必须属于调用 sudo 的控制进程用户，且执行进程改不了它
func TestSeparatedRunnerChecksWhoOwnsTheJobDirectory(t *testing.T) {
	tools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	layout, _ := prepareJobDir(t, root, testJobID, jobspec.KindAPK, tools)

	stranger := identity{uid: os.Getuid() + 1, sudoUID: os.Getuid() + 2, separated: true}
	if _, err := checkJobDir(stranger, root, testJobID, true); err == nil || !strings.Contains(err.Error(), "must belong to the controller") {
		t.Fatalf("a job directory owned by someone else was accepted: %v", err)
	}
	controller := identity{uid: os.Getuid() + 1, sudoUID: os.Getuid(), separated: true}
	if err := os.Chmod(layout.Src(), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layout.Dir(), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := checkJobDir(controller, root, testJobID, true); err != nil {
		t.Fatalf("a job directory prepared by the controller was refused: %v", err)
	}
	// 执行进程能写 src/ 就能改控制进程检出的代码之外的东西——拒绝
	if err := os.Chmod(layout.Src(), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := checkJobDir(controller, root, testJobID, true); err == nil {
		t.Fatal("a group-writable src/ was accepted")
	}
	if err := os.Chmod(layout.Src(), 0o750); err != nil {
		t.Fatal(err)
	}
	// spec.json 是符号链接：拒绝
	if err := os.Rename(layout.Spec(), layout.Spec()+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(layout.Spec()+".real", layout.Spec()); err != nil {
		t.Fatal(err)
	}
	if _, err := checkJobDir(controller, root, testJobID, true); err == nil {
		t.Fatal("a symlinked spec.json was accepted")
	}
}

func TestRunnerRefusesASpecWithAnEnvironmentOffTheList(t *testing.T) {
	tools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	layout, spec := prepareJobDir(t, root, testJobID, jobspec.KindAPK, tools)
	spec.Env = append(spec.Env, "LD_PRELOAD=/tmp/evil.so")
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(layout.Spec(), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", testJobID, "--kind", "apk")
	if code != exitUsage || !strings.Contains(out, "LD_PRELOAD") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if entries, _ := os.ReadDir(layout.Work()); len(entries) != 0 {
		t.Fatal("the runner started working before refusing the spec")
	}
}

// 安装包链路：子进程只拿到任务说明里的环境（一个变量都不多），产物按固定文件名交回
func TestBuildAPKHandsOverOutputsAndChildrenSeeOnlyTheSpecEnvironment(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", "rnm_sentinel-that-must-not-leak")
	tools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	layout, spec := prepareJobDir(t, root, testJobID, jobspec.KindAPK, tools)

	code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", testJobID, "--kind", "apk")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, step := range []string{"install", "fingerprint", "android-release", "sbom"} {
		got := tools.RecordedEnv(t, step)
		if strings.Join(got, "\n") != strings.Join(spec.Env, "\n") {
			t.Fatalf("step %s saw a different environment:\n got %v\nwant %v", step, got, spec.Env)
		}
	}
	apk, err := os.ReadFile(layout.OutFile(jobspec.UnsignedFileName))
	if err != nil || !bytes.Equal(apk, tools.APK) {
		t.Fatalf("the unsigned package was not handed over: %v", err)
	}
	sum := sha256.Sum256(apk)
	sbom, err := os.ReadFile(layout.OutFile(jobspec.SBOMFileName))
	if err != nil || !strings.Contains(string(sbom), hex.EncodeToString(sum[:])) {
		t.Fatalf("the SBOM was not handed over or not bound to the package: %v", err)
	}
	result, err := os.Open(layout.OutFile(jobspec.ResultFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	parsed, err := jobspec.DecodeResult(result, jobspec.KindAPK, jobspec.PlatformAndroid)
	if err != nil || parsed.NativeFingerprint != fakebuild.NativeFingerprint {
		t.Fatalf("result = %+v, %v", parsed, err)
	}
	// 每任务的 GRADLE_USER_HOME 在任务目录里，是新建的
	if info, err := os.Stat(layout.GradleUserHome()); err != nil || !info.IsDir() {
		t.Fatalf("no per-job GRADLE_USER_HOME: %v", err)
	}
}

// 热更新链路与安装包链路的子进程环境必须一致（除了任务目录本身），否则原生指纹对不上
func TestOTAAndAPKChildrenSeeTheSameEnvironment(t *testing.T) {
	apkTools := fakebuild.Install(t, t.TempDir())
	otaTools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	apkLayout, _ := prepareJobDir(t, root, "bld_apkJOB000001", jobspec.KindAPK, apkTools)
	otaLayout, otaSpec := prepareJobDir(t, root, "bld_otaJOB000001", jobspec.KindOTA, otaTools)
	// 两套假工具的目录不同，PATH 会不同；用同一套 PATH 重写 OTA 的说明
	otaSpec.Env, _ = jobspec.BuildEnv(otaLayout, map[string]string{"PATH": apkTools.PATH(), "LANG": "C.UTF-8"},
		jobspec.TaskEnv{TenantDirectory: "anyfun", APIBaseURL: "https://api.anyfun.win"})
	raw, _ := jobspec.EncodeSpec(otaSpec)
	if err := os.WriteFile(otaLayout.Spec(), raw, 0o640); err != nil {
		t.Fatal(err)
	}

	if code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", apkLayout.JobID, "--kind", "apk"); code != 0 {
		t.Fatalf("apk exit %d:\n%s", code, out)
	}
	apkEnv := strings.ReplaceAll(strings.Join(apkTools.RecordedEnv(t, "install"), "\n"), apkLayout.Dir(), "<job>")
	if err := os.RemoveAll(apkTools.Record); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(apkTools.Record, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", otaLayout.JobID, "--kind", "ota"); code != 0 {
		t.Fatalf("ota exit %d:\n%s", code, out)
	}
	otaEnv := strings.ReplaceAll(strings.Join(apkTools.RecordedEnv(t, "install"), "\n"), otaLayout.Dir(), "<job>")
	if apkEnv != otaEnv {
		t.Fatalf("the two chains saw different environments:\napk:\n%s\nota:\n%s", apkEnv, otaEnv)
	}
	if otaBuildEnv := strings.ReplaceAll(strings.Join(apkTools.RecordedEnv(t, "ota-build"), "\n"), otaLayout.Dir(), "<job>"); otaBuildEnv != apkEnv {
		t.Fatalf("pnpm ota:build saw a different environment:\n%s", otaBuildEnv)
	}
	// 执行进程的副本是自包含的 git 仓库：build-ota.mjs 要 git rev-parse HEAD
	commit, err := os.ReadFile(filepath.Join(apkTools.Record, "ota-commit.txt"))
	if err != nil || strings.TrimSpace(string(commit)) != otaSpec.CommitSHA {
		t.Fatalf("git in the runner copy reports %q (%v), want %s", commit, err, otaSpec.CommitSHA)
	}
	if _, err := os.Stat(otaLayout.OutFile(jobspec.OTAFileName)); err != nil {
		t.Fatalf("the OTA package was not handed over: %v", err)
	}
}

// 构建失败：退出码 1，最后一行是给控制进程的原因
func TestBuildFailureEndsWithAReasonLine(t *testing.T) {
	tools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	prepareJobDir(t, root, testJobID, jobspec.KindAPK, tools)
	if err := os.WriteFile(filepath.Join(tools.Bin, "node"), []byte("#!/bin/sh\necho syft missing >&2\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", testJobID, "--kind", "apk")
	if code != exitFailed {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, errorPrefix) || !strings.Contains(last, "node") {
		t.Fatalf("the last line does not carry the reason: %q", last)
	}
}

// cleanup 删掉执行进程在 work/ 与 out/ 里的一切，包括被改成 000 的目录；目录本身（属控制进程）留着
func TestCleanupEmptiesTheJobDirectory(t *testing.T) {
	tools := fakebuild.Install(t, t.TempDir())
	root := t.TempDir()
	layout, _ := prepareJobDir(t, root, testJobID, jobspec.KindAPK, tools)
	if code, out := runRunner(t, noSudo, "build", "--jobs-root", root, "--job", testJobID, "--kind", "apk"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	locked := filepath.Join(layout.GradleUserHome(), "init.d")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "persist.gradle"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	code, out := runRunner(t, noSudo, "cleanup", "--jobs-root", root, "--job", testJobID)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, dir := range []string{layout.Work(), layout.Out()} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s still has %d entries (%v)", dir, len(entries), err)
		}
	}
	if _, err := os.Stat(layout.GradleUserHome()); !os.IsNotExist(err) {
		t.Fatalf("the per-job GRADLE_USER_HOME survived cleanup: %v", err)
	}
}

// 回收只动本 uid 的东西
func TestSweepOwnedRemovesOnlyTheCallersEntries(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "metro-cache")
	if err := os.MkdirAll(filepath.Join(mine, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mine, 0); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	sweepOwned(dir, os.Getuid()+1)
	if _, err := os.Lstat(mine); err != nil {
		t.Fatal("another uid's sweep removed our entry")
	}
	sweepOwned(dir, os.Getuid())
	if _, err := os.Lstat(mine); !os.IsNotExist(err) {
		t.Fatalf("our entry survived: %v", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("our symlink survived: %v", err)
	}
	if _, err := os.Stat("/etc"); err != nil {
		t.Fatal("the sweep followed a symlink")
	}
}

func TestCopyTreeKeepsSymlinksAndRefusesSpecialFiles(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "gradlew"), []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dst, "gradlew")); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("the executable bit was lost: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); err != nil || target != "/etc/passwd" {
		t.Fatalf("the symlink was not copied as a symlink: %q %v", target, err)
	}
	if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(src, filepath.Join(t.TempDir(), "copy2")); err == nil {
		t.Fatal("a FIFO was copied")
	}
}

func TestLookPathUsesTheJobPathNotTheProcessPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm"), []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/nonexistent")
	if got, err := lookPath("pnpm", "relative:"+dir); err != nil || got != filepath.Join(dir, "pnpm") {
		t.Fatalf("lookPath = %q, %v", got, err)
	}
	if _, err := lookPath("../pnpm", dir); err == nil {
		t.Fatal("a command with a path was accepted")
	}
	if _, err := lookPath("pnpm", "relative"); err == nil {
		t.Fatal("a relative PATH entry was searched")
	}
}

func TestSelfCheckRequiresSeparationWhenAsked(t *testing.T) {
	root := t.TempDir()
	if code, out := runRunner(t, noSudo, "self-check", "--jobs-root", root, "--protocol", "1"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	// 控制进程与执行进程的任务协议版本不一致（只换了其中一个二进制）：启动时就拒绝
	for _, protocol := range [][]string{{}, {"--protocol", "2"}} {
		args := append([]string{"self-check", "--jobs-root", root}, protocol...)
		if code, out := runRunner(t, noSudo, args...); code != exitUsage || !strings.Contains(out, "together") {
			t.Fatalf("protocol %v: exit %d\n%s", protocol, code, out)
		}
	}
	if code, out := runRunner(t, noSudo, "self-check", "--jobs-root", root, "--protocol", "1", "--expect-separated"); code != exitUsage {
		t.Fatalf("a runner started by the same user passed --expect-separated: exit %d\n%s", code, out)
	}
	sameUser := func(key string) string {
		if key == "SUDO_UID" {
			return strconv.Itoa(os.Getuid())
		}
		return ""
	}
	if code, _ := runRunner(t, sameUser, "self-check", "--jobs-root", root, "--protocol", "1", "--expect-separated"); code != exitUsage {
		t.Fatal("sudo to the same user passed --expect-separated")
	}
}

// 证书检查的几条老规矩（从控制进程挪过来，检查本身现在在执行进程里）
func TestCertificateNeedleComesFromASingleLine(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\n" +
		strings.Repeat("A", 64) + "\n" +
		strings.Repeat("B", 64) + "\n" +
		strings.Repeat("C", 64) + "\n" +
		"-----END CERTIFICATE-----\n"
	needle := certificateNeedle(pem)
	if len(needle) != 48 || strings.Contains(needle, "\n") || !strings.Contains(pem, needle) {
		t.Fatalf("bad needle %q", needle)
	}
	for name, input := range map[string]string{
		"empty":      "",
		"armour":     "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
		"one line":   "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 64) + "\n-----END CERTIFICATE-----\n",
		"short line": "-----BEGIN CERTIFICATE-----\nAA\nBB\nCC\n-----END CERTIFICATE-----\n",
	} {
		if certificateNeedle(input) != "" {
			t.Fatalf("%s produced a needle anyway", name)
		}
	}
}

// AndroidManifest.xml 的字符串池是 UTF-16LE，两种编码都要找
func TestVerifyEmbeddedCertificateFindsUTF8AndUTF16(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, fakebuild.APKWithCertificate(t, fakebuild.CertificatePEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyEmbeddedCertificate(apk, fakebuild.CertificatePEM); err != nil {
		t.Fatalf("the certificate in the package was not found: %v", err)
	}
	other := strings.ReplaceAll(fakebuild.CertificatePEM, "Q", "R")
	if err := verifyEmbeddedCertificate(apk, other); err == nil {
		t.Fatal("a different certificate was reported as embedded")
	}
	if got := utf16LE("AB"); !bytes.Equal(got, []byte{'A', 0, 'B', 0}) {
		t.Fatalf("utf16LE = %v", got)
	}
}
