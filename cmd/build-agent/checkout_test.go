package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/fakebuild"
	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// hookScript 被执行时在 marker 里留一行。
func hookScript(marker, name string) []byte {
	return []byte("#!/bin/sh\necho " + name + " >> " + marker + "\n")
}

// 裸库里的 hook（含仓库配置里的 core.hooksPath）在 fetch 与检出时一律不执行。
// 先证明这些 hook 不加防护时确实会跑，否则"没跑"说明不了什么。
func TestCheckoutNeverRunsRepositoryHooks(t *testing.T) {
	rig := newRig(t)
	marker := filepath.Join(t.TempDir(), "hooks-ran")
	hooksDir := filepath.Join(rig.bare, "hooks")
	customHooks := filepath.Join(t.TempDir(), "custom-hooks")
	if err := os.MkdirAll(customHooks, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{hooksDir, customHooks} {
		for _, name := range []string{"post-checkout", "reference-transaction", "post-merge", "post-index-change", "pre-auto-gc"} {
			if err := os.WriteFile(filepath.Join(dir, name), hookScript(marker, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	source := filepath.Join(filepath.Dir(rig.bare), "source")
	commitMore := func(content string) {
		if err := os.WriteFile(filepath.Join(source, "package.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		fakebuild.Git(t, source, "commit", "-qam", "more")
	}

	// 对照：不带防护的 fetch 会跑 reference-transaction
	commitMore(`{"name":"control"}`)
	fakebuild.Git(t, rig.bare, "fetch", "--all", "--prune")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the control fetch did not run the hook, so this test would prove nothing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	// 仓库配置里指一个 hooksPath 也不能生效
	fakebuild.Git(t, rig.bare, "config", "core.hooksPath", customHooks)

	commitMore(`{"name":"real"}`)
	head := fakebuild.Git(t, source, "rev-parse", "HEAD")
	job := claimBody("bld_hooksJOB0001", "apk")
	claimed := mustClaimedJob(t, job)
	buf := newLogBuffer(newRedactor())
	prepared, err := rig.agent.prepareWorktree(context.Background(), claimed, buf)
	if err != nil {
		t.Fatalf("prepare failed: %v\n%s", err, strings.Join(buf.snapshot(), "\n"))
	}
	if raw, err := os.ReadFile(marker); err == nil {
		t.Fatalf("repository hooks ran during the checkout: %s", raw)
	}
	if prepared.Commit != head {
		t.Fatalf("checked out %s, want the fetched main %s", prepared.Commit, head)
	}
	// src/.git 是自包含的真目录，不是指回裸库的 gitfile；新仓库没有模板带来的 hook
	gitDir := filepath.Join(prepared.Layout.Src(), ".git")
	if info, err := os.Lstat(gitDir); err != nil || !info.IsDir() {
		t.Fatalf("src/.git is not a self-contained repository: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(gitDir, "hooks")); len(entries) != 0 {
		t.Fatalf("the job repository has hooks: %v", entries)
	}
	if alternates, err := os.ReadFile(filepath.Join(gitDir, "objects", "info", "alternates")); err == nil {
		t.Fatalf("the job repository borrows objects from elsewhere: %s", alternates)
	}
}

func mustClaimedJob(t *testing.T, body map[string]any) claimedJob {
	t.Helper()
	raw, err := jsonMarshal(body)
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseClaim(raw)
	if err != nil || result.Job == nil {
		t.Fatalf("parseClaim: %+v %v", result, err)
	}
	return *result.Job
}

// 环境白名单只在 prepareWorktree 里构造：安装包与热更新两个任务拿到的环境除任务目录外逐字相同
func TestPrepareWorktreeBuildsTheSameEnvironmentForAPKAndOTA(t *testing.T) {
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)
	rig := newRig(t)
	rig.agent.cfg.MachineEnv["JAVA_HOME"] = "/usr/lib/jvm/java-17-openjdk-amd64"
	buf := newLogBuffer(newRedactor())
	apk, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_envAPK000001", "apk")), buf)
	if err != nil {
		t.Fatal(err)
	}
	ota, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_envOTA000001", "ota")), buf)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(p preparedJob) string {
		return strings.ReplaceAll(strings.Join(p.Env, "\n"), p.Layout.Dir(), "<job>")
	}
	if normalize(apk) != normalize(ota) {
		t.Fatalf("apk and ota environments differ:\napk:\n%s\nota:\n%s", normalize(apk), normalize(ota))
	}
	if strings.Contains(normalize(apk), testToken) {
		t.Fatal("the machine token is in the runner environment")
	}
	// 写给执行进程的 spec.json 里就是这份环境
	raw, err := os.ReadFile(apk.Layout.Spec())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := jobspec.DecodeSpec(bytes.NewReader(raw))
	if err != nil || spec.Validate(apk.Layout) != nil || strings.Join(spec.Env, "\n") != strings.Join(apk.Env, "\n") {
		t.Fatalf("spec.json does not carry the prepared environment: %v", err)
	}
	// work/ 与 out/ 带 setgid、组可写、其他人无权限；src 与 spec 执行进程只读
	for _, dir := range []string{apk.Layout.Work(), apk.Layout.Out()} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSetgid == 0 || info.Mode().Perm() != 0o770 {
			t.Fatalf("%s has mode %v, want setgid 0770", dir, info.Mode())
		}
	}
	for _, path := range []string{apk.Layout.Spec(), filepath.Join(apk.Layout.Src(), "tenants", "anyfun", "tenant.json"), filepath.Join(apk.Layout.Src(), "ota-certificate.pem")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("%s is writable by group or others: %v", path, info.Mode())
		}
	}
}

// 服务端下发的字段先校验再动磁盘
func TestValidateClaimedJobRefusesUnsafeFields(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"no attempt":        func(b map[string]any) { delete(b, "attempt") },
		"other branch":      func(b map[string]any) { b["gitRef"] = "release/x" },
		"option injection":  func(b map[string]any) { b["gitRef"] = "--upload-pack=touch /tmp/x" },
		"tenant escape":     func(b map[string]any) { b["tenantDirectory"] = "../../etc" },
		"tenant slash":      func(b map[string]any) { b["tenantDirectory"] = "a/b" },
		"job id escape":     func(b map[string]any) { b["id"] = "../bld_x" },
		"version in path":   func(b map[string]any) { b["version"] = "1.0/../../x" },
		"no machine id":     func(b map[string]any) { delete(b, "claimedMachineId") },
		"ios":               func(b map[string]any) { b["platform"] = "ios" },
		"unknown kind":      func(b map[string]any) { b["kind"] = "script" },
		"no ota cert":       func(b map[string]any) { b["otaCertificatePem"] = nil },
		"zero build number": func(b map[string]any) { b["buildNumber"] = 0 },
	} {
		body := claimBody("bld_validJOB0001", "apk")
		mutate(body)
		raw, _ := jsonMarshal(body)
		result, err := parseClaim(raw)
		if err != nil || result.Job == nil {
			continue // 解析层已经拒了
		}
		if err := validateClaimedJob(*result.Job); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := validateClaimedJob(mustClaimedJob(t, claimBody("bld_validJOB0001", "apk"))); err != nil {
		t.Fatalf("a valid job was refused: %v", err)
	}
}

// 身份文件里的版本与 build 号必须等于任务行：出处声明签的是任务行
func TestTenantFileMustMatchTheJob(t *testing.T) {
	body := claimBody("bld_mismatch0001", "apk")
	body["buildNumber"] = 34
	if err := checkTenantFileMatchesJob(mustClaimedJob(t, body)); err == nil {
		t.Fatal("a tenant file with another versionCode was accepted")
	}
}
