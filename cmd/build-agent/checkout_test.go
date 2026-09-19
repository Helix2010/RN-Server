package main

import (
	"bytes"
	"context"
	"errors"
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
	// 仓库配置里指一个 hooksPath：fetch 之前就被镜像核对拒掉（见 TestCheckoutRefusesAnUntrustedMirror）；
	// 这里只看裸库 hooks/ 目录里的 hook
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
		"no attempt":       func(b map[string]any) { delete(b, "attempt") },
		"other branch":     func(b map[string]any) { b["gitRef"] = "release/x" },
		"option injection": func(b map[string]any) { b["gitRef"] = "--upload-pack=touch /tmp/x" },
		"tenant escape":    func(b map[string]any) { b["tenantDirectory"] = "../../etc" },
		"tenant slash":     func(b map[string]any) { b["tenantDirectory"] = "a/b" },
		"job id escape":    func(b map[string]any) { b["id"] = "../bld_x" },
		"version in path":  func(b map[string]any) { b["version"] = "1.0/../../x" },
		"no machine id":    func(b map[string]any) { delete(b, "claimedMachineId") },
		"unknown platform": func(b map[string]any) { b["platform"] = "harmony" },
		// 热更新包与平台无关，由 Android 那台机器构建；iOS 只做安装包
		"ios ota": func(b map[string]any) {
			b["platform"] = "ios"
			b["kind"] = "ota"
		},
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
	// iOS 的安装包任务是合法的：这台机器认不认它由 BUILD_AGENT_PLATFORMS 和
	// 服务端的登记决定，不由这里决定
	ios := claimBody("bld_validJOB0001", "apk")
	ios["platform"] = "ios"
	if err := validateClaimedJob(mustClaimedJob(t, ios)); err != nil {
		t.Fatalf("an ios package job was refused: %v", err)
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

// commitToSource 在构建机镜像的上游仓库里改一次并提交，下次检出时就是这份内容。
func commitToSource(t *testing.T, rig *testRig, change func(source string)) {
	t.Helper()
	source := filepath.Join(filepath.Dir(rig.bare), "source")
	change(source)
	fakebuild.Git(t, source, "add", "-A")
	fakebuild.Git(t, source, "commit", "-qm", "symlink fixture")
}

// 检出内容来自仓库 main，不可信：控制进程往检出里写服务端下发的文件时，不管符号链接在最后一段、
// 中间一段还是整个目录，都不许写穿到检出外面（出处私钥就在状态目录里），也不许写穿到检出里的
// 另一个文件。
func TestPrepareWorktreeNeverWritesThroughSymlinksInTheCheckout(t *testing.T) {
	cases := map[string]struct {
		icons  bool
		change func(t *testing.T, source, victim, outside string)
		// untouched 是必须保持原样的文件（相对检出以外的绝对路径由用例自己给）
		mustStayEmpty bool
	}{
		"ota certificate links to the provenance key": {
			change: func(t *testing.T, source, victim, _ string) {
				mustSymlink(t, victim, filepath.Join(source, "ota-certificate.pem"))
			},
		},
		"google-services.json links to the provenance key": {
			change: func(t *testing.T, source, victim, _ string) {
				mustSymlink(t, victim, filepath.Join(source, "google-services.json"))
			},
		},
		"tenant.json links to the provenance key": {
			change: func(t *testing.T, source, victim, _ string) {
				if err := os.MkdirAll(filepath.Join(source, "tenants", "anyfun"), 0o755); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, victim, filepath.Join(source, "tenants", "anyfun", "tenant.json"))
			},
		},
		"tenants/ is a directory link out of the checkout": {
			mustStayEmpty: true,
			change: func(t *testing.T, source, _, outside string) {
				if err := os.RemoveAll(filepath.Join(source, "tenants")); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, outside, filepath.Join(source, "tenants"))
			},
		},
		"an intermediate icon directory links out of the checkout": {
			icons:         true,
			mustStayEmpty: true,
			change: func(t *testing.T, source, _, outside string) {
				if err := os.RemoveAll(filepath.Join(source, "assets", "tenants", "anyfun")); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, outside, filepath.Join(source, "assets", "tenants", "anyfun"))
			},
		},
		"an icon file links to the provenance key": {
			icons: true,
			change: func(t *testing.T, source, victim, _ string) {
				icon := filepath.Join(source, "assets", "tenants", "anyfun", "icon.png")
				if err := os.Remove(icon); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, victim, icon)
			},
		},
		"a relative link to another file inside the checkout": {
			change: func(t *testing.T, source, _, _ string) {
				mustSymlink(t, "package.json", filepath.Join(source, "google-services.json"))
			},
		},
		"an icon that is only a symlink counts as missing": {
			change: func(t *testing.T, source, _, _ string) {
				icon := filepath.Join(source, "assets", "tenants", "anyfun", "icon.png")
				if err := os.Remove(icon); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, "/etc/hostname", icon)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newRig(t)
			victim := filepath.Join(rig.agent.cfg.StateDir, provenanceKeyFile)
			before, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			commitToSource(t, rig, func(source string) { tc.change(t, source, victim, outside) })
			packageBefore, _ := os.ReadFile(filepath.Join(filepath.Dir(rig.bare), "source", "package.json"))

			body := claimBody("bld_symlinkJOB01", "apk")
			if tc.icons {
				body["icons"] = []string{"icon.png", "android-icon-foreground.png", "android-icon-background.png", "android-icon-monochrome.png"}
			}
			prepared, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, body), newLogBuffer(newRedactor()))
			if err == nil {
				t.Fatal("a checkout with a symlink in a written path was accepted")
			}
			if !strings.Contains(err.Error(), "symlink") && !strings.Contains(err.Error(), "启动图标") {
				t.Fatalf("refused for another reason: %v", err)
			}
			after, readErr := os.ReadFile(victim)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatalf("the provenance key was changed through a symlink (%v)", readErr)
			}
			if _, err := loadOrCreateKeyring(rig.agent.cfg.StateDir); err != nil {
				t.Fatalf("the state directory is no longer usable: %v", err)
			}
			if entries, _ := os.ReadDir(outside); tc.mustStayEmpty && len(entries) != 0 {
				t.Fatalf("files were written outside the checkout: %v", entries)
			}
			if src := prepared.Layout.Src(); src != "" {
				if got, err := os.ReadFile(filepath.Join(src, "package.json")); err == nil && !bytes.Equal(got, packageBefore) {
					t.Fatalf("a file inside the checkout was overwritten through a relative link: %q", got)
				}
			}
			// 失败的任务照常上报与清理由 runJob 负责；这里清掉目录以免影响别的用例
			rig.agent.cleanupJob(prepared.Layout)
		})
	}
}

// 仓库里有同名的普通文件（tenants/anyfun/tenant.json 仍在 RN-App 里）：删掉重建，内容是服务端下发的
func TestPrepareWorktreeReplacesRegularFilesFromTheRepository(t *testing.T) {
	rig := newRig(t)
	commitToSource(t, rig, func(source string) {
		dir := filepath.Join(source, "tenants", "anyfun")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tenant.json"), []byte(`{"stale":true}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "ota-certificate.pem"), []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	body := claimBody("bld_replaceJOB01", "apk")
	body["icons"] = []string{"icon.png"}
	prepared, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, body), newLogBuffer(newRedactor()))
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := os.ReadFile(filepath.Join(prepared.Layout.Src(), "tenants", "anyfun", "tenant.json"))
	if strings.Contains(string(tenant), "stale") || !strings.Contains(string(tenant), "com.anyfun.foundation") {
		t.Fatalf("tenant.json was not replaced: %s", tenant)
	}
	certificate, _ := os.ReadFile(filepath.Join(prepared.Layout.Src(), "ota-certificate.pem"))
	if string(certificate) != fakebuild.CertificatePEM {
		t.Fatal("ota-certificate.pem was not replaced")
	}
	icon, _ := os.ReadFile(filepath.Join(prepared.Layout.Src(), "assets", "tenants", "anyfun", "icon.png"))
	if string(icon) != "png-from-server" {
		t.Fatalf("the icon from the server was not written: %q", icon)
	}
	rig.agent.cleanupJob(prepared.Layout)
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// git fetch 默认会 detach 出一个 git maintenance run --auto，在 fetch 返回之后继续往仓库里写，
// 和紧接着的复制、删除打架（压测里删任务目录报过 directory not empty）。每条 git 命令都要关掉它。
func TestControllerGitNeverStartsBackgroundMaintenance(t *testing.T) {
	joined := strings.Join(gitSafetyConfig, " ")
	for _, want := range []string{"maintenance.auto=false", "gc.auto=0", "core.hooksPath=/dev/null"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("controller git commands lack %s", want)
		}
	}
	a := &agent{cfg: config{MachineEnv: map[string]string{"PATH": "/usr/bin:/bin"}}}
	cmd := a.gitCommand(context.Background(), "", "fetch", "--all")
	if got := strings.Join(cmd.Args, " "); !strings.Contains(got, "-c maintenance.auto=false") || !strings.HasSuffix(got, "fetch --all") {
		t.Fatalf("git command line = %q", got)
	}
}

// 改造前的构建机上仓库镜像归 builder 可写：它的配置与目录结构在 fetch 之前按白名单核对，
// 不合规的镜像整个任务失败，不 fetch、不执行里面的任何东西，也不自动修。
func TestCheckoutRefusesAnUntrustedMirror(t *testing.T) {
	type poison func(t *testing.T, bare, marker string)
	gitConfig := func(args ...string) poison {
		return func(t *testing.T, bare, marker string) {
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "MARKER", marker)
			}
			fakebuild.Git(t, bare, append([]string{"config"}, args...)...)
		}
	}
	writeFile := func(name, content string) poison {
		return func(t *testing.T, bare, marker string) {
			path := filepath.Join(bare, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.ReplaceAll(content, "MARKER", marker)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]poison{
		"core.sshCommand":          gitConfig("core.sshCommand", "touch MARKER; ssh"),
		"core.hooksPath":           gitConfig("core.hooksPath", "/tmp"),
		"remote.origin.uploadpack": gitConfig("remote.origin.uploadpack", "touch MARKER; git-upload-pack"),
		"remote.origin.vcs":        gitConfig("remote.origin.vcs", "evil"),
		"credential.helper":        gitConfig("credential.helper", "!touch MARKER"),
		"url insteadOf":            gitConfig("url./elsewhere/.insteadOf", "/"),
		"a second remote":          gitConfig("remote.evil.url", "/elsewhere"),
		"a second origin url":      gitConfig("--add", "remote.origin.url", "/elsewhere"),
		"not bare":                 gitConfig("core.bare", "false"),
		"include.path": func(t *testing.T, bare, marker string) {
			included := filepath.Join(t.TempDir(), "included")
			if err := os.WriteFile(included, []byte("[core]\n\tsshCommand = touch "+marker+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fakebuild.Git(t, bare, "config", "include.path", included)
		},
		"includeIf": func(t *testing.T, bare, marker string) {
			fakebuild.Git(t, bare, "config", "includeIf.gitdir:/.path", filepath.Join(t.TempDir(), "included"))
		},
		"branches/x":              writeFile("branches/x", "/elsewhere\n"),
		"remotes/origin":          writeFile("remotes/origin", "URL: /elsewhere\nPull: refs/heads/main:refs/heads/main\n"),
		"objects/info/alternates": writeFile("objects/info/alternates", "/elsewhere/objects\n"),
		"info/attributes":         writeFile("info/attributes", "* filter=evil\n"),
		"info/grafts":             writeFile("info/grafts", "0000000000000000000000000000000000000000\n"),
		".git gitfile":            writeFile(".git", "gitdir: /elsewhere\n"),
		"commondir":               writeFile("commondir", "/elsewhere\n"),
		"config.worktree":         writeFile("config.worktree", "[core]\n\tsshCommand = touch MARKER\n"),
		"config is a symlink": func(t *testing.T, bare, marker string) {
			copied := filepath.Join(t.TempDir(), "config")
			raw, err := os.ReadFile(filepath.Join(bare, "config"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(copied, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(bare, "config")); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, copied, filepath.Join(bare, "config"))
		},
		"group-writable mirror": func(t *testing.T, bare, marker string) {
			if err := os.Chmod(bare, 0o770); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable config": func(t *testing.T, bare, marker string) {
			if err := os.Chmod(filepath.Join(bare, "config"), 0o660); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, apply := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newRig(t)
			marker := filepath.Join(t.TempDir(), "ran")
			apply(t, rig.bare, marker)
			buf := newLogBuffer(newRedactor())
			prepared, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_poisonJOB001", "apk")), buf)
			if err == nil {
				t.Fatal("an untrusted mirror was fetched")
			}
			if !errors.Is(err, errUntrustedMirror) || !strings.Contains(err.Error(), "SIGNING_GATE_ROLLOUT.md") {
				t.Fatalf("refused for another reason: %v", err)
			}
			if strings.Contains(strings.Join(buf.snapshot(), "\n"), "fetch") {
				t.Fatalf("git fetch ran before the mirror was checked:\n%s", strings.Join(buf.snapshot(), "\n"))
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("the mirror's configuration ran a command")
			}
			rig.agent.cleanupJob(prepared.Layout)
		})
	}
}

// 对照：不核对镜像时 remote.origin.uploadpack 确实会被 fetch 执行，上面的“没执行”才有意义
func TestUntrustedMirrorControlRunsTheUploadPackCommand(t *testing.T) {
	rig := newRig(t)
	marker := filepath.Join(t.TempDir(), "ran")
	fakebuild.Git(t, rig.bare, "config", "remote.origin.uploadpack", "touch "+marker+"; git-upload-pack")
	fakebuild.Git(t, rig.bare, "fetch", "origin")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the control fetch did not run remote.origin.uploadpack, so the refusal test proves nothing: %v", err)
	}
}

// git clone --mirror 产生的镜像（默认模板带 hooks 样例、info/exclude、description；空模板什么都不带）通过核对
func TestCheckoutAcceptsACleanMirror(t *testing.T) {
	rig := newRig(t)
	if err := rig.agent.checkMirror(context.Background()); err != nil {
		t.Fatalf("a mirror cloned with the default template was refused: %v", err)
	}
	source := filepath.Join(filepath.Dir(rig.bare), "source")
	bare := filepath.Join(t.TempDir(), "rn-app.git")
	fakebuild.Git(t, filepath.Dir(bare), "clone", "-q", "--mirror", "--template=", source, bare)
	rig.agent.cfg.Repo = bare
	if err := os.Chmod(bare, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(bare, "config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(bare, "branches"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_cleanMIRROR1", "apk")), newLogBuffer(newRedactor())); err != nil {
		t.Fatalf("a mirror cloned with an empty template was refused: %v", err)
	}
}

// macOS 上 git clone 自己写的那两个键不算"不可信"。真机上就栽在这里：Mac 打包机装好、
// 代理连上了服务端，每一轮都打一条"镜像配置不可信…有不允许的键 core.ignorecase"，一条
// 任务也不领——而那个键是 git 在 APFS 上 clone 时必写的，人什么都没做错。
func TestCheckoutAcceptsAMirrorClonedOnMacOS(t *testing.T) {
	for _, key := range []string{"core.ignorecase", "core.precomposeunicode"} {
		t.Run(key, func(t *testing.T) {
			rig := newRig(t)
			fakebuild.Git(t, rig.bare, "config", key, "true")
			if err := rig.agent.checkMirror(context.Background()); err != nil {
				t.Fatalf("a mirror carrying %s was refused: %v\n"+
					"git writes this itself when cloning on a case-insensitive filesystem; "+
					"refusing it means no Mac builder ever runs a job", key, err)
			}
		})
	}
}

// 仓库镜像的 fetch 只放行生产里的 ssh：本地路径与 ext:: 这类传输一律不许，镜像配置里的 url 改不了这一点
func TestMirrorFetchOnlyAllowsSSH(t *testing.T) {
	rig := newRig(t)
	a := rig.agent
	a.mirrorProtocol = newAgent(a.cfg, a.keys).mirrorProtocol
	if a.mirrorProtocol != "ssh" {
		t.Fatalf("the production mirror protocol is %q", a.mirrorProtocol)
	}
	cmd := a.gitCommandAllowing(context.Background(), "", a.mirrorProtocol, "fetch")
	if got := strings.Join(cmd.Args, " "); !strings.Contains(got, "-c protocol.allow=never -c protocol.ssh.allow=always fetch") {
		t.Fatalf("mirror fetch command line = %q", got)
	}
	// 本地路径的 origin（测试镜像就是）走 file 协议：被拒
	buf := newLogBuffer(newRedactor())
	if _, err := a.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_protoFILE001", "apk")), buf); err == nil ||
		!strings.Contains(strings.Join(buf.snapshot(), "\n"), "not allowed") {
		t.Fatalf("a file:// origin was fetched with only ssh allowed: %v\n%s", err, strings.Join(buf.snapshot(), "\n"))
	}
	// ext:: 能直接执行命令：被拒，命令没跑
	marker := filepath.Join(t.TempDir(), "ran")
	fakebuild.Git(t, rig.bare, "config", "remote.origin.url", "ext::sh -c touch% "+marker)
	if _, err := a.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_protoEXT0001", "apk")), newLogBuffer(newRedactor())); err == nil {
		t.Fatal("an ext:: origin was fetched")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("an ext:: origin ran a command")
	}
}

// ssh 由 GIT_SSH_COMMAND 固定：不读任何 ssh 配置、只用 deploy key、主机公钥只认固定 known_hosts。
// 用一个记录参数的假 ssh 实跑一次 fetch，证明它优先于仓库配置里的 core.sshCommand。
func TestControllerGitPinsSSH(t *testing.T) {
	rig := newRig(t)
	a := rig.agent
	env := strings.Join(a.gitEnv(), "\n")
	want := "GIT_SSH_COMMAND=ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i " + a.cfg.SSHKey +
		" -o UserKnownHostsFile=" + a.cfg.KnownHosts + " -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15"
	if !strings.Contains(env, "\n"+want+"\n") && !strings.HasSuffix(env, "\n"+want) {
		t.Fatalf("git environment lacks the pinned ssh command:\n%s", env)
	}

	bin := t.TempDir()
	recorded := filepath.Join(t.TempDir(), "ssh-args")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + recorded + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	a.cfg.MachineEnv["PATH"] = bin + ":" + a.cfg.MachineEnv["PATH"]
	marker := filepath.Join(t.TempDir(), "ran")
	fakebuild.Git(t, rig.bare, "config", "core.sshCommand", "touch "+marker+"; ssh")
	fakebuild.Git(t, rig.bare, "config", "remote.origin.url", "git@github.com:Helix2010/RN-App.git")
	_ = a.gitCommandAllowing(context.Background(), "", "ssh", "--git-dir="+rig.bare, "fetch", "origin").Run()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("core.sshCommand from the mirror's config ran")
	}
	raw, err := os.ReadFile(recorded)
	if err != nil {
		t.Fatalf("the pinned ssh was not used: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	joined := strings.Join(args, " ")
	for _, want := range []string{"-F /dev/null", "-o IdentitiesOnly=yes", "-i " + a.cfg.SSHKey, "-o UserKnownHostsFile=" + a.cfg.KnownHosts, "-o StrictHostKeyChecking=yes", "git@github.com"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ssh ran without %q: %v", want, args)
		}
	}
}

// 固定 known_hosts 必须属于 root（测试里是当前用户）、是普通文件、它和所在目录组与其他人都不可写
func TestCheckoutRefusesAnUnsafeKnownHostsFile(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, a *agent){
		"missing": func(t *testing.T, a *agent) {
			if err := os.Remove(a.cfg.KnownHosts); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable": func(t *testing.T, a *agent) {
			if err := os.Chmod(a.cfg.KnownHosts, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(t *testing.T, a *agent) {
			if err := os.Chmod(filepath.Dir(a.cfg.KnownHosts), 0o775); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, a *agent) {
			link := a.cfg.KnownHosts + ".link"
			mustSymlink(t, a.cfg.KnownHosts, link)
			a.cfg.KnownHosts = link
		},
		"another owner": func(t *testing.T, a *agent) { a.pinnedFilesOwner = os.Geteuid() + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRig(t)
			mutate(t, rig.agent)
			buf := newLogBuffer(newRedactor())
			prepared, err := rig.agent.prepareWorktree(context.Background(), mustClaimedJob(t, claimBody("bld_knownHOSTS01", "apk")), buf)
			if err == nil || !strings.Contains(err.Error(), rig.agent.cfg.KnownHosts) && !strings.Contains(err.Error(), filepath.Dir(rig.agent.cfg.KnownHosts)) {
				t.Fatalf("an unsafe known_hosts was accepted: %v", err)
			}
			if strings.Contains(strings.Join(buf.snapshot(), "\n"), "fetch") {
				t.Fatal("git fetch ran before the known_hosts file was checked")
			}
			rig.agent.cleanupJob(prepared.Layout)
		})
	}
}
