package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 构建热更新包。和编 APK 共用前半段（拉代码、写身份、取图标），后半段完全不同：
// 不需要 Android SDK、不需要 Gradle，**也不需要签名密钥**——热更新 manifest 是服务端
// 在下发那一刻用租户的 OTA 私钥签的，这台机器从头到尾碰不到它。
//
// 产出一条 verified 的修订，不发布。要不要发给用户是管理端上另一次带 reason 的动作。
func buildOTAPackage(ctx context.Context, cfg config, api *client, job claimedJob, buf *logBuffer) (buildResult, error) {
	var result buildResult
	if job.Platform != "android" {
		return result, fmt.Errorf("this agent only builds android OTA packages, got %q", job.Platform)
	}
	if strings.TrimSpace(job.RuntimeVersion) == "" || strings.TrimSpace(job.BaseReleaseID) == "" {
		return result, fmt.Errorf("the OTA job carries no base release or runtime version")
	}
	worktree, commitSHA, err := prepareWorktree(ctx, cfg, api, job, buf)
	if err != nil {
		return result, err
	}
	result.CommitSHA = commitSHA

	env := append(os.Environ(),
		"EXPO_PUBLIC_TENANT="+job.TenantDirectory,
		"EXPO_PUBLIC_API_BASE_URL="+job.APIBaseURL(),
	)
	if err := run(ctx, buf, worktree, env, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return result, err
	}

	zip := filepath.Join(worktree, "artifacts", fmt.Sprintf("ota-%s-%s.zip", job.TenantDirectory, job.ID))
	if err := os.MkdirAll(filepath.Dir(zip), 0o750); err != nil {
		return result, err
	}
	// runtimeVersion 显式给基线那一版：脚本默认会去问"当前在分发的版本"，而这条任务
	// 要对准的是**排队时选的那个基线**，两者可以不是同一个。
	//
	// --allow-dirty 是必需的：身份文件和图标是服务端下发后写进 worktree 的，检出必然
	// 是"脏"的。那个开关本来防的是"从未提交的代码出包"，而这里脏的不是代码。
	args := []string{
		"ota:build",
		"--platform", "android",
		"--channel", job.Channel,
		"--distribution-channel", "direct",
		"--api-base-url", job.APIBaseURL(),
		"--apply-strategy", job.ApplyStrategy,
		"--runtime-version", job.RuntimeVersion,
		"--application-id", job.ApplicationID(),
		"--output-zip", zip,
		"--allow-dirty", "true",
	}
	if err := run(ctx, buf, worktree, env, "pnpm", args...); err != nil {
		return result, err
	}
	if _, err := os.Stat(zip); err != nil {
		return result, fmt.Errorf("the OTA build reported success but %s is not there: %w", filepath.Base(zip), err)
	}
	result.ArtifactPath = zip
	if result.SHA256, err = fileSHA256(zip); err != nil {
		return result, err
	}
	buf.add("ota package sha256 " + result.SHA256)
	return result, nil
}

// nativeFingerprint 算这次检出的"原生面"指纹。
//
// @expo/fingerprint 只看自动链接的原生模块、原生配置和 expo config，不看 JS 源码——
// 正是"要不要重新编译原生"这个问题的定义。编 APK 时算一次存进发布记录，构建热更新时
// 再算一次比对：不一致就说明这次改动动了原生，不能走热更新（服务端会拒，见
// internal/api/ota_fingerprint.go）。
//
// 算不出来不让整条构建失败：指纹只影响"这个包以后能不能收热更新"，而一个能装能跑的
// 安装包本身是有价值的。缺指纹的后果会在发热更新那一刻被明确告知。
func nativeFingerprint(ctx context.Context, buf *logBuffer, worktree, tenantDirectory string, env []string) string {
	cmd := exec.CommandContext(ctx, "pnpm", "exec", "fingerprint", ".")
	cmd.Dir = worktree
	cmd.Env = append(env, "EXPO_PUBLIC_TENANT="+tenantDirectory)
	out, err := cmd.Output()
	if err != nil {
		buf.add("native fingerprint unavailable: " + err.Error())
		return ""
	}
	var parsed struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal(out, &parsed) != nil || strings.TrimSpace(parsed.Hash) == "" {
		buf.add("native fingerprint unavailable: the tool printed no hash")
		return ""
	}
	buf.add("native fingerprint " + parsed.Hash)
	return strings.TrimSpace(parsed.Hash)
}
