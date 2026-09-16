package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/ident"
)

// buildBranch 是构建机唯一检出的分支。任务里的 gitRef 只用来核对：服务端下发了别的分支，
// 就说明服务端被改过或者版本不对，不照做。
const (
	buildBranch    = "main"
	buildBranchRef = "refs/heads/" + buildBranch
)

// preparedJob 是控制进程为执行进程准备好的一个任务目录。
type preparedJob struct {
	Layout jobspec.Layout
	Commit string
	Env    []string
	Spec   jobspec.Spec
}

// validateClaimedJob 在动磁盘之前把服务端下发的字段逐个校验一遍：两端分属不同的信任域，
// 路径拼接与交给子进程的参数各自把住自己那一侧。
func validateClaimedJob(job claimedJob) error {
	switch {
	case !jobspec.ValidJobID(job.ID):
		return errors.New("the job id is malformed")
	case job.Attempt < 1:
		return errors.New("the job carries no attempt number")
	case job.Platform != "android":
		return fmt.Errorf("this build machine only builds android, got %q", firstRunes(job.Platform, 16))
	case job.Kind != string(jobspec.KindAPK) && job.Kind != string(jobspec.KindOTA):
		return fmt.Errorf("unknown job kind %q", firstRunes(job.Kind, 16))
	case job.GitRef != buildBranch:
		// 不回显整个值：它来自服务端，长度不受控
		return fmt.Errorf("refusing a job whose git ref is not %s (%d bytes, starts with %q); this machine always builds %s",
			buildBranch, len(job.GitRef), firstRunes(job.GitRef, 8), buildBranchRef)
	case job.TenantDirectory == "":
		return errors.New("the job does not say which tenants/ directory to build; set repoDirectory in this tenant's build configuration")
	case !jobspec.ValidTenantDirectory(job.TenantDirectory):
		return fmt.Errorf("refusing a tenant directory that is not a plain name under tenants/: %q", firstRunes(job.TenantDirectory, 64))
	case !jobspec.ValidVersion(job.Version):
		return errors.New("the job version is malformed")
	case job.BuildNumber < 1:
		return errors.New("the job build number must be positive")
	case strings.TrimSpace(job.OTACertificatePEM) == "":
		return fmt.Errorf("tenant %s has no OTA signing key; install one before building a package that must verify updates", firstRunes(job.TenantSlug, 64))
	}
	if job.Kind == string(jobspec.KindAPK) {
		// 出处声明要签机器 id；服务端给的认领机器就是本机
		if !ident.ValidServerID(job.ClaimedMachineID) {
			return errors.New("the job does not say which machine claimed it (claimedMachineId), so no provenance can be signed")
		}
		if !ident.ValidTenantSlug(job.TenantSlug) {
			return errors.New("the job tenant slug is malformed")
		}
	}
	if job.Kind == string(jobspec.KindOTA) && (strings.TrimSpace(job.RuntimeVersion) == "" || strings.TrimSpace(job.BaseReleaseID) == "") {
		return errors.New("the OTA job carries no base release or runtime version")
	}
	return nil
}

// prepareWorktree 做两种任务共用的那一段：建任务目录、检出 main、写身份文件与图标、
// 构造子进程环境、写任务说明。**环境只在这里构造**，安装包与热更新两条链路用的是同一份。
func (a *agent) prepareWorktree(ctx context.Context, job claimedJob, buf *logBuffer) (preparedJob, error) {
	var prepared preparedJob
	if err := validateClaimedJob(job); err != nil {
		return prepared, err
	}
	layout, err := jobspec.NewLayout(a.cfg.Workspace, job.ID)
	if err != nil {
		return prepared, err
	}
	prepared.Layout = layout
	if err := os.Mkdir(layout.Dir(), 0o750); err != nil {
		return prepared, fmt.Errorf("cannot create the job directory: %w", err)
	}
	// work/ 与 out/ 交给执行进程写：组可写并带 setgid，执行进程建的文件继承 rn-build-jobs 组，
	// 控制进程读得到产物；两者都不给其他人任何权限。
	for _, dir := range []string{layout.Work(), layout.Out()} {
		if err := os.Mkdir(dir, 0o770); err != nil {
			return prepared, err
		}
		if err := os.Chmod(dir, 0o770|os.ModeSetgid); err != nil {
			return prepared, err
		}
	}

	commit, err := a.checkoutMain(ctx, layout.Src(), buf)
	if err != nil {
		return prepared, err
	}
	prepared.Commit = commit
	src := layout.Src()

	// 身份文件由服务端合成随任务下发，仓库里没有这份文件。构建机仍然校验一遍（见 tenantfile.go）
	if _, err := writeTenantFile(src, job.TenantDirectory, job.TenantFile); err != nil {
		return prepared, err
	}
	buf.add(fmt.Sprintf("tenant %s written as %s (%d)", job.TenantDirectory, job.Version, job.BuildNumber))
	if err := checkTenantFileMatchesJob(job); err != nil {
		return prepared, err
	}
	written, err := fetchTenantIcons(ctx, a.api, job, src)
	if err != nil {
		return prepared, err
	}
	if written > 0 {
		buf.add(fmt.Sprintf("%d icons written from the tenant configuration", written))
	}
	// 图标在 prebuild 里才被读到，而那是 pnpm install 之后的事。这里先看一眼。
	if missing := missingTenantIcons(src, job.TenantDirectory); len(missing) > 0 {
		return prepared, fmt.Errorf("这个租户缺这几张启动图标：%s。"+
			"在控制台「Android 打包与签名 → 启动图标」上传，或者提交到 App 仓库的 assets/tenants/%s/ 下",
			strings.Join(missing, "、"), job.TenantDirectory)
	}
	// 证书与 Firebase 配置两种任务都写：它们是真实的原生输入，进 expo config，也就进原生指纹。
	// 路径必须是相对的（见 jobspec.OTACertificateRelPath），否则每个任务目录一个指纹。
	if err := writeJobFile(filepath.Join(src, jobspec.OTACertificateRelPath), []byte(job.OTACertificatePEM)); err != nil {
		return prepared, err
	}
	googleServices := strings.TrimSpace(job.GoogleServicesJSON) != ""
	if googleServices {
		decoded, err := base64.StdEncoding.DecodeString(job.GoogleServicesJSON)
		if err != nil {
			return prepared, fmt.Errorf("googleServicesJson is not base64: %w", err)
		}
		if err := writeJobFile(filepath.Join(src, jobspec.GoogleServicesRelPath), decoded); err != nil {
			return prepared, err
		}
		buf.add("google-services.json written from the tenant build configuration")
	}

	env, err := jobspec.BuildEnv(layout, a.cfg.MachineEnv, jobspec.TaskEnv{
		TenantDirectory: job.TenantDirectory,
		APIBaseURL:      job.APIBaseURL(),
		GoogleServices:  googleServices,
	})
	if err != nil {
		return prepared, err
	}
	prepared.Env = env
	spec := jobspec.Spec{
		Version:         jobspec.SpecVersion,
		JobID:           job.ID,
		Kind:            jobspec.Kind(job.Kind),
		TenantDirectory: job.TenantDirectory,
		AppVersion:      job.Version,
		BuildNumber:     job.BuildNumber,
		CommitSHA:       commit,
		Env:             env,
	}
	if spec.Kind == jobspec.KindOTA {
		spec.OTA = &jobspec.OTAArgs{
			Channel:        job.Channel,
			ApplyStrategy:  job.ApplyStrategy,
			RuntimeVersion: job.RuntimeVersion,
			APIBaseURL:     job.APIBaseURL(),
			ApplicationID:  job.ApplicationID(),
		}
	}
	if err := spec.Validate(layout); err != nil {
		return prepared, fmt.Errorf("the job cannot be described to the build runner: %w", err)
	}
	raw, err := jobspec.EncodeSpec(spec)
	if err != nil {
		return prepared, err
	}
	if err := writeJobFile(layout.Spec(), raw); err != nil {
		return prepared, err
	}
	prepared.Spec = spec
	return prepared, nil
}

// checkTenantFileMatchesJob：身份文件里的版本号与 build 号必须就是任务行上的值——出处声明
// 签的是任务行，包里编进去的是身份文件，两者不一致签名闸会拒签，在这里就说清楚。
func checkTenantFileMatchesJob(job claimedJob) error {
	if version := job.tenantField("version"); version != job.Version {
		return fmt.Errorf("the tenant file version %q does not match the job version %q", firstRunes(version, 32), job.Version)
	}
	var fields struct {
		AndroidVersionCode int `json:"androidVersionCode"`
	}
	if err := json.Unmarshal(job.TenantFile, &fields); err != nil || fields.AndroidVersionCode != job.BuildNumber {
		return fmt.Errorf("the tenant file androidVersionCode does not match the job build number %d", job.BuildNumber)
	}
	return nil
}

func writeJobFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0o640)
}

// checkoutMain 在控制进程里把 main 检出成一个自包含的单提交仓库（src/.git 是真目录），
// 执行进程复制一份就有能用的 git（build-ota.mjs 要 git status / rev-parse），
// 而完全不需要读裸库。
//
// 整个过程不执行仓库里的任何东西：hooksPath 指向 /dev/null（裸库里的 hook、fetch 时的
// reference-transaction、checkout 时的 post-checkout 都不跑），不读系统与全局 git 配置
// （filter、fsmonitor 等能执行命令的配置只可能来自那里），新仓库用空模板。
func (a *agent) checkoutMain(ctx context.Context, dst string, buf *logBuffer) (string, error) {
	gitCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if err := a.git(gitCtx, buf, "", "-C", a.cfg.Repo, "fetch", "--all", "--prune"); err != nil {
		return "", err
	}
	sha, err := a.gitOutput(gitCtx, "-C", a.cfg.Repo, "rev-parse", "--verify", "--end-of-options", buildBranchRef+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s in the build machine's repository: %w", buildBranchRef, err)
	}
	if !jobspec.ValidCommit(sha) {
		return "", errors.New("git printed something that is not a commit id")
	}
	if err := a.git(gitCtx, buf, "", "init", "--quiet", "--template=", dst); err != nil {
		return "", err
	}
	if err := a.git(gitCtx, buf, dst, "fetch", "--quiet", "--no-tags", "--depth=1", "file://"+a.cfg.Repo, buildBranchRef); err != nil {
		return "", err
	}
	fetched, err := a.gitOutput(gitCtx, "-C", dst, "rev-parse", "--verify", "--end-of-options", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}
	if fetched != sha {
		return "", fmt.Errorf("%s moved while it was being checked out (%s, then %s)", buildBranchRef, sha, fetched)
	}
	if err := a.git(gitCtx, buf, dst, "checkout", "--quiet", "--detach", sha); err != nil {
		return "", err
	}
	head, err := a.gitOutput(gitCtx, "-C", dst, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	if head != sha {
		return "", fmt.Errorf("the checkout is at %s, not %s", head, sha)
	}
	buf.add("commit " + sha + " (" + buildBranchRef + ")")
	return sha, nil
}

// gitEnv 是控制进程调用 git 的环境：不带令牌，不读系统和全局配置。
func (a *agent) gitEnv() []string {
	return []string{
		"PATH=" + a.cfg.MachineEnv["PATH"],
		"HOME=" + os.Getenv("HOME"),
		"LANG=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	}
}

func (a *agent) gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	full := append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=always"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = a.gitEnv()
	cmd.Dir = dir
	if dir == "" {
		cmd.Dir = "/"
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	return cmd
}

func (a *agent) git(ctx context.Context, buf *logBuffer, dir string, args ...string) error {
	buf.add("$ git " + strings.Join(args, " "))
	cmd := a.gitCommand(ctx, dir, args...)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("git could not start: %w", err)
	}
	streamLines(pipe, buf, nil)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("git %s failed: %w", args[0], err)
	}
	return nil
}

func (a *agent) gitOutput(ctx context.Context, args ...string) (string, error) {
	cmd := a.gitCommand(ctx, "", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// fetchTenantIcons 把服务端列出的图标一张一张取下来，写进 assets/tenants/<目录>/。
// 文件名由服务端给（约定的那四个），这里仍然挡一次路径逃逸。
func fetchTenantIcons(ctx context.Context, api *client, job claimedJob, checkout string) (int, error) {
	if len(job.Icons) == 0 {
		return 0, nil
	}
	dir := filepath.Join(checkout, "assets", "tenants", job.TenantDirectory)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("create tenant asset directory: %w", err)
	}
	written := 0
	for _, name := range job.Icons {
		if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || name == "" {
			return written, fmt.Errorf("refusing an icon name that escapes the tenant directory: %q", firstRunes(name, 64))
		}
		if err := api.downloadIcon(ctx, job, name, filepath.Join(dir, name)); err != nil {
			return written, fmt.Errorf("cannot fetch icon %s: %w", name, err)
		}
		written++
	}
	return written, nil
}

// missingTenantIcons 返回 prebuild 会去读、而检出里还没有的那几个图标。
func missingTenantIcons(checkout, directory string) []string {
	var missing []string
	for _, name := range []string{
		"icon.png",
		"android-icon-foreground.png",
		"android-icon-background.png",
		"android-icon-monochrome.png",
	} {
		if _, err := os.Stat(filepath.Join(checkout, "assets", "tenants", directory, name)); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

func firstRunes(value string, n int) string {
	runes := []rune(value)
	if len(runes) <= n {
		return string(runes)
	}
	return string(runes[:n]) + "…"
}
