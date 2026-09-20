package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	case !jobspec.ValidPlatform(job.Platform):
		return fmt.Errorf("unknown target platform %q", firstRunes(job.Platform, 16))
	case job.Platform == jobspec.PlatformIOS && job.Kind != string(jobspec.KindAPK):
		// 热更新包与平台无关，由 Android 那台机器构建
		return errors.New("only installable-package jobs are built on ios")
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
	// 不做没要过的活。领取请求里只报了本机能构建的平台，服务端还会与登记求交集——
	// 派过来一条别的平台只可能是服务端的 bug 或库被人改过，那时该当场停下，而不是
	// 在这台机器上试着跑一条它根本跑不了的构建（Linux 上没有 xcodebuild）。
	if !containsPlatform(a.cfg.Platforms, job.Platform) {
		return prepared, fmt.Errorf("this machine did not ask for %s builds (BUILD_AGENT_PLATFORMS=%s)",
			job.Platform, strings.Join(a.cfg.Platforms, ","))
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
		// 不在目录所属组里的用户 chmod g+s 会被内核静默去掉：那样执行进程交回的文件属于 builder 组，
		// 控制进程读不到，失败会出现在很远的地方。在这里就说清楚。
		if info, err := os.Stat(dir); err != nil || info.Mode()&os.ModeSetgid == 0 {
			return prepared, fmt.Errorf("cannot mark %s setgid: the build agent user must be a member of the jobs root's group (rn-build-jobs)", dir)
		}
	}

	commit, err := a.checkoutMain(ctx, layout.Src(), buf)
	if err != nil {
		return prepared, err
	}
	prepared.Commit = commit
	// 从这里开始往检出里写服务端下发的文件：检出内容不可信，写入一律不跟随符号链接
	checkout, err := openCheckoutFS(layout.Src())
	if err != nil {
		return prepared, err
	}
	defer checkout.Close()

	// 身份文件由服务端合成随任务下发。构建机仍然校验一遍（见 tenantfile.go）
	if _, err := writeTenantFile(checkout, job.TenantDirectory, job.TenantFile); err != nil {
		return prepared, err
	}
	buf.add(fmt.Sprintf("tenant %s written as %s (%d)", job.TenantDirectory, job.Version, job.BuildNumber))
	if err := checkTenantFileMatchesJob(job); err != nil {
		return prepared, err
	}
	written, err := fetchTenantIcons(ctx, a.api, job, checkout, buf)
	if err != nil {
		return prepared, err
	}
	if written > 0 {
		buf.add(fmt.Sprintf("%d icons written from the tenant configuration", written))
	}
	// 图标在 prebuild 里才被读到，而那是 pnpm install 之后的事。这里先看一眼。
	if missing := missingTenantIcons(checkout, job.TenantDirectory); len(missing) > 0 {
		return prepared, fmt.Errorf("这个租户缺这几张启动图标：%s。"+
			"在控制台「Android 打包与签名 → 启动图标」上传，或者提交到 App 仓库的 assets/tenants/%s/ 下",
			strings.Join(missing, "、"), job.TenantDirectory)
	}
	// 证书与 Firebase 配置两种任务都写：它们是真实的原生输入，进 expo config，也就进原生指纹。
	// 路径必须是相对的（见 jobspec.OTACertificateRelPath），否则每个任务目录一个指纹。
	if err := checkout.writeFile(jobspec.OTACertificateRelPath, []byte(job.OTACertificatePEM)); err != nil {
		return prepared, err
	}
	googleServices := strings.TrimSpace(job.GoogleServicesJSON) != ""
	if googleServices {
		decoded, err := base64.StdEncoding.DecodeString(job.GoogleServicesJSON)
		if err != nil {
			return prepared, fmt.Errorf("googleServicesJson is not base64: %w", err)
		}
		if err := checkout.writeFile(jobspec.GoogleServicesRelPath, decoded); err != nil {
			return prepared, err
		}
		buf.add("google-services.json written from the tenant build configuration")
	}

	env, err := jobspec.BuildEnv(layout, a.cfg.MachineEnv, jobspec.TaskEnv{
		Platform:        job.Platform,
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
		Platform:        job.Platform,
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
	if err := writeNewFile(layout.Dir(), jobspec.SpecFileName, raw); err != nil {
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

// checkoutMain 在控制进程里把 main 检出成一个自包含的单提交仓库（src/.git 是真目录），
// 执行进程复制一份就有能用的 git（build-ota.mjs 要 git status / rev-parse），
// 而完全不需要读裸库。
//
// 整个过程不执行仓库里的任何东西：hooksPath 指向 /dev/null（裸库里的 hook、fetch 时的
// reference-transaction、checkout 时的 post-checkout 都不跑），不读系统与全局 git 配置
// （filter、fsmonitor 等能执行命令的配置只可能来自那里），新仓库用空模板。
//
// 仓库镜像自己的配置也不信：改造前的构建机上它归 builder 可写，core.sshCommand、include.path、
// remote.origin.uploadpack 这类键都能让 fetch 执行命令或改道。fetch 之前按白名单核对（checkMirror），
// ssh 的参数由环境变量固定（gitEnv），传输协议只放行这一步要用的那一个。
func (a *agent) checkoutMain(ctx context.Context, dst string, buf *logBuffer) (string, error) {
	gitCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if err := a.checkKnownHosts(); err != nil {
		return "", err
	}
	if err := a.checkMirror(gitCtx); err != nil {
		return "", err
	}
	gitDir := "--git-dir=" + a.cfg.Repo
	if err := a.gitAllowing(gitCtx, buf, "", a.mirrorProtocol, gitDir, "fetch", "--prune", "origin"); err != nil {
		return "", err
	}
	sha, err := a.gitOutput(gitCtx, gitDir, "rev-parse", "--verify", "--end-of-options", buildBranchRef+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("cannot resolve %s in the build machine's repository: %w", buildBranchRef, err)
	}
	if !jobspec.ValidCommit(sha) {
		return "", errors.New("git printed something that is not a commit id")
	}
	if err := a.git(gitCtx, buf, "", "init", "--quiet", "--template=", dst); err != nil {
		return "", err
	}
	// 从本机镜像取：只放行 file 协议
	if err := a.gitAllowing(gitCtx, buf, dst, "file", "fetch", "--quiet", "--no-tags", "--depth=1", "file://"+a.cfg.Repo, buildBranchRef); err != nil {
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
	if err := a.verifyCommitSignature(gitCtx, dst, sha, buf); err != nil {
		return "", err
	}
	buf.add("commit " + sha + " (" + buildBranchRef + ")")
	return sha, nil
}

// errUntrustedMirror：仓库镜像的配置或目录结构不是 git clone --mirror 产生的样子。不自动修：
// 它可能是改造前 builder 写进去的，按手册挪走、以 rn-build-agent 重新克隆。
var errUntrustedMirror = errors.New("镜像配置不可信")

// mirrorConfigKeys 是仓库镜像 config 里允许出现的键：git clone --mirror 实际写出的那几个
// （git 2.34 与 2.55 实测；tagopt 是新版本写的）。git config --list 输出的节名与键名是小写的，
// 子节（origin）保留原样。别的任何键都拒绝。
var mirrorConfigKeys = map[string]bool{
	"core.repositoryformatversion": true,
	"core.filemode":                true,
	"core.bare":                    true,
	"core.logallrefupdates":        true,
	// macOS 上 git clone 自己写的两个：文件系统大小写不敏感、APFS/HFS+ 的 unicode 预组合。
	// 它们描述的是**文件系统**，不指向任何地方、也不让任何东西执行；而且 git 在 macOS 上
	// clone 时必写——不认它们等于 Mac 上克隆出来的镜像一律"配置不可信"，一条任务都跑不了。
	"core.ignorecase":        true,
	"core.precomposeunicode": true,
	"remote.origin.url":      true,
	"remote.origin.fetch":    true,
	"remote.origin.mirror":   true,
	"remote.origin.tagopt":   true,
}

// mirrorForbiddenEntries 是镜像目录里不许存在的东西：
//   - .git、commondir：git-upload-pack 与 git 自己会顺着它们去读另一个仓库（连同那边的配置）
//   - config.worktree：另一份配置
//   - objects/info/alternates、http-alternates：从别处借对象
//   - info/attributes、info/grafts：改变文件内容的过滤与改写历史
//
// branches/、remotes/ 是旧式的远端定义，只许是空目录（git 2.34 的模板会建空的 branches/）。
var (
	mirrorForbiddenEntries = []string{".git", "commondir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates", "info/attributes", "info/grafts"}
	mirrorEmptyDirs        = []string{"branches", "remotes"}
)

// checkMirror 在 fetch 之前核对仓库镜像。
func (a *agent) checkMirror(ctx context.Context) error {
	untrusted := func(format string, args ...any) error {
		return fmt.Errorf("%w：构建机的仓库镜像 %s %s，没有 fetch。按 deploy/amos/SIGNING_GATE_ROLLOUT.md「重建仓库镜像与 ~/.ssh」把它挪走、以 rn-build-agent 重新克隆",
			errUntrustedMirror, a.cfg.Repo, fmt.Sprintf(format, args...))
	}
	repo := a.cfg.Repo
	info, err := os.Lstat(repo)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the build machine has no repository mirror at %s yet: add its deploy key to GitHub and run the install command again (it clones the mirror)", repo)
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case info.Mode()&fs.ModeSymlink != 0 || !info.IsDir():
		return untrusted("不是真实目录")
	case !ok || int(st.Uid) != os.Geteuid():
		return untrusted("不属于构建控制进程用户")
	case info.Mode().Perm()&0o022 != 0:
		return untrusted("组或其他人可写")
	}
	config, err := os.Lstat(filepath.Join(repo, "config"))
	if err != nil || !config.Mode().IsRegular() {
		return untrusted("的 config 不是普通文件")
	}
	if st, ok := config.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() || config.Mode().Perm()&0o022 != 0 {
		return untrusted("的 config 不属于构建控制进程用户，或组与其他人可写")
	}
	for _, name := range mirrorForbiddenEntries {
		if _, err := os.Lstat(filepath.Join(repo, name)); err == nil {
			return untrusted("里有 %s", name)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	for _, name := range mirrorEmptyDirs {
		entries, err := os.ReadDir(filepath.Join(repo, name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return untrusted("的 %s 读不了（%v）", name, err)
		}
		if len(entries) > 0 {
			return untrusted("的 %s/ 不是空的（旧式远端定义）", name)
		}
	}

	// 用 git 自己的解析器读：与 fetch 看到的完全一致（大小写、续行、子节写法）。--no-includes 不跟随 include.path
	cmd := a.gitCommand(ctx, "", "config", "--file", filepath.Join(repo, "config"), "--no-includes", "--null", "--list")
	out, err := cmd.Output()
	if err != nil {
		return untrusted("的 config 解析不了")
	}
	seen := map[string]int{}
	for _, entry := range strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00") {
		if entry == "" {
			continue
		}
		key, value, _ := strings.Cut(entry, "\n")
		if !mirrorConfigKeys[key] {
			return untrusted("的 config 里有不允许的键 %q", firstRunes(key, 64))
		}
		seen[key]++
		switch {
		case key == "core.bare" && value != "true":
			return untrusted("不是裸仓库（core.bare=%q）", firstRunes(value, 16))
		case key != "remote.origin.fetch" && seen[key] > 1:
			return untrusted("的 config 里 %s 出现了不止一次", key)
		}
	}
	if seen["remote.origin.url"] != 1 {
		return untrusted("的 config 里没有 remote.origin.url")
	}
	return nil
}

// rootUID 是固定 known_hosts 文件必须的属主：root。控制进程自己改不了它。
const rootUID = 0

// checkKnownHosts 核对 fetch 用的 known_hosts：root（测试里是 a.pinnedFilesOwner）所有的普通文件，
// 它和所在目录组与其他人都不可写。
func (a *agent) checkKnownHosts() error {
	return a.checkPinnedFile(a.cfg.KnownHosts, "the pinned GitHub known_hosts",
		"so the build agent cannot change which host key GitHub must have")
}

// checkPinnedFile 核对一份"控制进程自己改不了"的文件：root（测试里是 a.pinnedFilesOwner）
// 所有的普通文件，在同样属于它的真实目录里，组和其他人不可写。
//
// 目录也要查：目录可写的话，换掉整个文件只是一次 rename。
func (a *agent) checkPinnedFile(path, what, why string) error {
	for _, p := range []string{path, filepath.Dir(path)} {
		info, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("%s %s is not usable (%w): install it as described in the machine setup guide", what, path, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		wantDir := p != path
		switch {
		case info.Mode()&fs.ModeSymlink != 0 || info.IsDir() != wantDir || (!wantDir && !info.Mode().IsRegular()):
			return fmt.Errorf("%s must be a regular file in a real directory, not a symlink: install %s as described in the machine setup guide", p, what)
		case !ok || int(st.Uid) != a.pinnedFilesOwner:
			return fmt.Errorf("%s must belong to root %s", p, why)
		case info.Mode().Perm()&0o022 != 0:
			return fmt.Errorf("%s must not be writable by group or others", p)
		}
	}
	return nil
}

// checkAllowedSigners 核对提交签名校验用的允许签名者文件（设计
// ios-mac-builders-home-network-2026-09-18 §4.6）。没配就是没开这道闸——iOS 机器上
// 不配会在 loadConfig 里直接启动失败。
func (a *agent) checkAllowedSigners() error {
	if a.cfg.AllowedSigners == "" {
		return nil
	}
	return a.checkPinnedFile(a.cfg.AllowedSigners, "the pinned allowed_signers file",
		"so the build agent cannot add a signer to the list it checks commits against")
}

// verifyCommitSignature 要求这个提交由 allowed_signers 里的某把 SSH 密钥签过。
//
// **为什么这道闸在 iOS 机器上是必需的**：这台 Mac 上放着全部租户的签名材料，而它构建的
// 是服务端指过来的那个提交。没有这道闸，任何一条通向"能改 main"或"能改服务端数据库"的
// 路，都直接变成"在这台机器上执行任意代码"——而那等于拿到全部租户的 Distribution 私钥。
// 有了它，推得上去也过不了这一关：签名者的私钥不在 GitHub、也不在服务端。
//
// gpg.format=ssh 与 allowedSignersFile 走命令行的 -c，不写进仓库配置：检出目录是每次任务
// 新建的，而 git 的配置优先级里命令行最高。allowed_signers 属于 root，控制进程改不了它。
func (a *agent) verifyCommitSignature(ctx context.Context, dir, sha string, buf *logBuffer) error {
	if a.cfg.AllowedSigners == "" {
		return nil
	}
	if err := a.checkAllowedSigners(); err != nil {
		return err
	}
	cmd := a.gitCommand(ctx, dir, "-c", "gpg.format=ssh",
		"-c", "gpg.ssh.allowedSignersFile="+a.cfg.AllowedSigners,
		"verify-commit", "--", sha)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// git 把"谁签的、签没签"都打在 stderr 上。原样带出去（经日志缓冲的脱敏），
		// 它是这条任务失败原因里唯一有用的部分
		return fmt.Errorf("commit %s is not signed by an allowed signer (%s): %w. "+
			"Every commit on the build branch must carry an SSH signature from a key listed in %s",
			sha, firstRunes(strings.TrimSpace(stderr.String()), 300), err, a.cfg.AllowedSigners)
	}
	buf.add("commit signature verified against " + a.cfg.AllowedSigners)
	return nil
}

// gitEnv 是控制进程调用 git 的环境：不带令牌，不读系统和全局配置。
//
// GIT_SSH_COMMAND 优先于仓库配置里的 core.sshCommand：ssh 不读任何配置文件（-F /dev/null，
// 连 /etc/ssh/ssh_config 也不读），只用 deploy key，主机公钥只认 root 所有的固定 known_hosts。
// GIT_NO_REPLACE_OBJECTS：refs/replace/ 不能把检出的对象换掉。
func (a *agent) gitEnv() []string {
	return []string{
		"PATH=" + a.cfg.MachineEnv["PATH"],
		"HOME=" + os.Getenv("HOME"),
		"LANG=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_SSH_COMMAND=" + a.cfg.sshCommand(),
	}
}

// sshCommand 是 fetch 仓库镜像时 git 执行的 ssh（经 sh -c；路径在 loadConfig 里校验过只含安全字符）。
func (c config) sshCommand() string {
	return "ssh -F /dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i " + c.SSHKey +
		" -o UserKnownHostsFile=" + c.KnownHosts + " -o GlobalKnownHostsFile=/dev/null" +
		" -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=15"
}

// gitSafetyConfig 是控制进程每条 git 命令都带的配置。
//
// maintenance.auto / gc.auto：git fetch 结束时会拉起一个 **detach 的** `git maintenance run --auto`
// （git 2.55 实测），它在 fetch 返回之后才去建锁文件、写 objects/。控制进程紧接着就把检出交给
// 执行进程复制、任务结束时整棵删掉，后台进程还在往里写，删除报 "directory not empty"、复制
// 可能撞上一闪而过的锁文件（压测里出现过）。构建机上的仓库用完即删，不需要自动维护。
//
// protocol.allow=never：默认不许任何传输；要联网或读本机仓库的那一步用 gitAllowing 单独放行一个协议。
var gitSafetyConfig = []string{
	"-c", "core.hooksPath=/dev/null",
	"-c", "core.fsmonitor=false",
	"-c", "maintenance.auto=false",
	"-c", "gc.auto=0",
	"-c", "protocol.allow=never",
}

func (a *agent) gitCommand(ctx context.Context, dir string, args ...string) *exec.Cmd {
	return a.gitCommandAllowing(ctx, dir, "", args...)
}

// gitCommandAllowing 同 gitCommand，另外放行一个传输协议（空表示不放行）。
func (a *agent) gitCommandAllowing(ctx context.Context, dir, protocol string, args ...string) *exec.Cmd {
	full := append([]string(nil), gitSafetyConfig...)
	if protocol != "" {
		full = append(full, "-c", "protocol."+protocol+".allow=always")
	}
	full = append(full, args...)
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
	return a.gitAllowing(ctx, buf, dir, "", args...)
}

func (a *agent) gitAllowing(ctx context.Context, buf *logBuffer, dir, protocol string, args ...string) error {
	buf.add("$ git " + strings.Join(args, " "))
	cmd := a.gitCommandAllowing(ctx, dir, protocol, args...)
	lines := newLineWriter(buf, nil)
	cmd.Stdout = lines
	cmd.Stderr = lines
	err := cmd.Run()
	lines.Close()
	if err != nil {
		return fmt.Errorf("git %s failed: %w", gitSubcommand(args), err)
	}
	return nil
}

// gitSubcommand 取出参数里的子命令名（跳过 --git-dir= 之类的全局选项），用于报错。
func gitSubcommand(args []string) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return strings.Join(args, " ")
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
// 文件名由服务端给（约定的那四个），这里仍然挡一次路径逃逸；写入不跟随检出里的符号链接。
//
// 每张图都带重试：这是一次构建最早的几步之一，此刻还没有任何成本沉淀，但**失败的代价
// 是整条任务判死**——2026-09-20 真机上第一条能跑起来的 iOS 任务就倒在这里，一句
// "cannot fetch icon icon.png: context deadline exceeded"。取图标是幂等的 GET，
// 重试一次比让人回控制台重排一次便宜得多。
//
// 重试放在 writeFrom **外面**：那条路每次都从头建一个临时文件，在回调里重试会把第二次
// 的字节接在半截文件后面。
func fetchTenantIcons(ctx context.Context, api *client, job claimedJob, checkout *checkoutFS, buf *logBuffer) (int, error) {
	if len(job.Icons) == 0 {
		return 0, nil
	}
	dir := filepath.Join("assets", "tenants", job.TenantDirectory)
	written := 0
	for _, name := range job.Icons {
		if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return written, fmt.Errorf("refusing an icon name that escapes the tenant directory: %q", firstRunes(name, 64))
		}
		err := withRetry(ctx, buf, "fetching icon "+name, iconAttempts, func(ctx context.Context) error {
			return checkout.writeFrom(filepath.Join(dir, name), func(w io.Writer) error {
				return api.downloadIcon(ctx, job, name, w)
			})
		})
		if err != nil {
			return written, fmt.Errorf("cannot fetch icon %s: %w", name, err)
		}
		written++
	}
	return written, nil
}

// iconAttempts：图标取几次。退避从 5 秒起翻倍，三次合计等 15 秒——比重排一次构建便宜。
const iconAttempts = 3

// missingTenantIcons 返回 prebuild 会去读、而检出里还没有（或者不是普通文件）的那几个图标。
func missingTenantIcons(checkout *checkoutFS, directory string) []string {
	var missing []string
	for _, name := range []string{
		"icon.png",
		"android-icon-foreground.png",
		"android-icon-background.png",
		"android-icon-monochrome.png",
	} {
		if !checkout.isRegularFile(filepath.Join("assets", "tenants", directory, name)) {
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
