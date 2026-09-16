package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// logBuffer 只留尾部若干行。完整日志留在构建机上，上报的是够定位失败的那一段。
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	red   *redactor
}

func newLogBuffer(red *redactor) *logBuffer {
	return &logBuffer{max: 200, red: red}
}

func (b *logBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, b.red.line(line))
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

// run 执行一条命令并把输出收进 logBuffer。用独立进程组，超时时杀整棵树——
// Gradle 会拉起一个常驻 daemon，只杀父进程会留下一个还在跑的构建。
func run(ctx context.Context, buf *logBuffer, dir string, env []string, name string, args ...string) error {
	buf.add("$ " + name + " " + strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s could not start: %w", name, err)
	}
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		buf.add(scanner.Text())
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type buildResult struct {
	CommitSHA    string
	ArtifactPath string
	SHA256       string
	SBOMPath     string
	// NativeFingerprint 决定这个包以后能不能收热更新（见 ota.go 的 nativeFingerprint）
	NativeFingerprint string
}

// buildJob 跑完一个任务的全部步骤。每一步失败都直接返回，调用方负责上报 fail
// 并清理 worktree。
func buildJob(ctx context.Context, cfg config, api *client, job claimedJob, buf *logBuffer) (buildResult, error) {
	if job.Kind == "ota" {
		return buildOTAPackage(ctx, cfg, api, job, buf)
	}
	return buildAPK(ctx, cfg, api, job, buf)
}

// prepareWorktree 做两种任务都要做的那一段：拉代码、开一份干净检出、写身份文件、
// 取图标。返回这次检出的 worktree 路径与确切提交。
func prepareWorktree(ctx context.Context, cfg config, api *client, job claimedJob, buf *logBuffer) (string, string, []string, error) {
	if job.TenantDirectory == "" {
		return "", "", nil, fmt.Errorf("the job does not say which tenants/ directory to build; set repoDirectory in this tenant's build configuration")
	}
	// 目录名会被拼进路径。服务端已经校验过，代理再挡一次——两端分属不同的信任域，
	// 各自把住自己那一侧是这类路径拼接的常规做法。
	if strings.ContainsAny(job.TenantDirectory, `/\`) || strings.Contains(job.TenantDirectory, "..") {
		return "", "", nil, fmt.Errorf("refusing a tenant directory that escapes tenants/: %q", job.TenantDirectory)
	}
	// git ref 同样会被原样交给 git，而它是**服务端从库里读出来下发的**——同一个
	// 函数上面几行已经为 TenantDirectory 做过这件事，理由一样：两端分属不同的
	// 信任域，各自把住自己那一侧。
	//
	// 最直接的危害是选项注入：`git worktree add --detach <path> <ref>` 里，一个
	// 以 `-` 开头的 ref 会被 git 当成选项。这条校验挡住它，也挡住路径穿越。
	//
	// 它**挡不住**「攻击者已经能往 RN-App 推一个带后门的提交」那种情况——那要靠
	// 把 ref 限定到白名单，是另一个设计决定（build-concurrency-2026-09-15 §9）。
	if err := validateGitRef(job.GitRef); err != nil {
		return "", "", nil, err
	}
	worktree := filepath.Join(cfg.Workspace, job.ID)
	env := os.Environ()
	// 每个任务一个全新 worktree。共用检出会把别人未提交的改动混进产物。
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "fetch", "--all", "--prune"); err != nil {
		return "", "", nil, err
	}
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "worktree", "add", "--detach", worktree, job.GitRef); err != nil {
		return "", "", nil, err
	}
	commit, err := exec.CommandContext(ctx, "git", "-C", worktree, "rev-parse", "HEAD").Output()
	if err != nil {
		return worktree, "", nil, fmt.Errorf("cannot resolve %s: %w", job.GitRef, err)
	}
	sha := strings.TrimSpace(string(commit))
	buf.add("commit " + sha)

	// 身份文件由服务端合成随任务下发，仓库里没有这份文件。代理仍然校验一遍——
	// 两端分属不同信任域（见 tenantfile.go）
	if _, err := writeTenantFile(worktree, job.TenantDirectory, job.TenantFile); err != nil {
		return worktree, sha, nil, err
	}
	buf.add(fmt.Sprintf("tenant %s written as %s (%d)", job.TenantDirectory, job.Version, job.BuildNumber))

	// 启动图标随任务下发，写进仓库约定的那个目录。热更新不打原生资源，但 app.config.ts
	// 求值时会读这些路径，少一张就整条失败在一句 ENOENT 上。
	written, err := fetchTenantIcons(ctx, api, job, worktree)
	if err != nil {
		return worktree, sha, nil, err
	}
	if written > 0 {
		buf.add(fmt.Sprintf("%d icons written from the tenant configuration", written))
	}
	// 图标在 prebuild 里才被读到，而那是 pnpm install 之后的事——少一个文件要等两
	// 分钟才报错，报的还是一句 ENOENT 加一串 @expo 的栈。这里先看一眼。
	if missing := missingTenantIcons(worktree, job.TenantDirectory); len(missing) > 0 {
		return worktree, sha, nil, fmt.Errorf("这个租户缺这几张启动图标：%s。"+
			"在控制台「Android 打包与签名 → 启动图标」上传，或者提交到 App 仓库的 assets/tenants/%s/ 下",
			strings.Join(missing, "、"), job.TenantDirectory)
	}

	// Firebase 配置也在这里写，两种任务都写。
	//
	// 路径必须是**相对**的。它会进到 expo config 的 android.googleServicesFile，而
	// 原生指纹把整份 expo config 算进去——写绝对路径的话，每个任务一个 worktree 就意味着
	// 每次构建一个不同的指纹，热更新永远和基线对不上（2026-09-13 实测：同一个提交在两个
	// 目录下算出两个哈希，差异就是这一项和它带出的 expoConfig）。
	//
	// 而且 OTA 那条也必须写：少了它 expo config 里 nativePushConfigured 会翻成 false，
	// 同样是一个不同的指纹。
	// 证书也在这里写，两种任务都写。
	//
	// 它是**真实的原生输入**（编进包里的 expo-updates 配置），所以它必然进指纹；而两条
	// 链路只要有一条不设它，算出来的就是两个指纹，热更新永远和基线对不上。2026-09-13
	// 实测：同一个 worktree 里只加这两个环境变量，哈希就变了。
	//
	// 与其在算指纹时把环境"洗干净"，不如让两条链路的环境**由同一段代码构造**——洗干净
	// 的那种做法，下一个人往 buildAPK 里加一个环境变量就又坏了，而且坏在很远的地方。
	extraEnv := []string{"EXPO_PUBLIC_TENANT=" + job.TenantDirectory}
	if strings.TrimSpace(job.OTACertificatePEM) == "" {
		return worktree, sha, nil, fmt.Errorf("tenant %s has no OTA signing key; install one before building a package that must verify updates", job.TenantSlug)
	}
	if err := os.WriteFile(filepath.Join(worktree, "ota-certificate.pem"), []byte(job.OTACertificatePEM), 0o644); err != nil {
		return worktree, sha, nil, err
	}
	extraEnv = append(extraEnv,
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=./ota-certificate.pem",
		"EXPO_REQUIRE_OTA_SIGNING=1",
	)
	if strings.TrimSpace(job.GoogleServicesJSON) != "" {
		decoded, err := base64.StdEncoding.DecodeString(job.GoogleServicesJSON)
		if err != nil {
			return worktree, sha, nil, fmt.Errorf("googleServicesJson is not base64: %w", err)
		}
		if err := os.WriteFile(filepath.Join(worktree, "google-services.json"), decoded, 0o644); err != nil {
			return worktree, sha, nil, err
		}
		extraEnv = append(extraEnv, "GOOGLE_SERVICES_JSON=./google-services.json")
		buf.add("google-services.json written from the tenant build configuration")
	}
	return worktree, sha, extraEnv, nil
}

func buildAPK(ctx context.Context, cfg config, api *client, job claimedJob, buf *logBuffer) (buildResult, error) {
	var result buildResult
	if job.Platform != "android" {
		return result, fmt.Errorf("this agent only builds android, got %q", job.Platform)
	}
	worktree, commitSHA, extraEnv, err := prepareWorktree(ctx, cfg, api, job, buf)
	if err != nil {
		return result, err
	}
	result.CommitSHA = commitSHA
	env := append(os.Environ(), extraEnv...)

	if err := run(ctx, buf, worktree, env, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return result, err
	}
	// 原生面指纹：随发布记录存下来，将来判断热更新能不能发给这个包。算不出来不致命。
	result.NativeFingerprint = nativeFingerprint(ctx, buf, worktree, env)
	// 现成的产物身份门禁在这条命令里面：权限清单、applicationId、签名指纹、
	// Gradle 依赖校验。代理不复制其中任何一条，也不绕过它们。
	if err := run(ctx, buf, worktree, env, "pnpm", "android:release", job.TenantDirectory); err != nil {
		return result, err
	}

	artifact := filepath.Join(worktree, "artifacts",
		fmt.Sprintf("%s-%s-build%d-release.apk", job.TenantDirectory, job.Version, job.BuildNumber))
	if _, err := os.Stat(artifact); err != nil {
		return result, fmt.Errorf("the build reported success but %s is not there: %w", filepath.Base(artifact), err)
	}
	result.ArtifactPath = artifact
	if err := verifyEmbeddedCertificate(artifact, job.OTACertificatePEM); err != nil {
		return result, err
	}
	buf.add("embedded OTA certificate matches " + job.OTACertificateSHA256)
	if result.SHA256, err = fileSHA256(artifact); err != nil {
		return result, err
	}
	buf.add("artifact sha256 " + result.SHA256)

	// SBOM 在 worktree 还在的时候生成：扫的是这次构建自己的 pnpm-lock.yaml，
	// 绑的是刚算出来的那个 sha256。
	if result.SBOMPath, err = generateSBOM(ctx, buf, worktree, job.TenantDirectory, artifact, env); err != nil {
		return result, err
	}
	return result, nil
}

// fetchTenantIcons 把服务端列出的图标一张一张取下来，写进 assets/tenants/<slug>/。
//
// 文件名由服务端给（约定的那四个），这里仍然挡一次路径逃逸：两端分属不同信任域，
// 各自把住自己那一侧。
func fetchTenantIcons(ctx context.Context, api *client, job claimedJob, worktree string) (int, error) {
	if len(job.Icons) == 0 {
		return 0, nil
	}
	dir := filepath.Join(worktree, "assets", "tenants", job.TenantDirectory)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create tenant asset directory: %w", err)
	}
	written := 0
	for _, name := range job.Icons {
		if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return written, fmt.Errorf("refusing an icon name that escapes the tenant directory: %q", name)
		}
		if err := api.downloadIcon(ctx, job.ID, name, filepath.Join(dir, name)); err != nil {
			return written, fmt.Errorf("cannot fetch icon %s: %w", name, err)
		}
		written++
	}
	return written, nil
}

// missingTenantIcons 返回 prebuild 会去读、而仓库里还没有的那几个图标。
//
// 文件名是约定（见服务端 tenantIcon），所以这里能提前判断。图标是唯一还留在 App
// 仓库里的按租户资源——tenant.json 和 google-services.json 都已经搬到服务端了。
func missingTenantIcons(worktree, directory string) []string {
	var missing []string
	for _, name := range []string{
		"icon.png",
		"android-icon-foreground.png",
		"android-icon-background.png",
		"android-icon-monochrome.png",
	} {
		path := filepath.Join(worktree, "assets", "tenants", directory, name)
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

func removeWorktree(cfg config, job claimedJob, buf *logBuffer) {
	worktree := filepath.Join(cfg.Workspace, job.ID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = run(ctx, buf, cfg.Workspace, os.Environ(), "git", "-C", cfg.Repo, "worktree", "remove", "--force", worktree)
	_ = os.RemoveAll(worktree)
}

// verifyEmbeddedCertificate 确认产物里真的编进了这个租户当前那张 OTA 证书。
//
// 这是"包里的证书"与"服务端当前签名用的密钥"之间最后一道扣子。扣错了的表现是
// 所有设备静默停在内置 bundle——设备上完全看不出来，只有服务端日志里有一条
// warning，而那时包已经发出去了。
//
// 做法是在 APK 里找证书 base64 正文的一段。expo-updates 运行时读的是
// AndroidManifest 的 expo.modules.updates.CODE_SIGNING_CERTIFICATE，而那个值可能
// 是字面量也可能是资源引用——与其解析两种形态，不如直接确认这串内容确实在包里。
func verifyEmbeddedCertificate(apkPath, certificatePEM string) error {
	needle := certificateNeedle(certificatePEM)
	if needle == "" {
		return errors.New("the job certificate is too short to check against the package")
	}
	archive, err := zip.OpenReader(apkPath)
	if err != nil {
		return fmt.Errorf("cannot read the built package: %w", err)
	}
	defer archive.Close()
	for _, entry := range archive.File {
		if entry.UncompressedSize64 > 64<<20 {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(reader, 64<<20))
		reader.Close()
		if err != nil {
			continue
		}
		// AndroidManifest.xml 的字符串池是 UTF-16LE，只按 UTF-8 找会一条都找不到
		// ——那样这道检查就成了恒假的断言，比没有更坏。2026-09-11 第一版就是这样，
		// 一个内容完全正确的包被判成"没编进证书"。
		if bytes.Contains(content, []byte(needle)) || bytes.Contains(content, utf16LE(needle)) {
			return nil
		}
	}
	return errors.New("the built package does not contain this tenant's OTA signing certificate: every device would silently refuse updates and stay on the embedded bundle")
}

// certificateNeedle 取证书 base64 正文中间一整行里的一段。整行取是因为 PEM 每 64
// 个字符换一次行，跨行取会因为换行符而找不到。
func certificateNeedle(certificatePEM string) string {
	lines := []string{}
	for _, line := range strings.Split(certificatePEM, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) < 3 {
		return ""
	}
	middle := lines[len(lines)/2]
	if len(middle) < 48 {
		return ""
	}
	return middle[:48]
}

// utf16LE 把 ASCII 串转成 Android 字符串池用的那种编码。证书正文是 base64，
// 全部落在 ASCII 范围内，所以每个字节后面补一个 0 就够了。
func utf16LE(text string) []byte {
	out := make([]byte, 0, len(text)*2)
	for i := 0; i < len(text); i++ {
		out = append(out, text[i], 0)
	}
	return out
}

// gitRefPattern 是我们愿意交给 git 的 ref 形状：分支名、标签、40 位 sha。
var gitRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$`)

func validateGitRef(ref string) error {
	if !gitRefPattern.MatchString(ref) {
		// 不回显整个值：它来自服务端，长度不受控
		return fmt.Errorf("refusing a git ref that is not a plain branch, tag or sha (%d bytes, starts with %q)",
			len(ref), firstRunes(ref, 8))
	}
	// `..` 在 ref 里是合法语法（a..b 是区间），但 worktree add 要的是单个
	// committish，而它同时也是路径穿越的形状
	if strings.Contains(ref, "..") {
		return fmt.Errorf("refusing a git ref containing '..'")
	}
	return nil
}

func firstRunes(value string, n int) string {
	runes := []rune(value)
	if len(runes) <= n {
		return string(runes)
	}
	return string(runes[:n]) + "…"
}
