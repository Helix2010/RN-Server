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
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
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
}

// buildJob 跑完一个任务的全部步骤。每一步失败都直接返回，调用方负责上报 fail
// 并清理 worktree。
func buildJob(ctx context.Context, cfg config, job claimedJob, buf *logBuffer) (buildResult, error) {
	var result buildResult
	if job.Platform != "android" {
		return result, fmt.Errorf("this agent only builds android, got %q", job.Platform)
	}
	if job.TenantDirectory == "" {
		return result, fmt.Errorf("the job does not say which tenants/ directory to build; set repoDirectory in this tenant's build configuration")
	}
	// 目录名会被拼进路径。服务端已经校验过，代理再挡一次——两端分属不同的信任域，
	// 各自把住自己那一侧是这类路径拼接的常规做法。
	if strings.ContainsAny(job.TenantDirectory, `/\`) || strings.Contains(job.TenantDirectory, "..") {
		return result, fmt.Errorf("refusing a tenant directory that escapes tenants/: %q", job.TenantDirectory)
	}
	worktree := filepath.Join(cfg.Workspace, job.ID)
	env := os.Environ()

	// 每个任务一个全新 worktree。共用检出会把别人未提交的改动混进产物。
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "fetch", "--all", "--prune"); err != nil {
		return result, err
	}
	if err := run(ctx, buf, cfg.Workspace, env, "git", "-C", cfg.Repo, "worktree", "add", "--detach", worktree, job.GitRef); err != nil {
		return result, err
	}
	commit, err := exec.CommandContext(ctx, "git", "-C", worktree, "rev-parse", "HEAD").Output()
	if err != nil {
		return result, fmt.Errorf("cannot resolve %s: %w", job.GitRef, err)
	}
	result.CommitSHA = strings.TrimSpace(string(commit))
	buf.add("commit " + result.CommitSHA)

	// 身份文件由服务端合成随任务下发，仓库里没有这份文件。代理仍然校验一遍——
	// 两端分属不同信任域（见 tenantfile.go）
	if _, err := writeTenantFile(worktree, job.TenantDirectory, job.TenantFile); err != nil {
		return result, err
	}
	buf.add(fmt.Sprintf("tenant %s written as %s (%d)", job.TenantDirectory, job.Version, job.BuildNumber))

	// 启动图标随任务下发，写进仓库约定的那个目录。服务端没下发的（老租户）就用
	// 仓库里已有的那一份，所以两种来源可以共存
	written, err := writeTenantIcons(worktree, job.TenantDirectory, job.Icons)
	if err != nil {
		return result, err
	}
	if written > 0 {
		buf.add(fmt.Sprintf("%d icons written from the tenant configuration", written))
	}
	// 图标在 prebuild 里才被读到，而那是 pnpm install 之后的事——少一个文件要等两
	// 分钟才报错，报的还是一句 ENOENT 加一串 @expo 的栈。这里先看一眼。
	if missing := missingTenantIcons(worktree, job.TenantDirectory); len(missing) > 0 {
		return result, fmt.Errorf("这个租户缺这几张启动图标：%s。"+
			"在控制台「Android 打包与签名 → 启动图标」上传，或者提交到 App 仓库的 assets/tenants/%s/ 下",
			strings.Join(missing, "、"), job.TenantDirectory)
	}

	// 证书随任务下发，代理不去猜该编哪一张
	if strings.TrimSpace(job.OTACertificatePEM) == "" {
		return result, fmt.Errorf("tenant %s has no OTA signing key; install one before building a package that must verify updates", job.TenantSlug)
	}
	certPath := filepath.Join(worktree, "ota-certificate.pem")
	if err := os.WriteFile(certPath, []byte(job.OTACertificatePEM), 0o644); err != nil {
		return result, err
	}
	env = append(env,
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=./ota-certificate.pem",
		"EXPO_REQUIRE_OTA_SIGNING=1",
		"EXPO_PUBLIC_TENANT="+job.TenantDirectory,
	)

	if strings.TrimSpace(job.GoogleServicesJSON) != "" {
		decoded, err := base64.StdEncoding.DecodeString(job.GoogleServicesJSON)
		if err != nil {
			return result, fmt.Errorf("googleServicesJson is not base64: %w", err)
		}
		googleServices := filepath.Join(worktree, "google-services.json")
		if err := os.WriteFile(googleServices, decoded, 0o644); err != nil {
			return result, err
		}
		env = append(env, "GOOGLE_SERVICES_JSON="+googleServices)
		buf.add("google-services.json written from the tenant build configuration")
	}

	// 签名密钥：服务端转交盒子，口令只在这台机器上。开出来写进任务工作区，
	// 0600，构建完随 worktree 一起删。
	keystorePath, keystoreEnv, secrets, err := unsealKeystore(cfg, job, worktree)
	if err != nil {
		return result, err
	}
	// 口令是运行时才知道的，必须登记进脱敏器；Gradle 失败时很乐意把命令行打出来
	for _, secret := range secrets {
		buf.red.add(secret)
	}
	buf.add("keystore unsealed to " + filepath.Base(keystorePath))
	env = append(env, keystoreEnv...)

	if err := run(ctx, buf, worktree, env, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return result, err
	}
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

// writeTenantIcons 把服务端下发的图标写进 assets/tenants/<slug>/。
//
// 文件名由服务端给（约定的那四个），这里仍然挡一次路径逃逸：两端分属不同信任域，
// 各自把住自己那一侧。
func writeTenantIcons(worktree, directory string, icons map[string]string) (int, error) {
	if len(icons) == 0 {
		return 0, nil
	}
	dir := filepath.Join(worktree, "assets", "tenants", directory)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create tenant asset directory: %w", err)
	}
	written := 0
	for name, encoded := range icons {
		if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
			return written, fmt.Errorf("refusing an icon name that escapes the tenant directory: %q", name)
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return written, fmt.Errorf("icon %s is not base64: %w", name, err)
		}
		if len(raw) == 0 {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0o644); err != nil {
			return written, fmt.Errorf("write icon %s: %w", name, err)
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

// openSealedKeystore 按盒子自己的格式选解法。
//
// v2 是加密给本机公钥的，用本机私钥解，没有人需要知道任何口令。v1 是旧格式，用
// 全机器共用的 BUILD_KEYSTORE_PASSPHRASE——留着只是为了让迁移之前存下的密钥继续
// 能构建，新写的盒子一律是 v2。
func openSealedKeystore(sealed buildkeystore.Sealed, cfg config) (buildkeystore.Bundle, error) {
	var bundle buildkeystore.Bundle
	if sealed.Version == 2 {
		bundle, err := buildkeystore.OpenWith(sealed, cfg.AgentPrivateKey)
		if err != nil {
			return bundle, fmt.Errorf("cannot open the sealed keystore: %w", err)
		}
		return bundle, nil
	}
	if strings.TrimSpace(cfg.KeystorePassphrase) == "" {
		return bundle, errors.New("this tenant's keystore is still in the old passphrase format, but BUILD_KEYSTORE_PASSPHRASE is not set on this build machine. Re-upload or regenerate the keystore from the console: new ones are encrypted to this machine's key and need no passphrase")
	}
	bundle, err := buildkeystore.Open(sealed, cfg.KeystorePassphrase)
	if err != nil {
		return bundle, fmt.Errorf("cannot open the sealed keystore: %w", err)
	}
	return bundle, nil
}

// unsealKeystore 把服务端转交的盒子在本机打开，落成一个只有构建期间存在的
// keystore 文件，并返回构建脚本要的那几个环境变量。
//
// 服务端只有本机的**公钥**，所以它转交的东西对它自己也是不可读的——这正是把签名
// 密钥放进数据库还能成立的原因。
func unsealKeystore(cfg config, job claimedJob, worktree string) (string, []string, []string, error) {
	if job.SealedKeystore == nil {
		return "", nil, nil, fmt.Errorf("tenant %s has no signing keystore configured; create one on the console page 「Android 打包与签名」 or run build-keystore create locally, before building", job.TenantSlug)
	}
	bundle, err := openSealedKeystore(*job.SealedKeystore, cfg)
	if err != nil {
		return "", nil, nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(bundle.KeystoreBase64)
	if err != nil || len(raw) == 0 {
		return "", nil, nil, errors.New("the sealed keystore does not contain a keystore")
	}
	path := filepath.Join(worktree, ".build-keystore.jks")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", nil, nil, err
	}
	alias := bundle.KeyAlias
	if strings.TrimSpace(job.KeyAlias) != "" {
		alias = job.KeyAlias
	}
	return path, []string{
		"ANDROID_RELEASE_KEYSTORE_PATH=" + path,
		// 变量名以 plugins/with-release-signing.js 的 RELEASE_SIGNING_ENV 为准，
		// 不是 keytool 的叫法：写错的表现是构建到最后一步才说"缺环境变量"
		"ANDROID_RELEASE_STORE_PASSWORD=" + bundle.StorePassword,
		"ANDROID_RELEASE_KEY_ALIAS=" + alias,
		"ANDROID_RELEASE_KEY_PASSWORD=" + bundle.KeyPassword,
	}, []string{bundle.StorePassword, bundle.KeyPassword}, nil
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
