package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// job 是一次构建里执行进程要用到的全部东西。
type job struct {
	out    io.Writer
	layout jobspec.Layout
	spec   jobspec.Spec
}

func build(ctx context.Context, out io.Writer, who identity, flags runnerFlags) error {
	layout, err := checkJobDir(who, flags.root, flags.job, true)
	if err != nil {
		return usageError{err}
	}
	spec, err := readSpec(layout, flags.kind)
	if err != nil {
		return usageError{fmt.Errorf("spec.json refused: %w", err)}
	}
	if !who.separated {
		fmt.Fprintln(out, "build-runner: WARNING running as the same user as the controller; this is only for local testing")
	}
	// 上一个任务留下的进程与临时文件先清掉，再开始执行任何第三方代码
	reap(who)
	if err := ensureEmpty(layout.Work(), "work/"); err != nil {
		return usageError{err}
	}
	if err := ensureEmpty(layout.Out(), "out/"); err != nil {
		return usageError{err}
	}
	for _, dir := range []string{layout.Home(), layout.GradleUserHome(), layout.PnpmStore(), layout.Tmp()} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
	}
	logf(out, "copying the checkout %s into the job's own work tree", shortCommit(spec.CommitSHA))
	if err := copyTree(layout.Src(), layout.App()); err != nil {
		return fmt.Errorf("cannot copy the checkout: %w", err)
	}
	j := job{out: out, layout: layout, spec: spec}
	switch spec.Kind {
	case jobspec.KindAPK:
		if spec.Platform == jobspec.PlatformIOS {
			return j.buildIPA(ctx)
		}
		return j.buildAPK(ctx)
	case jobspec.KindOTA:
		return j.buildOTA(ctx)
	}
	return usagef("unknown kind")
}

func cleanup(out io.Writer, who identity, layout jobspec.Layout) error {
	reap(who)
	var first error
	for _, dir := range []string{layout.Work(), layout.Out()} {
		if err := emptyDir(dir); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return fmt.Errorf("cleanup left files behind: %w", first)
	}
	logf(out, "job directory emptied")
	return nil
}

func (j job) buildAPK(ctx context.Context) error {
	app := j.layout.App()
	if err := j.run(ctx, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return err
	}
	// 原生指纹：签名闸会从包里再读一次核对，发布记录用签名闸读出的值。出处声明要求它
	// 有值，所以算不出来就让安装包任务失败。
	fingerprint, err := j.nativeFingerprint(ctx)
	if err != nil {
		return err
	}
	if err := j.run(ctx, "pnpm", "android:release", j.spec.TenantDirectory); err != nil {
		return err
	}
	name := jobspec.ArtifactName(j.spec.TenantDirectory, j.spec.AppVersion, j.spec.BuildNumber)
	artifact := filepath.Join(app, "artifacts", name)
	if info, err := os.Lstat(artifact); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("the build reported success but artifacts/%s is not there", name)
	}
	certificate, err := os.ReadFile(filepath.Join(app, jobspec.OTACertificateRelPath))
	if err != nil {
		return fmt.Errorf("cannot read the OTA certificate written for this job: %w", err)
	}
	if err := verifyEmbeddedCertificate(artifact, string(certificate)); err != nil {
		return err
	}
	logf(j.out, "embedded OTA certificate found in %s", name)
	sbom := strings.TrimSuffix(artifact, ".apk") + "-sbom.cdx.json"
	script := filepath.Join(app, "scripts", "build-sbom.mjs")
	if info, err := os.Lstat(script); err != nil || !info.Mode().IsRegular() {
		return errors.New("this checkout has no scripts/build-sbom.mjs, so no SBOM can be produced")
	}
	if err := j.run(ctx, "node", script,
		"--root", app, "--tenant", j.spec.TenantDirectory, "--apk", artifact, "--out", sbom); err != nil {
		return fmt.Errorf("SBOM generation failed (is syft installed on the build machine?): %w", err)
	}
	if err := copyFile(artifact, j.layout.OutFile(jobspec.UnsignedFileName), 0o640); err != nil {
		return fmt.Errorf("cannot hand over the unsigned package: %w", err)
	}
	if err := copyFile(sbom, j.layout.OutFile(jobspec.SBOMFileName), 0o640); err != nil {
		return fmt.Errorf("cannot hand over the SBOM: %w", err)
	}
	return j.writeResult(jobspec.Result{Version: jobspec.ResultVersion, Kind: jobspec.KindAPK, NativeFingerprint: fingerprint})
}

// buildIPA 出一个 iOS 安装包。
//
// 与 buildAPK 的三点不同，都来自"iOS 的签名与构建分不开"（设计 ios-testflight §4.2）：
// 产物是**已签名**的（xcodebuild -exportArchive 那一刻签名就发生了）、没有 SBOM 交给
// 签名闸复核、也不算原生指纹（那是签名闸复核未签名包用的）。
//
// 门禁在 RN-App 的 scripts/build-ios-release.mjs 里：bundle id、版本、CFBundleVersion、
// 内嵌 extra.buildNumber、OTA 请求头、权限文案、applinks entitlement 逐条核对。
// 这里只负责跑它、确认产物在、交回去。
//
// **第一台 Mac 上大概率先撞这一条**：子进程的 HOME 被改成了这次任务自己的目录
// （jobspec.jobPathEnv，为的是 Gradle / pnpm 的缓存隔离），而 macOS 的签名身份在
// **登录钥匙串**里，路径是 $HOME/Library/Keychains——HOME 一换，codesign 就找不到
// 证书。这条在 Linux 上验不出来，所以没有先写一个没跑过的修法。真机上按这个顺序试：
// 先把签名身份导进一个独立钥匙串并在机器安装时 `security list-keychains` 加进搜索
// 列表（隔离仍然成立），不行再考虑 iOS 任务不改写 HOME。
func (j job) buildIPA(ctx context.Context) error {
	app := j.layout.App()
	if err := j.run(ctx, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return err
	}
	args := []string{"ios:release", j.spec.TenantDirectory}
	if j.spec.IOSUpload {
		args = append(args, "--upload")
	}
	if err := j.run(ctx, "pnpm", args...); err != nil {
		return err
	}
	name := jobspec.IPAArtifactName(j.spec.TenantDirectory, j.spec.AppVersion, j.spec.BuildNumber)
	artifact := filepath.Join(app, "artifacts", name)
	if info, err := os.Lstat(artifact); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("the build reported success but artifacts/%s is not there", name)
	}
	if err := copyFile(artifact, j.layout.OutFile(jobspec.IPAFileName), 0o640); err != nil {
		return fmt.Errorf("cannot hand over the iOS package: %w", err)
	}
	// 报的是"这次有没有要求上传"，而它等于"有没有传成功"：上传失败的话上面那条
	// pnpm 会非零退出，整个任务已经判失败，走不到这里
	return j.writeResult(jobspec.Result{
		Version: jobspec.ResultVersion, Kind: jobspec.KindAPK,
		UploadedToAppStoreConnect: j.spec.IOSUpload,
	})
}

func (j job) buildOTA(ctx context.Context) error {
	app := j.layout.App()
	if err := j.run(ctx, "pnpm", "install", "--frozen-lockfile"); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(app, "artifacts"), 0o750); err != nil {
		return err
	}
	zipPath := filepath.Join(app, "artifacts", fmt.Sprintf("ota-%s-%s.zip", j.spec.TenantDirectory, j.spec.JobID))
	o := j.spec.OTA
	// runtimeVersion 显式给基线那一版；--allow-dirty 是必需的：身份文件和图标是任务下发后
	// 写进检出的，检出必然是"脏"的，而脏的不是代码。
	if err := j.run(ctx, "pnpm", "ota:build",
		"--platform", "android",
		"--channel", o.Channel,
		"--distribution-channel", "direct",
		"--api-base-url", o.APIBaseURL,
		"--apply-strategy", o.ApplyStrategy,
		"--runtime-version", o.RuntimeVersion,
		"--application-id", o.ApplicationID,
		"--output-zip", zipPath,
		"--allow-dirty", "true",
	); err != nil {
		return err
	}
	if info, err := os.Lstat(zipPath); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("the OTA build reported success but %s is not there", filepath.Base(zipPath))
	}
	if err := copyFile(zipPath, j.layout.OutFile(jobspec.OTAFileName), 0o640); err != nil {
		return fmt.Errorf("cannot hand over the OTA package: %w", err)
	}
	return j.writeResult(jobspec.Result{Version: jobspec.ResultVersion, Kind: jobspec.KindOTA})
}

func (j job) writeResult(result jobspec.Result) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tmp := j.layout.OutFile(jobspec.ResultFileName + ".tmp")
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, j.layout.OutFile(jobspec.ResultFileName)); err != nil {
		return err
	}
	logf(j.out, "outputs handed over")
	return nil
}

// nativeFingerprint 算这次检出的"原生面"指纹（@expo/fingerprint）。
func (j job) nativeFingerprint(ctx context.Context) (string, error) {
	var stdout bytes.Buffer
	cmd, err := j.command(ctx, "pnpm", "exec", "fingerprint", ".")
	if err != nil {
		return "", err
	}
	cmd.Stdout = &limitedWriter{w: &stdout, left: 1 << 20}
	if err := j.wait(cmd, "pnpm exec fingerprint ."); err != nil {
		return "", fmt.Errorf("native fingerprint unavailable: %w", err)
	}
	var parsed struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return "", errors.New("native fingerprint unavailable: the tool printed no JSON")
	}
	hash := strings.TrimSpace(parsed.Hash)
	if !jobspec.ValidNativeFingerprint(hash) {
		return "", errors.New("native fingerprint unavailable: the tool printed no usable hash")
	}
	logf(j.out, "native fingerprint %s", hash)
	return hash, nil
}

// run 执行一条命令，输出直接进标准输出（控制进程读它当日志）。
func (j job) run(ctx context.Context, name string, args ...string) error {
	cmd, err := j.command(ctx, name, args...)
	if err != nil {
		return err
	}
	cmd.Stdout = j.out
	return j.wait(cmd, name+" "+strings.Join(args, " "))
}

// command 构造子进程：可执行文件按任务环境里的 PATH 找（不是本进程的 PATH），环境只用
// 任务说明里的白名单，独立进程组，取消时杀整组——Gradle 会拉起常驻 daemon。
func (j job) command(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := lookPath(name, jobspec.EnvValue(j.spec.Env, "PATH"))
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = j.layout.App()
	cmd.Env = append([]string(nil), j.spec.Env...)
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	return cmd, nil
}

func (j job) wait(cmd *exec.Cmd, display string) error {
	logf(j.out, "$ %s", display)
	if cmd.Stderr == nil {
		cmd.Stderr = j.out
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s could not start: %w", filepath.Base(cmd.Path), err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%s failed: %w", filepath.Base(cmd.Path), err)
	}
	return nil
}

// lookPath 在给定的 PATH 里找可执行文件。os/exec 的 LookPath 用的是本进程环境，而本进程
// 环境来自 sudo，不是任务白名单。
func lookPath(name, pathList string) (string, error) {
	if strings.Contains(name, "/") {
		return "", fmt.Errorf("refusing a command with a path: %s", name)
	}
	for _, dir := range strings.Split(pathList, ":") {
		if !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf("%s is not on the job PATH", name)
}

type limitedWriter struct {
	w    io.Writer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		return 0, errors.New("output too large")
	}
	l.left -= len(p)
	return l.w.Write(p)
}

func logf(out io.Writer, format string, args ...any) {
	fmt.Fprintf(out, "build-runner: "+format+"\n", args...)
}

func shortCommit(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// verifyEmbeddedCertificate 确认产物里真的编进了这个租户当前那张 OTA 证书。这是早期反馈：
// 签名闸会从包里独立读出证书指纹核对。
//
// 做法是在 APK 里找证书 base64 正文的一段。expo-updates 运行时读的是 AndroidManifest 的
// expo.modules.updates.CODE_SIGNING_CERTIFICATE，而那个值可能是字面量也可能是资源引用——
// 与其解析两种形态，不如直接确认这串内容确实在包里。
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
		// ——那样这道检查就成了恒假的断言，比没有更坏。
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

// utf16LE 把 ASCII 串转成 Android 字符串池用的那种编码。
func utf16LE(text string) []byte {
	out := make([]byte, 0, len(text)*2)
	for i := 0; i < len(text); i++ {
		out = append(out, text[i], 0)
	}
	return out
}
