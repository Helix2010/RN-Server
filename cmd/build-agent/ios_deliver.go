package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/internal/ipa"
)

// iOS 产物的身份核对与上传（设计 ios-mac-builders-home-network-2026-09-18 §4.3）。
//
// 控制进程在这里做两件事，顺序不能反：
//
//  1. **自己读一遍包**，确认它的 bundle id、版本、build 号就是这条任务要的那个。执行进程
//     跑的是第三方依赖，它交上来的东西按不可信处理——用 Go 的 archive/zip 与自带的 plist
//     解析器，不对这个文件调 unzip / plutil；
//  2. 核对通过之后，把包交给**另一个用户**上传。控制进程自己一把 App Store Connect Key
//     都没有，执行进程更没有——这是"签名材料在这台机器上没有出口"这条的最后一环。

const (
	// iosUploadTimeout：几百 MB 走家用上行，十几分钟是常态
	iosUploadTimeout = 90 * time.Minute
)

// ipaIdentity 是从 .ipa 里读出来的身份。读法与服务端核对自助上传的 .ipa 共用一份（internal/ipa）。
type ipaIdentity = ipa.Identity

// readIPAIdentity 从 .ipa 里读 Payload/<App>.app/Info.plist（只认主 App，不认扩展）。
var readIPAIdentity = ipa.ReadIdentity

// checkIPAMatchesJob 把包里读出来的身份与任务行比一遍。
//
// 服务端在 /ios-release 还会按它自己那份记录再比一次——两侧分属不同的信任域，各自
// 按自己手里的记录把一次。这一次比的意义在于**上传之前**：包一旦进了 App Store Connect
// 就撤不回来，只能再出一个 build 号顶掉它。
func checkIPAMatchesJob(identity ipaIdentity, job claimedJob) error {
	mismatches := []string{}
	if !strings.EqualFold(identity.BundleID, job.BundleID()) {
		mismatches = append(mismatches, fmt.Sprintf("bundle id %q, expected %q", identity.BundleID, job.BundleID()))
	}
	if identity.ShortVersion != job.Version {
		mismatches = append(mismatches, fmt.Sprintf("version %q, expected %q", identity.ShortVersion, job.Version))
	}
	if identity.BuildNumber != strconv.Itoa(job.BuildNumber) {
		mismatches = append(mismatches, fmt.Sprintf("build number %q, expected %d", identity.BuildNumber, job.BuildNumber))
	}
	if len(mismatches) > 0 {
		return errors.New("the package the build runner handed over is not this job's: " + strings.Join(mismatches, "; "))
	}
	return nil
}

// uploadOutcome 是上传程序的一行 JSON 结果。
type uploadOutcome struct {
	// Uploaded：App Store Connect 上现在有这个 build（这次传的，或上一次尝试传的）
	Uploaded bool `json:"uploaded"`
	// UploadedByEarlierAttempt：这次没传，因为同一个 build 号已经在那边了。任务被回收
	// 重排后 build 号不变，上一次尝试可能已经传完只是没报上来（设计 §6.3）
	UploadedByEarlierAttempt bool `json:"uploadedByEarlierAttempt"`
	// Detail 是给人看的一句话，进任务日志
	Detail string `json:"detail"`
	// Probe 只在 --probe 时有值：ok / forbidden / error
	Probe string `json:"probe"`
}

// uploadIPA 把包交给上传账户。
//
// **包走标准输入，不是路径**（与设计 §4.3 第 2 步写的 `--ipa <路径>` 不同）：产物的副本
// 在控制进程的 spool 里，而 spool 在状态目录下——那里还放着出处私钥，目录是 0700。
// 给另一个账户开一条能读到那棵树的路，等于为了传一个不是机密的包，放宽了一个装着机密的
// 目录。上传程序自己把标准输入落到它自己的临时文件里。
func (a *agent) uploadIPA(ctx context.Context, job claimedJob, ipaPath string, identity ipaIdentity, buf *logBuffer) (uploadOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, iosUploadTimeout)
	defer cancel()
	file, err := os.Open(ipaPath)
	if err != nil {
		return uploadOutcome{}, err
	}
	defer file.Close()
	args := []string{
		"--team", job.AppleTeamID(),
		"--keys", a.cfg.IOSUploadKeys,
		"--expect-bundle-id", identity.BundleID,
		"--expect-version", identity.ShortVersion,
		"--expect-build", identity.BuildNumber,
	}
	cmd := a.uploaderCommand(ctx, args...)
	cmd.Stdin = file
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	// 上传程序的 stderr 是进度与错误，进任务日志；它不碰任何机密（Key 只有它自己读得到，
	// 而它不打印 Key）
	for _, line := range strings.Split(strings.TrimSpace(stderr.String()), "\n") {
		if line != "" {
			buf.add("ios-upload: " + line)
		}
	}
	if err != nil {
		return uploadOutcome{}, fmt.Errorf("the upload account could not upload this build: %w: %s",
			err, firstRunes(strings.TrimSpace(stderr.String()), 300))
	}
	var outcome uploadOutcome
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&outcome) != nil {
		return uploadOutcome{}, fmt.Errorf("the upload account printed something that is not an upload result: %s",
			firstRunes(strings.TrimSpace(stdout.String()), 200))
	}
	if !outcome.Uploaded {
		return outcome, fmt.Errorf("the upload did not happen: %s", firstRunes(outcome.Detail, 300))
	}
	return outcome, nil
}

// probeUploadKey 问上传程序"这把 Key 能不能用这套端点"（只读，不传任何东西）。
// 启动时每个 Team 各跑一次，结果随认领自报上去——好让"角色不够传不上去"在**第一次构建
// 之前**就看得见，而不是在一次构建的最后一步。
func (a *agent) probeUploadKey(ctx context.Context, teamID string, bundleIDs []string) string {
	if !a.cfg.IOSUpload || len(bundleIDs) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	// 探一个 App 就够了：这把 Key 的角色对这个 Team 下的每个 App 都一样（团队密钥没有
	// App 范围，§4.3a）
	cmd := a.uploaderCommand(ctx, "--probe", "--team", teamID, "--keys", a.cfg.IOSUploadKeys,
		"--expect-bundle-id", bundleIDs[0])
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "error"
	}
	var outcome uploadOutcome
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&outcome) != nil {
		return "error"
	}
	switch outcome.Probe {
	case "ok", "forbidden", "error":
		return outcome.Probe
	}
	return "error"
}

// uploadKeyTeams 问上传账户"哪些 Team 装好了上传 Key"。
//
// 控制进程自己看不到：上传区是 0700 _rnuploader，它连目录都 stat 不了。自己去读只会得到
// EACCES，而那条错与"确实没装 Key"长得一模一样——表现是开着上传的机器一个 Team 都报不
// 出来，控制台上永远"缺材料"（2026-09-20 真机）。与签名区那次同一个解法：由持有它的账户
// 交出原文，判断仍留在这一侧。
func (a *agent) uploadKeyTeams(ctx context.Context) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := a.uploaderCommand(ctx, "--list-keys", "--keys", a.cfg.IOSUploadKeys)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s --list-keys: %w: %s", a.cfg.IOSUploader, err,
			truncate(strings.TrimSpace(stderr.String()), 200))
	}
	var answer struct {
		Teams []string `json:"teams"`
	}
	decoder := json.NewDecoder(strings.NewReader(stdout.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&answer); err != nil {
		return nil, fmt.Errorf("the upload program did not answer with JSON: %w", err)
	}
	teams := map[string]bool{}
	for _, team := range answer.Teams {
		teams[team] = true
	}
	return teams, nil
}

// uploaderCommand 构造上传程序的调用：经 sudo 切到上传账户，环境只给 PATH 与 LANG。
// 与执行进程同一条路子——上传账户持有能传 build 的 Key，它不该看到本机令牌。
//
// 代理走**参数**（--proxy / --no-proxy），不走环境：sudoers 对上传程序是 NOSETENV，
// 环境变量进不去（2026-09-23 真机：上传直连 App Store Connect，TCP 超时）。
func (a *agent) uploaderCommand(ctx context.Context, args ...string) *exec.Cmd {
	args = append(a.cfg.Proxy.Args(), args...)
	env := []string{"PATH=" + a.cfg.MachineEnv["PATH"], "LANG=C"}
	if a.cfg.RunnerUser == directRunner {
		// 本地测试：不经 sudo。生产里 BUILD_AGENT_RUNNER_USER=- 已经在启动时大声告警过
		cmd := exec.CommandContext(ctx, a.cfg.IOSUploader, args...)
		cmd.Env = env
		return cmd
	}
	sudo := append([]string{"-n", "-u", a.cfg.IOSUploadUser, a.cfg.IOSUploader}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", sudo...)
	cmd.Env = env
	// 任务被取消或超时时请它停下，而不是用 exec 默认的 SIGKILL：SIGKILL 只杀得到 sudo，
	// 上传程序成了孤儿，会把包照样传完——一个已经取消的任务在 TestFlight 上多出一个 build。
	// SIGTERM 由 sudo 转发给上传程序（Go 程序收到它默认就退出），与执行进程同一个做法（runnerexec.go）
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = runnerStopGrace
	return cmd
}
