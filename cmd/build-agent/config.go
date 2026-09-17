package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// 配置全部来自**构建机本地**，只放启动项与这台机器的拓扑。服务端下发的只有任务本身——
// 它说不出仓库在哪、状态目录在哪、执行进程是谁。
type config struct {
	Server string
	// MachineToken 是控制台新建机器时发的本机令牌（请求头 x-machine-token）。
	// 它只在控制进程里：执行进程的环境是白名单构造的，不含它。
	MachineToken string
	Repo         string
	// Workspace 是任务根目录：每个任务一个 <Workspace>/<jobId>/，执行进程能进（组 rn-build-jobs），
	// 控制进程的状态目录不在它下面。
	Workspace string
	// StateDir 放 Ed25519 出处密钥与上传前的产物副本，只有控制进程用户能读（0700）。
	StateDir  string
	Platforms []string
	// IOSUpload：构建完之后把 .ipa 传进 App Store Connect。默认关。
	IOSUpload bool
	Timeout   time.Duration
	PollEvery time.Duration
	// Runner 是执行进程二进制的绝对路径；RunnerUser 是经 sudo 切换到的用户。
	// RunnerUser 为 "-" 表示不经 sudo 直接执行——执行进程与控制进程同一个用户，只用于本地测试。
	Runner     string
	RunnerUser string
	// MachineEnv 是交给执行进程的机器级变量（PATH、JAVA_HOME 等），只取 jobspec 白名单里的键。
	MachineEnv map[string]string
	// SSHKey 是 GitHub 只读 deploy key 的私钥；KnownHosts 是 root 所有、控制进程改不了的固定
	// known_hosts（install.sh 装到 /opt/rn-build-agent/github_known_hosts）。控制进程 fetch 仓库镜像时
	// 只用这两个文件，不读 ~/.ssh/config、~/.ssh/known_hosts（见 checkout.go gitEnv）。
	SSHKey     string
	KnownHosts string
	// MirrorProtocol 是 fetch 仓库镜像时唯一放行的传输协议。生产是 ssh（默认），
	// 只有本机测试用的假镜像（remote.origin.url 是本地路径）才设成 file，启动时会告警。
	MirrorProtocol string
}

const (
	defaultSSHKey     = "/var/lib/rn-build-agent/.ssh/id_ed25519"
	defaultKnownHosts = "/opt/rn-build-agent/github_known_hosts"
)

// directRunner 是 BUILD_AGENT_RUNNER_USER 的特殊值：不经 sudo。
const directRunner = "-"

func (c config) runnerSeparated() bool { return c.RunnerUser != directRunner }

var (
	machineTokenPattern = regexp.MustCompile(`^rnm_[A-Za-z0-9_-]{43}$`)
	unixUserPattern     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// shellSafePathPattern：这些路径会拼进 GIT_SSH_COMMAND（git 经 sh -c 执行它），只许不需要引号的字符
	shellSafePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

func containsPlatform(platforms []string, want string) bool {
	for _, platform := range platforms {
		if platform == want {
			return true
		}
	}
	return false
}

// iosUploadEnabled 只认明确的真值。写错的开关按关处理：多出一个没传上去的包，
// 比在没人预期的时候往 App Store Connect 推一个包好收场。
func iosUploadEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadConfig() (config, error) {
	cfg := config{
		Server:         strings.TrimRight(envOr("BUILD_AGENT_SERVER", ""), "/"),
		MachineToken:   envOr("BUILD_AGENT_MACHINE_TOKEN", ""),
		Repo:           envOr("BUILD_AGENT_REPO", ""),
		Workspace:      envOr("BUILD_AGENT_WORKSPACE", ""),
		StateDir:       envOr("BUILD_AGENT_STATE_DIR", ""),
		PollEvery:      10 * time.Second,
		Runner:         envOr("BUILD_AGENT_RUNNER", "/opt/rn-build-agent/build-runner"),
		RunnerUser:     envOr("BUILD_AGENT_RUNNER_USER", "builder"),
		MachineEnv:     map[string]string{},
		SSHKey:         envOr("BUILD_AGENT_SSH_KEY", defaultSSHKey),
		KnownHosts:     envOr("BUILD_AGENT_SSH_KNOWN_HOSTS", defaultKnownHosts),
		MirrorProtocol: envOr("BUILD_AGENT_MIRROR_PROTOCOL", "ssh"),
	}
	// 作废的机密先挡：它们留在 env 文件里就是一份没人管的秘密
	if os.Getenv("BUILD_KEYSTORE_PASSPHRASE") != "" {
		return cfg, errors.New("BUILD_KEYSTORE_PASSPHRASE is no longer used: build machines never see signing keys; delete it from the env file")
	}
	if os.Getenv("BUILD_AGENT_TOKEN") != "" {
		return cfg, errors.New("BUILD_AGENT_TOKEN was replaced by BUILD_AGENT_MACHINE_TOKEN (a per-machine token created in the console); delete the old key from the env file")
	}
	for key, value := range map[string]string{
		"BUILD_AGENT_SERVER":        cfg.Server,
		"BUILD_AGENT_MACHINE_TOKEN": cfg.MachineToken,
		"BUILD_AGENT_REPO":          cfg.Repo,
		"BUILD_AGENT_WORKSPACE":     cfg.Workspace,
		"BUILD_AGENT_STATE_DIR":     cfg.StateDir,
	} {
		if value == "" {
			return cfg, fmt.Errorf("%s is required", key)
		}
	}
	// 不回显令牌：报错会进 journal
	if !machineTokenPattern.MatchString(cfg.MachineToken) {
		return cfg, fmt.Errorf("BUILD_AGENT_MACHINE_TOKEN must look like rnm_ followed by 43 base64url characters (got %d characters)", len(cfg.MachineToken))
	}
	// 生产里用 http 等于把令牌明文发出去
	if !strings.HasPrefix(cfg.Server, "https://") && !strings.HasPrefix(cfg.Server, "http://127.0.0.1") && !strings.HasPrefix(cfg.Server, "http://localhost") {
		return cfg, fmt.Errorf("BUILD_AGENT_SERVER must be https, except for a loopback address in development (got %q)", cfg.Server)
	}
	for key, value := range map[string]string{
		"BUILD_AGENT_REPO":      cfg.Repo,
		"BUILD_AGENT_WORKSPACE": cfg.Workspace,
		"BUILD_AGENT_STATE_DIR": cfg.StateDir,
		"BUILD_AGENT_RUNNER":    cfg.Runner,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return cfg, fmt.Errorf("%s must be a clean absolute path (got %q)", key, value)
		}
	}
	for key, value := range map[string]string{"BUILD_AGENT_SSH_KEY": cfg.SSHKey, "BUILD_AGENT_SSH_KNOWN_HOSTS": cfg.KnownHosts} {
		if filepath.Clean(value) != value || !shellSafePathPattern.MatchString(value) {
			return cfg, fmt.Errorf("%s must be a clean absolute path of letters, digits and ._-/ (got %q)", key, value)
		}
	}
	if cfg.MirrorProtocol != "ssh" && cfg.MirrorProtocol != "file" {
		return cfg, fmt.Errorf("BUILD_AGENT_MIRROR_PROTOCOL must be ssh (production) or file (a local test mirror), got %q", cfg.MirrorProtocol)
	}
	if err := jobspec.ValidRoot(cfg.Workspace); err != nil {
		return cfg, fmt.Errorf("BUILD_AGENT_WORKSPACE: %w", err)
	}
	// 状态目录与任务根目录互不包含：执行进程能进任务根目录，出处密钥绝不能在它下面
	for _, pair := range [][2]string{
		{cfg.StateDir, cfg.Workspace}, {cfg.Workspace, cfg.StateDir}, {cfg.Repo, cfg.Workspace}, {cfg.Workspace, cfg.Repo},
	} {
		if within(pair[0], pair[1]) {
			return cfg, fmt.Errorf("BUILD_AGENT_STATE_DIR, BUILD_AGENT_REPO and BUILD_AGENT_WORKSPACE must not contain one another (%s is inside %s)", pair[0], pair[1])
		}
	}
	if cfg.RunnerUser != directRunner && !unixUserPattern.MatchString(cfg.RunnerUser) {
		return cfg, fmt.Errorf("BUILD_AGENT_RUNNER_USER must be a user name, or - for local testing without sudo (got %q)", cfg.RunnerUser)
	}

	// 自报的平台只能**收窄**登记里的能力：服务端认领时与 build.machines 求交集，
	// 这里写了 ios 而机器没被登记成能构建 iOS，那条任务照样不会派过来。
	for _, p := range strings.Split(envOr("BUILD_AGENT_PLATFORMS", "android"), ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		switch p {
		case jobspec.PlatformAndroid, jobspec.PlatformIOS:
			cfg.Platforms = append(cfg.Platforms, p)
		case "":
		default:
			return cfg, fmt.Errorf("BUILD_AGENT_PLATFORMS must name android and/or ios (got %q)", p)
		}
	}
	if len(cfg.Platforms) == 0 {
		return cfg, errors.New("BUILD_AGENT_PLATFORMS must name android and/or ios")
	}
	// iOS 只能在 macOS 上构建。让它在启动时就说清楚，而不是领到任务、检出完仓库、
	// 装完依赖，才在 xcodebuild 那一步失败——那时这条任务已经占了这台机器十几分钟
	if containsPlatform(cfg.Platforms, jobspec.PlatformIOS) && runtime.GOOS != "darwin" {
		return cfg, fmt.Errorf("BUILD_AGENT_PLATFORMS names ios but this machine runs %s; iOS packages need macOS with Xcode", runtime.GOOS)
	}
	// 上传 TestFlight 是一个对外可见的动作，所以由装这台机器的人显式打开，
	// 不由"排了一条 iOS 任务"隐含决定。关着时照样出包，只是停在这台机器上。
	cfg.IOSUpload = iosUploadEnabled(envOr("BUILD_AGENT_IOS_UPLOAD", ""))
	raw := envOr("BUILD_AGENT_TIMEOUT_MINUTES", "45")
	minutes, err := strconv.Atoi(raw)
	if err != nil || minutes < 1 || minutes > 480 {
		return cfg, fmt.Errorf("BUILD_AGENT_TIMEOUT_MINUTES must be between 1 and 480 (got %q)", raw)
	}
	cfg.Timeout = time.Duration(minutes) * time.Minute

	// 机器级工具变量：只取白名单里的，逐个校验。执行进程还会再校验一次。
	for _, key := range jobspec.MachineEnvKeys() {
		if value := os.Getenv(key); value != "" {
			cfg.MachineEnv[key] = value
		}
	}
	if cfg.MachineEnv["PATH"] == "" {
		return cfg, errors.New("PATH is required: it is handed to the build runner so it can find node, pnpm and java")
	}
	if cache := cfg.MachineEnv["GRADLE_RO_DEP_CACHE"]; cache != "" {
		if err := checkReadOnlyCache(cache); err != nil {
			return cfg, fmt.Errorf("GRADLE_RO_DEP_CACHE: %w", err)
		}
	}
	return cfg, nil
}

// within 判断 path 是否等于 parent 或在 parent 之下。
func within(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// checkReadOnlyCache 校验交给执行进程的只读 Gradle 依赖缓存：真实目录、属于控制进程用户、
// 组和其他人不可写。执行进程能改写它，就等于能给之后每个任务的依赖下毒。
func checkReadOnlyCache(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("must be a clean absolute path (got %q)", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must belong to the build agent user", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be writable by group or others", path)
	}
	return nil
}
