// build-agent 是构建机上的构建控制进程，以 rn-build-agent 用户常驻。
//
// 它持有本机令牌（BUILD_AGENT_MACHINE_TOKEN）、Ed25519 出处签名密钥和仓库裸库；
// 第三方代码（pnpm、Gradle、依赖包）只在构建执行进程 build-runner 里跑，那是经一条
// 收窄的 sudoers 规则启动的另一个用户（builder），拿不到令牌和密钥。构建机手上没有任何
// 签名密钥：它交付未签名包、SBOM 和出处声明，正式签名由签名闸做。
//
// 它只出不进：轮询服务端要任务，服务端从不连它，这台机器因此不开放任何入站端口。
//
// 子命令：
//
//	build-agent                 常驻（配置来自环境变量；配置不全以退出码 2 退出，机器被吊销以 77 退出）
//	build-agent show-key        只读打印出处公钥 base64 与完整 sha256
//	build-agent rotate-key      生成下一把出处密钥，常驻进程用当前密钥签换钥证明登记它
//	build-agent enroll          新机器用一次性注册码换机器令牌，令牌直接写进 env 文件（install.sh 以 root 调用）
//
// 设计见 docs/design/android-signing-gate-2026-09-16.md「构建机」。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// exitMachineRevoked 是机器被吊销时的退出码（EX_NOPERM）。不能是 2：2 是"配置不全"，
// rn-foundation-apply 的冒烟靠它。unit 用 RestartPreventExitStatus 阻止对它重启。
const exitMachineRevoked = 77

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "show-key":
			os.Exit(showKey(os.Args[2:], os.Stdout, os.Stderr))
		case "rotate-key":
			os.Exit(rotateKey(os.Args[2:], os.Stdout, os.Stderr))
		case "enroll":
			os.Exit(enroll(os.Args[2:], os.Stdout, os.Stderr))
		default:
			fmt.Fprintln(os.Stderr, "usage: build-agent [show-key|rotate-key|enroll] (configuration comes from the environment)")
			os.Exit(2)
		}
	}
	os.Exit(runAgent())
}

func runAgent() int {
	// 冒烟（rn-foundation-apply）以空环境跑它，必须在碰任何文件之前以 2 退出
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("build agent configuration is incomplete", "error", err)
		return 2
	}
	syscall.Umask(0o027)
	keys, err := loadOrCreateKeyring(cfg.StateDir)
	if err != nil {
		slog.Error("cannot load this machine's provenance key", "stateDir", cfg.StateDir, "error", err)
		return 2
	}
	if err := os.MkdirAll(cfg.Workspace, 0o750); err != nil {
		slog.Error("cannot create the jobs root", "path", cfg.Workspace, "error", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := newAgent(cfg, keys)
	if !cfg.runnerSeparated() {
		slog.Warn("!!! BUILD_AGENT_RUNNER_USER is '-': the build runner runs as the SAME user as the build agent, " +
			"so third-party build code can read the machine token and the provenance key. LOCAL TESTING ONLY, NEVER IN PRODUCTION !!!")
	}
	if err := recordRunnerMode(cfg.StateDir, cfg, time.Now()); err != nil {
		slog.Error("cannot record the runner mode for show-key", "stateDir", cfg.StateDir, "error", err)
		return 2
	}
	if err := a.checkRunner(ctx); err != nil {
		slog.Error("the build runner is not usable", "runner", cfg.Runner, "runnerUser", cfg.RunnerUser, "error", err)
		return 2
	}
	// 停机信号只用来"不再领新活"，正在跑的构建不打断
	go func() {
		<-ctx.Done()
		slog.Info("stop requested: not claiming any more builds; the one in flight will finish")
	}()

	// 上一条命留下的任务目录：硬杀时收尾那一步执行不到。这一刻手上没有任务，凡是在任务根目录里的都是孤儿。
	a.pruneOrphans()

	// 仓库镜像与固定 known_hosts 每个任务 fetch 之前都会核对；启动时先核对一次，升级后看日志就知道，
	// 不用等第一个任务失败。不合规不退出：镜像还没克隆（新机器 deploy key 没加到 GitHub）时也要能登记公钥。
	if err := a.checkKnownHosts(); err != nil {
		slog.Error("builds will fail until this is fixed", "error", err)
	}
	if _, err := os.Lstat(cfg.Repo); err == nil {
		if err := a.checkMirror(ctx); err != nil {
			slog.Error("builds will fail until this is fixed", "error", err)
		}
	}

	slog.Info("build agent started", "server", cfg.Server, "platforms", cfg.Platforms,
		"jobsRoot", cfg.Workspace, "runner", cfg.Runner, "runnerUser", cfg.RunnerUser,
		"runnerSeparated", cfg.runnerSeparated(), "provenancePublicKeySha256", keys.current.sha256)

	return a.serve(ctx)
}

// stateDirFlag 取 --state-dir，没有就用 BUILD_AGENT_STATE_DIR。
func stateDirFlag(name string, args []string, stderr io.Writer) (string, bool) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(stderr)
	dir := set.String("state-dir", os.Getenv("BUILD_AGENT_STATE_DIR"), "the build agent state directory")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return "", false
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "give --state-dir or set BUILD_AGENT_STATE_DIR")
		return "", false
	}
	return *dir, true
}

// showKey 只读打印这台构建机的出处公钥。**它绝不创建密钥**：运维拿它的输出去控制台接受、
// 去签名闸上 trust-builder，它自己造一把就等于让这次核对失去意义。
func showKey(args []string, stdout, stderr io.Writer) int {
	dir, ok := stateDirFlag("show-key", args, stderr)
	if !ok {
		return 2
	}
	ring, err := readKeyringReadOnly(dir)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "no provenance key in %s yet: start the build agent once (it creates the key), then run show-key again\n", dir)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the provenance key:", err)
		return 2
	}
	fmt.Fprintf(stdout, "provenance public key (ed25519, base64): %s\n", ring.current.publicBase64())
	fmt.Fprintf(stdout, "provenance public key sha256:            %s\n", ring.current.sha256)
	if ring.next != nil {
		fmt.Fprintf(stdout, "rotation key (ed25519, base64):          %s\n", ring.next.publicBase64())
		fmt.Fprintf(stdout, "rotation key sha256:                     %s\n", ring.next.sha256)
	}
	fmt.Fprintf(stdout, "build runner: %s\n", describeRunnerMode(dir))
	fmt.Fprintf(stdout, "state dir: %s\n", dir)
	return 0
}

// rotateKey 生成下一把出处密钥（已有就原样打印）。它不连服务端：常驻进程下一次登记时用
// 当前私钥签换钥证明把它登记上去，控制台接受之后换上。顺序是先在每台签名闸上
// trust-builder 新的 sha256，再在控制台接受——反过来的话，中间交付的包会被签名闸拒签。
func rotateKey(args []string, stdout, stderr io.Writer) int {
	dir, ok := stateDirFlag("rotate-key", args, stderr)
	if !ok {
		return 2
	}
	syscall.Umask(0o077)
	next, created, err := createNextKey(dir)
	if err != nil {
		fmt.Fprintln(stderr, "cannot create the rotation key:", err)
		return 2
	}
	if created {
		fmt.Fprintln(stdout, "rotation key created.")
	} else {
		fmt.Fprintln(stdout, "a rotation key already exists; nothing was created.")
	}
	fmt.Fprintf(stdout, "rotation key sha256: %s\n", next.sha256)
	fmt.Fprintln(stdout, "next: restart rn-build-agent so it registers the key with a rotation proof,")
	fmt.Fprintln(stdout, "      run `signer trust-builder` with this sha256 on every signer, then accept it in the console.")
	return 0
}
