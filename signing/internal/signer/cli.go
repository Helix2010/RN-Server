package signer

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/signing/internal/securefs"
)

const usageText = `用法 / usage:
  signer enroll         --server URL --code rne_… --env-file FILE --recovery-sha256 HEX [--name-check NAME]
                                            新机器注册（install.sh 以 root 执行）
  signer run            [--env-file FILE]   签名闸主进程（systemd 启动）
  signer show-key       [--env-file FILE]   打印本机公钥与 pin 文件片段（只读）
  signer confirm        --tenant SLUG [--env-file FILE]
  signer trust-peer     --peer NAME [--env-file FILE]
  signer trust-peer     --revoke --peer NAME --reason TEXT [--env-file FILE]
  signer trust-recovery [--env-file FILE]
  signer trust-recovery --revoke --recovery-sha256 HEX --reason TEXT [--env-file FILE]
  signer trust-builder  --builder NAME [--env-file FILE]
  signer trust-builder  --builder-id ID --name NAME [--env-file FILE]
  signer trust-builder  --revoke --builder-id ID --reason TEXT [--env-file FILE]
  signer promote        (--import OLD_PRIMARY_SIGNED_JSONL | --manual | --first) [--env-file FILE]
  signer abandon        --job ID --reason TEXT [--env-file FILE]
  signer list           [--env-file FILE]

没有 --env-file 时从进程环境读 SIGNER_* 配置。confirm、trust-peer、trust-recovery、trust-builder、
promote、abandon 必须由运维在交互终端里执行。`

// ExitTokenRejected 是服务端不再接受本机令牌（401 MACHINE_REVOKED / MACHINE_AUTH_REQUIRED）时
// signer run 的退出码（sysexits 的 EX_CONFIG）。rn-signer-*.service 用 RestartPreventExitStatus=78
// 阻止 systemd 重启：换令牌之前重启只会反复失败刷日志。其余致命错误退出码是 1。
const ExitTokenRejected = 78

// exitCode 把命令的错误映射成退出码。
func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errTokenRejected):
		return ExitTokenRejected
	}
	return 1
}

// Main 是 signer 命令的入口，返回退出码。
func Main(args []string, stdin *os.File, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	envFile := fs.String("env-file", "", "")
	tenant := fs.String("tenant", "", "")
	builderID := fs.String("builder-id", "", "")
	name := fs.String("name", "", "")
	revoke := fs.Bool("revoke", false, "")
	reason := fs.String("reason", "", "")
	importPath := fs.String("import", "", "")
	manual := fs.Bool("manual", false, "")
	first := fs.Bool("first", false, "")
	job := fs.String("job", "", "")
	peer := fs.String("peer", "", "")
	builder := fs.String("builder", "", "")
	recoverySHA := fs.String("recovery-sha256", "", "")
	server := fs.String("server", "", "")
	code := fs.String("code", "", "")
	nameCheck := fs.String("name-check", "", "")
	if cmd == "enroll-init" {
		// 隐藏子命令：root 的 signer enroll 以签名闸用户身份启动，stdin 一行 JSON
		if len(rest) != 0 {
			return 2
		}
		return EnrollInitMain(stdin, stdout, stderr)
	}
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	allowed := map[string][]string{
		"run": {"env-file"}, "show-key": {"env-file"}, "list": {"env-file"},
		"enroll":         {"env-file", "server", "code", "recovery-sha256", "name-check"},
		"confirm":        {"env-file", "tenant"},
		"trust-peer":     {"env-file", "peer", "revoke", "reason"},
		"trust-recovery": {"env-file", "revoke", "recovery-sha256", "reason"},
		"trust-builder":  {"env-file", "builder", "builder-id", "name", "revoke", "reason"},
		"promote":        {"env-file", "import", "manual", "first"},
		"abandon":        {"env-file", "job", "reason"},
	}
	flagsFor, ok := allowed[cmd]
	if !ok {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	okFlag := map[string]bool{}
	for _, f := range flagsFor {
		okFlag[f] = true
	}
	badFlag := false
	fs.Visit(func(f *flag.Flag) {
		if !okFlag[f.Name] {
			badFlag = true
		}
	})
	if badFlag {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	if cmd == "enroll" {
		// enroll 自己读写 env 文件（里面还没有令牌），不走下面的配置加载
		err := Enroll(context.Background(), EnrollOptions{ServerURL: *server, Code: *code, EnvFile: *envFile, RecoverySHA256: *recoverySHA, NameCheck: *nameCheck},
			NewHTTPClient(*server, "", newTransport()), newRootHost(), stdout)
		if err != nil {
			fmt.Fprintln(stderr, "错误:", cleanText(err.Error(), 2000))
		}
		return exitCode(err)
	}
	if *envFile != "" {
		values, err := ReadEnvFile(*envFile)
		if err != nil {
			fmt.Fprintln(stderr, "错误:", err)
			return 1
		}
		getenv = func(k string) string { return values[k] }
	}

	var err error
	switch cmd {
	case "run":
		err = cmdRun(getenv, stderr)
	case "show-key":
		err = cmdShowKey(getenv, stdout)
	case "list":
		err = cmdList(getenv, stdout)
	case "confirm":
		err = withOperator(stdin, getenv, NeedServer, shared, func(env OperatorEnv) error {
			return Confirm(context.Background(), env, *tenant)
		})
	case "trust-builder":
		switch {
		case *revoke:
			if *name != "" || *builder != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedLocal, shared, func(env OperatorEnv) error { return RevokeBuilder(env, *builderID, *reason) })
		case *builder != "":
			if *reason != "" || *builderID != "" || *name != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedServer, shared, func(env OperatorEnv) error {
				return TrustBuilderByName(context.Background(), env, *builder)
			})
		default:
			if *reason != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedLocal, shared, func(env OperatorEnv) error { return TrustBuilder(env, *builderID, *name) })
		}
	case "trust-peer":
		if *revoke {
			err = withOperator(stdin, getenv, NeedLocal, shared, func(env OperatorEnv) error { return RevokePeer(env, *peer, *reason) })
		} else {
			if *reason != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedServer, shared, func(env OperatorEnv) error { return TrustPeer(context.Background(), env, *peer) })
		}
	case "trust-recovery":
		if *revoke {
			err = withOperator(stdin, getenv, NeedLocal, shared, func(env OperatorEnv) error { return RevokeRecovery(env, *recoverySHA, *reason) })
		} else {
			// 指纹从密码管理器粘贴进终端，不走命令行参数
			if *reason != "" || *recoverySHA != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedServer, shared, func(env OperatorEnv) error { return TrustRecovery(context.Background(), env) })
		}
	case "promote":
		modes := 0
		mode := PromoteFirst
		if *importPath != "" {
			modes, mode = modes+1, PromoteImport
		}
		if *manual {
			modes, mode = modes+1, PromoteManual
		}
		if *first {
			modes, mode = modes+1, PromoteFirst
		}
		if modes != 1 {
			fmt.Fprintln(stderr, usageText)
			return 2
		}
		err = withOperator(stdin, getenv, NeedLocal, exclusive, func(env OperatorEnv) error { return Promote(env, mode, *importPath) })
	case "abandon":
		err = withOperator(stdin, getenv, NeedLocal, exclusive, func(env OperatorEnv) error { return Abandon(env, *job, *reason) })
	}
	if err != nil {
		fmt.Fprintln(stderr, "错误:", cleanText(err.Error(), 2000))
	}
	return exitCode(err)
}

// runLockMode 说明运维命令是否要求签名闸服务已停。
type runLockMode bool

const (
	// shared：记录文件自带多进程锁，可以与 signer run 同时执行（confirm、trust-builder、trust-peer、trust-recovery）。
	shared runLockMode = false
	// exclusive：与正在处理任务的 signer run 有竞争（abandon 可能释放它手上的预留，
	// promote 改角色并导入记录），必须先停服务、拿到运行锁。
	exclusive runLockMode = true
)

// withOperator 先确认是交互终端（不是就在读任何东西之前拒绝），再加载配置与本机记录。
func withOperator(stdin *os.File, getenv func(string) string, need Need, lock runLockMode, fn func(OperatorEnv) error) error {
	term, closeTerm, err := OpenTerminal(stdin)
	if err != nil {
		return err
	}
	defer closeTerm()
	return runOperator(term, getenv, need, lock, fn)
}

func runOperator(term Terminal, getenv func(string) string, need Need, lock runLockMode, fn func(OperatorEnv) error) error {
	cfg, err := LoadConfig(getenv, need)
	if err != nil {
		return err
	}
	if lock == exclusive {
		if err := securefs.CheckPrivateDir(cfg.StateDir); err != nil {
			return fmt.Errorf("%s: %w", EnvStateDir, err)
		}
		f, err := AcquireRunLock(cfg.StateDir)
		if err != nil {
			return fmt.Errorf("stop this signing gate's service first (systemctl stop rn-signer-a.service or rn-signer-b.service) and retry: %w", err)
		}
		defer f.Close()
	}
	keys, store, err := OpenRecords(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	defer store.Close()
	env := OperatorEnv{Config: cfg, Keys: keys, Store: store, Term: term}
	if need >= NeedServer {
		env.API = NewHTTPClient(cfg.ServerURL, cfg.MachineToken, newTransport())
	}
	return fn(env)
}

func cmdShowKey(getenv func(string) string, stdout io.Writer) error {
	cfg, err := LoadConfig(getenv, NeedLocal)
	if err != nil {
		return err
	}
	keys, store, err := OpenRecords(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	defer store.Close()
	role, err := store.Role()
	if err != nil {
		return err
	}
	return ShowKey(stdout, cfg.Name, keys, role.Role)
}

func cmdList(getenv func(string) string, stdout io.Writer) error {
	cfg, err := LoadConfig(getenv, NeedLocal)
	if err != nil {
		return err
	}
	keys, store, err := OpenRecords(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	defer store.Close()
	return List(stdout, keys, store)
}

func cmdRun(getenv func(string) string, stderr io.Writer) error {
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := LoadConfig(getenv, NeedAll)
	if err != nil {
		return err
	}
	log.Info("starting", "config", cfg)
	// 先拿锁再初始化：两个 run 同时首次启动时不能各生成一套私钥
	if err := securefs.CheckPrivateDir(cfg.StateDir); err != nil {
		return fmt.Errorf("%s: %w", EnvStateDir, err)
	}
	lock, err := AcquireRunLock(cfg.StateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	keys, created, err := InitState(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	if created {
		log.Warn("generated this signing gate's machine keys; run `signer show-key` and add them to the offline pin file",
			"x25519Sha256", keys.X25519SHA256(), "ed25519Sha256", keys.Ed25519SHA256())
	}
	keys, store, err := OpenRecords(cfg.StateDir, cfg.Name)
	if err != nil {
		return err
	}
	defer store.Close()
	// 明文 keystore 只写进 tmpfs
	if err := securefs.CheckPrivateDir(cfg.RuntimeDir); err != nil {
		return fmt.Errorf("%s: %w", EnvRuntimeDir, err)
	}
	if err := securefs.CheckTmpfs(cfg.RuntimeDir); err != nil {
		return fmt.Errorf("%s: %w", EnvRuntimeDir, err)
	}
	signer, err := NewJavaAPKSigner(cfg.JavaHome, cfg.BuildToolsDir)
	if err != nil {
		return err
	}
	// 签名闸执行与加载的每个文件都只能由 root 或签名闸用户修改（不能指向构建机那份 SDK）。
	// JAVA_HOME 整棵树都查：java 会加载 lib 下的 .so 与模块文件。
	if err := securefs.CheckTrustedTree(cfg.JavaHome); err != nil {
		return fmt.Errorf("refusing to run an untrusted JAVA_HOME: %w", err)
	}
	trusted := []string{signer.Java, signer.Jar}
	if cfg.CheckExec != "" {
		trusted = append(trusted, cfg.CheckExec)
	}
	for _, path := range trusted {
		if err := securefs.CheckTrustedPath(path); err != nil {
			return fmt.Errorf("refusing to execute an untrusted file: %w", err)
		}
	}
	var checker Checker
	if cfg.CheckSocket != "" {
		// 对端 uid 0：socket 必须由 systemd 创建并监听
		checker = SocketChecker{Path: cfg.CheckSocket, PeerUID: 0}
	} else {
		log.Warn("the checker runs as a plain child process (SIGNER_CHECK_EXEC): no systemd isolation; use SIGNER_CHECK_SOCKET in production")
		checker = ExecChecker{Path: cfg.CheckExec}
	}
	role, err := store.Role()
	if err != nil {
		return err
	}
	trustTip, signedTip, err := store.Tips()
	if err != nil {
		return err
	}
	log.Info("local records verified", "role", role.Role, "x25519Sha256", keys.X25519SHA256(), "ed25519Sha256", keys.Ed25519SHA256(),
		"trustLines", trustTip.Lines, "trustLastLineSha256", trustTip.LastHash, "signedLines", signedTip.Lines, "signedLastLineSha256", signedTip.LastHash)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	runner := &Runner{Config: cfg, Keys: keys, Store: store, API: NewHTTPClient(cfg.ServerURL, cfg.MachineToken, newTransport()),
		Checker: checker, Signer: signer, Log: log}
	if err := runner.Run(ctx); err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

// newTransport：不走代理（令牌只发给配置的源），超时收紧。
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          4,
	}
}
