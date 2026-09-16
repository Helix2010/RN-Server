package signer

import (
	"context"
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
  signer run            [--env-file FILE]   签名闸主进程（systemd 启动）
  signer show-key       [--env-file FILE]   打印本机公钥与 pin 文件片段（只读）
  signer confirm        --tenant SLUG [--env-file FILE]
  signer trust-builder  --builder-id ID --name NAME [--env-file FILE]
  signer trust-builder  --revoke --builder-id ID --reason TEXT [--env-file FILE]
  signer promote        (--import OLD_PRIMARY_SIGNED_JSONL | --manual | --first) [--env-file FILE]
  signer abandon        --job ID --reason TEXT [--env-file FILE]
  signer list           [--env-file FILE]

没有 --env-file 时从进程环境读 SIGNER_* 配置。confirm、trust-builder、promote、abandon
必须由运维在交互终端里执行。`

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
	if err := fs.Parse(rest); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	allowed := map[string][]string{
		"run": {"env-file"}, "show-key": {"env-file"}, "list": {"env-file"},
		"confirm":       {"env-file", "tenant"},
		"trust-builder": {"env-file", "builder-id", "name", "revoke", "reason"},
		"promote":       {"env-file", "import", "manual", "first"},
		"abandon":       {"env-file", "job", "reason"},
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
		err = withOperator(stdin, getenv, NeedServer, func(env OperatorEnv) error {
			return Confirm(context.Background(), env, *tenant)
		})
	case "trust-builder":
		if *revoke {
			if *name != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedLocal, func(env OperatorEnv) error { return RevokeBuilder(env, *builderID, *reason) })
		} else {
			if *reason != "" {
				fmt.Fprintln(stderr, usageText)
				return 2
			}
			err = withOperator(stdin, getenv, NeedLocal, func(env OperatorEnv) error { return TrustBuilder(env, *builderID, *name) })
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
		err = withOperator(stdin, getenv, NeedLocal, func(env OperatorEnv) error { return Promote(env, mode, *importPath) })
	case "abandon":
		err = withOperator(stdin, getenv, NeedLocal, func(env OperatorEnv) error { return Abandon(env, *job, *reason) })
	}
	if err != nil {
		fmt.Fprintln(stderr, "错误:", cleanText(err.Error(), 2000))
		return 1
	}
	return 0
}

// withOperator 先确认是交互终端（不是就在读任何东西之前拒绝），再加载配置与本机记录。
func withOperator(stdin *os.File, getenv func(string) string, need Need, fn func(OperatorEnv) error) error {
	term, closeTerm, err := OpenTerminal(stdin)
	if err != nil {
		return err
	}
	defer closeTerm()
	return runOperator(term, getenv, need, fn)
}

func runOperator(term Terminal, getenv func(string) string, need Need, fn func(OperatorEnv) error) error {
	cfg, err := LoadConfig(getenv, need)
	if err != nil {
		return err
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
	signer, err := NewJavaAPKSigner(cfg.JavaHome, cfg.BuildToolsDir)
	if err != nil {
		return err
	}
	var checker Checker
	if cfg.CheckSocket != "" {
		checker = SocketChecker{Path: cfg.CheckSocket}
	} else {
		log.Warn("the checker runs as a plain child process (SIGNER_CHECK_EXEC): no systemd isolation; use SIGNER_CHECK_SOCKET in production")
		checker = ExecChecker{Path: cfg.CheckExec}
	}
	role, err := store.Role()
	if err != nil {
		return err
	}
	log.Info("local records verified", "role", role.Role, "x25519Sha256", keys.X25519SHA256(), "ed25519Sha256", keys.Ed25519SHA256())
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
