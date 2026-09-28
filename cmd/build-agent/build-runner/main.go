// build-runner 是构建执行进程：以 builder 用户执行 pnpm、Gradle 和几千个第三方依赖的代码。
//
// 它由构建控制进程（build-agent，用户 rn-build-agent）经一条收窄的 sudoers 规则启动：
//
//	rn-build-agent ALL=(builder) NOPASSWD: /opt/rn-build-agent/build-runner
//
// 规则不限参数，所以**参数由这里自己校验**：任务目录只能是 <jobsRoot>/<jobId>，jobId 按服务端
// id 规则校验（不含 /、..），根目录必须是绝对的规范路径；经 sudo 运行时，根目录、任务目录与
// 控制进程准备的文件必须属于调用 sudo 的那个用户且不能被别人改写。它不读令牌、不碰出处密钥，
// 环境里也没有这些东西：子进程环境只来自任务说明里的白名单（jobspec.CheckEnv），不继承自己的环境。
//
// 子命令：
//
//	build-runner build      --jobs-root <abs> --job <id> --kind apk|ota
//	build-runner cleanup    --jobs-root <abs> --job <id>
//	build-runner self-check    --protocol <n> [--jobs-root <abs>] [--expect-separated]
//	build-runner ios-inventory        --signing-dir <abs>
//	build-runner install-ios-material     --signing-dir <abs> [--tenant <id> [--legacy]]   （密文走标准输入）
//	build-runner remove-ios-material      --signing-dir <abs> [--tenant <id>] --kind certificate|profile --team <TEAMID> [--scope <bundle id>]
//	build-runner material-key-fingerprint --signing-dir <abs>
//
// 退出码：0 成功；1 构建失败；2 参数、身份或任务目录不合规。失败原因最后一行以
// "build-runner: error: " 开头写到标准输出，控制进程取它做失败原因。
//
// 设计见 docs/design/android-signing-gate-2026-09-16.md「构建机」。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

const errorPrefix = "build-runner: error: "

// exitUsage 与 exitFailed 是退出码的全部取值（除 0）。
const (
	exitFailed = 1
	exitUsage  = 2
)

func main() {
	syscall.Umask(0o027)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Getenv))
}

// usageError 表示参数、身份或目录不合规（退出码 2）。
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

func run(ctx context.Context, args []string, in io.Reader, out io.Writer, getenv func(string) string) int {
	err := dispatch(ctx, args, in, out, getenv)
	if err == nil {
		return 0
	}
	fmt.Fprintln(out, errorPrefix+oneLine(err.Error()))
	var usage usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitFailed
}

func dispatch(ctx context.Context, args []string, in io.Reader, out io.Writer, getenv func(string) string) error {
	if len(args) == 0 {
		return usagef("usage: build-runner build|cleanup|self-check|ios-inventory ...")
	}
	who, err := detectIdentity(getenv)
	if err != nil {
		return usageError{err}
	}
	switch args[0] {
	case "build":
		flags, err := parseFlags(args[1:], true, true, false)
		if err != nil {
			return err
		}
		return build(ctx, out, who, flags)
	case "cleanup":
		flags, err := parseFlags(args[1:], true, false, false)
		if err != nil {
			return err
		}
		layout, err := checkJobDir(who, flags.root, flags.job, false)
		if err != nil {
			return usageError{err}
		}
		return cleanup(out, who, layout)
	case "material-key-fingerprint":
		set := flag.NewFlagSet("material-key-fingerprint", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		var dir onceValue
		set.Var(&dir, "signing-dir", "")
		if err := set.Parse(args[1:]); err != nil {
			return usagef("bad arguments: %v", err)
		}
		if set.NArg() != 0 {
			return usagef("unexpected positional arguments")
		}
		return materialKeyFingerprint(out, who, dir.value)
	case "install-ios-material":
		set := flag.NewFlagSet("install-ios-material", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		var dir, tenant onceValue
		set.Var(&dir, "signing-dir", "")
		set.Var(&tenant, "tenant", "")
		legacy := set.Bool("legacy", false, "")
		if err := set.Parse(args[1:]); err != nil {
			return usagef("bad arguments: %v", err)
		}
		if set.NArg() != 0 {
			return usagef("unexpected positional arguments")
		}
		if tenant.set && tenant.value == "" {
			return usagef("--tenant must not be empty")
		}
		return installIOSMaterial(ctx, out, in, who, dir.value, tenant.value, *legacy)
	case "remove-ios-material":
		set := flag.NewFlagSet("remove-ios-material", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		var dir, tenant, kind, team, scope onceValue
		set.Var(&dir, "signing-dir", "")
		set.Var(&tenant, "tenant", "")
		set.Var(&kind, "kind", "")
		set.Var(&team, "team", "")
		set.Var(&scope, "scope", "")
		if err := set.Parse(args[1:]); err != nil {
			return usagef("bad arguments: %v", err)
		}
		if set.NArg() != 0 {
			return usagef("unexpected positional arguments")
		}
		if tenant.set && tenant.value == "" {
			return usagef("--tenant must not be empty")
		}
		return removeIOSMaterial(ctx, out, who, dir.value, tenant.value, kind.value, team.value, scope.value)
	case "ios-inventory":
		set := flag.NewFlagSet("ios-inventory", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		var dir onceValue
		set.Var(&dir, "signing-dir", "")
		if err := set.Parse(args[1:]); err != nil {
			return usagef("bad arguments: %v", err)
		}
		if set.NArg() != 0 {
			return usagef("unexpected positional arguments")
		}
		return iosInventory(ctx, out, who, dir.value)
	case "self-check":
		flags, err := parseFlags(args[1:], false, false, true)
		if err != nil {
			return err
		}
		if flags.protocol != strconv.Itoa(jobspec.SpecVersion) {
			return usagef("build-runner speaks job protocol %d but the build agent asked for %q; deploy build-agent and build-runner together", jobspec.SpecVersion, flags.protocol)
		}
		if flags.expectSeparated && !who.separated {
			return usagef("build-runner is running as the same user that started it (uid %d); the sudoers rule must target a separate build user", who.uid)
		}
		// --jobs-root 是可选的：给了才查任务根目录。"它必须归控制进程"这条判据是拿
		// **调用者**（SUDO_UID）当控制进程的，只有控制进程自己来调时才成立。升级程序
		// 以 root 跑，它调这条只是想验"新二进制在这台机器上跑得起来"——带上 --jobs-root
		// 的话，判据会变成"任务根目录必须归 root"，而真机上它归控制账户，自检必然失败
		// （2026-09-20 真机撞上：升级卡在这里，日志说 uid 0 vs uid 201）。
		if flags.root != "" {
			if err := checkRoot(who, flags.root); err != nil {
				return usageError{err}
			}
		}
		fmt.Fprintf(out, "build-runner: ok uid=%d separated=%t\n", who.uid, who.separated)
		return nil
	}
	return usagef("unknown subcommand %q", args[0])
}

type runnerFlags struct {
	root            string
	job             string
	kind            jobspec.Kind
	expectSeparated bool
	protocol        string
}

// onceValue 拒绝同一个参数出现两次：flag 包默认"后者覆盖前者"，那会让一次看似
// 合规的检查放过第二个值。
type onceValue struct {
	set   bool
	value string
}

func (v *onceValue) String() string { return v.value }
func (v *onceValue) Set(s string) error {
	if v.set {
		return errors.New("given more than once")
	}
	v.set, v.value = true, s
	return nil
}

func parseFlags(args []string, needJob, needKind, allowExpect bool) (runnerFlags, error) {
	set := flag.NewFlagSet("build-runner", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var root, job, kind onceValue
	set.Var(&root, "jobs-root", "")
	if needJob {
		set.Var(&job, "job", "")
	}
	if needKind {
		set.Var(&kind, "kind", "")
	}
	expect := false
	var protocol onceValue
	if allowExpect {
		set.BoolVar(&expect, "expect-separated", false, "")
		set.Var(&protocol, "protocol", "")
	}
	if err := set.Parse(args); err != nil {
		return runnerFlags{}, usagef("bad arguments: %v", err)
	}
	if set.NArg() != 0 {
		return runnerFlags{}, usagef("unexpected positional arguments")
	}
	// self-check 之外的子命令都要任务根目录；self-check 不给就是"只验二进制"
	if !(allowExpect && root.value == "") {
		if err := jobspec.ValidRoot(root.value); err != nil {
			return runnerFlags{}, usageError{err}
		}
	}
	flags := runnerFlags{root: root.value, job: job.value, expectSeparated: expect, protocol: protocol.value}
	if needJob && !jobspec.ValidJobID(job.value) {
		return runnerFlags{}, usagef("--job is malformed")
	}
	if needKind {
		parsed, err := jobspec.ParseKind(kind.value)
		if err != nil {
			return runnerFlags{}, usageError{err}
		}
		flags.kind = parsed
	}
	return flags, nil
}

// identity 描述这个进程是以什么身份跑起来的。
type identity struct {
	uid int
	// sudoUID 是调用 sudo 的用户（控制进程）；不经 sudo 时为 -1
	sudoUID int
	// separated 表示执行进程与控制进程是不同 uid——生产形态。不分离只在本地测试
	// （BUILD_AGENT_RUNNER_USER=-）时出现：那时不做回收、不校验属主。
	separated bool
}

func detectIdentity(getenv func(string) string) (identity, error) {
	who := identity{uid: os.Getuid(), sudoUID: -1}
	if who.uid == 0 || os.Geteuid() == 0 {
		return who, errors.New("build-runner refuses to run as root")
	}
	if raw := getenv("SUDO_UID"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			return who, errors.New("SUDO_UID is malformed")
		}
		who.sudoUID = parsed
		who.separated = parsed != who.uid
	}
	return who, nil
}

func oneLine(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}
