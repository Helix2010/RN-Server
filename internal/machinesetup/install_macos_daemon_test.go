package machinesetup

// launchd 在 exec **之前**就切到 plist 里的 UserName，**创建 StandardOutPath 用的也是
// 那个身份**。/var/log 是 root:wheel 0755，_rnbuildagent 在里面建不出文件，于是整个 job
// 以 EX_CONFIG(78) 收场：程序一行都没跑，日志文件不存在，状态目录里什么都没有。真机上
// 就这么卡住了——`launchctl print` 里 runs 涨到 44，别处一点线索都没有。
//
// 所以装机必须把日志文件先按 job 的身份建出来。路径和账户从 plist 读，不写死：plist 来自
// 安装包，脚本是服务端单独下发的，两者可以不同版本。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// daemonRig 把 ensure_daemon_logs 单独拉出来跑：plutil 与 install 换成桩。
type daemonRig struct {
	dir, logDir, installLog string
}

func newDaemonRig(t *testing.T) daemonRig {
	t.Helper()
	dir := t.TempDir()
	rig := daemonRig{dir: dir, logDir: filepath.Join(dir, "log"), installLog: filepath.Join(dir, "install.log")}
	if err := os.MkdirAll(rig.logDir, 0o755); err != nil {
		t.Fatal(err)
	}

	body := string(InstallMacOSScript)
	const plutil = "/usr/bin/plutil"
	if !strings.Contains(body, plutil) {
		t.Fatalf("install-macos.sh no longer calls %s; this test swaps it for a stub", plutil)
	}
	body = strings.ReplaceAll(body, plutil, filepath.Join(dir, "bin/plutil"))
	body = strings.Replace(body, "\nmain \"$@\"\nexit\n", "\n", 1)
	write(t, filepath.Join(dir, "lib.sh"), body, 0o700)

	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// plutil 的桩：只实现脚本用到的那一种调用（-extract <键> raw -o - <文件>），
	// 值从测试自己写的 KEY=VALUE 文件里取。键不在就以非零退出，照真 plutil 的样子。
	write(t, filepath.Join(dir, "bin/plutil"), `#!/bin/bash
[ "$1" = -extract ] || { echo "stub plutil: unexpected args: $*" >&2; exit 64; }
key="$2"; file="${!#}"
line="$(grep "^$key=" "$file" || true)"
[ -n "$line" ] || exit 1
printf '%s\n' "${line#*=}"
`, 0o755)
	// chown/chmod 的桩：记下调用，不真的改（测试机上没有那两个账户）。
	for _, name := range []string{"chown", "chmod"} {
		write(t, filepath.Join(dir, "bin", name),
			"#!/bin/bash\nprintf '"+name+" %s\\n' \"$*\" >>\""+rig.installLog+"\"\n", 0o755)
	}
	// install 的桩：记下每一次调用，并真的把文件/目录造出来，好验"第二趟不再建"。
	write(t, filepath.Join(dir, "bin/install"), `#!/bin/bash
printf '%s\n' "$*" >>"`+rig.installLog+`"
if [ "$1" = -d ]; then mkdir -p "${!#}"; else : >"${!#}"; fi
`, 0o755)
	return rig
}

func (r daemonRig) plist(t *testing.T, name string, keys map[string]string) string {
	t.Helper()
	var body strings.Builder
	for key, value := range keys {
		body.WriteString(key + "=" + value + "\n")
	}
	path := filepath.Join(r.dir, name)
	write(t, path, body.String(), 0o644)
	return path
}

func (r daemonRig) run(t *testing.T, plists ...string) (string, bool) {
	t.Helper()
	harness := `set -u
. "` + r.dir + `/lib.sh"
PATH="` + r.dir + `/bin:$PATH"
`
	for _, p := range plists {
		harness += "ensure_daemon_logs " + p + "\n"
	}
	out, err := runBash(t, harness)
	return out, err == nil
}

// creates 只留 install 的调用；chown/chmod 记在同一个文件里。
func (r daemonRig) creates(t *testing.T) []string {
	t.Helper()
	var made []string
	for _, call := range r.installCalls(t) {
		if !strings.HasPrefix(call, "chown ") && !strings.HasPrefix(call, "chmod ") {
			made = append(made, call)
		}
	}
	return made
}

func (r daemonRig) installCalls(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(r.installLog)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func TestMacInstallCreatesTheDaemonLogAsTheJobAccount(t *testing.T) {
	rig := newDaemonRig(t)
	logPath := filepath.Join(rig.logDir, "rn-build-agent.log")
	plist := rig.plist(t, "agent.plist", map[string]string{
		"UserName": "_rnbuildagent", "GroupName": "_rnbuildjobs",
		"StandardOutPath": logPath, "StandardErrorPath": logPath,
	})

	out, ok := rig.run(t, plist)
	if !ok {
		t.Fatalf("ensure_daemon_logs failed:\n%s", out)
	}
	calls := rig.creates(t)
	if len(calls) != 1 {
		t.Fatalf("expected one install call (both plist keys name the same file), got %d:\n%s",
			len(calls), strings.Join(calls, "\n"))
	}
	for _, want := range []string{"-o _rnbuildagent", "-g _rnbuildjobs", logPath} {
		if !strings.Contains(calls[0], want) {
			t.Errorf("the log file is not created for the account launchd will run the job as: "+
				"%q missing from %q. launchd creates StandardOutPath with the job's uid/gid and fails "+
				"with EX_CONFIG(78) when it cannot", want, calls[0])
		}
	}
}

// 没写 UserName 的 job（升级程序）以 root 跑，日志也该是 root 的。
func TestMacInstallDefaultsTheLogOwnerToRoot(t *testing.T) {
	rig := newDaemonRig(t)
	logPath := filepath.Join(rig.logDir, "upgrade.log")
	plist := rig.plist(t, "upgrade.plist", map[string]string{
		"StandardOutPath": logPath, "StandardErrorPath": logPath,
	})
	if out, ok := rig.run(t, plist); !ok {
		t.Fatalf("ensure_daemon_logs failed:\n%s", out)
	}
	calls := rig.creates(t)
	if len(calls) != 1 || !strings.Contains(calls[0], "-o root") || !strings.Contains(calls[0], "-g wheel") {
		t.Errorf("a plist without UserName runs as root; its log must be root:wheel, got: %q",
			strings.Join(calls, "\n"))
	}
}

// 重复执行不清现场日志。
func TestMacInstallKeepsAnExistingDaemonLog(t *testing.T) {
	rig := newDaemonRig(t)
	logPath := filepath.Join(rig.logDir, "rn-build-agent.log")
	write(t, logPath, "上一条命留下的日志\n", 0o640)
	plist := rig.plist(t, "agent.plist", map[string]string{
		"UserName": "_rnbuildagent", "GroupName": "_rnbuildjobs",
		"StandardOutPath": logPath, "StandardErrorPath": logPath,
	})
	if out, ok := rig.run(t, plist); !ok {
		t.Fatalf("ensure_daemon_logs failed:\n%s", out)
	}
	calls := rig.installCalls(t)
	for _, call := range rig.creates(t) {
		t.Errorf("an existing log was rewritten: %q. Re-running the installer must not wipe the "+
			"log someone is reading right now", call)
	}
	// 属主还是要摆正：root 建的那个文件 launchd 以 _rnbuildagent 打不开，一样是 78
	if !strings.Contains(strings.Join(calls, "\n"), "chown _rnbuildagent:_rnbuildjobs") {
		t.Errorf("nothing put the existing log back under the job's account: %q", strings.Join(calls, "\n"))
	}
	if raw, err := os.ReadFile(logPath); err != nil || !strings.Contains(string(raw), "上一条命") {
		t.Errorf("the existing log lost its contents: %v %q", err, raw)
	}
}

// 读不出路径就停住。继续下去只会 bootstrap 出一个以 78 静默失败的 job。
func TestMacInstallStopsWhenTheLogPathCannotBeRead(t *testing.T) {
	rig := newDaemonRig(t)
	plist := rig.plist(t, "broken.plist", map[string]string{"UserName": "_rnbuildagent"})
	out, ok := rig.run(t, plist)
	if ok {
		t.Fatalf("ensure_daemon_logs carried on without knowing where the log goes:\n%s", out)
	}
	if !strings.Contains(out, "EX_CONFIG") {
		t.Errorf("the error does not say what happens next (launchd fails with EX_CONFIG and leaves no trace):\n%s", out)
	}
}

// 真的那两份 plist：日志得在 /var/log 下，而且装机必须在 bootstrap **之前**替它们建好。
func TestMacInstallPreparesLogsForBothShippedPlists(t *testing.T) {
	for _, name := range []string{
		"../../deploy/build-agent-macos/win.anyfun.rn-build-agent.plist",
		"../../deploy/build-agent-macos/win.anyfun.rn-build-agent-upgrade.plist",
	} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"StandardOutPath", "StandardErrorPath"} {
			if !strings.Contains(string(raw), "<key>"+key+"</key>") {
				t.Errorf("%s has no %s; ensure_daemon_logs would die on it", name, key)
			}
		}
	}

	body := string(InstallMacOSScript)
	start := strings.Index(body, "\ninstall_daemons() {\n")
	if start < 0 {
		t.Fatal("no install_daemons() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	prepare := strings.Index(fn, "ensure_daemon_logs")
	bootstrap := strings.Index(fn, "launchctl bootstrap")
	switch {
	case prepare < 0:
		t.Error("install_daemons never prepares the daemon log files; launchd cannot create them " +
			"as _rnbuildagent and the job dies with EX_CONFIG(78) before the program runs")
	case bootstrap < 0:
		t.Error("install_daemons no longer bootstraps anything")
	case prepare > bootstrap:
		t.Error("the log files are prepared after launchctl bootstrap; by then the job has already " +
			"failed and launchd is throttling it")
	}
	if strings.Count(fn, "ensure_daemon_logs") != 2 {
		t.Errorf("both plists need their logs prepared, found %d calls", strings.Count(fn, "ensure_daemon_logs"))
	}
}
