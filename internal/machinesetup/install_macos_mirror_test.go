package machinesetup

// 装机要在 deploy key 那里停一次：key 是这台机器现场生成的，GitHub 上还没有它。
// 人加完之后重新执行同一条命令，那一次**必须真的去克隆**。
//
// 上一版这里是反的：ensure_mirror 在镜像不存在时一律印公钥、返回 1，main 再照着 1 走
// "加完重新执行" 那一支——于是加不加 deploy key 都一样，每一次执行都停在同一行，装机
// 永远走不到 launchd。而 clone_mirror 挂在 main 的另一支上，只有"镜像已经在了"才会被
// 调用，调用到了也必然失败（往一个已存在的目录 git clone）。两边都错，真机上表现成
// 一个看不出错误的死循环。
//
// 形状检查挡不住这种错，所以这里把 ensure_mirror 真的跑起来，sudo 与 git 换成桩。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type mirrorRig struct {
	dir       string
	agentHome string
	gitLog    string
}

func newMirrorRig(t *testing.T) mirrorRig {
	t.Helper()
	for _, name := range []string{"bash", "ssh-keygen"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("no %s on this machine", name)
		}
	}
	dir := t.TempDir()
	rig := mirrorRig{dir: dir, agentHome: filepath.Join(dir, "agent"), gitLog: filepath.Join(dir, "git.log")}
	for _, sub := range []string{"agent/repos", "agent/.ssh", "bin"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// 脚本开头会把 PATH、HOME 重置、unset 掉所有导出变量与函数（它就该这么做），所以桩
	// 只能靠 source 之后再改 PATH 生效，而假的 AGENT_HOME 只能改脚本里那一行常量。
	body := string(InstallMacOSScript)
	const home = "readonly AGENT_HOME=/var/rn-build-agent"
	if !strings.Contains(body, home) {
		t.Fatalf("install-macos.sh no longer declares %q; this test pins AGENT_HOME by rewriting that line", home)
	}
	body = strings.Replace(body, home, "readonly AGENT_HOME="+rig.agentHome, 1)
	body = strings.Replace(body, "\nmain \"$@\"\nexit\n", "\n", 1)
	if strings.Contains(body, "\nmain \"$@\"\n") {
		t.Fatal("install-macos.sh no longer ends with main \"$@\" + exit; this test sources the script and must strip them")
	}
	write(t, filepath.Join(dir, "lib.sh"), body, 0o700)

	// sudo：吃掉 -n 与 -u <用户>，剩下的照跑。装机时这两步都是 root 切到 _rnbuildagent，
	// 测试里没有那个账户，跑本人即可——这里验的是流程走向，不是权限。
	write(t, filepath.Join(dir, "bin/sudo"), `#!/bin/bash
while [ "${1:-}" = -n ]; do shift; done
if [ "${1:-}" = -u ]; then shift 2; fi
exec "$@"
`, 0o755)
	// 失败开关走文件，不走环境变量：脚本开头会把所有导出变量 unset 掉（PATH、HOME 等
	// 几个除外），环境变量传不进桩里。
	write(t, filepath.Join(dir, "bin/git"), `#!/bin/bash
printf '%s\n' "$*" >>"`+rig.gitLog+`"
dest="${@: -1}"
# 真的 git clone 是先把目标目录建出来再去连 GitHub 的，失败时地上可能留着半个目录。
# 桩要照这个顺序来，不然"失败后清不清理"根本测不到。
mkdir -p "$dest"
if [ -f "`+filepath.Join(dir, "git-fails")+`" ]; then
  echo "git@github.com: Permission denied (publickey)." >&2
  exit 128
fi
mkdir -p "$dest/objects"
`, 0o755)
	return rig
}

// run 把 ensure_mirror 跑一遍，回它印了什么与它要不要人去加 key。
func (r mirrorRig) run(t *testing.T, gitFails bool) (out string, needsKey bool) {
	t.Helper()
	harness := `set -u
. "` + r.dir + `/lib.sh"
PATH="` + r.dir + `/bin:$PATH"
MACHINE_NAME=mac-01
if ensure_mirror; then echo "RESULT mirror-ready"; else echo "RESULT needs-deploy-key"; fi
`
	marker := filepath.Join(r.dir, "git-fails")
	if gitFails {
		write(t, marker, "", 0o600)
	} else {
		_ = os.Remove(marker)
	}
	raw, err := exec.Command("bash", "-c", harness).CombinedOutput()
	if err != nil {
		t.Fatalf("harness failed: %v\n%s", err, raw)
	}
	text := string(raw)
	switch {
	case strings.Contains(text, "RESULT mirror-ready"):
		return text, false
	case strings.Contains(text, "RESULT needs-deploy-key"):
		return text, true
	}
	t.Fatalf("ensure_mirror printed no result:\n%s", text)
	return "", false
}

func (r mirrorRig) gitRan(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(r.gitLog)
	return err == nil
}

func (r mirrorRig) mirrorExists(t *testing.T) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(r.agentHome, "repos/rn-app.git"))
	return err == nil
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// 第一趟：机器上还没有 key。生成、印出来、停。不该白跑一次必然失败的克隆。
func TestMacInstallStopsForTheDeployKeyOnTheFirstRun(t *testing.T) {
	rig := newMirrorRig(t)
	out, needsKey := rig.run(t, false)
	if !needsKey {
		t.Fatalf("first run should stop and ask for the deploy key:\n%s", out)
	}
	if !strings.Contains(out, "ssh-ed25519 ") {
		t.Errorf("the deploy key itself has to be on screen, otherwise there is nothing to paste into GitHub:\n%s", out)
	}
	if rig.gitRan(t) {
		t.Error("a key generated seconds ago cannot be on GitHub yet; cloning with it only buys a confusing failure")
	}
	if _, err := os.Stat(filepath.Join(rig.agentHome, ".ssh/id_ed25519")); err != nil {
		t.Errorf("no deploy key was generated: %v", err)
	}
}

// 第二趟：人加完 key 回来了。这一次必须真的克隆，克隆完接着往下装。
func TestMacInstallClonesOnceTheDeployKeyIsOnGitHub(t *testing.T) {
	rig := newMirrorRig(t)
	if _, needsKey := rig.run(t, false); !needsKey {
		t.Fatal("setup: the first run should have stopped for the deploy key")
	}
	out, needsKey := rig.run(t, false)
	if needsKey {
		t.Fatalf("the run after the deploy key was added must clone, not print the same key again "+
			"— printing it every time is an install that never finishes:\n%s", out)
	}
	if !rig.gitRan(t) {
		t.Fatal("git was never called: nothing cloned the mirror")
	}
	if !rig.mirrorExists(t) {
		t.Error("no mirror at repos/rn-app.git after a successful clone")
	}
}

// 克隆失败（key 加错了、没加、网络不通）：印公钥、返回"等人加"，并且**不留半个目录**
// ——留着的话下一次执行会把它当成"镜像已存在"跳过去。
func TestMacInstallLeavesNoHalfCloneBehind(t *testing.T) {
	rig := newMirrorRig(t)
	rig.run(t, false)
	out, needsKey := rig.run(t, true)
	if !needsKey {
		t.Fatalf("a failed clone must send the operator back to GitHub:\n%s", out)
	}
	if rig.mirrorExists(t) {
		t.Error("a failed clone left repos/rn-app.git behind; the next run would take it for a finished mirror")
	}
	if _, err := os.Stat(filepath.Join(rig.agentHome, "repos/rn-app.git.part")); err == nil {
		t.Error("the half clone is still sitting at repos/rn-app.git.part; every retry then starts by tripping over it")
	}
	if !strings.Contains(out, "Permission denied (publickey)") {
		t.Errorf("git's own words are what tells the operator which of the three causes it is:\n%s", out)
	}
}

// main 里那一支：克隆挂在 ensure_mirror 内部，main 只判断要不要停。写反过一次。
func TestMacInstallMainDoesNotCloneOnItsOwn(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\nmain() {\n")
	if start < 0 {
		t.Fatal("no main() in install-macos.sh")
	}
	main := body[start:]
	if end := strings.Index(main, "\n}\n"); end >= 0 {
		main = main[:end]
	}
	if !strings.Contains(main, "if ! ensure_mirror; then") {
		t.Error("main must stop for the deploy key on ensure_mirror's failure; " +
			"the inverted form made every run print the key and exit")
	}
	if strings.Contains(main, "clone_mirror") {
		t.Error("main calls clone_mirror directly. Cloning belongs inside ensure_mirror, " +
			"which knows whether the mirror is already there — cloning into an existing directory always fails")
	}
}

// 断电、Ctrl-C：脚本自己的清理跑不到。所以镜像的真身路径上不许出现过程态——克隆到
// .part，成了再改名。这一条只在"脚本没能收尾"时才看得出差别，桩造不出那个场面，
// 所以这里只盯形状。
func TestMacInstallClonesIntoAScratchPathFirst(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\nclone_mirror() {\n")
	if start < 0 {
		t.Fatal("no clone_mirror() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	if !strings.Contains(fn, `part="$AGENT_HOME/repos/rn-app.git.part"`) {
		t.Error("clone_mirror no longer clones into repos/rn-app.git.part. " +
			"Cloning straight into repos/rn-app.git means a power cut leaves a partial mirror " +
			"under the real path, and the next run reports 仓库镜像已存在")
	}
	if !strings.Contains(fn, `mv "$part" "$AGENT_HOME/repos/rn-app.git"`) {
		t.Error("nothing renames the finished clone into place")
	}
	for _, guard := range []string{"env -i", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "core.hooksPath=/dev/null", "protocol.allow=never", "--template="} {
		if !strings.Contains(fn, guard) {
			t.Errorf("clone_mirror dropped %q. This clone runs as _rnbuildagent, the account that holds "+
				"the machine token and the provenance key; install.sh gives the Linux builder every one "+
				"of these guards and this machine holds signing material on top", guard)
		}
	}
}

// runBash 跑一段 harness，回它的全部输出。
func runBash(t *testing.T, script string) (string, error) {
	t.Helper()
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	return string(out), err
}
