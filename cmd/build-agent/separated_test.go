package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/provenance"
)

// TestSeparatedUsersEndToEnd 以真正的两个 uid 跑一遍：本测试进程扮演控制进程，经 sudo 以
// RN_TEST_SUDO_RUNNER_USER 启动执行进程。需要 root（用 root 扮演 rn-build-agent，这样不用在
// 机器上新建用户和组），CI 上跳过。本地这样跑：
//
//	sudo -n env PATH="$PATH" HOME=/root GOCACHE=/tmp/s3-gocache GOTOOLCHAIN=local \
//	  RN_TEST_SUDO_RUNNER_USER=nobody go test -count=1 -run TestSeparatedUsersEndToEnd ./cmd/build-agent/
//
// 执行进程在开始时会回收该用户的全部进程与 /tmp 顶层文件，所以这个用户在机器上必须是空闲的。
func TestSeparatedUsersEndToEnd(t *testing.T) {
	name := os.Getenv("RN_TEST_SUDO_RUNNER_USER")
	if name == "" {
		t.Skip("set RN_TEST_SUDO_RUNNER_USER (and run as root) to exercise sudo with a separate build user")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to play the controller user without creating accounts")
	}
	account, err := osuser.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if out, _ := exec.Command("pgrep", "-u", account.Uid).Output(); len(strings.TrimSpace(string(out))) != 0 {
		t.Fatalf("user %s has running processes; the runner would kill them", name)
	}
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			if info, err := os.Lstat(filepath.Join(dir, entry.Name())); err == nil && int(info.Sys().(*syscall.Stat_t).Uid) == uid {
				t.Fatalf("%s already owns %s; the runner would remove it", name, filepath.Join(dir, entry.Name()))
			}
		}
	}
	t.Setenv("BUILD_AGENT_MACHINE_TOKEN", testToken)

	rig := newRig(t)
	a := rig.agent
	a.cfg.RunnerUser = name
	// 生产里任务根目录是 rn-build-agent:rn-build-jobs 2750、builder 在组里；这里用构建用户的主组扮演 rn-build-jobs
	for dir := filepath.Dir(a.cfg.Workspace); dir != "/tmp" && dir != "/"; dir = filepath.Dir(dir) {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(a.cfg.Workspace, 0, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.cfg.Workspace, 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(runnerBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rig.tools.Record, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := a.checkRunner(context.Background()); err != nil {
		t.Fatalf("self-check through sudo failed: %v", err)
	}

	// 上一个任务留下的"潜伏者"：一个后台进程与 /tmp 里的一个文件
	lurker := exec.Command(sudoPath, "-n", "-u", name, "--", "/bin/sleep", "300")
	if err := lurker.Start(); err != nil {
		t.Fatal(err)
	}
	lurkerDone := make(chan error, 1)
	go func() { lurkerDone <- lurker.Wait() }()
	planted := "/tmp/rn-s3-planted-" + strconv.Itoa(os.Getpid())
	if out, err := exec.Command(sudoPath, "-n", "-u", name, "--", "/usr/bin/touch", planted).CombinedOutput(); err != nil {
		t.Fatalf("plant: %v %s", err, out)
	}
	time.Sleep(200 * time.Millisecond)

	rig.server.queueClaim(claimBody("bld_sudoAPK000001", "apk"))
	if !a.pollOnce(context.Background()) {
		t.Fatal("no job")
	}
	if fails := rig.server.callsTo("/fail"); len(fails) != 0 {
		t.Fatalf("the job failed: %s", fails[0].Body)
	}
	built := rig.server.callsTo("/built")
	if len(built) != 1 {
		t.Fatal("not delivered")
	}
	var delivery struct {
		Provenance provenance.Envelope `json:"provenance"`
	}
	_ = json.Unmarshal(built[0].Body, &delivery)
	if _, err := provenance.Verify(delivery.Provenance, a.keys.current.public); err != nil {
		t.Fatalf("provenance: %v", err)
	}
	for _, step := range []string{"install", "fingerprint", "android-release"} {
		raw, err := os.ReadFile(filepath.Join(rig.tools.Record, step+".uid"))
		if err != nil || strings.TrimSpace(string(raw)) != account.Uid {
			t.Fatalf("step %s ran as uid %q, want %s (%v)", step, raw, account.Uid, err)
		}
		if env := strings.Join(rig.tools.RecordedEnv(t, step), "\n"); strings.Contains(env, testToken) {
			t.Fatalf("step %s saw the machine token", step)
		}
	}
	select {
	case <-lurkerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("a process left by the build user survived the next job")
	}
	if _, err := os.Lstat(planted); !os.IsNotExist(err) {
		_ = os.Remove(planted)
		t.Fatalf("a /tmp file left by the build user survived the next job: %v", err)
	}
	if left := jobRootEntries(t, a); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}

	// 执行进程的用户读不到控制进程的出处密钥、状态目录和进程环境
	for label, args := range map[string][]string{
		"provenance key":     {"/bin/cat", filepath.Join(a.cfg.StateDir, provenanceKeyFile)},
		"state dir":          {"/bin/ls", a.cfg.StateDir},
		"controller environ": {"/bin/cat", "/proc/" + strconv.Itoa(os.Getpid()) + "/environ"},
	} {
		out, err := exec.Command(sudoPath, append([]string{"-n", "-u", name, "--"}, args...)...).CombinedOutput()
		if err == nil || strings.Contains(string(out), testToken) {
			t.Fatalf("%s is readable by the build user: %s", label, out)
		}
	}
}
