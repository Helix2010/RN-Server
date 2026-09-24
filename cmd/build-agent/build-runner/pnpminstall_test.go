package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// installJob 造一个只用来跑 pnpm install 的任务：PATH 里只有测试写的假 pnpm，
// 它每次被调起都在 calls 文件里记一行，行为由脚本决定。
func installJob(t *testing.T, script string) (job, *bytes.Buffer, string) {
	t.Helper()
	root := t.TempDir()
	layout := jobspec.Layout{Root: root, JobID: "job-install"}
	if err := os.MkdirAll(layout.App(), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(root, "calls")
	body := "#!/bin/sh\necho x >>\"" + calls + "\"\nn=$(wc -l <\"" + calls + "\" | tr -d ' ')\n" + script
	if err := os.WriteFile(filepath.Join(bin, "pnpm"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	return job{out: out, layout: layout, spec: jobspec.Spec{Env: []string{"PATH=" + bin + ":/usr/bin:/bin"}}}, out, calls
}

func callCount(t *testing.T, calls string) int {
	t.Helper()
	raw, err := os.ReadFile(calls)
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "\n")
}

func shortIdle(t *testing.T) {
	t.Helper()
	restore := installIdleLimit
	installIdleLimit = 400 * time.Millisecond
	t.Cleanup(func() { installIdleLimit = restore })
}

// build 24 的样子：第一次打几行进度然后一声不吭地挂住；第二次正常装完。
func TestPnpmInstallThatGoesQuietIsStoppedAndRetriedOnce(t *testing.T) {
	shortIdle(t)
	j, out, calls := installJob(t, `
echo "Progress: resolved 1196, reused 0, downloaded 1195, added 1195"
if [ "$n" = 1 ]; then exec sleep 30; fi
echo "Done in 1m 6.1s"
`)
	started := time.Now()
	if err := j.install(context.Background()); err != nil {
		t.Fatalf("the retry should have succeeded: %v\n%s", err, out.String())
	}
	if got := callCount(t, calls); got != 2 {
		t.Fatalf("pnpm ran %d times, want 2", got)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the hung install was not stopped promptly (%s)", elapsed)
	}
	if !strings.Contains(out.String(), "trying once more") {
		t.Fatalf("the retry is not in the log:\n%s", out.String())
	}
}

func TestPnpmInstallThatHangsTwiceFailsWithTheReason(t *testing.T) {
	shortIdle(t)
	j, _, calls := installJob(t, "echo start\nexec sleep 30\n")
	err := j.install(context.Background())
	if !errors.Is(err, errInstallIdle) {
		t.Fatalf("err = %v, want errInstallIdle", err)
	}
	if got := callCount(t, calls); got != installAttempts {
		t.Fatalf("pnpm ran %d times, want %d", got, installAttempts)
	}
}

// 挂死以外的失败不重试：锁文件对不上、包签名验不过，重跑一次结果不会变。
func TestPnpmInstallFailureThatIsNotAHangIsNotRetried(t *testing.T) {
	shortIdle(t)
	j, _, calls := installJob(t, "echo ERR_PNPM_OUTDATED_LOCKFILE >&2\nexit 1\n")
	err := j.install(context.Background())
	if err == nil || errors.Is(err, errInstallIdle) {
		t.Fatalf("err = %v, want the plain failure", err)
	}
	if got := callCount(t, calls); got != 1 {
		t.Fatalf("pnpm ran %d times, want 1", got)
	}
}

// 一直在打输出的慢安装不算挂死，哪怕总时长超过了空闲时限。
func TestSlowPnpmInstallThatKeepsTalkingIsLeftAlone(t *testing.T) {
	shortIdle(t)
	j, _, calls := installJob(t, `
for i in 1 2 3 4 5 6; do echo "Progress: $i"; sleep 0.2; done
echo done
`)
	if err := j.install(context.Background()); err != nil {
		t.Fatalf("a slow but talkative install was stopped: %v", err)
	}
	if got := callCount(t, calls); got != 1 {
		t.Fatalf("pnpm ran %d times, want 1", got)
	}
}

// 任务本身被取消（控制台取消 / 总时限到）时不重试。
func TestPnpmInstallIsNotRetriedWhenTheJobIsCanceled(t *testing.T) {
	shortIdle(t)
	j, _, calls := installJob(t, "echo start\nexec sleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if err := j.install(ctx); err == nil {
		t.Fatal("a canceled install reported success")
	}
	if got := callCount(t, calls); got != 1 {
		t.Fatalf("pnpm ran %d times after the job was canceled, want 1", got)
	}
}
