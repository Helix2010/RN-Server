package signer

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/internal/checkwire"
	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
)

// 测试二进制经符号链接以不同名字启动时，扮演检查进程（或一个会崩溃的检查进程）。
const (
	actAsChecker        = "signer-check-under-test"
	actAsCrashedChecker = "signer-check-that-crashes"
	actAsHungChecker    = "signer-check-that-hangs"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "enroll-init" {
		// rootHost.Init 以 "<可执行文件> enroll-init" 启动子进程
		os.Exit(EnrollInitMain(os.Stdin, os.Stdout, os.Stderr))
	}
	// RSA 生成在 -race 下很慢：生成密钥的测试从一个小密钥池里轮流取（相邻两次一定不同）
	generateReleaseKey = pooledReleaseKey
	switch filepath.Base(os.Args[0]) {
	case actAsChecker:
		// ExecChecker 必须以空环境启动检查进程：令牌不能漏进去
		if env := os.Environ(); len(env) != 0 {
			fmt.Fprintf(os.Stderr, "checker environment is not empty: %d variables\n", len(env))
			os.Exit(3)
		}
		os.Exit(checkwire.Serve(os.Stdin, os.Stdout, os.Stderr))
	case actAsCrashedChecker:
		_, _ = io.CopyN(io.Discard, os.Stdin, 1024)
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL) // 像被 OOM killer 或 seccomp 杀掉一样，没有任何收尾
		time.Sleep(time.Second)
		os.Exit(1)
	case actAsHungChecker:
		time.Sleep(time.Hour)
	}
	os.Exit(m.Run())
}

func checkerBinary(t *testing.T, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), name)
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	return link
}

func writeAPK(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unsigned.apk")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExecCheckerRunsTheCheckerWithAnEmptyEnvironment(t *testing.T) {
	t.Setenv(EnvMachineToken, testToken) // 主进程环境里有令牌
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_execCHECK0000001", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	v, err := ExecChecker{Path: checkerBinary(t, actAsChecker)}.Check(context.Background(), in, writeAPK(t, build.APK))
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.CheckedSHA256 != build.SHA256 {
		t.Fatalf("verdict: %+v", v)
	}
	in.Confirmed.TrustRoots.Scheme = "other"
	v, err = ExecChecker{Path: checkerBinary(t, actAsChecker)}.Check(context.Background(), in, writeAPK(t, build.APK))
	if err != nil || v.OK || v.Code != "TRUST_ROOT_MISMATCH" {
		t.Fatalf("verdict: %+v %v", v, err)
	}
}

func TestExecCheckerCrashAndHangAreErrors(t *testing.T) {
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_execCHECK0000002", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	path := writeAPK(t, build.APK)
	_, err := ExecChecker{Path: checkerBinary(t, actAsCrashedChecker)}.Check(context.Background(), in, path)
	if err == nil || !strings.Contains(err.Error(), "signal") {
		t.Fatalf("crash: %v", err)
	}
	start := time.Now()
	_, err = ExecChecker{Path: checkerBinary(t, actAsHungChecker), Timeout: 300 * time.Millisecond}.Check(context.Background(), in, path)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("hang: %v after %v", err, time.Since(start))
	}
}

// 检查进程崩溃只让这一次签名成为临时错误；主进程继续认领下一条。
func TestCheckerCrashDoesNotStopTheSigner(t *testing.T) {
	crash := ExecChecker{Path: checkerBinary(t, actAsCrashedChecker)}
	h := newHarness(t, harnessOptions{checker: crash})
	h.enqueue(h.build("bld_crashJOB00000001", 46, nil), 1, nil)
	h.runOnce()
	assertOutcome(t, h, "transient", "CHECKER_FAILED")
	if list, _ := h.store.Reservations(); len(list) != 0 {
		t.Fatal("reserved without a verdict")
	}
	h.assertRuntimeEmpty()

	h.runner.Checker = ExecChecker{Path: checkerBinary(t, actAsChecker)}
	h.enqueue(h.build("bld_crashJOB00000002", 46, nil), 1, nil)
	if !h.runOnce() {
		t.Fatal("the signer stopped claiming after a checker crash")
	}
	if len(h.server.completes) != 1 {
		t.Fatalf("the next job was not signed: rejects %+v; logs:\n%s", h.server.rejects, h.logsString())
	}
}

func TestSocketChecker(t *testing.T) {
	dir, err := os.MkdirTemp("", "sock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "check.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	var served atomic.Int32
	// 模拟 systemd Accept=yes：每个连接一个"检查进程"，stdin/stdout 就是连接
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			served.Add(1)
			go func() {
				defer conn.Close()
				checkwire.Serve(conn, conn, io.Discard)
			}()
		}
	}()
	build := testfixture.NewBuild(t, testfixture.NewBuilder(t), "bld_sockCHECK0000001", 46, nil)
	in := build.Input(t, testfixture.Hex64('c'))
	v, err := SocketChecker{Path: socket, PeerUID: os.Getuid()}.Check(context.Background(), in, writeAPK(t, build.APK))
	if err != nil || !v.OK {
		t.Fatalf("verdict %+v, %v", v, err)
	}
	if _, err := (SocketChecker{Path: filepath.Join(dir, "missing.sock"), PeerUID: os.Getuid()}).Check(context.Background(), in, writeAPK(t, build.APK)); err == nil {
		t.Fatal("a missing socket did not fail")
	}
	// 监听者不是期望的 uid（生产默认 0 = systemd）：连上了也不发送
	before := served.Load()
	if _, err := (SocketChecker{Path: socket, PeerUID: os.Getuid() + 1}).Check(context.Background(), in, writeAPK(t, build.APK)); err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("a socket served by another uid: %v", err)
	}
	// socket 文件对组可写：谁都能换掉监听者
	if err := os.Chmod(socket, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := (SocketChecker{Path: socket, PeerUID: os.Getuid()}).Check(context.Background(), in, writeAPK(t, build.APK)); err == nil {
		t.Fatal("a group-writable socket was used")
	}
	// 数连接不能在拒绝之后立刻读计数：监听协程是异步 Accept 的，慢机器上（CI）计数还没加上。
	// 改回 0600 再做一次正常检查——它要等监听协程 Accept 并回了结论才返回，而 Accept 按到达顺序，
	// 所以它返回时，前面 uid 那次的连接一定已经计过数。uid 那次连了、路径那次没连，就恰好多 2。
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := (SocketChecker{Path: socket, PeerUID: os.Getuid()}).Check(context.Background(), in, writeAPK(t, build.APK)); err != nil || !v.OK {
		t.Fatalf("verdict after restoring the socket mode %+v, %v", v, err)
	}
	if got := served.Load(); got != before+2 {
		t.Fatalf("connections after the rejected checks: %d, want %d (the uid check connects, the path check does not)", got, before+2)
	}
}
