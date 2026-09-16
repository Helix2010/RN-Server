package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/Helix2010/RN-Server/signing/internal/checkwire"
	"github.com/Helix2010/RN-Server/signing/internal/securefs"
	"github.com/Helix2010/RN-Server/signing/policy"
)

// Checker 把策略输入与 APK 交给隔离的检查进程，取回结论。
// 任何错误（进程崩溃、超时、协议错误）都意味着"没有结论"，调用方按临时错误处理。
type Checker interface {
	Check(ctx context.Context, in policy.Input, apkPath string) (policy.Verdict, error)
}

const checkTimeout = 5 * time.Minute

// SocketChecker 连 systemd socket 激活的检查进程（生产）。
type SocketChecker struct {
	Path string
	// PeerUID 是创建并监听这个 socket 的进程必须具有的 uid。生产里 socket 由 systemd 创建，
	// 零值 0 即 root；这样即使 socket 路径被换成别人监听的 socket，签名闸也不会把包和策略
	// 输入交给它、更不会采信它的结论。测试里设成测试进程自己的 uid。
	PeerUID int
	Timeout time.Duration
}

// Check 实现 Checker。
func (s SocketChecker) Check(ctx context.Context, in policy.Input, apkPath string) (policy.Verdict, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = checkTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	f, err := os.Open(apkPath)
	if err != nil {
		return policy.Verdict{}, err
	}
	defer f.Close()
	if err := securefs.CheckTrustedPath(s.Path); err != nil {
		return policy.Verdict{}, fmt.Errorf("checker socket: %w", err)
	}
	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, "unix", s.Path)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("connect to the checker socket: %w", err)
	}
	defer c.Close()
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return policy.Verdict{}, errors.New("the checker socket is not a unix socket")
	}
	if err := checkPeerUID(conn, s.PeerUID); err != nil {
		return policy.Verdict{}, err
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := checkwire.WriteRequest(conn, in, f); err != nil {
		return policy.Verdict{}, fmt.Errorf("send to the checker: %w", err)
	}
	if err := conn.CloseWrite(); err != nil {
		return policy.Verdict{}, err
	}
	verdict, err := checkwire.ReadVerdict(conn)
	if err != nil {
		return policy.Verdict{}, fmt.Errorf("the checker returned no usable verdict (it may have crashed): %w", err)
	}
	return verdict, nil
}

// ExecChecker 以子进程启动检查进程（只用于本地测试，没有 systemd 提供的隔离）。
type ExecChecker struct {
	Path      string
	Timeout   time.Duration
	WaitDelay time.Duration // 零值用 childWaitDelay
}

// Check 实现 Checker。子进程环境为空（env -i），不继承签名闸的令牌。
func (e ExecChecker) Check(ctx context.Context, in policy.Input, apkPath string) (policy.Verdict, error) {
	timeout := e.Timeout
	if timeout == 0 {
		timeout = checkTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	f, err := os.Open(apkPath)
	if err != nil {
		return policy.Verdict{}, err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, e.Path)
	cmd.WaitDelay = e.WaitDelay
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = childWaitDelay
	}
	cmd.Env = []string{}
	cmd.Dir = "/"
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return policy.Verdict{}, err
	}
	var stdout limitedBuffer
	stdout.max = checkwire.MaxVerdict + 1
	var stderr limitedBuffer
	stderr.max = 8 << 10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return policy.Verdict{}, fmt.Errorf("start the checker: %w", err)
	}
	writeErr := make(chan error, 1)
	go func() {
		err := checkwire.WriteRequest(stdin, in, f)
		if closeErr := stdin.Close(); err == nil {
			err = closeErr
		}
		writeErr <- err
	}()
	waitErr := cmd.Wait()
	sendErr := <-writeErr
	if waitErr != nil {
		return policy.Verdict{}, fmt.Errorf("the checker failed (%v): %s", waitErr, cleanText(stderr.String(), 300))
	}
	if sendErr != nil && !errors.Is(sendErr, os.ErrClosed) {
		return policy.Verdict{}, fmt.Errorf("send to the checker: %w", sendErr)
	}
	verdict, err := checkwire.ReadVerdict(bytes.NewReader(stdout.Bytes()))
	if err != nil {
		return policy.Verdict{}, err
	}
	return verdict, nil
}

// limitedBuffer 最多保留 max 字节，之后的写入丢弃（不阻塞子进程）。
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*limitedBuffer)(nil)
