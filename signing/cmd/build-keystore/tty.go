//go:build linux || darwin

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// ttyPassphrase 从 /dev/tty 读口令，读的时候关掉回显。
type ttyPassphrase struct {
	f *os.File
	r *bufio.Reader
}

// openTTYPassphrase 要求标准输入是终端，然后打开 /dev/tty（口令不经过可能被重定向的 stdin/stdout）。
func openTTYPassphrase(stdin *os.File) (passphraseSource, error) {
	if !isTerminal(stdin.Fd()) {
		return nil, errNotTTY
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("%w（打不开 /dev/tty: %v）", errNotTTY, err)
	}
	if !isTerminal(f.Fd()) {
		f.Close()
		return nil, errNotTTY
	}
	return &ttyPassphrase{f: f, r: bufio.NewReaderSize(f, 4096)}, nil
}

func (t *ttyPassphrase) Close() error { return t.f.Close() }

func (t *ttyPassphrase) ReadPassphrase(prompt string) ([]byte, error) {
	old, err := getTermios(t.f.Fd())
	if err != nil {
		return nil, fmt.Errorf("读终端设置失败: %v", err)
	}
	noEcho := old
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON
	if err := setTermios(t.f.Fd(), &noEcho); err != nil {
		return nil, fmt.Errorf("关闭回显失败: %v", err)
	}
	// Ctrl-C 时先恢复回显再退出，免得把终端留在不回显的状态
	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			_ = setTermios(t.f.Fd(), &old)
			_, _ = io.WriteString(t.f, "\n")
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		signal.Stop(sigs)
		_ = setTermios(t.f.Fd(), &old)
		_, _ = io.WriteString(t.f, "\n")
	}()
	if _, err := io.WriteString(t.f, prompt); err != nil {
		return nil, err
	}
	return readSecretLine(t.r)
}

// readSecretLine 读一行（去掉结尾的 \n 或 \r\n）。超长报错；错误信息不含输入内容。
func readSecretLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			wipe(line)
			if errors.Is(err, io.EOF) {
				return nil, errors.New("没有读到口令（输入被关闭）")
			}
			return nil, err
		}
		if b == '\n' {
			break
		}
		if len(line) > 1024 {
			wipe(line)
			return nil, errors.New("口令太长")
		}
		line = append(line, b)
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, nil
}
