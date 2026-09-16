package signer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	// ErrNotTTY：运维命令必须在交互终端里运行。脚本化的"确认"等于没有确认。
	ErrNotTTY = errors.New("this command must be run by an operator in an interactive terminal (stdin is not a TTY)")
	// ErrControlCharacters：输入里有控制字符（例如粘贴进来的终端转义序列）。
	ErrControlCharacters = errors.New("the input contains control characters")
	// ErrAborted：运维没有按要求输入确认。
	ErrAborted = errors.New("aborted: nothing was written")
)

const maxLineLength = 4096

// Terminal 是运维的交互终端。测试里用假终端。
type Terminal interface {
	io.Writer
	// ReadLine 显示提示并读一行，去掉行尾换行；含控制字符或非 UTF-8 时返回 ErrControlCharacters。
	ReadLine(prompt string) (string, error)
}

// ttyTerminal 从 /dev/tty 读写，不经过 stdin/stdout（它们可能被重定向）。
type ttyTerminal struct {
	f *os.File
	r *bufio.Reader
}

// OpenTerminal 要求 stdin 是 TTY，然后打开 /dev/tty。
func OpenTerminal(stdin *os.File) (Terminal, func() error, error) {
	if !isTerminal(stdin.Fd()) {
		return nil, nil, ErrNotTTY
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: cannot open /dev/tty: %v", ErrNotTTY, err)
	}
	if !isTerminal(f.Fd()) {
		f.Close()
		return nil, nil, ErrNotTTY
	}
	return &ttyTerminal{f: f, r: bufio.NewReaderSize(f, maxLineLength+2)}, f.Close, nil
}

func (t *ttyTerminal) Write(p []byte) (int, error) { return t.f.Write(p) }

func (t *ttyTerminal) ReadLine(prompt string) (string, error) {
	if _, err := io.WriteString(t.f, prompt); err != nil {
		return "", err
	}
	return readLine(t.r)
}

// readLine 读一行并严格清洗。超长、控制字符、非 UTF-8 都拒绝。
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				break
			}
			return "", err
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
		if len(line) > maxLineLength {
			return "", errors.New("the input line is too long")
		}
	}
	text := strings.TrimSuffix(string(line), "\r")
	return text, CheckInputText(text)
}

// CheckInputText 拒绝控制字符、DEL、C1 控制字符与非 UTF-8。
func CheckInputText(s string) error {
	if !utf8.ValidString(s) {
		return ErrControlCharacters
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return ErrControlCharacters
		}
	}
	return nil
}

// ---- 交互辅助 ----

func printf(t Terminal, format string, args ...any) { _, _ = fmt.Fprintf(t, format, args...) }

// ask 读一行，校验不过时最多再给两次机会；控制字符直接失败。
func ask(t Terminal, prompt string, parse func(string) error) (string, error) {
	for tries := 0; ; tries++ {
		line, err := t.ReadLine(prompt)
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		perr := parse(line)
		if perr == nil {
			return line, nil
		}
		if tries == 2 {
			return "", fmt.Errorf("%w: %v", ErrAborted, perr)
		}
		printf(t, "  ✗ %v\n", perr)
	}
}

func askInt(t Terminal, prompt string, min, max int64) (int64, error) {
	var value int64
	_, err := ask(t, prompt, func(s string) error {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < min || n > max || strconv.FormatInt(n, 10) != s {
			return fmt.Errorf("expected a whole number between %d and %d", min, max)
		}
		value = n
		return nil
	})
	return value, err
}

// confirmTyped 要求运维把 expected 原样再输入一次。
func confirmTyped(t Terminal, prompt, expected string) error {
	line, err := t.ReadLine(prompt)
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != expected {
		return ErrAborted
	}
	return nil
}
