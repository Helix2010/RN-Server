package main

import (
	"bytes"
	"strings"
	"sync"
	"unicode"
)

// logBuffer 只留尾部若干行。它随心跳进服务端、进管理端界面；完整输出不落盘。
type logBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	red   *redactor
}

func newLogBuffer(red *redactor) *logBuffer {
	return &logBuffer{max: 200, red: red}
}

func (b *logBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, b.red.line(line))
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

// maxLogLine 是一行日志保留的最大字节数，超长的行截断。
const maxLogLine = 4096

// lineWriter 把子进程输出按行收进日志。它当 exec.Cmd 的 Stdout/Stderr 用（不用 StdoutPipe）：
// 这样 cmd.WaitDelay 能在进程退出后强制关掉管道——执行进程留下的后台进程握着输出管道不放时，
// 控制进程不会一直卡在读上。输出是不可信文本：控制字符替换掉，超长行截断。
//
// exec 保证 Stdout 与 Stderr 是同一个可比较的 writer 时同一时刻只有一个 goroutine 调 Write。
type lineWriter struct {
	buf       *logBuffer
	onLine    func(string)
	pending   []byte
	truncated bool
}

func newLineWriter(buf *logBuffer, onLine func(string)) *lineWriter {
	return &lineWriter{buf: buf, onLine: onLine}
}

func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		chunk, rest, newline := bytes.Cut(p, []byte{'\n'})
		p = rest
		if room := maxLogLine - len(w.pending); len(chunk) > room {
			if room > 0 {
				w.pending = append(w.pending, chunk[:room]...)
			}
			w.truncated = true
		} else {
			w.pending = append(w.pending, chunk...)
		}
		if newline {
			w.flush()
		}
	}
	return n, nil
}

// Close 把最后一段没有换行的输出也收进来。只在 cmd.Wait 返回之后调。
func (w *lineWriter) Close() {
	if len(w.pending) > 0 || w.truncated {
		w.flush()
	}
}

func (w *lineWriter) flush() {
	line := sanitizeLine(string(w.pending))
	if w.truncated {
		line += " …"
	}
	w.buf.add(line)
	if w.onLine != nil {
		w.onLine(line)
	}
	w.pending, w.truncated = w.pending[:0], false
}

func sanitizeLine(s string) string {
	s = strings.TrimRight(s, "\r")
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r == unicode.ReplacementChar || unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}
