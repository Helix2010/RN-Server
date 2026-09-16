package main

import (
	"bufio"
	"errors"
	"io"
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

// maxLogLine 是一行日志保留的最大字节数。超长的行截断，剩下的丢掉——但一定读完，
// 否则子进程写满管道就会卡死。
const maxLogLine = 4096

// streamLines 把 r 按行读进 buf，直到 EOF。执行进程的输出是不可信文本：控制字符
// （终端转义序列）替换掉，超长行截断，读取本身不设行数上限。
func streamLines(r io.Reader, buf *logBuffer, onLine func(string)) {
	reader := bufio.NewReaderSize(r, maxLogLine)
	var pending []byte
	truncated := false
	flush := func() {
		line := sanitizeLine(string(pending))
		if truncated {
			line += " …"
		}
		buf.add(line)
		if onLine != nil {
			onLine(line)
		}
		pending, truncated = pending[:0], false
	}
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			room := maxLogLine - len(pending)
			if room > 0 {
				if len(chunk) > room {
					pending = append(pending, chunk[:room]...)
					truncated = true
				} else {
					pending = append(pending, chunk...)
				}
			} else {
				truncated = true
			}
		}
		switch {
		case err == nil:
			flush()
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			if len(pending) > 0 {
				flush()
			}
			// 读错误（管道被关）：把剩下的丢掉就是了
			_, _ = io.Copy(io.Discard, r)
			return
		}
	}
}

func sanitizeLine(s string) string {
	s = strings.TrimRight(s, "\r\n")
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
