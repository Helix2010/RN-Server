package api

import (
	"strings"
	"unicode/utf8"
)

// sanitizeReportedText 清洗构建机与签名闸上报的自由文本（failureReason、logTail、签名闸的
// detail 与 error）。这些文字会显示在控制台上、写进审计，而上报方是按不可信处理的机器：
//
//   - C0 控制字符（保留 \t）、DEL、C1 控制字符去掉：ANSI 转义能清屏、改颜色，\r\n 能在一行里
//     伪造出"下一条日志"；
//   - Unicode 双向覆盖与隔离字符（U+202A–U+202E、U+2066–U+2069）和方向标记（U+200E、U+200F）
//     去掉：它们能让 "gnp.exe" 显示成 "exe.png"，或把一句话的后半段倒过来读。
//
// 不合法的 UTF-8 字节换成 U+FFFD（JSON 列只收合法 UTF-8）。
func sanitizeReportedText(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return r
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return -1
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
			return -1
		}
		return r
	}, text)
}

// clipBytes 把字符串截到至多 max 个字节，不切断 UTF-8 字符。
func clipBytes(text string, max int) string {
	if len(text) <= max {
		return text
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
