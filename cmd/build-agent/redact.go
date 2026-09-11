package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

// 日志尾部要进数据库、进管理端界面，而 Gradle 在失败时很乐意把整条命令行打出来，
// 里面就有 keystore 口令。上报前逐行过一遍。
//
// 这里挡的是**值**而不是键名：我们知道这台机器上哪些环境变量是机密，直接把它们的
// 具体取值替换掉，比去猜"哪种写法算是口令"可靠得多。

const redacted = "***"

var secretEnvPattern = regexp.MustCompile(`(?i)(PASSWORD|PASSPHRASE|SECRET|TOKEN|PRIVATE_KEY|KEYSTORE_PASS)`)

// secretValues 收集本进程环境里所有机密变量的取值，长的排前面——先替换长的，
// 否则一个短值可能把长值切成两半而留下后半段。
func secretValues(environ []string) []string {
	values := []string{}
	for _, entry := range environ {
		key, value, found := strings.Cut(entry, "=")
		if !found || len(value) < 6 || !secretEnvPattern.MatchString(key) {
			continue
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

type redactor struct{ values []string }

func newRedactor() *redactor { return &redactor{values: secretValues(os.Environ())} }

func (r *redactor) line(text string) string {
	for _, value := range r.values {
		text = strings.ReplaceAll(text, value, redacted)
	}
	return text
}

func (r *redactor) lines(input []string) []string {
	out := make([]string, len(input))
	for i, line := range input {
		out[i] = r.line(line)
	}
	return out
}
