package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 钥匙串口令的字母表（设计 §4.2）。
//
// 这个口令会出现在交给 `security -i` 的一行命令里。限定字母表不是洁癖：一个带空格或
// 引号的口令会让那一行被切成别的命令，而写这个文件的是装机脚本——它生成的口令本来就
// 只有字母数字和 _-。装机脚本换了写法时，这里要当场失败，而不是把一条拼歪的命令送出去。
func TestKeychainPasswordAlphabetIsEnforced(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		t.Helper()
		path := filepath.Join(dir, "pw")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := strings.Repeat("aB3_-", 5)
	if password, err := readKeychainPassword(write(good + "\n")); err != nil || password != good {
		t.Fatalf("a valid password was refused: %q %v", password, err)
	}
	for name, content := range map[string]string{
		"empty":                 "",
		"too short":             "short",
		"space":                 strings.Repeat("a", 20) + " x",
		"quote":                 strings.Repeat("a", 20) + `"`,
		"newline in the middle": "aaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbb",
		"semicolon":             strings.Repeat("a", 20) + ";id",
	} {
		if _, err := readKeychainPassword(write(content)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := readKeychainPassword(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing password file was accepted")
	}
}
