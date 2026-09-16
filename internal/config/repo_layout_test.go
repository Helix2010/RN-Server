package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// internal/ 下不该有 package main。
//
// 这个仓库已经吃过一次，而且是同一次提交里吃了两回：评审备份功能时写了两个临时
// 程序（一个验伪造、一个量包体尺寸），两个都自己标着"用完即删"，然后被一条
// `git add -A` 一起扫进了提交。它们编译得过、测试也全绿，没有任何东西会红——
// 直到有人在生产源码树里翻到一个攻击脚本。
//
// 真正的可执行程序全在 cmd/ 下。所以"internal/ 里出现 package main"这个信号，
// 除了临时程序不会是别的，误报为零。
func TestInternalHasNoCommandPrograms(t *testing.T) {
	var found []string
	err := filepath.WalkDir("..", func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == "package main" {
				found = append(found, path)
				break
			}
			// 包子句之前只可能是注释和空行，见到别的就说明已经错过了
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "//") {
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历 internal/ 失败: %v", err)
	}
	if len(found) > 0 {
		t.Errorf("internal/ 下出现了 package main，这一般是临时程序被误提交：\n  %s\n"+
			"真要发布的程序请放 cmd/；临时程序请在提交前删掉。",
			strings.Join(found, "\n  "))
	}
}
