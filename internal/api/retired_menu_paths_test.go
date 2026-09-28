package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 拆成两个控制台（2026-09-28）之后没有「平台维护」这个菜单了：平台页面在平台控制台「打包与签名」等分组下，
// 租户看不到平台控制台。服务端报错里再写旧菜单路径，就是把人往不存在的地方领（控制台那边由 RN-Admin 的
// 词典测试守着，这里守服务端自己的文案）。只查「「平台维护」与「平台维护 →」：把平台维护当普通名词用的不算。
func TestServerMessagesDoNotPointAtTheRetiredPlatformMaintenanceMenu(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "「平台维护") || strings.Contains(line, "平台维护 →") {
				t.Errorf("%s:%d still points at the retired 平台维护 menu: %s", file, number+1, strings.TrimSpace(line))
			}
		}
	}
}
