package backupbundle

import (
	"strings"
	"testing"
	"time"
)

// 名字里带产出时间：编号是数据库自增的，换一个数据库就从 1 重来，只靠编号会重名。
// 时间放在编号前面，桶里按名字排就是按时间排。
func TestPackageBaseNameCarriesTheProductionTime(t *testing.T) {
	at := time.Date(2026, 9, 16, 10, 24, 5, 0, time.FixedZone("CST", 8*3600))
	got := PackageBaseName(1, at, "AB")
	if got != "backup-20260916T022405Z-00000001-AB" {
		t.Errorf("名字 %q——时间要换成 UTC、放在编号前面", got)
	}
	earlier := PackageBaseName(99, at.Add(-time.Hour), "AB")
	if !(earlier < got) {
		t.Errorf("按名字排应当就是按时间排：%q 应在 %q 之前", earlier, got)
	}
	if strings.ContainsAny(got, ":/ ") {
		t.Errorf("名字里不能有冒号、斜杠或空格，下载到 Windows 上会出问题: %q", got)
	}
}
