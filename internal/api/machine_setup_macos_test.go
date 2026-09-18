package api

import "strings"
import "testing"

// 装机命令是人照着敲的那几行。那个 sha256 必须留成尖括号占位：控制台一旦替人填上，
// 这台 Mac 的信任根就变成了"服务端说的"，而它将持有全部租户的签名材料（设计 §4.5）。
func TestMacOSInstallCommandKeepsTheOutOfBandDigestBlank(t *testing.T) {
	command := macOSInstallCommand("https://api.example.com", "rne_abc")
	for _, want := range []string{
		"curl -fsSLo install-macos.sh https://api.example.com/v1/machine-setup/install-macos.sh",
		"shasum -a 256 install-macos.sh",
		"--server https://api.example.com --code rne_abc",
		"--release-key-sha256 <",
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("install command is missing %q:\n%s", want, command)
		}
	}
	// 管道执行等于"下载完就跑"，正是这条命令要避免的
	if strings.Contains(command, "| sudo bash") {
		t.Fatalf("the macOS install command must not pipe into a shell:\n%s", command)
	}
	// 每个反斜杠续行后面必须真的换行，否则粘进终端是一条跑不起来的命令
	for _, line := range strings.Split(command, "\n") {
		if strings.HasSuffix(line, "\\") && strings.TrimSpace(line) == "\\" {
			t.Fatalf("empty continuation line in:\n%s", command)
		}
	}
	// 归档摘要与 allowed_signers 摘要都由脚本从验过签的清单里取，不该再要人抄
	for _, gone := range []string{"--expect-sha256", "--allowed-signers-sha256"} {
		if strings.Contains(command, gone) {
			t.Fatalf("%s should no longer be asked of the operator:\n%s", gone, command)
		}
	}
	if lines := strings.Count(command, "\n"); lines != 3 {
		t.Fatalf("expected 4 lines, got %d:\n%s", lines+1, command)
	}
}
