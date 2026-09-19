package main

// 每一处构建这个二进制的地方都必须打上 -X main.commit。
//
// 不打戳时 agentCommit() 回空串，而版本闸的判据是"已批准 != 空 && 自报 != 已批准 → 409
// 不派活"——**空同样算不相等**。所以只要机群里有一台跑着没打戳的二进制，平台管理员就
// 永远不能用版本闸：钉住任何一版都会把那台机器连同它负责的构建一起挡下来。
//
// 真机上就是这样：amos-builder 在线、正常打 Android 包，但 agentCommit 是 null——因为
// CI 里给 amos 编 build-agent 的那一行只写了 -ldflags="-s -w"。安装包里的那一份一直
// 打着戳（build-bundles.sh），所以这个漏洞只在"不从安装包装的机器"上出现，而那正是
// 机房里那台最老的构建机。

import (
	"os"
	"strings"
	"testing"
)

func TestEveryBuildOfThisBinaryStampsTheCommit(t *testing.T) {
	for _, path := range []string{
		"../../.github/workflows/deploy-amos.yml",
		"../../deploy/setup/build-bundles.sh",
		"../../deploy/build-agent/README.md",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body := string(raw)
		// LDFLAGS 这类变量：同一个文件里定义过 main.commit 就算打了戳
		viaVariable := strings.Contains(body, "main.commit=")
		found := 0
		for i, line := range strings.Split(body, "\n") {
			if !strings.Contains(line, "go build") || !buildsTheAgent(line) {
				continue
			}
			found++
			switch {
			case strings.Contains(line, "main.commit="):
			case strings.Contains(line, "LDFLAGS") && viaVariable:
			default:
				t.Errorf("%s:%d builds ./cmd/build-agent without -X main.commit:\n  %s\n"+
					"An agent that cannot name its own version reports an empty commit, which the version "+
					"gate treats as a mismatch — pinning any version then blocks this machine and everything "+
					"it builds, while the console still shows it online", path, i+1, strings.TrimSpace(line))
			}
		}
		if found == 0 {
			t.Errorf("%s no longer builds ./cmd/build-agent; drop it from this list or the guard is watching nothing", path)
		}
	}
}

// buildsTheAgent 只认控制进程本身，不认 build-runner、ios-upload、upgrade 那几个
// ——自报版本的只有控制进程。
func buildsTheAgent(line string) bool {
	for _, field := range strings.Fields(line) {
		// build-bundles.sh 把这条命令包在子 shell 里，末尾带一个右括号
		if strings.Trim(field, `"'()`) == "./cmd/build-agent" {
			return true
		}
	}
	return false
}
