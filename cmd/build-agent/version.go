package main

import (
	"fmt"
	"io"
	"regexp"
	"runtime"
)

// commit 是编译进二进制的提交（`-ldflags "-X main.commit=<sha>"`，CI 与
// deploy/setup/build-bundles.sh 两处都要注入，值必须一致）。
//
// 它不是装饰：自升级那条路（设计 ios-mac-builders-home-network-2026-09-18 §5.6）靠它回答
// "这台机器上跑的是哪一版"。平台管理员在控制台批准一个提交之后，认领时带的这个值与批准值
// 不一致，服务端就不派活、回 409 AGENT_UPGRADE_REQUIRED——于是升级总是发生在空闲的时候，
// 正在跑的构建自然做完。
//
// 没注入时是空串，一切照旧（服务端把"没报"与"报了但不一致"分开处理）：手工编译出来的
// 二进制不会因为没有版本号就不能用。
var commit string

// commitPattern：完整的 git 提交 sha。服务端按同一条规则校验，不合规的值不如不报——
// 报一个 "dirty" 上去，控制台会显示成一个永远追不上审批值的版本
var commitPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// agentCommit 返回要报给服务端的提交，注入的值不合规时返回空串。
func agentCommit() string {
	if commitPattern.MatchString(commit) {
		return commit
	}
	return ""
}

// version 打印这台机器上这个二进制的身份。升级脚本在原子替换之后用它确认换上了新的那一个。
func version(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: build-agent version")
		return 2
	}
	printed := commit
	if printed == "" {
		printed = "(not injected at build time)"
	}
	fmt.Fprintf(stdout, "build-agent commit: %s\n", printed)
	fmt.Fprintf(stdout, "go: %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return 0
}
