package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 停机标记与升级失败记录（设计 ios-mac-builders-home-network-2026-09-18 §4.1、§5.6）。
//
// macOS 的 launchd 与 systemd 有一处不同：systemd 能按退出码决定重不重启
// （RestartPreventExitStatus），launchd 不能——它只会看到"进程没了"，然后立刻拉起来。
// 一个要求升级就退出的代理在 launchd 下会变成每秒重启一次。
//
// 所以退出之前先写一个**标记文件**，plist 里用 KeepAlive.PathState 说"这个文件在就别拉起
// 我"。root 的升级程序换完二进制之后删掉它，launchd 随即把新版拉起来。
const (
	haltFileName          = "halt"
	upgradeFailedFileName = "upgrade-failed.json"
	// exitUpgradeRequired：服务端要求升级时的退出码。与"配置不全"（2）和"机器被吊销"
	// （77）分开，好让日志里一眼看出这次退出是计划内的
	exitUpgradeRequired = 75
)

// haltPath 是停机标记的路径。它在状态目录里（控制进程能写），而升级程序以 root 跑，
// 读得到也删得掉。
func haltPath(stateDir string) string { return filepath.Join(stateDir, haltFileName) }

// writeHalt 写停机标记。内容是一行原因，给人看，也给升级程序看——`upgrade:<提交>`
// 那一行就是它要装的版本。
//
// 写不成也要照常退出：写不成的后果是 launchd 把旧版拉回来接着跑（而不是升级），
// 那比"退不出去"好。
func writeHalt(stateDir, reason string) error {
	line := strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	if line == "" {
		line = "halt"
	}
	return os.WriteFile(haltPath(stateDir), []byte(line+"\n"), 0o644)
}

// upgradeHaltReason 是"去装这一版"的停机原因。升级程序按这个前缀取目标提交。
func upgradeHaltReason(commit string) string { return "upgrade:" + commit }

// upgradeFailure 是升级程序失败时留下的记录。
type upgradeFailure struct {
	Commit string `json:"commit"`
	Error  string `json:"error"`
	At     string `json:"at"`
}

// readUpgradeFailure 读上一次升级失败的记录。
//
// **为什么要读它**：升级由 root 的那个程序做，它失败的时候代理还在跑旧版——控制台上
// 看到的只是"这台机器的版本一直追不上审批值"，不说原因就只能上机器看日志。读出来打进
// 日志，并随认领报给服务端。
//
// 没有这个文件是正常状态，不是错误。
func readUpgradeFailure(stateDir string) (upgradeFailure, bool) {
	var failure upgradeFailure
	raw, err := os.ReadFile(filepath.Join(stateDir, upgradeFailedFileName))
	if err != nil {
		return failure, false
	}
	if len(raw) > 8<<10 || json.Unmarshal(raw, &failure) != nil {
		return upgradeFailure{Error: "the upgrade helper left an unreadable " + upgradeFailedFileName}, true
	}
	if strings.TrimSpace(failure.Error) == "" {
		return failure, false
	}
	return failure, true
}

// summary 是报给服务端与打进日志的那一句话。
func (f upgradeFailure) summary() string {
	commit := strings.TrimSpace(f.Commit)
	if commit == "" {
		commit = "(unknown commit)"
	}
	at := strings.TrimSpace(f.At)
	if at == "" {
		at = "(unknown time)"
	}
	return fmt.Sprintf("upgrading to %s failed at %s: %s", firstRunes(commit, 64), at, firstRunes(f.Error, 200))
}

// writeUpgradeFailure 由升级程序调用，记下这一次失败。
func writeUpgradeFailure(stateDir, commit string, cause error, at time.Time) error {
	if cause == nil {
		return errors.New("an upgrade failure needs a cause")
	}
	raw, err := json.Marshal(upgradeFailure{
		Commit: commit, Error: firstRunes(cause.Error(), 400), At: at.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, upgradeFailedFileName), append(raw, '\n'), 0o644)
}

// clearUpgradeFailure 在升级成功之后删掉那条记录。
func clearUpgradeFailure(stateDir string) {
	_ = os.Remove(filepath.Join(stateDir, upgradeFailedFileName))
}
