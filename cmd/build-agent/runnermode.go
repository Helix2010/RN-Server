package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// runnerModeFile 记下常驻进程最近一次启动时执行进程是怎么跑的。
//
// BUILD_AGENT_RUNNER_USER=- 让执行进程与控制进程同一个用户：第三方构建代码读得到本机令牌和
// 出处私钥，这台机器交付的出处声明就不再可信。它只许本地测试用，但它是一个显式配置、不是
// 回退，所以代码不拒绝它；能做的是让它无处藏身——启动日志、每个任务的日志，以及运维在
// 签名闸上 trust-builder 之前要跑的 show-key 都把它打出来。show-key 读不到 env 文件
// （root 0600），所以由常驻进程把这个状态写进状态目录。
const runnerModeFile = "runner-mode.json"

type runnerMode struct {
	RunnerUser string `json:"runnerUser"`
	Separated  bool   `json:"separated"`
	RecordedAt string `json:"recordedAt"`
}

// recordRunnerMode 以临时文件加 rename 写入（0600）。
func recordRunnerMode(stateDir string, cfg config, now time.Time) error {
	raw, err := json.Marshal(runnerMode{RunnerUser: cfg.RunnerUser, Separated: cfg.runnerSeparated(), RecordedAt: now.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	tmp := filepath.Join(stateDir, runnerModeFile+".tmp")
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(stateDir, runnerModeFile))
}

// describeRunnerMode 给 show-key 用，只读。
func describeRunnerMode(stateDir string) string {
	path := filepath.Join(stateDir, runnerModeFile)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return "unknown (the build agent has not started with this state directory yet)"
	}
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || checkPrivate(path, info, false) != nil {
		return "unknown (" + path + " is not a private regular file)"
	}
	var mode runnerMode
	raw, _ := io.ReadAll(io.LimitReader(file, 4096))
	if json.Unmarshal(raw, &mode) != nil {
		return "unknown (" + path + " is not readable)"
	}
	if !mode.Separated {
		return fmt.Sprintf("!!! SAME USER AS THE BUILD AGENT (BUILD_AGENT_RUNNER_USER=%s, last start %s): third-party build code can read the machine token and this provenance key. Local testing only; never trust this machine on a signer !!!",
			mode.RunnerUser, mode.RecordedAt)
	}
	return fmt.Sprintf("separate user %s via sudo (last start %s)", mode.RunnerUser, mode.RecordedAt)
}
