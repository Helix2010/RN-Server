package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// pnpm install 挂死的看门狗。
//
// 2026-09-23 mac-01 build 24：`pnpm install` 打完 "downloaded 1195, added 1195" 之后整整
// 50 分钟一行输出都没有——最后一个 tarball 的连接挂住了，pnpm 自己的超时没管用。任务的总时限
// （BUILD_AGENT_TIMEOUT_MINUTES）必须容得下一次完整的 iOS archive（七八十分钟），所以它兜不住
// 这种"前五分钟就已经死了"的情况；控制台上也停不掉，最后是有人上 Mac 去 pkill 的。
//
// pnpm install 在干活时会一直打进度（resolved/downloaded/added 的计数、每个包的 postinstall），
// 正常情况下几秒一行。连续 installIdleLimit 没有任何输出就当挂死：停下、再来一次。第二次复用
// 这个任务的 pnpm store 里已经下好的包，只补剩下的那几个。
//
// 只看 pnpm install，不看 `pnpm ios:release`：后者里 xcodebuild 的输出写进文件
// （RN-App scripts/build-ios-release.mjs），一次 archive 会有一个多小时一行都不打，那是正常的。

// installIdleLimit 是 pnpm install 连续没有输出多久算挂死。变量是为了测试能调短。
var installIdleLimit = 10 * time.Minute

// installAttempts：挂死之后再来一次就够了。连着两次都挂，多半是网络真的断了，
// 再试也只是把一个注定失败的任务拖得更久。
const installAttempts = 2

var errInstallIdle = errors.New("pnpm install printed nothing for too long")

// outputDrainGrace：进程退出之后，等它最后那点输出转写完的时间。留下的后台进程握着管道时
// 不会有 EOF，过了这个时间就不等了（那些进程由任务结束时的清理回收）。
const outputDrainGrace = 2 * time.Second

// install 跑 `pnpm install --frozen-lockfile`，挂死就停下重来一次。别的失败原样返回，不重试：
// 锁文件对不上、包签名验不过这类错误重跑一次结果不会变。
func (j job) install(ctx context.Context) error {
	var err error
	for attempt := 1; attempt <= installAttempts; attempt++ {
		err = j.runWatched(ctx, installIdleLimit, "pnpm", "install", "--frozen-lockfile")
		if err == nil || !errors.Is(err, errInstallIdle) || ctx.Err() != nil {
			return err
		}
		if attempt < installAttempts {
			logf(j.out, "pnpm install printed nothing for %s; stopping it and trying once more (packages already in this job's store are kept)", installIdleLimit)
		}
	}
	return err
}

// runWatched 同 run，另外盯着输出：连续 idle 没有新输出就把命令停掉，返回 errInstallIdle。
func (j job) runWatched(ctx context.Context, idle time.Duration, name string, args ...string) error {
	watchCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	cmd, err := j.command(watchCtx, name, args...)
	if err != nil {
		return err
	}
	// 输出经一根**自己建的**管道转写并计时。不能直接把 activityWriter 交给 exec：它不是
	// *os.File，exec 会自己建管道并在 Wait 里等管道读完——pnpm 留下的后台进程握着写端不放时，
	// Wait 就一直卡到 WaitDelay，然后报 "WaitDelay expired before I/O complete" 判构建失败
	// （cmd/build-agent 的 TestLingeringProcessHoldingTheOutputDoesNotHangTheAgent 防的正是这个）。
	// 交给 exec 的是 *os.File，Wait 在进程退出时就回来；转写的尾巴最多再等 outputDrainGrace。
	logf(j.out, "$ %s", name+" "+strings.Join(args, " "))
	activity := newActivityWriter(j.out)
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout = writer
	cmd.Stderr = writer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		defer reader.Close()
		_, _ = io.Copy(activity, reader)
	}()

	done := make(chan struct{})
	go func() {
		tick := idle / 4
		if tick > 30*time.Second {
			tick = 30 * time.Second
		}
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if activity.quietFor() >= idle {
					stop(errInstallIdle)
					return
				}
			}
		}
	}()
	if err := cmd.Start(); err != nil {
		writer.Close()
		close(done)
		return fmt.Errorf("%s could not start: %w", filepath.Base(cmd.Path), err)
	}
	// 父进程这一端的写端要关掉，否则管道永远读不到 EOF
	writer.Close()
	err = cmd.Wait()
	close(done)
	select {
	case <-drained:
	case <-time.After(outputDrainGrace):
	}
	// 从这里起不再往 j.out 写：后台进程还握着管道的话，它后来的输出直接丢掉，
	// 不与之后的日志行交错（也不和它们抢同一个 writer）
	activity.detach()
	if err != nil {
		err = fmt.Errorf("%s failed: %w", filepath.Base(cmd.Path), err)
	}
	if errors.Is(context.Cause(watchCtx), errInstallIdle) && ctx.Err() == nil {
		return fmt.Errorf("%w (%s): %v", errInstallIdle, idle, err)
	}
	return err
}

// activityWriter 原样转写，并记下最后一次写入的时刻。detach 之后只计时、不再转写。
type activityWriter struct {
	w        io.Writer
	mu       sync.Mutex
	last     time.Time
	detached bool
}

func newActivityWriter(w io.Writer) *activityWriter {
	return &activityWriter{w: w, last: time.Now()}
}

func (a *activityWriter) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = time.Now()
	if a.detached {
		return len(p), nil
	}
	return a.w.Write(p)
}

func (a *activityWriter) detach() {
	a.mu.Lock()
	a.detached = true
	a.mu.Unlock()
}

func (a *activityWriter) quietFor() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.last)
}
