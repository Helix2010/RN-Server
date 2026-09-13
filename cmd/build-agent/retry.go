package main

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"
)

// retryLater 标记"这次失败值得再试一次"。
//
// 分清楚这件事是有代价差别的：传输层错误、5xx、429 都是"现在不行，等会儿可能行"，
// 而 4xx 是服务端明确的拒绝（版本号没涨、令牌不对、任务已经不在跑了），重试一百次
// 也是同一个答案，只是把失败原因推迟几分钟才送到人眼前。
type retryLater struct{ err error }

func (e retryLater) Error() string { return e.err.Error() }
func (e retryLater) Unwrap() error { return e.err }

func worthRetrying(err error) bool {
	var later retryLater
	return errors.As(err, &later)
}

// withRetry 重试一件值得重试的事，退避到分钟级。
//
// 用在产物回传上：那时候包已经编出来了，六分钟的构建、一个 build 号、一次签名都在
// 里面，为一次 502 全扔掉不值当。多等几分钟不浪费任何东西。
//
// 每一次重试都写进日志缓冲，管理端的日志尾部能看到"传第几次"——否则界面上只是静止
// 几分钟，没人知道它在干什么。
// 退避的起点。做成变量只是为了测试能把它调小——重试一次就等五秒的测试没人愿意跑。
var retryBaseDelay = 5 * time.Second

func withRetry(ctx context.Context, buf *logBuffer, what string, attempts int, send func(context.Context) error) error {
	delay := retryBaseDelay
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err = send(ctx); err == nil {
			return nil
		}
		if !worthRetrying(err) {
			return err
		}
		if attempt == attempts {
			break
		}
		buf.add(what + " failed (attempt " + strconv.Itoa(attempt) + "), retrying: " + err.Error())
		slog.Warn("retrying "+what, "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		if delay < 2*time.Minute {
			delay *= 2
		}
	}
	return err
}
