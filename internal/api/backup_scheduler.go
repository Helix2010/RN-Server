package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
)

// BackupScheduler 是备份的后台节拍（设计 §8.5）。
//
// 它做两件事，每分钟一次：
//
//  1. **回收超时的记录。** 认领超时（pending 超过 15 分钟没被领走）必须跑在
//     服务端自己的定时器上——它的触发条件恰恰是「打包机不轮询了」。这个仓库的
//     既定做法正好会把它做错：claimBuildJob 的注释写着「挂在这条路径上而不是
//     另起一个后台循环」，照抄就死，那条 pending 会**永远**占着 live_slot，
//     此后每一次定时都撞 1062、每一次「立即备份」都 409，而平台没有告警。
//
//  2. **到点了就建一条定时待办。** 到没到点**由库决定**，不是 ticker 的相位：
//     time.NewTicker(interval) 的相位从进程启动算起，BACKUP_INTERVAL_HOURS=24
//     加上每天一次部署 = **一次都不会跑**，而控制台上「上次成功时间」一直是空的，
//     没人会把它和部署节奏联系起来。这是本方案最坏的一类失败：以为有备份，其实没有。
//
// 先例：push.Dispatcher.Run 在第一行就跑一条纯时间列的 UPDATE 把上一次进程留下的
// 在途任务收回来，同样不依赖任何内存状态。
type BackupScheduler struct {
	server *server
	tick   time.Duration
}

// NewBackupScheduler 造一个调度器。cfg 与 db 必须和 HTTP 服务端用同一份。
func NewBackupScheduler(cfg config.Config, db *sql.DB) *BackupScheduler {
	return &BackupScheduler{server: &server{cfg: cfg, db: db}, tick: time.Minute}
}

// Run 一直跑到 ctx 结束。
func (b *BackupScheduler) Run(ctx context.Context) {
	// 不看 cfg.Backup.Enabled()：那只看 env，桶在控制台上配的部署里它恒为 false，
	// 调度器会整个不跑——包括回收。那样一条没人领的 pending 会永远占着闸，此后
	// 「立即备份」一直 409。回收只是两条带索引的 UPDATE，没投用的部署跑它也不花什么
	slog.Info("platform backup scheduler started",
		"intervalHours", b.server.cfg.Backup.IntervalHours, "instanceId", b.server.cfg.Backup.InstanceID)

	// 启动时先回收一次：上一次进程可能正卡在回滚窗口里，那条记录停在 running
	// 而没有任何东西会去动它
	b.once(ctx)

	ticker := time.NewTicker(b.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("platform backup scheduler stopped")
			return
		case <-ticker.C:
			b.once(ctx)
		}
	}
}

func (b *BackupScheduler) once(ctx context.Context) {
	// 每一轮都给自己一个短超时：数据库卡住时不要把整个调度器拖死
	work, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if reaped, err := b.server.reapBackupRuns(work); err != nil {
		slog.Error("reaping stale backup runs failed", "error", err)
	} else if reaped > 0 {
		slog.Warn("timed out backup runs were failed", "count", reaped)
	}
	// 判死只写库，暂存还在盘上——一条被判死的备份会留下最多两份 512 MiB 的密文。
	// 它们是密文、服务端读不懂，但这台机器同时在构建 APK，磁盘被占满倒下的不止
	// 备份。扫一遍而不是让 reap 逐条清：这样进程崩过之后的残留也一起收掉
	b.server.sweepBackupStaging(work)
	b.maybeSchedule(work)
}

func (b *BackupScheduler) maybeSchedule(ctx context.Context) {
	interval := b.server.cfg.Backup.IntervalHours
	if interval <= 0 {
		return
	}
	last, err := b.server.lastScheduledBackupAt(ctx)
	if err != nil {
		slog.Error("cannot tell when the last scheduled backup ran", "error", err)
		return
	}
	if !last.IsZero() && time.Since(last) < time.Duration(interval)*time.Hour {
		return
	}
	_, err = b.server.createBackupRun(ctx, "schedule", backupScheduleActor, backupScheduleReason)
	switch {
	case err == nil:
		slog.Info("a scheduled backup was queued", "intervalHours", interval)
	case isBackupInFlightError(err):
		// 多实例下第二个实例会吃这个。这是**正常**的，不是错误——当成
		// 「别人已经建过了」静默吞掉。每分钟一条 ERROR 会把人训练到无视日志
		slog.Debug("another instance already queued this scheduled backup")
	default:
		slog.Error("queueing a scheduled backup failed", "error", err)
	}
}

func isBackupInFlightError(err error) bool { return errors.Is(err, errBackupInFlight) }
