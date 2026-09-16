package api

import (
	"context"
	"database/sql"
	"time"
)

// rowsMatched 回答一条按条件更新单行的 UPDATE 有没有命中那一行。
//
// MySQL 的 RowsAffected 默认是"值真的变了的行数"（驱动没开 clientFoundRows）：SET 的每个值都与原值
// 相同时是 0，而条件其实满足。时间列是毫秒精度，同一毫秒里重复的心跳、重复提交同一个值就是这样——
// 把 0 当成"条件不满足"，会把一次正常的心跳误判成 BUILD_ATTEMPT_STALE / SIGN_ATTEMPT_STALE，
// 或把一次重复提交误判成"状态已变"。
//
// affected=0 时按同样的条件（where 与 args，调用方传 UPDATE 用的那一组）再查一次：行还满足条件，就是
// "命中了但没有变化"。复查带 FOR SHARE 读最新提交的值：在事务里调用时，UPDATE 已经锁住了命中的行，
// 结论是准确的；不在事务里时，两条语句之间行可能刚被别人改掉——那时报"没命中"，与晚一点到达的同一个
// 请求得到的结果一样。
//
// 不在连接上统一开 clientFoundRows：那会改掉全仓所有 RowsAffected 的含义，包括依赖"0 = 没有变化"的
// INSERT … ON DUPLICATE KEY UPDATE（例如本地化种子的计数）。table 与 where 只能是代码里的常量。
func rowsMatched(ctx context.Context, q rowQuerier, result sql.Result, table, where string, args ...any) (bool, error) {
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected != 0 {
		return affected == 1, nil
	}
	var count int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE `+where+` FOR SHARE`, args...).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

// now 是处理函数取"现在"的地方（UTC）。测试注入固定时钟，才能不靠机器快慢地复现同一毫秒里的两次写。
func (s *server) now() time.Time {
	if s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}
