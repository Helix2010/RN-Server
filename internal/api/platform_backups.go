package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// platform_backups 的状态机（设计 platform-backup-recovery-2026-09-15 §8.5）。
//
// 四个写方都要动同一行：控制台建待办、打包机认领、服务端收尾、超时扫描。
// **每一条转换都写成带状态条件的 UPDATE 并检查 RowsAffected**，先例是
// markBuildJobFailed 的 WHERE status IN (…)。不加 CAS 的具体后果：payload 第 2 分钟
// 到达，服务端开始封外层加上传；第 30 分钟产出超时扫描判 failed；第 31 分钟上传完成，
// 服务端无条件写 succeeded——一条本该 failed 的记录变成 succeeded，而 failure_reason
// 还留着。反过来也成立。
const (
	backupStatusPending   = "pending"
	backupStatusRunning   = "running"
	backupStatusSucceeded = "succeeded"
	backupStatusFailed    = "failed"

	// backupClaimTimeout：pending 超过这么久没被认领就判死。触发条件恰恰是
	// 「打包机不轮询了」，所以这个扫描**必须跑在服务端自己的定时器上**，
	// 不能照抄 claimBuildJob 那条「挂在轮询路径上」的注释——挂上去就永远不会触发
	backupClaimTimeout = 15 * time.Minute
	// backupProduceTimeout：running 且最后一次进展早于这么久就判死
	backupProduceTimeout = 30 * time.Minute

	// backupScheduleReason 是定时触发写进 reason 的固定常量。
	// reason 列 NOT NULL 且没有默认值，不定死的话实现者会写空串，
	// 而 AGENTS.md 要求每条平台级动作都有可读的发起原因
	backupScheduleReason = "scheduled backup"
	backupScheduleActor  = "system-backup"
)

// errBackupInFlight 是「已经有一条在途」。调用方把它翻成 409，不是 500
var errBackupInFlight = errors.New("a backup is already in flight")

// backupObject 是一组包在对象存储里的落点。三组一起存进 objects 那一列
type backupObject struct {
	Pair      string `json:"pair"`
	ObjectKey string `json:"objectKey"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

type backupRun struct {
	ID                string
	Seq               uint64
	Status            string
	TriggerBy         string
	RequestedBy       string
	Reason            string
	ClaimedBy         string
	ClaimedAt         *time.Time
	PayloadReceivedAt *time.Time
	Objects           []backupObject
	TenantCount       *uint64
	FailureReason     string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

const backupRunColumns = `id,seq,status,trigger_by,requested_by,reason,claimed_by,claimed_at,
	payload_received_at,objects,tenant_count,failure_reason,created_at,updated_at`

func scanBackupRun(row interface{ Scan(...any) error }) (backupRun, error) {
	var (
		run       backupRun
		claimedBy sql.NullString
		claimedAt sql.NullTime
		received  sql.NullTime
		objects   sql.NullString
		tenants   sql.NullInt64
		failure   sql.NullString
	)
	if err := row.Scan(&run.ID, &run.Seq, &run.Status, &run.TriggerBy, &run.RequestedBy, &run.Reason,
		&claimedBy, &claimedAt, &received, &objects, &tenants, &failure,
		&run.CreatedAt, &run.UpdatedAt); err != nil {
		return backupRun{}, err
	}
	run.ClaimedBy = claimedBy.String
	if claimedAt.Valid {
		at := claimedAt.Time
		run.ClaimedAt = &at
	}
	if received.Valid {
		at := received.Time
		run.PayloadReceivedAt = &at
	}
	if objects.Valid && strings.TrimSpace(objects.String) != "" {
		if err := json.Unmarshal([]byte(objects.String), &run.Objects); err != nil {
			return backupRun{}, fmt.Errorf("decode backup objects: %w", err)
		}
	}
	if tenants.Valid {
		count := uint64(tenants.Int64)
		run.TenantCount = &count
	}
	run.FailureReason = failure.String
	return run, nil
}

// createBackupRun 建一条待办。
//
// **单条 INSERT**，不包在有外部调用的事务里。实测过：把状态翻成 succeeded 的
// UPDATE（live_slot 1→NULL）会让并发 INSERT 一直等到该事务提交，5 秒的事务就
// 阻塞 5 秒——而 /backup/run 不在 10 秒数据库超时的豁免名单里，一慢就是 500。
func (s *server) createBackupRun(ctx context.Context, trigger, requestedBy, reason string) (backupRun, error) {
	id := "pbk_" + randomID(16)
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO platform_backups(id,status,trigger_by,requested_by,reason,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?)`,
		id, backupStatusPending, trigger, requestedBy, reason, now, now)
	if err != nil {
		if isBackupInFlightConflict(err) {
			return backupRun{}, errBackupInFlight
		}
		return backupRun{}, err
	}
	return s.backupRunByID(ctx, id)
}

// isBackupInFlightConflict 只认 live 那个索引。
//
// seq 是 AUTO_INCREMENT，所以正常情况下唯一能冲突的就是 live_slot。仍然显式匹配
// 索引名而不是「凡 1062 都当 409」：将来多一个唯一约束时，那条会正确地冒成 500
// 让人看见，而不是被悄悄翻译成一句「已经有一条在跑」
func isBackupInFlightConflict(err error) bool {
	var mysqlError *mysql.MySQLError
	if !errors.As(err, &mysqlError) || mysqlError.Number != 1062 {
		return false
	}
	return strings.Contains(mysqlError.Message, "ux_platform_backups_live")
}

func (s *server) backupRunByID(ctx context.Context, id string) (backupRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+backupRunColumns+` FROM platform_backups WHERE id=? LIMIT 1`, id)
	return scanBackupRun(row)
}

func (s *server) backupRunBySeq(ctx context.Context, seq uint64) (backupRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+backupRunColumns+` FROM platform_backups WHERE seq=? LIMIT 1`, seq)
	return scanBackupRun(row)
}

// liveBackupRun 返回当前在途的那一条（没有就是 sql.ErrNoRows）。
// 建待办撞 409 时要把它的 seq 和 status 带给调用者——运维没有别的出口去看
// 「到底是哪一条占着」
func (s *server) liveBackupRun(ctx context.Context) (backupRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+backupRunColumns+` FROM platform_backups WHERE live_slot=1 LIMIT 1`)
	return scanBackupRun(row)
}

func (s *server) listBackupRuns(ctx context.Context, limit int) ([]backupRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+backupRunColumns+` FROM platform_backups ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []backupRun{}
	for rows.Next() {
		run, err := scanBackupRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// claimBackupRun 原子认领：SELECT … FOR UPDATE SKIP LOCKED 挑一条，再带状态条件 UPDATE。
//
// 不这么做的话，两个进程会同时读到同一条并各自 UPDATE，两边都去解开全部租户的签名
// 密钥、打 tar、上传，第二个才在 /payload 吃 409——损害在 409 之前就发生了。而且
// 第二个大概率把 409 当硬失败去调 /fail，把第一条**已经成功**的记录翻成 failed。
func (s *server) claimBackupRun(ctx context.Context, agent string) (backupRun, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return backupRun{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM platform_backups WHERE status=? ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED`,
		backupStatusPending).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return backupRun{}, false, nil
	}
	if err != nil {
		return backupRun{}, false, err
	}
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx,
		`UPDATE platform_backups SET status=?,claimed_by=?,claimed_at=?,updated_at=?
		 WHERE id=? AND status=?`,
		backupStatusRunning, clipRunes(agent, 120), now, now, id, backupStatusPending)
	if err != nil {
		return backupRun{}, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return backupRun{}, false, err
	}
	if affected == 0 {
		// 别人抢先了。不是错误，下一轮再来
		return backupRun{}, false, nil
	}
	if err := tx.Commit(); err != nil {
		return backupRun{}, false, err
	}
	run, err := s.backupRunByID(ctx, id)
	return run, err == nil, err
}

// markBackupPayloadComplete 记下两份内层密文都到齐了。
//
// 只在**都**到齐时才写 payload_received_at：产出超时按
// COALESCE(payload_received_at, claimed_at) 算，没到齐之前它保持 NULL，超时按认领
// 时间算——「只传上来一份就断了」因此会被正确判死，而不是把时钟往后推。
func (s *server) markBackupPayloadComplete(ctx context.Context, id string) (bool, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx,
		`UPDATE platform_backups SET payload_received_at=?,updated_at=? WHERE id=? AND status=?`,
		now, now, id, backupStatusRunning)
	return changedOneRow(result, err)
}

// finishBackupRun 收尾。**必须带 WHERE status='running'**：0 行说明被超时扫描
// 或别人抢先收尾了，放弃并记日志，不要覆盖
func (s *server) finishBackupRun(ctx context.Context, id string, objects []backupObject, tenantCount int) (bool, error) {
	encoded, err := json.Marshal(objects)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx,
		`UPDATE platform_backups SET status=?,objects=?,tenant_count=?,updated_at=?
		 WHERE id=? AND status=?`,
		backupStatusSucceeded, string(encoded), tenantCount, now, id, backupStatusRunning)
	return changedOneRow(result, err)
}

// failBackupRun 判死。pending 和 running 都能判——认领超时打的是 pending，
// 打包机上报和强制判失败打的是 running
func (s *server) failBackupRun(ctx context.Context, id, reason string) (bool, error) {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx,
		`UPDATE platform_backups SET status=?,failure_reason=?,updated_at=?
		 WHERE id=? AND status IN (?,?)`,
		backupStatusFailed, clipRunes(strings.TrimSpace(reason), 500), now,
		id, backupStatusPending, backupStatusRunning)
	return changedOneRow(result, err)
}

// reapBackupRuns 跑两个超时扫描，返回被判死的条数。
//
// **判据只读行上的时间列，不许有任何内存状态。** 这样重启、部署、回滚、再滚回全部
// 自愈：回滚窗口里停在 running 的那条，滚回新版本之后这个扫描会自己收拾掉；依赖内存
// 状态的话它会永久占着 live_slot，而此后每一次定时都撞 1062、每一次「立即备份」都 409。
//
// 调用方是服务端自己的 ticker，**不是打包机的轮询路径**。认领超时的触发条件恰恰是
// 「打包机不轮询了」，挂在轮询上等于它永远不会触发（build_jobs.go 的注释正好是
// 反例，照抄就死）。
func (s *server) reapBackupRuns(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	claimed, err := s.db.ExecContext(ctx,
		`UPDATE platform_backups SET status=?,failure_reason=?,updated_at=?
		 WHERE status=? AND created_at<?`,
		backupStatusFailed, "the build agent did not pick this up within 15 minutes", now,
		backupStatusPending, now.Add(-backupClaimTimeout))
	if err != nil {
		return 0, err
	}
	produced, err := s.db.ExecContext(ctx,
		`UPDATE platform_backups SET status=?,failure_reason=?,updated_at=?
		 WHERE status=? AND COALESCE(payload_received_at, claimed_at)<?`,
		backupStatusFailed, "the build agent stopped partway through producing this backup", now,
		backupStatusRunning, now.Add(-backupProduceTimeout))
	if err != nil {
		return 0, err
	}
	a, _ := claimed.RowsAffected()
	b, _ := produced.RowsAffected()
	return a + b, nil
}

// lastScheduledBackupAt 是最近一次**定时**触发的时间。
//
// 定时不能用 time.NewTicker(interval)：ticker 的相位从进程启动算起，
// BACKUP_INTERVAL_HOURS=24 加上每天一次部署 = **备份一次都不会跑**，而控制台上
// 「上次成功时间」一直是空的，没人会把它和部署节奏联系起来。这是本方案最坏的一类
// 失败：以为有备份，其实没有。
//
// 正确写法是 ticker 只做 1 分钟一次的「到点了吗」轮询，到没到点由库决定——重启、
// 多实例、中途改间隔全部自洽。
func (s *server) lastScheduledBackupAt(ctx context.Context) (time.Time, error) {
	var at sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(created_at) FROM platform_backups WHERE trigger_by='schedule'`).Scan(&at)
	if err != nil {
		return time.Time{}, err
	}
	if !at.Valid {
		return time.Time{}, nil
	}
	return at.Time, nil
}

// consecutiveBackupFailures 从最近一条 succeeded 往回数。
//
// 不加计数器列：一个事实一处。计数器要在四个写方里同步维护，而它随时可能和
// 实际记录对不上——那时你分不清是备份真的连挂了 5 次，还是计数器坏了
func (s *server) consecutiveBackupFailures(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT status FROM platform_backups WHERE status IN (?,?) ORDER BY seq DESC LIMIT 50`,
		backupStatusSucceeded, backupStatusFailed)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			return 0, err
		}
		if status == backupStatusSucceeded {
			break
		}
		count++
	}
	return count, rows.Err()
}

func changedOneRow(result sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}
