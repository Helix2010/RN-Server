package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"
)

// 打包任务交付对象（未签名包、SBOM、已签名包）的清理。
//
// 每次上传都是一个新键（deliveryObjectSegment），任务行只记最新那一个。任务被放弃（回收、取消、
// 强制判失败、构建机或签名闸报失败）或者被重新认领时，行上的键不再有人引用，不删就成了桶里的
// 孤儿。规则：状态变化与"把键列置空"在同一个事务里，**提交之后**再删对象——反过来的话，事务
// 回滚时行还指着一个已经删掉的对象。删不掉只记日志：状态已经提交，对象只是多占一点空间。
//
// 签名成功的任务，未签名包与 SBOM 由发布记录继续引用（file_metadata），删除发布时一并删
// （release_purge.go）；已签名包就是发布记录的 object_key。

type objectSet uint8

const (
	releaseUnsigned objectSet = 1 << iota
	releaseSBOM
	releaseSigned

	releaseNothing        objectSet = 0
	releaseBuildDelivery            = releaseUnsigned | releaseSBOM
	releaseAllDeliveries            = releaseBuildDelivery | releaseSigned
	jobObjectKeyColumns             = `unsigned_object_key,sbom_object_key,signed_object_key`
	deliveryDeleteTimeout           = 30 * time.Second
)

type jobObjectKeys struct {
	Unsigned, SBOM, Signed sql.NullString
}

// pick 返回集合里非空的键。
func (k jobObjectKeys) pick(set objectSet) []string {
	keys := []string{}
	add := func(want objectSet, key sql.NullString) {
		if set&want != 0 && key.Valid && strings.TrimSpace(key.String) != "" {
			keys = append(keys, key.String)
		}
	}
	add(releaseUnsigned, k.Unsigned)
	add(releaseSBOM, k.SBOM)
	add(releaseSigned, k.Signed)
	return keys
}

// clearColumns 是把集合里的键列置空的 SET 片段（以逗号开头，可以直接接在别的赋值后面）。
func (set objectSet) clearColumns() string {
	var b strings.Builder
	if set&releaseUnsigned != 0 {
		b.WriteString(",unsigned_object_key=NULL")
	}
	if set&releaseSBOM != 0 {
		b.WriteString(",sbom_object_key=NULL")
	}
	if set&releaseSigned != 0 {
		b.WriteString(",signed_object_key=NULL")
	}
	return b.String()
}

// lockedJob 是 transitionBuildJob 锁住那一刻的任务行（审计与后续判断用得到的几列）。
type lockedJob struct {
	TenantID         string
	SignAttempt      int
	SignFailures     int
	SigningMachineID sql.NullString
	Keys             jobObjectKeys
}

// jobTransition 描述一次带对象清理的状态变化。
type jobTransition struct {
	// Where 以 "WHERE id=? ..." 开头，是状态、编号、机器等守卫条件；不匹配时不改任何东西
	Where     string
	WhereArgs []any
	// Set 是 UPDATE 的赋值部分（不含 WHERE），SetArgs 是它的参数
	Set     string
	SetArgs []any
	// Release 是这次变化之后不再有人引用的对象
	Release objectSet
	// After 在同一事务里、UPDATE 之后执行（写审计），返回错误则整体回滚
	After func(tx *sql.Tx, locked lockedJob) error
}

// transitionBuildJob 锁住满足守卫条件的任务行，执行状态变化并置空被放弃的对象键，提交之后删掉
// 那些对象。matched=false 表示守卫条件不成立（编号过期、状态已经变了），什么都没改。
func (s *server) transitionBuildJob(ctx context.Context, jobID string, t jobTransition) (locked lockedJob, matched bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return lockedJob{}, false, err
	}
	defer tx.Rollback()
	switch err := tx.QueryRowContext(ctx,
		`SELECT tenant_id,sign_attempt,sign_failures,signing_machine_id,`+jobObjectKeyColumns+` FROM build_jobs `+t.Where+` FOR UPDATE`, t.WhereArgs...).
		Scan(&locked.TenantID, &locked.SignAttempt, &locked.SignFailures, &locked.SigningMachineID, &locked.Keys.Unsigned, &locked.Keys.SBOM, &locked.Keys.Signed); {
	case errors.Is(err, sql.ErrNoRows):
		return lockedJob{}, false, nil
	case err != nil:
		return lockedJob{}, false, err
	}
	args := append(append([]any{}, t.SetArgs...), jobID)
	if _, err := tx.ExecContext(ctx, `UPDATE build_jobs SET `+t.Set+t.Release.clearColumns()+` WHERE id=?`, args...); err != nil {
		return lockedJob{}, false, err
	}
	if t.After != nil {
		if err := t.After(tx, locked); err != nil {
			return lockedJob{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return lockedJob{}, false, err
	}
	s.deleteDeliveryObjects(locked.TenantID, jobID, locked.Keys.pick(t.Release))
	return locked, true, nil
}

// deleteDeliveryObjects 尽力删掉不再被引用的交付对象。只在状态已经提交之后调用。
func (s *server) deleteDeliveryObjects(tenant, jobID string, keys []string) {
	if len(keys) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), deliveryDeleteTimeout)
	defer cancel()
	client, _, err := s.storageClientForTenant(ctx, tenant)
	if err != nil {
		slog.Warn("cannot reach release storage to delete abandoned build deliveries", "job", jobID, "tenant", tenant, "keys", keys, "error", err)
		return
	}
	for _, key := range keys {
		if err := client.Delete(ctx, key); err != nil {
			slog.Warn("cannot delete an abandoned build delivery", "job", jobID, "tenant", tenant, "key", key, "error", err)
		}
	}
}
