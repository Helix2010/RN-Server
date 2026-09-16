package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 回收定时器（设计「构建任务的状态与字段」规则第一条、「机器挂了怎么办」前两行）。
//
// 原来的回收挂在构建机认领上："没有构建机来问活就没什么要回收"。签名闸上线之后这句
// 不成立了：签名闸挂了，signing 的任务要退回待签名，而这件事和有没有构建机在轮询无关；
// 构建机全挂了，claimed 的任务也该按规则退回排队或判失败，而不是等下一台机器来问。
// 所以回收是服务端自己的定时器，每分钟一次，随服务启动、随服务关闭退出。
//
// 多个服务端实例同时跑也没关系：每条回收都是带条件的 UPDATE（状态、编号、心跳仍然过期），
// 两个实例抢同一条任务，只有一个能改到。

const (
	// buildJobHeartbeatTimeout：构建机每 30 秒报一次心跳，构建再慢也不会停
	buildJobHeartbeatTimeout = 10 * time.Minute
	// signJobHeartbeatTimeout：签名一个包是分钟级以内的事
	signJobHeartbeatTimeout = 5 * time.Minute
	// maxSignFailures：签名心跳超时与临时错误各计一次，到 2 判失败（约定 2.6）
	maxSignFailures     = 2
	buildReaperInterval = time.Minute
	reaperActor         = "system-build"
)

// RunBuildJobReaper 是 cmd/server 启动的回收循环：先跑一轮，之后每分钟一轮，ctx 结束就返回。
func RunBuildJobReaper(ctx context.Context, cfg config.Config, storage *store.Store) {
	s := &server{cfg: cfg, db: storage.DB}
	runBuildJobReaperLoopWithHook(ctx, s, buildReaperInterval, nil)
}

// runBuildJobReaperLoopWithHook 是回收循环本体；afterRound 在每一轮之后调用（测试用来数轮次，生产为 nil）。
func runBuildJobReaperLoopWithHook(ctx context.Context, s *server, interval time.Duration, afterRound func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		roundCtx, cancel := context.WithTimeout(ctx, interval)
		s.reapBuildJobs(roundCtx, time.Now().UTC())
		cancel()
		if afterRound != nil {
			afterRound()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// reapResult 是一轮回收做了什么，给测试和日志用。
type reapResult struct {
	Requeued   []string
	Failed     []string
	SignBack   []string
	SignFailed []string
}

func (s *server) reapBuildJobs(ctx context.Context, now time.Time) reapResult {
	var result reapResult
	s.reapStaleBuilds(ctx, now, &result)
	s.reapStaleSignings(ctx, now, &result)
	return result
}

// reapStaleBuilds：claimed/running 10 分钟没有心跳。
// 安装包任务 attempt 没到上限退回 queued（认领编号在下一次认领时加一），到了判失败；
// 热更新任务直接判失败，不自动重排——热更新是"两分钟内全量设备生效"的东西，不该在
// 没人看着的时候自己再发一次。
func (s *server) reapStaleBuilds(ctx context.Context, now time.Time, result *reapResult) {
	cutoff := now.Add(-buildJobHeartbeatTimeout)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,tenant_id,kind,status,attempt,COALESCE(claimed_by,''),COALESCE(claimed_machine_id,'') FROM build_jobs
		  WHERE status IN (`+sqlBuilderActive+`) AND COALESCE(heartbeat_at,claimed_at,created_at) < ?`, cutoff)
	if err != nil {
		slog.Error("cannot look for stale build jobs", "error", err)
		return
	}
	type stale struct {
		id, tenant, kind, status, machineName, machineID string
		attempt                                          int
	}
	var found []stale
	for rows.Next() {
		var item stale
		if err := rows.Scan(&item.id, &item.tenant, &item.kind, &item.status, &item.attempt, &item.machineName, &item.machineID); err != nil {
			slog.Error("cannot read a stale build job", "error", err)
			continue
		}
		found = append(found, item)
	}
	rows.Close()
	for _, item := range found {
		guard := `WHERE id=? AND status IN (` + sqlBuilderActive + `) AND attempt=? AND COALESCE(heartbeat_at,claimed_at,created_at) < ?`
		if item.kind == jobKindAPK && item.attempt < maxBuildAttempts {
			res, err := s.db.ExecContext(ctx,
				`UPDATE build_jobs SET status='queued',claimed_at=NULL,heartbeat_at=NULL,updated_at=? `+guard,
				now, item.id, item.attempt, cutoff)
			if !reaped(res, err, item.id) {
				continue
			}
			result.Requeued = append(result.Requeued, item.id)
			slog.Warn("requeued a build job whose builder stopped reporting",
				"job", item.id, "tenant", item.tenant, "attempt", item.attempt, "machineId", item.machineID)
			s.auditNow(newAudit(item.tenant, reaperActor, "build_job_requeued", "build-job", item.id,
				fmt.Sprintf("builder stopped reporting for %s; requeued", buildJobHeartbeatTimeout), "",
				map[string]any{"jobId": item.id, "attempt": item.attempt, "machineId": nullableString(item.machineID), "was": item.status}))
			continue
		}
		reason := fmt.Sprintf("构建机 %s 超过 %s 没有回报进度，任务按失败处理。", item.machineName, buildJobHeartbeatTimeout)
		if item.kind == jobKindAPK {
			reason = fmt.Sprintf("已经被认领 %d 次，构建机每次都超过 %s 没有回报进度（最近一次是 %s），不再自动重排。"+
				"多半是同一个原因反复把构建机拖死；看最近一次的日志尾部，修好之后重新排一个任务。",
				item.attempt, buildJobHeartbeatTimeout, item.machineName)
		} else {
			reason += "热更新任务不自动重排，确认原因之后重新排一个。"
		}
		res, err := s.db.ExecContext(ctx,
			`UPDATE build_jobs SET status='failed',failure_reason=?,updated_at=? `+guard,
			clipRunes(reason, 500), now, item.id, item.attempt, cutoff)
		if !reaped(res, err, item.id) {
			continue
		}
		result.Failed = append(result.Failed, item.id)
		slog.Warn("failed a build job whose builder stopped reporting",
			"job", item.id, "tenant", item.tenant, "kind", item.kind, "attempt", item.attempt, "machineId", item.machineID)
		s.auditNow(newAudit(item.tenant, reaperActor, "build_job_reaped", "build-job", item.id, clipRunes(reason, 500), "",
			map[string]any{"jobId": item.id, "kind": item.kind, "attempt": item.attempt, "machineId": nullableString(item.machineID), "was": item.status}))
	}
}

// reapStaleSignings：signing 5 分钟没有签名心跳，退回 built 并计一次签名失败，到上限判失败。
// 主签名闸恢复后，本机记录里的预留让它对同一任务幂等续签。
func (s *server) reapStaleSignings(ctx context.Context, now time.Time, result *reapResult) {
	cutoff := now.Add(-signJobHeartbeatTimeout)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,tenant_id,sign_attempt,sign_failures,COALESCE(signing_machine_id,'') FROM build_jobs
		  WHERE kind='apk' AND status IN (`+sqlSignerActive+`) AND COALESCE(signing_heartbeat_at,signing_claimed_at,updated_at) < ?`, cutoff)
	if err != nil {
		slog.Error("cannot look for stale signing jobs", "error", err)
		return
	}
	type stale struct {
		id, tenant, machineID string
		signAttempt, failures int
	}
	var found []stale
	for rows.Next() {
		var item stale
		if err := rows.Scan(&item.id, &item.tenant, &item.signAttempt, &item.failures, &item.machineID); err != nil {
			slog.Error("cannot read a stale signing job", "error", err)
			continue
		}
		found = append(found, item)
	}
	rows.Close()
	for _, item := range found {
		outcome, _ := json.Marshal(buildJobSignOutcome{
			Kind: "transient", Code: "SIGNER_HEARTBEAT_TIMEOUT",
			Detail:    fmt.Sprintf("签名闸超过 %s 没有签名心跳", signJobHeartbeatTimeout),
			MachineID: item.machineID, At: iso(now),
		})
		failed := item.failures+1 >= maxSignFailures
		reason := sql.NullString{}
		if failed {
			reason = sql.NullString{Valid: true, String: clipRunes(fmt.Sprintf(
				"签名闸已经 %d 次没签成（最近一次是签名心跳超过 %s 没有更新），不再派给签名闸。检查签名闸的日志与本机记录后重新排一个任务。",
				item.failures+1, signJobHeartbeatTimeout), 500)}
		}
		// sign_failures 放在最后赋值：MySQL 的多列 SET 从左到右求值，前面的 CASE 要读更新前的值
		res, err := s.db.ExecContext(ctx,
			`UPDATE build_jobs SET status=?,failure_reason=COALESCE(?,failure_reason),sign_outcome=?,updated_at=?,sign_failures=sign_failures+1
			  WHERE id=? AND status IN (`+sqlSignerActive+`) AND sign_attempt=? AND sign_failures=? AND COALESCE(signing_heartbeat_at,signing_claimed_at,updated_at) < ?`,
			map[bool]string{true: jobFailed, false: jobBuilt}[failed], reason, outcome, now,
			item.id, item.signAttempt, item.failures, cutoff)
		if !reaped(res, err, item.id) {
			continue
		}
		if failed {
			result.SignFailed = append(result.SignFailed, item.id)
			s.auditNow(newAudit(item.tenant, signerActor, "build_job_sign_failed", "build-job", item.id, reason.String, "",
				map[string]any{"jobId": item.id, "signAttempt": item.signAttempt, "signFailures": item.failures + 1,
					"machineId": nullableString(item.machineID), "code": "SIGNER_HEARTBEAT_TIMEOUT"}))
		} else {
			result.SignBack = append(result.SignBack, item.id)
		}
		slog.Warn("reclaimed a signing job whose signer stopped reporting",
			"job", item.id, "tenant", item.tenant, "signAttempt", item.signAttempt, "machineId", item.machineID, "failed", failed)
	}
}

func reaped(result sql.Result, err error, id string) bool {
	if err != nil {
		slog.Error("cannot reap a build job", "job", id, "error", err)
		return false
	}
	affected, _ := result.RowsAffected()
	return affected == 1
}
