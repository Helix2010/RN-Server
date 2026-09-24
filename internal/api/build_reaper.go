package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/Helix2010/RN-Server/internal/secretbox"
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
	// buildQueueStallWarning：排队超过它的 iOS 任务发一条告警（设计
	// ios-mac-builders-home-network-2026-09-18 §5.4）。回收器只管 claimed/running，
	// 一条**没人认领**的任务不会被回收也不会失败——它会一直排着，占着这个租户这个平台的
	// build 号。最常见的两个成因：唯一那台 Mac 关机了几天；排队之后有人改了
	// release.ios 的 Team ID 或 bundle id，于是再没有任何一台机器的自报盘点能匹配上。
	// 六小时是"家里的 Mac 睡了一夜也该醒了"的量级：更短会在正常的夜间等待里响，
	// 更长就失去了"人还记得自己排过这条"的窗口
	buildQueueStallWarning = 6 * time.Hour
	// buildQueueStalledAction 同时是审计动作名与去重依据：每条任务只告警一次，
	// 而回收是每分钟一轮的循环
	buildQueueStalledAction = "build_job_queue_stalled"
)

// RunBuildJobReaper 是 cmd/server 启动的回收循环：先跑一轮，之后每分钟一轮，ctx 结束就返回。
func RunBuildJobReaper(ctx context.Context, cfg config.Config, storage *store.Store) {
	// 对象存储与主密钥：回收时要删掉被放弃的交付对象，而租户存储凭据是用主密钥封着的。
	// 主密钥不可用时照常回收状态，删对象那一步记日志跳过
	box, _ := secretbox.New(cfg.StorageMasterKey)
	s := &server{cfg: cfg, db: storage.DB, objects: objectstore.AWSFactory{}, secrets: box}
	runReaperLoop(ctx, buildReaperInterval, func(roundCtx context.Context) {
		s.reapBuildJobs(roundCtx, time.Now().UTC())
	})
}

// runReaperLoop 是回收循环本体：立刻跑一轮，之后每个 interval 一轮；每一轮的 ctx 最多活一个
// interval，一轮卡住不会叠到下一轮上。ctx 结束就返回。
func runReaperLoop(ctx context.Context, interval time.Duration, round func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		roundCtx, cancel := context.WithTimeout(ctx, interval)
		round(roundCtx)
		cancel()
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
	// QueueStalled 是这一轮新告警的"排太久没人领"的任务。它们的状态没有被改动——
	// 排队不是故障，只是需要有人看一眼
	QueueStalled []string
	// IPAPurged 是这一轮清掉的、过了保留期的自助上传交付件（任务 id）
	IPAPurged []string
}

func (s *server) reapBuildJobs(ctx context.Context, now time.Time) reapResult {
	var result reapResult
	s.reapStaleBuilds(ctx, now, &result)
	s.reapStaleSignings(ctx, now, &result)
	s.warnStalledIOSQueue(ctx, now, &result)
	result.IPAPurged = s.purgeExpiredIPADeliveries(ctx, now)
	return result
}

// warnStalledIOSQueue 对排队超过六小时的 iOS 安装包任务发一条告警。
//
// **不改状态**：Mac 掉线时队列不停是已定的决策，任务要能等它回来。这里做的只是让
// "等得不正常久"这件事有人知道——回收器管不着排队中的任务，没有这条告警的话，一条
// 因为 release.ios 被改过而永远没人能领的任务，会安静地占着 build 号直到有人想起它。
//
// 每条任务只告警一次，靠审计里有没有这条记录去重（回收是每分钟一轮）。多个服务端
// 实例同时跑时可能各写一条：去重查询和写入之间没有锁。重复一条告警比漏一条便宜，
// 也比为它引一把锁便宜。
func (s *server) warnStalledIOSQueue(ctx context.Context, now time.Time, result *reapResult) {
	cutoff := now.Add(-buildQueueStallWarning)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,tenant_id,version,build_number,COALESCE(delivery,'`+iosDeliveryTestFlight+`'),created_at FROM build_jobs
		  WHERE status='`+jobQueued+`' AND kind='`+jobKindAPK+`' AND platform='`+buildPlatformIOS+`' AND created_at < ?
		  ORDER BY created_at LIMIT 50`, cutoff)
	if err != nil {
		slog.Error("cannot look for iOS builds stuck in the queue", "error", err)
		return
	}
	type stalled struct {
		id, tenant, version, delivery string
		buildNumber                   int
		createdAt                     time.Time
	}
	var found []stalled
	for rows.Next() {
		var item stalled
		if err := rows.Scan(&item.id, &item.tenant, &item.version, &item.buildNumber, &item.delivery, &item.createdAt); err != nil {
			slog.Error("cannot read an iOS build stuck in the queue", "error", err)
			continue
		}
		found = append(found, item)
	}
	rows.Close()
	if len(found) == 0 {
		return
	}
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		slog.Error("cannot read the machine registry while warning about stuck iOS builds", "error", err)
		return
	}
	for _, item := range found {
		if s.alreadyWarnedAboutQueue(ctx, item.tenant, item.id, item.createdAt) {
			continue
		}
		// 说清楚是"没人在线"还是"没人有材料"：两者的处理完全不同——前者去把 Mac 叫醒，
		// 后者去看是不是有人动过这个租户的 Apple Team 或 bundle id
		detail := "当前没有能打这个租户 iOS 包的打包机在线。"
		identity, err := s.iosReleaseIdentityRecord(ctx, item.tenant)
		switch {
		case err != nil || identity == nil:
			detail = "这个租户的 iOS 发布身份读不出来或已被删除，这条任务不会有人认领。"
		default:
			coverage, err := s.iosSigningCoverage(ctx, registry, identity.Value.AppleTeamID, identity.Value.BundleID, now)
			if err != nil {
				break
			}
			// 按这条任务自己的交付方式说：全托管卡在"没有能上传的机器"、自助上传卡在"打包机程序太旧"，
			// 和"没人有材料"一样都不会自己好
			if code, _ := (iosDeliveryReadiness{coverage: coverage}).problem(item.delivery, identity.Value.AppleTeamID, identity.Value.BundleID); code != "" {
				switch code {
				case "NO_BUILDER_FOR_TEAM":
					detail = "没有任何一台打包机报告过它手上有 Team " + identity.Value.AppleTeamID + "、bundle id " +
						identity.Value.BundleID + " 的签名材料——排队之后这个租户的 iOS 身份被改过，或者材料从那台 Mac 上没了。" +
						"这条任务不会有人认领，改回去或者取消它。"
				case "NO_UPLOADER_FOR_TEAM":
					detail = "这条任务是「全托管」，但没有任何一台打包机报告过 Team " + identity.Value.AppleTeamID +
						" 的上传 Key 可用（Key 被删、被吊销，或者探测一直失败）。这条任务不会有人认领，补上 Key 或者取消它。"
				case "NO_IPA_BUILDER_FOR_TEAM":
					detail = "这条任务是「自助上传」，但手上有这个 Team 材料的打包机都不支持把 .ipa 交回平台。" +
						"这条任务不会有人认领，批准新版打包机或者取消它。"
				}
				break
			}
			// 机器是齐的，那就是被排在前面的任务挡住了：同租户的 iOS 任务按排队顺序领
			var earlier string
			if err := s.db.QueryRowContext(ctx,
				`SELECT id FROM build_jobs WHERE tenant_id=? AND platform='`+buildPlatformIOS+`' AND kind='`+jobKindAPK+`' AND status='`+jobQueued+`'
				  AND (created_at<? OR (created_at=? AND id<?)) ORDER BY created_at LIMIT 1`,
				item.tenant, item.createdAt, item.createdAt, item.id).Scan(&earlier); err == nil {
				detail = "它排在同一个租户更早的任务 " + earlier + " 后面：同租户的 iOS 任务按排队顺序领，那一条没被领走，这一条就一直等着。先处理那一条。"
			}
		}
		reason := fmt.Sprintf("这条 iOS 打包任务（%s / build %d）已经排了 %s 还没有被认领。%s",
			item.version, item.buildNumber, now.Sub(item.createdAt).Truncate(time.Minute), detail)
		result.QueueStalled = append(result.QueueStalled, item.id)
		slog.Warn("an iOS build job has been queued for too long",
			"job", item.id, "tenant", item.tenant, "queuedFor", now.Sub(item.createdAt).Truncate(time.Minute).String())
		s.auditNow(newAudit(item.tenant, reaperActor, buildQueueStalledAction, "build-job", item.id, clipRunes(reason, 500), "",
			map[string]any{"jobId": item.id, "version": item.version, "buildNumber": item.buildNumber, "delivery": item.delivery,
				"queuedSeconds": int(now.Sub(item.createdAt).Seconds())}))
	}
}

// alreadyWarnedAboutQueue 查这条任务有没有告警过。按 (tenant_id, created_at) 那个索引
// 走，下界取任务的排队时刻——审计表是只增的，不限下界等于全表扫。
func (s *server) alreadyWarnedAboutQueue(ctx context.Context, tenant, jobID string, since time.Time) bool {
	var exists int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM audit_events WHERE tenant_id=? AND created_at>=? AND action=? AND target_type='build-job' AND target_id=? LIMIT 1`,
		tenant, since, buildQueueStalledAction, jobID).Scan(&exists)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// 查不出来就当告警过：宁可漏一条，也不要每分钟重复写一条审计
		slog.Error("cannot tell whether a stuck iOS build was already reported", "job", jobID, "error", err)
		return true
	}
	return err == nil
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
		guardArgs := []any{item.id, item.attempt, cutoff}
		// 这一次认领传上来的未签名包与 SBOM 不会再有人用：重排后下一次认领从头交付，判失败则不再交付
		if item.kind == jobKindAPK && item.attempt < maxBuildAttempts {
			_, matched, err := s.transitionBuildJob(ctx, item.id, jobTransition{
				Where: guard, WhereArgs: guardArgs,
				Set: `status='queued',claimed_at=NULL,heartbeat_at=NULL,updated_at=?`, SetArgs: []any{now},
				Release: releaseBuildDelivery,
			})
			if !reaped(matched, err, item.id) {
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
		_, matched, err := s.transitionBuildJob(ctx, item.id, jobTransition{
			Where: guard, WhereArgs: guardArgs,
			Set: `status='failed',failure_reason=?,updated_at=?`, SetArgs: []any{clipRunes(reason, 500), now},
			Release: releaseBuildDelivery,
		})
		if !reaped(matched, err, item.id) {
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
		// 状态在 Go 里按读到的 sign_failures 算好；WHERE 带 sign_failures=?，读到之后有人改过就改不到行。
		// 这一次签名认领交回的已签名包作废；判失败时未签名包与 SBOM 也不再有人用
		release := releaseSigned
		if failed {
			release = releaseAllDeliveries
		}
		_, matched, err := s.transitionBuildJob(ctx, item.id, jobTransition{
			Where:     `WHERE id=? AND status IN (` + sqlSignerActive + `) AND sign_attempt=? AND sign_failures=? AND COALESCE(signing_heartbeat_at,signing_claimed_at,updated_at) < ?`,
			WhereArgs: []any{item.id, item.signAttempt, item.failures, cutoff},
			Set:       `status=?,failure_reason=COALESCE(?,failure_reason),sign_outcome=?,updated_at=?,sign_failures=sign_failures+1`,
			SetArgs:   []any{map[bool]string{true: jobFailed, false: jobBuilt}[failed], reason, outcome, now},
			Release:   release,
		})
		if !reaped(matched, err, item.id) {
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

func reaped(matched bool, err error, id string) bool {
	if err != nil {
		slog.Error("cannot reap a build job", "job", id, "error", err)
		return false
	}
	return matched
}
