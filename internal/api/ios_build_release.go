package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/gin-gonic/gin"
)

// iOS 安装包任务的收尾（设计 ios-testflight-distribution-2026-09-17 §4.5.4）。
//
// ## 为什么 iOS 不走 built → signing → succeeded 那一段
//
// Android 那套的前提是"构建与签名可以分开"：构建机交付未签名包，签名闸在另一台机器上
// 签。iOS 分不开——`xcodebuild -exportArchive` 导出的那一刻签名就已经发生，那台 Mac
// 必然同时持有源码和签名身份。所以 iOS 任务是 claimed/running → succeeded 一步到位，
// 中间没有待签名这个状态（signer.go 的认领本来就带 `platform='android'`，这里再把
// /built 对 iOS 关掉，免得任务停在一个永远没人认领的 built 上）。
//
// ## 为什么发布记录没有产物
//
// TestFlight 的包在 Apple 那边，而且**不是我们手里这一份**：Apple 会重新签名、瘦身，
// 用户装的是它处理过的产物。把 .ipa 当发布产物存起来，会让"发布记录的 sha256"这个
// 字段在 iOS 上变成一个看起来有意义、实际对不上任何东西的值。
//
// 这条记录的价值在别处：它是 latestVersion 的依据、是 OTA 基线、是审计里"这一版什么
// 时候发的"。我们手里那份 .ipa 的摘要记进 file_metadata，只作为"构建机交付了什么"的
// 自报凭证，不是分发凭证。

// iosReleaseReport 是 Mac 构建完之后的上报。
type iosReleaseReport struct {
	CommitSHA string `json:"commitSha"`
	// IPASHA256 / IPASize 是构建机手里那份 .ipa 的摘要。自报，不作为分发凭证
	IPASHA256 string `json:"ipaSha256"`
	IPASize   int64  `json:"ipaSize"`
	// 产物门禁在 Mac 上读出来的身份，服务端拿它和任务行、release.ios 再对一遍
	BundleID     string `json:"bundleId"`
	ShortVersion string `json:"shortVersion"`
	BuildNumber  int    `json:"buildNumber"`
	// UploadedToAppStoreConnect：这次有没有真的传上去（pnpm ios:release 要显式 --upload）。
	// 记下来是因为"包打出来了"和"TestFlight 上有这一版"是两件事，运营要能分辨
	UploadedToAppStoreConnect bool     `json:"uploadedToAppStoreConnect"`
	LogTail                   []string `json:"logTail"`
}

// completeIOSBuildJob 收 iOS 安装包任务的结果：落一条无产物的发布记录，任务转 succeeded。
func (s *server) completeIOSBuildJob(c *gin.Context) {
	job, ok := builderJobFromContext(c)
	if !ok {
		return
	}
	if job.Kind != jobKindAPK || job.Platform != buildPlatformIOS {
		problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH", "Only iOS installable-package builds are completed here")
		return
	}
	machine, _ := machineFromContext(c)
	var body iosReleaseReport
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha, ipaSha256, ipaSize, bundleId, shortVersion and buildNumber are required")
		return
	}
	commit := strings.ToLower(strings.TrimSpace(body.CommitSHA))
	digest := strings.ToLower(strings.TrimSpace(body.IPASHA256))
	if !commitSHAPattern.MatchString(commit) || !fingerprint.Valid(digest) || body.IPASize <= 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha and ipaSha256 must be hex digests and ipaSize must be positive")
		return
	}
	// 上报的身份必须和这条任务、和登记的 iOS 发布身份都对得上。Mac 上的产物门禁已经
	// 比过一轮，这里再比一次是因为那一轮的判据来自下发给它的 tenant.json——两侧分属
	// 不同的信任域，各自按自己那份记录把一次。
	identity, err := s.iosReleaseIdentityRecord(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if identity == nil {
		problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE", "这个租户的 iOS 发布身份在构建期间被删掉了，这个包落不了库")
		return
	}
	mismatches := []string{}
	if !strings.EqualFold(strings.TrimSpace(body.BundleID), identity.Value.BundleID) {
		mismatches = append(mismatches, "bundleId")
	}
	if strings.TrimSpace(body.ShortVersion) != job.Version {
		mismatches = append(mismatches, "shortVersion")
	}
	if body.BuildNumber != job.BuildNumber {
		mismatches = append(mismatches, "buildNumber")
	}
	if len(mismatches) > 0 {
		problem(c, http.StatusUnprocessableEntity, "IOS_ARTIFACT_MISMATCH",
			"上报的产物身份与这条任务对不上："+strings.Join(mismatches, "、"))
		return
	}

	metadata := map[string]any{
		// hosted 是这条记录与 Android 记录最重要的区别：产物不在我们手里
		"hosted":                    "testflight",
		"bundleId":                  identity.Value.BundleID,
		"appleTeamId":               identity.Value.AppleTeamID,
		"installUrl":                identity.Value.InstallURL,
		"ipaSha256":                 digest,
		"ipaSize":                   body.IPASize,
		"ipaSelfReported":           true,
		"commitSha":                 commit,
		"commitSelfReported":        true,
		"buildJobId":                job.ID,
		"builderId":                 machine.ID,
		"uploadedToAppStoreConnect": body.UploadedToAppStoreConnect,
	}
	now := time.Now().UTC()
	insert := releaseInsert{
		ID: "rel_" + randomID(16), Tenant: job.TenantID, Platform: job.Platform, Version: job.Version, BuildNumber: job.BuildNumber,
		// runtimeVersion 与 app.config.ts 一致（runtimeVersion: appVersion）：OTA 基线靠它对齐
		RuntimeVersion: job.Version,
		Metadata:       metadata, Notes: buildJobReleaseNotes(job),
		Actor: builderSystemActor, RequestID: requestID(c), AuditReason: "an iOS builder delivered a TestFlight build",
		AuditSummary: map[string]any{"buildJobId": job.ID, "builderId": machine.ID, "attempt": job.Attempt,
			"uploadedToAppStoreConnect": body.UploadedToAppStoreConnect},
	}
	releaseID := ""
	rejection, err := s.withReleaseSequence(c.Request.Context(), job.TenantID, job.Platform, func(tx *sql.Tx) (*releaseRejection, error) {
		ctx := c.Request.Context()
		var status string
		var lockedAttempt int
		var lockedMachine, lockedArtifact, lockedRelease sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT status,attempt,claimed_machine_id,artifact_sha256,release_id FROM build_jobs WHERE id=? FOR UPDATE`, job.ID).
			Scan(&status, &lockedAttempt, &lockedMachine, &lockedArtifact, &lockedRelease); err != nil {
			return nil, err
		}
		// 重试是常态（上传完成后网络断了）：同一次认领、同一份产物再报一次，回原来那条记录
		if status == jobSucceeded && lockedRelease.Valid && lockedAttempt == job.Attempt &&
			lockedMachine.String == machine.ID && lockedArtifact.String == digest {
			releaseID = lockedRelease.String
			return nil, nil
		}
		// 同一次认领已经完成过，但这次报的是另一份产物（有人重跑了构建，或手工调了接口）。
		// 说成"认领已过期"会把人引去查任务状态，而真正发生的是"这条任务已经有结果了"
		if status == jobSucceeded && lockedRelease.Valid && lockedAttempt == job.Attempt && lockedMachine.String == machine.ID {
			return &releaseRejection{Status: http.StatusConflict, Code: "IOS_RESULT_CONFLICT",
				Detail: "This claim already completed with a different package; the recorded release is not replaced"}, nil
		}
		if !buildJobTransitionAllowed(eventBuilderIOSRelease, jobKindAPK, status) ||
			lockedAttempt != job.Attempt || lockedMachine.String != machine.ID {
			return &releaseRejection{Status: http.StatusConflict, Code: "BUILD_ATTEMPT_STALE",
				Detail: "This claim is no longer current for this machine; stop working on the job"}, nil
		}
		if rejection, err := insertReleaseInTx(ctx, tx, insert, now); err != nil || rejection != nil {
			return rejection, err
		}
		result, err := tx.ExecContext(ctx,
			`UPDATE build_jobs SET status='succeeded',commit_sha=?,artifact_sha256=?,release_id=?,log_tail=?,heartbeat_at=?,updated_at=?
			  WHERE id=? AND attempt=? AND claimed_machine_id=?`,
			commit, digest, insert.ID, clampLogTail(body.LogTail), now, now, job.ID, job.Attempt, machine.ID)
		if err != nil {
			return nil, err
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			return nil, errors.New("the locked build job did not accept the completion")
		}
		if err := insertAudit(ctx, tx, newAudit(job.TenantID, builderSystemActor, "build_job_ios_released", "build-job", job.ID,
			"an iOS builder delivered a TestFlight build", requestID(c),
			map[string]any{"jobId": job.ID, "releaseId": insert.ID, "attempt": job.Attempt, "builderId": machine.ID,
				"bundleId": identity.Value.BundleID, "ipaSha256": digest,
				"uploadedToAppStoreConnect": body.UploadedToAppStoreConnect})); err != nil {
			return nil, err
		}
		releaseID = insert.ID
		return nil, nil
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to record the iOS release")
		return
	}
	if rejection != nil {
		problem(c, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	c.JSON(http.StatusOK, gin.H{"releaseId": releaseID})
}

// iosHostedReleaseMetadata 判断一条发布记录是不是"产物托管在 Apple"的那一类。
// 下载与产物校验这两条路径据此跳过：没有对象可下，也没有摘要可核。
func iosHostedReleaseMetadata(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	hosted, _ := value["hosted"].(string)
	return hosted != ""
}
