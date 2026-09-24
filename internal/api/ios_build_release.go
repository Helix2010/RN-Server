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
// 这条记录的价值在别处：它是 OTA 基线、是审计里"这一版什么时候发的"。iOS 的 latestVersion
// 读的是人工配置的更新策略（server.go），不跟着发布记录走——包出来了不等于用户装得到。
// 我们手里那份 .ipa 的摘要记进 file_metadata，只作为"构建机交付了什么"的自报凭证，不是分发凭证。
//
// 自助上传（设计 ios-tenant-delivery-tiers-2026-09-24 §3.5）的 .ipa 确实存在我们这里，但它是
// **交给租户的交付件**：对象键记在任务行的 unsigned_* 列（iOS 不经过签名闸，这几列本来空着，
// 回收、取消、删除发布的清理都按这几列做），发布记录的 sha256 / verified_at 仍然不填——激活
// 发布要求它们非空，于是这种记录不会被激活、不会触发推送与强更；公开下载也按 hosted 挡住。

// 发布记录 file_metadata.hosted 的取值。非空就表示"分发产物不在我们手里"：
// 公开下载与产物校验两条路径据此跳过（iosHostedReleaseMetadata）。
const (
	iosHostedTestFlight = "testflight"
	// iosHostedTenantUpload：自助上传。我们存着一份 .ipa，但那是交给租户的交付件，只能走鉴权下载
	iosHostedTenantUpload = "tenant-upload"
)

// iosToolchainMaxRunes 够放下 `Xcode 16.2` + `Build version 16C5032a` 两段。
const iosToolchainMaxRunes = 120

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
	UploadedToAppStoreConnect bool `json:"uploadedToAppStoreConnect"`
	// UploadedByEarlierAttempt：这次没传，因为 ASC 上已经有同一个 build 号了
	// （设计 ios-mac-builders-home-network-2026-09-18 §6.3）。任务被回收重排后 build 号
	// 不变，上一次尝试可能已经把 .ipa 传上去了、只是没报上来。这时 Apple 那份 .ipa 对应的
	// 是**上一次检出的提交**，与这条记录里自报的 commitSha / ipaSha256 可能不是一回事——
	// 这个标记就是在说这件事，别把它当成"没上传"
	UploadedByEarlierAttempt bool `json:"uploadedByEarlierAttempt"`
	// Toolchain 是这台 Mac 上 xcodebuild -version 的那一行。几台 Mac 装同一个 Xcode 是
	// 人工维护的约定（§5.3），版本漂移只有记下来才看得见
	Toolchain string   `json:"toolchain"`
	LogTail   []string `json:"logTail"`
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
	// 交付方式决定"做完"是什么意思（ios_delivery.go）：
	//   - 全托管：包必须已经在 App Store Connect 上。全托管的任务只派给上传 Key 可用的机器，
	//     报"没上传"就是出了岔子——收下的话，控制台会显示成功，而 TestFlight 上什么都没有；
	//   - 自助上传：包必须在**这次认领下**交回了服务端，而且就是上报的这一份。
	delivery := jobDelivery(job)
	hosted := iosHostedTestFlight
	auditReason := "an iOS builder delivered a TestFlight build"
	switch delivery {
	case iosDeliveryTestFlight:
		if !body.UploadedToAppStoreConnect {
			problem(c, http.StatusConflict, "IOS_UPLOAD_MISSING",
				"这条任务的交付方式是「全托管」，但构建机报告没有把包传进 App Store Connect；任务没有按成功收下")
			return
		}
	case iosDeliveryIPA:
		if body.UploadedToAppStoreConnect {
			problem(c, http.StatusConflict, "IOS_DELIVERY_MISMATCH",
				"这条任务的交付方式是「自助上传」，构建机却报告把包传进了 App Store Connect")
			return
		}
		if !job.UnsignedSHA256.Valid || job.UnsignedSHA256.String != digest || !job.UnsignedSize.Valid || job.UnsignedSize.Int64 != body.IPASize {
			problem(c, http.StatusConflict, "IOS_IPA_NOT_DELIVERED",
				"这条任务的交付方式是「自助上传」，但这次认领下交回服务端的 .ipa 与上报的对不上（或者还没交回）")
			return
		}
		hosted = iosHostedTenantUpload
		auditReason = "an iOS builder delivered an .ipa for the tenant to upload"
	}

	metadata := map[string]any{
		// hosted 是这条记录与 Android 记录最重要的区别：分发产物不在我们手里。自助上传的
		// .ipa 虽然存在我们这里，但它是交给租户的交付件，用户装的仍是 Apple 处理过的那一份
		"hosted":                    hosted,
		"delivery":                  delivery,
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
		"uploadedByEarlierAttempt":  body.UploadedByEarlierAttempt,
	}
	// 没报就不写这个键：旧版代理不带它，写一个空串等于说"这台机器的 Xcode 是空的"
	if toolchain := sanitizeSignerText(body.Toolchain, iosToolchainMaxRunes); toolchain != "" {
		metadata["toolchain"] = toolchain
	}
	now := time.Now().UTC()
	insert := releaseInsert{
		ID: "rel_" + randomID(16), Tenant: job.TenantID, Platform: job.Platform, Version: job.Version, BuildNumber: job.BuildNumber,
		// runtimeVersion 与 app.config.ts 一致（runtimeVersion: appVersion）：OTA 基线靠它对齐
		RuntimeVersion: job.Version,
		Metadata:       metadata, Notes: buildJobReleaseNotes(job),
		Actor: builderSystemActor, RequestID: requestID(c), AuditReason: auditReason,
		AuditSummary: map[string]any{"buildJobId": job.ID, "builderId": machine.ID, "attempt": job.Attempt, "delivery": delivery,
			"uploadedToAppStoreConnect": body.UploadedToAppStoreConnect,
			"uploadedByEarlierAttempt":  body.UploadedByEarlierAttempt},
	}
	releaseID := ""
	rejection, err := s.withReleaseSequence(c.Request.Context(), job.TenantID, job.Platform, func(tx *sql.Tx) (*releaseRejection, error) {
		ctx := c.Request.Context()
		var status string
		var lockedAttempt int
		var lockedMachine, lockedArtifact, lockedRelease, lockedIPA sql.NullString
		var lockedIPASize sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT status,attempt,claimed_machine_id,artifact_sha256,release_id,unsigned_sha256,unsigned_size FROM build_jobs WHERE id=? FOR UPDATE`, job.ID).
			Scan(&status, &lockedAttempt, &lockedMachine, &lockedArtifact, &lockedRelease, &lockedIPA, &lockedIPASize); err != nil {
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
		// 交付件在锁住的这一行上再比一次：读任务与收尾之间，同一次认领的另一次上传可能已经把它换掉
		if delivery == iosDeliveryIPA && (lockedIPA.String != digest || lockedIPASize.Int64 != body.IPASize) {
			return &releaseRejection{Status: http.StatusConflict, Code: "IOS_IPA_NOT_DELIVERED",
				Detail: "The .ipa delivered under this claim changed before completion; report again with the current one"}, nil
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
			auditReason, requestID(c),
			map[string]any{"jobId": job.ID, "releaseId": insert.ID, "attempt": job.Attempt, "builderId": machine.ID,
				"bundleId": identity.Value.BundleID, "ipaSha256": digest, "delivery": delivery,
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
