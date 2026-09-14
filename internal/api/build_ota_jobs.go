package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 热更新包也由管理端排任务、打包机构建，和 APK 走同一张表、同一套状态流转。
//
// 在此之前热更新只能在开发机上手工做：导出、拼 tenant.json、上传、建修订。拼身份
// 那一步是纯手工的，而仓库里的 tenants/<slug>/tenant.json 从 2026-09-12 起就不是权威
// 来源了——它停在 anyfun 1.3.7 而线上分发的是 1.3.14。手工那条路每走一次都在赌。
//
// 和 APK 那条比，这条链路上**没有任何机密**：不需要 Android SDK、不需要 Gradle、
// 更不需要签名密钥——OTA 的 manifest 是服务端在下发那一刻用租户的 OTA 私钥签的，
// 打包机从头到尾碰不到它。所以这种任务将来可以放到一台权限更低的机器上。
//
// 构建 ≠ 发布。任务成功只产出一条 verified 的修订，要不要发给用户仍然是管理端上一次
// 单独的、带 reason 和二次确认的动作。这条边界不要打破：immediate 的热更是"两分钟内
// 全量设备强制重启进新包"，它必须是一个人明确按下的。

// otaJobBase 是这次热更新要对准的那个安装包。
type otaJobBase struct {
	ID             string
	Platform       string
	Version        string
	BuildNumber    int
	RuntimeVersion string
	// NativeFingerprint 是基线 APK 的原生面指纹。空串表示这个包在指纹功能上线
	// 之前构建，没法用来判断热更新是否只含 JS 改动，因此不能做基线。
	NativeFingerprint string
}

// createOTABuildJob 排一个构建热更新包的任务。
func (s *server) createOTABuildJob(c *gin.Context, body buildJobCreate) {
	ctx := c.Request.Context()
	reason := strings.TrimSpace(body.Reason)
	applyStrategy := strings.TrimSpace(body.ApplyStrategy)
	if applyStrategy == "" {
		applyStrategy = "next_launch"
	}
	if !body.Confirm || len(reason) < 3 || strings.TrimSpace(body.BaseReleaseID) == "" {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB",
			"baseReleaseId, reason and confirm=true are required for an OTA build")
		return
	}
	if applyStrategy != "next_launch" && applyStrategy != "immediate" {
		problem(c, http.StatusUnprocessableEntity, "INVALID_OTA_APPLY_STRATEGY",
			"applyStrategy must be next_launch or immediate")
		return
	}
	// 说明和 APK 任务同一套校验：两边最后写进发布记录的形状必须一样
	notes, notesCode, notesDetail := normalizeReleaseNotes(body.ReleaseNotes)
	if notesCode != "" {
		problem(c, http.StatusUnprocessableEntity, notesCode, notesDetail)
		return
	}
	encodedNotes, _ := json.Marshal(notes)

	base, err := s.otaJobBaseFor(ctx, tenantID(c), strings.TrimSpace(body.BaseReleaseID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			problem(c, http.StatusNotFound, "OTA_BASE_RELEASE_NOT_FOUND", "Base APK release not found")
			return
		}
		var invalid *otaBaseInvalid
		if errors.As(err, &invalid) {
			problem(c, http.StatusUnprocessableEntity, "OTA_BASE_RELEASE_INVALID", invalid.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to inspect the base release")
		return
	}
	// 打包机只做 android。iOS 的热更新包能构建，但目前没有一台 iOS 打包机认领它，
	// 排进去只会永远排队然后被心跳超时收掉——不如现在就说清楚。
	if base.Platform != "android" {
		problem(c, http.StatusUnprocessableEntity, "OTA_BASE_RELEASE_INVALID",
			"只有 Android 的热更新包可以由打包机构建；iOS 仍然需要手工构建后上传")
		return
	}
	// 没有签名密钥就别构建：客户端要验签而服务端签不了时，设备会静默拒绝这次更新
	// 并停在内置 bundle——在设备上完全看不出发生了什么。
	signer, err := s.otaSignerFor(ctx, tenantID(c))
	if err != nil || signer == nil {
		problem(c, http.StatusConflict, "OTA_SIGNING_KEY_MISSING",
			"这个租户还没有 OTA 签名密钥，构建出来的更新设备会拒绝。先到「OTA 签名密钥」生成一把。")
		return
	}

	// 身份在排队这一刻就要能合成出来，而且要用**基线那一版**的版本号与 build 号：
	// 热更新包会把这份身份烧进 manifest 的 extra，App 应用之后读的就是它而不是 APK
	// 里内嵌的那份。对不上，设备就会拿一个错的版本号去问"要不要升级"。
	slug, err := s.tenantSlug(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to resolve this tenant")
		return
	}
	buildCfg, _, err := s.buildConfigFor(ctx, tenantID(c), slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	manifest, err := s.tenantManifestFor(ctx, tenantID(c), buildCfg, base.Version, base.BuildNumber)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			problem(c, http.StatusConflict, "APP_IDENTITY_INCOMPLETE", missing.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "APP_IDENTITY_INVALID", "Unable to compose the tenant app identity")
		return
	}
	// channel 取合成身份里的那个，不看请求：它编在基线 APK 里，客户端只会问这一个
	// channel。让调用方传等于给了一个"发到一个没人订阅的频道"的机会。
	channel := manifest.OTAChannel

	now := time.Now().UTC()
	id := "bld_" + randomID(16)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	defer tx.Rollback()
	// version / build_number 存基线那一版：列表上要显示"这条热更是给谁的"，而且这两列
	// 是 NOT NULL。唯一索引不收 OTA 任务（见 buildJobsOTAMigration），不会和基线那条
	// APK 任务撞号。
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO build_jobs(id,tenant_id,platform,kind,base_release_id,channel,apply_strategy,git_ref,version,build_number,status,log_tail,reason,release_notes,created_by,created_at,updated_at)
		 VALUES(?,?,?,'ota',?,?,?,?,?,?,'queued',JSON_ARRAY(),?,?,?,?,?)`,
		id, tenantID(c), base.Platform, base.ID, channel, applyStrategy, buildGitRef,
		base.Version, base.BuildNumber, reason, encodedNotes, actor(c), now, now); err != nil {
		// ux_build_jobs_live_ota：同租户同平台同时只允许一条在跑的 OTA 任务。队列是
		// 跨租户的，不加这道闸，一个租户连点十下就把所有人的打包机占满了。
		if strings.Contains(err.Error(), "ux_build_jobs_live_ota") {
			problem(c, http.StatusConflict, "OTA_BUILD_ALREADY_QUEUED",
				"这个租户已经有一条热更新构建在排队或进行中，等它结束再排下一条")
			return
		}
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	event := newAudit(tenantID(c), actor(c), "build_job_create", "build-job", id, reason, requestID(c),
		map[string]any{"kind": "ota", "platform": base.Platform, "gitRef": buildGitRef,
			"baseReleaseId": base.ID, "channel": channel, "applyStrategy": applyStrategy})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	c.JSON(http.StatusCreated, buildJobView(buildJob{
		ID: id, TenantID: tenantID(c), Platform: base.Platform, Kind: "ota",
		BaseReleaseID: sql.NullString{String: base.ID, Valid: true},
		Channel:       sql.NullString{String: channel, Valid: true},
		ApplyStrategy: sql.NullString{String: applyStrategy, Valid: true},
		GitRef:        buildGitRef, Version: base.Version, BuildNumber: base.BuildNumber,
		Status: "queued", Reason: reason, ReleaseNotes: encodedNotes,
		CreatedBy: actor(c), CreatedAt: now, UpdatedAt: now,
	}))
}

// otaBaseInvalid：基线存在但不能用来发热更新。
type otaBaseInvalid struct{ detail string }

func (e *otaBaseInvalid) Error() string { return e.detail }

func (s *server) otaJobBaseFor(ctx context.Context, tenant, id string) (otaJobBase, error) {
	var base otaJobBase
	var status string
	var fileMetadata []byte
	if err := s.db.QueryRowContext(ctx,
		`SELECT id,platform,version,build_number,runtime_version,status,file_metadata FROM app_releases WHERE tenant_id=? AND id=?`,
		tenant, id).Scan(&base.ID, &base.Platform, &base.Version, &base.BuildNumber, &base.RuntimeVersion, &status, &fileMetadata); err != nil {
		return base, err
	}
	if status != "verified" && status != "active" && status != "canary" {
		return base, &otaBaseInvalid{fmt.Sprintf("基线安装包当前是 %s，只有已校验或在分发的版本可以作为热更新基线", status)}
	}
	if strings.TrimSpace(base.RuntimeVersion) == "" {
		return base, &otaBaseInvalid{"这个安装包没有记录 runtimeVersion，不能作为热更新基线（它是在记录该字段之前入库的）"}
	}
	// 没有原生指纹的基线，上传那一步必然被 otaFingerprintMismatch 拒掉——这里就说，
	// 别让它先跑完一趟构建。2026-09-14 anyfun 就是这么失败的：装依赖、Metro 打完
	// 3651 个模块、产出 11MB 的包，66 秒之后才在最后一步收到这句话。
	//
	// 判据和上传时是同一个（baseNativeFingerprint），措辞也用同一句：控制台上看到的
	// 和打包机日志里看到的必须是同一件事，不然排查的人会以为是两个问题。
	base.NativeFingerprint = baseNativeFingerprint(fileMetadata)
	if base.NativeFingerprint == "" {
		return base, &otaBaseInvalid{errOTAFingerprintMissing.Error()}
	}
	return base, nil
}

// buildJobOTAUpload 让代理为这条任务领一张热更新包的上传票据。
//
// 基线和 channel 取**任务行上的值**，不采信请求体——和 APK 那条一样的道理
// （buildAgentReleaseFromArtifact）：它们决定这个包发给谁，而任务行上那份是管理端
// 排队时定下并且过了校验的。
func (s *server) buildJobOTAUpload(c *gin.Context) {
	job, ok := otaJobFromContext(c)
	if !ok {
		return
	}
	var body struct {
		FileName string `json:"fileName"`
		Size     int64  `json:"size"`
	}
	if decode(c, &body) != nil || body.Size < 1 {
		problem(c, http.StatusBadRequest, "INVALID_OTA_UPLOAD", "fileName and size are required")
		return
	}
	rewriteJSONBody(c, map[string]any{
		"fileName":      body.FileName,
		"contentType":   "application/zip",
		"size":          body.Size,
		"baseReleaseId": job.BaseReleaseID.String,
		"channel":       job.Channel.String,
	})
	s.createOTAUploader(c)
}

// buildJobOTARelease 让代理用任务参数落一条热更新修订。
//
// 落成的修订是 verified，不是 active：要不要发给用户仍然是管理端上一次单独的、带
// reason 与二次确认的动作。构建和发布分开这件事是有意的——immediate 的热更意味着
// 两分钟内全量设备强制重启进新包，它必须是一个人明确按下的。
func (s *server) buildJobOTARelease(c *gin.Context) {
	job, ok := otaJobFromContext(c)
	if !ok {
		return
	}
	var body struct {
		ArtifactToken   string `json:"artifactToken"`
		SourceCommitSHA string `json:"sourceCommitSha"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.ArtifactToken) == "" {
		problem(c, http.StatusBadRequest, "INVALID_OTA_RELEASE", "artifactToken is required")
		return
	}
	notes := map[string]any{}
	for language, lines := range buildJobReleaseNotes(job) {
		notes[language] = lines
	}
	rewriteJSONBody(c, map[string]any{
		"artifactToken":   strings.TrimSpace(body.ArtifactToken),
		"baseReleaseId":   job.BaseReleaseID.String,
		"channel":         job.Channel.String,
		"applyStrategy":   job.ApplyStrategy.String,
		"sourceCommitSha": strings.TrimSpace(body.SourceCommitSHA),
		"releaseNotes":    notes,
	})
	s.saveOTARelease(c)
}

func otaJobFromContext(c *gin.Context) (buildJob, bool) {
	item, _ := c.Get("buildJob")
	job, ok := item.(buildJob)
	if !ok {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to read the build job")
		return job, false
	}
	if job.Kind != "ota" || !job.BaseReleaseID.Valid || !job.Channel.Valid {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_OTA", "This build job is not an OTA build")
		return job, false
	}
	return job, true
}
