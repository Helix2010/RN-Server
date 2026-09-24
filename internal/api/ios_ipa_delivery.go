package api

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/ipa"
	"github.com/gin-gonic/gin"
)

// 自助上传的 .ipa：构建机交回、服务端核对后存下、控制台鉴权下载
// （设计 ios-tenant-delivery-tiers-2026-09-24 §3.4–§3.6）。
//
// 对象键记在任务行的 unsigned_* 列上：iOS 不经过签名闸，这几列本来空着；回收、取消、失败、
// 重新认领与删除发布的清理都按这几列做（build_job_objects.go、release_purge.go），交付件不会
// 变成桶里的孤儿。发布记录只在 file_metadata 里带一份摘要，分发产物的 sha256 列不填（激活发布靠它）。

// iosPackageObjectName 是交付件在存储里的文件名，也是下载时给租户的文件名。
func iosPackageObjectName(bundleID, version string, buildNumber int) string {
	return safeDownloadName(bundleID + "-" + version + "-build" + strconv.Itoa(buildNumber) + ".ipa")
}

// uploadIOSPackage 收下自助上传任务的 .ipa：先在临时文件上核对，对得上才写进存储、记到任务行。
//
// 核对比 Mac 上那一道多几项（internal/ipa.Inspect）：内嵌描述文件必须是这个租户 Team 的
// App Store 描述文件——没有设备列表、不能调试、不是企业分发，压缩包里只能有 Xcode 导出的那些
// 目录。这个包会交到租户手里，"它只能交给 App Store"要是检查出来的。
func (s *server) uploadIOSPackage(c *gin.Context) {
	job, ok := builderJobFromContext(c)
	if !ok {
		return
	}
	if job.Kind != jobKindAPK || job.Platform != buildPlatformIOS || jobDelivery(job) != iosDeliveryIPA {
		problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH", "Only self-upload iOS builds hand an .ipa back to the server")
		return
	}
	machine, _ := machineFromContext(c)
	identity, err := s.iosReleaseIdentityRecord(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if identity == nil {
		problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE", "这个租户的 iOS 发布身份在构建期间被删掉了，这个包落不了库")
		return
	}
	client, prefix, err := s.storageClientForTenant(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	received, status, code, detail := receiveStreamToTemp(c, s.cfg.ArtifactMaxSizeBytes)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	defer received.cleanup()
	inspection, err := ipa.Inspect(received.path)
	if err != nil {
		problem(c, http.StatusUnprocessableEntity, "IOS_IPA_INVALID", "交回的 .ipa 没有通过核对："+err.Error())
		return
	}
	mismatches := []string{}
	if !strings.EqualFold(inspection.Identity.BundleID, identity.Value.BundleID) {
		mismatches = append(mismatches, "bundleId")
	}
	if inspection.Identity.ShortVersion != job.Version {
		mismatches = append(mismatches, "shortVersion")
	}
	if inspection.Identity.BuildNumber != strconv.Itoa(job.BuildNumber) {
		mismatches = append(mismatches, "buildNumber")
	}
	if !strings.EqualFold(inspection.Profile.TeamID, identity.Value.AppleTeamID) ||
		!strings.EqualFold(inspection.Profile.BundleID, identity.Value.BundleID) {
		mismatches = append(mismatches, "provisioning profile (team or bundle id)")
	}
	if len(mismatches) > 0 {
		problem(c, http.StatusUnprocessableEntity, "IOS_ARTIFACT_MISMATCH", "交回的 .ipa 与这条任务对不上："+strings.Join(mismatches, "、"))
		return
	}
	key := buildJobObjectKey(prefix, job.TenantID, job.ID, deliveryObjectSegment("a", job.Attempt),
		iosPackageObjectName(identity.Value.BundleID, job.Version, job.BuildNumber))
	if status, code, detail := s.storeReceivedStream(client, key, received); status != 0 {
		problem(c, status, code, detail)
		return
	}
	// 请求可能已经断开，落库不跟着请求取消（与 receiveBuildDelivery 同一个道理）
	replaced, current, err := s.recordDeliveredObject(context.Background(),
		`SELECT unsigned_object_key FROM build_jobs
		  WHERE id=? AND kind='apk' AND platform='`+buildPlatformIOS+`' AND delivery='`+iosDeliveryIPA+`'
		    AND status IN (`+sqlStatusList(buildJobEventFrom(eventBuilderUpload, jobKindAPK))+`) AND attempt=? AND claimed_machine_id=?`,
		[]any{job.ID, job.Attempt, machine.ID},
		`UPDATE build_jobs SET unsigned_object_key=?,unsigned_size=?,unsigned_sha256=?,updated_at=? WHERE id=?`,
		[]any{key, received.size, received.sha256, time.Now().UTC(), job.ID})
	if err != nil {
		// 不删对象：提交报错时事务可能其实已经提交，删了就是删一个被引用的键
		slog.Error("cannot record a delivered iOS package", "job", job.ID, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the delivered file")
		return
	}
	if !current {
		_ = client.Delete(context.Background(), key)
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	deleteReplacedObject(client, replaced, key, job.ID)
	c.JSON(http.StatusOK, gin.H{"sha256": received.sha256, "size": received.size})
}

// downloadIOSPackage 把自助上传任务的 .ipa 交给控制台。
//
// 服务端鉴权后流式转发，不给存储的预签名链接：国内网络连存储所在区域可能握手都过不去
// （2026-09-23 Mac 连 OBS 新加坡实测）；签发了链接不等于真的下载了，审计记不准；链接泄露
// 之后谁都能下——而这是一份还没发布的钱包二进制，拿到它的人可以用自己的证书重签装机、改包仿冒。
// 支持单区间 Range（大文件断点续传），每次请求都记审计。
func (s *server) downloadIOSPackage(c *gin.Context) {
	ctx := c.Request.Context()
	var platform, kind, status, version string
	var delivery, key, digest sql.NullString
	var size sql.NullInt64
	var buildNumber int
	err := s.db.QueryRowContext(ctx,
		`SELECT platform,kind,delivery,status,version,build_number,unsigned_object_key,unsigned_sha256,unsigned_size FROM build_jobs WHERE tenant_id=? AND id=?`,
		tenantID(c), c.Param("id")).Scan(&platform, &kind, &delivery, &status, &version, &buildNumber, &key, &digest, &size)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "BUILD_JOB_NOT_FOUND", "Build job not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to load the build")
		return
	}
	if platform != buildPlatformIOS || kind != jobKindAPK || delivery.String != iosDeliveryIPA {
		problem(c, http.StatusNotFound, "IOS_IPA_NOT_AVAILABLE", "这条构建不是「自助上传」的 iOS 构建，没有可下载的 .ipa")
		return
	}
	// 只交成功了的：还在跑的任务，交回的包可能被同一次认领的重传换掉，或者随任务失败被删
	if status != jobSucceeded || !key.Valid || key.String == "" || !size.Valid || !digest.Valid {
		problem(c, http.StatusNotFound, "IOS_IPA_NOT_AVAILABLE", "这条构建还没有成功出包，或者交付件已经过了保留期被清理")
		return
	}
	identity, err := s.iosReleaseIdentityRecord(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	bundleID := "app"
	if identity != nil {
		bundleID = identity.Value.BundleID
	}
	client, _, err := s.storageClientForTenant(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// 下发前核对存储里的还是收下时核过的那一个：大小不对就不发（存储被改写不会有别人发现）
	stored, err := client.Stat(ctx, key.String)
	if err != nil {
		problem(c, http.StatusFailedDependency, "IOS_IPA_DOWNLOAD_FAILED", "Unable to read the .ipa from release storage")
		return
	}
	if stored.Size != size.Int64 {
		slog.Error("a delivered iOS package changed in storage", "job", c.Param("id"), "tenant", tenantID(c), "stored", stored.Size, "recorded", size.Int64)
		problem(c, http.StatusFailedDependency, "IOS_IPA_OBJECT_CHANGED", "The .ipa in release storage no longer matches what the server verified")
		return
	}
	etag := `"` + digest.String + `"`
	rng, hasRange, satisfiable := parseByteRange(c.GetHeader("Range"), size.Int64)
	if ifRange := strings.TrimSpace(c.GetHeader("If-Range")); hasRange && ifRange != "" && ifRange != etag {
		hasRange = false
	}
	if hasRange && !satisfiable {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(size.Int64, 10))
		c.Header("Accept-Ranges", "bytes")
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		c.Writer.WriteHeaderNow()
		return
	}
	start, end := int64(0), size.Int64-1
	var body io.ReadCloser
	if hasRange {
		start, end = rng.start, rng.end
		body, err = client.GetRange(ctx, key.String, start, end)
	} else {
		body, err = client.Get(ctx, key.String)
	}
	if err != nil {
		problem(c, http.StatusFailedDependency, "IOS_IPA_DOWNLOAD_FAILED", "Unable to read the .ipa from release storage")
		return
	}
	defer body.Close()
	// 审计记在开始发之前：发到一半断了也是一次下载
	s.auditNow(newAudit(tenantID(c), actor(c), "ios_ipa_download", "build-job", c.Param("id"), "downloaded a self-upload .ipa", requestID(c),
		map[string]any{"jobId": c.Param("id"), "sha256": digest.String, "rangeStart": start, "rangeEnd": end, "size": size.Int64}))
	c.Header("Content-Type", octetStream)
	c.Header("Content-Disposition", `attachment; filename="`+iosPackageObjectName(bundleID, version, buildNumber)+`"`)
	c.Header("Accept-Ranges", "bytes")
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-store")
	if hasRange {
		c.Header("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(size.Int64, 10))
		c.Header("Content-Length", strconv.FormatInt(end-start+1, 10))
		c.Status(http.StatusPartialContent)
	} else {
		c.Header("Content-Length", strconv.FormatInt(size.Int64, 10))
	}
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Warn("self-upload .ipa download stream ended early", "job", c.Param("id"), "error", err)
	}
}
