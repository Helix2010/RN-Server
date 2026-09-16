package api

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/gin-gonic/gin"
)

const otaMaxPackageBytes int64 = 512 * 1024 * 1024

type otaUploadToken struct {
	ID, TenantID, ObjectKey, FileName, ContentType string
	Size, ExpiresAt                                int64
}

type otaClientIdentity struct {
	APIBaseURL    string
	ApplicationID string
	AppVersion    string
	BuildNumber   int
	Platform      string
	Distribution  string
	OTAChannel    string
}

func (s *server) encodeOTAUploadToken(v otaUploadToken) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if s.secrets == nil {
		return "", errors.New("storage master key unavailable")
	}
	enc, err := s.secrets.Encrypt(string(raw), "ota-artifact:"+v.TenantID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func (s *server) decodeOTAUploadToken(tenant, encoded string) (otaUploadToken, error) {
	var v otaUploadToken
	if s.secrets == nil || strings.TrimSpace(encoded) == "" {
		return v, errors.New("OTA artifact token unavailable")
	}
	enc, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return v, errors.New("invalid OTA artifact token")
	}
	plain, err := s.secrets.Decrypt(enc, "ota-artifact:"+tenant)
	if err != nil || json.Unmarshal([]byte(plain), &v) != nil || v.TenantID != tenant || time.Now().UTC().Unix() > v.ExpiresAt {
		return v, errors.New("invalid or expired OTA artifact token")
	}
	return v, nil
}

func otaTokenFromRequest(c *gin.Context) string {
	if v := strings.TrimSpace(c.GetHeader("x-ota-artifact-token")); v != "" {
		return v
	}
	return strings.TrimSpace(c.Query("token"))
}

func (s *server) listOTABaseReleases(c *gin.Context) {
	platform := strings.ToLower(strings.TrimSpace(c.Query("platform")))
	query := `SELECT id,platform,version,build_number,runtime_version,status,file_metadata,created_at FROM app_releases WHERE tenant_id=? AND status IN ('verified','active') AND runtime_version<>'' AND (?='' OR platform=?) ORDER BY build_number DESC LIMIT 100`
	rows, err := s.db.QueryContext(c.Request.Context(), query, tenantID(c), platform, platform)
	if err != nil {
		problem(c, 500, "OTA_BASE_RELEASE_QUERY_FAILED", "Unable to load OTA base releases")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, p, version, runtime, status string
		var build int
		var fileMetadata []byte
		var created time.Time
		if err := rows.Scan(&id, &p, &version, &build, &runtime, &status, &fileMetadata, &created); err != nil {
			problem(c, 500, "OTA_BASE_RELEASE_QUERY_FAILED", "Unable to load OTA base releases")
			return
		}
		// 指纹缺失的基线仍然列出来，只是带着 null：管理端要能把它显示成"不可用 + 为什么"。
		// 直接从列表里滤掉更省事，但那样用户看到的是一个本该在的版本凭空消失，
		// 只能来问我们——而答案（"它比指纹功能早"）本来可以直接写在那一行上。
		items = append(items, gin.H{"id": id, "platform": p, "version": version, "buildNumber": build, "runtimeVersion": runtime, "status": status, "nativeFingerprint": nullableString(baseNativeFingerprint(fileMetadata)), "createdAt": iso(created)})
	}
	c.JSON(200, gin.H{"items": items, "nextCursor": nil, "hasMore": false})
}

var otaStatuses = []string{"draft", "verified", "active", "canary", "paused", "superseded", "rejected"}

// listOTAReleases GET /v1/admin/ota/releases（设计 admin-list-pagination-2026-09-14 §4.3）。
func (s *server) listOTAReleases(c *gin.Context) {
	ctx, tenant := c.Request.Context(), tenantID(c)
	where, page, invalid := parseOTAListFilter(c, tenant)
	if invalid != "" {
		problem(c, 422, "INVALID_OTA_FILTER", invalid)
		return
	}
	// 计数与取页用同一个 JOIN：基线行不在的 OTA 取页时查不出来，计数也不能算它
	const from = `ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id`
	total, err := s.countListRows(ctx, from, where)
	if err != nil {
		problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
		return
	}
	query := where.and(page.after)
	rows, err := s.db.QueryContext(ctx, `SELECT o.id,o.base_release_id,o.platform,o.channel,o.runtime_version,o.revision,o.update_id,o.release_kind,o.apply_strategy,o.status,o.canary_installations,o.manifest_sha256,o.release_notes,o.source_commit_sha,o.rejection_reason,o.created_by,o.verified_at,o.published_at,o.created_at,o.updated_at, a.version,a.build_number FROM `+from+` WHERE `+query.sql()+` ORDER BY o.revision DESC, o.created_at DESC, o.id DESC LIMIT ?`, append(query.args, page.limit+1)...)
	if err != nil {
		problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
		return
	}
	defer rows.Close()
	items, cursors := []gin.H{}, []string{}
	for rows.Next() {
		var id, base, p, channel, runtime, updateID, kind, applyStrategy, st, creator, notes, baseVersion string
		var sha, source, rejection sql.NullString
		var audience []byte
		var revision, baseBuild int
		var verified, published, created, updated sql.NullTime
		if err := rows.Scan(&id, &base, &p, &channel, &runtime, &revision, &updateID, &kind, &applyStrategy, &st, &audience, &sha, &notes, &source, &rejection, &creator, &verified, &published, &created, &updated, &baseVersion, &baseBuild); err != nil {
			problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
			return
		}
		// 按公开契约的形状解析：语言 -> 行数组。写入侧已拒绝别的形状，库里再出现
		// 就是数据事故，整份列表直接失败，不把不符合契约的响应交给管理端
		var noteValue map[string][]string
		if err := json.Unmarshal([]byte(notes), &noteValue); err != nil {
			problem(c, 500, "OTA_RELEASE_NOTES_CORRUPT", "Stored release notes do not match the published shape")
			return
		}
		items = append(items, gin.H{"id": id, "baseReleaseId": base, "baseVersion": baseVersion, "baseBuildNumber": baseBuild, "platform": p, "channel": channel, "runtimeVersion": runtime, "revision": revision, "updateId": updateID, "releaseKind": kind, "applyStrategy": applyStrategy, "status": st, "canaryInstallations": canaryAudienceForStatus(st, audience), "manifestSha256": nullableString(sha.String), "releaseNotes": noteValue, "sourceCommitSha": nullableString(source.String), "rejectionReason": nullableString(rejection.String), "createdBy": creator, "verifiedAt": nullableOTAFieldTime(verified), "publishedAt": nullableOTAFieldTime(published), "createdAt": nullableOTAFieldTime(created), "updatedAt": nullableOTAFieldTime(updated)})
		cursors = append(cursors, encodeListCursor(revision, created.Time, id))
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
		return
	}
	bases, err := s.otaListBaseReleases(ctx, tenant, strings.TrimSpace(c.Query("platform")))
	if err != nil {
		problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
		return
	}
	items, next := finishListPage(items, cursors, page.limit)
	response := listResponse(items, total, next, page.limit)
	response["baseReleases"] = bases
	c.JSON(200, response)
}

func parseOTAListFilter(c *gin.Context, tenant string) (sqlWhere, listPage, string) {
	where := sqlWhere{}
	where.add("o.tenant_id=?", tenant)
	if invalid := addEnumFilter(c, &where, "platform", "o.platform", "android", "ios"); invalid != "" {
		return where, listPage{}, invalid
	}
	if invalid := addEnumFilter(c, &where, "status", "o.status", otaStatuses...); invalid != "" {
		return where, listPage{}, invalid
	}
	addExactFilter(c, &where, "channel", "o.channel")
	addExactFilter(c, &where, "baseReleaseId", "o.base_release_id")
	page, invalid := parseListPage(c, sortKey{"o.revision", cursorUint}, sortKey{"o.created_at", cursorTime}, sortKey{"o.id", cursorText})
	return where, page, invalid
}

// otaListBaseReleases 有 OTA 记录的基线 APK（去重），给列表的"基线 APK"筛选当选项。
// 不能从当前页去重：分页之后当前页不代表全集。也不能用 /ota/base-releases：那里只列
// verified/active 的基线，已暂停、已完成基线上的 OTA 记录会筛不出来。
func (s *server) otaListBaseReleases(ctx context.Context, tenant, platform string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT a.id,a.platform,a.version,a.build_number FROM ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id WHERE o.tenant_id=? AND (?='' OR o.platform=?) ORDER BY a.build_number DESC, a.id DESC`, tenant, platform, platform)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, p, version string
		var build int
		if err := rows.Scan(&id, &p, &version, &build); err != nil {
			return nil, err
		}
		items = append(items, gin.H{"id": id, "platform": p, "version": version, "buildNumber": build})
	}
	return items, rows.Err()
}

func (s *server) otaReleaseDetail(c *gin.Context) {
	var id, baseID, platform, channel, runtime, updateID, kind, applyStrategy, status, baseVersion, creator string
	var revision, baseBuild int
	var manifestKey, manifestSHA, source, reject sql.NullString
	var notes, audience []byte
	var verified, published, created, updated sql.NullTime
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT o.id,o.base_release_id,o.platform,o.channel,o.runtime_version,o.revision,o.update_id,o.release_kind,o.apply_strategy,o.status,o.canary_installations,o.manifest_key,o.manifest_sha256,o.release_notes,o.source_commit_sha,o.rejection_reason,o.created_by,o.verified_at,o.published_at,o.created_at,o.updated_at,a.version,a.build_number FROM ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id WHERE o.tenant_id=? AND o.id=?`, tenantID(c), c.Param("id")).Scan(&id, &baseID, &platform, &channel, &runtime, &revision, &updateID, &kind, &applyStrategy, &status, &audience, &manifestKey, &manifestSHA, &notes, &source, &reject, &creator, &verified, &published, &created, &updated, &baseVersion, &baseBuild)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "OTA_NOT_FOUND", "OTA release not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_QUERY_FAILED", "Unable to load OTA release")
		return
	}
	var releaseNotes map[string][]string
	if err := json.Unmarshal(notes, &releaseNotes); err != nil {
		problem(c, 500, "OTA_RELEASE_NOTES_CORRUPT", "Stored release notes do not match the published shape")
		return
	}
	baseMetadata := map[string]any{}
	var rawBaseMetadata []byte
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT file_metadata FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), baseID).Scan(&rawBaseMetadata); err == nil {
		_ = json.Unmarshal(rawBaseMetadata, &baseMetadata)
	}
	var manifest map[string]any
	if manifestKey.Valid {
		client, _, storageErr := s.storageClientForTenant(c.Request.Context(), tenantID(c))
		if storageErr != nil {
			problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
			return
		}
		body, getErr := client.Get(c.Request.Context(), manifestKey.String)
		if getErr != nil {
			problem(c, http.StatusFailedDependency, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(body, 8*1024*1024))
		_ = body.Close()
		if readErr != nil || (manifestSHA.Valid && hex.EncodeToString(hashBytes(raw)) != manifestSHA.String) || json.Unmarshal(raw, &manifest) != nil {
			problem(c, http.StatusFailedDependency, "OTA_MANIFEST_INVALID", "OTA manifest integrity check failed")
			return
		}
	}
	identity := otaManifestIdentity(manifest)
	c.JSON(http.StatusOK, gin.H{
		"release":      gin.H{"id": id, "baseReleaseId": baseID, "baseVersion": baseVersion, "baseBuildNumber": baseBuild, "platform": platform, "channel": channel, "runtimeVersion": runtime, "revision": revision, "updateId": updateID, "releaseKind": kind, "applyStrategy": applyStrategy, "status": status, "canaryInstallations": canaryAudienceForStatus(status, audience), "manifestKey": nullableString(manifestKey.String), "manifestSha256": nullableString(manifestSHA.String), "releaseNotes": releaseNotes, "sourceCommitSha": nullableString(source.String), "rejectionReason": nullableString(reject.String), "createdBy": creator, "verifiedAt": nullableOTAFieldTime(verified), "publishedAt": nullableOTAFieldTime(published), "createdAt": nullableOTAFieldTime(created), "updatedAt": nullableOTAFieldTime(updated)},
		"identity":     identity,
		"baseMetadata": baseMetadata,
		"manifest":     manifest,
	})
}

func nullableOTAFieldTime(v sql.NullTime) any {
	if !v.Valid {
		return nil
	}
	return iso(v.Time)
}

func (s *server) createOTAUploader(c *gin.Context) {
	var body struct {
		FileName, ContentType, BaseReleaseID, Channel string
		Size                                          int64
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_OTA_UPLOAD", "Invalid OTA upload payload")
		return
	}
	body.FileName = path.Base(strings.TrimSpace(body.FileName))
	body.ContentType = strings.ToLower(strings.TrimSpace(body.ContentType))
	body.Channel = strings.TrimSpace(body.Channel)
	if body.FileName == "" || body.Size < 1 || body.Size > otaMaxPackageBytes || body.BaseReleaseID == "" || body.Channel == "" {
		problem(c, 400, "INVALID_OTA_UPLOAD", "fileName, size, baseReleaseId and channel are required")
		return
	}
	var platform, runtime, status string
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT platform,runtime_version,status FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), body.BaseReleaseID).Scan(&platform, &runtime, &status); err != nil {
		problem(c, 404, "OTA_BASE_RELEASE_NOT_FOUND", "Base APK release not found")
		return
	}
	if platform != "android" && platform != "ios" || (status != "verified" && status != "active") {
		problem(c, 422, "OTA_BASE_RELEASE_INVALID", "Base release must be a verified or active Android/iOS release")
		return
	}
	_, prefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	id := "ota_art_" + randomID(16)
	key := strings.TrimLeft(path.Join(prefix, "tenants", tenantID(c), "ota-uploads", id, "package.zip"), "/")
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second).Unix()
	tok, err := s.encodeOTAUploadToken(otaUploadToken{ID: id, TenantID: tenantID(c), ObjectKey: key, FileName: body.FileName, ContentType: body.ContentType, Size: body.Size, ExpiresAt: expiresAt})
	if err != nil {
		problem(c, 503, "OTA_TOKEN_UNAVAILABLE", "OTA upload signing is not configured")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// 只有构建任务会走到这里（buildJobOTAUpload），回传地址是代理通道那一条
	url := s.absoluteURL(c, "/v1/build-agent/jobs/"+c.Param("id")+"/ota-artifact")
	headers := map[string]string{"content-type": body.ContentType, "x-ota-artifact-token": tok}
	requires := true
	if s.cfg.ArtifactUploadMode == "direct" {
		url, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		requires = false
		if err != nil {
			problem(c, http.StatusFailedDependency, "OTA_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
			return
		}
	}
	c.JSON(201, gin.H{"artifact": gin.H{"id": id, "token": tok, "fileName": body.FileName, "contentType": body.ContentType, "size": body.Size, "objectKey": key, "baseReleaseId": body.BaseReleaseID, "platform": platform, "runtimeVersion": runtime, "channel": body.Channel, "expiresAt": iso(time.Unix(expiresAt, 0).UTC())}, "upload": gin.H{"method": "PUT", "url": url, "headers": headers, "expiresAt": iso(time.Unix(expiresAt, 0).UTC()), "requiresCredentials": requires}})
}

func (s *server) uploadOTAArtifact(c *gin.Context) {
	if s.cfg.ArtifactUploadMode != "proxy" {
		problem(c, 404, "OTA_UPLOAD_PROXY_DISABLED", "Server-side OTA upload is disabled")
		return
	}
	v, err := s.decodeOTAUploadToken(tenantID(c), otaTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_OTA_ARTIFACT_TOKEN", err.Error())
		return
	}
	if c.Request.ContentLength != v.Size {
		problem(c, 411, "OTA_UPLOAD_SIZE_MISMATCH", "Uploaded file size does not match declaration")
		return
	}
	size, err := s.receiveAndStoreArtifact(c, v.ObjectKey, v.ContentType, v.Size)
	if err != nil {
		slog.Error("OTA artifact proxy upload failed", "tenant", tenantID(c), "artifactId", v.ID, "objectKey", v.ObjectKey, "expectedSize", v.Size, "error", err)
		problem(c, http.StatusFailedDependency, "OTA_UPLOAD_FAILED", err.Error())
		return
	}
	c.JSON(200, gin.H{"artifact": gin.H{"id": v.ID, "fileSize": size, "objectKey": v.ObjectKey}})
}

func (s *server) saveOTARelease(c *gin.Context) {
	var body struct {
		ArtifactToken, BaseReleaseID, Channel, SourceCommitSHA, ApplyStrategy string
		ReleaseNotes                                                          map[string]any `json:"releaseNotes"`
	}
	// 解码失败要说清是哪个字段。这个结构体没有 confirm，而同类接口大多要求
	// confirm=true——照着别处的写法带上它，DisallowUnknownFields 就会拒掉整个
	// 请求，而报错只说"payload 无效"，完全看不出多了什么
	if err := decode(c, &body); err != nil {
		problem(c, 400, "INVALID_OTA_RELEASE", "Request body was rejected: "+err.Error())
		return
	}
	body.ApplyStrategy = strings.TrimSpace(body.ApplyStrategy)
	body.Channel = strings.TrimSpace(body.Channel)
	if body.ApplyStrategy == "" {
		body.ApplyStrategy = "next_launch"
	}
	if body.ArtifactToken == "" || body.BaseReleaseID == "" || body.Channel == "" {
		problem(c, 400, "INVALID_OTA_RELEASE", "artifactToken, baseReleaseId and channel are required")
		return
	}
	if body.ApplyStrategy != "next_launch" && body.ApplyStrategy != "immediate" {
		problem(c, 422, "INVALID_OTA_APPLY_STRATEGY", "applyStrategy must be next_launch or immediate")
		return
	}
	releaseNotes, notesCode, notesDetail := normalizeReleaseNotes(body.ReleaseNotes)
	if notesCode != "" {
		problem(c, 422, notesCode, notesDetail)
		return
	}
	v, err := s.decodeOTAUploadToken(tenantID(c), body.ArtifactToken)
	if err != nil {
		problem(c, 401, "INVALID_OTA_ARTIFACT_TOKEN", err.Error())
		return
	}
	var basePlatform, baseRuntime, baseStatus, baseVersion, baseObjectKey string
	var baseBuild int
	var baseFileMetadata []byte
	var baseSHA sql.NullString
	var baseSize sql.NullInt64
	if err = s.db.QueryRowContext(c.Request.Context(), `SELECT platform,runtime_version,status,version,build_number,file_metadata,object_key,sha256,file_size FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), body.BaseReleaseID).Scan(&basePlatform, &baseRuntime, &baseStatus, &baseVersion, &baseBuild, &baseFileMetadata, &baseObjectKey, &baseSHA, &baseSize); err != nil {
		problem(c, 404, "OTA_BASE_RELEASE_NOT_FOUND", "Base APK release not found")
		return
	}
	if basePlatform != "android" && basePlatform != "ios" || (baseStatus != "verified" && baseStatus != "active") {
		problem(c, 422, "OTA_BASE_RELEASE_INVALID", "Base release must be verified or active Android/iOS")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// The upload object is temporary staging data. Remove it after finalize
	// succeeds or fails; interrupted uploads are handled by storage lifecycle.
	defer client.Delete(context.Background(), v.ObjectKey)
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	// OTA 的应用身份必须等于基线 APK 内嵌的 extra.applicationId（只有 Android 基线经过 apkinspect，
	// 有可信的内嵌值；iOS 基线服务端读不出来，暂不绑定并记 warning）。改动前入库的 Android 基线没有
	// 记这个值，从对象存储重新解析一次并回填 file_metadata；解析不出来的基线不能再挂 OTA
	baseApplicationID := ""
	if bindsApplicationIDToBase(basePlatform) {
		baseApplicationID, err = storedMetadataString(baseFileMetadata, "applicationId")
		if err != nil {
			problem(c, 500, "RELEASE_METADATA_INVALID", "Stored base release metadata is invalid")
			return
		}
		if baseApplicationID == "" {
			source := backfillSource{Tenant: tenantID(c), ReleaseID: body.BaseReleaseID, ObjectKey: baseObjectKey, SHA256: strings.ToLower(strings.TrimSpace(baseSHA.String)), Size: -1}
			if baseSize.Valid {
				source.Size = baseSize.Int64
			}
			baseApplicationID, err = s.backfillReleaseApplicationID(ctx, client, source, requestID(c))
			if errors.Is(err, errBaseReleaseChanged) {
				// 对象存储里的基线 APK 已不是入库时校验过的那个：不能拿它的身份写回数据库
				problem(c, http.StatusFailedDependency, "OTA_BASE_RELEASE_CHANGED", "Stored base APK no longer matches the verified release; re-create the base release before publishing OTA")
				return
			}
			if err != nil {
				slog.Error("unable to read the base APK for application id back-fill", "tenant", tenantID(c), "baseReleaseId", body.BaseReleaseID, "error", err)
				problem(c, http.StatusFailedDependency, "OTA_BASE_RELEASE_UNREADABLE", "Unable to read the base APK to determine its application id")
				return
			}
		}
		if baseApplicationID == "" {
			problem(c, 422, "OTA_BASE_APPLICATION_ID_UNKNOWN", "Base release does not carry an embedded application id; re-upload the base package")
			return
		}
	} else {
		slog.Warn("OTA application id is not bound to the base release: platform has no server-readable embedded config", "tenant", tenantID(c), "baseReleaseId", body.BaseReleaseID, "platform", basePlatform)
	}
	zipBody, err := client.Get(ctx, v.ObjectKey)
	if err != nil {
		problem(c, 422, "OTA_PACKAGE_MISSING", "Uploaded OTA package is missing")
		return
	}
	defer zipBody.Close()
	tmp, err := os.CreateTemp("", "rn-ota-*.zip")
	if err != nil {
		problem(c, 500, "OTA_VERIFY_FAILED", "Unable to prepare OTA verification")
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = io.Copy(tmp, io.LimitReader(zipBody, otaMaxPackageBytes+1)); err != nil {
		tmp.Close()
		problem(c, http.StatusFailedDependency, "OTA_READ_FAILED", "Unable to read OTA package")
		return
	}
	if err = tmp.Close(); err != nil {
		problem(c, 500, "OTA_VERIFY_FAILED", "Unable to prepare OTA verification")
		return
	}
	zr, err := zip.OpenReader(tmpPath)
	if err != nil {
		problem(c, 422, "OTA_VERIFY_FAILED", "OTA package must be a valid zip archive")
		return
	}
	defer zr.Close()
	manifestFile := (*zip.File)(nil)
	packageFiles := map[string]*zip.File{}
	for _, f := range zr.File {
		clean := path.Clean(f.Name)
		if !f.FileInfo().IsDir() && clean != "." && !strings.HasPrefix(clean, "../") {
			packageFiles[clean] = f
		}
		if clean == "manifest.json" {
			manifestFile = f
		}
	}
	if manifestFile == nil {
		problem(c, 422, "OTA_MANIFEST_MISSING", "OTA package manifest.json is required")
		return
	}
	manifestBytes, err := readZipEntry(manifestFile, 4*1024*1024)
	if err != nil {
		problem(c, 422, "OTA_MANIFEST_INVALID", "Unable to read OTA manifest")
		return
	}
	var manifest map[string]any
	if json.Unmarshal(manifestBytes, &manifest) != nil {
		problem(c, 422, "OTA_MANIFEST_INVALID", "OTA manifest must be valid JSON")
		return
	}
	if err := validateOTAManifestPackage(manifest, packageFiles, basePlatform, baseRuntime, body.Channel); err != nil {
		problem(c, 422, "OTA_MANIFEST_INVALID", err.Error())
		return
	}
	if bindsApplicationIDToBase(basePlatform) {
		if err := otaApplicationIDMismatch(manifest, baseApplicationID); err != nil {
			problem(c, 422, "OTA_APPLICATION_ID_MISMATCH", err.Error())
			return
		}
	}
	// 更新包不能改变应用身份：apiBaseUrl 决定设备此后把请求发给谁，
	// bootstrapSignerAddress 决定它信谁的签名。见 ota_identity.go。
	identity, err := s.tenantIdentityFor(c.Request.Context(), tenantID(c), baseVersion, baseBuild)
	if err != nil {
		problem(c, 500, "APP_IDENTITY_INVALID", err.Error())
		return
	}
	if err := otaIdentityMismatchAgainst(identity, manifest); err != nil {
		problem(c, 422, "OTA_IDENTITY_MISMATCH", err.Error())
		return
	}
	// 原生面变了就不能走热更新：设备会去调一个 APK 里不存在的原生模块（见 ota_fingerprint.go）
	if err := otaFingerprintMismatch(manifest, baseFileMetadata); err != nil {
		code := "OTA_NATIVE_CHANGED"
		if errors.Is(err, errOTAFingerprintMissing) {
			code = "OTA_BASE_FINGERPRINT_MISSING"
		}
		problem(c, 422, code, err.Error())
		return
	}
	updateID := manifest["id"].(string)
	releaseID := "ota_" + randomID(16)
	_, prefix, _ := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	baseKey := strings.TrimLeft(path.Join(prefix, "tenants", tenantID(c), "ota", body.Channel, basePlatform, baseRuntime, releaseID), "/")
	uploadedKeys := []string{}
	// 每个已上传资源对象的大小与 ETag（objectstore.Stat），下发前比对（otaAsset）。
	// manifest.json 不记：otaManifest 下发前按 manifest_sha256 校验全文，比 ETag 更强
	objectMetadata := map[string]any{}
	persisted := false
	defer func() {
		if !persisted {
			for _, key := range uploadedKeys {
				_ = client.Delete(context.Background(), key)
			}
		}
	}()
	// Upload immutable files and rewrite manifest URLs to the stable asset endpoint.
	for _, f := range zr.File {
		clean := path.Clean(f.Name)
		if f.FileInfo().IsDir() || clean == "manifest.json" || strings.HasPrefix(clean, "../") || clean == "." {
			continue
		}
		if err := s.putZipEntry(ctx, client, baseKey, clean, f); err != nil {
			problem(c, http.StatusFailedDependency, "OTA_RESOURCE_SAVE_FAILED", "Unable to store OTA resources")
			return
		}
		uploadedKeys = append(uploadedKeys, path.Join(baseKey, clean))
		storedObject, statErr := client.Stat(ctx, path.Join(baseKey, clean))
		if statErr != nil {
			problem(c, http.StatusFailedDependency, "OTA_RESOURCE_SAVE_FAILED", "Unable to verify stored OTA resources")
			return
		}
		if strings.TrimSpace(storedObject.ETag) == "" {
			// 没有 ETag 就没有"对象被替换"的可检测性：不能带着空值入库，否则下发时只剩大小比对
			problem(c, http.StatusFailedDependency, "OTA_OBJECT_ETAG_MISSING", "Object storage returned no ETag for a stored OTA resource; the package cannot be pinned")
			return
		}
		objectMetadata[clean] = map[string]any{"size": storedObject.Size, "etag": storedObject.ETag}
	}
	manifest["runtimeVersion"] = baseRuntime
	manifest["platform"] = basePlatform
	manifest["channel"] = body.Channel
	// 地址取**租户自己的** apiBaseUrl，不是请求的 Host。
	//
	// 2026-09-13 实测：打包机所有请求都发到它配置的那一个域名（api.anyfun.win），于是
	// 代理帮 predict 建的修订被写进了 anyfun 的资源地址，设备拉不到任何资源，报
	// AssetsFailedToLoad；而 extra.apiBaseUrl 也被一起改掉了——正是上面那道身份闸要防的
	// 事，只不过是服务端自己干的。Host 本来就不该决定"这个租户的 App 该连谁"。
	assetBase := strings.TrimRight(identity.APIBaseURL, "/")
	rewriteOTAClientIdentity(manifest, otaClientIdentity{
		APIBaseURL:    assetBase,
		ApplicationID: otaManifestExtraString(manifest, "applicationId"),
		AppVersion:    baseVersion,
		BuildNumber:   baseBuild,
		Platform:      basePlatform,
		Distribution:  otaDistribution(basePlatform, baseFileMetadata, manifest),
		OTAChannel:    body.Channel,
	})
	manifest["metadata"] = mergeManifestMetadata(manifest["metadata"], body.Channel, body.ApplyStrategy)
	manifest = rewriteManifestURLs(manifest, assetBase+"/v1/ota/assets/"+releaseID+"/")
	finalManifest, _ := json.Marshal(manifest)
	manifestKey := path.Join(baseKey, "manifest.json")
	if err := client.Put(ctx, manifestKey, strings.NewReader(string(finalManifest)), int64(len(finalManifest)), "application/json"); err != nil {
		problem(c, http.StatusFailedDependency, "OTA_RESOURCE_SAVE_FAILED", "Unable to store OTA manifest")
		return
	}
	uploadedKeys = append(uploadedKeys, manifestKey)
	rawObjectMetadata, _ := json.Marshal(objectMetadata)
	hash := sha256.Sum256(finalManifest)
	// map[string][]string 一定能序列化，没有需要处理的错误分支
	notes, _ := json.Marshal(releaseNotes)
	conn, err := s.db.Conn(c.Request.Context())
	if err != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to create OTA release")
		return
	}
	defer conn.Close()
	lock := otaSequenceLockName(tenantID(c), basePlatform, body.Channel, baseRuntime)
	var locked int
	if err = conn.QueryRowContext(c.Request.Context(), `SELECT GET_LOCK(?,5)`, lock).Scan(&locked); err != nil {
		problem(c, 500, "OTA_SEQUENCE_LOCK_FAILED", "Unable to coordinate OTA revision allocation")
		return
	}
	if locked != 1 {
		problem(c, 409, "OTA_SEQUENCE_BUSY", "Another OTA is being created for this runtime")
		return
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lock)
	tx, err := conn.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to create OTA release")
		return
	}
	defer tx.Rollback()
	var revision int
	_ = tx.QueryRowContext(c.Request.Context(), `SELECT COALESCE(MAX(revision),0)+1 FROM ota_releases WHERE tenant_id=? AND platform=? AND channel=? AND runtime_version=?`, tenantID(c), basePlatform, body.Channel, baseRuntime).Scan(&revision)
	now := time.Now().UTC()
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,apply_strategy,status,manifest_key,manifest_sha256,object_metadata,release_notes,source_commit_sha,created_by,verified_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, releaseID, tenantID(c), body.BaseReleaseID, basePlatform, body.Channel, baseRuntime, revision, updateID, body.ApplyStrategy, "verified", manifestKey, hex.EncodeToString(hash[:]), rawObjectMetadata, notes, nullableSQLValue(body.SourceCommitSHA), actor(c), now, now, now)
	if err != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to save OTA release")
		return
	}
	// applyStrategy 和 channel 一起记：applyStrategy=immediate 的含义是"拉到之后当场
	// 打断所有用户并重启应用"，是这条记录里后果最重的一个字段，而在此之前它**不在审计
	// 里**——2026-09-14 排查"我明明选了立即重启"时，只能从别处间接推断这条修订建出来
	// 时到底是什么值。后果最重的字段必须自己留痕。
	event := newAudit(tenantID(c), actor(c), "ota_create", "ota-release", releaseID, "OTA package verified and saved", requestID(c), map[string]any{"baseReleaseId": body.BaseReleaseID, "platform": basePlatform, "runtimeVersion": baseRuntime, "revision": revision, "applyStrategy": body.ApplyStrategy, "channel": body.Channel})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to save OTA audit")
		return
	}
	if tx.Commit() != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to commit OTA release")
		return
	}
	persisted = true
	c.JSON(201, gin.H{"release": gin.H{"id": releaseID, "baseReleaseId": body.BaseReleaseID, "platform": basePlatform, "channel": body.Channel, "runtimeVersion": baseRuntime, "revision": revision, "updateId": updateID, "applyStrategy": body.ApplyStrategy, "status": "verified", "manifestSha256": hex.EncodeToString(hash[:]), "releaseNotes": releaseNotes, "verifiedAt": iso(now), "createdAt": iso(now), "updatedAt": iso(now)}})
}

// commitOTACanaryAudience 在已经持有 slot 锁与事务的前提下改灰度名单，不动状态。
func (s *server) commitOTACanaryAudience(c *gin.Context, tx *sql.Tx, id, status string, audience []string, reason string) {
	now := s.now()
	audienceValue, _ := json.Marshal(audience)
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET canary_installations=?,updated_at=? WHERE tenant_id=? AND id=? AND status='canary'`, audienceValue, now, tenantID(c), id)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	// 同一毫秒里重复提交同一份名单时 RowsAffected 是 0，按条件复查（rowsMatched）
	if matched, err := rowsMatched(c.Request.Context(), tx, result, "ota_releases", "tenant_id=? AND id=? AND status='canary'", tenantID(c), id); err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	} else if !matched {
		problem(c, 409, "OTA_STATE_CHANGED", "OTA release changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ota_set_canary_audience", "ota-release", id, reason, requestID(c), map[string]any{"status": status, "canaryAudience": canaryAudienceDigest(audience)})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to save OTA audit")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": status, "canaryInstallations": audience})
}

func nullableSQLValue(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func otaSequenceLockName(tenant, platform, channel, runtime string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{tenant, platform, channel, runtime}, "\x00")))
	return "rn_ota_" + hex.EncodeToString(digest[:])[:56]
}

func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	r, e := f.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, limit+1))
}

func validateOTAManifestPackage(manifest map[string]any, files map[string]*zip.File, platform, runtime, channel string) error {
	if id, ok := manifest["id"].(string); !ok || !uuidPattern.MatchString(strings.TrimSpace(id)) {
		return errors.New("manifest id must be a UUID")
	}
	if value, _ := manifest["runtimeVersion"].(string); value != runtime {
		return errors.New("manifest runtimeVersion does not match the base APK")
	}
	if value, _ := manifest["platform"].(string); strings.ToLower(value) != platform {
		return errors.New("manifest platform does not match the base APK")
	}
	if value, exists := manifest["channel"].(string); exists && value != "" && value != channel {
		return errors.New("manifest channel does not match the selected channel")
	}
	if created, ok := manifest["createdAt"].(string); !ok || created == "" {
		return errors.New("manifest createdAt is required")
	} else if _, err := time.Parse(time.RFC3339, created); err != nil {
		return errors.New("manifest createdAt must be RFC 3339")
	}
	launch, ok := manifest["launchAsset"].(map[string]any)
	if !ok {
		return errors.New("manifest launchAsset is required")
	}
	if err := verifyOTAManifestAsset("launchAsset", launch, files); err != nil {
		return err
	}
	extra, ok := manifest["extra"].(map[string]any)
	if !ok || strings.TrimSpace(fmt.Sprint(extra["scopeKey"])) == "" {
		return errors.New("manifest extra.scopeKey is required")
	}
	// 应用身份（App 的 X-Application-ID）来自租户配置，OTA 构建脚本会写进 extra；
	// 这里只要求存在，不能拿基线 APK 的包名顶替：包名是 package_id，不是应用身份。
	// 它必须等于基线 APK 内嵌的 applicationId，这一步在 saveOTARelease 里做（otaApplicationIDMismatch）
	if otaManifestExtraString(manifest, "applicationId") == "" {
		return errors.New("manifest extra.applicationId is required")
	}
	assets, ok := manifest["assets"].([]any)
	if !ok {
		return errors.New("manifest assets must be an array")
	}
	for index, item := range assets {
		asset, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("manifest asset %d is invalid", index)
		}
		if err := verifyOTAManifestAsset(fmt.Sprintf("asset %d", index), asset, files); err != nil {
			return err
		}
	}
	return nil
}

// bindsApplicationIDToBase：只有 Android 基线经过 apkinspect，服务端有可信的内嵌 extra.applicationId 可比；
// iOS 基线（IPA）服务端不解析，暂不绑定（已在 OPERATIONS_AND_RELEASE.md §5 记为缺口）。
func bindsApplicationIDToBase(basePlatform string) bool { return basePlatform == "android" }

// otaApplicationIDMismatch 把 OTA 自带的应用身份绑到基线 APK：两者不同就是给另一个应用打的包，
// 装上后设备会以另一个身份上报（app_installations 出现同一台设备两条记录，安装凭证对不上）。
func otaApplicationIDMismatch(manifest map[string]any, baseApplicationID string) error {
	if strings.TrimSpace(baseApplicationID) == "" {
		return errors.New("base release application id is unknown")
	}
	if value := otaManifestExtraString(manifest, "applicationId"); value != baseApplicationID {
		return fmt.Errorf("manifest extra.applicationId %q does not match the base APK application id %q", value, baseApplicationID)
	}
	return nil
}

// backfillSource 是回填时要核对的基线记录：对象 key，以及入库时校验过的 sha256 与大小。
type backfillSource struct {
	Tenant, ReleaseID, ObjectKey string
	// 入库时的 sha256（小写 hex）；为空表示记录里没有，无法核对，回填拒绝
	SHA256 string
	// 入库时的字节数；-1 表示记录里没有
	Size int64
}

// errBaseReleaseChanged：对象存储里的基线 APK 与入库记录不符，调用方回 502 OTA_BASE_RELEASE_CHANGED。
var errBaseReleaseChanged = errors.New("stored base release no longer matches the verified artifact")

// backfillReleaseApplicationID 从对象存储重新解析基线 APK，把 extra.applicationId 写回 file_metadata。
// 只给改动前入库、file_metadata 里没有 applicationId 的基线用；之后的入库路径在校验时就记了。
// 解析前先核对下载到的字节与入库 sha256 / 大小一致：对象存储里的 APK 可能已被换成同大小的另一个包，
// 不能把替换件的身份写进数据库再放行匹配它的 OTA。
// 这是 OTA 事务之外的一次系统写入（回填的是既有事实，OTA 随后失败也不需要撤回），写 audit_events 留痕。
func (s *server) backfillReleaseApplicationID(ctx context.Context, client interface {
	Get(context.Context, string) (io.ReadCloser, error)
}, source backfillSource, requestID string) (string, error) {
	if source.SHA256 == "" || source.Size < 0 {
		return "", errors.New("base release has no stored sha256/size to verify the object against")
	}
	body, err := client.Get(ctx, source.ObjectKey)
	if err != nil {
		return "", fmt.Errorf("read base release object: %w", err)
	}
	defer body.Close()
	temporary, err := os.CreateTemp("", "rn-base-*.apk")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(body, s.cfg.ArtifactMaxSizeBytes+1))
	if err != nil {
		_ = temporary.Close()
		return "", fmt.Errorf("copy base release object: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return "", err
	}
	if written > s.cfg.ArtifactMaxSizeBytes {
		// 超过上限说明对象不是入库时那个 APK（入库时同一上限校验过）：不能截断后解析出一个错误身份
		return "", fmt.Errorf("base release object exceeds ARTIFACT_MAX_SIZE_MB (%d bytes read)", written)
	}
	actualSHA := hex.EncodeToString(digest.Sum(nil))
	if written != source.Size || actualSHA != source.SHA256 {
		slog.Error("stored base release changed after verification", "tenant", source.Tenant, "releaseId", source.ReleaseID, "storedSize", source.Size, "objectSize", written, "storedSha256", source.SHA256, "objectSha256", actualSHA)
		s.auditNow(newAudit(source.Tenant, "system-ota", "ota_base_release_changed", "release", source.ReleaseID, "Stored base APK no longer matches the verified release; application id back-fill refused", requestID, map[string]any{"storedSize": source.Size, "objectSize": written, "storedSha256": source.SHA256, "objectSha256": actualSHA}))
		return "", errBaseReleaseChanged
	}
	apk, err := apkinspect.Inspect(temporaryPath)
	if err != nil {
		return "", fmt.Errorf("inspect base release: %w", err)
	}
	if apk.ApplicationID == "" {
		return "", nil
	}
	if _, err = s.db.ExecContext(ctx, `UPDATE app_releases SET file_metadata=JSON_SET(COALESCE(file_metadata,JSON_OBJECT()),'$.applicationId',?),updated_at=? WHERE tenant_id=? AND id=?`, apk.ApplicationID, time.Now().UTC(), source.Tenant, source.ReleaseID); err != nil {
		return "", fmt.Errorf("persist base release application id: %w", err)
	}
	s.auditNow(newAudit(source.Tenant, "system-ota", "release_applicationid_backfilled", "release", source.ReleaseID, "Embedded application id read from the stored base APK and recorded in file_metadata", requestID, map[string]any{"applicationId": apk.ApplicationID, "packageName": apk.PackageName}))
	slog.Info("backfilled base release application id from the stored APK", "tenant", source.Tenant, "releaseId", source.ReleaseID, "applicationId", apk.ApplicationID)
	return apk.ApplicationID, nil
}

// legacyObjectWarning 对改列前入库、没有对象 ETag 记录的发布，每条只提醒一次：重新入库才能获得完整校验
func legacyObjectWarning(id, kind string) {
	if _, loaded := legacyObjectWarned.LoadOrStore(kind+":"+id, struct{}{}); !loaded {
		slog.Warn("release object has no stored ETag; only size is checked before download, re-create the release to pin the object", "kind", kind, "id", id)
	}
}

var legacyObjectWarned sync.Map

func verifyOTAManifestAsset(label string, asset map[string]any, files map[string]*zip.File) error {
	filePath, _ := asset["path"].(string)
	filePath = path.Clean(strings.TrimSpace(filePath))
	if filePath == "" || filePath == "." || strings.HasPrefix(filePath, "../") || strings.HasPrefix(filePath, "/") {
		return fmt.Errorf("manifest %s path is invalid", label)
	}
	file, exists := files[filePath]
	if !exists {
		return fmt.Errorf("manifest %s file is missing", label)
	}
	if key, _ := asset["key"].(string); strings.TrimSpace(key) == "" {
		return fmt.Errorf("manifest %s key is required", label)
	}
	if contentType, _ := asset["contentType"].(string); strings.TrimSpace(contentType) == "" {
		return fmt.Errorf("manifest %s contentType is required", label)
	}
	if urlValue, _ := asset["url"].(string); strings.TrimSpace(urlValue) == "" {
		return fmt.Errorf("manifest %s url is required", label)
	}
	if fileExtension, _ := asset["fileExtension"].(string); strings.TrimSpace(fileExtension) == "" {
		return fmt.Errorf("manifest %s fileExtension is required", label)
	}
	expected, _ := asset["hash"].(string)
	if expected == "" {
		return fmt.Errorf("manifest %s hash is required", label)
	}
	raw, err := readZipEntry(file, otaMaxPackageBytes)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", label, err)
	}
	digest := sha256.Sum256(raw)
	base64Hash := base64.RawURLEncoding.EncodeToString(digest[:])
	if expected != base64Hash && !strings.EqualFold(expected, hex.EncodeToString(digest[:])) {
		return fmt.Errorf("manifest %s hash does not match file content", label)
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func (s *server) putZipEntry(ctx context.Context, client interface {
	Put(context.Context, string, io.Reader, int64, string) error
}, base, key string, f *zip.File) error {
	r, e := f.Open()
	if e != nil {
		return e
	}
	defer r.Close()
	info := f.FileInfo()
	if info.Size() > otaMaxPackageBytes {
		return errors.New("resource too large")
	}
	return client.Put(ctx, path.Join(base, key), io.LimitReader(r, info.Size()), info.Size(), contentTypeForPath(key))
}
func contentTypeForPath(name string) string {
	ext := strings.ToLower(path.Ext(name))
	switch ext {
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".ttf":
		return "font/ttf"
	default:
		return "application/octet-stream"
	}
}
func mergeManifestMetadata(v any, channel, applyStrategy string) map[string]any {
	m := map[string]any{"channel": channel, "applyStrategy": applyStrategy}
	if x, ok := v.(map[string]any); ok {
		for k, val := range x {
			m[k] = val
		}
	}
	return m
}

func rewriteOTAClientIdentity(manifest map[string]any, identity otaClientIdentity) {
	extra, _ := manifest["extra"].(map[string]any)
	if extra == nil {
		extra = map[string]any{}
	}
	expoClient, _ := extra["expoClient"].(map[string]any)
	if expoClient == nil {
		expoClient = map[string]any{}
	}
	expoClient["version"] = identity.AppVersion
	android, _ := expoClient["android"].(map[string]any)
	if identity.Platform == "android" {
		if android == nil {
			android = map[string]any{}
		}
		android["versionCode"] = identity.BuildNumber
		expoClient["android"] = android
	}
	ios, _ := expoClient["ios"].(map[string]any)
	if identity.Platform == "ios" {
		if ios == nil {
			ios = map[string]any{}
		}
		ios["buildNumber"] = fmt.Sprint(identity.BuildNumber)
		expoClient["ios"] = ios
	}
	clientExtra, _ := expoClient["extra"].(map[string]any)
	if clientExtra == nil {
		clientExtra = map[string]any{}
	}
	clientExtra["apiBaseUrl"] = identity.APIBaseURL
	clientExtra["distributionChannel"] = identity.Distribution
	clientExtra["otaChannel"] = identity.OTAChannel
	clientExtra["applicationId"] = identity.ApplicationID
	clientExtra["appVersion"] = identity.AppVersion
	clientExtra["buildNumber"] = fmt.Sprint(identity.BuildNumber)
	expoClient["extra"] = clientExtra
	updates, _ := expoClient["updates"].(map[string]any)
	if updates == nil {
		updates = map[string]any{}
	}
	updates["url"] = strings.TrimRight(identity.APIBaseURL, "/") + "/v1/ota/manifest"
	expoClient["updates"] = updates
	extra["expoClient"] = expoClient
	extra["scopeKey"] = identity.APIBaseURL
	extra["apiBaseUrl"] = identity.APIBaseURL
	extra["distributionChannel"] = identity.Distribution
	extra["otaChannel"] = identity.OTAChannel
	extra["applicationId"] = identity.ApplicationID
	extra["appVersion"] = identity.AppVersion
	extra["buildNumber"] = identity.BuildNumber
	manifest["extra"] = extra
}

func otaDistribution(platform string, raw []byte, manifest map[string]any) string {
	var metadata map[string]any
	if json.Unmarshal(raw, &metadata) == nil {
		if value, ok := metadata["distributionChannel"].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if value := otaManifestExtraString(manifest, "distributionChannel"); oneOf(value, "development", "staging", "store", "direct", "mdm") {
		return value
	}
	if platform == "ios" {
		return "mdm"
	}
	return "direct"
}

func otaManifestExtraString(manifest map[string]any, key string) string {
	extra, _ := manifest["extra"].(map[string]any)
	if value, ok := extra[key].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	expoClient, _ := extra["expoClient"].(map[string]any)
	clientExtra, _ := expoClient["extra"].(map[string]any)
	if value, ok := clientExtra[key].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return ""
}

func otaManifestIdentity(manifest map[string]any) gin.H {
	identity := gin.H{}
	extra, _ := manifest["extra"].(map[string]any)
	client, _ := extra["expoClient"].(map[string]any)
	clientExtra, _ := client["extra"].(map[string]any)
	put := func(key string, values ...map[string]any) {
		for _, source := range values {
			if value, ok := source[key]; ok {
				identity[key] = value
				return
			}
		}
	}
	put("apiBaseUrl", extra, clientExtra)
	put("distributionChannel", extra, clientExtra)
	put("otaChannel", extra, clientExtra)
	put("applicationId", extra, clientExtra)
	put("appVersion", extra, clientExtra)
	put("buildNumber", extra, clientExtra)
	if value, ok := client["version"]; ok {
		identity["expoClientVersion"] = value
	}
	put("runtimeVersion", manifest)
	put("platform", manifest)
	put("channel", manifest)
	if android, ok := client["android"].(map[string]any); ok {
		if value, exists := android["versionCode"]; exists {
			identity["expoClientAndroidVersionCode"] = value
		}
	}
	if ios, ok := client["ios"].(map[string]any); ok {
		if value, exists := ios["buildNumber"]; exists {
			identity["expoClientIOSBuildNumber"] = value
		}
	}
	if len(identity) == 0 {
		return nil
	}
	return identity
}
func rewriteManifestURLs(m map[string]any, base string) map[string]any {
	if x, ok := m["launchAsset"].(map[string]any); ok {
		if p, ok := x["path"].(string); ok {
			x["url"] = base + strings.TrimLeft(path.Clean(p), "/")
		} else if _, ok := x["url"]; !ok {
			x["url"] = base + "bundle.js"
		}
		m["launchAsset"] = x
	}
	if arr, ok := m["assets"].([]any); ok {
		for _, item := range arr {
			if x, ok := item.(map[string]any); ok {
				if p, ok := x["path"].(string); ok {
					x["url"] = base + strings.TrimLeft(path.Clean(p), "/")
				}
			}
		}
	}
	return m
}

func (s *server) otaManifest(c *gin.Context) {
	platform := strings.ToLower(strings.TrimSpace(c.GetHeader("expo-platform")))
	if platform == "" {
		platform = strings.ToLower(strings.TrimSpace(c.Query("platform")))
	}
	runtime := strings.TrimSpace(c.GetHeader("expo-runtime-version"))
	if runtime == "" {
		runtime = strings.TrimSpace(c.Query("runtimeVersion"))
	}
	channel := strings.TrimSpace(c.GetHeader("expo-channel-name"))
	if channel == "" {
		channel = tenantOTAChannel
	}
	if platform == "" || runtime == "" {
		writeExpoNoUpdate(c)
		return
	}
	appVersion, buildNumber, baselineOK := otaClientBaseline(c)
	if !baselineOK {
		writeExpoNoUpdate(c)
		return
	}
	if protocol := strings.TrimSpace(c.GetHeader("expo-protocol-version")); protocol != "" && protocol != "1" {
		problem(c, http.StatusBadRequest, "OTA_PROTOCOL_UNSUPPORTED", "Unsupported Expo Updates protocol version")
		return
	}
	var id, kind, strategy string
	var key, sha sql.NullString
	var published sql.NullTime
	// 灰度：这条请求带不了 Authorization，身份来自 bootstrap 下发、原生侧
	// 通过 Expo-Extra-Params 捎回来的短时令牌。令牌过期 / 伪造 / 不带一律空串，
	// 设备静默回到 active 修订（canary.go）
	audience := s.canaryAudienceFromExtraParams(c, tenantID(c))
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT o.id,o.release_kind,o.apply_strategy,o.manifest_key,o.manifest_sha256,o.published_at FROM ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id WHERE o.tenant_id=? AND o.platform=? AND o.channel=? AND o.runtime_version=? AND `+canaryVisibleOTASQL+` AND (?='' OR a.version=?) AND (?='' OR CAST(a.build_number AS CHAR)=?) ORDER BY o.revision DESC LIMIT 1`, tenantID(c), platform, channel, runtime, audience, audience, appVersion, appVersion, buildNumber, buildNumber).Scan(&id, &kind, &strategy, &key, &sha, &published)
	if errors.Is(err, sql.ErrNoRows) {
		writeExpoNoUpdate(c)
		return
	}
	if err != nil {
		problem(c, 500, "OTA_MANIFEST_QUERY_FAILED", "Unable to load OTA manifest")
		return
	}
	// 签名器在分支之前取：directive 和 manifest 都要签。rollBackToEmbedded 尤其
	// 不能漏——它本身就是一条"把所有人退回内置版本"的指令，未签名的它等于给任何
	// 能顶替这条响应的人一个远程降级开关（安全评审 N19）。
	signer, signerErr := s.otaSignerFor(c.Request.Context(), tenantID(c))
	if signerErr != nil {
		slog.Error("ota signing key is configured but unusable", "tenant", tenantID(c), "error", signerErr)
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_KEY_INVALID", "The configured OTA signing key cannot be used")
		return
	}
	// 客户端要验签而我们没有密钥：它会拒绝这次更新并停在内置 bundle。这个故障
	// 在设备上完全静默，只能从服务端看见，所以一定要留下痕迹。按 (租户, 运行时)
	// 去重，避免公开端点被反复请求时刷屏。
	if signer == nil && clientExpectsOTASignature(c.GetHeader("expo-expect-signature")) &&
		objectChanges.shouldNotify("ota-unsigned:"+tenantID(c)+":"+runtime, time.Now()) {
		slog.Warn("client asked for a signed OTA manifest but this tenant has no signing key",
			"tenant", tenantID(c), "runtimeVersion", runtime, "platform", platform)
	}
	if kind == "rollback" {
		commitTime := time.Now().UTC()
		if published.Valid {
			commitTime = published.Time.UTC()
		}
		payload, _ := json.Marshal(gin.H{"type": "rollBackToEmbedded", "parameters": gin.H{"commitTime": iso(commitTime)}})
		signature, err := signer.sign(payload)
		if err != nil {
			problem(c, http.StatusInternalServerError, "OTA_SIGNING_FAILED", "Unable to sign the OTA directive")
			return
		}
		writeExpoMultipart(c, "directive", payload, signature)
		return
	}
	if !key.Valid || !sha.Valid {
		problem(c, http.StatusFailedDependency, "OTA_MANIFEST_INVALID", "OTA manifest is unavailable")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	body, err := client.Get(c.Request.Context(), key.String)
	if err != nil {
		problem(c, http.StatusFailedDependency, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
		return
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, 8*1024*1024))
	if err != nil {
		problem(c, http.StatusFailedDependency, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
		return
	}
	if hex.EncodeToString(hashBytes(raw)) != sha.String {
		problem(c, http.StatusFailedDependency, "OTA_MANIFEST_INVALID", "OTA manifest integrity check failed")
		return
	}
	// 生效策略以数据库为准（管理端可事后改）：ETag 要把策略算进去，否则改完客户端拿到 304。
	// 签名的 keyid 同理——装上或换掉签名密钥时 manifest 字节并没有变，不把它算进 ETag
	// 的话，带 if-none-match 的客户端会一直拿 304，永远收不到那个签名。
	signerKeyID := ""
	if signer != nil {
		signerKeyID = signer.keyID
	}
	etag := `"` + sha.String + "-" + strategy + "-" + signerKeyID + `"`
	if strings.TrimSpace(c.GetHeader("if-none-match")) == etag {
		c.Header("ETag", etag)
		c.Status(http.StatusNotModified)
		return
	}
	if raw, err = applyManifestStrategy(raw, strategy); err != nil {
		problem(c, http.StatusFailedDependency, "OTA_MANIFEST_INVALID", "OTA manifest is not valid JSON")
		return
	}
	// 签的是**改写完成后**的字节。对入库原文签名等于把 applyManifestStrategy 那段
	// 改写留在签名覆盖范围之外（安全评审 §13 阶段 0b-2）。
	signature, err := signer.sign(raw)
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_FAILED", "Unable to sign the OTA manifest")
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Header("expo-protocol-version", "1")
	c.Header("expo-sfv-version", "0")
	c.Header("ETag", etag)
	if strings.Contains(c.GetHeader("Accept"), "multipart/mixed") {
		writeExpoMultipart(c, "manifest", raw, signature)
		return
	}
	// plain 响应里签名是 HTTP 响应头（FileDownloader.kt:478）
	if signature != "" {
		c.Header("expo-signature", signature)
	}
	c.Data(200, "application/expo+json", raw)
}

// otaFlagEditable：生效策略只对还会下发给客户端的记录有意义——待发布、活跃、灰度、暂停；
// 已被新 revision 取代或被拒绝的记录改了没有效果，拒绝。灰度修订确实会下发给名单里的
// 设备，所以它的生效策略必须可改；全量包那边的 mandatory 恰好相反（设计 §3.5 禁止
// 灰度版本设强制升级），两个开关的可编辑状态不一样，不要合并。
func otaFlagEditable(status string) bool {
	return status == "verified" || status == "active" || status == "canary" || status == "paused"
}

// setOTAApplyStrategy 事后修改 OTA 的生效策略（管理端列表里的开关）。
// manifest 文件里登记时写死的 metadata.applyStrategy 不改，下发时用数据库里的值覆盖
// （applyManifestStrategy）；bootstrap 本来就读数据库，App 以 bootstrap 为准。
func (s *server) setOTAApplyStrategy(c *gin.Context, id, strategy, reason string) {
	if strategy != "next_launch" && strategy != "immediate" {
		problem(c, 422, "INVALID_OTA_APPLY_STRATEGY", "applyStrategy must be next_launch or immediate")
		return
	}
	var status, previous string
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT status,apply_strategy FROM ota_releases WHERE tenant_id=? AND id=?`, tenantID(c), id).Scan(&status, &previous); err != nil {
		problem(c, 404, "OTA_NOT_FOUND", "OTA release not found")
		return
	}
	if !otaFlagEditable(status) {
		problem(c, 409, "OTA_FLAG_LOCKED", fmt.Sprintf("Cannot change the apply strategy of a %s OTA release", status))
		return
	}
	now := s.now()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET apply_strategy=?,updated_at=? WHERE tenant_id=? AND id=? AND status=?`, strategy, now, tenantID(c), id, status)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	if matched, err := rowsMatched(c.Request.Context(), tx, result, "ota_releases", "tenant_id=? AND id=? AND status=?", tenantID(c), id, status); err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	} else if !matched {
		problem(c, 409, "OTA_STATE_CHANGED", "OTA release changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ota_set_apply_strategy", "ota-release", id, reason, requestID(c), map[string]any{"status": status, "applyStrategy": strategy, "previous": previous})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to save OTA audit")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "status": status, "applyStrategy": strategy})
}

// applyManifestStrategy 用数据库里当前的生效策略覆盖 manifest 文件里登记时写死的值。
// 文件与 manifest_sha256 保持不动（完整性校验仍对原文件），返回的字节是下发给客户端的内容。
func applyManifestStrategy(raw []byte, strategy string) ([]byte, error) {
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	metadata, _ := manifest["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
	}
	if current, _ := metadata["applyStrategy"].(string); current == strategy {
		return raw, nil
	}
	metadata["applyStrategy"] = strategy
	manifest["metadata"] = metadata
	return json.Marshal(manifest)
}

func otaClientBaseline(c *gin.Context) (string, string, bool) {
	appVersion := strings.TrimSpace(c.GetHeader("x-app-version"))
	buildNumber := strings.TrimSpace(c.GetHeader("x-build-number"))
	return appVersion, buildNumber, appVersion != "" && buildNumber != ""
}

func writeExpoNoUpdate(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
	c.Header("expo-protocol-version", "1")
	c.Header("expo-sfv-version", "0")
	c.Status(http.StatusNoContent)
	c.Writer.WriteHeaderNow()
}

func hashBytes(v []byte) []byte { h := sha256.Sum256(v); return h[:] }

// writeExpoMultipart 写 multipart 响应。`signature` 非空时作为**part 的头**带上——
// multipart 下 expo-updates 是从 part 头里读 expo-signature 的，不是从 HTTP 响应头
// （FileDownloader.kt:556,570）。写错位置的表现是"签了但客户端说没签名"。
func writeExpoMultipart(c *gin.Context, name string, payload []byte, signature string) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="`+name+`"`)
	header.Set("Content-Type", "application/json")
	if signature != "" {
		header.Set("expo-signature", signature)
	}
	part, err := writer.CreatePart(header)
	if err != nil {
		problem(c, 500, "OTA_PROTOCOL_WRITE_FAILED", "Unable to encode OTA response")
		return
	}
	_, _ = part.Write(payload)
	_ = writer.Close()
	c.Header("Cache-Control", "no-cache")
	c.Header("expo-protocol-version", "1")
	c.Header("expo-sfv-version", "0")
	c.Data(http.StatusOK, "multipart/mixed; boundary="+writer.Boundary(), body.Bytes())
}

func (s *server) otaAsset(c *gin.Context) {
	id := c.Param("id")
	relPath := strings.TrimPrefix(c.Param("path"), "/")
	if id == "" || relPath == "" || strings.Contains(relPath, "..") {
		problem(c, 404, "OTA_ASSET_NOT_FOUND", "OTA asset not found")
		return
	}
	var key sql.NullString
	var rawObjectMetadata []byte
	// canary 与 paused / superseded 同档：资源请求由原生下载器发出，不带
	// Expo-Extra-Params（只有 manifest 请求带），所以这里没有身份可验。
	// 把关的是 manifest——资源路径只能从已经通过灰度校验的 manifest 里拿到，
	// 而且必须逐条对得上 object_metadata 才下发
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT manifest_key,object_metadata FROM ota_releases WHERE tenant_id=? AND id=? AND status IN ('active','canary','paused','superseded')`, tenantID(c), id).Scan(&key, &rawObjectMetadata); err != nil || !key.Valid {
		problem(c, 404, "OTA_ASSET_NOT_FOUND", "OTA asset not found")
		return
	}
	base := path.Dir(key.String)
	assetKey := path.Join(base, relPath)
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	// 资源对象在入库后被改写的话不下发。expo-updates 会按 manifest 里的 hash 校验资源，
	// 这里是服务端自己的那一道。三种记录状态必须分开：迁移 37 之前的记录没有对象表，只能放行并提醒；
	// 对象表损坏是数据事故（500）；对象表里没有这条路径就是包里没有这个文件（404），不能拿前缀下任意对象顶上
	record, state, recordErr := otaObjectRecord(rawObjectMetadata, relPath)
	switch state {
	case otaObjectLegacy:
		legacyObjectWarning(id, "ota")
	case otaObjectInvalid:
		slog.Error("ota_releases.object_metadata is not valid", "otaReleaseId", id, "tenant", tenantID(c), "error", recordErr)
		problem(c, 500, "OTA_OBJECT_METADATA_INVALID", "Stored OTA object metadata is invalid")
		return
	case otaObjectUnlisted:
		problem(c, 404, "OTA_ASSET_NOT_FOUND", "OTA asset not found")
		return
	case otaObjectRecorded:
		actual, mismatch, statErr := verifyStoredObject(c.Request.Context(), client, assetKey, record.Size, record.ETag)
		if statErr != nil {
			problem(c, http.StatusFailedDependency, "OTA_ASSET_UNAVAILABLE", "Unable to read OTA resource from storage")
			return
		}
		if mismatch != "" {
			s.noteObjectChanged("ota", tenantID(c), id, mismatch+":"+relPath, requestID(c), actual, record.Size, record.ETag, map[string]any{"path": relPath})
			problem(c, http.StatusFailedDependency, "OTA_OBJECT_CHANGED", "OTA resource in storage no longer matches the verified package")
			return
		}
	}
	body, err := client.Get(c.Request.Context(), assetKey)
	if err != nil {
		problem(c, http.StatusFailedDependency, "OTA_ASSET_UNAVAILABLE", "Unable to read OTA resource from storage")
		return
	}
	defer body.Close()
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("Content-Type", contentTypeForPath(relPath))
	io.Copy(c.Writer, body)
}

// otaObjectState 是 ota_releases.object_metadata 对某条资源路径的四种判定。
type otaObjectState int

const (
	// otaObjectLegacy：列为 NULL，迁移 37 之前入库，没有对象记录
	otaObjectLegacy otaObjectState = iota
	// otaObjectRecorded：有这条路径的大小与 ETag
	otaObjectRecorded
	// otaObjectUnlisted：对象表存在但没有这条路径——包里没有这个文件
	otaObjectUnlisted
	// otaObjectInvalid：列有内容但不是合法结构，数据事故
	otaObjectInvalid
)

type otaObjectEntry struct {
	Size int64
	ETag string
}

// otaObjectRecord 读 ota_releases.object_metadata 里某个相对路径的入库大小与 ETag，并说明记录状态。
func otaObjectRecord(raw []byte, relPath string) (otaObjectEntry, otaObjectState, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return otaObjectEntry{}, otaObjectLegacy, nil
	}
	var metadata map[string]map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return otaObjectEntry{}, otaObjectInvalid, fmt.Errorf("object_metadata is not valid JSON: %w", err)
	}
	item, exists := metadata[relPath]
	if !exists {
		return otaObjectEntry{}, otaObjectUnlisted, nil
	}
	size, isNumber := item["size"].(float64)
	if !isNumber || size < 0 {
		return otaObjectEntry{}, otaObjectInvalid, fmt.Errorf("object_metadata[%q].size is not a non-negative number", relPath)
	}
	etag, isString := item["etag"].(string)
	if !isString || strings.TrimSpace(etag) == "" {
		// 入库时空 ETag 已被拒绝（OTA_OBJECT_ETAG_MISSING）：这里出现空值只能是数据被改过，不能退化成只比大小
		return otaObjectEntry{}, otaObjectInvalid, fmt.Errorf("object_metadata[%q].etag is missing or empty", relPath)
	}
	return otaObjectEntry{Size: int64(size), ETag: etag}, otaObjectRecorded, nil
}

func (s *server) otaAction(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
		// set-apply-strategy 专用：目标策略；其它动作忽略
		ApplyStrategy string `json:"applyStrategy"`
		// canary / set-canary-audience 专用：灰度名单（installation_id）
		Installations []string `json:"installations"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return
	}
	id, action := c.Param("id"), c.Param("action")
	if action == "set-apply-strategy" {
		s.setOTAApplyStrategy(c, id, body.ApplyStrategy, body.Reason)
		return
	}
	if action == "republish" {
		problem(c, 422, "OTA_REPUBLISH_UNSUPPORTED", "Republish must create a new immutable update from source artifacts")
		return
	}
	var slotPlatform, slotChannel, slotRuntime string
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT platform,channel,runtime_version FROM ota_releases WHERE tenant_id=? AND id=?`, tenantID(c), id).Scan(&slotPlatform, &slotChannel, &slotRuntime); err != nil {
		problem(c, 404, "OTA_NOT_FOUND", "OTA release not found")
		return
	}
	// 灰度名单在进事务前校验：查安装表要走库，不占着 slot 锁做
	var audience []string
	if action == "canary" || action == "set-canary-audience" {
		var code, detail string
		if audience, code, detail = normalizeCanaryAudience(body.Installations); code != "" {
			problem(c, 422, code, detail)
			return
		}
		if code, detail := s.rejectUnknownCanaryInstallations(c, slotPlatform, audience); code != "" {
			problem(c, 422, code, detail)
			return
		}
	}
	conn, err := s.db.Conn(c.Request.Context())
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	defer conn.Close()
	lockName := otaSequenceLockName(tenantID(c), slotPlatform, slotChannel, slotRuntime)
	var locked int
	if err := conn.QueryRowContext(c.Request.Context(), `SELECT GET_LOCK(?,5)`, lockName).Scan(&locked); err != nil {
		problem(c, 500, "OTA_SEQUENCE_LOCK_FAILED", "Unable to coordinate OTA action")
		return
	}
	if locked != 1 {
		problem(c, 409, "OTA_SEQUENCE_BUSY", "Another OTA action is in progress")
		return
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lockName)
	tx, err := conn.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	defer tx.Rollback()
	var status, platform, channel, runtime string
	if err = tx.QueryRowContext(c.Request.Context(), `SELECT status,platform,channel,runtime_version FROM ota_releases WHERE tenant_id=? AND id=? FOR UPDATE`, tenantID(c), id).Scan(&status, &platform, &channel, &runtime); err != nil {
		problem(c, 404, "OTA_NOT_FOUND", "OTA release not found")
		return
	}
	target := ""
	if action == "publish" && status == "verified" {
		target = "active"
	}
	if action == "pause" && status == "active" {
		target = "paused"
	}
	// 灰度与 active 平行：转灰度不收尾任何 active 修订，收尾语句也只扫 status='active'
	if action == "canary" && status == "verified" {
		target = "canary"
	}
	if action == "promote" && status == "canary" {
		target = "active"
	}
	if action == "cancel-canary" && status == "canary" {
		target = "rejected"
	}
	if action == "set-canary-audience" {
		if status != "canary" {
			problem(c, 409, "INVALID_OTA_TRANSITION", "Invalid OTA state transition")
			return
		}
		s.commitOTACanaryAudience(c, tx, id, status, audience, body.Reason)
		return
	}
	if action == "rollback" {
		// Rollback is represented by a new immutable directive so clients that
		// have already cached a previous update can return to their embedded JS.
		var revision int
		if err := tx.QueryRowContext(c.Request.Context(), `SELECT COALESCE(MAX(revision),0)+1 FROM ota_releases WHERE tenant_id=? AND platform=? AND channel=? AND runtime_version=?`, tenantID(c), platform, channel, runtime).Scan(&revision); err != nil {
			problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to allocate OTA revision")
			return
		}
		now := time.Now().UTC()
		newID := "ota_" + randomID(16)
		updateID := randomUUID()
		if _, err := tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET status='superseded',updated_at=? WHERE tenant_id=? AND platform=? AND channel=? AND runtime_version=? AND status='active'`, now, tenantID(c), platform, channel, runtime); err != nil {
			problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to pause current OTA")
			return
		}
		if _, err := tx.ExecContext(c.Request.Context(), `INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,release_kind,status,manifest_key,manifest_sha256,release_notes,created_by,published_at,created_at,updated_at) SELECT ?,tenant_id,base_release_id,platform,channel,runtime_version,?,?,?,'active',NULL,NULL,'{}',?,?,?,? FROM ota_releases WHERE tenant_id=? AND id=?`, newID, revision, updateID, "rollback", actor(c), now, now, now, tenantID(c), id); err != nil {
			problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to create rollback directive")
			return
		}
		event := newAudit(tenantID(c), actor(c), "ota_rollback", "ota-release", newID, body.Reason, requestID(c), map[string]any{"sourceReleaseId": id, "directive": "rollBackToEmbedded"})
		if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
			problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to save OTA audit")
			return
		}
		c.JSON(http.StatusCreated, gin.H{"id": newID, "status": "active", "releaseKind": "rollback", "directive": "rollBackToEmbedded", "revision": revision, "runtimeVersion": runtime})
		return
	}
	if target == "" {
		problem(c, 409, "INVALID_OTA_TRANSITION", "Invalid OTA state transition")
		return
	}
	now := time.Now().UTC()
	if target == "active" {
		_, _ = tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET status='superseded',updated_at=? WHERE tenant_id=? AND platform=? AND channel=? AND runtime_version=? AND status='active'`, now, tenantID(c), platform, channel, runtime)
	}
	// 名单只在灰度状态下有意义：离开灰度就清空，免得一条 superseded 记录上留着
	// 看起来还在生效的范围
	audienceValue, _ := json.Marshal(audience)
	if target != "canary" {
		audienceValue = nil
	}
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET status=?,canary_installations=?,published_at=CASE WHEN ?='active' THEN ? ELSE published_at END,updated_at=? WHERE tenant_id=? AND id=? AND status=?`, target, audienceValue, target, now, now, tenantID(c), id, status)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "OTA_STATE_CHANGED", "OTA release changed; refresh and retry")
		return
	}
	summary := map[string]any{"status": target}
	if target == "canary" {
		summary["canaryAudience"] = canaryAudienceDigest(audience)
	}
	event := newAudit(tenantID(c), actor(c), "ota_"+action, "ota-release", id, body.Reason, requestID(c), summary)
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to save OTA audit")
		return
	}
	if target == "active" {
		if err := enqueuePushEvent(c.Request.Context(), tx, tenantID(c), "ota_updated", map[string]any{"otaReleaseId": id, "platform": platform, "channel": channel, "runtimeVersion": runtime}); err != nil {
			problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to enqueue OTA notification")
			return
		}
	}
	if tx.Commit() != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to save OTA audit")
		return
	}
	c.JSON(201, gin.H{"id": id, "status": target})
}
