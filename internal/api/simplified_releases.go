package api

import (
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
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/gin-gonic/gin"
)

var defaultPlatforms = map[string]bool{"android": true, "ios": true, "harmony": true}

type releaseArtifactToken struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantId"`
	ObjectKey   string `json:"objectKey"`
	FileName    string `json:"fileName"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	ExpiresAt   int64  `json:"expiresAt"`
}

func (s *server) encodeReleaseArtifactToken(value releaseArtifactToken) (string, error) {
	if s.secrets == nil {
		return "", errors.New("storage master key is unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	encrypted, err := s.secrets.Encrypt(string(raw), "release-artifact:"+value.TenantID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

func (s *server) decodeReleaseArtifactToken(tenant, encoded string) (releaseArtifactToken, error) {
	var value releaseArtifactToken
	if s.secrets == nil || strings.TrimSpace(encoded) == "" {
		return value, errors.New("artifact token is unavailable")
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return value, errors.New("artifact token is invalid")
	}
	plaintext, err := s.secrets.Decrypt(encrypted, "release-artifact:"+tenant)
	if err != nil || json.Unmarshal([]byte(plaintext), &value) != nil || value.TenantID != tenant || time.Now().UTC().Unix() > value.ExpiresAt {
		return value, errors.New("artifact token is invalid or expired")
	}
	return value, nil
}

func releaseArtifactTokenFromRequest(c *gin.Context) string {
	if token := strings.TrimSpace(c.GetHeader("x-release-artifact-token")); token != "" {
		return token
	}
	return strings.TrimSpace(c.Query("token"))
}

func (s *server) createReleaseArtifactUpload(c *gin.Context) {
	var body struct {
		FileName    string `json:"fileName"`
		ContentType string `json:"contentType"`
		Size        int64  `json:"size"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_ARTIFACT_UPLOAD", "Invalid artifact upload payload")
		return
	}
	body.FileName = path.Base(strings.TrimSpace(body.FileName))
	body.ContentType = strings.ToLower(strings.TrimSpace(body.ContentType))
	if body.FileName == "" || body.FileName == "." || body.Size < 1 || body.Size > s.cfg.ArtifactMaxSizeBytes {
		problem(c, http.StatusBadRequest, "INVALID_ARTIFACT_UPLOAD", "File name and size are invalid")
		return
	}
	client, objectPrefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	now := time.Now().UTC()
	id := "art_" + randomID(16)
	key := releaseArtifactObjectKey(objectPrefix, tenantID(c), id, body.FileName)
	value := releaseArtifactToken{ID: id, TenantID: tenantID(c), ObjectKey: key, FileName: body.FileName, ContentType: body.ContentType, Size: body.Size, ExpiresAt: now.Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second).Unix()}
	token, err := s.encodeReleaseArtifactToken(value)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "ARTIFACT_TOKEN_UNAVAILABLE", "Artifact upload signing is not configured")
		return
	}
	// 代理走自己那条回传地址：它没有管理端凭据，拿到管理端的 URL 只会 401
	uploadPath := "/v1/admin/release-artifacts/upload"
	if buildAgentUploadsArtifact(c) {
		uploadPath = "/v1/build-agent/jobs/" + c.Param("id") + "/artifact"
	}
	uploadURL := s.absoluteURL(c, uploadPath)
	headers := map[string]string{"content-type": body.ContentType, "x-release-artifact-token": token}
	requiresCredentials := true
	if s.cfg.ArtifactUploadMode == "direct" {
		uploadURL, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		if err != nil {
			problem(c, http.StatusBadGateway, "ARTIFACT_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
			return
		}
		requiresCredentials = false
	}
	c.JSON(http.StatusCreated, gin.H{"artifact": gin.H{"id": id, "token": token, "fileName": body.FileName, "contentType": body.ContentType, "size": body.Size, "objectKey": key, "expiresAt": iso(time.Unix(value.ExpiresAt, 0).UTC())}, "upload": gin.H{"method": "PUT", "url": uploadURL, "headers": headers, "expiresAt": iso(time.Unix(value.ExpiresAt, 0).UTC()), "requiresCredentials": requiresCredentials}})
}

func (s *server) uploadReleaseArtifact(c *gin.Context) {
	if s.cfg.ArtifactUploadMode != "proxy" {
		problem(c, http.StatusNotFound, "RELEASE_UPLOAD_PROXY_DISABLED", "Server-side release upload is disabled")
		return
	}
	value, err := s.decodeReleaseArtifactToken(tenantID(c), releaseArtifactTokenFromRequest(c))
	if err != nil {
		problem(c, http.StatusUnauthorized, "INVALID_ARTIFACT_TOKEN", err.Error())
		return
	}
	if c.Request.ContentLength != value.Size {
		problem(c, http.StatusLengthRequired, "RELEASE_UPLOAD_SIZE_MISMATCH", "Uploaded file size does not match the artifact declaration")
		return
	}
	storedSize, err := s.receiveAndStoreArtifact(c, value.ObjectKey, value.ContentType, value.Size)
	if err != nil {
		slog.Error("release artifact proxy upload failed", "tenant", tenantID(c), "artifactId", value.ID, "objectKey", value.ObjectKey, "expectedSize", value.Size, "error", err)
		problem(c, http.StatusBadGateway, "RELEASE_UPLOAD_FAILED", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"artifact": gin.H{"id": value.ID, "fileSize": storedSize, "objectKey": value.ObjectKey}})
}

func (s *server) receiveAndStoreArtifact(c *gin.Context, objectKey, contentType string, expectedSize int64) (int64, error) {
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		return 0, errors.New("release storage is not configured")
	}
	temporary, err := os.CreateTemp("", "rn-artifact-upload-*")
	if err != nil {
		return 0, fmt.Errorf("prepare temporary upload: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	limited := http.MaxBytesReader(c.Writer, c.Request.Body, expectedSize)
	written, copyErr := io.Copy(temporary, limited)
	if copyErr != nil {
		_ = temporary.Close()
		return 0, fmt.Errorf("receive upload body: %w", copyErr)
	}
	if written != expectedSize {
		_ = temporary.Close()
		return 0, fmt.Errorf("uploaded size mismatch: got %d, expected %d", written, expectedSize)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		_ = temporary.Close()
		return 0, fmt.Errorf("prepare stored upload: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	if err := client.Put(ctx, objectKey, temporary, expectedSize, contentType); err != nil {
		_ = temporary.Close()
		return 0, fmt.Errorf("write object storage: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return 0, fmt.Errorf("close temporary upload: %w", err)
	}
	storedSize, _, err := client.Head(ctx, objectKey)
	if err != nil {
		return 0, fmt.Errorf("verify stored upload: %w", err)
	}
	if storedSize != expectedSize {
		return 0, fmt.Errorf("stored size mismatch: got %d, expected %d", storedSize, expectedSize)
	}
	return storedSize, nil
}

func (s *server) deleteReleaseArtifact(c *gin.Context) {
	value, err := s.decodeReleaseArtifactToken(tenantID(c), releaseArtifactTokenFromRequest(c))
	if err != nil {
		problem(c, http.StatusUnauthorized, "INVALID_ARTIFACT_TOKEN", err.Error())
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err == nil {
		_ = client.Delete(c.Request.Context(), value.ObjectKey)
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func (s *server) createReleaseFromArtifact(c *gin.Context) {
	var body struct {
		ArtifactToken string         `json:"artifactToken"`
		Platform      string         `json:"platform"`
		Version       string         `json:"version"`
		BuildNumber   int            `json:"buildNumber"`
		ReleaseNotes  map[string]any `json:"releaseNotes"`
		// 强制升级：用户在 App 里没有"稍后再说"，只能升。
		// 按 docs/RELIABILITY_AND_RELEASE.md 只用于严重安全漏洞、协议不兼容、
		// 法律合规阻断；为什么强制走审计 reason 留痕。
		Mandatory bool `json:"mandatory"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE", "Invalid release payload")
		return
	}
	body.Platform = strings.ToLower(strings.TrimSpace(body.Platform))
	body.Version = strings.TrimSpace(body.Version)
	if !validVersion(body.Version) || body.BuildNumber < 1 {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE", "Platform, version and build number are invalid")
		return
	}
	releaseNotes, notesCode, notesDetail := normalizeReleaseNotes(body.ReleaseNotes)
	if notesCode != "" {
		problem(c, http.StatusUnprocessableEntity, notesCode, notesDetail)
		return
	}
	if enabled, err := s.platformEnabled(c.Request.Context(), tenantID(c), body.Platform); err != nil || !enabled {
		problem(c, http.StatusUnprocessableEntity, "PLATFORM_DISABLED", "The requested platform is not enabled for this tenant")
		return
	}
	artifact, err := s.decodeReleaseArtifactToken(tenantID(c), body.ArtifactToken)
	if err != nil {
		problem(c, http.StatusUnauthorized, "INVALID_ARTIFACT_TOKEN", err.Error())
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	stored, err := client.Stat(ctx, artifact.ObjectKey)
	if err != nil || stored.Size != artifact.Size {
		problem(c, http.StatusUnprocessableEntity, "RELEASE_FILE_INVALID", "Uploaded file is missing or has an unexpected size")
		return
	}
	if strings.TrimSpace(stored.ETag) == "" {
		// 没有 ETag 就没有"对象被替换"的可检测性：不能带着空值入库，否则下载时只剩大小比对
		problem(c, http.StatusBadGateway, "RELEASE_OBJECT_ETAG_MISSING", "Object storage returned no ETag for the uploaded artifact; the release cannot be pinned")
		return
	}
	size := stored.Size
	temporary, err := os.CreateTemp("", "rn-release-*")
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_VERIFY_FAILED", "Unable to prepare release verification")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	objectBody, err := client.Get(ctx, artifact.ObjectKey)
	if err != nil {
		_ = temporary.Close()
		problem(c, http.StatusBadGateway, "RELEASE_READ_FAILED", "Unable to read uploaded release")
		return
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(objectBody, s.cfg.ArtifactMaxSizeBytes+1))
	_ = objectBody.Close()
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written != size {
		problem(c, http.StatusBadGateway, "RELEASE_READ_FAILED", "Unable to read the complete release")
		return
	}
	// objectEtag 是校验时对象存储给的 ETag（objectstore.Stat，已去引号）；公开下载前再 Stat 一次比对，
	// 发布后对象被换掉即拒绝下发。CopyObject / 存储类变更会改 ETag，此时必须重新入库
	metadata := map[string]any{"fileName": artifact.FileName, "size": size, "sha256": hex.EncodeToString(hash.Sum(nil)), "objectEtag": stored.ETag}
	runtimeVersion := ""
	if body.Platform == "android" {
		apk, inspectErr := apkinspect.Inspect(temporaryPath)
		// 解析阶段的拒绝还拿不到包名/签名者，审计只记代码与错误摘要；文档承诺每次入库拒绝都留痕
		rejectBeforeInspect := func(code, detail string) {
			s.auditNow(newAudit(tenantID(c), actor(c), "release_rejected", "release-artifact", artifact.ID, detail, requestID(c), map[string]any{"code": code, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "error": inspectErr.Error()}))
			problem(c, http.StatusUnprocessableEntity, code, detail)
		}
		if errors.Is(inspectErr, apkinspect.ErrEmbeddedConfigInvalid) {
			// 有内嵌配置但不是合法 JSON：这是构建产物损坏，不能当成"没有 applicationId"报缺失
			rejectBeforeInspect("RELEASE_EMBEDDED_CONFIG_INVALID", "APK embedded Expo config is not valid JSON")
			return
		}
		if inspectErr != nil {
			rejectBeforeInspect("RELEASE_VERIFY_FAILED", "Android package or signature verification failed")
			return
		}
		// 先看身份再看版本：公开 debug 密钥、未 pin、包名或签名者不符的包不该走到版本比对
		pin, pinErr := s.androidReleaseIdentityRecord(ctx, tenantID(c))
		if pinErr != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
			return
		}
		var pinned *androidReleaseIdentity
		if pin != nil {
			pinned = &pin.Value
		}
		if code, detail := checkAndroidReleaseIdentity(apk, pinned, s.cfg.Environment == "production"); code != "" {
			s.auditNow(newAudit(tenantID(c), actor(c), "release_rejected", "release-artifact", artifact.ID, detail, requestID(c), map[string]any{"code": code, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "packageName": apk.PackageName, "signerSha256": normalizeFingerprint(apk.SignerSHA256)}))
			problem(c, http.StatusUnprocessableEntity, code, detail)
			return
		}
		rejectRelease := func(code, detail string) {
			s.auditNow(newAudit(tenantID(c), actor(c), "release_rejected", "release-artifact", artifact.ID, detail, requestID(c), map[string]any{"code": code, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "packageName": apk.PackageName, "signerSha256": normalizeFingerprint(apk.SignerSHA256)}))
			problem(c, http.StatusUnprocessableEntity, code, detail)
		}
		if apk.ApplicationID == "" {
			rejectRelease("RELEASE_APPLICATION_ID_MISSING", "APK does not embed extra.applicationId; OTA identity cannot be bound to it")
			return
		}
		runtimeVersion = apk.RuntimeVersion
		metadata["packageName"], metadata["versionName"], metadata["versionCode"], metadata["runtimeVersion"] = apk.PackageName, apk.VersionName, apk.VersionCode, runtimeVersion
		metadata["minSdk"], metadata["signerSha256"], metadata["signingScheme"] = apk.MinSDK, normalizeFingerprint(apk.SignerSHA256), apk.SigningScheme
		metadata["applicationId"] = apk.ApplicationID
		if apk.VersionName != body.Version || apk.VersionCode != int64(body.BuildNumber) {
			rejectRelease("RELEASE_IDENTITY_MISMATCH", "APK versionName/versionCode does not match the release version and build number")
			return
		}
	}
	conn, err := s.db.Conn(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to create release")
		return
	}
	defer conn.Close()
	lockName := "rn_release_" + tenantID(c) + "_" + body.Platform
	var locked int
	if err = conn.QueryRowContext(c.Request.Context(), `SELECT GET_LOCK(?,5)`, lockName).Scan(&locked); err != nil || locked != 1 {
		problem(c, http.StatusConflict, "RELEASE_SEQUENCE_BUSY", "Another release is being created for this platform")
		return
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lockName)
	tx, err := conn.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to create release")
		return
	}
	defer tx.Rollback()
	var latestBuild int
	var latestVersion sql.NullString
	err = tx.QueryRowContext(c.Request.Context(), `SELECT version,build_number FROM app_releases WHERE tenant_id=? AND platform=? ORDER BY build_number DESC LIMIT 1`, tenantID(c), body.Platform).Scan(&latestVersion, &latestBuild)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to read release sequence")
		return
	}
	if body.BuildNumber <= latestBuild || (latestVersion.Valid && compareVersion(body.Version, latestVersion.String) <= 0) {
		problem(c, http.StatusConflict, "RELEASE_VERSION_NOT_INCREASING", "Version and build number must both be greater than the latest release for this platform")
		return
	}
	now := time.Now().UTC()
	id := "rel_" + randomID(16)
	// map[string][]string 一定能序列化，没有需要处理的错误分支
	notes, _ := json.Marshal(releaseNotes)
	rawMetadata, _ := json.Marshal(metadata)
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,file_metadata,mandatory,verified_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, tenantID(c), body.Platform, body.Version, body.BuildNumber, runtimeVersion, "verified", notes, artifact.ObjectKey, artifact.FileName, artifact.ContentType, artifact.Size, size, metadata["sha256"], rawMetadata, body.Mandatory, now, actor(c), now, now)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to save release")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_create", "release", id, "Uploaded artifact verified and saved", requestID(c), map[string]any{"platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "mandatory": body.Mandatory})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to save release audit")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"release": gin.H{"id": id, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "runtimeVersion": runtimeVersion, "status": "verified", "releaseNotes": releaseNotes, "fileName": artifact.FileName, "contentType": artifact.ContentType, "expectedSize": artifact.Size, "fileSize": size, "sha256": metadata["sha256"], "fileMetadata": metadata, "mandatory": body.Mandatory, "verifiedAt": iso(now), "createdAt": iso(now), "updatedAt": iso(now), "lastAction": nil}})
}

// visibleSimplifiedRelease 取这台设备现在该拿的那一个全量版本：active，或者
// 它在名单里的灰度版本（build 更大者胜）。installationID 为空 = 认不出身份，
// 只剩 active（见 canary.go 的 canaryVisibleSQL）。
func (s *server) visibleSimplifiedRelease(ctx context.Context, tenant, platform, installationID string) (simplifiedActiveRelease, error) {
	var item simplifiedActiveRelease
	var notes, rawMetadata []byte
	var sha sql.NullString
	var size sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,version,release_notes,sha256,file_size,mandatory,status,file_metadata FROM app_releases WHERE tenant_id=? AND platform=? AND `+canaryVisibleSQL+` ORDER BY build_number DESC LIMIT 1`, tenant, platform, installationID, installationID).Scan(&item.ID, &item.Version, &notes, &sha, &size, &item.Mandatory, &item.Status, &rawMetadata)
	if err != nil {
		return item, err
	}
	if err := json.Unmarshal(notes, &item.ReleaseNotes); err != nil {
		return item, err
	}
	// 签名者读不出来（旧记录没这个键、或元数据坏了）就当"不知道"：这个字段只用于
	// 决定要不要关掉应用内直装，拿不到时保持现状，不把正常升级也挡掉
	item.SignerSHA256, _ = storedMetadataString(rawMetadata, "signerSha256")
	if sha.Valid {
		item.SHA256 = &sha.String
	}
	if size.Valid {
		item.FileSize = &size.Int64
	}
	return item, nil
}

// installedReleaseSigner 反查"设备现在装的那个 build"入库时记下的签名证书指纹。
// 查不到（从没上传过这个 build、或旧记录没记指纹）返回空串，调用方按"不知道"处理。
func (s *server) installedReleaseSigner(ctx context.Context, tenant, platform, version, buildNumber string) string {
	if version == "" || buildNumber == "" {
		return ""
	}
	var rawMetadata []byte
	if err := s.db.QueryRowContext(ctx, `SELECT file_metadata FROM app_releases WHERE tenant_id=? AND platform=? AND version=? AND build_number=? ORDER BY created_at DESC LIMIT 1`, tenant, platform, version, buildNumber).Scan(&rawMetadata); err != nil {
		return ""
	}
	signer, _ := storedMetadataString(rawMetadata, "signerSha256")
	return signer
}

// directInstallAllowed 决定这台设备该不该看到"应用内直接安装"。
//
// Android 不允许签名不同的 APK 覆盖安装。轮换签名密钥之后，老密钥签的装机下载
// 新包能成功、装到系统安装器那一步必定被拒——用户看到的是一个点一次失败一次、
// 没有任何解释的按钮，强制升级时更是死循环（安全评审 N1 的迁移窗口）。
//
// 两边指纹都知道且不相等时关掉直装：客户端会退回"去下载页"，运营也就有地方
// 把"先备份助记词、卸载旧版、重新安装"讲清楚。任何一边不知道都保持现状——
// 宁可多给一个可能失败的按钮，也不要把正常升级的设备一起挡住。
func directInstallAllowed(featureEnabled bool, platform, installedSigner, targetSigner string) bool {
	if !featureEnabled || platform != "android" {
		return false
	}
	if installedSigner == "" || targetSigner == "" {
		return true
	}
	return strings.EqualFold(installedSigner, targetSigner)
}

// activeMandatoryVersion 返回 active 记录声明的"必须升到这一版"，没有强制要求时空串。
// 强制升级只由 active 决定：灰度版本不得设 mandatory（设计 §3.5），而且一台设备
// 拿到灰度版本不能把 active 上的强制要求弄丢——否则给某台机器发个灰度包就等于
// 单独给它解除了强制升级。
func (s *server) activeMandatoryVersion(ctx context.Context, tenant, platform string) string {
	var version string
	var mandatory bool
	if err := s.db.QueryRowContext(ctx, `SELECT version,mandatory FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`, tenant, platform).Scan(&version, &mandatory); err != nil || !mandatory {
		return ""
	}
	return version
}

func (s *server) platformEnabled(ctx context.Context, tenant, platform string) (bool, error) {
	if platform == "" || len(platform) > 32 {
		return false, nil
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT config_value FROM app_configs WHERE config_key='release.platforms' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`, tenant, tenant).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultPlatforms[platform], nil
	}
	if err != nil {
		return false, err
	}
	var value map[string]map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return false, errors.New("invalid release.platforms config")
	}
	if item, ok := value[platform]; ok {
		if enabled, exists := item["enabled"].(bool); exists && !enabled {
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

func releaseArtifactObjectKey(prefix, tenant, artifactID, fileName string) string {
	return strings.TrimLeft(path.Join(prefix, "tenants", tenant, "release-uploads", artifactID, "application"+path.Ext(fileName)), "/")
}

func (s *server) publicLatestReleaseFromDomain(c *gin.Context) {
	platform := strings.ToLower(strings.TrimSpace(c.Query("platform")))
	if platform == "" {
		platform = strings.ToLower(strings.TrimSpace(c.GetHeader("x-platform")))
	}
	if enabled, err := s.platformEnabled(c.Request.Context(), tenantID(c), platform); err != nil || !enabled {
		problem(c, 400, "INVALID_PLATFORM", "A supported platform is required")
		return
	}
	var id, version, fileName, key, status, runtime string
	var rawNotes []byte
	var build int
	var size sql.NullInt64
	var sha sql.NullString
	// 匿名请求只看得到 active；带上有效安装凭证的设备还能看到发给它的灰度版本
	audience := s.canaryAudienceID(c, tenantID(c))
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,version,build_number,runtime_version,file_name,object_key,file_size,sha256,status,release_notes FROM app_releases WHERE tenant_id=? AND platform=? AND `+canaryVisibleSQL+` ORDER BY build_number DESC LIMIT 1`, tenantID(c), platform, audience, audience).Scan(&id, &version, &build, &runtime, &fileName, &key, &size, &sha, &status, &rawNotes)
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Active release not found")
		return
	}
	download := s.absoluteURL(c, "/v1/public/releases/"+id+"/download")
	var notes map[string][]string
	_ = json.Unmarshal(rawNotes, &notes)
	c.Header("Cache-Control", "public, max-age=60")
	// runtimeVersion 是给 OTA 构建用的：热更新包必须对准"正在分发的那一版"的 runtime，
	// 否则没有任何设备会收到它。这个值本来就不是秘密——/v1/ota/manifest 对任何客户端
	// 都会返回它——只是这个接口一直漏了，于是构建脚本只能去读仓库里那份会过期的
	// tenant.json（见 RN-App scripts/build-ota.mjs）
	c.JSON(200, gin.H{"tenantId": tenantID(c), "platform": platform, "version": version, "buildNumber": build, "runtimeVersion": runtime, "status": status, "fileName": fileName, "size": nullableInt64(size), "sha256": nullableSQLString(sha), "downloadUrl": download, "releaseId": id, "releaseNotes": notes})
}

// publicLatestReleaseDownload 是"永远给最新包"的固定下载地址。
//
// 为什么要单独一条：真正的下载地址里带着发布 ID，每发一版就变一次，贴在官网、
// 二维码或群里的链接每次发版都得换。这条地址不变，内部按与 /latest 完全一致的
// 可见性挑出这台设备现在该拿的那一版（含灰度：名单内设备拿到的是灰度包），
// 再 302 到带发布 ID 的真实地址——下载本身仍走原来那条路径，Range、ETag、
// 对象一致性校验一个都不少。
//
// 不缓存这个跳转：它的意义就是"随时点都是最新的"，被缓存住就失去了意义。
func (s *server) publicLatestReleaseDownload(c *gin.Context) {
	platform := strings.ToLower(strings.TrimSpace(c.Query("platform")))
	if platform == "" {
		platform = strings.ToLower(strings.TrimSpace(c.GetHeader("x-platform")))
	}
	if platform == "" {
		// 浏览器扫码打开时不会带这些，默认给 Android：iOS 目前没有直装分发链路
		platform = "android"
	}
	if enabled, err := s.platformEnabled(c.Request.Context(), tenantID(c), platform); err != nil || !enabled {
		problem(c, 400, "INVALID_PLATFORM", "A supported platform is required")
		return
	}
	audience := s.canaryAudienceID(c, tenantID(c))
	var id string
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id FROM app_releases WHERE tenant_id=? AND platform=? AND `+canaryVisibleSQL+` ORDER BY build_number DESC LIMIT 1`, tenantID(c), platform, audience, audience).Scan(&id)
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Active release not found")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, s.absoluteURL(c, "/v1/public/releases/"+id+"/download"))
}

// byteRange 是解析后的单区间 Range（闭区间）。
type byteRange struct{ start, end int64 }

// parseByteRange 解析 `Range: bytes=start-end` / `bytes=start-` / `bytes=-suffix`（只认单区间）。
// 返回 (r, ok, satisfiable)：没有 Range 头或格式不认识 → ok=false（按全量处理）；
// 区间落在文件之外 → satisfiable=false（416）。
func parseByteRange(header string, size int64) (byteRange, bool, bool) {
	header = strings.TrimSpace(header)
	if header == "" || size <= 0 || !strings.HasPrefix(header, "bytes=") {
		return byteRange{}, false, false
	}
	spec := strings.TrimPrefix(header, "bytes=")
	if strings.Contains(spec, ",") {
		return byteRange{}, false, false
	}
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return byteRange{}, false, false
	}
	startText, endText := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if startText == "" {
		// bytes=-N：最后 N 字节
		suffix, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffix <= 0 {
			return byteRange{}, false, false
		}
		if suffix > size {
			suffix = size
		}
		return byteRange{start: size - suffix, end: size - 1}, true, true
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return byteRange{}, false, false
	}
	end := size - 1
	if endText != "" {
		end, err = strconv.ParseInt(endText, 10, 64)
		if err != nil || end < start {
			return byteRange{}, false, false
		}
		if end > size-1 {
			end = size - 1
		}
	}
	if start >= size {
		return byteRange{}, true, false
	}
	return byteRange{start: start, end: end}, true, true
}

// publicReleaseDownload 下发已发布的安装包；支持单区间 Range（安装包断点续传）：
// 总是带 Accept-Ranges / ETag；Range 合法给 206 + Content-Range，越界给 416，
// If-Range 与 ETag 不一致时忽略 Range 回全量（文件换了就不能接着旧的下）。
func (s *server) publicReleaseDownload(c *gin.Context) {
	var key, fileName string
	var contentType, sha sql.NullString
	var fileSize sql.NullInt64
	var rawMetadata []byte
	// 灰度设备要能真的下载到它在 bootstrap 里看到的那一个；名单外的人拿到 ID 直接下也是 404
	audience := s.canaryAudienceID(c, tenantID(c))
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT object_key,file_name,content_type,file_size,sha256,file_metadata FROM app_releases WHERE tenant_id=? AND id=? AND `+canaryVisibleSQL, tenantID(c), c.Param("id"), audience, audience).Scan(&key, &fileName, &contentType, &fileSize, &sha, &rawMetadata)
	if err != nil {
		s.noteCanaryDownloadRefused(c, c.Param("id"), audience)
		problem(c, 404, "RELEASE_NOT_FOUND", "Published release not found")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	etag := ""
	if sha.Valid && sha.String != "" {
		etag = `"` + sha.String + `"`
	}
	size := int64(-1)
	if fileSize.Valid && fileSize.Int64 >= 0 {
		size = fileSize.Int64
	}
	// 下发前核对对象存储里的东西还是入库时校验过的那一个：大小与 ETag 都要一致。
	// 校验只在上传时做过一次，之后对象存储被改写（凭证泄漏、误操作）不会有任何人发现，
	// 而 debug 签名 + 客户端不校 sha256 的现状会让替换后的包被系统安装器当成合法升级
	// 键不存在 = 改动前入库的旧记录（只比大小并提醒一次）；键存在但空 / 非字串 = 数据事故（500），不降级
	storedEtag, hasEtag, metadataErr := storedMetadataField(rawMetadata, "objectEtag")
	if metadataErr != nil {
		slog.Error("release file_metadata is invalid", "releaseId", c.Param("id"), "tenant", tenantID(c), "error", metadataErr)
		problem(c, 500, "RELEASE_METADATA_INVALID", "Stored release metadata is invalid")
		return
	}
	if !hasEtag {
		legacyObjectWarning(c.Param("id"), "release")
	}
	actual, mismatch, statErr := verifyStoredObject(c.Request.Context(), client, key, size, storedEtag)
	if statErr != nil {
		problem(c, 502, "RELEASE_DOWNLOAD_FAILED", "Unable to read release package")
		return
	}
	if mismatch != "" {
		s.noteObjectChanged("release", tenantID(c), c.Param("id"), mismatch, requestID(c), actual, size, storedEtag, nil)
		problem(c, 502, "RELEASE_OBJECT_CHANGED", "Release package in storage no longer matches the verified artifact")
		return
	}
	rng, hasRange, satisfiable := parseByteRange(c.GetHeader("Range"), size)
	if ifRange := strings.TrimSpace(c.GetHeader("If-Range")); hasRange && ifRange != "" && ifRange != etag {
		hasRange = false
	}
	if hasRange && !satisfiable {
		c.Header("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
		c.Header("Accept-Ranges", "bytes")
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		c.Writer.WriteHeaderNow()
		return
	}
	var body io.ReadCloser
	if hasRange {
		body, err = client.GetRange(c.Request.Context(), key, rng.start, rng.end)
	} else {
		body, err = client.Get(c.Request.Context(), key)
	}
	if err != nil {
		problem(c, 502, "RELEASE_DOWNLOAD_FAILED", "Unable to read release package")
		return
	}
	defer body.Close()
	if contentType.Valid && isSafeHeaderValue(contentType.String) {
		c.Header("Content-Type", contentType.String)
	} else {
		c.Header("Content-Type", "application/octet-stream")
	}
	c.Header("Content-Disposition", `attachment; filename="`+safeDownloadName(fileName)+`"`)
	c.Header("Accept-Ranges", "bytes")
	if etag != "" {
		c.Header("ETag", etag)
	}
	if hasRange {
		c.Header("Content-Range", "bytes "+strconv.FormatInt(rng.start, 10)+"-"+strconv.FormatInt(rng.end, 10)+"/"+strconv.FormatInt(size, 10))
		c.Header("Content-Length", strconv.FormatInt(rng.end-rng.start+1, 10))
		c.Status(http.StatusPartialContent)
	} else if size >= 0 {
		c.Header("Content-Length", strconv.FormatInt(size, 10))
	}
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Error("release download stream failed", "releaseId", c.Param("id"), "error", err)
	}
}

// noteCanaryDownloadRefused 把"灰度包被拒下载"从一个静默 404 变成能查的事件。
//
// 客户端这边只会看到"下载失败"，而失败的原因可能是：没带凭证、带了但四元组
// 里少了平台 / 应用身份（不走 apiClient 的传输很容易漏）、凭证过期被吊销、
// 或者这台机器真的不在名单里。2026-09-11 联调时就是因为分不清这几种，
// 白查了很久。只在请求方自报了安装 ID 时多查一次状态，正常 404 不受影响。
func (s *server) noteCanaryDownloadRefused(c *gin.Context, releaseID, audience string) {
	claimed := strings.TrimSpace(c.GetHeader("x-installation-id"))
	if claimed == "" {
		return
	}
	var status string
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT status FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), releaseID).Scan(&status); err != nil || status != "canary" {
		return
	}
	reason := "installation is not in the canary audience"
	if audience == "" {
		_, code := s.verifyInstallationCredentialFor(c, tenantID(c), claimed)
		reason = "installation identity was not accepted: " + code
	}
	slog.Warn("canary release download refused",
		"tenant", tenantID(c), "releaseId", releaseID, "installationId", claimed,
		"applicationId", c.GetHeader("x-application-id"), "platform", c.GetHeader("x-platform"),
		"reason", reason, "requestId", requestID(c))
}

func safeDownloadName(name string) string {
	name = path.Base(strings.TrimSpace(name))
	name = strings.NewReplacer(`"`, "", "\r", "", "\n", "").Replace(name)
	if name == "" || name == "." || name == ".." {
		return "application.apk"
	}
	return name
}

func isSafeHeaderValue(value string) bool {
	return !strings.ContainsAny(value, "\r\n")
}
