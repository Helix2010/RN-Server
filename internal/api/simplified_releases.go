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
	uploadURL := absoluteURL(c, "/v1/admin/release-artifacts/upload")
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
	size, _, err := client.Head(ctx, artifact.ObjectKey)
	if err != nil || size != artifact.Size {
		problem(c, http.StatusUnprocessableEntity, "RELEASE_FILE_INVALID", "Uploaded file is missing or has an unexpected size")
		return
	}
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
	metadata := map[string]any{"fileName": artifact.FileName, "size": size, "sha256": hex.EncodeToString(hash.Sum(nil))}
	runtimeVersion := ""
	if body.Platform == "android" {
		apk, inspectErr := apkinspect.Inspect(temporaryPath)
		if inspectErr != nil {
			problem(c, http.StatusUnprocessableEntity, "RELEASE_VERIFY_FAILED", "Android package or signature verification failed")
			return
		}
		runtimeVersion = apk.RuntimeVersion
		metadata["packageName"], metadata["versionName"], metadata["versionCode"], metadata["runtimeVersion"] = apk.PackageName, apk.VersionName, apk.VersionCode, runtimeVersion
		metadata["minSdk"], metadata["signerSha256"], metadata["signingScheme"] = apk.MinSDK, apk.SignerSHA256, apk.SigningScheme
		if apk.VersionName != body.Version || apk.VersionCode != int64(body.BuildNumber) {
			problem(c, http.StatusUnprocessableEntity, "RELEASE_IDENTITY_MISMATCH", "APK versionName/versionCode does not match the release version and build number")
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
	notes, _ := json.Marshal(body.ReleaseNotes)
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
	c.JSON(http.StatusCreated, gin.H{"release": gin.H{"id": id, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "runtimeVersion": runtimeVersion, "status": "verified", "releaseNotes": body.ReleaseNotes, "fileName": artifact.FileName, "contentType": artifact.ContentType, "expectedSize": artifact.Size, "fileSize": size, "sha256": metadata["sha256"], "fileMetadata": metadata, "verifiedAt": iso(now), "createdAt": iso(now), "updatedAt": iso(now), "lastAction": nil}})
}

func (s *server) activeSimplifiedRelease(ctx context.Context, tenant, platform string) (simplifiedActiveRelease, error) {
	var item simplifiedActiveRelease
	var notes []byte
	var sha sql.NullString
	var size sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,version,release_notes,sha256,file_size,mandatory FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`, tenant, platform).Scan(&item.ID, &item.Version, &notes, &sha, &size, &item.Mandatory)
	if err != nil {
		return item, err
	}
	if err := json.Unmarshal(notes, &item.ReleaseNotes); err != nil {
		return item, err
	}
	if sha.Valid {
		item.SHA256 = &sha.String
	}
	if size.Valid {
		item.FileSize = &size.Int64
	}
	return item, nil
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
	var id, version, fileName, key, status string
	var rawNotes []byte
	var build int
	var size sql.NullInt64
	var sha sql.NullString
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,version,build_number,file_name,object_key,file_size,sha256,status,release_notes FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`, tenantID(c), platform).Scan(&id, &version, &build, &fileName, &key, &size, &sha, &status, &rawNotes)
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Active release not found")
		return
	}
	download := absoluteURL(c, "/v1/public/releases/"+id+"/download")
	var notes map[string][]string
	_ = json.Unmarshal(rawNotes, &notes)
	c.Header("Cache-Control", "public, max-age=60")
	c.JSON(200, gin.H{"tenantId": tenantID(c), "platform": platform, "version": version, "buildNumber": build, "status": status, "fileName": fileName, "size": nullableInt64(size), "sha256": nullableSQLString(sha), "downloadUrl": download, "releaseId": id, "releaseNotes": notes})
}

func (s *server) publicReleaseDownload(c *gin.Context) {
	var key, fileName string
	var contentType sql.NullString
	var fileSize sql.NullInt64
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT object_key,file_name,content_type,file_size FROM app_releases WHERE tenant_id=? AND id=? AND status='active'`, tenantID(c), c.Param("id")).Scan(&key, &fileName, &contentType, &fileSize)
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Published release not found")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	body, err := client.Get(c.Request.Context(), key)
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
	if fileSize.Valid && fileSize.Int64 >= 0 {
		c.Header("Content-Length", strconv.FormatInt(fileSize.Int64, 10))
	}
	if _, err := io.Copy(c.Writer, body); err != nil {
		slog.Error("release download stream failed", "releaseId", c.Param("id"), "error", err)
	}
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
