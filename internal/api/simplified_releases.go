package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/gin-gonic/gin"
)

var defaultPlatforms = map[string]bool{"android": true, "ios": true, "harmony": true}

type simplifiedUploadRequest struct {
	Platform       string         `json:"platform"`
	Version        string         `json:"version"`
	BuildNumber    int            `json:"buildNumber"`
	RuntimeVersion string         `json:"runtimeVersion"`
	ReleaseNotes   map[string]any `json:"releaseNotes"`
	FileName       string         `json:"fileName"`
	ContentType    string         `json:"contentType"`
	Size           int64          `json:"size"`
}

func (s *server) activeSimplifiedRelease(ctx context.Context, tenant, platform string) (simplifiedActiveRelease, error) {
	var item simplifiedActiveRelease
	var notes []byte
	var sha sql.NullString
	var size sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,version,release_notes,sha256,file_size FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`, tenant, platform).Scan(&item.ID, &item.Version, &notes, &sha, &size)
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

func (s *server) createReleaseUpload(c *gin.Context) {
	var body simplifiedUploadRequest
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_RELEASE_UPLOAD", "Invalid release upload payload")
		return
	}
	body.Platform = strings.ToLower(strings.TrimSpace(body.Platform))
	body.Version, body.RuntimeVersion = strings.TrimSpace(body.Version), strings.TrimSpace(body.RuntimeVersion)
	body.FileName, body.ContentType = path.Base(strings.TrimSpace(body.FileName)), strings.ToLower(strings.TrimSpace(body.ContentType))
	if !validVersion(body.Version) || body.BuildNumber < 1 || body.RuntimeVersion == "" || body.FileName == "." || body.FileName == "" || body.Size < 1 || body.Size > s.cfg.ArtifactMaxSizeBytes {
		problem(c, 400, "INVALID_RELEASE_UPLOAD", "Platform, version, build number, file name and size are invalid")
		return
	}
	if enabled, err := s.platformEnabled(c.Request.Context(), tenantID(c), body.Platform); err != nil || !enabled {
		problem(c, 422, "PLATFORM_DISABLED", "The requested platform is not enabled for this tenant")
		return
	}
	now := time.Now().UTC()
	conn, err := s.db.Conn(c.Request.Context())
	if err != nil {
		problem(c, 500, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to create release")
		return
	}
	defer conn.Close()
	lockName := "rn_release_" + tenantID(c) + "_" + body.Platform
	var locked int
	if err = conn.QueryRowContext(c.Request.Context(), `SELECT GET_LOCK(?,5)`, lockName).Scan(&locked); err != nil || locked != 1 {
		problem(c, 409, "RELEASE_SEQUENCE_BUSY", "Another release is being created for this platform")
		return
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lockName)
	tx, err := conn.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to create release")
		return
	}
	defer tx.Rollback()
	var latestBuild int
	var latestVersion sql.NullString
	err = tx.QueryRowContext(c.Request.Context(), `SELECT version,build_number FROM app_releases WHERE tenant_id=? AND platform=? ORDER BY build_number DESC LIMIT 1`, tenantID(c), body.Platform).Scan(&latestVersion, &latestBuild)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	if err != nil {
		problem(c, 500, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to read release sequence")
		return
	}
	if body.BuildNumber <= latestBuild || (latestVersion.Valid && compareVersion(body.Version, latestVersion.String) <= 0) {
		problem(c, 409, "RELEASE_VERSION_NOT_INCREASING", "Version and build number must both be greater than the latest release for this platform")
		return
	}
	id := "rel_" + randomID(16)
	client, objectPrefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	key := simplifiedObjectKey(objectPrefix, tenantID(c), id, body.FileName)
	uploadURL := absoluteURL(c, "/v1/admin/releases/"+id+"/upload")
	headers := map[string]string{"content-type": body.ContentType}
	requiresCredentials := true
	if s.cfg.ArtifactUploadMode == "direct" {
		uploadURL, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		if err != nil {
			problem(c, 502, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
			return
		}
		requiresCredentials = false
	}
	notes, _ := json.Marshal(body.ReleaseNotes)
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, tenantID(c), body.Platform, body.Version, body.BuildNumber, body.RuntimeVersion, "uploaded", notes, key, body.FileName, body.ContentType, body.Size, actor(c), now, now)
	if err != nil {
		problem(c, 500, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to save release")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_upload_create", "release", id, "Created release upload", requestID(c), map[string]any{"platform": body.Platform, "buildNumber": body.BuildNumber})
	if err = insertAudit(c.Request.Context(), tx, event); err != nil || tx.Commit() != nil {
		problem(c, 500, "RELEASE_UPLOAD_CREATE_FAILED", "Unable to save release audit")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"release": gin.H{"id": id, "tenantId": tenantID(c), "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "status": "uploaded", "releaseNotes": body.ReleaseNotes, "objectKey": key}, "upload": gin.H{"method": "PUT", "url": uploadURL, "headers": headers, "expiresAt": iso(now.Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second)), "requiresCredentials": requiresCredentials}})
}

type countedReader struct {
	reader io.Reader
	count  int64
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += int64(n)
	return n, err
}

func (s *server) uploadRelease(c *gin.Context) {
	if s.cfg.ArtifactUploadMode != "proxy" {
		problem(c, http.StatusNotFound, "RELEASE_UPLOAD_PROXY_DISABLED", "Server-side release upload is disabled")
		return
	}
	tenant := tenantID(c)
	id := c.Param("id")
	var key, contentType string
	var expected int64
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT object_key,content_type,expected_size FROM app_releases WHERE tenant_id=? AND id=? AND status='uploaded'`, tenant, id).Scan(&key, &contentType, &expected)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "RELEASE_NOT_FOUND", "Release upload not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_QUERY_FAILED", "Unable to load release upload")
		return
	}
	if c.Request.ContentLength != expected {
		problem(c, http.StatusLengthRequired, "RELEASE_UPLOAD_SIZE_MISMATCH", "Uploaded file size does not match the release declaration")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenant)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	limited := http.MaxBytesReader(c.Writer, c.Request.Body, expected)
	body := &countedReader{reader: io.LimitReader(limited, expected)}
	temporary, err := os.CreateTemp("", "rn-upload-*")
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_UPLOAD_FAILED", "Unable to prepare the release package")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := io.Copy(temporary, body); err != nil {
		_ = temporary.Close()
		problem(c, http.StatusBadRequest, "RELEASE_UPLOAD_FAILED", "Unable to read the release package")
		return
	}
	if body.count != expected {
		_ = temporary.Close()
		problem(c, http.StatusUnprocessableEntity, "RELEASE_UPLOAD_SIZE_MISMATCH", "Uploaded file size does not match the release declaration")
		return
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		_ = temporary.Close()
		problem(c, http.StatusInternalServerError, "RELEASE_UPLOAD_FAILED", "Unable to prepare the release package")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	if err := client.Put(ctx, key, temporary, expected, contentType); err != nil {
		slog.Error("release package upload failed", "tenant", tenant, "releaseId", id, "objectKey", key, "expectedSize", expected, "error", err)
		_ = temporary.Close()
		problem(c, http.StatusBadGateway, "RELEASE_UPLOAD_FAILED", "Unable to store the release package")
		return
	}
	if err := temporary.Close(); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_UPLOAD_FAILED", "Unable to finalize the release package")
		return
	}
	storedSize, _, err := client.Head(ctx, key)
	if err != nil || storedSize != expected {
		slog.Error("stored release package verification failed", "tenant", tenant, "releaseId", id, "objectKey", key, "expectedSize", expected, "storedSize", storedSize, "error", err)
		problem(c, http.StatusBadGateway, "RELEASE_UPLOAD_FAILED", "Stored release package size could not be verified")
		return
	}
	c.JSON(http.StatusOK, gin.H{"release": gin.H{"id": id, "status": "uploaded", "fileSize": storedSize}})
}

func (s *server) finalizeReleaseUpload(c *gin.Context) {
	tenant := tenantID(c)
	id := c.Param("id")
	var key, fileName string
	var expected int64
	var platform, expectedVersion string
	var expectedBuild int64
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT object_key,file_name,expected_size,platform,version,build_number FROM app_releases WHERE tenant_id=? AND id=? AND status='uploaded'`, tenant, id).Scan(&key, &fileName, &expected, &platform, &expectedVersion, &expectedBuild)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "RELEASE_NOT_FOUND", "Release upload not found")
		return
	}
	if err != nil {
		problem(c, 500, "RELEASE_QUERY_FAILED", "Unable to load release upload")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenant)
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	size, _, err := client.Head(ctx, key)
	if err != nil || size != expected {
		problem(c, 422, "RELEASE_FILE_INVALID", "Uploaded file is missing or has an unexpected size")
		return
	}
	temporary, err := os.CreateTemp("", "rn-release-*")
	if err != nil {
		problem(c, 500, "RELEASE_VERIFY_FAILED", "Unable to prepare release verification")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	body, err := client.Get(ctx, key)
	if err != nil {
		_ = temporary.Close()
		problem(c, 502, "RELEASE_READ_FAILED", "Unable to read uploaded release")
		return
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(body, s.cfg.ArtifactMaxSizeBytes+1))
	_ = body.Close()
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written != size {
		problem(c, 502, "RELEASE_READ_FAILED", "Unable to read the complete release")
		return
	}
	metadata := map[string]any{"fileName": fileName, "size": size, "sha256": hex.EncodeToString(hash.Sum(nil))}
	if platform == "android" {
		apk, inspectErr := apkinspect.Inspect(temporaryPath)
		if inspectErr != nil {
			problem(c, 422, "RELEASE_VERIFY_FAILED", "Android package or signature verification failed")
			return
		}
		metadata["packageName"], metadata["versionName"], metadata["versionCode"] = apk.PackageName, apk.VersionName, apk.VersionCode
		metadata["minSdk"], metadata["signerSha256"], metadata["signingScheme"] = apk.MinSDK, apk.SignerSHA256, apk.SigningScheme
		if apk.VersionName != expectedVersion || apk.VersionCode != expectedBuild {
			problem(c, 422, "RELEASE_IDENTITY_MISMATCH", "APK versionName/versionCode does not match the release version and build number")
			return
		}
	}
	rawMetadata, _ := json.Marshal(metadata)
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(), `UPDATE app_releases SET status='verified',file_size=?,sha256=?,file_metadata=?,verified_at=?,updated_at=? WHERE tenant_id=? AND id=? AND status='uploaded'`, size, metadata["sha256"], rawMetadata, now, now, tenant, id)
	if err != nil {
		problem(c, 500, "RELEASE_VERIFY_FAILED", "Unable to save release verification")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "RELEASE_STATE_CHANGED", "Release state changed while it was being verified")
		return
	}
	c.JSON(200, gin.H{"release": gin.H{"id": id, "platform": platform, "status": "verified", "fileName": fileName, "fileSize": size, "sha256": metadata["sha256"], "metadata": metadata}})
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

func simplifiedObjectKey(prefix, tenant, releaseID, fileName string) string {
	return strings.TrimLeft(path.Join(prefix, "tenants", tenant, "releases", releaseID, "application"+path.Ext(fileName)), "/")
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
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT object_key,file_name FROM app_releases WHERE tenant_id=? AND id=? AND status='active'`, tenantID(c), c.Param("id")).Scan(&key, &fileName)
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Published release not found")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	url, err := client.PresignGet(c.Request.Context(), key, time.Duration(s.cfg.ArtifactDownloadTTL)*time.Second, fileName)
	if err != nil {
		problem(c, 502, "RELEASE_DOWNLOAD_FAILED", "Unable to create release download URL")
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, url)
}
