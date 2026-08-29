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
	"time"

	"github.com/gin-gonic/gin"
)

const otaMaxPackageBytes int64 = 512 * 1024 * 1024

var otaUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

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
	query := `SELECT id,platform,version,build_number,runtime_version,status,created_at FROM app_releases WHERE tenant_id=? AND status IN ('verified','active') AND runtime_version<>'' AND (?='' OR platform=?) ORDER BY build_number DESC LIMIT 100`
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
		var created time.Time
		if err := rows.Scan(&id, &p, &version, &build, &runtime, &status, &created); err != nil {
			problem(c, 500, "OTA_BASE_RELEASE_QUERY_FAILED", "Unable to load OTA base releases")
			return
		}
		items = append(items, gin.H{"id": id, "platform": p, "version": version, "buildNumber": build, "runtimeVersion": runtime, "status": status, "createdAt": iso(created)})
	}
	c.JSON(200, gin.H{"items": items, "nextCursor": nil, "hasMore": false})
}

func (s *server) listOTAReleases(c *gin.Context) {
	platform, status := strings.ToLower(strings.TrimSpace(c.Query("platform"))), strings.ToLower(strings.TrimSpace(c.Query("status")))
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT o.id,o.base_release_id,o.platform,o.channel,o.runtime_version,o.revision,o.update_id,o.release_kind,o.apply_strategy,o.status,o.manifest_sha256,o.release_notes,o.source_commit_sha,o.rejection_reason,o.created_by,o.verified_at,o.published_at,o.created_at,o.updated_at, a.version,a.build_number FROM ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id WHERE o.tenant_id=? AND (?='' OR o.platform=?) AND (?='' OR o.status=?) ORDER BY o.revision DESC, o.created_at DESC, o.id DESC LIMIT 200`, tenantID(c), platform, platform, status, status)
	if err != nil {
		problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, base, p, channel, runtime, updateID, kind, applyStrategy, st, creator, notes, baseVersion string
		var sha, source, rejection sql.NullString
		var revision, baseBuild int
		var verified, published, created, updated sql.NullTime
		if err := rows.Scan(&id, &base, &p, &channel, &runtime, &revision, &updateID, &kind, &applyStrategy, &st, &sha, &notes, &source, &rejection, &creator, &verified, &published, &created, &updated, &baseVersion, &baseBuild); err != nil {
			problem(c, 500, "OTA_QUERY_FAILED", "Unable to load OTA releases")
			return
		}
		var noteValue map[string]any
		_ = json.Unmarshal([]byte(notes), &noteValue)
		items = append(items, gin.H{"id": id, "baseReleaseId": base, "baseVersion": baseVersion, "baseBuildNumber": baseBuild, "platform": p, "channel": channel, "runtimeVersion": runtime, "revision": revision, "updateId": updateID, "releaseKind": kind, "applyStrategy": applyStrategy, "status": st, "manifestSha256": nullableString(sha.String), "releaseNotes": noteValue, "sourceCommitSha": nullableString(source.String), "rejectionReason": nullableString(rejection.String), "createdBy": creator, "verifiedAt": nullableOTAFieldTime(verified), "publishedAt": nullableOTAFieldTime(published), "createdAt": nullableOTAFieldTime(created), "updatedAt": nullableOTAFieldTime(updated)})
	}
	c.JSON(200, gin.H{"items": items, "nextCursor": nil, "hasMore": false})
}

func (s *server) otaReleaseDetail(c *gin.Context) {
	var id, baseID, platform, channel, runtime, updateID, kind, applyStrategy, status, baseVersion, creator string
	var revision, baseBuild int
	var manifestKey, manifestSHA, source, reject sql.NullString
	var notes []byte
	var verified, published, created, updated sql.NullTime
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT o.id,o.base_release_id,o.platform,o.channel,o.runtime_version,o.revision,o.update_id,o.release_kind,o.apply_strategy,o.status,o.manifest_key,o.manifest_sha256,o.release_notes,o.source_commit_sha,o.rejection_reason,o.created_by,o.verified_at,o.published_at,o.created_at,o.updated_at,a.version,a.build_number FROM ota_releases o JOIN app_releases a ON a.id=o.base_release_id AND a.tenant_id=o.tenant_id WHERE o.tenant_id=? AND o.id=?`, tenantID(c), c.Param("id")).Scan(&id, &baseID, &platform, &channel, &runtime, &revision, &updateID, &kind, &applyStrategy, &status, &manifestKey, &manifestSHA, &notes, &source, &reject, &creator, &verified, &published, &created, &updated, &baseVersion, &baseBuild)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "OTA_NOT_FOUND", "OTA release not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_QUERY_FAILED", "Unable to load OTA release")
		return
	}
	var releaseNotes map[string]any
	_ = json.Unmarshal(notes, &releaseNotes)
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
			problem(c, http.StatusBadGateway, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
			return
		}
		raw, readErr := io.ReadAll(io.LimitReader(body, 8*1024*1024))
		_ = body.Close()
		if readErr != nil || (manifestSHA.Valid && hex.EncodeToString(hashBytes(raw)) != manifestSHA.String) || json.Unmarshal(raw, &manifest) != nil {
			problem(c, http.StatusBadGateway, "OTA_MANIFEST_INVALID", "OTA manifest integrity check failed")
			return
		}
	}
	identity := otaManifestIdentity(manifest)
	c.JSON(http.StatusOK, gin.H{
		"release":      gin.H{"id": id, "baseReleaseId": baseID, "baseVersion": baseVersion, "baseBuildNumber": baseBuild, "platform": platform, "channel": channel, "runtimeVersion": runtime, "revision": revision, "updateId": updateID, "releaseKind": kind, "applyStrategy": applyStrategy, "status": status, "manifestKey": nullableString(manifestKey.String), "manifestSha256": nullableString(manifestSHA.String), "releaseNotes": releaseNotes, "sourceCommitSha": nullableString(source.String), "rejectionReason": nullableString(reject.String), "createdBy": creator, "verifiedAt": nullableOTAFieldTime(verified), "publishedAt": nullableOTAFieldTime(published), "createdAt": nullableOTAFieldTime(created), "updatedAt": nullableOTAFieldTime(updated)},
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
	url := absoluteURL(c, "/v1/admin/ota/artifacts/upload")
	headers := map[string]string{"content-type": body.ContentType, "x-ota-artifact-token": tok}
	requires := true
	if s.cfg.ArtifactUploadMode == "direct" {
		url, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		requires = false
		if err != nil {
			problem(c, 502, "OTA_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
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
		problem(c, 502, "OTA_UPLOAD_FAILED", err.Error())
		return
	}
	c.JSON(200, gin.H{"artifact": gin.H{"id": v.ID, "fileSize": size, "objectKey": v.ObjectKey}})
}

func (s *server) deleteOTAArtifact(c *gin.Context) {
	v, err := s.decodeOTAUploadToken(tenantID(c), otaTokenFromRequest(c))
	if err == nil {
		if client, _, e := s.storageClientForTenant(c.Request.Context(), tenantID(c)); e == nil {
			_ = client.Delete(c.Request.Context(), v.ObjectKey)
		}
	}
	c.JSON(200, gin.H{"deleted": true})
}

func (s *server) saveOTARelease(c *gin.Context) {
	var body struct {
		ArtifactToken, BaseReleaseID, Channel, SourceCommitSHA, ApplyStrategy string
		ReleaseNotes                                                          map[string]any `json:"releaseNotes"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_OTA_RELEASE", "Invalid OTA release payload")
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
	v, err := s.decodeOTAUploadToken(tenantID(c), body.ArtifactToken)
	if err != nil {
		problem(c, 401, "INVALID_OTA_ARTIFACT_TOKEN", err.Error())
		return
	}
	var basePlatform, baseRuntime, baseStatus, baseVersion string
	var baseBuild int
	var baseFileMetadata []byte
	if err = s.db.QueryRowContext(c.Request.Context(), `SELECT platform,runtime_version,status,version,build_number,file_metadata FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), body.BaseReleaseID).Scan(&basePlatform, &baseRuntime, &baseStatus, &baseVersion, &baseBuild, &baseFileMetadata); err != nil {
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
		problem(c, 502, "OTA_READ_FAILED", "Unable to read OTA package")
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
	updateID := manifest["id"].(string)
	releaseID := "ota_" + randomID(16)
	_, prefix, _ := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	baseKey := strings.TrimLeft(path.Join(prefix, "tenants", tenantID(c), "ota", body.Channel, basePlatform, baseRuntime, releaseID), "/")
	uploadedKeys := []string{}
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
			problem(c, 502, "OTA_RESOURCE_SAVE_FAILED", "Unable to store OTA resources")
			return
		}
		uploadedKeys = append(uploadedKeys, path.Join(baseKey, clean))
	}
	manifest["runtimeVersion"] = baseRuntime
	manifest["platform"] = basePlatform
	manifest["channel"] = body.Channel
	rewriteOTAClientIdentity(manifest, otaClientIdentity{
		APIBaseURL:    absoluteURL(c, ""),
		ApplicationID: otaApplicationID(baseFileMetadata, manifest),
		AppVersion:    baseVersion,
		BuildNumber:   baseBuild,
		Platform:      basePlatform,
		Distribution:  otaDistribution(basePlatform, baseFileMetadata, manifest),
		OTAChannel:    body.Channel,
	})
	manifest["metadata"] = mergeManifestMetadata(manifest["metadata"], body.Channel, body.ApplyStrategy)
	manifest = rewriteManifestURLs(manifest, absoluteURL(c, "/v1/ota/assets/"+releaseID+"/"))
	finalManifest, _ := json.Marshal(manifest)
	manifestKey := path.Join(baseKey, "manifest.json")
	if err := client.Put(ctx, manifestKey, strings.NewReader(string(finalManifest)), int64(len(finalManifest)), "application/json"); err != nil {
		problem(c, 502, "OTA_RESOURCE_SAVE_FAILED", "Unable to store OTA manifest")
		return
	}
	uploadedKeys = append(uploadedKeys, manifestKey)
	hash := sha256.Sum256(finalManifest)
	notes, _ := json.Marshal(body.ReleaseNotes)
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
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,apply_strategy,status,manifest_key,manifest_sha256,release_notes,source_commit_sha,created_by,verified_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, releaseID, tenantID(c), body.BaseReleaseID, basePlatform, body.Channel, baseRuntime, revision, updateID, body.ApplyStrategy, "verified", manifestKey, hex.EncodeToString(hash[:]), notes, nullableSQLValue(body.SourceCommitSHA), actor(c), now, now, now)
	if err != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to save OTA release")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ota_create", "ota-release", releaseID, "OTA package verified and saved", requestID(c), map[string]any{"baseReleaseId": body.BaseReleaseID, "platform": basePlatform, "runtimeVersion": baseRuntime, "revision": revision})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to save OTA audit")
		return
	}
	if tx.Commit() != nil {
		problem(c, 500, "OTA_CREATE_FAILED", "Unable to commit OTA release")
		return
	}
	persisted = true
	c.JSON(201, gin.H{"release": gin.H{"id": releaseID, "baseReleaseId": body.BaseReleaseID, "platform": basePlatform, "channel": body.Channel, "runtimeVersion": baseRuntime, "revision": revision, "updateId": updateID, "applyStrategy": body.ApplyStrategy, "status": "verified", "manifestSha256": hex.EncodeToString(hash[:]), "releaseNotes": body.ReleaseNotes, "verifiedAt": iso(now), "createdAt": iso(now), "updatedAt": iso(now)}})
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

func otaApplicationID(raw []byte, manifest map[string]any) string {
	var metadata map[string]any
	if json.Unmarshal(raw, &metadata) == nil {
		if value, ok := metadata["packageName"].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	if value := otaManifestExtraString(manifest, "applicationId"); value != "" {
		return value
	}
	return "dex-mobile"
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
		channel = s.cfg.OTAChannel
	}
	if platform == "" || runtime == "" {
		c.Status(http.StatusNoContent)
		return
	}
	if protocol := strings.TrimSpace(c.GetHeader("expo-protocol-version")); protocol != "" && protocol != "1" {
		problem(c, http.StatusBadRequest, "OTA_PROTOCOL_UNSUPPORTED", "Unsupported Expo Updates protocol version")
		return
	}
	var id, kind string
	var key, sha sql.NullString
	var published sql.NullTime
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,release_kind,manifest_key,manifest_sha256,published_at FROM ota_releases WHERE tenant_id=? AND platform=? AND channel=? AND runtime_version=? AND status='active' ORDER BY revision DESC LIMIT 1`, tenantID(c), platform, channel, runtime).Scan(&id, &kind, &key, &sha, &published)
	if errors.Is(err, sql.ErrNoRows) {
		c.Status(http.StatusNoContent)
		return
	}
	if err != nil {
		problem(c, 500, "OTA_MANIFEST_QUERY_FAILED", "Unable to load OTA manifest")
		return
	}
	if kind == "rollback" {
		commitTime := time.Now().UTC()
		if published.Valid {
			commitTime = published.Time.UTC()
		}
		payload, _ := json.Marshal(gin.H{"type": "rollBackToEmbedded", "parameters": gin.H{"commitTime": iso(commitTime)}})
		writeExpoMultipart(c, "directive", payload)
		return
	}
	if !key.Valid || !sha.Valid {
		problem(c, http.StatusBadGateway, "OTA_MANIFEST_INVALID", "OTA manifest is unavailable")
		return
	}
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	body, err := client.Get(c.Request.Context(), key.String)
	if err != nil {
		problem(c, 502, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
		return
	}
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, 8*1024*1024))
	if err != nil {
		problem(c, 502, "OTA_MANIFEST_UNAVAILABLE", "Unable to read OTA manifest")
		return
	}
	if hex.EncodeToString(hashBytes(raw)) != sha.String {
		problem(c, 502, "OTA_MANIFEST_INVALID", "OTA manifest integrity check failed")
		return
	}
	if strings.TrimSpace(c.GetHeader("if-none-match")) == `"`+sha.String+`"` {
		c.Header("ETag", `"`+sha.String+`"`)
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("Cache-Control", "no-cache")
	c.Header("expo-protocol-version", "1")
	c.Header("expo-sfv-version", "0")
	c.Header("ETag", `"`+sha.String+`"`)
	if strings.Contains(c.GetHeader("Accept"), "multipart/mixed") {
		writeExpoMultipart(c, "manifest", raw)
		return
	}
	c.Data(200, "application/expo+json", raw)
}
func hashBytes(v []byte) []byte { h := sha256.Sum256(v); return h[:] }

func writeExpoMultipart(c *gin.Context, name string, payload []byte) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="`+name+`"`)
	header.Set("Content-Type", "application/json")
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
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT manifest_key FROM ota_releases WHERE tenant_id=? AND id=? AND status IN ('active','paused','superseded')`, tenantID(c), id).Scan(&key); err != nil || !key.Valid {
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
	body, err := client.Get(c.Request.Context(), assetKey)
	if err != nil {
		problem(c, 404, "OTA_ASSET_NOT_FOUND", "OTA asset not found")
		return
	}
	defer body.Close()
	c.Header("Cache-Control", "public, max-age=31536000, immutable")
	c.Header("Content-Type", contentTypeForPath(relPath))
	io.Copy(c.Writer, body)
}

func (s *server) otaAction(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return
	}
	id, action := c.Param("id"), c.Param("action")
	if action == "republish" {
		problem(c, 422, "OTA_REPUBLISH_UNSUPPORTED", "Republish must create a new immutable update from source artifacts")
		return
	}
	var slotPlatform, slotChannel, slotRuntime string
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT platform,channel,runtime_version FROM ota_releases WHERE tenant_id=? AND id=?`, tenantID(c), id).Scan(&slotPlatform, &slotChannel, &slotRuntime); err != nil {
		problem(c, 404, "OTA_NOT_FOUND", "OTA release not found")
		return
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
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE ota_releases SET status=?,published_at=CASE WHEN ?='active' THEN ? ELSE published_at END,updated_at=? WHERE tenant_id=? AND id=? AND status=?`, target, target, now, now, tenantID(c), id, status)
	if err != nil {
		problem(c, 500, "OTA_TRANSITION_FAILED", "Unable to update OTA release")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "OTA_STATE_CHANGED", "OTA release changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ota_"+action, "ota-release", id, body.Reason, requestID(c), map[string]any{"status": target})
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
