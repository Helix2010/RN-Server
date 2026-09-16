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
	"github.com/Helix2010/RN-Server/internal/objectstore"
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
	uploadURL := s.absoluteURL(c, "/v1/admin/release-artifacts/upload")
	headers := map[string]string{"content-type": body.ContentType, "x-release-artifact-token": token}
	requiresCredentials := true
	if s.cfg.ArtifactUploadMode == "direct" {
		uploadURL, headers, err = client.PresignPut(c.Request.Context(), key, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
		if err != nil {
			problem(c, http.StatusFailedDependency, "ARTIFACT_UPLOAD_CREATE_FAILED", "Unable to create storage upload URL")
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
		problem(c, http.StatusFailedDependency, "RELEASE_UPLOAD_FAILED", err.Error())
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
		ArtifactToken string `json:"artifactToken"`
		// SBOM 的上传票据，可选。人工上传的包一般没有。
		SBOMToken    string         `json:"sbomToken"`
		Platform     string         `json:"platform"`
		Version      string         `json:"version"`
		BuildNumber  int            `json:"buildNumber"`
		ReleaseNotes map[string]any `json:"releaseNotes"`
		// 强制升级：用户在 App 里没有"稍后再说"，只能升。
		// 按 docs/RELIABILITY_AND_RELEASE.md 只用于严重安全漏洞、协议不兼容、
		// 法律合规阻断；为什么强制走审计 reason 留痕。
		Mandatory bool `json:"mandatory"`
		// NativeFingerprint 是 @expo/fingerprint 算出来的"原生面"指纹：热更新包能不能发给
		// 这个安装包，靠它判（见 ota_fingerprint.go）。人工上传的包一般没有，那样的基线不能发热更新。
		NativeFingerprint string `json:"nativeFingerprint"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE", "Invalid release payload")
		return
	}
	ctx := c.Request.Context()
	body.NativeFingerprint = strings.ToLower(strings.TrimSpace(body.NativeFingerprint))
	if body.NativeFingerprint != "" && !isHex(body.NativeFingerprint, 32, 128) {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE", "nativeFingerprint must be a hex digest")
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
	if enabled, err := s.platformEnabled(ctx, tenantID(c), body.Platform); err != nil || !enabled {
		problem(c, http.StatusUnprocessableEntity, "PLATFORM_DISABLED", "The requested platform is not enabled for this tenant")
		return
	}
	// 签名闸正在给这个租户签的时候不能手工插一个包进来：手工那条会抢走签名闸要用的
	// build 号与版本号，签名闸签完那一刻在版本递增上失败，而签过的号在签名闸本机记录里
	// 永远占着。入库事务里还会再查一次，这里先查是为了在下载与解析整个包之前就说清楚
	if body.Platform == "android" {
		if blocked, err := s.releaseSigningInFlight(ctx, s.db, tenantID(c), body.Platform); err != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to inspect builds in flight")
			return
		} else if blocked {
			problem(c, http.StatusConflict, "RELEASE_SIGNING_IN_FLIGHT", "A build for this platform is waiting for or being signed by the signer; wait for it to finish, or cancel it, before uploading a release by hand")
			return
		}
	}
	artifact, err := s.decodeReleaseArtifactToken(tenantID(c), body.ArtifactToken)
	if err != nil {
		problem(c, http.StatusUnauthorized, "INVALID_ARTIFACT_TOKEN", err.Error())
		return
	}
	client, _, err := s.storageClientForTenant(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	verifyCtx, cancel := context.WithTimeout(ctx, time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	stored, rejection := s.downloadStoredArtifact(verifyCtx, client, artifact.ObjectKey, artifact.Size)
	if rejection != nil {
		problem(c, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	defer os.Remove(stored.Path)
	// objectEtag 是校验时对象存储给的 ETag（objectstore.Stat，已去引号）；公开下载前再 Stat 一次比对，
	// 发布后对象被换掉即拒绝下发。CopyObject / 存储类变更会改 ETag，此时必须重新入库
	metadata := map[string]any{"fileName": artifact.FileName, "size": stored.Size, "sha256": stored.SHA256, "objectEtag": stored.ETag}
	// SBOM 记在发布记录上，而不是只落在对象存储里：等某个依赖明天爆 CVE，要回答
	// "线上那个 1.3.12 受不受影响"，得先能从发布记录找到对应的那一份清单。
	if sbom, err := s.storedSBOM(verifyCtx, client, tenantID(c), strings.TrimSpace(body.SBOMToken)); err != nil {
		problem(c, http.StatusUnprocessableEntity, "RELEASE_SBOM_INVALID", err.Error())
		return
	} else if sbom != nil {
		metadata["sbom"] = sbom
	}
	runtimeVersion := ""
	if body.Platform == "android" {
		verified, rejection, err := s.verifyAndroidArtifact(verifyCtx, tenantID(c), stored.Path, body.Version, body.BuildNumber)
		if err != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
			return
		}
		if rejection != nil {
			rejection.Summary["platform"] = body.Platform
			s.auditNow(newAudit(tenantID(c), actor(c), "release_rejected", "release-artifact", artifact.ID, rejection.Detail, requestID(c), rejection.Summary))
			problem(c, rejection.Status, rejection.Code, rejection.Detail)
			return
		}
		runtimeVersion = verified.RuntimeVersion
		for key, value := range verified.Metadata {
			metadata[key] = value
		}
		if body.NativeFingerprint != "" {
			metadata["nativeFingerprint"] = body.NativeFingerprint
		}
	}
	now := time.Now().UTC()
	insert := releaseInsert{
		ID: "rel_" + randomID(16), Tenant: tenantID(c), Platform: body.Platform, Version: body.Version, BuildNumber: body.BuildNumber,
		RuntimeVersion: runtimeVersion, ObjectKey: artifact.ObjectKey, FileName: artifact.FileName, ContentType: artifact.ContentType,
		ExpectedSize: artifact.Size, FileSize: stored.Size, SHA256: stored.SHA256, Metadata: metadata, Notes: releaseNotes,
		Mandatory: body.Mandatory, Actor: actor(c), RequestID: requestID(c), AuditReason: "Uploaded artifact verified and saved",
	}
	rejection, err = s.withReleaseSequence(ctx, tenantID(c), body.Platform, func(tx *sql.Tx) (*releaseRejection, error) {
		if body.Platform == "android" {
			blocked, err := s.releaseSigningInFlight(ctx, tx, tenantID(c), body.Platform)
			if err != nil {
				return nil, err
			}
			if blocked {
				return &releaseRejection{Status: http.StatusConflict, Code: "RELEASE_SIGNING_IN_FLIGHT",
					Detail: "A build for this platform is waiting for or being signed by the signer; wait for it to finish, or cancel it, before uploading a release by hand"}, nil
			}
		}
		return insertReleaseInTx(ctx, tx, insert, now)
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_CREATE_FAILED", "Unable to save release")
		return
	}
	if rejection != nil {
		problem(c, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"release": gin.H{"id": insert.ID, "platform": body.Platform, "version": body.Version, "buildNumber": body.BuildNumber, "runtimeVersion": runtimeVersion, "status": "verified", "releaseNotes": releaseNotes, "fileName": artifact.FileName, "contentType": artifact.ContentType, "expectedSize": artifact.Size, "fileSize": stored.Size, "sha256": stored.SHA256, "fileMetadata": metadata, "mandatory": body.Mandatory, "verifiedAt": iso(now), "createdAt": iso(now), "updatedAt": iso(now), "lastAction": nil}})
}

// ---- 入库校验（手工上传与签名闸共用） ----

// releaseRejection 是入库校验的拒绝：状态码、错误码、说明，以及写审计用的摘要。
type releaseRejection struct {
	Status  int
	Code    string
	Detail  string
	Summary map[string]any
}

// storedArtifact 是从对象存储取回、落在本地临时文件里的产物。调用方负责删掉 Path。
type storedArtifact struct {
	Path   string
	Size   int64
	SHA256 string
	ETag   string
}

// downloadStoredArtifact 核对对象存在、大小与声明一致、带 ETag，再整份取回算 sha256。
func (s *server) downloadStoredArtifact(ctx context.Context, client objectstore.Client, key string, expectedSize int64) (storedArtifact, *releaseRejection) {
	stat, err := client.Stat(ctx, key)
	if err != nil || stat.Size != expectedSize {
		return storedArtifact{}, &releaseRejection{Status: http.StatusUnprocessableEntity, Code: "RELEASE_FILE_INVALID", Detail: "Uploaded file is missing or has an unexpected size"}
	}
	if strings.TrimSpace(stat.ETag) == "" {
		// 没有 ETag 就没有"对象被替换"的可检测性：不能带着空值入库，否则下载时只剩大小比对
		return storedArtifact{}, &releaseRejection{Status: http.StatusFailedDependency, Code: "RELEASE_OBJECT_ETAG_MISSING", Detail: "Object storage returned no ETag for the uploaded artifact; the release cannot be pinned"}
	}
	temporary, err := os.CreateTemp("", "rn-release-*")
	if err != nil {
		return storedArtifact{}, &releaseRejection{Status: http.StatusInternalServerError, Code: "RELEASE_VERIFY_FAILED", Detail: "Unable to prepare release verification"}
	}
	objectBody, err := client.Get(ctx, key)
	if err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporary.Name())
		return storedArtifact{}, &releaseRejection{Status: http.StatusFailedDependency, Code: "RELEASE_READ_FAILED", Detail: "Unable to read uploaded release"}
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(objectBody, s.cfg.ArtifactMaxSizeBytes+1))
	_ = objectBody.Close()
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written != stat.Size {
		_ = os.Remove(temporary.Name())
		return storedArtifact{}, &releaseRejection{Status: http.StatusFailedDependency, Code: "RELEASE_READ_FAILED", Detail: "Unable to read the complete release"}
	}
	return storedArtifact{Path: temporary.Name(), Size: stat.Size, SHA256: hex.EncodeToString(hash.Sum(nil)), ETag: stat.ETag}, nil
}

// verifiedAndroidArtifact 是通过了入库校验的 Android 包。
type verifiedAndroidArtifact struct {
	APK            apkinspect.Metadata
	RuntimeVersion string
	Metadata       map[string]any
}

// verifyAndroidArtifact 在事务外做完一个 Android 包入库前的全部校验：解析与签名校验、
// 公开 debug 密钥、作废的旧指纹、发布身份（包名 + 签名者）、内嵌 applicationId、
// versionName/versionCode 与发布记录一致。手工上传与签名闸完成共用这一个函数，
// 复制一份出来迟早会漏掉其中一条，而漏掉的那条正是门禁存在的理由。
func (s *server) verifyAndroidArtifact(ctx context.Context, tenant, path, version string, buildNumber int) (verifiedAndroidArtifact, *releaseRejection, error) {
	var verified verifiedAndroidArtifact
	apk, inspectErr := apkinspect.Inspect(path)
	summary := map[string]any{"version": version, "buildNumber": buildNumber}
	if inspectErr != nil {
		// 解析阶段的拒绝还拿不到包名/签名者，审计只记代码与错误摘要
		summary["error"] = inspectErr.Error()
		if errors.Is(inspectErr, apkinspect.ErrEmbeddedConfigInvalid) {
			// 有内嵌配置但不是合法 JSON：这是构建产物损坏，不能当成"没有 applicationId"报缺失
			return verified, &releaseRejection{Status: http.StatusUnprocessableEntity, Code: "RELEASE_EMBEDDED_CONFIG_INVALID", Detail: "APK embedded Expo config is not valid JSON", Summary: withCode(summary, "RELEASE_EMBEDDED_CONFIG_INVALID")}, nil
		}
		return verified, &releaseRejection{Status: http.StatusUnprocessableEntity, Code: "RELEASE_VERIFY_FAILED", Detail: "Android package or signature verification failed", Summary: withCode(summary, "RELEASE_VERIFY_FAILED")}, nil
	}
	summary["packageName"], summary["signerSha256"] = apk.PackageName, normalizeFingerprint(apk.SignerSHA256)
	// 先看身份再看版本：公开 debug 密钥、作废指纹、未 pin、包名或签名者不符的包不该走到版本比对
	pin, err := s.androidReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		return verified, nil, err
	}
	var pinned *androidReleaseIdentity
	if pin != nil {
		pinned = &pin.Value
	}
	reject := func(code, detail string) (verifiedAndroidArtifact, *releaseRejection, error) {
		return verified, &releaseRejection{Status: http.StatusUnprocessableEntity, Code: code, Detail: detail, Summary: withCode(summary, code)}, nil
	}
	if code, detail := checkAndroidReleaseIdentity(apk, pinned, s.cfg.Environment == "production"); code != "" {
		return reject(code, detail)
	}
	if apk.ApplicationID == "" {
		return reject("RELEASE_APPLICATION_ID_MISSING", "APK does not embed extra.applicationId; OTA identity cannot be bound to it")
	}
	if apk.VersionName != version || apk.VersionCode != int64(buildNumber) {
		return reject("RELEASE_IDENTITY_MISMATCH", "APK versionName/versionCode does not match the release version and build number")
	}
	verified.APK = apk
	verified.RuntimeVersion = apk.RuntimeVersion
	verified.Metadata = map[string]any{
		"packageName": apk.PackageName, "versionName": apk.VersionName, "versionCode": apk.VersionCode, "runtimeVersion": apk.RuntimeVersion,
		"minSdk": apk.MinSDK, "signerSha256": normalizeFingerprint(apk.SignerSHA256), "signingScheme": apk.SigningScheme,
		"applicationId": apk.ApplicationID,
	}
	return verified, nil, nil
}

func withCode(summary map[string]any, code string) map[string]any {
	out := make(map[string]any, len(summary)+1)
	for key, value := range summary {
		out[key] = value
	}
	out["code"] = code
	return out
}

// releaseSigningInFlight：该租户该平台有 built 或 signing 的安装包任务。
func (s *server) releaseSigningInFlight(ctx context.Context, q rowQuerier, tenant, platform string) (bool, error) {
	var exists int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM build_jobs WHERE tenant_id=? AND platform=? AND kind='apk' AND status IN ('built','signing') LIMIT 1`, tenant, platform).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// withReleaseSequence 在"该租户该平台的发布序列锁"里开一个事务执行 fn。
//
// 锁是 GET_LOCK 命名锁，拿不到（另一个入库正在进行）回 409 RELEASE_SEQUENCE_BUSY——签名闸把它
// 当作临时错误重试。fn 返回拒绝或错误时事务回滚。
func (s *server) withReleaseSequence(ctx context.Context, tenant, platform string, fn func(tx *sql.Tx) (*releaseRejection, error)) (*releaseRejection, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	lockName := "rn_release_" + tenant + "_" + platform
	var locked sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?,5)`, lockName).Scan(&locked); err != nil || !locked.Valid || locked.Int64 != 1 {
		return &releaseRejection{Status: http.StatusConflict, Code: "RELEASE_SEQUENCE_BUSY", Detail: "Another release is being created for this platform"}, nil
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lockName)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rejection, err := fn(tx)
	if err != nil || rejection != nil {
		return rejection, err
	}
	return nil, tx.Commit()
}

// releaseInsert 是一条要写进 app_releases 的发布记录。
type releaseInsert struct {
	ID, Tenant, Platform, Version string
	BuildNumber                   int
	RuntimeVersion                string
	ObjectKey, FileName           string
	ContentType                   string
	ExpectedSize, FileSize        int64
	SHA256                        string
	Metadata                      map[string]any
	Notes                         map[string][]string
	Mandatory                     bool
	Actor, RequestID, AuditReason string
	AuditSummary                  map[string]any
}

// insertReleaseInTx 在调用方的事务里做版本递增校验、写发布记录与 release_create 审计。
// 调用方必须已经拿着 withReleaseSequence 的锁：递增校验读的是"该平台最新一条"，没有锁时
// 两个并发入库都会读到同一个最大值。
func insertReleaseInTx(ctx context.Context, tx *sql.Tx, r releaseInsert, now time.Time) (*releaseRejection, error) {
	var latestBuild int
	var latestVersion sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT version,build_number FROM app_releases WHERE tenant_id=? AND platform=? ORDER BY build_number DESC LIMIT 1`, r.Tenant, r.Platform).Scan(&latestVersion, &latestBuild)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if r.BuildNumber <= latestBuild || (latestVersion.Valid && compareVersion(r.Version, latestVersion.String) <= 0) {
		return &releaseRejection{Status: http.StatusConflict, Code: "RELEASE_VERSION_NOT_INCREASING", Detail: "Version and build number must both be greater than the latest release for this platform"}, nil
	}
	// map[string][]string 一定能序列化，没有需要处理的错误分支
	notes, _ := json.Marshal(r.Notes)
	rawMetadata, err := json.Marshal(r.Metadata)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,file_metadata,mandatory,verified_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.Tenant, r.Platform, r.Version, r.BuildNumber, r.RuntimeVersion, "verified", notes, r.ObjectKey, r.FileName, r.ContentType, r.ExpectedSize, r.FileSize, r.SHA256, rawMetadata, r.Mandatory, now, r.Actor, now, now); err != nil {
		return nil, err
	}
	summary := map[string]any{"platform": r.Platform, "version": r.Version, "buildNumber": r.BuildNumber, "mandatory": r.Mandatory}
	for key, value := range r.AuditSummary {
		summary[key] = value
	}
	if err := insertAudit(ctx, tx, newAudit(r.Tenant, r.Actor, "release_create", "release", r.ID, r.AuditReason, r.RequestID, summary)); err != nil {
		return nil, err
	}
	return nil, nil
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
		problem(c, http.StatusFailedDependency, "RELEASE_DOWNLOAD_FAILED", "Unable to read release package")
		return
	}
	if mismatch != "" {
		s.noteObjectChanged("release", tenantID(c), c.Param("id"), mismatch, requestID(c), actual, size, storedEtag, nil)
		problem(c, http.StatusFailedDependency, "RELEASE_OBJECT_CHANGED", "Release package in storage no longer matches the verified artifact")
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
		problem(c, http.StatusFailedDependency, "RELEASE_DOWNLOAD_FAILED", "Unable to read release package")
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

// storedSBOM 确认 SBOM 确实落进了对象存储，返回要记进发布记录的那几个字段。
//
// token 为空返回 (nil, nil)：人工上传的包没有 SBOM，那不是错误。给了 token 却对不
// 上，才是错误——发布记录上写着一份取不回来的清单，比不写更糟。
func (s *server) storedSBOM(ctx context.Context, client objectstore.Client, tenant, token string) (map[string]any, error) {
	if token == "" {
		return nil, nil
	}
	value, err := s.decodeReleaseArtifactToken(tenant, token)
	if err != nil {
		return nil, errors.New("the SBOM upload token is invalid or expired")
	}
	stored, err := client.Stat(ctx, value.ObjectKey)
	if err != nil || stored.Size != value.Size {
		return nil, errors.New("the SBOM object is missing or has an unexpected size")
	}
	return map[string]any{
		"fileName":  value.FileName,
		"objectKey": value.ObjectKey,
		"size":      stored.Size,
		"format":    "cyclonedx-json",
	}, nil
}
