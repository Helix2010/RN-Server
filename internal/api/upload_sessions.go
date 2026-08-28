package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

const (
	defaultMultipartPartSize int64 = 16 * 1024 * 1024
	maxMultipartParts              = 10000
)

type uploadSessionToken struct {
	SessionID string `json:"sessionId"`
	TenantID  string `json:"tenantId"`
	UploadID  string `json:"-"`
	ExpiresAt int64  `json:"expiresAt"`
}

type uploadPartState struct {
	PartNumber int    `json:"partNumber"`
	ETag       string `json:"etag"`
	Size       int64  `json:"size"`
}

type uploadSessionView struct {
	ID           string
	UploadType   string
	ObjectKey    string
	FileName     string
	ContentType  string
	ExpectedSize int64
	PartSize     int64
	TotalParts   int
	Status       string
	ExpiresAt    time.Time
	Parts        []uploadPartState
}

func (s *server) encodeUploadSessionToken(v uploadSessionToken) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil || s.secrets == nil {
		return "", errors.New("upload session token unavailable")
	}
	enc, err := s.secrets.Encrypt(string(raw), "upload-session:"+v.TenantID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(enc), nil
}

func (s *server) decodeUploadSessionToken(tenant, encoded string) (uploadSessionToken, error) {
	var v uploadSessionToken
	if s.secrets == nil || strings.TrimSpace(encoded) == "" {
		return v, errors.New("upload session token unavailable")
	}
	enc, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return v, errors.New("invalid upload session token")
	}
	plain, err := s.secrets.Decrypt(enc, "upload-session:"+tenant)
	if err != nil || json.Unmarshal([]byte(plain), &v) != nil || v.TenantID != tenant || time.Now().UTC().Unix() > v.ExpiresAt || v.SessionID == "" {
		return v, errors.New("invalid or expired upload session token")
	}
	return v, nil
}

func uploadSessionTokenFromRequest(c *gin.Context) string {
	for _, name := range []string{"x-upload-session-token", "x-release-artifact-token", "x-ota-artifact-token"} {
		if value := strings.TrimSpace(c.GetHeader(name)); value != "" {
			return value
		}
	}
	return strings.TrimSpace(c.Query("token"))
}

func (s *server) createUploadSession(c *gin.Context) {
	var body struct {
		UploadType  string `json:"uploadType"`
		FileName    string `json:"fileName"`
		ContentType string `json:"contentType"`
		Size        int64  `json:"size"`
		PartSize    int64  `json:"partSize"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_UPLOAD_SESSION", "Invalid upload session payload")
		return
	}
	body.UploadType = strings.ToLower(strings.TrimSpace(body.UploadType))
	body.FileName = path.Base(strings.TrimSpace(body.FileName))
	body.ContentType = strings.ToLower(strings.TrimSpace(body.ContentType))
	if body.UploadType != "apk" && body.UploadType != "ota" || body.FileName == "" || body.FileName == "." || body.Size < 1 || body.Size > s.cfg.ArtifactMaxSizeBytes {
		problem(c, 422, "INVALID_UPLOAD_SESSION", "uploadType, fileName and size are invalid")
		return
	}
	if body.PartSize == 0 {
		body.PartSize = defaultMultipartPartSize
	}
	if body.PartSize < 5*1024*1024 || body.PartSize > 512*1024*1024 {
		problem(c, 422, "INVALID_UPLOAD_SESSION", "partSize must be between 5MB and 512MB")
		return
	}
	total := int((body.Size + body.PartSize - 1) / body.PartSize)
	if total < 1 || total > maxMultipartParts {
		problem(c, 422, "INVALID_UPLOAD_SESSION", "file produces too many parts")
		return
	}
	client, prefix, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	id := "upl_" + randomID(16)
	key := strings.TrimLeft(path.Join(prefix, "tenants", tenantID(c), "upload-sessions", id, "payload"+path.Ext(body.FileName)), "/")
	uploadID, err := client.CreateMultipartUpload(c.Request.Context(), key, body.ContentType)
	if err != nil {
		problem(c, 502, "UPLOAD_SESSION_CREATE_FAILED", "Unable to create multipart upload")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(time.Duration(s.cfg.ArtifactMultipartTTL) * time.Second)
	parts := []uploadPartState{}
	rawParts, _ := json.Marshal(parts)
	if _, err := s.db.ExecContext(c.Request.Context(), `INSERT INTO upload_sessions(id,tenant_id,upload_type,object_key,upload_id,file_name,content_type,expected_size,part_size,total_parts,uploaded_parts,status,expires_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?)`, id, tenantID(c), body.UploadType, key, uploadID, body.FileName, body.ContentType, body.Size, body.PartSize, total, rawParts, expires, actor(c), now, now); err != nil {
		_ = client.AbortMultipartUpload(context.Background(), key, uploadID)
		problem(c, 500, "UPLOAD_SESSION_CREATE_FAILED", "Unable to persist upload session")
		return
	}
	tok, err := s.encodeUploadSessionToken(uploadSessionToken{SessionID: id, TenantID: tenantID(c), ExpiresAt: expires.Unix()})
	if err != nil {
		_ = client.AbortMultipartUpload(context.Background(), key, uploadID)
		_, _ = s.db.ExecContext(context.Background(), `UPDATE upload_sessions SET status='aborted',updated_at=? WHERE tenant_id=? AND id=? AND status='active'`, time.Now().UTC(), tenantID(c), id)
		problem(c, 503, "UPLOAD_SESSION_TOKEN_UNAVAILABLE", "Upload session signing is not configured")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"session": s.uploadSessionJSON(uploadSessionView{ID: id, UploadType: body.UploadType, FileName: body.FileName, ContentType: body.ContentType, ExpectedSize: body.Size, PartSize: body.PartSize, TotalParts: total, Status: "active", ExpiresAt: expires, Parts: parts}), "token": tok, "uploadMode": s.cfg.ArtifactUploadMode})
}

func (s *server) getUploadSession(c *gin.Context) {
	encoded := uploadSessionTokenFromRequest(c)
	session, client, tok, err := s.loadUploadSession(c, encoded)
	if err != nil {
		problem(c, 401, "INVALID_UPLOAD_SESSION", "Upload session token is invalid or expired")
		return
	}
	if parts, listErr := client.ListParts(c.Request.Context(), session.ObjectKey, tok.UploadID); listErr == nil {
		session.Parts = make([]uploadPartState, 0, len(parts))
		for _, part := range parts {
			session.Parts = append(session.Parts, uploadPartState{PartNumber: part.PartNumber, ETag: part.ETag, Size: part.Size})
		}
	}
	c.JSON(200, gin.H{"session": s.uploadSessionJSON(session), "token": encoded})
}

func (s *server) uploadSessionPart(c *gin.Context) {
	session, client, tok, err := s.loadUploadSession(c, uploadSessionTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_UPLOAD_SESSION", "Upload session token is invalid or expired")
		return
	}
	if session.Status != "active" || session.ExpiresAt.Before(time.Now().UTC()) {
		problem(c, 409, "UPLOAD_SESSION_NOT_ACTIVE", "Upload session is no longer active")
		return
	}
	partNumber, err := strconv.Atoi(c.Param("partNumber"))
	if err != nil || partNumber < 1 || partNumber > session.TotalParts {
		problem(c, 422, "INVALID_UPLOAD_PART", "partNumber is invalid")
		return
	}
	for _, part := range session.Parts {
		if part.PartNumber == partNumber {
			c.JSON(200, gin.H{"part": part})
			return
		}
	}
	expected := session.PartSize
	if partNumber == session.TotalParts {
		expected = session.ExpectedSize - session.PartSize*int64(session.TotalParts-1)
	}
	if c.Request.ContentLength < 0 {
		problem(c, 411, "UPLOAD_PART_LENGTH_REQUIRED", "Content-Length is required for a multipart part")
		return
	}
	if c.Request.ContentLength != expected {
		problem(c, 411, "UPLOAD_PART_SIZE_MISMATCH", "Uploaded part size does not match declaration")
		return
	}
	limited := io.LimitReader(c.Request.Body, expected+1)
	etag, err := client.UploadPart(c.Request.Context(), session.ObjectKey, tok.UploadID, partNumber, limited, expected)
	if err != nil {
		problem(c, 502, "UPLOAD_PART_FAILED", "Unable to upload part")
		return
	}
	if err := s.recordUploadPart(c, session.ID, partNumber, etag, expected); err != nil {
		problem(c, 409, "UPLOAD_PART_CONFLICT", "Unable to record uploaded part")
		return
	}
	c.JSON(200, gin.H{"part": uploadPartState{PartNumber: partNumber, ETag: etag, Size: expected}})
}

func (s *server) presignUploadSessionPart(c *gin.Context) {
	session, client, tok, err := s.loadUploadSession(c, uploadSessionTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_UPLOAD_SESSION", "Upload session token is invalid or expired")
		return
	}
	if session.Status != "active" || session.ExpiresAt.Before(time.Now().UTC()) {
		problem(c, http.StatusConflict, "UPLOAD_SESSION_NOT_ACTIVE", "Upload session is no longer active")
		return
	}
	partNumber, err := strconv.Atoi(c.Param("partNumber"))
	if err != nil || partNumber < 1 || partNumber > session.TotalParts {
		problem(c, 422, "INVALID_UPLOAD_PART", "partNumber is invalid")
		return
	}
	url, headers, err := client.PresignUploadPart(c.Request.Context(), session.ObjectKey, tok.UploadID, partNumber, time.Duration(s.cfg.ArtifactMultipartTTL)*time.Second)
	if err != nil {
		problem(c, 502, "UPLOAD_PART_PRESIGN_FAILED", "Unable to create part upload URL")
		return
	}
	c.JSON(200, gin.H{"partNumber": partNumber, "url": url, "headers": headers, "expiresAt": iso(session.ExpiresAt)})
}

func (s *server) completeUploadSession(c *gin.Context) {
	session, client, tok, err := s.loadUploadSession(c, uploadSessionTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_UPLOAD_SESSION", "Upload session token is invalid or expired")
		return
	}
	if session.Status == "completed" {
		size, _, headErr := client.Head(c.Request.Context(), session.ObjectKey)
		if headErr != nil || size != session.ExpectedSize {
			problem(c, http.StatusUnprocessableEntity, "UPLOAD_SIZE_INVALID", "Completed upload object is missing or invalid")
			return
		}
		s.emitCompletedUpload(c, session)
		return
	}
	if session.Status != "active" || session.ExpiresAt.Before(time.Now().UTC()) {
		problem(c, 409, "UPLOAD_SESSION_NOT_ACTIVE", "Upload session is no longer active")
		return
	}
	var body struct {
		Parts []uploadPartState `json:"parts"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_UPLOAD_COMPLETE", "Invalid uploaded parts payload")
		return
	}
	if len(body.Parts) != session.TotalParts {
		problem(c, 422, "UPLOAD_PARTS_INCOMPLETE", "All upload parts are required")
		return
	}
	storageParts, listErr := client.ListParts(c.Request.Context(), session.ObjectKey, tok.UploadID)
	if listErr != nil {
		// Some S3-compatible providers (or tenant IAM policies) allow part
		// uploads and completion but do not expose ListParts. The database
		// ledger is already written after every successful part upload, so use
		// it as the recovery source and let CompleteMultipartUpload remain the
		// provider's authoritative validation.
		slog.Warn("multipart parts listing unavailable; using persisted ledger", "tenant", tenantID(c), "sessionId", session.ID, "error", listErr)
	} else {
		session.Parts = make([]uploadPartState, 0, len(storageParts))
		for _, part := range storageParts {
			session.Parts = append(session.Parts, uploadPartState{PartNumber: part.PartNumber, ETag: part.ETag, Size: part.Size})
		}
	}
	sort.Slice(body.Parts, func(i, j int) bool { return body.Parts[i].PartNumber < body.Parts[j].PartNumber })
	for i, part := range body.Parts {
		if part.PartNumber != i+1 || strings.TrimSpace(part.ETag) == "" || part.Size <= 0 {
			problem(c, 422, "UPLOAD_PARTS_INVALID", "Uploaded parts are invalid")
			return
		}
		if !s.partMatches(session.Parts, part) {
			problem(c, 409, "UPLOAD_PARTS_CONFLICT", "Uploaded parts do not match the session")
			return
		}
	}
	if err := client.CompleteMultipartUpload(c.Request.Context(), session.ObjectKey, tok.UploadID, func() []objectstore.CompletedPart {
		out := make([]objectstore.CompletedPart, len(body.Parts))
		for i, p := range body.Parts {
			out[i] = objectstore.CompletedPart{PartNumber: p.PartNumber, ETag: p.ETag, Size: p.Size}
		}
		return out
	}()); err != nil {
		// A successful provider completion can still lose its HTTP response.
		// Check the immutable object before deciding that completion failed.
		if size, _, headErr := client.Head(c.Request.Context(), session.ObjectKey); headErr == nil && size == session.ExpectedSize {
			slog.Warn("multipart complete response was lost; object is already complete", "tenant", tenantID(c), "sessionId", session.ID)
		} else {
			slog.Error("multipart complete failed", "tenant", tenantID(c), "sessionId", session.ID, "partCount", len(body.Parts), "objectSize", session.ExpectedSize, "error", err)
			// Keep the session active so a transient/provider compatibility error
			// can be retried without uploading all parts again. Expiry cleanup
			// will abort abandoned sessions.
			problem(c, 502, "UPLOAD_COMPLETE_FAILED", "Unable to complete multipart upload; the uploaded parts were kept for retry")
			return
		}
	}
	size, _, err := client.Head(c.Request.Context(), session.ObjectKey)
	if err != nil || size != session.ExpectedSize {
		_ = client.Delete(context.Background(), session.ObjectKey)
		_, _ = s.db.ExecContext(context.Background(), `UPDATE upload_sessions SET status='aborted',updated_at=? WHERE tenant_id=? AND id=?`, time.Now().UTC(), tenantID(c), session.ID)
		problem(c, 422, "UPLOAD_SIZE_INVALID", "Completed object size does not match declaration")
		return
	}
	result, updateErr := s.db.ExecContext(c.Request.Context(), `UPDATE upload_sessions SET status='completed',updated_at=? WHERE tenant_id=? AND id=? AND status='active'`, time.Now().UTC(), tenantID(c), session.ID)
	if updateErr != nil {
		_ = client.Delete(context.Background(), session.ObjectKey)
		problem(c, 500, "UPLOAD_SESSION_UPDATE_FAILED", "Unable to finalize upload session")
		return
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		var status string
		if statusErr := s.db.QueryRowContext(c.Request.Context(), `SELECT status FROM upload_sessions WHERE tenant_id=? AND id=?`, tenantID(c), session.ID).Scan(&status); statusErr == nil && status == "completed" {
			// An idempotent retry may complete an already-completed session. The
			// artifact token below remains deterministic for this session.
		} else {
			problem(c, 409, "UPLOAD_SESSION_NOT_ACTIVE", "Upload session is no longer active")
			return
		}
	}
	s.emitCompletedUpload(c, session)
}

func (s *server) emitCompletedUpload(c *gin.Context, session uploadSessionView) {
	var artifactToken string
	var err error
	expiresAt := time.Now().UTC().Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second)
	if session.UploadType == "apk" {
		artifactToken, err = s.encodeReleaseArtifactToken(releaseArtifactToken{ID: session.ID, TenantID: tenantID(c), ObjectKey: session.ObjectKey, FileName: session.FileName, ContentType: session.ContentType, Size: session.ExpectedSize, ExpiresAt: expiresAt.Unix()})
	} else {
		artifactToken, err = s.encodeOTAUploadToken(otaUploadToken{ID: session.ID, TenantID: tenantID(c), ObjectKey: session.ObjectKey, FileName: session.FileName, ContentType: session.ContentType, Size: session.ExpectedSize, ExpiresAt: expiresAt.Unix()})
	}
	if err != nil {
		problem(c, 503, "UPLOAD_ARTIFACT_TOKEN_UNAVAILABLE", "Unable to create artifact token")
		return
	}
	c.JSON(200, gin.H{"artifact": gin.H{"id": session.ID, "token": artifactToken, "objectKey": session.ObjectKey, "fileName": session.FileName, "contentType": session.ContentType, "size": session.ExpectedSize, "expiresAt": iso(expiresAt)}})
}

func (s *server) cancelUploadSession(c *gin.Context) {
	session, client, tok, err := s.loadUploadSession(c, uploadSessionTokenFromRequest(c))
	if err != nil {
		problem(c, 401, "INVALID_UPLOAD_SESSION", "Upload session token is invalid or expired")
		return
	}
	if session.Status == "active" {
		_ = client.AbortMultipartUpload(c.Request.Context(), session.ObjectKey, tok.UploadID)
		_, _ = s.db.ExecContext(c.Request.Context(), `UPDATE upload_sessions SET status='aborted',updated_at=? WHERE tenant_id=? AND id=? AND status='active'`, time.Now().UTC(), tenantID(c), session.ID)
	}
	c.JSON(200, gin.H{"cancelled": true})
}

func (s *server) loadUploadSession(c *gin.Context, encoded string) (uploadSessionView, objectstore.Client, uploadSessionToken, error) {
	var zero uploadSessionView
	tok, err := s.decodeUploadSessionToken(tenantID(c), encoded)
	if err != nil {
		return zero, nil, tok, err
	}
	if id := strings.TrimSpace(c.Param("id")); id != "" && id != tok.SessionID {
		return zero, nil, tok, errors.New("upload session does not match request")
	}
	if pathID := strings.TrimSpace(c.Param("id")); pathID != "" && pathID != tok.SessionID {
		return zero, nil, tok, errors.New("upload session token does not match the requested session")
	}
	var session uploadSessionView
	var raw []byte
	var uploadID string
	var expires time.Time
	err = s.db.QueryRowContext(c.Request.Context(), `SELECT id,upload_type,object_key,upload_id,file_name,content_type,expected_size,part_size,total_parts,uploaded_parts,status,expires_at FROM upload_sessions WHERE tenant_id=? AND id=? LIMIT 1`, tenantID(c), tok.SessionID).Scan(&session.ID, &session.UploadType, &session.ObjectKey, &uploadID, &session.FileName, &session.ContentType, &session.ExpectedSize, &session.PartSize, &session.TotalParts, &raw, &session.Status, &expires)
	if err != nil {
		return zero, nil, tok, err
	}
	session.ExpiresAt = expires
	_ = json.Unmarshal(raw, &session.Parts)
	client, _, err := s.storageClientForTenant(c.Request.Context(), tenantID(c))
	if err != nil {
		return zero, nil, tok, err
	}
	tok.UploadID = uploadID
	tok.SessionID = session.ID
	return session, client, tok, nil
}

func (s *server) recordUploadPart(c *gin.Context, id string, number int, etag string, size int64) error {
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT uploaded_parts FROM upload_sessions WHERE tenant_id=? AND id=? AND status='active' FOR UPDATE`, tenantID(c), id).Scan(&raw); err != nil {
		return err
	}
	var parts []uploadPartState
	_ = json.Unmarshal(raw, &parts)
	for _, part := range parts {
		if part.PartNumber == number {
			if part.ETag != etag || part.Size != size {
				return errors.New("part already recorded with different ETag or size")
			}
			return tx.Commit()
		}
	}
	parts = append(parts, uploadPartState{PartNumber: number, ETag: etag, Size: size})
	raw, _ = json.Marshal(parts)
	_, err = tx.ExecContext(c.Request.Context(), `UPDATE upload_sessions SET uploaded_parts=?,updated_at=? WHERE tenant_id=? AND id=?`, raw, time.Now().UTC(), tenantID(c), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) cleanupExpiredUploadSessions(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT id,object_key,upload_id,tenant_id FROM upload_sessions WHERE tenant_id=? AND status='active' AND expires_at<? LIMIT 100`, tenantID(c), time.Now().UTC())
	if err != nil {
		problem(c, 500, "UPLOAD_CLEANUP_FAILED", "Unable to load expired upload sessions")
		return
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, key, uploadID, tenant string
		if rows.Scan(&id, &key, &uploadID, &tenant) != nil {
			continue
		}
		client, _, e := s.storageClientForTenant(c.Request.Context(), tenant)
		if e == nil {
			_ = client.AbortMultipartUpload(c.Request.Context(), key, uploadID)
		}
		_, _ = s.db.ExecContext(c.Request.Context(), `UPDATE upload_sessions SET status='expired',updated_at=? WHERE tenant_id=? AND id=? AND status='active'`, time.Now().UTC(), tenant, id)
		count++
	}
	c.JSON(200, gin.H{"expired": count})
}

func (s *server) partMatches(parts []uploadPartState, candidate uploadPartState) bool {
	for _, part := range parts {
		if part.PartNumber == candidate.PartNumber {
			return part.ETag == candidate.ETag && part.Size == candidate.Size
		}
	}
	return false
}

func (s *server) uploadSessionJSON(v uploadSessionView) gin.H {
	return gin.H{"id": v.ID, "uploadType": v.UploadType, "fileName": v.FileName, "contentType": v.ContentType, "size": v.ExpectedSize, "partSize": v.PartSize, "totalParts": v.TotalParts, "status": v.Status, "expiresAt": iso(v.ExpiresAt), "parts": v.Parts, "uploadedParts": v.Parts}
}
