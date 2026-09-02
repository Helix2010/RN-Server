package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Helix2010/RN-Server/internal/chain"
	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/mod/semver"
)

type server struct {
	cfg      config.Config
	db       *sql.DB
	mu       sync.Mutex
	attempts map[string]attempt
	objects  objectstore.Factory
	tenant   *tenantResolver
	secrets  *secretbox.Box
	// tokens 只从平台默认端点读代币元数据；测试用假实现替换
	tokens tokenMetadataReader
}

type attempt struct {
	Failures int
	ResetsAt time.Time
}

type release struct {
	ID              string              `json:"id"`
	Platform        string              `json:"platform"`
	Version         string              `json:"version"`
	BuildNumber     int                 `json:"buildNumber"`
	RuntimeVersion  string              `json:"runtimeVersion"`
	Status          string              `json:"status"`
	ReleaseNotes    map[string][]string `json:"releaseNotes"`
	FileName        *string             `json:"fileName"`
	ContentType     *string             `json:"contentType"`
	ExpectedSize    *int64              `json:"expectedSize"`
	FileSize        *int64              `json:"fileSize"`
	SHA256          *string             `json:"sha256"`
	FileMetadata    map[string]any      `json:"fileMetadata"`
	RejectionReason *string             `json:"rejectionReason"`
	// Mandatory 表示这一版上线后用户不可跳过
	Mandatory   bool    `json:"mandatory"`
	VerifiedAt  *string `json:"verifiedAt"`
	PublishedAt *string `json:"publishedAt"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
	LastAction  *string `json:"lastAction"`
}

type simplifiedActiveRelease struct {
	ID           string
	Version      string
	ReleaseNotes map[string][]string
	SHA256       *string
	FileSize     *int64
	// Mandatory 表示这个版本不可跳过
	Mandatory bool
}

type auditEvent struct {
	ID         string         `json:"id"`
	ActorID    string         `json:"actorId"`
	Action     string         `json:"action"`
	TargetType string         `json:"targetType"`
	TargetID   string         `json:"targetId"`
	Reason     string         `json:"reason"`
	RequestID  string         `json:"requestId"`
	CreatedAt  string         `json:"createdAt"`
	Summary    map[string]any `json:"summary"`
	TenantID   string         `json:"tenantId"`
}

func New(cfg config.Config, storage *store.Store) http.Handler {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	box, _ := secretbox.New(cfg.StorageMasterKey)
	s := &server{cfg: cfg, db: storage.DB, attempts: map[string]attempt{}, objects: objectstore.AWSFactory{}, tenant: newTenantResolver(storage.DB), secrets: box, tokens: chain.NewReader(nil)}
	r := gin.New()
	r.Use(gin.Recovery(), s.requestContext(), s.databaseTimeout(), s.securityHeaders(), s.cors())
	r.GET("/health/live", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "live"}) })
	r.GET("/health/ready", s.ready)
	r.GET("/openapi.json", func(c *gin.Context) { c.File("contracts/openapi.json") })
	r.GET("/docs", s.docs)
	r.GET("/v1/mobile/bootstrap", s.bootstrap)
	r.POST("/v1/mobile/installations/heartbeat", s.domainTenantScope(), s.installationHeartbeat)
	r.POST("/v1/mobile/installations/register", s.domainTenantScope(), s.registerInstallation)
	r.POST("/v1/mobile/push-tokens", s.domainTenantScope(), s.registerPushToken)
	r.POST("/v1/mobile/auth/nonce", s.domainTenantScope(), s.walletAuthNonce)
	r.POST("/v1/mobile/auth/verify", s.domainTenantScope(), s.walletAuthVerify)
	r.GET("/v1/mobile/auth/session", s.domainTenantScope(), s.walletAuthSession)
	r.POST("/v1/mobile/auth/logout", s.domainTenantScope(), s.walletAuthLogout)
	r.GET("/v1/mobile/languages/:languageCode/document", s.mobileLanguageDocument)
	r.GET("/v1/mobile/branding/assets/:id", s.domainTenantScope(), s.brandingAsset)
	r.GET("/v1/ota/manifest", s.domainTenantScope(), s.otaManifest)
	r.GET("/v1/ota/assets/:id/*path", s.domainTenantScope(), s.otaAsset)
	r.GET("/v1/public/releases/latest", s.domainTenantScope(), s.publicLatestReleaseFromDomain)
	r.GET("/v1/public/releases/:id/download", s.domainTenantScope(), s.publicReleaseDownload)
	admin := r.Group("/v1/admin")
	admin.POST("/auth/login", s.login)
	protected := admin.Group("")
	protected.Use(s.authenticate())
	protected.GET("/auth/session", s.session)
	protected.POST("/auth/logout", s.logout)
	current := protected.Group("")
	current.Use(s.domainTenantScope())
	current.GET("/tenant", s.currentTenant)
	s.registerTenantRoutes(current)
	return r
}

func (s *server) currentTenant(c *gin.Context) {
	item, ok := c.Get("tenant")
	if !ok {
		problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
		return
	}
	c.JSON(200, gin.H{"tenant": item})
}

func (s *server) registerTenantRoutes(group *gin.RouterGroup) {
	group.GET("/overview", s.overview)
	group.GET("/installations/overview", s.installationOverview)
	group.GET("/installations", s.listInstallations)
	group.POST("/installations/:id/revoke", s.revokeInstallation)
	group.GET("/push/outbox", s.listPushOutbox)
	group.GET("/push/deliveries", s.listPushDeliveries)
	group.GET("/releases", s.listReleases)
	group.POST("/releases", s.createReleaseFromArtifact)
	group.GET("/releases/:id", s.releaseDetail)
	group.POST("/releases/:id/:action", s.releaseAction)
	group.GET("/audit-events", s.listAudits)
	group.GET("/app-config", s.getAppConfig)
	group.PATCH("/app-config", s.updateAppConfig)
	group.GET("/branding", s.getBranding)
	group.PATCH("/branding", s.updateBranding)
	group.GET("/tokens", s.listTokens)
	group.POST("/tokens/preview", s.previewToken)
	group.POST("/tokens", s.createToken)
	group.PATCH("/tokens/:id", s.patchToken)
	group.POST("/tokens/:id/resync", s.resyncToken)
	group.DELETE("/tokens/:id", s.deleteToken)
	group.GET("/localization", s.getLocalization)
	group.PUT("/localization/languages", s.updateLocalizationLanguages)
	group.PUT("/localization/documents", s.updateLocalizationDocuments)
	group.POST("/localization/publish", s.publishLocalization)
	group.GET("/release-storage", s.getReleaseStorage)
	group.PUT("/release-storage", s.updateReleaseStorage)
	group.POST("/release-storage/test", s.testReleaseStorage)
	group.POST("/release-artifacts/uploads", s.createReleaseArtifactUpload)
	group.PUT("/release-artifacts/upload", s.uploadReleaseArtifact)
	group.DELETE("/release-artifacts/upload", s.deleteReleaseArtifact)
	group.GET("/ota/base-releases", s.listOTABaseReleases)
	group.GET("/ota/releases", s.listOTAReleases)
	group.GET("/ota/releases/:id", s.otaReleaseDetail)
	group.POST("/ota/artifacts/uploads", s.createOTAUploader)
	group.PUT("/ota/artifacts/upload", s.uploadOTAArtifact)
	group.DELETE("/ota/artifacts/upload", s.deleteOTAArtifact)
	group.POST("/ota/releases", s.saveOTARelease)
	group.POST("/ota/releases/:id/:action", s.otaAction)
	group.POST("/upload-sessions", s.createUploadSession)
	group.POST("/upload-sessions/cleanup-expired", s.cleanupExpiredUploadSessions)
	group.GET("/upload-sessions/:id", s.getUploadSession)
	group.PUT("/upload-sessions/:id/parts/:partNumber", s.uploadSessionPart)
	group.POST("/upload-sessions/:id/parts/:partNumber/presign", s.presignUploadSessionPart)
	group.POST("/upload-sessions/:id/complete", s.completeUploadSession)
	group.DELETE("/upload-sessions/:id", s.cancelUploadSession)
	group.POST("/branding/assets/uploads", s.createBrandingAssetUpload)
	group.PUT("/branding/assets/upload", s.uploadBrandingAsset)
	group.DELETE("/branding/assets/upload", s.deleteBrandingAsset)
}

func (s *server) domainTenantScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		item, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
		if err != nil {
			problem(c, 404, "TENANT_DOMAIN_NOT_FOUND", "Request domain is not mapped to an active tenant")
			c.Abort()
			return
		}
		c.Set("tenantId", item.ID)
		c.Set("tenant", item)
		c.Next()
	}
}

func (s *server) databaseTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		multipartPartUpload := c.Request.Method == http.MethodPut && strings.Contains(c.Request.URL.Path, "/v1/admin/upload-sessions/") && strings.Contains(c.Request.URL.Path, "/parts/")
		if strings.HasSuffix(c.Request.URL.Path, "/upload") || multipartPartUpload || strings.HasSuffix(c.Request.URL.Path, "/finalize") || strings.HasSuffix(c.Request.URL.Path, "/release-storage/test") || strings.HasSuffix(c.Request.URL.Path, "/download") || readsTokenChain(c.Request) {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.MySQLQueryTimeout)*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// readsTokenChain 识别要去链上读元数据的三个代币接口。它们跟 /release-storage/test
// 一样要等外部系统：最多五次 RPC、每次 5 秒，套在数据库超时里会被误杀。
func readsTokenChain(r *http.Request) bool {
	path := r.URL.Path
	return strings.HasSuffix(path, "/tokens/preview") ||
		(r.Method == http.MethodPost && strings.HasSuffix(path, "/tokens")) ||
		strings.HasSuffix(path, "/resync")
}

func (s *server) requestContext() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := strings.TrimSpace(c.GetHeader("x-request-id"))
		if requestID == "" {
			requestID = "req_" + randomID(12)
		}
		c.Set("requestId", requestID)
		c.Header("x-request-id", requestID)
		c.Next()
	}
}

func (s *server) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("Referrer-Policy", "no-referrer")
		c.Next()
	}
}

func (s *server) cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" && s.originAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Expose-Headers", "ETag,X-Request-Id")
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "content-type,x-admin-key,x-admin-id,x-request-id,x-release-artifact-token,x-ota-artifact-token,x-branding-asset-token,x-upload-session-token,x-part-sha256,expo-platform,expo-runtime-version,expo-channel-name,expo-protocol-version,expo-expect-signature")
		}
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.CORSOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (s *server) ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		problem(c, 503, "NOT_READY", "Database is unavailable")
		return
	}
	c.JSON(200, gin.H{"status": "ready", "database": "mysql"})
}

func (s *server) docs(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(200, `<!doctype html><html><head><title>RN Foundation API</title></head><body><h1>RN Foundation API</h1><p><a href="/openapi.json">OpenAPI contract</a></p></body></html>`)
}

func (s *server) authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if cookie, err := c.Cookie("rn_admin_session"); err == nil && cookie != "" {
			hash := sha256Hex(cookie)
			var actor string
			var expires time.Time
			err := s.db.QueryRowContext(c.Request.Context(), `SELECT actor_id, expires_at FROM admin_sessions WHERE token_hash=? AND expires_at>? LIMIT 1`, hash, time.Now().UTC()).Scan(&actor, &expires)
			if err == nil {
				if !safeMethod(c.Request.Method) && !s.originAllowed(c.GetHeader("Origin")) {
					problem(c, 403, "UNTRUSTED_ORIGIN", "Untrusted admin request origin")
					c.Abort()
					return
				}
				c.Set("actorId", actor)
				c.Set("authMethod", "session")
				c.Set("expiresAt", iso(expires))
				c.Next()
				return
			}
		}
		key, actor := c.GetHeader("x-admin-key"), strings.TrimSpace(c.GetHeader("x-admin-id"))
		if s.cfg.AdminAPIKey != "" && actor != "" && constantEqual(key, s.cfg.AdminAPIKey) {
			c.Set("actorId", actor)
			c.Set("authMethod", "api-key")
			c.Set("expiresAt", nil)
			c.Next()
			return
		}
		problem(c, 401, "ADMIN_AUTH_REQUIRED", "Admin authentication required")
		c.Abort()
	}
}

func (s *server) login(c *gin.Context) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(c, &input); err != nil || input.Username == "" || input.Password == "" || len(input.Password) > 1024 {
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	if s.rateLimited(c.ClientIP()) {
		problem(c, 429, "LOGIN_RATE_LIMITED", "Too many login attempts")
		return
	}
	valid := constantEqual(strings.TrimSpace(input.Username), s.cfg.AdminUsername) && verifyPassword(input.Password, s.cfg.AdminPasswordHash)
	if !valid {
		s.failedLogin(c.ClientIP())
		problem(c, 401, "INVALID_CREDENTIALS", "Invalid username or password")
		return
	}
	s.mu.Lock()
	delete(s.attempts, c.ClientIP())
	s.mu.Unlock()
	token := randomID(32)
	now := time.Now().UTC()
	expires := now.Add(time.Duration(s.cfg.AdminSessionTTL) * time.Second)
	if _, err := s.db.ExecContext(c.Request.Context(), `INSERT INTO admin_sessions (token_hash,actor_id,expires_at,created_at) VALUES (?,?,?,?)`, sha256Hex(token), s.cfg.AdminUsername, expires, now); err != nil {
		problem(c, 500, "SESSION_CREATE_FAILED", "Unable to create admin session")
		return
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "rn_admin_session", Value: token, Path: "/v1/admin", MaxAge: s.cfg.AdminSessionTTL, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"authenticated": true, "actorId": s.cfg.AdminUsername, "expiresAt": iso(expires), "method": "session"})
}

func (s *server) session(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"authenticated": true, "actorId": actor(c), "expiresAt": valueFrom(c, "expiresAt"), "method": valueFrom(c, "authMethod")})
}

func (s *server) logout(c *gin.Context) {
	if token, err := c.Cookie("rn_admin_session"); err == nil {
		_, _ = s.db.ExecContext(c.Request.Context(), `DELETE FROM admin_sessions WHERE token_hash=?`, sha256Hex(token))
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: "rn_admin_session", Value: "", Path: "/v1/admin", MaxAge: -1, HttpOnly: true, Secure: s.cfg.AdminCookieSecure, SameSite: http.SameSiteStrictMode})
	c.JSON(200, gin.H{"authenticated": false})
}

func (s *server) rateLimited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[ip]
	if !ok || time.Now().After(a.ResetsAt) {
		delete(s.attempts, ip)
		return false
	}
	return a.Failures >= s.cfg.AdminLoginMax
}
func (s *server) failedLogin(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[ip]
	if time.Now().After(a.ResetsAt) {
		a = attempt{ResetsAt: time.Now().Add(time.Duration(s.cfg.AdminLoginWindow) * time.Second)}
	}
	a.Failures++
	s.attempts[ip] = a
}

func (s *server) listReleases(c *gin.Context) {
	releases, err := s.queryReleases(c.Request.Context(), tenantID(c), c.Query("platform"), c.Query("status"))
	if err != nil {
		problem(c, 500, "RELEASE_QUERY_FAILED", "Unable to load releases")
		return
	}
	c.JSON(200, gin.H{"items": releases, "nextCursor": nil, "hasMore": false})
}

func (s *server) queryReleases(ctx context.Context, tenant, platform, status string) ([]release, error) {
	query := `SELECT id,platform,version,build_number,runtime_version,status,release_notes,file_name,content_type,expected_size,file_size,sha256,file_metadata,rejection_reason,mandatory,verified_at,published_at,last_action,created_at,updated_at FROM app_releases WHERE tenant_id=? AND (?='' OR platform=?) AND (?='' OR status=?) ORDER BY build_number DESC, updated_at DESC, id DESC`
	rows, err := s.db.QueryContext(ctx, query, tenant, platform, platform, status, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []release{}
	for rows.Next() {
		item, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

type scanner interface{ Scan(...any) error }

func scanRelease(row scanner) (release, error) {
	var r release
	var notes, metadata []byte
	var fileName, contentType, sha, rejection sql.NullString
	var expectedSize, fileSize sql.NullInt64
	var verifiedAt, publishedAt sql.NullTime
	var action sql.NullString
	var created, updated time.Time
	err := row.Scan(&r.ID, &r.Platform, &r.Version, &r.BuildNumber, &r.RuntimeVersion, &r.Status, &notes, &fileName, &contentType, &expectedSize, &fileSize, &sha, &metadata, &rejection, &r.Mandatory, &verifiedAt, &publishedAt, &action, &created, &updated)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal(notes, &r.ReleaseNotes)
	_ = json.Unmarshal(metadata, &r.FileMetadata)
	if fileName.Valid {
		r.FileName = &fileName.String
	}
	if contentType.Valid {
		r.ContentType = &contentType.String
	}
	if expectedSize.Valid {
		r.ExpectedSize = &expectedSize.Int64
	}
	if fileSize.Valid {
		r.FileSize = &fileSize.Int64
	}
	if sha.Valid {
		r.SHA256 = &sha.String
	}
	if rejection.Valid {
		r.RejectionReason = &rejection.String
	}
	r.CreatedAt = iso(created)
	r.UpdatedAt = iso(updated)
	if verifiedAt.Valid {
		v := iso(verifiedAt.Time)
		r.VerifiedAt = &v
	}
	if publishedAt.Valid {
		v := iso(publishedAt.Time)
		r.PublishedAt = &v
	}
	if action.Valid {
		r.LastAction = &action.String
	}
	return r, nil
}

func (s *server) releaseDetail(c *gin.Context) {
	r, err := s.findRelease(c.Request.Context(), tenantID(c), c.Param("id"))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "RELEASE_NOT_FOUND", "Release not found")
		return
	}
	if err != nil {
		problem(c, 500, "RELEASE_QUERY_FAILED", "Unable to load release")
		return
	}
	audits, _ := s.queryAudits(c.Request.Context(), tenantID(c), r.ID)
	c.JSON(200, gin.H{"release": r, "audits": audits})
}

func (s *server) findRelease(ctx context.Context, tenant, id string) (release, error) {
	return scanRelease(s.db.QueryRowContext(ctx, `SELECT id,platform,version,build_number,runtime_version,status,release_notes,file_name,content_type,expected_size,file_size,sha256,file_metadata,rejection_reason,mandatory,verified_at,published_at,last_action,created_at,updated_at FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id))
}

var transitions = map[string]map[string]string{"publish": {"verified": "active", "paused": "active"}, "pause": {"active": "paused"}}

func (s *server) releaseAction(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return
	}
	r, err := s.findRelease(c.Request.Context(), tenantID(c), c.Param("id"))
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Release not found")
		return
	}
	target, ok := transitions[c.Param("action")][r.Status]
	if !ok {
		problem(c, 409, "INVALID_TRANSITION", fmt.Sprintf("Cannot apply %s to %s", c.Param("action"), r.Status))
		return
	}
	if target == "active" {
		var verified bool
		_ = s.db.QueryRowContext(c.Request.Context(), `SELECT object_key IS NOT NULL AND sha256 IS NOT NULL AND verified_at IS NOT NULL FROM app_releases WHERE tenant_id=? AND id=?`, tenantID(c), r.ID).Scan(&verified)
		if !verified {
			problem(c, 409, "VERIFIED_ARTIFACT_REQUIRED", "The bound APK artifact is no longer publishable")
			return
		}
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	defer tx.Rollback()
	if target == "active" {
		_, _ = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status='completed',last_action='completed',updated_at=? WHERE tenant_id=? AND id<>? AND platform=? AND status='active'`, now, tenantID(c), r.ID, r.Platform)
	}
	_, err = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status=?,last_action=?,updated_at=?,published_at=CASE WHEN ?='active' THEN ? ELSE published_at END WHERE tenant_id=? AND id=?`, target, target, now, target, now, tenantID(c), r.ID)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	event := newAudit(tenantID(c), actor(c), c.Param("action"), "release", r.ID, body.Reason, requestID(c), map[string]any{"version": r.Version, "platform": r.Platform, "status": target})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	if target == "active" {
		if err := enqueuePushEvent(c.Request.Context(), tx, tenantID(c), "app_update_available", map[string]any{"releaseId": r.ID, "platform": r.Platform, "version": r.Version, "buildNumber": r.BuildNumber}); err != nil {
			problem(c, 500, "TRANSITION_FAILED", "Unable to enqueue update notification")
			return
		}
	}
	if tx.Commit() != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	r.Status = target
	r.UpdatedAt = iso(now)
	r.LastAction = &target
	if target == "active" {
		v := iso(now)
		r.PublishedAt = &v
	}
	c.JSON(201, gin.H{"release": r})
}

func (s *server) overview(c *gin.Context) {
	items, err := s.queryReleases(c.Request.Context(), tenantID(c), "", "")
	if err != nil {
		problem(c, 500, "OVERVIEW_FAILED", "Unable to load overview")
		return
	}
	counts := map[string]int{"uploaded": 0, "verified": 0, "active": 0, "paused": 0, "completed": 0, "rejected": 0, "rolled_back": 0}
	current := map[string]any{"android": nil, "ios": nil, "harmony": nil}
	for _, r := range items {
		counts[r.Status]++
		if r.Status == "active" {
			if current[r.Platform] == nil {
				current[r.Platform] = r
			}
		}
	}
	c.JSON(200, gin.H{"generatedAt": iso(time.Now()), "current": current, "counts": counts, "signals": gin.H{"crashFreeSessions": nil, "updateSuccessRate": nil, "note": "Connect telemetry provider before production SLO decisions"}})
}

func (s *server) listAudits(c *gin.Context) {
	items, err := s.queryAudits(c.Request.Context(), tenantID(c), "")
	if err != nil {
		problem(c, 500, "AUDIT_QUERY_FAILED", "Unable to load audit events")
		return
	}
	c.JSON(200, gin.H{"items": items, "nextCursor": nil, "hasMore": false})
}
func (s *server) queryAudits(ctx context.Context, tenant, target string) ([]auditEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at FROM audit_events WHERE tenant_id=? AND (?='' OR target_id=?) ORDER BY created_at DESC LIMIT 1000`, tenant, target, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []auditEvent{}
	for rows.Next() {
		var a auditEvent
		var summary []byte
		var created time.Time
		if err := rows.Scan(&a.ID, &a.ActorID, &a.Action, &a.TargetType, &a.TargetID, &a.Reason, &a.RequestID, &summary, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(summary, &a.Summary)
		a.TenantID = tenant
		a.CreatedAt = iso(created)
		items = append(items, a)
	}
	return items, rows.Err()
}

func (s *server) getAppConfig(c *gin.Context) {
	view, err := s.appConfigView(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, 500, "CONFIG_QUERY_FAILED", "Unable to load app config")
		return
	}
	c.JSON(200, view)
}
func (s *server) appConfigView(ctx context.Context, tenant string) (gin.H, error) {
	var raw []byte
	var version int
	var sourceTenant string
	var updatedBy string
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`, tenant, tenant).Scan(&sourceTenant, &raw, &version, &updatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		raw = []byte(initialConfig)
		now := time.Now().UTC()
		_, err = s.db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,'mobile-bootstrap',?,1,'system-bootstrap',?)`, raw, now)
		if err != nil {
			return nil, err
		}
		version = 1
		sourceTenant = "0"
		updatedBy = "system-bootstrap"
		updated = now
	} else if err != nil {
		return nil, err
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	value["modules"] = normalizeModules(object(value["modules"]))
	value["wallet"] = normalizeWallet(object(value["wallet"]))
	return gin.H{"summary": configSummary(value), "config": value, "metadata": gin.H{"databaseVersion": version, "updatedBy": updatedBy, "updatedAt": iso(updated), "inherited": sourceTenant == "0", "walletCatalog": walletCatalog()}}, nil
}
func (s *server) updateAppConfig(c *gin.Context) {
	var body struct {
		Reason          string         `json:"reason"`
		Confirm         bool           `json:"confirm"`
		ExpectedVersion int            `json:"expectedVersion"`
		Config          map[string]any `json:"config"`
	}
	if decode(c, &body) != nil || !body.Confirm || body.ExpectedVersion < 1 || len(strings.TrimSpace(body.Reason)) < 3 || !validConfig(body.Config) {
		problem(c, 400, "INVALID_APP_CONFIG", "config, expectedVersion, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	defer tx.Rollback()
	var stored []byte
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT config_value FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1 FOR UPDATE`, tenantID(c), tenantID(c)).Scan(&stored); err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	if incoming, present := body.Config["wallet"]; present && incoming != nil {
		if err := validateWalletSection(incoming); err != nil {
			problem(c, 400, "INVALID_WALLET_CONFIG", err.Error())
			return
		}
	} else if carried := storedWalletSection(stored); carried != nil {
		// 客户端不带 wallet 段时保留库里已有的：否则一次改颜色就会把租户的
		// projectId 和链端点顺手清空。沿用的值不再校验——它已经在库里，
		// 读路径会把不合法的部分归一化掉
		body.Config["wallet"] = carried
	}
	raw, _ := json.Marshal(body.Config)
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key='mobile-bootstrap' AND version=?`, raw, actor(c), now, tenantID(c), body.ExpectedVersion)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	affected, _ := result.RowsAffected()
	newVersion := body.ExpectedVersion + 1
	if affected == 0 {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
			SELECT ?, 'mobile-bootstrap', ?, 1, ?, ? FROM app_configs global_config
			WHERE global_config.tenant_id=0 AND global_config.config_key='mobile-bootstrap' AND global_config.version=?
			AND NOT EXISTS (SELECT 1 FROM app_configs tenant_config WHERE tenant_config.tenant_id=? AND tenant_config.config_key='mobile-bootstrap')`, tenantID(c), raw, actor(c), now, body.ExpectedVersion, tenantID(c))
		if err == nil {
			affected, _ = result.RowsAffected()
			newVersion = 1
		}
	}
	if affected != 1 {
		problem(c, 409, "STALE_APP_CONFIG", "App config changed since it was loaded; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "config_update", "app-config", "mobile-bootstrap", body.Reason, requestID(c), map[string]any{"status": "active", "databaseVersionBefore": body.ExpectedVersion, "databaseVersionAfter": newVersion, "configVersion": body.Config["configVersion"]})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config audit")
		return
	}
	if err := enqueuePushEvent(c.Request.Context(), tx, tenantID(c), "bootstrap_updated", map[string]any{"configVersion": body.Config["configVersion"]}); err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to enqueue config notification")
		return
	}
	if tx.Commit() != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	view, _ := s.appConfigView(c.Request.Context(), tenantID(c))
	view["status"] = "active"
	view["savedAt"] = iso(now)
	view["actorId"] = actor(c)
	view["requestId"] = requestID(c)
	c.JSON(200, view)
}

// supportedNetworks is the EVM chain catalog this platform can talk to. The
// EIP-155 id and the default endpoints live here so a tenant only overrides
// what it actually wants to change.
//
// RPC endpoints are delivered to every client, so they are public by
// definition: use endpoints that are safe to expose (domain-restricted or
// rate-limited keys), or proxy RPC through this server. Never put a bearer
// secret in an rpcUrl.
type evmNetwork struct {
	ID          string
	Name        string
	ChainID     int
	RPCUrls     []any
	ExplorerURL string
	// Testnet 上的币没有价值。混进主网列表里，运营会误开给生产租户、用户会
	// 把它当成真链，所以这个标记要一路传到管理端和 App 的界面上。
	Testnet bool
	// NativeSymbol / NativeDecimals 描述原生币。原生币没有合约、读不了链，
	// 它的符号与精度只能来自这里；管理端也靠这两项显示原生币行。
	NativeSymbol   string
	NativeDecimals int
}

var supportedNetworks = []evmNetwork{
	{"bsc", "BNB Smart Chain", 56, []any{"https://bsc-dataseed.bnbchain.org"}, "https://bscscan.com", false, "BNB", 18},
	{"eth", "Ethereum", 1, []any{"https://ethereum-rpc.publicnode.com"}, "https://etherscan.io", false, "ETH", 18},
	{"base", "Base", 8453, []any{"https://mainnet.base.org"}, "https://basescan.org", false, "ETH", 18},
	{"op-sepolia", "OP Sepolia", 11155420, []any{"https://sepolia.optimism.io"}, "https://sepolia-optimism.etherscan.io", true, "ETH", 18},
}

// walletCatalog tells the admin console which chains this platform can talk to
// and what the platform defaults are. Without it the console would have to keep
// its own copy of the chain list, which is exactly how the two lists drift.
func walletCatalog() []any {
	items := []any{}
	for _, network := range supportedNetworks {
		items = append(items, map[string]any{
			"id":                 network.ID,
			"name":               network.Name,
			"chainId":            network.ChainID,
			"defaultRpcUrls":     network.RPCUrls,
			"defaultExplorerUrl": network.ExplorerURL,
			"testnet":            network.Testnet,
			"nativeSymbol":       network.NativeSymbol,
			"nativeDecimals":     network.NativeDecimals,
		})
	}
	return items
}

// supportedNetworkIDs 拼出报错里要展示的链清单。硬编码成 "bsc / eth / base"
// 的话，每加一条链就会多一处对不上的文案。
func supportedNetworkIDs() string {
	ids := make([]string, 0, len(supportedNetworks))
	for _, network := range supportedNetworks {
		ids = append(ids, network.ID)
	}
	return strings.Join(ids, " / ")
}

func supportedNetwork(id string) (int, bool) {
	network, ok := platformNetwork(id)
	return network.ChainID, ok
}

func platformNetwork(id string) (evmNetwork, bool) {
	for _, network := range supportedNetworks {
		if network.ID == id {
			return network, true
		}
	}
	return evmNetwork{}, false
}

// walletProjectIDPattern matches a WalletConnect / Reown project id: a hex
// client identifier, not a secret. Validated loosely on purpose — the point is
// to catch a pasted URL or a copied-with-quotes value, not to guess the vendor's
// future id format.
var walletProjectIDPattern = regexp.MustCompile(`^[0-9a-zA-Z]{16,64}$`)

// validateWalletSection rejects a wallet section the admin console should never
// have sent. Everything the bootstrap path later reads is validated here, on the
// write path: an operator who pastes an http:// endpoint must be told, not have
// it quietly dropped and wonder why nothing changed. The read path never repairs
// stored data — see normalizeWallet and the 503 in the bootstrap handler.
func validateWalletSection(raw any) error {
	section, ok := raw.(map[string]any)
	if !ok {
		return errors.New("wallet 必须是一个对象")
	}
	for key := range section {
		if !oneOf(key, "walletConnectProjectId", "chains", "networks", "onchainSends") {
			return fmt.Errorf("wallet.%s 不是可配置项", key)
		}
	}
	if value, present := section["onchainSends"]; present {
		if _, ok := value.(bool); !ok {
			return errors.New("onchainSends 必须是布尔值")
		}
	}
	if value, present := section["walletConnectProjectId"]; present {
		projectID, ok := value.(string)
		if !ok {
			return errors.New("walletConnectProjectId 必须是字符串")
		}
		trimmed := strings.TrimSpace(projectID)
		if trimmed != "" && !walletProjectIDPattern.MatchString(trimmed) {
			return errors.New("walletConnectProjectId 格式不对：应为 cloud.reown.com 上的 Project ID（16-64 位字母数字），不要填入完整链接")
		}
	}
	if value, present := section["chains"]; present {
		chains, ok := value.([]any)
		if !ok {
			return errors.New("chains 必须是数组")
		}
		if len(chains) == 0 {
			return errors.New("至少要启用一条链，否则 App 里的钱包无链可用")
		}
		for _, item := range chains {
			id, ok := item.(string)
			if !ok {
				return errors.New("chains 只能包含链 id 字符串")
			}
			if _, supported := supportedNetwork(id); !supported {
				return fmt.Errorf("不支持的链 %q：当前平台支持 %s", id, supportedNetworkIDs())
			}
		}
	}
	if value, present := section["networks"]; present {
		networks, ok := value.([]any)
		if !ok {
			return errors.New("networks 必须是数组")
		}
		for _, item := range networks {
			network := object(item)
			if network == nil {
				return errors.New("networks 的每一项都必须是对象")
			}
			id, ok := network["id"].(string)
			if !ok {
				return errors.New("networks 的每一项都要有 id")
			}
			chainID, supported := supportedNetwork(id)
			if !supported {
				return fmt.Errorf("不支持的链 %q：当前平台支持 %s", id, supportedNetworkIDs())
			}
			// chainId 由平台目录决定：填错会让签名打到另一条链上
			if raw, present := network["chainId"]; present {
				value, ok := raw.(float64)
				if !ok || int(value) != chainID {
					return fmt.Errorf("%s 的 chainId 固定为 %d，不可修改", id, chainID)
				}
			}
			if raw, present := network["rpcUrls"]; present {
				urls, ok := raw.([]any)
				if !ok {
					return fmt.Errorf("%s 的 rpcUrls 必须是数组", id)
				}
				if len(urls) > maxEndpointsPerChain {
					return fmt.Errorf("%s 最多配置 %d 个 RPC 端点", id, maxEndpointsPerChain)
				}
				for _, entry := range urls {
					endpoint, ok := entry.(string)
					if !ok || !isHTTPSURL(endpoint) {
						return fmt.Errorf("%s 的 RPC 端点必须是 https:// 开头、不含账号密码和空格的完整地址：明文 RPC 会泄露用户查询的每个地址和余额，而 bootstrap 对所有客户端公开", id)
					}
				}
			}
			if raw, present := network["explorerUrl"]; present {
				explorer, ok := raw.(string)
				if !ok || (strings.TrimSpace(explorer) != "" && !isHTTPSURL(explorer)) {
					return fmt.Errorf("%s 的区块浏览器地址必须是 https:// 开头的完整地址", id)
				}
			}
		}
	}
	return nil
}

// storedWalletSection reads the wallet section already in the database, so a
// config that arrives without one carries it over instead of erasing it. Any
// client that round-trips the config through a schema that does not know about
// `wallet` would otherwise wipe the tenant's project id and endpoints as a side
// effect of an unrelated edit.
func storedWalletSection(stored []byte) any {
	var current map[string]any
	if len(stored) == 0 || json.Unmarshal(stored, &current) != nil {
		return nil
	}
	return current["wallet"]
}

// normalizeWallet fills in the wallet section a client needs at startup:
// the WalletConnect project id (a client identifier, not a secret) and the
// per-chain endpoints. Both are tenant configuration rather than build
// parameters, so changing them never requires a new app build.
func normalizeWallet(raw map[string]any) map[string]any {
	enabled := map[string]bool{}
	overrides := map[string]map[string]any{}
	projectID := ""
	// onchainSends 是"转出是否真的上链"的租户级开关，默认关。
	// 不能用"有没有 RPC 端点"当开关：没配过端点的租户也会拿到平台默认端点，
	// 那样新版本一发布，所有租户的主网转出就同时变成真钱。
	onchainSends := false
	if raw != nil {
		if value, ok := raw["onchainSends"].(bool); ok {
			onchainSends = value
		}
		if value, ok := raw["walletConnectProjectId"].(string); ok {
			projectID = strings.TrimSpace(value)
		}
		if chains, ok := raw["chains"].([]any); ok {
			for _, item := range chains {
				if name, ok := item.(string); ok {
					enabled[name] = true
				}
			}
		}
		if networks, ok := raw["networks"].([]any); ok {
			for _, item := range networks {
				network := object(item)
				if network == nil {
					continue
				}
				if id, ok := network["id"].(string); ok {
					overrides[id] = network
					// networks 里出现即视为启用，省得两处都要配
					if _, listed := raw["chains"]; !listed {
						enabled[id] = true
					}
				}
			}
		}
	}
	// 声明式默认：租户还没配过钱包段时启用全部**主网**——管理端钱包页显示的就是这个
	// 结果。测试链必须由运营显式勾选，否则新增一条测试链就会自动出现在所有租户里。
	// 租户配了链却没有一条在目录里（目录下线了一条链），下发的就是空列表：这是
	// 需要迁移租户配置的事故，不在运行时替它换成别的链。
	if len(enabled) == 0 {
		for _, network := range supportedNetworks {
			if network.Testnet {
				continue
			}
			enabled[network.ID] = true
		}
	}

	chains := []any{}
	networks := []any{}
	for _, network := range supportedNetworks {
		if !enabled[network.ID] {
			continue
		}
		entry := map[string]any{
			"id":          network.ID,
			"chainId":     network.ChainID,
			"rpcUrls":     network.RPCUrls,
			"explorerUrl": network.ExplorerURL,
			"testnet":     network.Testnet,
		}
		if override := overrides[network.ID]; override != nil {
			if urls := httpsList(override["rpcUrls"]); len(urls) > 0 {
				entry["rpcUrls"] = urls
			}
			if explorer, ok := override["explorerUrl"].(string); ok && isHTTPSURL(explorer) {
				entry["explorerUrl"] = strings.TrimRight(strings.TrimSpace(explorer), "/")
			}
		}
		chains = append(chains, network.ID)
		networks = append(networks, entry)
	}
	return map[string]any{
		"walletConnectProjectId": projectID,
		// chains 保留为启用链的 id 列表：老客户端只认它，别为了整洁把它删掉
		"chains":       chains,
		"networks":     networks,
		"onchainSends": onchainSends,
	}
}

// maxEndpointLength caps a single RPC / explorer URL; anything longer is not
// a URL an operator typed, it is a mistake or an attack on the bootstrap size.
const maxEndpointLength = 512

// maxEndpointsPerChain caps the fallback list; a client tries them in order and
// nobody benefits from a fiftieth fallback.
const maxEndpointsPerChain = 8

// isHTTPSURL is the single definition of "an endpoint we will deliver".
//
// A prefix check is not enough: the app validates with a real URL parser, so
// anything this accepts that the parser rejects makes the whole bootstrap fail
// to parse on every device of that tenant. Credentials in the URL are refused
// outright — bootstrap is public to every client.
func isHTTPSURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > maxEndpointLength {
		return false
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Hostname() != ""
}

// httpsList keeps only https endpoints; a cleartext RPC would leak every
// address and balance the app looks up. Duplicates collapse to one: the client
// tries endpoints in order and a repeated entry is just a wasted retry.
func httpsList(raw any) []any {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	urls := []any{}
	seen := map[string]bool{}
	for _, item := range items {
		value, ok := item.(string)
		if !ok || !isHTTPSURL(value) {
			continue
		}
		trimmed := strings.TrimSpace(value)
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		urls = append(urls, trimmed)
		if len(urls) >= maxEndpointsPerChain {
			break
		}
	}
	return urls
}

type updateDecisionInput struct {
	// Current 是客户端上报的版本（x-app-version）
	Current string
	// Minimum 来自租户配置 updatePolicy.minSupportedVersion
	Minimum string
	Latest  string
	// Distribution 是分发渠道：store / direct / mdm / development
	Distribution string
	// ActionURL 空表示这个渠道拿不到安装入口
	ActionURL string
	// MandatoryVersion 是 active 发布声明"必须升级"时的版本号，空表示没声明
	MandatoryVersion string
}

// resolveUpdateDecision 决定客户端看到 none / recommended / required。
//
// 强制升级有两个来源：租户配置里的最低支持版本，以及 active 发布记录自己的
// mandatory 标记。后者等效于"把最低版本提到这一版"，但**只升不降**——把老版本
// 标成强制再激活，不该让所有人被要求"升级"到更老的包。两者都仍然走 semver
// 比较，而不是让某个布尔位直接决定结果（见 docs/RELIABILITY_AND_RELEASE.md）。
func resolveUpdateDecision(in updateDecisionInput) string {
	minimum := in.Minimum
	if in.MandatoryVersion != "" && compareVersion(in.MandatoryVersion, minimum) > 0 {
		minimum = in.MandatoryVersion
	}
	if compareVersion(in.Current, minimum) < 0 {
		// 以前这里只要拿不到 actionURL 就一律降级成 recommended，结果是运营以为
		// 强更生效了、装了正式包的用户却看到带"稍后再说"的软更。现在只对
		// development 这种本来就没有安装入口的渠道降级，别把自己人锁在外面。
		if in.ActionURL == "" && in.Distribution == "development" {
			return "recommended"
		}
		return "required"
	}
	if compareVersion(in.Current, in.Latest) < 0 {
		return "recommended"
	}
	return "none"
}

func (s *server) bootstrap(c *gin.Context) {
	tenant, err := s.tenant.resolve(c.Request.Context(), c.Request.Host)
	if err != nil {
		problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
		return
	}
	view, err := s.appConfigView(c.Request.Context(), tenant.ID)
	if err != nil {
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	cfg := view["config"].(map[string]any)
	modules := normalizeModules(object(cfg["modules"]))
	wallet := normalizeWallet(object(cfg["wallet"]))
	// 租户配了链却没有一条还在平台目录里（目录下线了一条链）：这是要迁移租户配置的事故，
	// 不下发一个"零条链"的钱包段让 App 悄悄变成空壳
	if chains, _ := wallet["chains"].([]any); len(chains) == 0 {
		slog.Error("wallet section resolves to no supported chain", "tenant", tenant.ID, "configured", object(cfg["wallet"])["chains"])
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	// 代币目录只在这里下发：管理端的配置视图不带 tokens，它不是通过配置 PATCH 写的
	if err := s.attachWalletTokens(c.Request.Context(), tenant.ID, wallet); err != nil {
		slog.Error("wallet tokens could not be loaded for bootstrap", "tenant", tenant.ID, "error", err)
		problem(c, 503, "BOOTSTRAP_UNAVAILABLE", "Configuration is unavailable")
		return
	}
	requestedLocale := strings.TrimSpace(c.Query("locale"))
	locale := requestedLocale
	if locale == "" {
		locale = "zh-CN"
	}
	platform := strings.ToLower(c.GetHeader("x-platform"))
	if !oneOf(platform, "android", "ios", "harmony") {
		platform = "android"
	}
	distribution := c.GetHeader("x-distribution-channel")
	if !oneOf(distribution, "store", "direct", "mdm") {
		distribution = "development"
	}
	version := normalizeVersion(c.GetHeader("x-app-version"))
	updatePolicy := object(cfg["updatePolicy"])
	latest := text(updatePolicy["latestVersion"], "1.1.0")
	minimum := text(updatePolicy["minSupportedVersion"], "0.9.0")
	actionURL := s.actionURL(platform, distribution)
	var releaseID any
	var artifactSHA any
	var artifactSize any
	// active 发布声明"必须升级"时它的版本号；空表示没有强制要求
	mandatoryVersion := ""
	releaseNotes := []string{"远程语言与主题配置", "统一升级决策"}
	if platform == "android" && distribution == "direct" {
		if active, findErr := s.activeSimplifiedRelease(c.Request.Context(), tenant.ID, platform); findErr == nil {
			latest = active.Version
			releaseNotes = releaseNotesForLocale(active.ReleaseNotes, locale)
			releaseID = active.ID
			artifactSHA = active.SHA256
			artifactSize = active.FileSize
			actionURL = absoluteURL(c, "/v1/public/releases/"+active.ID+"/download")
			if active.Mandatory {
				mandatoryVersion = active.Version
			}
		}
	} else if active, findErr := s.activeSimplifiedRelease(c.Request.Context(), tenant.ID, platform); findErr == nil && active.Mandatory {
		// 商店 / MDM 渠道拿不到直装包，但运营勾的"强制升级"仍然要生效：
		// 否则管理端显示的强制徽章对 iOS 是假的
		mandatoryVersion = active.Version
	}
	decision := resolveUpdateDecision(updateDecisionInput{
		Current:          version,
		Minimum:          minimum,
		Latest:           latest,
		Distribution:     distribution,
		ActionURL:        actionURL,
		MandatoryVersion: mandatoryVersion,
	})
	localization := object(cfg["localization"])
	localeCatalog, _ := languageCatalog(effectiveLanguagesConfig{
		Languages: map[string]effectiveLanguage{
			"zh-CN": {Label: "简体中文", NativeName: "中文", Enabled: true, Sort: 1},
			"en-US": {Label: "English", NativeName: "English", Enabled: true, Sort: 2},
		},
	})
	locale = text(localization["fallbackLocale"], "zh-CN")
	if requestedLocale != "" {
		if !validLanguageCode(requestedLocale) {
			problem(c, 400, "INVALID_LANGUAGE_CODE", "Language code must use canonical BCP 47 format")
			return
		}
		locale = requestedLocale
	}
	if settings, _, _, settingsErr := s.effectiveLanguageSettings(c.Request.Context(), tenant.ID); settingsErr == nil {
		if language, supported := settings.Languages[locale]; !supported || !language.Enabled {
			locale = settings.FallbackLanguage
		}
		localeCatalog, _ = languageCatalog(settings)
		localization = map[string]any{"fallbackLocale": settings.FallbackLanguage, "supportedLocales": enabledLanguageCodes(settings), "localeCatalog": localeCatalog, "messagesVersion": cfg["configVersion"], "refreshIntervalSeconds": settings.RefreshIntervalSeconds}
		if compiled, compileErr := s.compiledMessages(c.Request.Context(), tenant.ID, locale, settings.FallbackLanguage); compileErr == nil {
			localization["messages"] = map[string]any{locale: compiled}
		} else {
			localization["messages"] = map[string]any{locale: map[string]string{}}
		}
		if language, exists := settings.Languages[locale]; exists && language.Resource != nil {
			localization["resource"] = language.Resource
		} else {
			localization["resource"] = nil
		}
	}
	messages := object(localization["messages"])
	theme := object(cfg["theme"])
	features := object(cfg["features"])
	brandingConfig, _, _, _, _, brandingErr := s.brandingRecord(c.Request.Context(), tenant.ID)
	if brandingErr != nil {
		brandingConfig = cloneMap(defaultBrandingConfig)
	}
	brandingMessages := map[string]string{}
	if compiled, compileErr := s.compiledMessages(c.Request.Context(), tenant.ID, locale, text(localization["fallbackLocale"], "zh-CN")); compileErr == nil {
		brandingMessages = compiled
	}
	branding := resolveBranding(brandingConfig, locale, text(localization["fallbackLocale"], "zh-CN"), brandingMessages)
	runtime := text(c.GetHeader("x-runtime-version"), "embedded")
	otaChannel := text(updatePolicy["otaChannel"], s.cfg.OTAChannel)
	ota := gin.H{"enabled": features["otaEnabled"], "channel": otaChannel, "runtimeVersion": runtime, "revision": nil, "updateId": nil, "baseReleaseId": nil, "applyStrategy": nil, "releaseNotes": []string{}}
	if runtime != "embedded" && truth(features["otaEnabled"]) {
		var otaRevision int
		var otaID, baseID, applyStrategy string
		var otaNotes []byte
		if err := s.db.QueryRowContext(c.Request.Context(), `SELECT o.revision,o.update_id,o.base_release_id,o.apply_strategy,o.release_notes FROM ota_releases o WHERE o.tenant_id=? AND o.platform=? AND o.channel=? AND o.runtime_version=? AND o.status='active' ORDER BY o.revision DESC LIMIT 1`, tenant.ID, platform, otaChannel, runtime).Scan(&otaRevision, &otaID, &baseID, &applyStrategy, &otaNotes); err == nil {
			var notes map[string][]string
			_ = json.Unmarshal(otaNotes, &notes)
			ota["revision"], ota["updateId"], ota["baseReleaseId"], ota["applyStrategy"], ota["releaseNotes"] = otaRevision, otaID, baseID, applyStrategy, releaseNotesForLocale(notes, locale)
		}
	}
	c.JSON(200, gin.H{"schemaVersion": 1, "configVersion": cfg["configVersion"], "generatedAt": iso(time.Now()), "ttlSeconds": cfg["ttlSeconds"], "requestId": requestID(c), "localization": gin.H{"selectedLocale": locale, "fallbackLocale": localization["fallbackLocale"], "supportedLocales": localization["supportedLocales"], "localeCatalog": localeCatalog, "messagesVersion": localization["messagesVersion"], "refreshIntervalSeconds": localization["refreshIntervalSeconds"], "messages": messages[locale], "resource": localization["resource"]}, "theme": theme, "modules": gin.H{"predict": truth(modules["predict"]), "dex": truth(modules["dex"])}, "wallet": wallet, "features": gin.H{"updateCenter": features["updateCenter"], "otaEnabled": features["otaEnabled"], "directUpdateEnabled": platform == "android" && truth(features["directUpdateEnabled"]), "diagnosticsEnabled": features["diagnosticsEnabled"]}, "branding": branding, "app": gin.H{"version": version, "buildNumber": text(c.GetHeader("x-build-number"), "0"), "platform": platform, "distribution": distribution, "runtimeVersion": runtime}, "update": gin.H{"decision": decision, "minSupportedVersion": minimum, "latestVersion": latest, "releaseNotes": releaseNotes, "ota": ota, "full": gin.H{"channel": distribution, "actionUrl": nullableString(actionURL), "releaseId": releaseID, "sha256": artifactSHA, "size": artifactSize}}, "support": gin.H{"diagnosticId": requestID(c), "statusPageUrl": object(cfg["support"])["statusPageUrl"]}})
}

func enabledLanguageCodes(settings effectiveLanguagesConfig) []string {
	codes := make([]string, 0, len(settings.Languages))
	for code, item := range settings.Languages {
		if item.Enabled {
			codes = append(codes, code)
		}
	}
	sort.Strings(codes)
	return codes
}

func (s *server) actionURL(platform, distribution string) string {
	if platform == "android" && distribution == "direct" {
		return s.cfg.AndroidDirectURL
	}
	if platform == "android" && distribution == "store" {
		return s.cfg.AndroidStoreURL
	}
	if platform == "ios" && distribution == "mdm" {
		return s.cfg.IOSMDMURL
	}
	if platform == "ios" && distribution == "store" {
		return s.cfg.IOSStoreURL
	}
	return ""
}

func insertAudit(ctx context.Context, tx *sql.Tx, a auditEvent) error {
	summary, _ := json.Marshal(a.Summary)
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, a.ID, a.TenantID, a.ActorID, a.Action, a.TargetType, a.TargetID, a.Reason, a.RequestID, summary, time.Now().UTC())
	return err
}
func newAudit(tenant, actor, action, targetType, targetID, reason, requestID string, summary map[string]any) auditEvent {
	return auditEvent{ID: "audit_" + randomID(16), TenantID: tenant, ActorID: actor, Action: action, TargetType: targetType, TargetID: targetID, Reason: reason, RequestID: requestID, CreatedAt: iso(time.Now()), Summary: summary}
}
func validConfig(v map[string]any) bool {
	if v == nil {
		return false
	}
	_, ok1 := v["configVersion"].(string)
	ttl, ok2 := v["ttlSeconds"].(float64)
	modules := object(v["modules"])
	if modules == nil {
		modules = map[string]any{"predict": true, "dex": true}
	}
	policy := object(v["updatePolicy"])
	// 版本号不是 semver 时，compareVersion 会把非法值当成 "1.0.0"，强制升级静默失效
	policyValid := policy != nil && validVersion(text(policy["minSupportedVersion"], "")) && validVersion(text(policy["latestVersion"], ""))
	return ok1 && ok2 && ttl >= 30 && ttl <= 86400 && (truth(modules["predict"]) || truth(modules["dex"])) && object(v["localization"]) != nil && object(v["theme"]) != nil && object(v["features"]) != nil && policyValid && object(v["support"]) != nil
}

func normalizeModules(value map[string]any) map[string]any {
	if value == nil || (!truth(value["predict"]) && !truth(value["dex"])) {
		return map[string]any{"predict": true, "dex": true}
	}
	return map[string]any{"predict": truth(value["predict"]), "dex": truth(value["dex"])}
}
func configSummary(v map[string]any) gin.H {
	l := object(v["localization"])
	t := object(v["theme"])
	f := object(v["features"])
	enabled := []string{}
	for k, val := range f {
		if truth(val) {
			enabled = append(enabled, k)
		}
	}
	wallet := object(v["wallet"])
	projectID, _ := wallet["walletConnectProjectId"].(string)
	chains, ok := wallet["chains"].([]any)
	if !ok {
		chains = []any{}
	}
	return gin.H{"configVersion": v["configVersion"], "localization": gin.H{"supportedLocales": l["supportedLocales"], "messagesVersion": l["messagesVersion"]}, "theme": gin.H{"paletteVersion": t["paletteVersion"], "modes": []string{"light", "dark"}}, "featureFlags": enabled, "updatePolicy": gin.H{"source": "mysql", "approvalRequired": false}, "wallet": gin.H{"chains": chains, "walletConnectConfigured": strings.TrimSpace(projectID) != ""}}
}
func decode(c *gin.Context, v any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}
func problem(c *gin.Context, status int, code, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.JSON(status, gin.H{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": detail, "requestId": requestID(c)})
}
func requestID(c *gin.Context) string          { v, _ := c.Get("requestId"); return fmt.Sprint(v) }
func actor(c *gin.Context) string              { v, _ := c.Get("actorId"); return fmt.Sprint(v) }
func tenantID(c *gin.Context) string           { v, _ := c.Get("tenantId"); return fmt.Sprint(v) }
func valueFrom(c *gin.Context, key string) any { v, _ := c.Get(key); return v }

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
func sha256Hex(v string) string { sum := sha256.Sum256([]byte(v)); return hex.EncodeToString(sum[:]) }
func constantEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, e1 := strconv.Atoi(parts[1])
	r, e2 := strconv.Atoi(parts[2])
	p, e3 := strconv.Atoi(parts[3])
	if e1 != nil || e2 != nil || e3 != nil || n < 16384 || n > 32768 || r < 8 || r > 16 || p < 1 || p > 4 {
		return false
	}
	salt, e4 := base64.RawURLEncoding.DecodeString(parts[4])
	expected, e5 := base64.RawURLEncoding.DecodeString(parts[5])
	if e4 != nil || e5 != nil {
		return false
	}
	actual, e6 := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	return e6 == nil && subtle.ConstantTimeCompare(actual, expected) == 1
}
func safeMethod(m string) bool { return m == "GET" || m == "HEAD" || m == "OPTIONS" }
func iso(t time.Time) string   { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func oneOf(v string, options ...string) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}
func truth(v any) bool            { b, _ := v.(bool); return b }
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

func releaseNotesForLocale(notes map[string][]string, locale string) []string {
	if selected := notes[locale]; len(selected) > 0 {
		return selected
	}
	if fallback := notes["zh-CN"]; len(fallback) > 0 {
		return fallback
	}
	for _, value := range notes {
		if len(value) > 0 {
			return value
		}
	}
	return []string{}
}
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func absoluteURL(c *gin.Context, path string) string {
	scheme := "http"
	if c.GetHeader("x-forwarded-proto") == "https" || c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host + path
}
func nullableInt64(v sql.NullInt64) any {
	if !v.Valid {
		return nil
	}
	return v.Int64
}
func nullableSQLString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "1.0.0"
	}
	if semver.IsValid("v" + v) {
		return v
	}
	return "1.0.0"
}
func validVersion(v string) bool     { return semver.IsValid("v" + v) }
func compareVersion(a, b string) int { return semver.Compare("v"+a, "v"+b) }

const initialConfig = `{"configVersion":"2026.08.24.1","ttlSeconds":300,"localization":{"fallbackLocale":"zh-CN","supportedLocales":["zh-CN","en-US"],"messagesVersion":"2026.08.24.1","messages":{"zh-CN":{"app.name":"RN 应用基座","home.title":"远程配置中心"},"en-US":{"app.name":"RN App Foundation","home.title":"Remote configuration center"}}},"theme":{"defaultMode":"system","allowUserOverride":true,"paletteVersion":"ocean-1","light":{"primary":"#3157D5","onPrimary":"#FFFFFF","background":"#F4F7FB","surface":"#FFFFFF","surfaceVariant":"#EAF0F8","text":"#101828","textMuted":"#5A687C","border":"#D5DDE9","success":"#147A50","warning":"#9A5C00","danger":"#B42318","info":"#2962A3","pricePositive":"#0E8A5F","priceNegative":"#D03C45","risk":"#7A4D00","focus":"#7293FF","backdrop":"rgba(11,18,32,.56)"},"dark":{"primary":"#AFC6FF","onPrimary":"#082B78","background":"#0B1220","surface":"#121C2D","surfaceVariant":"#1D2A3E","text":"#F0F4FA","textMuted":"#A9B7CA","border":"#35445A","success":"#61D6A3","warning":"#F4BD68","danger":"#FFB4AB","info":"#A8CAFF","pricePositive":"#5CDBA8","priceNegative":"#FF7B86","risk":"#F4BD68","focus":"#AFC6FF","backdrop":"rgba(0,0,0,.72)"}},"features":{"updateCenter":true,"otaEnabled":true,"directUpdateEnabled":true,"diagnosticsEnabled":true},"updatePolicy":{"minSupportedVersion":"0.9.0","latestVersion":"1.1.0","otaChannel":"production"},"support":{"statusPageUrl":"https://status.example.com"}}`
