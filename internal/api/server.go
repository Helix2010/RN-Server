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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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
}

type attempt struct {
	Failures int
	ResetsAt time.Time
}

type release struct {
	ID             string         `json:"id"`
	ApplicationID  string         `json:"applicationId"`
	Platform       string         `json:"platform"`
	Version        string         `json:"version"`
	BuildNumber    int            `json:"buildNumber"`
	RuntimeVersion string         `json:"runtimeVersion"`
	Channel        string         `json:"channel"`
	Status         string         `json:"status"`
	ReleaseNotes   []string       `json:"releaseNotes"`
	Artifact       map[string]any `json:"artifact"`
	Rollout        map[string]any `json:"rollout"`
	CreatedAt      string         `json:"createdAt"`
	UpdatedAt      string         `json:"updatedAt"`
	ActivatedAt    *string        `json:"activatedAt"`
	LastAction     *string        `json:"lastAction"`
	ArtifactID     *string        `json:"artifactId,omitempty"`
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
	s := &server{cfg: cfg, db: storage.DB, attempts: map[string]attempt{}, objects: objectstore.AWSFactory{}}
	r := gin.New()
	r.Use(gin.Recovery(), s.requestContext(), s.databaseTimeout(), s.securityHeaders(), s.cors())
	r.GET("/health/live", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "live"}) })
	r.GET("/health/ready", s.ready)
	r.GET("/openapi.json", func(c *gin.Context) { c.File("contracts/openapi.json") })
	r.GET("/docs", s.docs)
	r.GET("/v1/mobile/bootstrap", s.bootstrap)
	r.GET("/v1/public/tenants/:tenantSlug/apps/:applicationId/android/direct/latest", s.publicLatestRelease)
	r.GET("/v1/public/artifacts/:id/download", s.publicArtifactDownload)
	admin := r.Group("/v1/admin")
	admin.POST("/auth/login", s.login)
	protected := admin.Group("")
	protected.Use(s.authenticate())
	protected.GET("/auth/session", s.session)
	protected.POST("/auth/logout", s.logout)
	protected.GET("/tenants", s.listTenants)
	protected.POST("/tenants", s.createTenant)
	tenant := protected.Group("/tenants/:tenantId")
	tenant.Use(s.tenantScope())
	s.registerTenantRoutes(tenant)
	legacy := protected.Group("")
	legacy.Use(s.defaultTenantScope())
	s.registerTenantRoutes(legacy)
	return r
}

func (s *server) registerTenantRoutes(group *gin.RouterGroup) {
	group.GET("/overview", s.overview)
	group.GET("/releases", s.listReleases)
	group.POST("/releases", s.createRelease)
	group.GET("/releases/:id", s.releaseDetail)
	group.POST("/releases/:id/:action", s.releaseAction)
	group.GET("/audit-events", s.listAudits)
	group.GET("/app-config", s.getAppConfig)
	group.PATCH("/app-config", s.updateAppConfig)
	group.GET("/applications", s.listApplications)
	group.POST("/applications", s.createApplication)
	group.PUT("/applications/:applicationId", s.updateApplication)
	group.GET("/storage-config", s.getStorageConfig)
	group.PUT("/storage-config", s.putStorageConfig)
	group.POST("/storage-config/test", s.testStorageConfig)
	group.GET("/artifacts", s.listArtifacts)
	group.POST("/artifacts/uploads", s.createArtifactUpload)
	group.POST("/artifacts/:id/finalize", s.finalizeArtifact)
}

func (s *server) tenantScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.Param("tenantId"))
		var status string
		if id == "" || s.db.QueryRowContext(c.Request.Context(), `SELECT status FROM tenants WHERE id=?`, id).Scan(&status) != nil {
			problem(c, 404, "TENANT_NOT_FOUND", "Tenant not found")
			c.Abort()
			return
		}
		if status != "active" {
			problem(c, 409, "TENANT_DISABLED", "Tenant is disabled")
			c.Abort()
			return
		}
		c.Set("tenantId", id)
		c.Next()
	}
}

func (s *server) defaultTenantScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tenantId", "tenant_default")
		c.Next()
	}
}

func (s *server) databaseTimeout() gin.HandlerFunc {
	return func(c *gin.Context) {
		if strings.HasSuffix(c.Request.URL.Path, "/finalize") || strings.HasSuffix(c.Request.URL.Path, "/storage-config/test") || strings.HasSuffix(c.Request.URL.Path, "/download") {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.MySQLQueryTimeout)*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
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
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Methods", "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS")
			c.Header("Access-Control-Allow-Headers", "content-type,x-admin-key,x-admin-id,x-request-id")
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
	query := `SELECT id,application_id,platform,version,build_number,runtime_version,channel,status,release_notes,artifact,rollout,activated_at,last_action,created_at,updated_at,artifact_id FROM app_releases WHERE tenant_id=? AND (?='' OR platform=?) AND (?='' OR status=?) ORDER BY updated_at DESC`
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
	var notes, artifact, rollout []byte
	var activated sql.NullTime
	var action sql.NullString
	var created, updated time.Time
	var artifactID sql.NullString
	err := row.Scan(&r.ID, &r.ApplicationID, &r.Platform, &r.Version, &r.BuildNumber, &r.RuntimeVersion, &r.Channel, &r.Status, &notes, &artifact, &rollout, &activated, &action, &created, &updated, &artifactID)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal(notes, &r.ReleaseNotes)
	if len(artifact) > 0 {
		_ = json.Unmarshal(artifact, &r.Artifact)
	}
	_ = json.Unmarshal(rollout, &r.Rollout)
	r.CreatedAt = iso(created)
	r.UpdatedAt = iso(updated)
	if activated.Valid {
		v := iso(activated.Time)
		r.ActivatedAt = &v
	}
	if action.Valid {
		r.LastAction = &action.String
	}
	if artifactID.Valid {
		r.ArtifactID = &artifactID.String
	}
	return r, nil
}

func (s *server) createRelease(c *gin.Context) {
	var input release
	if err := decode(c, &input); err != nil || !validVersion(input.Version) || input.BuildNumber < 1 || !oneOf(input.Platform, "android", "ios") || !oneOf(input.Channel, "store", "direct", "mdm", "ota") {
		problem(c, 400, "INVALID_RELEASE", "Invalid release payload")
		return
	}
	if input.ApplicationID == "" || input.RuntimeVersion == "" {
		problem(c, 400, "INVALID_RELEASE", "Invalid release payload")
		return
	}
	if err := s.requireApplication(c.Request.Context(), tenantID(c), input.ApplicationID); err != nil {
		problem(c, 400, "APPLICATION_NOT_FOUND", "Application is not configured for this tenant")
		return
	}
	if input.Channel == "direct" {
		if input.Platform != "android" || input.ArtifactID == nil || *input.ArtifactID == "" {
			problem(c, 400, "VERIFIED_ARTIFACT_REQUIRED", "Android direct releases require a verified APK artifact")
			return
		}
		artifact, err := s.artifactForRelease(c.Request.Context(), tenantID(c), *input.ArtifactID, input.ApplicationID, input.Version, input.BuildNumber)
		if err != nil {
			problem(c, 409, "VERIFIED_ARTIFACT_REQUIRED", "Artifact is not verified or does not match the release identity")
			return
		}
		input.Artifact = artifact
	} else if input.ArtifactID != nil || input.Artifact != nil {
		problem(c, 400, "INVALID_RELEASE_ARTIFACT", "Only Android direct releases accept APK artifacts")
		return
	}
	now := time.Now().UTC()
	input.ID = "rel_" + randomID(16)
	input.CreatedAt = iso(now)
	input.UpdatedAt = iso(now)
	action := "create"
	input.LastAction = &action
	if input.Artifact != nil {
		input.Status = "verified"
	} else {
		input.Status = "draft"
	}
	if input.ReleaseNotes == nil {
		input.ReleaseNotes = []string{}
	}
	if input.Rollout == nil {
		input.Rollout = map[string]any{}
	}
	defaults(input.Rollout)
	notes, _ := json.Marshal(input.ReleaseNotes)
	artifact, _ := json.Marshal(input.Artifact)
	rollout, _ := json.Marshal(input.Rollout)
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "RELEASE_CREATE_FAILED", "Unable to create release")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_releases (id,tenant_id,application_id,platform,version,build_number,runtime_version,channel,status,release_notes,artifact,artifact_id,rollout,activated_at,last_action,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, input.ID, tenantID(c), input.ApplicationID, input.Platform, input.Version, input.BuildNumber, input.RuntimeVersion, input.Channel, input.Status, notes, nullableJSON(input.Artifact, artifact), input.ArtifactID, rollout, nil, action, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			problem(c, 409, "DUPLICATE_RELEASE", "A release with this build and channel already exists")
		} else {
			problem(c, 500, "RELEASE_CREATE_FAILED", "Unable to create release")
		}
		return
	}
	event := newAudit(tenantID(c), actor(c), "create", "release", input.ID, "Created release", requestID(c), map[string]any{"version": input.Version, "platform": input.Platform, "status": input.Status})
	if err = insertAudit(c.Request.Context(), tx, event); err != nil || tx.Commit() != nil {
		problem(c, 500, "RELEASE_CREATE_FAILED", "Unable to create release")
		return
	}
	c.JSON(201, gin.H{"release": input, "audit": gin.H{"actorId": actor(c), "requestId": requestID(c), "action": "create"}})
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
	return scanRelease(s.db.QueryRowContext(ctx, `SELECT id,application_id,platform,version,build_number,runtime_version,channel,status,release_notes,artifact,rollout,activated_at,last_action,created_at,updated_at,artifact_id FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id))
}

var transitions = map[string]map[string]string{"stage": {"verified": "staged"}, "activate": {"staged": "active", "paused": "active"}, "pause": {"active": "paused"}, "rollback": {"active": "rolled_back", "paused": "rolled_back"}}

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
	if (target == "active" || target == "rolled_back") && number(r.Rollout["percentage"]) == 0 {
		problem(c, 400, "ROLLOUT_REQUIRED", "Configure a rollout percentage before activation")
		return
	}
	if target == "active" && r.Channel == "direct" {
		if r.ArtifactID == nil || s.artifactStillVerified(c.Request.Context(), tenantID(c), *r.ArtifactID) != nil {
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
		_, _ = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status='completed',last_action='completed',updated_at=? WHERE tenant_id=? AND id<>? AND application_id=? AND platform=? AND channel=? AND status='active'`, now, tenantID(c), r.ID, r.ApplicationID, r.Platform, r.Channel)
	}
	var activated any = nil
	if target == "active" {
		activated = now
	} else if r.ActivatedAt != nil {
		if parsed, e := time.Parse(time.RFC3339Nano, *r.ActivatedAt); e == nil {
			activated = parsed
		}
	}
	_, err = tx.ExecContext(c.Request.Context(), `UPDATE app_releases SET status=?,last_action=?,updated_at=?,activated_at=? WHERE tenant_id=? AND id=?`, target, target, now, activated, tenantID(c), r.ID)
	if err != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	event := newAudit(tenantID(c), actor(c), c.Param("action"), "release", r.ID, body.Reason, requestID(c), map[string]any{"version": r.Version, "platform": r.Platform, "status": target})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TRANSITION_FAILED", "Unable to update release")
		return
	}
	r.Status = target
	r.UpdatedAt = iso(now)
	r.LastAction = &target
	if target == "active" {
		v := iso(now)
		r.ActivatedAt = &v
	}
	c.JSON(201, gin.H{"release": r})
}

func (s *server) overview(c *gin.Context) {
	items, err := s.queryReleases(c.Request.Context(), tenantID(c), "", "")
	if err != nil {
		problem(c, 500, "OVERVIEW_FAILED", "Unable to load overview")
		return
	}
	counts := map[string]int{"draft": 0, "uploaded": 0, "verified": 0, "staged": 0, "active": 0, "paused": 0, "completed": 0, "rejected": 0, "rolled_back": 0}
	current := map[string]any{"android": nil, "ios": nil}
	sum, active := 0, 0
	for _, r := range items {
		counts[r.Status]++
		if r.Status == "active" {
			sum += int(number(r.Rollout["percentage"]))
			active++
			if r.Channel != "ota" && current[r.Platform] == nil {
				current[r.Platform] = r
			}
		}
	}
	rollout := 0
	if active > 0 {
		rollout = sum / active
	}
	c.JSON(200, gin.H{"generatedAt": iso(time.Now()), "current": current, "counts": counts, "rollout": rollout, "signals": gin.H{"crashFreeSessions": nil, "updateSuccessRate": nil, "note": "Connect telemetry provider before production SLO decisions"}})
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
	var updatedBy string
	var updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key='mobile-bootstrap'`, tenant).Scan(&raw, &version, &updatedBy, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		raw = []byte(initialConfig)
		now := time.Now().UTC()
		_, err = s.db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,1,'system-bootstrap',?)`, tenant, raw, now)
		if err != nil {
			return nil, err
		}
		version = 1
		updatedBy = "system-bootstrap"
		updated = now
	} else if err != nil {
		return nil, err
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return gin.H{"summary": configSummary(value), "config": value, "metadata": gin.H{"databaseVersion": version, "updatedBy": updatedBy, "updatedAt": iso(updated)}}, nil
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
	raw, _ := json.Marshal(body.Config)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key='mobile-bootstrap' AND version=?`, raw, actor(c), now, tenantID(c), body.ExpectedVersion)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		problem(c, 409, "STALE_APP_CONFIG", "App config changed since it was loaded; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "config_update", "app-config", "mobile-bootstrap", body.Reason, requestID(c), map[string]any{"status": "active", "databaseVersionBefore": body.ExpectedVersion, "databaseVersionAfter": body.ExpectedVersion + 1, "configVersion": body.Config["configVersion"]})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
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

func (s *server) bootstrap(c *gin.Context) {
	tenant, err := s.resolveTenant(c.Request.Context(), c.Query("tenant"))
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
	locale := "zh-CN"
	if strings.HasPrefix(strings.ToLower(c.Query("locale")), "en") {
		locale = "en-US"
	}
	platform := strings.ToLower(c.GetHeader("x-platform"))
	if platform != "ios" {
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
	var artifactID any
	var artifactSHA any
	var artifactSize any
	releaseNotes := []string{"远程语言与主题配置", "统一升级决策"}
	applicationID := strings.TrimSpace(c.GetHeader("x-application-id"))
	if applicationID == "" {
		applicationID = "dex-mobile"
	}
	if platform == "android" && distribution == "direct" {
		if active, artifact, findErr := s.activeDirectRelease(c.Request.Context(), tenant.ID, applicationID); findErr == nil {
			latest = active.Version
			releaseNotes = active.ReleaseNotes
			artifactID = artifact["id"]
			artifactSHA = artifact["sha256"]
			artifactSize = artifact["size"]
			actionURL = absoluteURL(c, "/v1/public/artifacts/"+fmt.Sprint(artifact["id"])+"/download")
		}
	}
	decision := "none"
	if compareVersion(version, minimum) < 0 {
		if actionURL != "" {
			decision = "required"
		} else {
			decision = "recommended"
		}
	} else if compareVersion(version, latest) < 0 {
		decision = "recommended"
	}
	localization := object(cfg["localization"])
	messages := object(localization["messages"])
	theme := object(cfg["theme"])
	features := object(cfg["features"])
	runtime := text(c.GetHeader("x-runtime-version"), "embedded")
	c.JSON(200, gin.H{"schemaVersion": 1, "configVersion": cfg["configVersion"], "generatedAt": iso(time.Now()), "ttlSeconds": cfg["ttlSeconds"], "requestId": requestID(c), "localization": gin.H{"selectedLocale": locale, "fallbackLocale": localization["fallbackLocale"], "supportedLocales": localization["supportedLocales"], "messagesVersion": localization["messagesVersion"], "messages": messages[locale]}, "theme": theme, "features": gin.H{"updateCenter": features["updateCenter"], "otaEnabled": features["otaEnabled"], "directUpdateEnabled": platform == "android" && truth(features["directUpdateEnabled"]), "diagnosticsEnabled": features["diagnosticsEnabled"]}, "app": gin.H{"version": version, "buildNumber": text(c.GetHeader("x-build-number"), "0"), "platform": platform, "distribution": distribution, "runtimeVersion": runtime}, "update": gin.H{"decision": decision, "minSupportedVersion": minimum, "latestVersion": latest, "releaseNotes": releaseNotes, "ota": gin.H{"enabled": features["otaEnabled"], "channel": text(updatePolicy["otaChannel"], s.cfg.OTAChannel), "runtimeVersion": runtime}, "full": gin.H{"channel": distribution, "actionUrl": nullableString(actionURL), "artifactId": artifactID, "sha256": artifactSHA, "size": artifactSize}}, "support": gin.H{"diagnosticId": requestID(c), "statusPageUrl": object(cfg["support"])["statusPageUrl"]}})
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
	return ok1 && ok2 && ttl >= 30 && ttl <= 86400 && object(v["localization"]) != nil && object(v["theme"]) != nil && object(v["features"]) != nil && object(v["updatePolicy"]) != nil && object(v["support"]) != nil
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
	return gin.H{"configVersion": v["configVersion"], "localization": gin.H{"supportedLocales": l["supportedLocales"], "messagesVersion": l["messagesVersion"]}, "theme": gin.H{"paletteVersion": t["paletteVersion"], "modes": []string{"light", "dark"}}, "featureFlags": enabled, "updatePolicy": gin.H{"source": "mysql", "approvalRequired": false}}
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

func (s *server) secretBox() (*secretbox.Box, error) {
	return secretbox.New(s.cfg.StorageMasterKey)
}
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
func defaults(r map[string]any) {
	if _, ok := r["percentage"]; !ok {
		r["percentage"] = 0
	}
	if _, ok := r["audience"]; !ok {
		r["audience"] = "all"
	}
	if _, ok := r["startsAt"]; !ok {
		r["startsAt"] = nil
	}
	if _, ok := r["stopRule"]; !ok {
		r["stopRule"] = nil
	}
}
func nullableJSON(v map[string]any, raw []byte) any {
	if v == nil {
		return nil
	}
	return raw
}
func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		return 0
	}
}
func truth(v any) bool            { b, _ := v.(bool); return b }
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
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
