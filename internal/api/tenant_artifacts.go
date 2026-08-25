package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

var (
	tenantSlugPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	applicationPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,119}$`)
	packageNamePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
	hexSHA256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	storageBucketPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,253}$`)
	objectPrefixPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/_-]{0,254}$`)
)

type tenantRecord struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type applicationRecord struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	Platform             string  `json:"platform"`
	PackageName          string  `json:"packageName"`
	ExpectedSignerSHA256 *string `json:"expectedSignerSha256"`
	CreatedAt            string  `json:"createdAt"`
	UpdatedAt            string  `json:"updatedAt"`
}

type storageRecord struct {
	TenantID           string
	Version            int
	Provider           string
	Endpoint           string
	Region             string
	Bucket             string
	ObjectPrefix       string
	ForcePathStyle     bool
	PublicBaseURL      string
	AccessKeyCipher    []byte
	SecretKeyCipher    []byte
	SessionTokenCipher []byte
	AccessKeyHint      string
	UpdatedBy          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type storageSecrets struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type artifactRecord struct {
	ID                   string
	TenantID             string
	ApplicationID        string
	StorageConfigVersion int
	ObjectKey            string
	FileName             string
	ContentType          string
	ExpectedSize         int64
	Size                 sql.NullInt64
	SHA256               sql.NullString
	PackageName          sql.NullString
	VersionName          sql.NullString
	VersionCode          sql.NullInt64
	MinSDK               sql.NullInt64
	SignerSHA256         sql.NullString
	SigningScheme        sql.NullInt64
	SignerSubject        sql.NullString
	Status               string
	RejectionReason      sql.NullString
	CreatedBy            string
	VerifiedAt           sql.NullTime
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (s *server) listTenants(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT id,slug,name,status,created_at,updated_at FROM tenants ORDER BY name,id`)
	if err != nil {
		problem(c, 500, "TENANT_QUERY_FAILED", "Unable to load tenants")
		return
	}
	defer rows.Close()
	items := []tenantRecord{}
	for rows.Next() {
		var item tenantRecord
		var created, updated time.Time
		if err := rows.Scan(&item.ID, &item.Slug, &item.Name, &item.Status, &created, &updated); err != nil {
			problem(c, 500, "TENANT_QUERY_FAILED", "Unable to load tenants")
			return
		}
		item.CreatedAt, item.UpdatedAt = iso(created), iso(updated)
		items = append(items, item)
	}
	c.JSON(200, gin.H{"items": items})
}

func (s *server) createTenant(c *gin.Context) {
	var body struct {
		Slug    string `json:"slug"`
		Name    string `json:"name"`
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_TENANT", "Invalid tenant payload")
		return
	}
	body.Slug = strings.ToLower(strings.TrimSpace(body.Slug))
	body.Name = strings.TrimSpace(body.Name)
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || !tenantSlugPattern.MatchString(body.Slug) || len(body.Name) < 2 || len(body.Name) > 160 {
		problem(c, 400, "INVALID_TENANT", "Valid slug, name, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	item := tenantRecord{ID: "tenant_" + randomID(12), Slug: body.Slug, Name: body.Name, Status: "active", CreatedAt: iso(now), UpdatedAt: iso(now)}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TENANT_CREATE_FAILED", "Unable to create tenant")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(c.Request.Context(), `INSERT INTO tenants(id,slug,name,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)`, item.ID, item.Slug, item.Name, now, now); err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			problem(c, 409, "TENANT_SLUG_EXISTS", "Tenant slug already exists")
		} else {
			problem(c, 500, "TENANT_CREATE_FAILED", "Unable to create tenant")
		}
		return
	}
	event := newAudit(item.ID, actor(c), "tenant_create", "tenant", item.ID, body.Reason, requestID(c), map[string]any{"slug": item.Slug, "status": item.Status})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TENANT_CREATE_FAILED", "Unable to create tenant")
		return
	}
	c.JSON(201, gin.H{"tenant": item})
}

func (s *server) resolveTenant(ctx context.Context, slug string) (tenantRecord, error) {
	if strings.TrimSpace(slug) == "" {
		slug = "default"
	}
	var item tenantRecord
	var created, updated time.Time
	err := s.db.QueryRowContext(ctx, `SELECT id,slug,name,status,created_at,updated_at FROM tenants WHERE slug=? AND status='active'`, slug).Scan(&item.ID, &item.Slug, &item.Name, &item.Status, &created, &updated)
	item.CreatedAt, item.UpdatedAt = iso(created), iso(updated)
	return item, err
}

func (s *server) listApplications(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT id,name,platform,package_name,expected_signer_sha256,created_at,updated_at FROM tenant_applications WHERE tenant_id=? ORDER BY name,id`, tenantID(c))
	if err != nil {
		problem(c, 500, "APPLICATION_QUERY_FAILED", "Unable to load applications")
		return
	}
	defer rows.Close()
	items := []applicationRecord{}
	for rows.Next() {
		var item applicationRecord
		var signer sql.NullString
		var created, updated time.Time
		if err := rows.Scan(&item.ID, &item.Name, &item.Platform, &item.PackageName, &signer, &created, &updated); err != nil {
			problem(c, 500, "APPLICATION_QUERY_FAILED", "Unable to load applications")
			return
		}
		if signer.Valid {
			item.ExpectedSignerSHA256 = &signer.String
		}
		item.CreatedAt, item.UpdatedAt = iso(created), iso(updated)
		items = append(items, item)
	}
	c.JSON(200, gin.H{"items": items})
}

func (s *server) createApplication(c *gin.Context) {
	var body struct {
		ID                   string `json:"id"`
		Name                 string `json:"name"`
		PackageName          string `json:"packageName"`
		ExpectedSignerSHA256 string `json:"expectedSignerSha256"`
		Reason               string `json:"reason"`
		Confirm              bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_APPLICATION", "Invalid application payload")
		return
	}
	body.ID = strings.ToLower(strings.TrimSpace(body.ID))
	body.Name, body.PackageName = strings.TrimSpace(body.Name), strings.TrimSpace(body.PackageName)
	body.ExpectedSignerSHA256 = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(body.ExpectedSignerSHA256, ":", "")))
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || !applicationPattern.MatchString(body.ID) || len(body.Name) < 2 || !packageNamePattern.MatchString(body.PackageName) || !hexSHA256Pattern.MatchString(body.ExpectedSignerSHA256) {
		problem(c, 400, "INVALID_APPLICATION", "App id, package name, signer SHA-256, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	item := applicationRecord{ID: body.ID, Name: body.Name, Platform: "android", PackageName: body.PackageName, ExpectedSignerSHA256: &body.ExpectedSignerSHA256, CreatedAt: iso(now), UpdatedAt: iso(now)}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "APPLICATION_CREATE_FAILED", "Unable to create application")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO tenant_applications(id,tenant_id,name,platform,package_name,expected_signer_sha256,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, item.ID, tenantID(c), item.Name, item.Platform, item.PackageName, body.ExpectedSignerSHA256, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			problem(c, 409, "APPLICATION_EXISTS", "Application id or package name already exists in this tenant")
		} else {
			problem(c, 500, "APPLICATION_CREATE_FAILED", "Unable to create application")
		}
		return
	}
	event := newAudit(tenantID(c), actor(c), "application_create", "application", item.ID, body.Reason, requestID(c), map[string]any{"packageName": item.PackageName, "platform": item.Platform})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "APPLICATION_CREATE_FAILED", "Unable to create application")
		return
	}
	c.JSON(201, gin.H{"application": item})
}

func (s *server) updateApplication(c *gin.Context) {
	var body struct {
		Name                 string `json:"name"`
		PackageName          string `json:"packageName"`
		ExpectedSignerSHA256 string `json:"expectedSignerSha256"`
		Reason               string `json:"reason"`
		Confirm              bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_APPLICATION", "Invalid application payload")
		return
	}
	body.Name, body.PackageName = strings.TrimSpace(body.Name), strings.TrimSpace(body.PackageName)
	body.ExpectedSignerSHA256 = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(body.ExpectedSignerSHA256, ":", "")))
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || len(body.Name) < 2 || !packageNamePattern.MatchString(body.PackageName) || !hexSHA256Pattern.MatchString(body.ExpectedSignerSHA256) {
		problem(c, 400, "INVALID_APPLICATION", "Name, package name, signer SHA-256, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "APPLICATION_UPDATE_FAILED", "Unable to update application")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE tenant_applications SET name=?,package_name=?,expected_signer_sha256=?,updated_at=? WHERE tenant_id=? AND id=?`, body.Name, body.PackageName, body.ExpectedSignerSHA256, now, tenantID(c), c.Param("applicationId"))
	if err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			problem(c, 409, "APPLICATION_PACKAGE_EXISTS", "Package name already exists in this tenant")
		} else {
			problem(c, 500, "APPLICATION_UPDATE_FAILED", "Unable to update application")
		}
		return
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		problem(c, 404, "APPLICATION_NOT_FOUND", "Application not found")
		return
	}
	event := newAudit(tenantID(c), actor(c), "application_update", "application", c.Param("applicationId"), body.Reason, requestID(c), map[string]any{"packageName": body.PackageName, "signerSha256": body.ExpectedSignerSHA256})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "APPLICATION_UPDATE_FAILED", "Unable to update application")
		return
	}
	item := applicationRecord{ID: c.Param("applicationId"), Name: body.Name, Platform: "android", PackageName: body.PackageName, ExpectedSignerSHA256: &body.ExpectedSignerSHA256, UpdatedAt: iso(now)}
	var created time.Time
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT created_at FROM tenant_applications WHERE tenant_id=? AND id=?`, tenantID(c), item.ID).Scan(&created); err == nil {
		item.CreatedAt = iso(created)
	}
	c.JSON(200, gin.H{"application": item})
}

func (s *server) requireApplication(ctx context.Context, tenant, applicationID string) error {
	var found string
	return s.db.QueryRowContext(ctx, `SELECT id FROM tenant_applications WHERE tenant_id=? AND id=?`, tenant, applicationID).Scan(&found)
}

func (s *server) getStorageConfig(c *gin.Context) {
	record, err := s.loadStorageRecord(c.Request.Context(), tenantID(c), 0)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(200, gin.H{"configured": false, "version": 0, "credentialsConfigured": false, "sessionTokenConfigured": false})
		return
	}
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_QUERY_FAILED", "Unable to load storage configuration")
		return
	}
	c.JSON(200, storageView(record))
}

func (s *server) putStorageConfig(c *gin.Context) {
	var body struct {
		Provider        string `json:"provider"`
		Endpoint        string `json:"endpoint"`
		Region          string `json:"region"`
		Bucket          string `json:"bucket"`
		ObjectPrefix    string `json:"objectPrefix"`
		ForcePathStyle  bool   `json:"forcePathStyle"`
		PublicBaseURL   string `json:"publicBaseUrl"`
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
		ExpectedVersion int    `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_STORAGE_CONFIG", "Invalid storage configuration")
		return
	}
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	body.Endpoint, body.Region, body.Bucket = strings.TrimSpace(body.Endpoint), strings.TrimSpace(body.Region), strings.TrimSpace(body.Bucket)
	body.ObjectPrefix = cleanObjectPrefix(body.ObjectPrefix)
	body.PublicBaseURL = strings.TrimRight(strings.TrimSpace(body.PublicBaseURL), "/")
	endpointRequired := body.Provider == "r2" || body.Provider == "minio"
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || !oneOf(body.Provider, "s3", "r2", "minio") || body.Region == "" || !storageBucketPattern.MatchString(body.Bucket) || (body.ObjectPrefix != "" && !objectPrefixPattern.MatchString(body.ObjectPrefix)) || body.ExpectedVersion < 0 || (endpointRequired && body.Endpoint == "") || !validStorageURL(body.Endpoint, true, s.cfg.Environment) || !validStorageURL(body.PublicBaseURL, true, s.cfg.Environment) {
		problem(c, 400, "INVALID_STORAGE_CONFIG", "Provider, endpoint, region, bucket, version, reason and confirm=true are invalid")
		return
	}
	current, err := s.loadStorageRecord(c.Request.Context(), tenantID(c), 0)
	if errors.Is(err, sql.ErrNoRows) {
		if body.ExpectedVersion != 0 {
			problem(c, 409, "STALE_STORAGE_CONFIG", "Storage configuration changed; refresh and retry")
			return
		}
		current = storageRecord{TenantID: tenantID(c)}
	} else if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to load storage configuration")
		return
	} else if body.ExpectedVersion != current.Version {
		problem(c, 409, "STALE_STORAGE_CONFIG", "Storage configuration changed; refresh and retry")
		return
	}
	existingSecrets, err := s.decryptStorageSecrets(current)
	if err != nil {
		problem(c, 500, "STORAGE_SECRET_UNAVAILABLE", "Stored credentials cannot be decrypted")
		return
	}
	if body.AccessKeyID != "" || body.SecretAccessKey != "" || body.SessionToken != "" {
		if body.AccessKeyID == "" || body.SecretAccessKey == "" {
			problem(c, 400, "INVALID_STORAGE_CREDENTIALS", "Access key and secret key must be replaced together")
			return
		}
		existingSecrets = storageSecrets{AccessKeyID: strings.TrimSpace(body.AccessKeyID), SecretAccessKey: body.SecretAccessKey, SessionToken: body.SessionToken}
	}
	if existingSecrets.AccessKeyID == "" || existingSecrets.SecretAccessKey == "" {
		problem(c, 400, "INVALID_STORAGE_CREDENTIALS", "Access key and secret key are required")
		return
	}
	newVersion := current.Version + 1
	box, err := s.secretBox()
	if err != nil {
		problem(c, 503, "STORAGE_ENCRYPTION_UNAVAILABLE", "Storage credential encryption is not configured")
		return
	}
	accessCipher, err := box.Encrypt(existingSecrets.AccessKeyID, storageAAD(tenantID(c), newVersion, "access-key"))
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to encrypt storage credentials")
		return
	}
	secretCipher, err := box.Encrypt(existingSecrets.SecretAccessKey, storageAAD(tenantID(c), newVersion, "secret-key"))
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to encrypt storage credentials")
		return
	}
	tokenCipher, err := box.Encrypt(existingSecrets.SessionToken, storageAAD(tenantID(c), newVersion, "session-token"))
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to encrypt storage credentials")
		return
	}
	now := time.Now().UTC()
	record := storageRecord{TenantID: tenantID(c), Version: newVersion, Provider: body.Provider, Endpoint: body.Endpoint, Region: body.Region, Bucket: body.Bucket, ObjectPrefix: body.ObjectPrefix, ForcePathStyle: body.ForcePathStyle, PublicBaseURL: body.PublicBaseURL, AccessKeyCipher: accessCipher, SecretKeyCipher: secretCipher, SessionTokenCipher: tokenCipher, AccessKeyHint: maskAccessKey(existingSecrets.AccessKeyID), UpdatedBy: actor(c), CreatedAt: now, UpdatedAt: now}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save storage configuration")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO tenant_storage_configs(tenant_id,version,provider,endpoint,region,bucket,object_prefix,force_path_style,public_base_url,access_key_id_encrypted,secret_access_key_encrypted,session_token_encrypted,access_key_hint,updated_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, record.TenantID, record.Version, record.Provider, nullableString(record.Endpoint), record.Region, record.Bucket, record.ObjectPrefix, record.ForcePathStyle, nullableString(record.PublicBaseURL), nullableBytes(record.AccessKeyCipher), nullableBytes(record.SecretKeyCipher), nullableBytes(record.SessionTokenCipher), nullableString(record.AccessKeyHint), record.UpdatedBy, now, now)
	if err != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save storage configuration")
		return
	}
	event := newAudit(tenantID(c), actor(c), "storage_config_update", "storage-config", tenantID(c), body.Reason, requestID(c), map[string]any{"provider": record.Provider, "bucket": record.Bucket, "version": record.Version})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save storage configuration")
		return
	}
	c.JSON(200, storageView(record))
}

func (s *server) testStorageConfig(c *gin.Context) {
	record, client, err := s.storageClient(c.Request.Context(), tenantID(c), 0)
	if err != nil {
		problem(c, 409, "STORAGE_CONFIG_REQUIRED", "Configure storage before testing it")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	if err := client.Test(ctx); err != nil {
		problem(c, 502, "STORAGE_CONNECTION_FAILED", "Unable to access the configured bucket")
		return
	}
	c.JSON(200, gin.H{"ok": true, "provider": record.Provider, "bucket": record.Bucket, "checkedAt": iso(time.Now())})
}

func (s *server) loadStorageRecord(ctx context.Context, tenant string, version int) (storageRecord, error) {
	var record storageRecord
	var endpoint, publicURL, hint sql.NullString
	query := `SELECT tenant_id,version,provider,endpoint,region,bucket,object_prefix,force_path_style,public_base_url,access_key_id_encrypted,secret_access_key_encrypted,session_token_encrypted,access_key_hint,updated_by,created_at,updated_at FROM tenant_storage_configs WHERE tenant_id=?`
	args := []any{tenant}
	if version > 0 {
		query += ` AND version=?`
		args = append(args, version)
	} else {
		query += ` ORDER BY version DESC LIMIT 1`
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&record.TenantID, &record.Version, &record.Provider, &endpoint, &record.Region, &record.Bucket, &record.ObjectPrefix, &record.ForcePathStyle, &publicURL, &record.AccessKeyCipher, &record.SecretKeyCipher, &record.SessionTokenCipher, &hint, &record.UpdatedBy, &record.CreatedAt, &record.UpdatedAt)
	record.Endpoint, record.PublicBaseURL, record.AccessKeyHint = endpoint.String, publicURL.String, hint.String
	return record, err
}

func (s *server) decryptStorageSecrets(record storageRecord) (storageSecrets, error) {
	if record.Version == 0 {
		return storageSecrets{}, nil
	}
	if len(record.AccessKeyCipher)+len(record.SecretKeyCipher)+len(record.SessionTokenCipher) == 0 {
		return storageSecrets{}, nil
	}
	box, err := s.secretBox()
	if err != nil {
		return storageSecrets{}, err
	}
	access, err := box.Decrypt(record.AccessKeyCipher, storageAAD(record.TenantID, record.Version, "access-key"))
	if err != nil {
		return storageSecrets{}, err
	}
	secret, err := box.Decrypt(record.SecretKeyCipher, storageAAD(record.TenantID, record.Version, "secret-key"))
	if err != nil {
		return storageSecrets{}, err
	}
	token, err := box.Decrypt(record.SessionTokenCipher, storageAAD(record.TenantID, record.Version, "session-token"))
	return storageSecrets{AccessKeyID: access, SecretAccessKey: secret, SessionToken: token}, err
}

func (s *server) storageClient(ctx context.Context, tenant string, version int) (storageRecord, objectstore.Client, error) {
	record, err := s.loadStorageRecord(ctx, tenant, version)
	if err != nil {
		return storageRecord{}, nil, err
	}
	secrets, err := s.decryptStorageSecrets(record)
	if err != nil {
		return storageRecord{}, nil, err
	}
	client, err := s.objects.New(objectstore.Config{Endpoint: record.Endpoint, Region: record.Region, Bucket: record.Bucket, AccessKeyID: secrets.AccessKeyID, SecretAccessKey: secrets.SecretAccessKey, SessionToken: secrets.SessionToken, ForcePathStyle: record.ForcePathStyle})
	return record, client, err
}

func storageView(record storageRecord) gin.H {
	return gin.H{"configured": true, "version": record.Version, "provider": record.Provider, "endpoint": nullableString(record.Endpoint), "region": record.Region, "bucket": record.Bucket, "objectPrefix": record.ObjectPrefix, "forcePathStyle": record.ForcePathStyle, "publicBaseUrl": nullableString(record.PublicBaseURL), "accessKeyHint": nullableString(record.AccessKeyHint), "credentialsConfigured": len(record.AccessKeyCipher) > 0 && len(record.SecretKeyCipher) > 0, "sessionTokenConfigured": len(record.SessionTokenCipher) > 0, "updatedBy": record.UpdatedBy, "updatedAt": iso(record.UpdatedAt)}
}

func (s *server) listArtifacts(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), artifactSelect+` WHERE tenant_id=? ORDER BY created_at DESC LIMIT 200`, tenantID(c))
	if err != nil {
		problem(c, 500, "ARTIFACT_QUERY_FAILED", "Unable to load artifacts")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		item, err := scanArtifact(rows)
		if err != nil {
			problem(c, 500, "ARTIFACT_QUERY_FAILED", "Unable to load artifacts")
			return
		}
		items = append(items, artifactView(item))
	}
	c.JSON(200, gin.H{"items": items})
}

func (s *server) createArtifactUpload(c *gin.Context) {
	var body struct {
		ApplicationID string `json:"applicationId"`
		FileName      string `json:"fileName"`
		ContentType   string `json:"contentType"`
		Size          int64  `json:"size"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_ARTIFACT_UPLOAD", "Invalid artifact upload payload")
		return
	}
	body.ApplicationID, body.FileName, body.ContentType = strings.TrimSpace(body.ApplicationID), path.Base(strings.TrimSpace(body.FileName)), strings.ToLower(strings.TrimSpace(body.ContentType))
	if s.requireApplication(c.Request.Context(), tenantID(c), body.ApplicationID) != nil || body.FileName == "." || body.FileName == "" || !strings.EqualFold(path.Ext(body.FileName), ".apk") || !oneOf(body.ContentType, "application/vnd.android.package-archive", "application/octet-stream") || body.Size < 1 || body.Size > s.cfg.ArtifactMaxSizeBytes {
		problem(c, 400, "INVALID_ARTIFACT_UPLOAD", "A configured application and valid APK up to the configured size limit are required")
		return
	}
	record, client, err := s.storageClient(c.Request.Context(), tenantID(c), 0)
	if err != nil {
		problem(c, 409, "STORAGE_CONFIG_REQUIRED", "Configure and test tenant storage before uploading")
		return
	}
	id := "artifact_" + randomID(16)
	objectKey := buildObjectKey(record.ObjectPrefix, tenantID(c), id, body.FileName)
	uploadURL, headers, err := client.PresignPut(c.Request.Context(), objectKey, body.ContentType, body.Size, time.Duration(s.cfg.ArtifactUploadTTL)*time.Second)
	if err != nil {
		problem(c, 502, "ARTIFACT_UPLOAD_CREATE_FAILED", "Unable to create a storage upload URL")
		return
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(c.Request.Context(), `INSERT INTO artifacts(id,tenant_id,application_id,storage_config_version,object_key,file_name,content_type,expected_size,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, id, tenantID(c), body.ApplicationID, record.Version, objectKey, body.FileName, body.ContentType, body.Size, "pending", actor(c), now, now)
	if err != nil {
		problem(c, 500, "ARTIFACT_UPLOAD_CREATE_FAILED", "Unable to create artifact record")
		return
	}
	artifact, _ := s.findArtifact(c.Request.Context(), tenantID(c), id)
	c.JSON(201, gin.H{"artifact": artifactView(artifact), "upload": gin.H{"method": "PUT", "url": uploadURL, "headers": headers, "expiresAt": iso(now.Add(time.Duration(s.cfg.ArtifactUploadTTL) * time.Second))}})
}

func (s *server) finalizeArtifact(c *gin.Context) {
	artifact, err := s.findArtifact(c.Request.Context(), tenantID(c), c.Param("id"))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "ARTIFACT_NOT_FOUND", "Artifact not found")
		return
	}
	if err != nil {
		problem(c, 500, "ARTIFACT_QUERY_FAILED", "Unable to load artifact")
		return
	}
	if artifact.Status == "verified" {
		c.JSON(200, gin.H{"artifact": artifactView(artifact)})
		return
	}
	if artifact.Status == "rejected" {
		problem(c, 409, "ARTIFACT_REJECTED", "Rejected artifacts cannot be finalized again")
		return
	}
	_, client, err := s.storageClient(c.Request.Context(), tenantID(c), artifact.StorageConfigVersion)
	if err != nil {
		problem(c, 503, "STORAGE_CONFIG_UNAVAILABLE", "Artifact storage configuration is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	size, _, err := client.Head(ctx, artifact.ObjectKey)
	if err != nil {
		problem(c, 409, "ARTIFACT_UPLOAD_INCOMPLETE", "Uploaded object is not available yet")
		return
	}
	if size != artifact.ExpectedSize || size > s.cfg.ArtifactMaxSizeBytes {
		s.rejectArtifact(c, artifact, "Uploaded object size does not match the requested APK size")
		return
	}
	body, err := client.Get(ctx, artifact.ObjectKey)
	if err != nil {
		problem(c, 502, "ARTIFACT_READ_FAILED", "Unable to read uploaded artifact")
		return
	}
	defer body.Close()
	temporary, err := os.CreateTemp("", "rn-artifact-*.apk")
	if err != nil {
		problem(c, 500, "ARTIFACT_VERIFY_FAILED", "Unable to prepare artifact verification")
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	written, copyErr := io.Copy(temporary, io.LimitReader(body, s.cfg.ArtifactMaxSizeBytes+1))
	closeErr := temporary.Close()
	if copyErr != nil || closeErr != nil || written != size {
		problem(c, 502, "ARTIFACT_READ_FAILED", "Unable to read the complete uploaded artifact")
		return
	}
	metadata, err := apkinspect.Inspect(temporaryPath)
	if err != nil {
		s.rejectArtifact(c, artifact, "APK structure or signature verification failed")
		return
	}
	var packageName string
	var expectedSigner sql.NullString
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT package_name,expected_signer_sha256 FROM tenant_applications WHERE tenant_id=? AND id=?`, tenantID(c), artifact.ApplicationID).Scan(&packageName, &expectedSigner); err != nil {
		problem(c, 409, "APPLICATION_NOT_FOUND", "Artifact application is no longer configured")
		return
	}
	if metadata.PackageName != packageName {
		s.rejectArtifact(c, artifact, "APK package name does not match the configured application")
		return
	}
	if !expectedSigner.Valid || !strings.EqualFold(metadata.SignerSHA256, expectedSigner.String) {
		s.rejectArtifact(c, artifact, "APK signer SHA-256 does not match the configured application signer")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "ARTIFACT_VERIFY_FAILED", "Unable to save artifact verification")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `UPDATE artifacts SET size=?,sha256=?,package_name=?,version_name=?,version_code=?,min_sdk=?,signer_sha256=?,signing_scheme=?,signer_subject=?,status='verified',rejection_reason=NULL,verified_at=?,updated_at=? WHERE tenant_id=? AND id=? AND status='pending'`, metadata.Size, metadata.SHA256, metadata.PackageName, metadata.VersionName, metadata.VersionCode, metadata.MinSDK, metadata.SignerSHA256, metadata.SigningScheme, metadata.SignerCertificate, now, now, tenantID(c), artifact.ID)
	affected := int64(0)
	if err == nil {
		affected, err = result.RowsAffected()
	}
	if err != nil || affected != 1 {
		problem(c, 409, "ARTIFACT_STATE_CHANGED", "Artifact state changed while it was being verified")
		return
	}
	event := newAudit(tenantID(c), actor(c), "artifact_verified", "artifact", artifact.ID, "Server verified APK identity and signature", requestID(c), map[string]any{"applicationId": artifact.ApplicationID, "packageName": metadata.PackageName, "versionName": metadata.VersionName, "versionCode": metadata.VersionCode, "sha256": metadata.SHA256})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "ARTIFACT_VERIFY_FAILED", "Unable to save artifact verification")
		return
	}
	verified, _ := s.findArtifact(c.Request.Context(), tenantID(c), artifact.ID)
	c.JSON(200, gin.H{"artifact": artifactView(verified)})
}

func (s *server) rejectArtifact(c *gin.Context, artifact artifactRecord, reason string) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err == nil {
		_, err = tx.ExecContext(c.Request.Context(), `UPDATE artifacts SET status='rejected',rejection_reason=?,updated_at=? WHERE tenant_id=? AND id=? AND status='pending'`, reason, now, tenantID(c), artifact.ID)
	}
	if err == nil {
		event := newAudit(tenantID(c), actor(c), "artifact_rejected", "artifact", artifact.ID, reason, requestID(c), map[string]any{"applicationId": artifact.ApplicationID, "status": "rejected"})
		err = insertAudit(c.Request.Context(), tx, event)
	}
	if err == nil {
		err = tx.Commit()
	} else if tx != nil {
		_ = tx.Rollback()
	}
	if err != nil {
		problem(c, 500, "ARTIFACT_VERIFY_FAILED", "Unable to save artifact rejection")
		return
	}
	problem(c, 422, "APK_VERIFICATION_FAILED", reason)
}

const artifactSelect = `SELECT id,tenant_id,application_id,storage_config_version,object_key,file_name,content_type,expected_size,size,sha256,package_name,version_name,version_code,min_sdk,signer_sha256,signing_scheme,signer_subject,status,rejection_reason,created_by,verified_at,created_at,updated_at FROM artifacts`

type rowScanner interface{ Scan(...any) error }

func scanArtifact(row rowScanner) (artifactRecord, error) {
	var item artifactRecord
	err := row.Scan(&item.ID, &item.TenantID, &item.ApplicationID, &item.StorageConfigVersion, &item.ObjectKey, &item.FileName, &item.ContentType, &item.ExpectedSize, &item.Size, &item.SHA256, &item.PackageName, &item.VersionName, &item.VersionCode, &item.MinSDK, &item.SignerSHA256, &item.SigningScheme, &item.SignerSubject, &item.Status, &item.RejectionReason, &item.CreatedBy, &item.VerifiedAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *server) findArtifact(ctx context.Context, tenant, id string) (artifactRecord, error) {
	return scanArtifact(s.db.QueryRowContext(ctx, artifactSelect+` WHERE tenant_id=? AND id=?`, tenant, id))
}

func artifactView(item artifactRecord) gin.H {
	return gin.H{"id": item.ID, "applicationId": item.ApplicationID, "fileName": item.FileName, "contentType": item.ContentType, "expectedSize": item.ExpectedSize, "size": nullableInt64(item.Size), "sha256": nullableSQLString(item.SHA256), "packageName": nullableSQLString(item.PackageName), "versionName": nullableSQLString(item.VersionName), "versionCode": nullableInt64(item.VersionCode), "minSdk": nullableInt64(item.MinSDK), "minOsVersion": minOSVersion(item.MinSDK), "signerSha256": nullableSQLString(item.SignerSHA256), "signingFingerprint": nullableSQLString(item.SignerSHA256), "signingScheme": nullableInt64(item.SigningScheme), "status": item.Status, "rejectionReason": nullableSQLString(item.RejectionReason), "verifiedAt": nullableTime(item.VerifiedAt), "createdAt": iso(item.CreatedAt), "updatedAt": iso(item.UpdatedAt), "downloadUrl": nil}
}

func (s *server) artifactForRelease(ctx context.Context, tenant, artifactID, applicationID, version string, build int) (map[string]any, error) {
	item, err := s.findArtifact(ctx, tenant, artifactID)
	if err != nil || item.Status != "verified" || item.ApplicationID != applicationID || !item.VersionName.Valid || item.VersionName.String != version || !item.VersionCode.Valid || item.VersionCode.Int64 != int64(build) {
		return nil, errors.New("artifact identity mismatch")
	}
	view := artifactView(item)
	view["downloadUrl"] = "/v1/public/artifacts/" + item.ID + "/download"
	return view, nil
}

func (s *server) artifactStillVerified(ctx context.Context, tenant, artifactID string) error {
	var status string
	return s.db.QueryRowContext(ctx, `SELECT status FROM artifacts WHERE tenant_id=? AND id=? AND status='verified'`, tenant, artifactID).Scan(&status)
}

func (s *server) activeDirectRelease(ctx context.Context, tenant, applicationID string) (release, map[string]any, error) {
	r, err := scanRelease(s.db.QueryRowContext(ctx, `SELECT id,application_id,platform,version,build_number,runtime_version,channel,status,release_notes,artifact,rollout,activated_at,last_action,created_at,updated_at,artifact_id FROM app_releases WHERE tenant_id=? AND application_id=? AND platform='android' AND channel='direct' AND status='active' ORDER BY activated_at DESC LIMIT 1`, tenant, applicationID))
	if err != nil || r.ArtifactID == nil {
		return release{}, nil, sql.ErrNoRows
	}
	artifact, err := s.findArtifact(ctx, tenant, *r.ArtifactID)
	if err != nil || artifact.Status != "verified" {
		return release{}, nil, sql.ErrNoRows
	}
	return r, artifactView(artifact), nil
}

func (s *server) publicLatestRelease(c *gin.Context) {
	tenant, err := s.resolveTenant(c.Request.Context(), c.Param("tenantSlug"))
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Active direct release not found")
		return
	}
	r, artifact, err := s.activeDirectRelease(c.Request.Context(), tenant.ID, c.Param("applicationId"))
	if err != nil {
		problem(c, 404, "RELEASE_NOT_FOUND", "Active direct release not found")
		return
	}
	downloadURL := absoluteURL(c, "/v1/public/artifacts/"+fmt.Sprint(artifact["id"])+"/download")
	artifact["downloadUrl"] = downloadURL
	c.Header("Cache-Control", "public, max-age=60")
	c.JSON(200, gin.H{"tenant": gin.H{"slug": tenant.Slug, "name": tenant.Name}, "applicationId": r.ApplicationID, "version": r.Version, "buildNumber": r.BuildNumber, "releaseNotes": r.ReleaseNotes, "artifact": artifact, "downloadUrl": downloadURL, "publishedAt": r.ActivatedAt})
}

func (s *server) publicArtifactDownload(c *gin.Context) {
	var tenant, fileName string
	var storageVersion int
	var objectKey string
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT a.tenant_id,a.storage_config_version,a.object_key,a.file_name FROM artifacts a JOIN app_releases r ON r.tenant_id=a.tenant_id AND r.artifact_id=a.id WHERE a.id=? AND a.status='verified' AND r.status='active' AND r.channel='direct' LIMIT 1`, c.Param("id")).Scan(&tenant, &storageVersion, &objectKey, &fileName)
	if err != nil {
		problem(c, 404, "ARTIFACT_NOT_FOUND", "Published artifact not found")
		return
	}
	record, client, err := s.storageClient(c.Request.Context(), tenant, storageVersion)
	if err != nil {
		problem(c, 503, "ARTIFACT_STORAGE_UNAVAILABLE", "Artifact storage is unavailable")
		return
	}
	if record.PublicBaseURL != "" {
		base, parseErr := url.Parse(record.PublicBaseURL + "/")
		if parseErr == nil {
			base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(objectKey, "/")
			c.Redirect(http.StatusTemporaryRedirect, base.String())
			return
		}
	}
	downloadURL, err := client.PresignGet(c.Request.Context(), objectKey, time.Duration(s.cfg.ArtifactDownloadTTL)*time.Second, fileName)
	if err != nil {
		problem(c, 502, "ARTIFACT_DOWNLOAD_FAILED", "Unable to create artifact download URL")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusTemporaryRedirect, downloadURL)
}

func storageAAD(tenant string, version int, field string) string {
	return tenant + ":" + strconv.Itoa(version) + ":" + field
}

func buildObjectKey(prefix, tenant, artifactID, _ string) string {
	parts := []string{cleanObjectPrefix(prefix), "tenants", tenant, "artifacts", artifactID, "application.apk"}
	return strings.TrimLeft(path.Join(parts...), "/")
}

func cleanObjectPrefix(prefix string) string {
	clean := strings.Trim(path.Clean(strings.TrimSpace(prefix)), "/")
	if clean == "." || strings.HasPrefix(clean, "..") {
		return ""
	}
	return clean
}

func validStorageURL(raw string, optional bool, environment string) bool {
	if raw == "" {
		return optional
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return environment != "production" || parsed.Scheme == "https"
}

func maskAccessKey(value string) string {
	if len(value) <= 4 {
		return ""
	}
	return "••••" + value[len(value)-4:]
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableSQLString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullableInt64(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return iso(value.Time)
}

func minOSVersion(value sql.NullInt64) string {
	if !value.Valid {
		return ""
	}
	return "API " + strconv.FormatInt(value.Int64, 10)
}

func absoluteURL(c *gin.Context, route string) string {
	scheme := c.GetHeader("X-Forwarded-Proto")
	if scheme != "https" && scheme != "http" {
		if c.Request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + c.Request.Host + route
}
