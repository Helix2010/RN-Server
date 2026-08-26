package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

const releaseStorageConfigKey = "release.storage"

type storedReleaseStorage struct {
	Provider                 string `json:"provider"`
	Endpoint                 string `json:"endpoint,omitempty"`
	Region                   string `json:"region"`
	Bucket                   string `json:"bucket"`
	ObjectPrefix             string `json:"objectPrefix,omitempty"`
	PublicBaseURL            string `json:"publicBaseUrl,omitempty"`
	ForcePathStyle           bool   `json:"forcePathStyle"`
	AccessKeyIDEncrypted     string `json:"accessKeyIdEncrypted,omitempty"`
	SecretAccessKeyEncrypted string `json:"secretAccessKeyEncrypted,omitempty"`
	SessionTokenEncrypted    string `json:"sessionTokenEncrypted,omitempty"`
}

type releaseStorageWrite struct {
	Provider         string `json:"provider"`
	Endpoint         string `json:"endpoint"`
	Region           string `json:"region"`
	Bucket           string `json:"bucket"`
	ObjectPrefix     string `json:"objectPrefix"`
	PublicBaseURL    string `json:"publicBaseUrl"`
	ForcePathStyle   bool   `json:"forcePathStyle"`
	AccessKeyID      string `json:"accessKeyId"`
	SecretAccessKey  string `json:"secretAccessKey"`
	SessionToken     string `json:"sessionToken"`
	ClearCredentials bool   `json:"clearCredentials"`
	ExpectedVersion  int    `json:"expectedVersion"`
	Reason           string `json:"reason"`
	Confirm          bool   `json:"confirm"`
}

type releaseStorageRecord struct {
	Value        storedReleaseStorage
	SourceTenant string
	Version      int
	UpdatedBy    string
	UpdatedAt    time.Time
}

func (s *server) getReleaseStorage(c *gin.Context) {
	record, err := s.releaseStorageRecord(c.Request.Context(), tenantID(c))
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusOK, releaseStorageView(releaseStorageRecord{}, tenantID(c)))
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_QUERY_FAILED", "Unable to load release storage configuration")
		return
	}
	c.JSON(http.StatusOK, releaseStorageView(record, tenantID(c)))
}

func (s *server) updateReleaseStorage(c *gin.Context) {
	var body releaseStorageWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_STORAGE_CONFIG", "Storage config, expectedVersion, reason and confirm=true are required")
		return
	}
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	body.Endpoint = strings.TrimRight(strings.TrimSpace(body.Endpoint), "/")
	body.Region = strings.TrimSpace(body.Region)
	body.Bucket = strings.TrimSpace(body.Bucket)
	body.ObjectPrefix = strings.Trim(strings.TrimSpace(body.ObjectPrefix), "/")
	body.PublicBaseURL = strings.TrimRight(strings.TrimSpace(body.PublicBaseURL), "/")
	body.AccessKeyID = strings.TrimSpace(body.AccessKeyID)
	if err := validateReleaseStorageWrite(body); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_STORAGE_CONFIG", err.Error())
		return
	}

	current, err := s.releaseStorageRecord(c.Request.Context(), tenantID(c))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_QUERY_FAILED", "Unable to load release storage configuration")
		return
	}
	currentVersion := 0
	if err == nil {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_STORAGE_CONFIG", "Release storage configuration changed; refresh and retry")
		return
	}

	value := storedReleaseStorage{
		Provider: body.Provider, Endpoint: body.Endpoint, Region: body.Region, Bucket: body.Bucket,
		ObjectPrefix: body.ObjectPrefix, PublicBaseURL: body.PublicBaseURL, ForcePathStyle: body.ForcePathStyle,
	}
	if !body.ClearCredentials && body.AccessKeyID == "" && body.SecretAccessKey == "" && body.SessionToken == "" && err == nil {
		accessKeyID, secretAccessKey, sessionToken, decryptErr := s.decryptReleaseStorage(current)
		if decryptErr != nil {
			problem(c, http.StatusInternalServerError, "STORAGE_SECRET_UNAVAILABLE", "Stored release storage credentials cannot be decrypted")
			return
		}
		body.AccessKeyID, body.SecretAccessKey, body.SessionToken = accessKeyID, secretAccessKey, sessionToken
	}
	if body.AccessKeyID != "" || body.SecretAccessKey != "" || body.SessionToken != "" {
		if s.secrets == nil {
			problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "STORAGE_MASTER_KEY is required before saving storage credentials")
			return
		}
		value.AccessKeyIDEncrypted, err = s.encryptStorageSecret(body.AccessKeyID, tenantID(c), "accessKeyId")
		if err == nil {
			value.SecretAccessKeyEncrypted, err = s.encryptStorageSecret(body.SecretAccessKey, tenantID(c), "secretAccessKey")
		}
		if err == nil {
			value.SessionTokenEncrypted, err = s.encryptStorageSecret(body.SessionToken, tenantID(c), "sessionToken")
		}
		if err != nil {
			problem(c, http.StatusInternalServerError, "STORAGE_SECRET_SAVE_FAILED", "Unable to encrypt release storage credentials")
			return
		}
	}
	raw, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save release storage configuration")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if current.SourceTenant == tenantID(c) {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), releaseStorageConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), releaseStorageConfigKey, raw, actor(c), now, tenantID(c), releaseStorageConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save release storage configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_STORAGE_CONFIG", "Release storage configuration changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "release_storage_update", "app-config", releaseStorageConfigKey, body.Reason, requestID(c), map[string]any{"provider": body.Provider, "bucket": body.Bucket, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_SAVE_FAILED", "Unable to save release storage configuration")
		return
	}
	c.JSON(http.StatusOK, releaseStorageView(releaseStorageRecord{Value: value, SourceTenant: tenantID(c), Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}, tenantID(c)))
}

func (s *server) testReleaseStorage(c *gin.Context) {
	record, err := s.releaseStorageRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusPreconditionFailed, "STORAGE_NOT_CONFIGURED", "Release storage is not configured for this tenant")
		return
	}
	client, err := s.storageClient(record)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage configuration is invalid")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	if err := client.Test(ctx); err != nil {
		slog.Error("release storage connectivity test failed", "provider", record.Value.Provider, "endpoint", record.Value.Endpoint, "bucket", record.Value.Bucket, "error", err)
		problem(c, http.StatusBadGateway, "STORAGE_TEST_FAILED", "Unable to access the configured release storage bucket")
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "provider": record.Value.Provider, "bucket": record.Value.Bucket, "checkedAt": iso(time.Now())})
}

func (s *server) releaseStorageRecord(ctx context.Context, tenant string) (releaseStorageRecord, error) {
	var record releaseStorageRecord
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs WHERE config_key=? AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`, releaseStorageConfigKey, tenant, tenant).Scan(&record.SourceTenant, &raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return record, err
	}
	return record, nil
}

func (s *server) storageClient(record releaseStorageRecord) (objectstore.Client, error) {
	accessKeyID, secretAccessKey, sessionToken, err := s.decryptReleaseStorage(record)
	if err != nil {
		return nil, err
	}
	return s.objects.New(objectstore.Config{
		Endpoint: record.Value.Endpoint, Region: record.Value.Region, Bucket: record.Value.Bucket,
		AccessKeyID: accessKeyID, SecretAccessKey: secretAccessKey, SessionToken: sessionToken,
		ForcePathStyle: record.Value.ForcePathStyle,
	})
}

func (s *server) storageClientForTenant(ctx context.Context, tenant string) (objectstore.Client, string, error) {
	record, err := s.releaseStorageRecord(ctx, tenant)
	if err != nil {
		return nil, "", err
	}
	client, err := s.storageClient(record)
	return client, record.Value.ObjectPrefix, err
}

func (s *server) decryptReleaseStorage(record releaseStorageRecord) (string, string, string, error) {
	if record.Value.AccessKeyIDEncrypted == "" && record.Value.SecretAccessKeyEncrypted == "" && record.Value.SessionTokenEncrypted == "" {
		return "", "", "", nil
	}
	if s.secrets == nil {
		return "", "", "", errors.New("storage master key is unavailable")
	}
	decrypt := func(encoded, field string) (string, error) {
		if encoded == "" {
			return "", nil
		}
		ciphertext, err := base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err
		}
		return s.secrets.Decrypt(ciphertext, storageAssociatedData(record.SourceTenant, field))
	}
	accessKeyID, err := decrypt(record.Value.AccessKeyIDEncrypted, "accessKeyId")
	if err != nil {
		return "", "", "", err
	}
	secretAccessKey, err := decrypt(record.Value.SecretAccessKeyEncrypted, "secretAccessKey")
	if err != nil {
		return "", "", "", err
	}
	sessionToken, err := decrypt(record.Value.SessionTokenEncrypted, "sessionToken")
	return accessKeyID, secretAccessKey, sessionToken, err
}

func (s *server) encryptStorageSecret(value, tenant, field string) (string, error) {
	if value == "" {
		return "", nil
	}
	ciphertext, err := s.secrets.Encrypt(value, storageAssociatedData(tenant, field))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func storageAssociatedData(tenant, field string) string {
	return tenant + ":" + releaseStorageConfigKey + ":" + field
}

func releaseStorageView(record releaseStorageRecord, tenant string) gin.H {
	value := record.Value
	return gin.H{
		"configured": value.Region != "" && value.Bucket != "", "version": record.Version,
		"provider": nullableString(value.Provider), "endpoint": nullableString(value.Endpoint), "region": value.Region,
		"bucket": value.Bucket, "objectPrefix": value.ObjectPrefix, "publicBaseUrl": nullableString(value.PublicBaseURL),
		"forcePathStyle": value.ForcePathStyle, "credentialsConfigured": value.AccessKeyIDEncrypted != "" && value.SecretAccessKeyEncrypted != "",
		"sessionTokenConfigured": value.SessionTokenEncrypted != "", "accessKeyHint": encryptedHint(value.AccessKeyIDEncrypted),
		"inherited": record.SourceTenant != "" && record.SourceTenant != tenant, "updatedBy": record.UpdatedBy,
		"updatedAt": nullableTime(record.UpdatedAt),
	}
}

func validateReleaseStorageWrite(body releaseStorageWrite) error {
	if !oneOf(body.Provider, "s3", "r2", "minio") || body.Region == "" || body.Bucket == "" {
		return errors.New("provider, region and bucket are required")
	}
	if (body.AccessKeyID == "") != (body.SecretAccessKey == "") {
		return errors.New("accessKeyId and secretAccessKey must be provided together")
	}
	for _, raw := range []string{body.Endpoint, body.PublicBaseURL} {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("endpoint and publicBaseUrl must be absolute HTTP(S) URLs")
		}
	}
	return nil
}

func encryptedHint(value string) any {
	if value == "" {
		return nil
	}
	return "已加密保存"
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return iso(value)
}
