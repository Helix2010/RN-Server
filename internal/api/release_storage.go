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
	"sort"
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
	if err := validateReleaseStorageWrite(body, s.cfg.Environment == "production"); err != nil {
		if errors.Is(err, errStorageEndpointInsecure) {
			problem(c, http.StatusUnprocessableEntity, "STORAGE_ENDPOINT_INSECURE", err.Error())
			return
		}
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
		problem(c, http.StatusFailedDependency, "STORAGE_TEST_FAILED", "Unable to access the configured release storage bucket")
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
	if storageEndpointInsecure(record.Value, s.cfg.Environment == "production") {
		// 生产环境不能用 http 存储地址：直传 presigned URL 会以明文下发。配置必须先改成 https
		slog.Error("release storage endpoint is not https; refusing to use it in production", "tenant", record.SourceTenant, "endpoint", record.Value.Endpoint, "publicBaseUrl", record.Value.PublicBaseURL)
		return nil, errStorageEndpointInsecure
	}
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

// errStorageEndpointInsecure：生产环境的对象存储地址必须是 https。直传模式下上传入口就是存储的
// presigned URL，`absoluteURL` 管不到它，所以协议要求落在配置本身上。
var errStorageEndpointInsecure = errors.New("endpoint and publicBaseUrl must use https in production")

func validateReleaseStorageWrite(body releaseStorageWrite, production bool) error {
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
		if production && parsed.Scheme != "https" {
			return errStorageEndpointInsecure
		}
	}
	return nil
}

// storageEndpointInsecure：已保存的配置在生产环境里含 http 地址（改规则前保存的，或直接改库）。
func storageEndpointInsecure(value storedReleaseStorage, production bool) bool {
	if !production {
		return false
	}
	for _, raw := range []string{value.Endpoint, value.PublicBaseURL} {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" {
			return true
		}
	}
	return false
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

// 浏览器直传对象存储时，桶上必须放行控制台的来源，否则预检被拒，而界面上只会显示
// "无法连接对象存储"——票据、签名、写权限全是好的，看不出问题在桶的配置上。
//
// 来源从 tenant_domain 推导，不写进配置文件：加一个租户本来就要往那张表里加域名，
// 再让人去华为云控制台改一次桶策略，是同一件事维护两遍，漏了就是上面那个故障。
//
// **写入的是全平台所有活跃租户域名的并集**。CORS 是桶级配置而不是前缀级的，同一个
// 桶被多个租户共用时，只写当前租户的来源会把其他租户踢掉。
func (s *server) tenantConsoleOrigins(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT LOWER(TRIM(TRAILING '.' FROM d.domain))
		FROM tenant_domain d
		JOIN tenants t ON t.id = d.tenant_id
		WHERE d.status='active' AND d.deleted=0
		  AND (CAST(t.status AS UNSIGNED)=1 OR t.status='active') AND t.deleted=0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var origins []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		origins = append(origins, "https://"+domain)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(origins)
	return origins, nil
}

// 浏览器直传要的那条桶级规则长什么样。**只读**：这个接口不写桶策略。
//
// 曾经写过。做法是保存存储配置时顺手 PutBucketCORS，桶上的规则就跟着 tenant_domain
// 自动更新。它要求发布存储那把 AK/SK 除了对象读写之外还有改桶配置的权限——而那把
// 密钥同时被签发直传票据的路径用着，多给的这份权限在每一次上传里都在场，只为了一
// 件极低频的事（加租户时改一次跨域规则）。按最小权限还原成只读，桶策略回到人工在
// 对象存储控制台上配。
//
// 留下的这半边仍然有用：要配哪些来源是从 tenant_domain 算出来的，加了租户之后调
// 一次就知道该补什么，不用去翻配置文件，也不会漏。
func (s *server) bucketCORSRequirements(c *gin.Context) {
	origins, err := s.tenantConsoleOrigins(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANT_DOMAIN_QUERY_FAILED", "Unable to list tenant domains")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"allowedOrigins": origins,
		"allowedMethods": []string{"PUT", "GET", "HEAD"},
		"allowedHeaders": []string{"*"},
		"exposeHeaders":  []string{"ETag"},
		"maxAgeSeconds":  3600,
		"note": "把这条规则配到发布存储那个桶上（对象存储控制台 → 桶 → 跨域规则）。" +
			"服务端不会替你写：发布存储的访问密钥按最小权限只有对象读写，没有改桶配置的权限。",
	})
}
