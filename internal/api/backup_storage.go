package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/objectstore"
)

// 备份桶的配置在控制台上维护（设计 §6.1、§8.2）。
//
// 为什么落库而不是只认 env：换一次桶、轮一次凭据不该需要改 env 再重启整个后端
// ——那是平台管理员做的日常运维，不是一次部署。
//
// env 仍然是回退，而且这条回退很要紧：**桶凭据落库之后是用 STORAGE_MASTER_KEY
// 加密的，而那把钥匙在 rn-foundation.env 里。库没了的那一天，库里这份读不出来。**
// 所以 env 里那份不是冗余，它是「库也没了」那个场景下唯一还能拿到桶的东西。
// 控制台上会把这句话写给运维看。
const backupBucketConfigKey = "backup.bucket"

type storedBackupBucket struct {
	Provider                 string `json:"provider,omitempty"`
	ForcePathStyle           bool   `json:"forcePathStyle,omitempty"`
	Endpoint                 string `json:"endpoint,omitempty"`
	Region                   string `json:"region"`
	Bucket                   string `json:"bucket"`
	Prefix                   string `json:"prefix,omitempty"`
	AccessKeyIDEncrypted     string `json:"accessKeyIdEncrypted,omitempty"`
	SecretAccessKeyEncrypted string `json:"secretAccessKeyEncrypted,omitempty"`
}

type backupBucketRecord struct {
	Value     storedBackupBucket
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func backupBucketAssociatedData(field string) string {
	return platformTenantID + ":" + backupBucketConfigKey + ":" + field
}

// resolveBackupBucket 取当前生效的桶配置：库里配了就用库里的，否则用 env。
func (s *server) resolveBackupBucket(ctx context.Context) (config.BackupBucket, string, error) {
	record, err := s.backupBucketRecord(ctx)
	if err != nil {
		return config.BackupBucket{}, "", err
	}
	if record == nil || strings.TrimSpace(record.Value.Bucket) == "" {
		return applyBackupBucketDefaults(s.cfg.Backup.Bucket), "env", nil
	}
	out := config.BackupBucket{
		Provider:       record.Value.Provider,
		ForcePathStyle: record.Value.ForcePathStyle,
		Endpoint:       record.Value.Endpoint,
		Region:         record.Value.Region,
		Bucket:         record.Value.Bucket,
		Prefix:         record.Value.Prefix,
	}
	// 凭据没填就沿用 env 的那一份：允许「桶名落库、凭据仍在 env」这种过渡状态
	out.AccessKeyID, out.SecretAccessKey = s.cfg.Backup.Bucket.AccessKeyID, s.cfg.Backup.Bucket.SecretAccessKey
	if record.Value.AccessKeyIDEncrypted != "" {
		id, err := s.decryptBackupBucketField(record.Value.AccessKeyIDEncrypted, "accessKeyId")
		if err != nil {
			return config.BackupBucket{}, "", err
		}
		secret, err := s.decryptBackupBucketField(record.Value.SecretAccessKeyEncrypted, "secretAccessKey")
		if err != nil {
			return config.BackupBucket{}, "", err
		}
		out.AccessKeyID, out.SecretAccessKey = id, secret
	}
	return applyBackupBucketDefaults(out), "console", nil
}

// applyBackupBucketDefaults 补上 provider 和 path style。
//
// 这两项是后加的。老配置（库里那条 JSON 或者 env）里没有它们，而 ForcePathStyle
// 的零值是 false——直接用零值会让一个本来连得上的 MinIO 桶在升级之后连不上，
// 而备份是无人值守跑的，没人在现场看那条错误。所以：**只有在 provider 也没有的
// 时候**才认定是老配置，沿用以前那条推断（填了 endpoint 就开）。
func applyBackupBucketDefaults(bucket config.BackupBucket) config.BackupBucket {
	if strings.TrimSpace(bucket.Provider) == "" {
		bucket.Provider = "s3"
		bucket.ForcePathStyle = strings.TrimSpace(bucket.Endpoint) != ""
	}
	return bucket
}

func (s *server) decryptBackupBucketField(encoded, field string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if s.secrets == nil {
		return "", errors.New("STORAGE_MASTER_KEY is not configured, so the stored bucket credentials cannot be read")
	}
	return s.secrets.Decrypt(raw, backupBucketAssociatedData(field))
}

func (s *server) backupBucketRecord(ctx context.Context) (*backupBucketRecord, error) {
	var raw []byte
	var version int
	var updatedBy string
	var updatedAt time.Time
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value, version, updated_by, updated_at FROM app_configs
		  WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, backupBucketConfigKey).Scan(&raw, &version, &updatedBy, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var value storedBackupBucket
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return &backupBucketRecord{Value: value, Version: version, UpdatedBy: updatedBy, UpdatedAt: updatedAt}, nil
}

// getBackupStorage 是控制台那张桶配置表单的数据源。凭据只回「配没配」，从不回值。
func (s *server) getBackupStorage(c *gin.Context) {
	ctx := c.Request.Context()
	record, err := s.backupBucketRecord(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_READ_FAILED", "Unable to read the backup bucket configuration")
		return
	}
	effective, source, err := s.resolveBackupBucket(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_READ_FAILED", err.Error())
		return
	}
	view := gin.H{
		"source":         source,
		"provider":       effective.Provider,
		"forcePathStyle": effective.ForcePathStyle,
		"endpoint":       nullableString(effective.Endpoint),
		"region":         nullableString(effective.Region),
		"bucket":         nullableString(effective.Bucket),
		"prefix":         nullableString(effective.Prefix),
		// 只说配没配。凭据的值任何接口都不回
		"credentialsConfigured": effective.AccessKeyID != "" && effective.SecretAccessKey != "",
		"version":               0,
		"versioning":            s.backupBucketVersioning(),
	}
	if record != nil {
		view["version"] = record.Version
		view["updatedBy"] = record.UpdatedBy
		view["updatedAt"] = iso(record.UpdatedAt)
		view["credentialsInConsole"] = record.Value.AccessKeyIDEncrypted != ""
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, view)
}

type backupBucketWrite struct {
	Provider        string `json:"provider"`
	ForcePathStyle  bool   `json:"forcePathStyle"`
	Endpoint        string `json:"endpoint"`
	Region          string `json:"region"`
	Bucket          string `json:"bucket"`
	Prefix          string `json:"prefix"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	// ExpectedVersion 是乐观锁：两个人同时改桶，后写的那个不该悄悄覆盖前一个
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// updateBackupStorage 保存桶配置。
func (s *server) updateBackupStorage(c *gin.Context) {
	var body backupBucketWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET", "reason and confirm=true are required")
		return
	}
	body.Bucket = strings.TrimSpace(body.Bucket)
	body.Region = strings.TrimSpace(body.Region)
	body.Endpoint = strings.TrimSpace(body.Endpoint)
	body.Provider = strings.ToLower(strings.TrimSpace(body.Provider))
	if body.Bucket == "" || body.Region == "" {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET", "bucket and region are required")
		return
	}
	// 和发布存储认同一份提供商清单（objectstore.Providers），别在两个地方各长出一套
	if !objectstore.KnownProvider(body.Provider) {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET",
			"provider must be one of "+strings.Join(objectstore.Providers, ", "))
		return
	}
	if objectstore.ProviderNeedsEndpoint(body.Provider) && body.Endpoint == "" {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET",
			"this provider has no default endpoint; fill in the endpoint")
		return
	}
	if s.cfg.Environment == "production" && body.Endpoint != "" && !strings.HasPrefix(body.Endpoint, "https://") {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET", "the endpoint must be https in production")
		return
	}
	// 凭据要么两个都给，要么都不给（不给 = 沿用已存的那份）
	if (body.AccessKeyID == "") != (body.SecretAccessKey == "") {
		problem(c, http.StatusBadRequest, "INVALID_BACKUP_BUCKET",
			"accessKeyId and secretAccessKey must be provided together")
		return
	}

	ctx := c.Request.Context()
	existing, err := s.backupBucketRecord(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_READ_FAILED", "Unable to read the backup bucket configuration")
		return
	}
	currentVersion := 0
	value := storedBackupBucket{}
	if existing != nil {
		currentVersion, value = existing.Version, existing.Value
	}
	if body.ExpectedVersion != 0 && body.ExpectedVersion != currentVersion {
		problem(c, http.StatusConflict, "BACKUP_BUCKET_STALE",
			"someone else changed the bucket configuration; reload and try again")
		return
	}

	value.Endpoint, value.Region = body.Endpoint, body.Region
	value.Bucket, value.Prefix = body.Bucket, strings.TrimSpace(body.Prefix)
	value.Provider, value.ForcePathStyle = body.Provider, body.ForcePathStyle
	if body.AccessKeyID != "" {
		if s.secrets == nil {
			problem(c, http.StatusPreconditionFailed, "BACKUP_BUCKET_NO_MASTER_KEY",
				"STORAGE_MASTER_KEY is not configured, so credentials cannot be stored")
			return
		}
		id, err := s.secrets.Encrypt(body.AccessKeyID, backupBucketAssociatedData("accessKeyId"))
		if err != nil {
			problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_SAVE_FAILED", "Unable to store the credentials")
			return
		}
		secret, err := s.secrets.Encrypt(body.SecretAccessKey, backupBucketAssociatedData("secretAccessKey"))
		if err != nil {
			problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_SAVE_FAILED", "Unable to store the credentials")
			return
		}
		value.AccessKeyIDEncrypted = base64.RawStdEncoding.EncodeToString(id)
		value.SecretAccessKeyEncrypted = base64.RawStdEncoding.EncodeToString(secret)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_SAVE_FAILED", "Unable to store the configuration")
		return
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 VALUES(?,?,?,1,?,?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=version+1,
		   updated_by=VALUES(updated_by),updated_at=VALUES(updated_at)`,
		platformTenantID, backupBucketConfigKey, encoded, actor(c), now); err != nil {
		problem(c, http.StatusInternalServerError, "BACKUP_BUCKET_SAVE_FAILED", "Unable to store the configuration")
		return
	}
	// 桶换了，上一次「测试连接」测的是旧桶，那个 versioning 结论作废
	s.forgetBackupBucketVersioning()

	s.auditNow(newAudit(platformTenantID, actor(c), "backup_bucket_updated", "app-config",
		backupBucketConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"bucket": value.Bucket, "region": value.Region, "provider": value.Provider,
			"credentialsChanged": body.AccessKeyID != ""}))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"status": "saved", "bucket": value.Bucket})
}
