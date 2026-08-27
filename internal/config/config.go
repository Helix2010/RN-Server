package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Environment                string
	Port                       string
	HTTPReadTimeout            int
	HTTPWriteTimeout           int
	CORSOrigins                []string
	AdminAPIKey                string
	AdminUsername              string
	AdminPasswordHash          string
	AdminSessionTTL            int
	AdminCookieSecure          bool
	AdminLoginMax              int
	AdminLoginWindow           int
	MySQLHost                  string
	MySQLPort                  int
	MySQLUser                  string
	MySQLPassword              string
	MySQLDatabase              string
	MySQLConnectionLimit       int
	MySQLMaxIdleConnections    int
	MySQLConnectionMaxLifetime int
	MySQLConnectionMaxIdleTime int
	MySQLQueryTimeout          int
	MySQLCharset               string
	MySQLTimezone              string
	MySQLParseTime             bool
	MySQLConnectTimeout        int
	MySQLReadTimeout           int
	MySQLWriteTimeout          int
	MySQLInitTimeout           int
	MySQLInitMaxAttempts       int
	MySQLInitRetryDelay        int
	MySQLAutoMigrate           bool
	StorageMasterKey           string
	ArtifactMaxSizeBytes       int64
	ArtifactUploadMode         string
	ArtifactUploadTTL          int
	ArtifactDownloadTTL        int
	ArtifactVerifyTimeout      int
	OTAChannel                 string
	AndroidStoreURL            string
	AndroidDirectURL           string
	IOSStoreURL                string
	IOSMDMURL                  string
}

func Load() (Config, error) {
	cfg := Config{
		Environment:                value("APP_ENV", "development"),
		Port:                       value("PORT", "3000"),
		HTTPReadTimeout:            integer("HTTP_READ_TIMEOUT_SECONDS", 900),
		HTTPWriteTimeout:           integer("HTTP_WRITE_TIMEOUT_SECONDS", 900),
		CORSOrigins:                split(value("CORS_ORIGINS", "*")),
		AdminAPIKey:                os.Getenv("ADMIN_API_KEY"),
		AdminUsername:              os.Getenv("ADMIN_USERNAME"),
		AdminPasswordHash:          os.Getenv("ADMIN_PASSWORD_HASH"),
		AdminSessionTTL:            integer("ADMIN_SESSION_TTL_SECONDS", 28800),
		AdminCookieSecure:          boolean("ADMIN_COOKIE_SECURE", false),
		AdminLoginMax:              integer("ADMIN_LOGIN_MAX_ATTEMPTS", 5),
		AdminLoginWindow:           integer("ADMIN_LOGIN_WINDOW_SECONDS", 900),
		MySQLHost:                  value("MYSQL_HOST", "127.0.0.1"),
		MySQLPort:                  integer("MYSQL_PORT", 3306),
		MySQLUser:                  value("MYSQL_USER", "root"),
		MySQLPassword:              os.Getenv("MYSQL_PASSWORD"),
		MySQLDatabase:              value("MYSQL_DATABASE", "rn_foundation"),
		MySQLConnectionLimit:       integer("MYSQL_CONNECTION_LIMIT", 10),
		MySQLMaxIdleConnections:    integer("MYSQL_MAX_IDLE_CONNECTIONS", 2),
		MySQLConnectionMaxLifetime: integer("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", 1800),
		MySQLConnectionMaxIdleTime: integer("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", 300),
		MySQLQueryTimeout:          integer("MYSQL_QUERY_TIMEOUT_SECONDS", 10),
		MySQLCharset:               value("MYSQL_CHARSET", "utf8mb4"),
		MySQLTimezone:              value("MYSQL_TIMEZONE", "UTC"),
		MySQLParseTime:             boolean("MYSQL_PARSE_TIME", true),
		MySQLConnectTimeout:        integer("MYSQL_CONNECT_TIMEOUT_SECONDS", 15),
		MySQLReadTimeout:           integer("MYSQL_READ_TIMEOUT_SECONDS", 30),
		MySQLWriteTimeout:          integer("MYSQL_WRITE_TIMEOUT_SECONDS", 30),
		MySQLInitTimeout:           integer("MYSQL_INIT_TIMEOUT_SECONDS", 30),
		MySQLInitMaxAttempts:       integer("MYSQL_INIT_MAX_ATTEMPTS", 3),
		MySQLInitRetryDelay:        integer("MYSQL_INIT_RETRY_DELAY_SECONDS", 5),
		MySQLAutoMigrate:           boolean("MYSQL_AUTO_MIGRATE", true),
		StorageMasterKey:           strings.TrimSpace(os.Getenv("STORAGE_MASTER_KEY")),
		ArtifactMaxSizeBytes:       int64(integer("ARTIFACT_MAX_SIZE_MB", 512)) * 1024 * 1024,
		ArtifactUploadMode:         value("ARTIFACT_UPLOAD_MODE", "direct"),
		ArtifactUploadTTL:          integer("ARTIFACT_UPLOAD_TTL_SECONDS", 900),
		ArtifactDownloadTTL:        integer("ARTIFACT_DOWNLOAD_TTL_SECONDS", 300),
		ArtifactVerifyTimeout:      integer("ARTIFACT_VERIFY_TIMEOUT_SECONDS", 300),
		OTAChannel:                 value("OTA_CHANNEL", "production"),
		AndroidStoreURL:            os.Getenv("ANDROID_STORE_URL"),
		AndroidDirectURL:           os.Getenv("ANDROID_DIRECT_URL"),
		IOSStoreURL:                os.Getenv("IOS_STORE_URL"),
		IOSMDMURL:                  os.Getenv("IOS_MDM_URL"),
	}
	if cfg.Environment == "test" && !strings.HasSuffix(cfg.MySQLDatabase, "_test") {
		cfg.MySQLDatabase += "_test"
	}
	if cfg.Environment == "production" {
		if cfg.AdminUsername == "" || cfg.AdminPasswordHash == "" {
			return Config{}, errors.New("ADMIN_USERNAME and ADMIN_PASSWORD_HASH are required in production")
		}
		if len(cfg.CORSOrigins) == 1 && cfg.CORSOrigins[0] == "*" {
			return Config{}, errors.New("CORS_ORIGINS must be explicit in production")
		}
		if cfg.StorageMasterKey == "" {
			return Config{}, errors.New("STORAGE_MASTER_KEY is required in production")
		}
	}
	if cfg.HTTPReadTimeout < 1 || cfg.HTTPWriteTimeout < 1 ||
		cfg.MySQLPort < 1 || cfg.MySQLPort > 65535 || cfg.MySQLConnectionLimit < 1 ||
		cfg.MySQLMaxIdleConnections < 0 || cfg.MySQLMaxIdleConnections > cfg.MySQLConnectionLimit ||
		cfg.MySQLConnectionMaxLifetime < 1 || cfg.MySQLConnectionMaxIdleTime < 1 || cfg.MySQLQueryTimeout < 1 ||
		cfg.MySQLConnectTimeout < 1 || cfg.MySQLReadTimeout < 1 || cfg.MySQLWriteTimeout < 1 ||
		cfg.MySQLInitTimeout < 1 || cfg.MySQLInitMaxAttempts < 1 || cfg.MySQLInitMaxAttempts > 10 || cfg.MySQLInitRetryDelay < 0 {
		return Config{}, errors.New("invalid MySQL numeric configuration")
	}
	if strings.ContainsAny(cfg.MySQLDatabase+cfg.MySQLCharset, "`'\"; ") {
		return Config{}, errors.New("invalid MySQL database or charset")
	}
	if cfg.AdminSessionTTL < 300 || cfg.AdminLoginMax < 3 || cfg.AdminLoginWindow < 60 {
		return Config{}, errors.New("invalid admin session or rate-limit configuration")
	}
	if cfg.StorageMasterKey != "" && !validMasterKey(cfg.StorageMasterKey) {
		return Config{}, errors.New("STORAGE_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	if cfg.ArtifactUploadMode != "direct" && cfg.ArtifactUploadMode != "proxy" {
		return Config{}, errors.New("ARTIFACT_UPLOAD_MODE must be direct or proxy")
	}
	if cfg.ArtifactMaxSizeBytes < 1024*1024 || cfg.ArtifactMaxSizeBytes > 2*1024*1024*1024 ||
		cfg.ArtifactUploadTTL < 60 || cfg.ArtifactUploadTTL > 3600 || cfg.ArtifactDownloadTTL < 30 || cfg.ArtifactDownloadTTL > 3600 ||
		cfg.ArtifactVerifyTimeout < 30 || cfg.ArtifactVerifyTimeout > 1800 {
		return Config{}, errors.New("invalid artifact storage configuration")
	}
	return cfg, nil
}

func validMasterKey(encoded string) bool {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	return err == nil && len(key) == 32
}

func (c Config) MySQLAddress() string { return fmt.Sprintf("%s:%d", c.MySQLHost, c.MySQLPort) }

func value(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func integer(key string, fallback int) int {
	v, err := strconv.Atoi(value(key, strconv.Itoa(fallback)))
	if err != nil {
		return -1
	}
	return v
}

func boolean(key string, fallback bool) bool {
	v, err := strconv.ParseBool(value(key, strconv.FormatBool(fallback)))
	if err != nil {
		return fallback
	}
	return v
}

func split(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
