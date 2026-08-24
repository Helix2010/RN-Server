package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Environment          string
	Port                 string
	CORSOrigins          []string
	AdminAPIKey          string
	AdminUsername        string
	AdminPasswordHash    string
	AdminSessionTTL      int
	AdminCookieSecure    bool
	AdminLoginMax        int
	AdminLoginWindow     int
	MySQLHost            string
	MySQLPort            int
	MySQLUser            string
	MySQLPassword        string
	MySQLDatabase        string
	MySQLConnectionLimit int
	MySQLCharset         string
	MySQLTimezone        string
	MySQLParseTime       bool
	OTAChannel           string
	AndroidStoreURL      string
	AndroidDirectURL     string
	IOSStoreURL          string
	IOSMDMURL            string
}

func Load() (Config, error) {
	cfg := Config{
		Environment:          value("NODE_ENV", "development"),
		Port:                 value("PORT", "3000"),
		CORSOrigins:          split(value("CORS_ORIGINS", "*")),
		AdminAPIKey:          os.Getenv("ADMIN_API_KEY"),
		AdminUsername:        os.Getenv("ADMIN_USERNAME"),
		AdminPasswordHash:    os.Getenv("ADMIN_PASSWORD_HASH"),
		AdminSessionTTL:      integer("ADMIN_SESSION_TTL_SECONDS", 28800),
		AdminCookieSecure:    boolean("ADMIN_COOKIE_SECURE", false),
		AdminLoginMax:        integer("ADMIN_LOGIN_MAX_ATTEMPTS", 5),
		AdminLoginWindow:     integer("ADMIN_LOGIN_WINDOW_SECONDS", 900),
		MySQLHost:            value("MYSQL_HOST", "127.0.0.1"),
		MySQLPort:            integer("MYSQL_PORT", 3306),
		MySQLUser:            value("MYSQL_USER", "root"),
		MySQLPassword:        os.Getenv("MYSQL_PASSWORD"),
		MySQLDatabase:        value("MYSQL_DATABASE", "rn_foundation"),
		MySQLConnectionLimit: integer("MYSQL_CONNECTION_LIMIT", 10),
		MySQLCharset:         value("MYSQL_CHARSET", "utf8mb4"),
		MySQLTimezone:        value("MYSQL_TIMEZONE", "UTC"),
		MySQLParseTime:       boolean("MYSQL_PARSE_TIME", true),
		OTAChannel:           value("OTA_CHANNEL", "production"),
		AndroidStoreURL:      os.Getenv("ANDROID_STORE_URL"),
		AndroidDirectURL:     os.Getenv("ANDROID_DIRECT_URL"),
		IOSStoreURL:          os.Getenv("IOS_STORE_URL"),
		IOSMDMURL:            os.Getenv("IOS_MDM_URL"),
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
	}
	if cfg.MySQLPort < 1 || cfg.MySQLPort > 65535 || cfg.MySQLConnectionLimit < 1 {
		return Config{}, errors.New("invalid MySQL numeric configuration")
	}
	if strings.ContainsAny(cfg.MySQLDatabase+cfg.MySQLCharset, "`'\"; ") {
		return Config{}, errors.New("invalid MySQL database or charset")
	}
	if cfg.AdminSessionTTL < 300 || cfg.AdminLoginMax < 3 || cfg.AdminLoginWindow < 60 {
		return Config{}, errors.New("invalid admin session or rate-limit configuration")
	}
	return cfg, nil
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
