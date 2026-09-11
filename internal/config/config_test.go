package config

import "testing"

func TestLoadUsesConfigurableMySQLOptions(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("MYSQL_DATABASE", "foundation")
	t.Setenv("MYSQL_CHARSET", "utf8mb4")
	t.Setenv("MYSQL_TIMEZONE", "Z")
	t.Setenv("MYSQL_PARSE_TIME", "true")
	t.Setenv("MYSQL_CONNECT_TIMEOUT_SECONDS", "23")
	t.Setenv("MYSQL_READ_TIMEOUT_SECONDS", "41")
	t.Setenv("MYSQL_WRITE_TIMEOUT_SECONDS", "43")
	t.Setenv("MYSQL_MAX_IDLE_CONNECTIONS", "2")
	t.Setenv("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", "601")
	t.Setenv("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", "61")
	t.Setenv("MYSQL_QUERY_TIMEOUT_SECONDS", "11")
	t.Setenv("MYSQL_INIT_TIMEOUT_SECONDS", "47")
	t.Setenv("MYSQL_INIT_MAX_ATTEMPTS", "4")
	t.Setenv("MYSQL_INIT_RETRY_DELAY_SECONDS", "7")
	t.Setenv("MYSQL_AUTO_MIGRATE", "false")
	t.Setenv("HTTP_READ_TIMEOUT_SECONDS", "901")
	t.Setenv("HTTP_WRITE_TIMEOUT_SECONDS", "902")
	t.Setenv("ARTIFACT_MULTIPART_TTL_SECONDS", "1800")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPReadTimeout != 901 || cfg.HTTPWriteTimeout != 902 || cfg.ArtifactMultipartTTL != 1800 || cfg.MySQLDatabase != "foundation_test" || cfg.MySQLCharset != "utf8mb4" || cfg.MySQLTimezone != "Z" || !cfg.MySQLParseTime ||
		cfg.MySQLConnectTimeout != 23 || cfg.MySQLReadTimeout != 41 || cfg.MySQLWriteTimeout != 43 ||
		cfg.MySQLMaxIdleConnections != 2 || cfg.MySQLConnectionMaxLifetime != 601 || cfg.MySQLConnectionMaxIdleTime != 61 || cfg.MySQLQueryTimeout != 11 ||
		cfg.MySQLInitTimeout != 47 || cfg.MySQLInitMaxAttempts != 4 || cfg.MySQLInitRetryDelay != 7 || cfg.MySQLAutoMigrate {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsIdlePoolLargerThanOpenPool(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_CONNECTION_LIMIT", "3")
	t.Setenv("MYSQL_MAX_IDLE_CONNECTIONS", "4")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid MySQL pool configuration")
	}
}

func TestProductionRequiresLoginAndExplicitOrigin(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("CORS_ORIGINS", "*")
	if _, err := Load(); err == nil {
		t.Fatal("expected production validation error")
	}
}

// 管理会话 cookie 默认只走 TLS，x-admin-key 通道的审计身份默认由配置绑定：
// 两个默认值都是安全评审 N17 的门禁项，改回不安全的默认必须先改测试。
func TestLoadAdminSecurityDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AdminCookieSecure {
		t.Fatal("ADMIN_COOKIE_SECURE must default to true")
	}
	if cfg.AdminAPIActor != "api-key-automation" {
		t.Fatalf("unexpected default api-key actor: %q", cfg.AdminAPIActor)
	}
	t.Setenv("ADMIN_COOKIE_SECURE", "false")
	t.Setenv("ADMIN_API_ACTOR", "release-bot")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminCookieSecure || cfg.AdminAPIActor != "release-bot" {
		t.Fatalf("environment must still win: %#v", cfg)
	}
}
