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
	t.Setenv("MYSQL_INIT_TIMEOUT_SECONDS", "47")
	t.Setenv("MYSQL_INIT_MAX_ATTEMPTS", "4")
	t.Setenv("MYSQL_INIT_RETRY_DELAY_SECONDS", "7")
	t.Setenv("MYSQL_AUTO_MIGRATE", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQLDatabase != "foundation_test" || cfg.MySQLCharset != "utf8mb4" || cfg.MySQLTimezone != "Z" || !cfg.MySQLParseTime ||
		cfg.MySQLConnectTimeout != 23 || cfg.MySQLReadTimeout != 41 || cfg.MySQLWriteTimeout != 43 ||
		cfg.MySQLInitTimeout != 47 || cfg.MySQLInitMaxAttempts != 4 || cfg.MySQLInitRetryDelay != 7 || cfg.MySQLAutoMigrate {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestProductionRequiresLoginAndExplicitOrigin(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("CORS_ORIGINS", "*")
	if _, err := Load(); err == nil {
		t.Fatal("expected production validation error")
	}
}
