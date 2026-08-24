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
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQLDatabase != "foundation_test" || cfg.MySQLCharset != "utf8mb4" || cfg.MySQLTimezone != "Z" || !cfg.MySQLParseTime ||
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
