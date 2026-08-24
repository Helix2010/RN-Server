package config

import "testing"

func TestLoadUsesConfigurableMySQLOptions(t *testing.T) {
	t.Setenv("NODE_ENV", "test")
	t.Setenv("MYSQL_DATABASE", "foundation")
	t.Setenv("MYSQL_CHARSET", "utf8mb4")
	t.Setenv("MYSQL_TIMEZONE", "Z")
	t.Setenv("MYSQL_PARSE_TIME", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQLDatabase != "foundation_test" || cfg.MySQLCharset != "utf8mb4" || cfg.MySQLTimezone != "Z" || !cfg.MySQLParseTime {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestProductionRequiresLoginAndExplicitOrigin(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	t.Setenv("CORS_ORIGINS", "*")
	if _, err := Load(); err == nil {
		t.Fatal("expected production validation error")
	}
}
