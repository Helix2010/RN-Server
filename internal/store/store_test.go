package store

import (
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
)

func TestDriverConfigUsesConfiguredConnectionOptions(t *testing.T) {
	cfg := config.Config{
		MySQLHost:           "db.internal",
		MySQLPort:           13306,
		MySQLUser:           "app",
		MySQLPassword:       "secret",
		MySQLDatabase:       "foundation",
		MySQLCharset:        "utf8mb4",
		MySQLTimezone:       "Asia/Shanghai",
		MySQLParseTime:      true,
		MySQLConnectTimeout: 17,
		MySQLReadTimeout:    29,
		MySQLWriteTimeout:   31,
	}

	driverCfg, err := driverConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if driverCfg.Addr != "db.internal:13306" || driverCfg.DBName != "foundation" || driverCfg.Params["charset"] != "utf8mb4" ||
		!driverCfg.ParseTime || driverCfg.Loc.String() != "Asia/Shanghai" || driverCfg.Timeout != 17*time.Second ||
		driverCfg.ReadTimeout != 29*time.Second || driverCfg.WriteTimeout != 31*time.Second || !driverCfg.AllowNativePasswords {
		t.Fatalf("unexpected driver config: %#v", driverCfg)
	}
}

func TestPoolSettingsUseConfiguredLimits(t *testing.T) {
	cfg := config.Config{
		MySQLConnectionLimit:       5,
		MySQLMaxIdleConnections:    1,
		MySQLConnectionMaxLifetime: 601,
		MySQLConnectionMaxIdleTime: 61,
	}

	settings := configuredPoolSettings(cfg)
	if settings.maxOpen != 5 || settings.maxIdle != 1 || settings.maxLifetime != 601*time.Second || settings.maxIdleTime != 61*time.Second {
		t.Fatalf("unexpected pool settings: %#v", settings)
	}
}
