package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }

type poolSettings struct {
	maxOpen     int
	maxIdle     int
	maxLifetime time.Duration
	maxIdleTime time.Duration
}

func Open(cfg config.Config) (*Store, error) {
	driverCfg, err := driverConfig(cfg)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("mysql", driverCfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	settings := configuredPoolSettings(cfg)
	db.SetMaxOpenConns(settings.maxOpen)
	db.SetMaxIdleConns(settings.maxIdle)
	db.SetConnMaxLifetime(settings.maxLifetime)
	db.SetConnMaxIdleTime(settings.maxIdleTime)
	if err := pingWithRetry(db, cfg); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{DB: db}
	if cfg.MySQLAutoMigrate {
		if err := s.migrate(cfg); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

func configuredPoolSettings(cfg config.Config) poolSettings {
	return poolSettings{
		maxOpen:     cfg.MySQLConnectionLimit,
		maxIdle:     cfg.MySQLMaxIdleConnections,
		maxLifetime: time.Duration(cfg.MySQLConnectionMaxLifetime) * time.Second,
		maxIdleTime: time.Duration(cfg.MySQLConnectionMaxIdleTime) * time.Second,
	}
}

func driverConfig(cfg config.Config) (mysql.Config, error) {
	location := cfg.MySQLTimezone
	if location == "Z" {
		location = "UTC"
	}
	loc := time.Local
	if !strings.EqualFold(location, "local") {
		var err error
		loc, err = time.LoadLocation(location)
		if err != nil {
			return mysql.Config{}, fmt.Errorf("invalid MYSQL_TIMEZONE: %w", err)
		}
	}
	return mysql.Config{
		User:                 cfg.MySQLUser,
		Passwd:               cfg.MySQLPassword,
		Net:                  "tcp",
		Addr:                 cfg.MySQLAddress(),
		DBName:               cfg.MySQLDatabase,
		ParseTime:            cfg.MySQLParseTime,
		Loc:                  loc,
		AllowNativePasswords: true,
		Params:               map[string]string{"charset": cfg.MySQLCharset},
		Timeout:              time.Duration(cfg.MySQLConnectTimeout) * time.Second,
		ReadTimeout:          time.Duration(cfg.MySQLReadTimeout) * time.Second,
		WriteTimeout:         time.Duration(cfg.MySQLWriteTimeout) * time.Second,
	}, nil
}

func pingWithRetry(db *sql.DB, cfg config.Config) error {
	var lastErr error
	for attempt := 1; attempt <= cfg.MySQLInitMaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MySQLInitTimeout)*time.Second)
		lastErr = db.PingContext(ctx)
		cancel()
		if lastErr == nil {
			return nil
		}
		if attempt < cfg.MySQLInitMaxAttempts && cfg.MySQLInitRetryDelay > 0 {
			time.Sleep(time.Duration(cfg.MySQLInitRetryDelay) * time.Second)
		}
	}
	return fmt.Errorf("database ping failed after %d attempt(s): %w", cfg.MySQLInitMaxAttempts, lastErr)
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(cfg config.Config) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS app_releases (id VARCHAR(80) PRIMARY KEY, application_id VARCHAR(120) NOT NULL, platform ENUM('android','ios') NOT NULL, version VARCHAR(40) NOT NULL, build_number INT UNSIGNED NOT NULL, runtime_version VARCHAR(120) NOT NULL, channel ENUM('store','direct','mdm','ota') NOT NULL, status ENUM('draft','uploaded','verified','staged','active','paused','completed','rejected','rolled_back') NOT NULL, release_notes JSON NOT NULL, artifact JSON NULL, rollout JSON NOT NULL, activated_at DATETIME(3) NULL, last_action VARCHAR(80) NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, UNIQUE KEY uq_release_build (application_id, platform, channel, build_number), KEY ix_release_active (platform, channel, status), KEY ix_release_updated (updated_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS audit_events (id VARCHAR(80) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, action VARCHAR(100) NOT NULL, target_type VARCHAR(80) NOT NULL, target_id VARCHAR(120) NOT NULL, reason VARCHAR(500) NOT NULL, request_id VARCHAR(120) NOT NULL, summary JSON NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_audit_target (target_type, target_id, created_at), KEY ix_audit_created (created_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS app_configs (config_key VARCHAR(100) PRIMARY KEY, config_value JSON NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1, updated_by VARCHAR(120) NOT NULL, updated_at DATETIME(3) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash CHAR(64) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, expires_at DATETIME(3) NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_admin_session_expiry (expires_at)) ENGINE=InnoDB`,
	}
	for index, statement := range statements {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MySQLInitTimeout)*time.Second)
		_, err := s.DB.ExecContext(ctx, statement)
		cancel()
		if err != nil {
			return fmt.Errorf("database migration statement %d failed: %w", index+1, err)
		}
	}
	return nil
}
