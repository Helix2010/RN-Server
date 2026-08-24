package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }

func Open(cfg config.Config) (*Store, error) {
	bootstrap := mysql.Config{User: cfg.MySQLUser, Passwd: cfg.MySQLPassword, Net: "tcp", Addr: cfg.MySQLAddress(), AllowNativePasswords: true, Params: map[string]string{"charset": cfg.MySQLCharset}, Timeout: 15 * time.Second}
	db, err := sql.Open("mysql", bootstrap.FormatDSN())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET %s", cfg.MySQLDatabase, cfg.MySQLCharset)); err != nil {
		db.Close()
		return nil, err
	}
	_ = db.Close()

	location := cfg.MySQLTimezone
	if location == "Z" {
		location = "UTC"
	}
	loc := time.UTC
	if location == "local" {
		loc = time.Local
	}
	dsn := mysql.Config{User: cfg.MySQLUser, Passwd: cfg.MySQLPassword, Net: "tcp", Addr: cfg.MySQLAddress(), DBName: cfg.MySQLDatabase, ParseTime: cfg.MySQLParseTime, Loc: loc, AllowNativePasswords: true, Params: map[string]string{"charset": cfg.MySQLCharset}, Timeout: 15 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
	db, err = sql.Open("mysql", dsn.FormatDSN())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(cfg.MySQLConnectionLimit)
	db.SetMaxIdleConns(cfg.MySQLConnectionLimit)
	db.SetConnMaxLifetime(30 * time.Minute)
	s := &Store{DB: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS app_releases (id VARCHAR(80) PRIMARY KEY, application_id VARCHAR(120) NOT NULL, platform ENUM('android','ios') NOT NULL, version VARCHAR(40) NOT NULL, build_number INT UNSIGNED NOT NULL, runtime_version VARCHAR(120) NOT NULL, channel ENUM('store','direct','mdm','ota') NOT NULL, status ENUM('draft','uploaded','verified','staged','active','paused','completed','rejected','rolled_back') NOT NULL, release_notes JSON NOT NULL, artifact JSON NULL, rollout JSON NOT NULL, activated_at DATETIME(3) NULL, last_action VARCHAR(80) NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, UNIQUE KEY uq_release_build (application_id, platform, channel, build_number), KEY ix_release_active (platform, channel, status), KEY ix_release_updated (updated_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS audit_events (id VARCHAR(80) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, action VARCHAR(100) NOT NULL, target_type VARCHAR(80) NOT NULL, target_id VARCHAR(120) NOT NULL, reason VARCHAR(500) NOT NULL, request_id VARCHAR(120) NOT NULL, summary JSON NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_audit_target (target_type, target_id, created_at), KEY ix_audit_created (created_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS app_configs (config_key VARCHAR(100) PRIMARY KEY, config_value JSON NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1, updated_by VARCHAR(120) NOT NULL, updated_at DATETIME(3) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash CHAR(64) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, expires_at DATETIME(3) NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_admin_session_expiry (expires_at)) ENGINE=InnoDB`,
	}
	for _, statement := range statements {
		if _, err := s.DB.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
