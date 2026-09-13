package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	_ "github.com/go-sql-driver/mysql"
)

type Store struct{ DB *sql.DB }

type poolSettings struct {
	maxOpen     int
	maxIdle     int
	maxLifetime time.Duration
	maxIdleTime time.Duration
}

func Open(cfg config.Config) (*Store, error) {
	if cfg.MySQL == nil {
		return nil, errors.New("database connection is not configured (MYSQL_DSN)")
	}
	db, err := sql.Open("mysql", cfg.MySQL.FormatDSN())
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
		if err := s.Migrate(cfg); err != nil {
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
