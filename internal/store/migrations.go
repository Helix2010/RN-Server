package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
)

const defaultTenantID = "tenant_default"

type migration struct {
	version int
	name    string
	apply   func(context.Context, *sql.DB) error
}

var migrations = []migration{
	{version: 1, name: "baseline", apply: baselineMigration},
	{version: 2, name: "multi_tenant_artifact_storage", apply: multiTenantArtifactMigration},
}

func (s *Store) Migrate(cfg config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MySQLInitTimeout)*time.Second*4)
	defer cancel()
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INT UNSIGNED PRIMARY KEY, name VARCHAR(160) NOT NULL, applied_at DATETIME(3) NOT NULL) ENGINE=InnoDB`); err != nil {
		return fmt.Errorf("create schema migration ledger: %w", err)
	}
	var locked int
	if err := s.DB.QueryRowContext(ctx, `SELECT GET_LOCK('rn_foundation_schema_migrations', 30)`).Scan(&locked); err != nil || locked != 1 {
		return fmt.Errorf("acquire schema migration lock: %w", err)
	}
	defer s.DB.ExecContext(context.Background(), `SELECT RELEASE_LOCK('rn_foundation_schema_migrations')`)

	for _, item := range migrations {
		var exists int
		err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM schema_migrations WHERE version=?`, item.version).Scan(&exists)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("read schema migration %d: %w", item.version, err)
		}
		if err := item.apply(ctx, s.DB); err != nil {
			return fmt.Errorf("apply schema migration %d (%s): %w", item.version, item.name, err)
		}
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO schema_migrations(version,name,applied_at) VALUES(?,?,?)`, item.version, item.name, time.Now().UTC()); err != nil {
			return fmt.Errorf("record schema migration %d: %w", item.version, err)
		}
	}
	return nil
}

func baselineMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS app_releases (id VARCHAR(80) PRIMARY KEY, application_id VARCHAR(120) NOT NULL, platform ENUM('android','ios') NOT NULL, version VARCHAR(40) NOT NULL, build_number INT UNSIGNED NOT NULL, runtime_version VARCHAR(120) NOT NULL, channel ENUM('store','direct','mdm','ota') NOT NULL, status ENUM('draft','uploaded','verified','staged','active','paused','completed','rejected','rolled_back') NOT NULL, release_notes JSON NOT NULL, artifact JSON NULL, rollout JSON NOT NULL, activated_at DATETIME(3) NULL, last_action VARCHAR(80) NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, UNIQUE KEY uq_release_build (application_id, platform, channel, build_number), KEY ix_release_active (platform, channel, status), KEY ix_release_updated (updated_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS audit_events (id VARCHAR(80) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, action VARCHAR(100) NOT NULL, target_type VARCHAR(80) NOT NULL, target_id VARCHAR(120) NOT NULL, reason VARCHAR(500) NOT NULL, request_id VARCHAR(120) NOT NULL, summary JSON NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_audit_target (target_type, target_id, created_at), KEY ix_audit_created (created_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS app_configs (config_key VARCHAR(100) PRIMARY KEY, config_value JSON NOT NULL, version INT UNSIGNED NOT NULL DEFAULT 1, updated_by VARCHAR(120) NOT NULL, updated_at DATETIME(3) NOT NULL) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS admin_sessions (token_hash CHAR(64) PRIMARY KEY, actor_id VARCHAR(120) NOT NULL, expires_at DATETIME(3) NOT NULL, created_at DATETIME(3) NOT NULL, KEY ix_admin_session_expiry (expires_at)) ENGINE=InnoDB`,
	}
	for index, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("baseline statement %d: %w", index+1, err)
		}
	}
	return nil
}

func multiTenantArtifactMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS tenants (id VARCHAR(80) PRIMARY KEY, slug VARCHAR(80) NOT NULL, name VARCHAR(160) NOT NULL, status ENUM('active','disabled') NOT NULL DEFAULT 'active', created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, UNIQUE KEY uq_tenant_slug (slug)) ENGINE=InnoDB`,
		`INSERT IGNORE INTO tenants(id,slug,name,status,created_at,updated_at) VALUES('tenant_default','default','Default tenant','active',UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		`CREATE TABLE IF NOT EXISTS tenant_applications (id VARCHAR(120) NOT NULL, tenant_id VARCHAR(80) NOT NULL, name VARCHAR(160) NOT NULL, platform ENUM('android') NOT NULL DEFAULT 'android', package_name VARCHAR(255) NOT NULL, expected_signer_sha256 CHAR(64) NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, PRIMARY KEY(tenant_id,id), UNIQUE KEY uq_tenant_package (tenant_id,package_name), KEY ix_application_tenant (tenant_id)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS tenant_storage_configs (tenant_id VARCHAR(80) NOT NULL, version INT UNSIGNED NOT NULL, provider VARCHAR(40) NOT NULL DEFAULT 's3', endpoint VARCHAR(500) NULL, region VARCHAR(100) NOT NULL, bucket VARCHAR(255) NOT NULL, object_prefix VARCHAR(255) NOT NULL DEFAULT '', force_path_style BOOLEAN NOT NULL DEFAULT FALSE, public_base_url VARCHAR(500) NULL, access_key_id_encrypted BLOB NULL, secret_access_key_encrypted BLOB NULL, session_token_encrypted BLOB NULL, access_key_hint VARCHAR(16) NULL, updated_by VARCHAR(120) NOT NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, PRIMARY KEY(tenant_id,version), KEY ix_storage_tenant_updated(tenant_id,updated_at)) ENGINE=InnoDB`,
		`CREATE TABLE IF NOT EXISTS artifacts (id VARCHAR(80) PRIMARY KEY, tenant_id VARCHAR(80) NOT NULL, application_id VARCHAR(120) NOT NULL, storage_config_version INT UNSIGNED NOT NULL, object_key VARCHAR(512) CHARACTER SET ascii NOT NULL, file_name VARCHAR(255) NOT NULL, content_type VARCHAR(120) NOT NULL, expected_size BIGINT UNSIGNED NOT NULL, size BIGINT UNSIGNED NULL, sha256 CHAR(64) NULL, package_name VARCHAR(255) NULL, version_name VARCHAR(80) NULL, version_code BIGINT UNSIGNED NULL, min_sdk INT UNSIGNED NULL, signer_sha256 CHAR(64) NULL, signing_scheme INT UNSIGNED NULL, signer_subject VARCHAR(500) NULL, status ENUM('pending','uploaded','verified','rejected') NOT NULL, rejection_reason VARCHAR(500) NULL, created_by VARCHAR(120) NOT NULL, verified_at DATETIME(3) NULL, created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL, UNIQUE KEY uq_artifact_object (tenant_id,object_key), KEY ix_artifact_tenant_status (tenant_id,status,created_at), KEY ix_artifact_application (tenant_id,application_id,created_at)) ENGINE=InnoDB`,
	}
	for index, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("multi-tenant create statement %d: %w", index+1, err)
		}
	}

	for _, column := range []struct {
		table, name, definition string
	}{
		{"app_releases", "tenant_id", "VARCHAR(80) NULL"},
		{"app_releases", "artifact_id", "VARCHAR(80) NULL"},
		{"audit_events", "tenant_id", "VARCHAR(80) NULL"},
		{"app_configs", "tenant_id", "VARCHAR(80) NULL"},
	} {
		if err := addColumnIfMissing(ctx, db, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	for _, table := range []string{"app_releases", "audit_events", "app_configs"} {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("UPDATE `%s` SET tenant_id=? WHERE tenant_id IS NULL OR tenant_id=''", table), defaultTenantID); err != nil {
			return fmt.Errorf("backfill %s tenant: %w", table, err)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE `%s` MODIFY tenant_id VARCHAR(80) NOT NULL DEFAULT 'tenant_default'", table)); err != nil {
			return fmt.Errorf("enforce %s tenant: %w", table, err)
		}
	}

	if columns, err := primaryKeyColumns(ctx, db, "app_configs"); err != nil {
		return err
	} else if strings.Join(columns, ",") != "tenant_id,config_key" {
		if _, err := db.ExecContext(ctx, `ALTER TABLE app_configs DROP PRIMARY KEY, ADD PRIMARY KEY(tenant_id,config_key)`); err != nil {
			return fmt.Errorf("scope app_configs primary key: %w", err)
		}
	}
	if exists, err := indexExists(ctx, db, "app_releases", "uq_release_build"); err != nil {
		return err
	} else if exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE app_releases DROP INDEX uq_release_build`); err != nil {
			return fmt.Errorf("drop legacy release uniqueness: %w", err)
		}
	}
	if exists, err := indexExists(ctx, db, "app_releases", "uq_release_tenant_build"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE app_releases ADD UNIQUE KEY uq_release_tenant_build(tenant_id,application_id,platform,channel,build_number), ADD KEY ix_release_tenant_status(tenant_id,status,updated_at), ADD KEY ix_release_artifact(tenant_id,artifact_id)`); err != nil {
			return fmt.Errorf("add tenant release indexes: %w", err)
		}
	}
	if exists, err := indexExists(ctx, db, "audit_events", "ix_audit_tenant_created"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE audit_events ADD KEY ix_audit_tenant_created(tenant_id,created_at)`); err != nil {
			return fmt.Errorf("add tenant audit index: %w", err)
		}
	}
	if exists, err := indexExists(ctx, db, "app_configs", "ix_config_tenant_updated"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE app_configs ADD KEY ix_config_tenant_updated(tenant_id,updated_at)`); err != nil {
			return fmt.Errorf("add tenant config index: %w", err)
		}
	}
	_, err := db.ExecContext(ctx, `INSERT IGNORE INTO tenant_applications(id,tenant_id,name,platform,package_name,created_at,updated_at) SELECT DISTINCT application_id,tenant_id,application_id,'android',application_id,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3) FROM app_releases WHERE platform='android'`)
	return err
}

func addColumnIfMissing(ctx context.Context, db *sql.DB, table, column, definition string) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`, table, column).Scan(&count); err != nil {
		return fmt.Errorf("inspect %s.%s: %w", table, column, err)
	}
	if count > 0 {
		return nil
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE `%s` ADD COLUMN `%s` %s", table, column, definition)); err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

func indexExists(ctx context.Context, db *sql.DB, table, index string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name=? AND index_name=?`, table, index).Scan(&count)
	return count > 0, err
}

func primaryKeyColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT column_name FROM information_schema.key_column_usage WHERE table_schema=DATABASE() AND table_name=? AND constraint_name='PRIMARY' ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, rows.Err()
}
