package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
)

type migration struct {
	version int
	name    string
	apply   func(context.Context, *sql.DB) error
}

var migrations = []migration{
	{version: 5, name: "domain_release_final", apply: finalMigration},
	{version: 6, name: "dynamic_localization", apply: localizationMigration},
}

func (s *Store) Migrate(cfg config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.MySQLInitTimeout)*time.Second*4)
	defer cancel()
	if _, err := s.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INT UNSIGNED PRIMARY KEY, name VARCHAR(160) NOT NULL, applied_at DATETIME(3) NOT NULL) ENGINE=InnoDB`); err != nil {
		return fmt.Errorf("create schema migration ledger: %w", err)
	}
	var locked int
	if err := s.DB.QueryRowContext(ctx, `SELECT GET_LOCK('rn_foundation_schema_migrations',30)`).Scan(&locked); err != nil || locked != 1 {
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

func finalMigration(ctx context.Context, db *sql.DB) error {
	for _, table := range []string{"app_releases", "audit_events", "app_configs", "admin_sessions", "tenant_applications", "tenant_storage_configs", "artifacts"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS `"+table+"`"); err != nil {
			return fmt.Errorf("drop old table %s: %w", table, err)
		}
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS tenants (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '租户主键', slug VARCHAR(100) NOT NULL COMMENT '租户唯一标识', status TINYINT(1) NOT NULL DEFAULT 1 COMMENT '启用状态', start_date DATE NOT NULL COMMENT '生效日期', expiry_date DATE NOT NULL COMMENT '失效日期', deleted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '软删除标记', created_at DATETIME(3) NOT NULL COMMENT '创建时间', updated_at DATETIME(3) NOT NULL COMMENT '更新时间', PRIMARY KEY(id), UNIQUE KEY uq_tenant_slug(slug), KEY ix_tenant_status(status,deleted)) ENGINE=InnoDB COMMENT='租户主表'`,
		`CREATE TABLE IF NOT EXISTS tenant_domain (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '域名记录主键', tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID', domain VARCHAR(255) NOT NULL COMMENT '绑定域名，不含协议和端口', is_primary TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否主域名', status VARCHAR(32) NOT NULL DEFAULT 'pending' COMMENT '域名状态', deleted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '软删除标记', created_at DATETIME(3) NOT NULL COMMENT '创建时间', updated_at DATETIME(3) NOT NULL COMMENT '更新时间', PRIMARY KEY(id), UNIQUE KEY uq_tenant_domain(domain), KEY ix_domain_tenant(tenant_id,deleted)) ENGINE=InnoDB COMMENT='租户域名映射'`,
		`CREATE TABLE app_configs (tenant_id BIGINT NOT NULL DEFAULT 0 COMMENT '租户ID，0表示全局默认', config_key VARCHAR(100) NOT NULL COMMENT '配置键', config_value JSON NOT NULL COMMENT '配置JSON，敏感字段必须应用层加密', version INT UNSIGNED NOT NULL DEFAULT 1 COMMENT '乐观锁版本', updated_by VARCHAR(120) NOT NULL COMMENT '最后修改人', updated_at DATETIME(3) NOT NULL COMMENT '最后修改时间', PRIMARY KEY(tenant_id,config_key), KEY ix_config_updated(tenant_id,updated_at)) ENGINE=InnoDB COMMENT='租户应用配置与发布存储配置'`,
		`CREATE TABLE app_releases (id VARCHAR(80) NOT NULL COMMENT '发布ID', tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID', platform ENUM('android','ios','harmony') NOT NULL COMMENT '客户端平台', version VARCHAR(40) NOT NULL COMMENT '语义版本号', build_number INT UNSIGNED NOT NULL COMMENT '单调递增构建号', runtime_version VARCHAR(120) NOT NULL COMMENT '热更新运行时版本', status ENUM('uploaded','verified','active','paused','completed','rejected','rolled_back') NOT NULL COMMENT '发布状态', release_notes JSON NOT NULL COMMENT '多语言版本说明', object_key VARCHAR(512) CHARACTER SET ascii NOT NULL COMMENT '对象存储Key', file_name VARCHAR(255) NOT NULL COMMENT '原始文件名', content_type VARCHAR(120) NOT NULL COMMENT '文件MIME类型', expected_size BIGINT UNSIGNED NOT NULL COMMENT '上传声明大小', file_size BIGINT UNSIGNED NULL COMMENT '服务端校验大小', sha256 CHAR(64) NULL COMMENT '文件SHA-256', file_metadata JSON NULL COMMENT '安装包解析元数据', rejection_reason VARCHAR(500) NULL COMMENT '校验拒绝原因', verified_at DATETIME(3) NULL COMMENT '校验完成时间', published_at DATETIME(3) NULL COMMENT '全量发布时间', last_action VARCHAR(80) NULL COMMENT '最后状态动作', created_by VARCHAR(120) NOT NULL COMMENT '创建人', created_at DATETIME(3) NOT NULL COMMENT '创建时间', updated_at DATETIME(3) NOT NULL COMMENT '更新时间', PRIMARY KEY(id), UNIQUE KEY uq_release_tenant_platform_build(tenant_id,platform,build_number), KEY ix_release_tenant_status(tenant_id,status,updated_at), KEY ix_release_platform_build(tenant_id,platform,build_number)) ENGINE=InnoDB COMMENT='租户安装包发布单表事实源'`,
		`CREATE TABLE audit_events (id VARCHAR(80) NOT NULL COMMENT '审计事件ID', tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID', actor_id VARCHAR(120) NOT NULL COMMENT '操作人', action VARCHAR(100) NOT NULL COMMENT '动作', target_type VARCHAR(80) NOT NULL COMMENT '目标类型', target_id VARCHAR(120) NOT NULL COMMENT '目标ID', reason VARCHAR(500) NOT NULL COMMENT '操作原因', request_id VARCHAR(120) NOT NULL COMMENT '请求追踪ID', summary JSON NOT NULL COMMENT '脱敏操作摘要', created_at DATETIME(3) NOT NULL COMMENT '创建时间', PRIMARY KEY(id), KEY ix_audit_tenant_created(tenant_id,created_at)) ENGINE=InnoDB COMMENT='管理操作审计日志'`,
		`CREATE TABLE admin_sessions (token_hash CHAR(64) NOT NULL COMMENT '会话令牌SHA-256', actor_id VARCHAR(120) NOT NULL COMMENT '管理员账号', expires_at DATETIME(3) NOT NULL COMMENT '过期时间', created_at DATETIME(3) NOT NULL COMMENT '创建时间', PRIMARY KEY(token_hash), KEY ix_session_expiry(expires_at)) ENGINE=InnoDB COMMENT='管理端登录会话'`,
		`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at) SELECT 100000001,'default',1,'2000-01-01','2099-12-31',0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3) WHERE NOT EXISTS (SELECT 1 FROM tenants)`,
		`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at) SELECT 100000001,'localhost',1,'active',0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3) WHERE NOT EXISTS (SELECT 1 FROM tenant_domain)`,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,'release.platforms','{"android":{"enabled":true},"ios":{"enabled":true},"harmony":{"enabled":true}}',1,'system-migration',UTC_TIMESTAMP(3))`,
	}
	for i, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create final schema statement %d: %w", i+1, err)
		}
	}
	return nil
}

func normalizeLanguageConfigRows(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT tenant_id,config_value FROM app_configs WHERE config_key='languages'`)
	if err != nil {
		return err
	}
	type row struct {
		tenantID int64
		raw      []byte
	}
	items := []row{}
	for rows.Next() {
		var item row
		if err := rows.Scan(&item.tenantID, &item.raw); err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		var value map[string]any
		if err := json.Unmarshal(item.raw, &value); err != nil {
			return err
		}
		if _, exists := value["languages"]; exists {
			continue
		}
		languages := map[string]any{}
		sortValue := 1
		for _, code := range []string{"zh-CN", "en-US"} {
			oldValue, exists := value[code].(map[string]any)
			if !exists {
				continue
			}
			label, _ := oldValue["label"].(string)
			if label == "" {
				label = code
			}
			enabled, ok := oldValue["enabled"].(bool)
			if !ok {
				enabled = true
			}
			languages[code] = map[string]any{"label": label, "nativeName": label, "enabled": enabled, "direction": "ltr", "sort": sortValue}
			sortValue++
		}
		if len(languages) == 0 {
			continue
		}
		normalized := map[string]any{"schemaVersion": 2, "fallbackLanguage": "zh-CN", "refreshIntervalSeconds": 21600, "languages": languages, "resources": map[string]any{}}
		raw, _ := json.Marshal(normalized)
		if _, err := db.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by='system-localization',updated_at=UTC_TIMESTAMP(3) WHERE tenant_id=? AND config_key='languages'`, raw, item.tenantID); err != nil {
			return err
		}
	}
	return nil
}

func localizationMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS language_document (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '多语言文案主键',
			lang VARCHAR(35) NOT NULL COMMENT 'BCP 47 语言编码，例如 zh-CN',
			` + "`key`" + ` VARCHAR(255) NOT NULL COMMENT '文案 Key',
			content VARCHAR(5000) NOT NULL COMMENT '文案内容',
			meta VARCHAR(255) NOT NULL DEFAULT '' COMMENT '文案元数据',
			type INT NOT NULL DEFAULT 14 COMMENT '文案类型，14 表示 App 文案',
			edit TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否允许编辑',
			tenant_id BIGINT NOT NULL DEFAULT 0 COMMENT '租户ID，0表示全局文案',
			ctime DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
			mtime DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '修改时间',
			deleted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '软删除标记',
			PRIMARY KEY(id),
			UNIQUE KEY uk_language_document(lang,` + "`key`" + `,type,tenant_id),
			KEY ix_language_document_tenant(tenant_id,lang,type,deleted),
			KEY ix_language_document_key(` + "`key`" + `,type,deleted)
		) ENGINE=InnoDB COMMENT='全局与租户多语言文案'`,
		`ALTER TABLE language_document MODIFY lang VARCHAR(35) NOT NULL COMMENT 'BCP 47 语言编码，例如 zh-CN'`,
		`ALTER TABLE language_document MODIFY ` + "`key`" + ` VARCHAR(255) NOT NULL COMMENT '文案 Key'`,
		`ALTER TABLE language_document MODIFY type INT NOT NULL DEFAULT 14 COMMENT '文案类型，14 表示 App 文案'`,
		`ALTER TABLE language_document COMMENT='全局与租户多语言文案'`,
		`DELETE bad FROM language_document bad JOIN language_document good ON good.lang='zh-CN' AND bad.lang='zh_CN' AND good.` + "`key`" + `=bad.` + "`key`" + ` AND good.type=bad.type AND good.tenant_id=bad.tenant_id WHERE bad.lang='zh_CN'`,
		`DELETE bad FROM language_document bad JOIN language_document good ON good.lang='en-US' AND bad.lang='en_US' AND good.` + "`key`" + `=bad.` + "`key`" + ` AND good.type=bad.type AND good.tenant_id=bad.tenant_id WHERE bad.lang='en_US'`,
		`UPDATE language_document SET lang='zh-CN' WHERE lang='zh_CN'`,
		`UPDATE language_document SET lang='en-US' WHERE lang='en_US'`,
		`UPDATE app_configs SET config_value=CAST(REPLACE(REPLACE(CAST(config_value AS CHAR),'zh_CN','zh-CN'),'en_US','en-US') AS JSON) WHERE config_key IN ('languages','mobile-bootstrap')`,
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 SELECT 0,'languages',JSON_OBJECT('schemaVersion',2,'fallbackLanguage','zh-CN','refreshIntervalSeconds',21600,'languages',JSON_OBJECT(
			'zh-CN',JSON_OBJECT('label','简体中文','nativeName','简体中文','enabled',true,'direction','ltr','sort',1,'publishStatus','published'),
			'en-US',JSON_OBJECT('label','English','nativeName','English','enabled',true,'direction','ltr','sort',2,'publishStatus','published')
		 )),1,'system-localization',UTC_TIMESTAMP(3)
		 WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=0 AND config_key='languages')`,
		`INSERT INTO language_document(lang,` + "`key`" + `,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES
		 ('zh-CN','app.name','RN 应用基座','应用名称',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0),
		 ('zh-CN','home.title','远程配置中心','首页标题',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0),
		 ('en-US','app.name','RN App Foundation','Application name',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0),
		 ('en-US','home.title','Remote configuration center','Home title',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0)
		 ON DUPLICATE KEY UPDATE id=id`,
	}
	for i, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("localization migration statement %d: %w", i+1, err)
		}
	}
	return normalizeLanguageConfigRows(ctx, db)
}
