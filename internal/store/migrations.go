package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
	{version: 7, name: "localization_document_status", apply: localizationDocumentStatusMigration},
	{version: 8, name: "reset_rn_app_localization", apply: resetRNAppLocalizationMigration},
	{version: 9, name: "normalize_rn_app_localization_keys", apply: normalizeRNAppLocalizationKeysMigration},
	{version: 10, name: "ota_releases", apply: otaReleasesMigration},
}

func otaReleasesMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ota_releases (
		id VARCHAR(80) NOT NULL COMMENT 'OTA发布记录ID',
		tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
		base_release_id VARCHAR(80) NOT NULL COMMENT '基线APK发布ID',
		platform ENUM('android','ios') NOT NULL COMMENT '客户端平台',
		channel VARCHAR(40) NOT NULL COMMENT '发布通道',
		runtime_version VARCHAR(160) NOT NULL COMMENT '兼容的原生Runtime',
		revision INT UNSIGNED NOT NULL COMMENT '同租户平台通道Runtime下递增序号',
		update_id VARCHAR(120) NOT NULL COMMENT 'Expo Update ID',
		release_kind ENUM('update','rollback') NOT NULL DEFAULT 'update' COMMENT '正常更新或回到内置Bundle指令',
		status ENUM('draft','verified','active','paused','superseded','rejected') NOT NULL COMMENT 'OTA状态',
		manifest_key VARCHAR(512) NULL COMMENT '正常更新Manifest对象Key，回退指令为空',
		manifest_sha256 CHAR(64) NULL COMMENT '正常更新Manifest SHA-256，回退指令为空',
		release_notes JSON NOT NULL COMMENT '多语言发布说明',
		source_commit_sha VARCHAR(80) NULL COMMENT '生成OTA的代码提交SHA',
		rejection_reason VARCHAR(500) NULL COMMENT '校验拒绝原因',
		created_by VARCHAR(120) NOT NULL COMMENT '创建人',
		verified_at DATETIME(3) NULL COMMENT '校验时间',
		published_at DATETIME(3) NULL COMMENT '发布时间',
		created_at DATETIME(3) NOT NULL COMMENT '创建时间',
		updated_at DATETIME(3) NOT NULL COMMENT '更新时间',
		PRIMARY KEY(id), UNIQUE KEY uq_ota_update_id(update_id),
		UNIQUE KEY uq_ota_revision(tenant_id,platform,channel,runtime_version,revision),
		KEY ix_ota_lookup(tenant_id,platform,channel,runtime_version,status,published_at)
	) ENGINE=InnoDB COMMENT='租户OTA热更新发布记录'`)
	return err
}

func resetRNAppLocalizationMigration(ctx context.Context, db *sql.DB) error {
	seed := []struct {
		lang, key, content, meta string
	}{
		{"zh-CN", "app.name", "AnyFun", "应用名称"},
		{"zh-CN", "home.eyebrow", "ANYFUN / WEB3 PORTFOLIO", "首页眉题"},
		{"zh-CN", "home.title", "资产总览", "首页标题"},
		{"zh-CN", "home.description", "安全查看资产、网络与应用更新状态。", "首页说明"},
		{"zh-CN", "home.update", "应用升级", "升级标题"},
		{"zh-CN", "home.market", "市场行情", "行情标题"},
		{"zh-CN", "home.network", "Ethereum 主网", "网络名称"},
		{"zh-CN", "home.contract", "钱包展示合约", "合约说明"},
		{"zh-CN", "home.portfolio", "总资产估值", "资产估值"},
		{"zh-CN", "home.portfolioChange", "过去 24 小时 · 数据仅用于展示", "资产变化"},
		{"zh-CN", "home.primaryAction", "查看升级", "主操作"},
		{"zh-CN", "home.secondaryAction", "资产明细", "次操作"},
		{"zh-CN", "home.security", "安全基座", "安全区块"},
		{"zh-CN", "home.securityTitle", "安全与升级能力已就绪", "安全标题"},
		{"zh-CN", "home.securityDescription", "主题、语言、远程配置和升级策略均通过受控服务端配置下发。", "安全说明"},
		{"zh-CN", "home.secureStorage", "安全存储", "安全能力"},
		{"zh-CN", "home.signedUpdates", "签名更新", "升级能力"},
		{"zh-CN", "action.refresh", "刷新配置", "刷新操作"},
		{"zh-CN", "action.checkupdate", "检查更新", "检查更新"},
		{"zh-CN", "action.install", "前往更新", "安装更新"},
		{"zh-CN", "action.settings", "设置", "设置入口"},
		{"zh-CN", "action.back", "返回", "返回操作"},
		{"zh-CN", "theme.system", "跟随系统", "系统主题"},
		{"zh-CN", "theme.light", "浅色", "浅色主题"},
		{"zh-CN", "theme.dark", "深色", "深色主题"},
		{"zh-CN", "status.connected", "服务已连接", "连接状态"},
		{"zh-CN", "status.cached", "正在使用安全缓存", "缓存状态"},
		{"zh-CN", "status.loading", "正在同步应用配置", "加载状态"},
		{"zh-CN", "status.error", "暂时无法获取远程配置", "错误状态"},
		{"zh-CN", "update.none", "当前已经是最新版本", "无更新"},
		{"zh-CN", "update.optional", "发现可选更新", "可选更新"},
		{"zh-CN", "update.recommended", "建议升级到最新版本", "建议更新"},
		{"zh-CN", "update.required", "当前版本必须升级后继续使用", "强制更新"},
		{"zh-CN", "update.releaseControl", "升级中心", "升级页眉题"},
		{"zh-CN", "update.policy", "版本策略", "版本策略"},
		{"zh-CN", "update.currentVersion", "当前版本", "当前版本"},
		{"zh-CN", "update.minimumVersion", "最低支持", "最低版本"},
		{"zh-CN", "update.latestVersion", "最新版本", "最新版本"},
		{"zh-CN", "update.channel", "分发通道", "分发渠道"},
		{"zh-CN", "update.release", "发布记录", "发布记录"},
		{"zh-CN", "update.requestId", "请求编号", "请求编号"},
		{"zh-CN", "update.diagnostics", "诊断信息", "诊断信息"},
		{"zh-CN", "update.otaTitle", "JS 与资源热更新", "OTA 标题"},
		{"zh-CN", "update.runtime", "运行时版本", "运行时"},
		{"zh-CN", "update.checking", "检查中…", "检查状态"},
		{"zh-CN", "update.apply", "重启并应用 OTA", "应用 OTA"},
		{"zh-CN", "update.otaDisabled", "OTA 已被远程策略关闭", "OTA 状态"},
		{"zh-CN", "update.otaUnavailable", "当前构建未启用 OTA，请使用开发构建或发布版本验证。", "OTA 状态"},
		{"zh-CN", "update.otaCurrent", "当前已是最新兼容版本", "OTA 状态"},
		{"zh-CN", "update.otaReady", "更新已下载，重启后应用", "OTA 状态"},
		{"zh-CN", "update.otaError", "暂时无法检查 OTA，请稍后重试。", "OTA 错误"},
		{"zh-CN", "update.fullTitle", "全量更新", "全量更新"},
		{"zh-CN", "update.fullDescription", "通过当前分发渠道安装签名版本，更新前请确认版本与来源。", "全量更新说明"},
		{"zh-CN", "update.fullOpened", "已打开当前分发渠道的升级入口", "全量更新状态"},
		{"zh-CN", "update.fullUnavailable", "当前分发渠道尚未配置可安装地址", "全量更新状态"},
		{"zh-CN", "update.notConfigured", "尚未配置", "配置状态"},
		{"zh-CN", "feature.updateCenter", "升级中心", "功能开关"},
		{"zh-CN", "feature.ota", "OTA 热更新", "功能开关"},
		{"zh-CN", "feature.directUpdate", "Android 直装更新", "功能开关"},
		{"zh-CN", "feature.diagnostics", "诊断信息", "功能开关"},
		{"zh-CN", "settings.title", "设置", "设置标题"},
		{"zh-CN", "settings.subtitle", "管理显示偏好、语言和升级入口。", "设置说明"},
		{"zh-CN", "settings.appearance", "外观与语言", "设置分组"},
		{"zh-CN", "settings.theme", "主题", "主题设置"},
		{"zh-CN", "settings.themeLocked", "主题由应用策略锁定为系统设置。", "主题策略"},
		{"zh-CN", "settings.language", "语言", "语言设置"},
		{"zh-CN", "settings.updates", "升级与分发", "升级设置"},
		{"zh-CN", "settings.updateCenter", "升级中心", "升级设置"},
		{"zh-CN", "settings.ota", "OTA 热更新", "升级设置"},
		{"zh-CN", "settings.distribution", "分发渠道", "升级设置"},
		{"zh-CN", "settings.openUpdateCenter", "打开升级中心", "升级入口"},
		{"zh-CN", "settings.about", "关于此应用", "关于"},
		{"zh-CN", "settings.version", "应用版本", "版本信息"},
		{"zh-CN", "settings.build", "构建号", "版本信息"},
		{"zh-CN", "settings.runtime", "运行时", "版本信息"},
		{"zh-CN", "settings.configVersion", "配置版本", "版本信息"},
		{"zh-CN", "settings.service", "服务状态", "服务状态"},
		{"zh-CN", "settings.enabled", "已启用", "状态"},
		{"zh-CN", "settings.disabled", "已关闭", "状态"},
		{"zh-CN", "settings.diagnostics", "诊断与帮助", "诊断"},
		{"zh-CN", "settings.diagnosticsHint", "遇到问题时，可将诊断编号提供给支持人员。", "诊断说明"},
		{"zh-CN", "settings.statusPage", "打开状态页", "状态页"},
		{"en-US", "app.name", "AnyFun", "App name"},
		{"en-US", "home.eyebrow", "ANYFUN / WEB3 PORTFOLIO", "Home eyebrow"},
		{"en-US", "home.title", "Portfolio", "Home title"},
		{"en-US", "home.description", "Securely review assets, network and app update status.", "Home description"},
		{"en-US", "home.update", "App updates", "Update title"},
		{"en-US", "home.market", "Market", "Market title"},
		{"en-US", "home.network", "Ethereum Mainnet", "Network"},
		{"en-US", "home.contract", "Wallet display contract", "Contract"},
		{"en-US", "home.portfolio", "Total portfolio value", "Portfolio"},
		{"en-US", "home.portfolioChange", "Past 24 hours · display-only sample data", "Portfolio change"},
		{"en-US", "home.primaryAction", "View updates", "Primary action"},
		{"en-US", "home.secondaryAction", "Asset details", "Secondary action"},
		{"en-US", "home.security", "Security foundation", "Security"},
		{"en-US", "home.securityTitle", "Security and update capabilities are ready", "Security title"},
		{"en-US", "home.securityDescription", "Themes, languages, remote configuration and update policies are delivered through controlled server configuration.", "Security description"},
		{"en-US", "home.secureStorage", "Secure storage", "Security capability"},
		{"en-US", "home.signedUpdates", "Signed updates", "Update capability"},
		{"en-US", "action.refresh", "Refresh configuration", "Refresh"},
		{"en-US", "action.checkupdate", "Check for updates", "Check updates"},
		{"en-US", "action.install", "Open update", "Install"},
		{"en-US", "action.settings", "Settings", "Settings"},
		{"en-US", "action.back", "Back", "Back"},
		{"en-US", "theme.system", "System", "System theme"},
		{"en-US", "theme.light", "Light", "Light theme"},
		{"en-US", "theme.dark", "Dark", "Dark theme"},
		{"en-US", "status.connected", "Service connected", "Connected"},
		{"en-US", "status.cached", "Using safe cached configuration", "Cached"},
		{"en-US", "status.loading", "Syncing app configuration", "Loading"},
		{"en-US", "status.error", "Remote configuration is temporarily unavailable", "Error"},
		{"en-US", "update.none", "You already have the latest version", "No update"},
		{"en-US", "update.optional", "An optional update is available", "Optional update"},
		{"en-US", "update.recommended", "Updating to the latest version is recommended", "Recommended update"},
		{"en-US", "update.required", "Update is required to continue", "Required update"},
		{"en-US", "update.releaseControl", "Update center", "Update heading"},
		{"en-US", "update.policy", "Version policy", "Version policy"},
		{"en-US", "update.currentVersion", "Current version", "Current version"},
		{"en-US", "update.minimumVersion", "Minimum supported", "Minimum version"},
		{"en-US", "update.latestVersion", "Latest version", "Latest version"},
		{"en-US", "update.channel", "Distribution channel", "Channel"},
		{"en-US", "update.release", "Release", "Release"},
		{"en-US", "update.requestId", "Request ID", "Request ID"},
		{"en-US", "update.diagnostics", "Diagnostics", "Diagnostics"},
		{"en-US", "update.otaTitle", "JS and asset hot update", "OTA title"},
		{"en-US", "update.runtime", "Runtime version", "Runtime"},
		{"en-US", "update.checking", "Checking…", "Checking"},
		{"en-US", "update.apply", "Restart and apply OTA", "Apply OTA"},
		{"en-US", "update.otaDisabled", "OTA is disabled by remote policy", "OTA status"},
		{"en-US", "update.otaUnavailable", "OTA is unavailable in this build. Use a development or release build.", "OTA status"},
		{"en-US", "update.otaCurrent", "This runtime is up to date", "OTA status"},
		{"en-US", "update.otaReady", "Update downloaded and ready after restart", "OTA status"},
		{"en-US", "update.otaError", "Unable to check OTA right now. Try again later.", "OTA error"},
		{"en-US", "update.fullTitle", "Full update", "Full update"},
		{"en-US", "update.fullDescription", "Install a signed version through the current distribution channel.", "Full update description"},
		{"en-US", "update.fullOpened", "Opened the update entry for this distribution channel", "Full update status"},
		{"en-US", "update.fullUnavailable", "No install URL is configured for this distribution channel", "Full update status"},
		{"en-US", "update.notConfigured", "Not configured", "Configuration status"},
		{"en-US", "feature.updateCenter", "Update center", "Feature flag"},
		{"en-US", "feature.ota", "OTA hot update", "Feature flag"},
		{"en-US", "feature.directUpdate", "Android direct update", "Feature flag"},
		{"en-US", "feature.diagnostics", "Diagnostics", "Feature flag"},
		{"en-US", "settings.title", "Settings", "Settings title"},
		{"en-US", "settings.subtitle", "Manage appearance, language and update entry points.", "Settings description"},
		{"en-US", "settings.appearance", "Appearance and language", "Settings group"},
		{"en-US", "settings.theme", "Theme", "Theme setting"},
		{"en-US", "settings.themeLocked", "Theme is locked to the system setting by app policy.", "Theme policy"},
		{"en-US", "settings.language", "Language", "Language setting"},
		{"en-US", "settings.updates", "Updates and distribution", "Update settings"},
		{"en-US", "settings.updateCenter", "Update center", "Update settings"},
		{"en-US", "settings.ota", "OTA hot update", "Update settings"},
		{"en-US", "settings.distribution", "Distribution channel", "Update settings"},
		{"en-US", "settings.openUpdateCenter", "Open update center", "Update entry"},
		{"en-US", "settings.about", "About this app", "About"},
		{"en-US", "settings.version", "App version", "Version info"},
		{"en-US", "settings.build", "Build number", "Version info"},
		{"en-US", "settings.runtime", "Runtime", "Version info"},
		{"en-US", "settings.configVersion", "Config version", "Version info"},
		{"en-US", "settings.service", "Service status", "Service status"},
		{"en-US", "settings.enabled", "Enabled", "State"},
		{"en-US", "settings.disabled", "Disabled", "State"},
		{"en-US", "settings.diagnostics", "Diagnostics and help", "Diagnostics"},
		{"en-US", "settings.diagnosticsHint", "Share this diagnostic ID with support when you need help.", "Diagnostics description"},
		{"en-US", "settings.statusPage", "Open status page", "Status page"},
	}
	if len(seed) == 0 {
		return fmt.Errorf("rn app localization seed is empty")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM language_document WHERE type=14`); err != nil {
		return fmt.Errorf("clear legacy app localization: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_configs WHERE config_key='languages'`); err != nil {
		return fmt.Errorf("clear legacy language config: %w", err)
	}
	settings := `{"schemaVersion":2,"fallbackLanguage":"zh-CN","refreshIntervalSeconds":21600,"languages":{"zh-CN":{"label":"简体中文","nativeName":"简体中文","enabled":true,"direction":"ltr","sort":1,"publishStatus":"published"},"en-US":{"label":"English","nativeName":"English","enabled":true,"direction":"ltr","sort":2,"publishStatus":"published"}},"resources":{}}`
	if _, err := tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,'languages',?,1,'system-localization',UTC_TIMESTAMP(3))`, settings); err != nil {
		return fmt.Errorf("seed language config: %w", err)
	}
	for _, item := range seed {
		if _, err := tx.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?, ?,14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0)`, item.lang, strings.ToLower(item.key), item.content, item.meta); err != nil {
			return fmt.Errorf("seed language document %s/%s: %w", item.lang, item.key, err)
		}
	}
	return tx.Commit()
}

func normalizeRNAppLocalizationKeysMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE language_document SET `+"`key`"+`=LOWER(`+"`key`"+`) WHERE type=14`)
	return err
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

func localizationDocumentStatusMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`DELETE bad FROM language_document bad JOIN language_document good ON bad.lang=good.lang AND bad.type=good.type AND bad.tenant_id=good.tenant_id AND LOWER(bad.` + "`key`" + `)=LOWER(good.` + "`key`" + `) AND bad.id>good.id`,
		`UPDATE language_document SET ` + "`key`" + `=LOWER(` + "`key`" + `)`,
		`ALTER TABLE language_document MODIFY ` + "`key`" + ` VARCHAR(255) NOT NULL COMMENT '小写文案Key，仅允许字母、数字、点、下划线和短横线'`,
		`ALTER TABLE language_document MODIFY deleted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '文案启用状态：0启用，1停用；同一租户Key的各语言保持一致'`,
	}
	for i, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("localization document status migration statement %d: %w", i+1, err)
		}
	}
	return nil
}
