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
	{version: 11, name: "ota_apply_strategy", apply: otaApplyStrategyMigration},
	{version: 12, name: "upload_sessions", apply: uploadSessionsMigration},
	{version: 13, name: "branding_launch_copy", apply: brandingLaunchCopyMigration},
	{version: 14, name: "app_installations_and_push", apply: appInstallationsAndPushMigration},
	{version: 15, name: "app_product_shell_copy", apply: appProductShellCopyMigration},
	{version: 16, name: "app_push_deliveries", apply: appPushDeliveriesMigration},
	{version: 17, name: "app_push_outbox_error", apply: appPushOutboxErrorMigration},
	{version: 18, name: "installation_credentials", apply: installationCredentialsMigration},
	{version: 19, name: "installation_branding_version", apply: installationBrandingVersionMigration},
	{version: 20, name: "installation_revoked_status", apply: installationRevokedStatusMigration},
	{version: 21, name: "device_schema_comments", apply: deviceSchemaCommentsMigration},
	{version: 22, name: "push_notification_copy", apply: pushNotificationCopyMigration},
	{version: 23, name: "app_modules_config", apply: appModulesConfigMigration},
	{version: 24, name: "version_info_copy", apply: versionInfoCopyMigration},
	{version: 25, name: "wallet_identity", apply: walletIdentityMigration},
	{version: 26, name: "wallet_bootstrap_section", apply: walletBootstrapSectionMigration},
	{version: 27, name: "release_mandatory_flag", apply: releaseMandatoryFlagMigration},
	{version: 28, name: "chain_token_catalog", apply: chainTokenCatalogMigration},
}

// ChainTokenSeedRow 是迁移 28 写入的一条平台代币（tenant_id=0）。
//
// 导出它是为了让 api 包用同一份表判断 allowlisted，测试再拿它跟 App 客户端的
// 白名单 src/core/wallet/config/token-allowlist.ts 逐条对照——两份表各抄一遍，
// 迟早有一份改了另一份没改。
type ChainTokenSeedRow struct {
	Chain           string
	Address         string // EIP-55 形式；"native" 表示原生币
	Symbol          string
	Name            string
	Decimals        int
	DisplayDecimals int
	LogoColor       string
	SortWeight      int
}

// ChainTokenSeed 是平台预置的代币：每条链的原生币，加上五个已在链上核验过的
// 主流稳定币。同一个 USDT 在 BSC 上是 18 位、以太坊上是 6 位——这里的精度全部
// 来自链上 decimals()，不是凭直觉填的。测试链只有原生币，不预置任何代币。
var ChainTokenSeed = []ChainTokenSeedRow{
	{Chain: "bsc", Address: "native", Symbol: "BNB", Name: "BNB", Decimals: 18, DisplayDecimals: 4, LogoColor: "#F0B90B", SortWeight: 1000},
	{Chain: "eth", Address: "native", Symbol: "ETH", Name: "Ether", Decimals: 18, DisplayDecimals: 4, LogoColor: "#627EEA", SortWeight: 1000},
	{Chain: "base", Address: "native", Symbol: "ETH", Name: "Ether", Decimals: 18, DisplayDecimals: 4, LogoColor: "#627EEA", SortWeight: 1000},
	{Chain: "op-sepolia", Address: "native", Symbol: "ETH", Name: "Ether", Decimals: 18, DisplayDecimals: 4, LogoColor: "#627EEA", SortWeight: 1000},
	{Chain: "bsc", Address: "0x55d398326f99059fF775485246999027B3197955", Symbol: "USDT", Name: "Tether USD", Decimals: 18, DisplayDecimals: 2, LogoColor: "#26A17B", SortWeight: 900},
	{Chain: "bsc", Address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", Symbol: "USDC", Name: "USD Coin", Decimals: 18, DisplayDecimals: 2, LogoColor: "#2775CA", SortWeight: 800},
	{Chain: "eth", Address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", Symbol: "USDT", Name: "Tether USD", Decimals: 6, DisplayDecimals: 2, LogoColor: "#26A17B", SortWeight: 900},
	{Chain: "eth", Address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", Symbol: "USDC", Name: "USD Coin", Decimals: 6, DisplayDecimals: 2, LogoColor: "#2775CA", SortWeight: 800},
	{Chain: "base", Address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Symbol: "USDC", Name: "USD Coin", Decimals: 6, DisplayDecimals: 2, LogoColor: "#2775CA", SortWeight: 800},
}

// chainTokenCatalogMigration 建立"全局 + 租户覆盖"两层的代币目录并写入平台预置。
//
// 表里刻意没有 source 列（元数据只能来自链上，留一列只会诱导人开手填入口）和
// verified 列（客户端只认自己那份白名单，服务端下发的 verified 一律不采纳——它恰恰
// 是被攻破的服务端最想控制的字段）。metadata_synced_at 预置为 NULL：这些值是人在
// 链上核验后写进代码的，服务端自己还没读过；第一次 resync 会把它填上。
//
// 建表用 IF NOT EXISTS，预置用 ON DUPLICATE KEY UPDATE id=id，重跑安全；运营改过的
// 预置行不会被覆盖回去。
func chainTokenCatalogMigration(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS chain_token_catalog (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '代币主键',
		tenant_id BIGINT NOT NULL DEFAULT 0 COMMENT '租户ID，0表示平台全局代币',
		chain VARCHAR(32) NOT NULL COMMENT '链 id，与平台链目录一致：bsc/eth/base/op-sepolia',
		contract_address VARCHAR(42) NOT NULL COMMENT '合约地址，入库前已做 EIP-55 规范化；native 表示原生币',
		symbol VARCHAR(32) NOT NULL COMMENT '代币符号。添加时由服务端从链上 symbol() 读取，不可编辑',
		name VARCHAR(128) NOT NULL DEFAULT '' COMMENT '代币全名。添加时从链上 name() 预填，可人工修订',
		decimals TINYINT UNSIGNED NOT NULL COMMENT '链上精度（协议事实）。添加时由服务端从链上 decimals() 读取，不可编辑；错一位金额差 10 倍',
		display_decimals TINYINT UNSIGNED NOT NULL COMMENT '展示精度：界面显示与输入保留的小数位，向下截断；0 ≤ display_decimals ≤ decimals；只影响显示，绝不参与金额换算',
		logo_color VARCHAR(16) NOT NULL DEFAULT '' COMMENT '列表占位色',
		sort_weight INT NOT NULL DEFAULT 0 COMMENT '展示排序，越大越靠前',
		enabled TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否下发给 App；租户可用一条覆盖行停用全局币',
		metadata_synced_at DATETIME(3) NULL COMMENT '最近一次从链上读取 symbol/decimals 的时间',
		ctime DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT '创建时间',
		mtime DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3) COMMENT '修改时间',
		deleted TINYINT(1) NOT NULL DEFAULT 0 COMMENT '软删除标记',
		PRIMARY KEY(id),
		UNIQUE KEY uk_chain_token(chain, contract_address, tenant_id),
		KEY ix_chain_token_tenant(tenant_id, chain, enabled, deleted)
	) ENGINE=InnoDB COMMENT='全局与租户代币目录'`); err != nil {
		return fmt.Errorf("create chain_token_catalog: %w", err)
	}
	for _, row := range ChainTokenSeed {
		if _, err := db.ExecContext(ctx, `INSERT INTO chain_token_catalog(tenant_id,chain,contract_address,symbol,name,decimals,display_decimals,logo_color,sort_weight,enabled,metadata_synced_at,ctime,mtime,deleted)
			VALUES(0,?,?,?,?,?,?,?,?,1,NULL,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE id=id`,
			row.Chain, row.Address, row.Symbol, row.Name, row.Decimals, row.DisplayDecimals, row.LogoColor, row.SortWeight); err != nil {
			return fmt.Errorf("seed chain token %s/%s: %w", row.Chain, row.Symbol, err)
		}
	}
	return nil
}

// releaseMandatoryFlagMigration 让"这个版本必须升级"成为发布记录自己的属性。
// 在此之前运营只能去改全局 updatePolicy.minSupportedVersion，跟具体发布毫无
// 关联，两处不一致就会出现"包还没能装、最低版本却先提上去"。
//
// 只加一列：为什么要强制走既有的审计 reason，给用户看的说明是 release_notes，
// 两者都已经有地方存了。
func releaseMandatoryFlagMigration(ctx context.Context, db *sql.DB) error {
	var exists int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=DATABASE() AND table_name='app_releases' AND column_name='mandatory'`).Scan(&exists)
	if err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	_, err = db.ExecContext(ctx, `ALTER TABLE app_releases
		ADD COLUMN mandatory TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1=用户不可跳过此次升级'`)
	return err
}

// walletBootstrapSectionMigration 给已有的 bootstrap 配置补上 wallet 段，
// 这样每个租户的 WalletConnect projectId 可以在管理端改，不必重新打包。
func walletBootstrapSectionMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE app_configs
		SET config_value=JSON_SET(config_value,'$.wallet',JSON_OBJECT('walletConnectProjectId','','chains',JSON_ARRAY('bsc','eth','base'))),
		    version=version+1, updated_by='system-wallet', updated_at=UTC_TIMESTAMP(3)
		WHERE config_key='mobile-bootstrap' AND JSON_EXTRACT(config_value,'$.wallet') IS NULL`)
	return err
}

// walletIdentityMigration 建立"地址即账号"的身份模型：一次性 nonce、租户内的
// 钱包用户、以及签名换来的会话。服务端只保存地址与会话，永不接触私钥。
func walletIdentityMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS wallet_auth_nonce (
			nonce CHAR(43) NOT NULL COMMENT 'SIWE一次性随机数',
			tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			address_key VARCHAR(42) NOT NULL COMMENT '小写地址，绑定挑战与签名者',
			domain VARCHAR(255) NOT NULL COMMENT '签发挑战的域名',
			message TEXT NOT NULL COMMENT '服务端构造的完整SIWE消息',
			issued_at DATETIME(3) NOT NULL COMMENT '签发时间',
			expires_at DATETIME(3) NOT NULL COMMENT '挑战过期时间',
			consumed_at DATETIME(3) NULL COMMENT '核销时间，非空即不可复用',
			PRIMARY KEY(nonce),
			KEY ix_wallet_nonce_gc(expires_at),
			KEY ix_wallet_nonce_address(tenant_id,address_key)
		) ENGINE=InnoDB COMMENT='SIWE登录挑战'`,
		`CREATE TABLE IF NOT EXISTS wallet_user (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '钱包用户主键',
			tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			address VARCHAR(42) NOT NULL COMMENT 'EIP-55校验和地址',
			address_key VARCHAR(42) NOT NULL COMMENT '小写地址，租户内唯一',
			first_seen_at DATETIME(3) NOT NULL COMMENT '首次登录即注册时间',
			last_login_at DATETIME(3) NOT NULL COMMENT '最近登录时间',
			login_count BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '登录次数',
			status ENUM('active','blocked') NOT NULL DEFAULT 'active' COMMENT '账号状态',
			created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			updated_at DATETIME(3) NOT NULL COMMENT '更新时间',
			PRIMARY KEY(id),
			UNIQUE KEY uq_wallet_user(tenant_id,address_key),
			KEY ix_wallet_user_active(tenant_id,last_login_at)
		) ENGINE=InnoDB COMMENT='租户钱包用户，地址即账号'`,
		`CREATE TABLE IF NOT EXISTS wallet_session (
			id VARCHAR(80) NOT NULL COMMENT '会话ID',
			tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			user_id BIGINT UNSIGNED NOT NULL COMMENT '钱包用户ID',
			token_hash CHAR(64) NOT NULL COMMENT '会话令牌SHA-256',
			connector VARCHAR(32) NOT NULL COMMENT '登录使用的钱包连接器',
			chains VARCHAR(160) NOT NULL COMMENT '会话声明的链，逗号分隔',
			issued_at DATETIME(3) NOT NULL COMMENT '签发时间',
			expires_at DATETIME(3) NOT NULL COMMENT '过期时间',
			last_seen_at DATETIME(3) NOT NULL COMMENT '最近使用时间',
			revoked_at DATETIME(3) NULL COMMENT '撤销时间',
			PRIMARY KEY(id),
			UNIQUE KEY uq_wallet_session_token(token_hash),
			KEY ix_wallet_session_user(tenant_id,user_id,expires_at)
		) ENGINE=InnoDB COMMENT='钱包会话'`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func versionInfoCopyMigration(ctx context.Context, db *sql.DB) error {
	items := []struct{ lang, content, meta string }{
		{"zh-CN", "版本信息", "版本信息入口"},
		{"en-US", "Version information", "Version information entry"},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,'update.versioninfo',?,?,14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE id=id`, item.lang, item.content, item.meta); err != nil {
			return err
		}
	}
	return nil
}

func appModulesConfigMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE app_configs SET config_value=JSON_SET(config_value,'$.modules',JSON_OBJECT('predict',true,'dex',true)),version=version+1,updated_by='system-modules',updated_at=UTC_TIMESTAMP(3) WHERE config_key='mobile-bootstrap' AND JSON_EXTRACT(config_value,'$.modules') IS NULL`)
	return err
}

func pushNotificationCopyMigration(ctx context.Context, db *sql.DB) error {
	items := []struct{ lang, key, content, meta string }{
		{"zh-CN", "update.localizationTitle", "语言资源已更新", "推送标题"}, {"zh-CN", "update.localizationDescription", "新的语言包已准备好，将在下次刷新后生效。", "推送正文"}, {"zh-CN", "update.brandingTitle", "品牌配置已更新", "推送标题"}, {"zh-CN", "update.brandingDescription", "新的品牌资源已准备好，将在下次启动时生效。", "推送正文"}, {"zh-CN", "update.configTitle", "应用配置已更新", "推送标题"}, {"zh-CN", "update.configDescription", "应用配置已更新，正在后台同步。", "推送正文"},
		{"en-US", "update.localizationTitle", "Language resources updated", "Push title"}, {"en-US", "update.localizationDescription", "New language resources are ready and will apply after the next refresh.", "Push body"}, {"en-US", "update.brandingTitle", "Branding updated", "Push title"}, {"en-US", "update.brandingDescription", "New branding resources are ready and will apply on the next launch.", "Push body"}, {"en-US", "update.configTitle", "App configuration updated", "Push title"}, {"en-US", "update.configDescription", "App configuration changed and is syncing in the background.", "Push body"},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?, ?,14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE content=VALUES(content),meta=VALUES(meta),deleted=0`, item.lang, item.key, item.content, item.meta); err != nil {
			return err
		}
	}
	return nil
}

func deviceSchemaCommentsMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`ALTER TABLE device_clients
			MODIFY COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '平台内部设备归并ID',
			MODIFY COLUMN platform ENUM('android','ios') NOT NULL COMMENT '设备平台',
			MODIFY COLUMN device_key_hash CHAR(64) NOT NULL COMMENT '平台设备来源标识HMAC，不保存原始设备ID',
			MODIFY COLUMN first_seen_at DATETIME(3) NOT NULL COMMENT '首次发现时间',
			MODIFY COLUMN last_seen_at DATETIME(3) NOT NULL COMMENT '最近活跃时间',
			MODIFY COLUMN created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			MODIFY COLUMN updated_at DATETIME(3) NOT NULL COMMENT '更新时间'`,
		`ALTER TABLE app_installations
			MODIFY COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '安装实例内部ID',
			MODIFY COLUMN tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			MODIFY COLUMN device_client_id BIGINT UNSIGNED NULL COMMENT '平台设备归并ID，仅平台内部使用',
			MODIFY COLUMN installation_id VARCHAR(80) NOT NULL COMMENT '当前租户App安装实例ID',
			MODIFY COLUMN application_id VARCHAR(120) NOT NULL COMMENT '应用身份',
			MODIFY COLUMN package_id VARCHAR(180) NOT NULL COMMENT 'Android包名或iOS Bundle ID',
			MODIFY COLUMN platform ENUM('android','ios') NOT NULL COMMENT 'App平台',
			MODIFY COLUMN distribution_channel VARCHAR(40) NOT NULL COMMENT '分发渠道',
			MODIFY COLUMN app_version VARCHAR(40) NOT NULL COMMENT 'APK/IPA版本号',
			MODIFY COLUMN build_number VARCHAR(40) NOT NULL COMMENT '构建号',
			MODIFY COLUMN runtime_version VARCHAR(160) NOT NULL COMMENT '原生Runtime版本',
			MODIFY COLUMN ota_channel VARCHAR(40) NOT NULL COMMENT 'OTA通道',
			MODIFY COLUMN ota_revision INT UNSIGNED NULL COMMENT '当前OTA修订号',
			MODIFY COLUMN localization_version VARCHAR(80) NULL COMMENT '当前语言包版本',
			MODIFY COLUMN branding_version INT UNSIGNED NULL COMMENT '当前品牌配置版本',
			MODIFY COLUMN locale VARCHAR(40) NULL COMMENT '当前语言',
			MODIFY COLUMN theme VARCHAR(20) NULL COMMENT '当前主题',
			MODIFY COLUMN os_version VARCHAR(40) NULL COMMENT '系统版本',
			MODIFY COLUMN device_class VARCHAR(80) NULL COMMENT '设备类型，不含硬件唯一标识',
			MODIFY COLUMN first_seen_at DATETIME(3) NOT NULL COMMENT '首次安装实例上报时间',
			MODIFY COLUMN last_active_at DATETIME(3) NOT NULL COMMENT '最近活跃时间',
			MODIFY COLUMN status ENUM('active','inactive','push_disabled','revoked') NOT NULL DEFAULT 'active' COMMENT '安装实例状态',
			MODIFY COLUMN credential_hash CHAR(64) NULL COMMENT '安装凭证SHA-256哈希',
			MODIFY COLUMN credential_version INT UNSIGNED NOT NULL DEFAULT 1 COMMENT '安装凭证版本',
			MODIFY COLUMN credential_expires_at DATETIME(3) NULL COMMENT '安装凭证过期时间',
			MODIFY COLUMN credential_last_used_at DATETIME(3) NULL COMMENT '凭证最近使用时间',
			MODIFY COLUMN credential_revoked_at DATETIME(3) NULL COMMENT '凭证撤销时间',
			MODIFY COLUMN revoked_reason VARCHAR(255) NULL COMMENT '凭证撤销原因',
			MODIFY COLUMN created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			MODIFY COLUMN updated_at DATETIME(3) NOT NULL COMMENT '更新时间'`,
		`ALTER TABLE app_push_tokens
			MODIFY COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '推送Token内部ID',
			MODIFY COLUMN tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			MODIFY COLUMN installation_id VARCHAR(80) NOT NULL COMMENT '安装实例ID',
			MODIFY COLUMN platform ENUM('android','ios') NOT NULL COMMENT '推送平台',
			MODIFY COLUMN provider ENUM('fcm','apns','hms') NOT NULL COMMENT '推送供应商',
			MODIFY COLUMN token VARCHAR(512) NOT NULL COMMENT '供应商推送Token',
			MODIFY COLUMN environment VARCHAR(20) NOT NULL DEFAULT 'production' COMMENT '推送环境',
			MODIFY COLUMN permission_status VARCHAR(32) NOT NULL DEFAULT 'unknown' COMMENT '系统通知权限状态',
			MODIFY COLUMN last_seen_at DATETIME(3) NOT NULL COMMENT 'Token最近上报时间',
			MODIFY COLUMN invalid_at DATETIME(3) NULL COMMENT 'Token失效时间',
			MODIFY COLUMN created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			MODIFY COLUMN updated_at DATETIME(3) NOT NULL COMMENT '更新时间'`,
		`ALTER TABLE app_push_outbox
			MODIFY COLUMN id VARCHAR(80) NOT NULL COMMENT '推送事件ID',
			MODIFY COLUMN tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			MODIFY COLUMN event_type VARCHAR(64) NOT NULL COMMENT '事件类型',
			MODIFY COLUMN payload JSON NOT NULL COMMENT '推送事件轻量Payload',
			MODIFY COLUMN status ENUM('pending','processing','sent','partial_failed','failed','cancelled') NOT NULL DEFAULT 'pending' COMMENT 'Outbox状态',
			MODIFY COLUMN attempts INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '投递尝试次数',
			MODIFY COLUMN last_error VARCHAR(500) NULL COMMENT '最近一次投递错误',
			MODIFY COLUMN next_attempt_at DATETIME(3) NOT NULL COMMENT '下一次投递时间',
			MODIFY COLUMN locked_at DATETIME(3) NULL COMMENT 'Worker锁定时间',
			MODIFY COLUMN sent_at DATETIME(3) NULL COMMENT '事件完成时间',
			MODIFY COLUMN created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			MODIFY COLUMN updated_at DATETIME(3) NOT NULL COMMENT '更新时间'`,
		`ALTER TABLE app_push_deliveries
			MODIFY COLUMN event_id VARCHAR(80) NOT NULL COMMENT 'Outbox事件ID',
			MODIFY COLUMN tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			MODIFY COLUMN installation_id VARCHAR(80) NOT NULL COMMENT '安装实例ID',
			MODIFY COLUMN provider VARCHAR(16) NOT NULL COMMENT '推送供应商',
			MODIFY COLUMN provider_message_id VARCHAR(255) NULL COMMENT '供应商消息ID',
			MODIFY COLUMN status VARCHAR(32) NOT NULL COMMENT '投递状态',
			MODIFY COLUMN failure_code VARCHAR(255) NULL COMMENT '失败原因',
			MODIFY COLUMN sent_at DATETIME(3) NULL COMMENT '发送时间',
			MODIFY COLUMN delivered_at DATETIME(3) NULL COMMENT '送达时间',
			MODIFY COLUMN opened_at DATETIME(3) NULL COMMENT '打开时间',
			MODIFY COLUMN created_at DATETIME(3) NOT NULL COMMENT '创建时间',
			MODIFY COLUMN updated_at DATETIME(3) NOT NULL COMMENT '更新时间'`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func installationRevokedStatusMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE app_installations MODIFY COLUMN status ENUM('active','inactive','push_disabled','revoked') NOT NULL DEFAULT 'active' COMMENT '安装实例状态'`)
	return err
}

func installationBrandingVersionMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE app_installations ADD COLUMN branding_version INT UNSIGNED NULL COMMENT '品牌配置版本' AFTER localization_version`)
	return err
}

func installationCredentialsMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE app_installations
		ADD COLUMN credential_hash CHAR(64) NULL COMMENT '安装凭证SHA-256哈希',
		ADD COLUMN credential_version INT UNSIGNED NOT NULL DEFAULT 1 COMMENT '安装凭证版本',
		ADD COLUMN credential_expires_at DATETIME(3) NULL COMMENT '安装凭证过期时间',
		ADD COLUMN credential_last_used_at DATETIME(3) NULL COMMENT '最近使用时间',
		ADD COLUMN credential_revoked_at DATETIME(3) NULL COMMENT '安装凭证撤销时间',
		ADD COLUMN revoked_reason VARCHAR(255) NULL COMMENT '安装凭证撤销原因'`)
	return err
}

func appPushOutboxErrorMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE app_push_outbox ADD COLUMN last_error VARCHAR(500) NULL COMMENT '最近一次投递错误' AFTER attempts`)
	return err
}

func appPushDeliveriesMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_push_deliveries (
		event_id VARCHAR(80) NOT NULL,
		tenant_id BIGINT UNSIGNED NOT NULL,
		installation_id VARCHAR(80) NOT NULL,
		provider VARCHAR(16) NOT NULL,
		provider_message_id VARCHAR(255) NULL,
		status VARCHAR(32) NOT NULL,
		failure_code VARCHAR(255) NULL,
		sent_at DATETIME(3) NULL,
		delivered_at DATETIME(3) NULL,
		opened_at DATETIME(3) NULL,
		created_at DATETIME(3) NOT NULL,
		updated_at DATETIME(3) NOT NULL,
		PRIMARY KEY(event_id, installation_id, provider),
		KEY ix_push_delivery_tenant(tenant_id, created_at), KEY ix_push_delivery_status(status, created_at)
	) ENGINE=InnoDB COMMENT='推送事件投递记录'`)
	return err
}

func appProductShellCopyMigration(ctx context.Context, db *sql.DB) error {
	items := []struct{ lang, key, content, meta string }{
		{"zh-CN", "nav.home", "首页", "底部导航"}, {"zh-CN", "nav.assets", "资产", "底部导航"}, {"zh-CN", "nav.profile", "我的", "底部导航"},
		{"zh-CN", "assets.eyebrow", "PORTFOLIO", "资产页眉题"},
		{"zh-CN", "assets.title", "我的资产", "资产页标题"}, {"zh-CN", "assets.subtitle", "跨网络查看余额、估值和今日变化。", "资产页说明"}, {"zh-CN", "assets.total", "总资产", "资产摘要"}, {"zh-CN", "assets.today", "今日收益", "资产摘要"}, {"zh-CN", "assets.available", "可用资产", "资产摘要"}, {"zh-CN", "assets.networks", "已连接网络", "资产摘要"}, {"zh-CN", "assets.holdings", "资产明细", "资产列表"}, {"zh-CN", "assets.updated", "刚刚更新", "资产列表"},
		{"zh-CN", "profile.eyebrow", "ACCOUNT", "个人中心眉题"}, {"zh-CN", "profile.title", "个人中心", "个人中心标题"}, {"zh-CN", "profile.subtitle", "管理账户偏好、安全状态和应用更新。", "个人中心说明"}, {"zh-CN", "profile.preferences", "偏好与应用", "个人中心分组"}, {"zh-CN", "profile.settingsHint", "语言、主题、版本与诊断设置", "个人中心入口"}, {"zh-CN", "profile.security", "设备与安全", "个人中心分组"}, {"zh-CN", "profile.network", "当前网络", "个人中心信息"}, {"zh-CN", "profile.manage", "管理应用设置", "个人中心操作"},
		{"zh-CN", "settings.languageVersion", "语言包版本", "设置版本信息"}, {"zh-CN", "settings.enableNotifications", "开启更新通知", "通知权限"}, {"zh-CN", "settings.notificationsEnabled", "更新通知已开启", "通知权限"}, {"zh-CN", "settings.notificationsDenied", "通知权限未开启，可在系统设置中恢复。", "通知权限"},
		{"zh-CN", "update.noticeTitle", "发现新版本", "升级提示"}, {"zh-CN", "update.noticeDescription", "新版本已准备好，可查看更新内容后选择升级。", "升级提示"}, {"zh-CN", "update.viewNow", "查看更新", "升级操作"},
		{"en-US", "nav.home", "Home", "Bottom navigation"}, {"en-US", "nav.assets", "Assets", "Bottom navigation"}, {"en-US", "nav.profile", "Profile", "Bottom navigation"},
		{"en-US", "assets.eyebrow", "PORTFOLIO", "Assets eyebrow"},
		{"en-US", "assets.title", "My assets", "Assets title"}, {"en-US", "assets.subtitle", "Review balances, value and daily moves across networks.", "Assets description"}, {"en-US", "assets.total", "Total assets", "Assets summary"}, {"en-US", "assets.today", "Today's return", "Assets summary"}, {"en-US", "assets.available", "Available", "Assets summary"}, {"en-US", "assets.networks", "Networks", "Assets summary"}, {"en-US", "assets.holdings", "Holdings", "Assets list"}, {"en-US", "assets.updated", "Updated now", "Assets list"},
		{"en-US", "profile.eyebrow", "ACCOUNT", "Profile eyebrow"}, {"en-US", "profile.title", "Profile", "Profile title"}, {"en-US", "profile.subtitle", "Manage preferences, security status and app updates.", "Profile description"}, {"en-US", "profile.preferences", "Preferences and app", "Profile group"}, {"en-US", "profile.settingsHint", "Language, theme, version and diagnostics", "Profile entry"}, {"en-US", "profile.security", "Device and security", "Profile group"}, {"en-US", "profile.network", "Current network", "Profile info"}, {"en-US", "profile.manage", "Manage app settings", "Profile action"},
		{"en-US", "settings.languageVersion", "Language package version", "Settings version info"}, {"en-US", "settings.enableNotifications", "Enable update notifications", "Notification permission"}, {"en-US", "settings.notificationsEnabled", "Update notifications enabled", "Notification permission"}, {"en-US", "settings.notificationsDenied", "Notifications are disabled. You can enable them in system settings.", "Notification permission"},
		{"en-US", "update.noticeTitle", "New version available", "Update prompt"}, {"en-US", "update.noticeDescription", "A new version is ready. Review the changes before updating.", "Update prompt"}, {"en-US", "update.viewNow", "View update", "Update action"},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?, ?,14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE content=VALUES(content),meta=VALUES(meta),deleted=0`, item.lang, item.key, item.content, item.meta); err != nil {
			return err
		}
	}
	return nil
}

func appInstallationsAndPushMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS device_clients (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '平台内部设备归并ID',
			platform ENUM('android','ios') NOT NULL COMMENT '平台',
			device_key_hash CHAR(64) NOT NULL COMMENT '平台设备来源标识HMAC',
			first_seen_at DATETIME(3) NOT NULL COMMENT '首次发现时间',
			last_seen_at DATETIME(3) NOT NULL COMMENT '最近活跃时间',
			created_at DATETIME(3) NOT NULL,
			updated_at DATETIME(3) NOT NULL,
			PRIMARY KEY(id), UNIQUE KEY uq_device_client(platform,device_key_hash)
		) ENGINE=InnoDB COMMENT='平台内部设备归并记录'`,
		`CREATE TABLE IF NOT EXISTS app_installations (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
			device_client_id BIGINT UNSIGNED NULL COMMENT '平台设备归并ID',
			installation_id VARCHAR(80) NOT NULL COMMENT '当前App安装实例ID',
			application_id VARCHAR(120) NOT NULL COMMENT '应用身份',
			package_id VARCHAR(180) NOT NULL COMMENT '包名或Bundle ID',
			platform ENUM('android','ios') NOT NULL,
			distribution_channel VARCHAR(40) NOT NULL,
			app_version VARCHAR(40) NOT NULL,
			build_number VARCHAR(40) NOT NULL,
			runtime_version VARCHAR(160) NOT NULL,
			ota_channel VARCHAR(40) NOT NULL,
			ota_revision INT UNSIGNED NULL,
			localization_version VARCHAR(80) NULL,
			locale VARCHAR(40) NULL,
			theme VARCHAR(20) NULL,
			os_version VARCHAR(40) NULL,
			device_class VARCHAR(80) NULL,
			first_seen_at DATETIME(3) NOT NULL,
			last_active_at DATETIME(3) NOT NULL,
			status ENUM('active','inactive','push_disabled') NOT NULL DEFAULT 'active',
			created_at DATETIME(3) NOT NULL,
			updated_at DATETIME(3) NOT NULL,
			PRIMARY KEY(id), UNIQUE KEY uq_installation(tenant_id,application_id,installation_id),
			KEY ix_installation_active(tenant_id,last_active_at), KEY ix_installation_version(tenant_id,platform,app_version,build_number), KEY ix_installation_device(device_client_id)
		) ENGINE=InnoDB COMMENT='租户App安装实例'`,
		`CREATE TABLE IF NOT EXISTS app_push_tokens (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			tenant_id BIGINT UNSIGNED NOT NULL,
			installation_id VARCHAR(80) NOT NULL,
			platform ENUM('android','ios') NOT NULL,
			provider ENUM('fcm','apns','hms') NOT NULL,
			token VARCHAR(512) NOT NULL COMMENT '推送Token',
			environment VARCHAR(20) NOT NULL DEFAULT 'production',
			permission_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
			last_seen_at DATETIME(3) NOT NULL,
			invalid_at DATETIME(3) NULL,
			created_at DATETIME(3) NOT NULL,
			updated_at DATETIME(3) NOT NULL,
			PRIMARY KEY(id), UNIQUE KEY uq_push_token(tenant_id,installation_id,provider,token), KEY ix_push_installation(tenant_id,installation_id)
		) ENGINE=InnoDB COMMENT='租户App推送Token'`,
		`CREATE TABLE IF NOT EXISTS app_push_outbox (
			id VARCHAR(80) NOT NULL,
			tenant_id BIGINT UNSIGNED NOT NULL,
			event_type VARCHAR(64) NOT NULL,
			payload JSON NOT NULL,
			status ENUM('pending','processing','sent','partial_failed','failed','cancelled') NOT NULL DEFAULT 'pending',
			attempts INT UNSIGNED NOT NULL DEFAULT 0,
			next_attempt_at DATETIME(3) NOT NULL,
			locked_at DATETIME(3) NULL,
			sent_at DATETIME(3) NULL,
			created_at DATETIME(3) NOT NULL,
			updated_at DATETIME(3) NOT NULL,
			PRIMARY KEY(id), KEY ix_push_outbox_pending(status,next_attempt_at), KEY ix_push_outbox_tenant(tenant_id,created_at)
		) ENGINE=InnoDB COMMENT='租户推送事件Outbox'`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func brandingLaunchCopyMigration(ctx context.Context, db *sql.DB) error {
	items := []struct{ lang, key, content, meta string }{
		{"zh-CN", "launch.title", "AnyFun", "启动页标题"},
		{"zh-CN", "launch.subtitle", "正在同步应用配置", "启动页副标题"},
		{"en-US", "launch.title", "AnyFun", "Launch title"},
		{"en-US", "launch.subtitle", "Syncing app configuration", "Launch subtitle"},
	}
	for _, item := range items {
		if _, err := db.ExecContext(ctx, `INSERT INTO language_document(lang,`+"`key`"+`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,?, ?,14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE content=VALUES(content),meta=VALUES(meta),deleted=0`, item.lang, item.key, item.content, item.meta); err != nil {
			return fmt.Errorf("seed branding launch copy %s/%s: %w", item.lang, item.key, err)
		}
	}
	return nil
}

func uploadSessionsMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS upload_sessions (
		id VARCHAR(80) NOT NULL COMMENT '分段上传会话ID',
		tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
		upload_type ENUM('apk','ota') NOT NULL COMMENT '上传类型',
		object_key VARCHAR(512) NOT NULL COMMENT '临时对象Key',
		upload_id VARCHAR(255) NOT NULL COMMENT '对象存储Multipart Upload ID',
		file_name VARCHAR(255) NOT NULL COMMENT '文件名',
		content_type VARCHAR(120) NOT NULL COMMENT '内容类型',
		expected_size BIGINT UNSIGNED NOT NULL COMMENT '预期文件大小',
		part_size INT UNSIGNED NOT NULL COMMENT '分片大小',
		total_parts INT UNSIGNED NOT NULL COMMENT '分片总数',
		uploaded_parts JSON NOT NULL COMMENT '已完成分片及ETag',
		status ENUM('active','completed','aborted','expired') NOT NULL DEFAULT 'active' COMMENT '会话状态',
		expires_at DATETIME(3) NOT NULL COMMENT '过期时间',
		created_by VARCHAR(120) NOT NULL COMMENT '创建人',
		created_at DATETIME(3) NOT NULL COMMENT '创建时间',
		updated_at DATETIME(3) NOT NULL COMMENT '更新时间',
		PRIMARY KEY (id), UNIQUE KEY uq_upload_multipart (tenant_id, upload_id),
		KEY ix_upload_cleanup (status, expires_at), KEY ix_upload_tenant (tenant_id, created_at)
	) ENGINE=InnoDB COMMENT='租户分段上传会话'`)
	return err
}

func otaApplyStrategyMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `ALTER TABLE ota_releases ADD COLUMN apply_strategy ENUM('next_launch','immediate') NOT NULL DEFAULT 'next_launch' COMMENT '客户端应用时机：下次启动或下载后提示立即重启' AFTER release_kind`)
	return err
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
