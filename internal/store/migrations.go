package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/referral"
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
	{version: 29, name: "current_rn_app_localization_seed", apply: currentRNAppLocalizationSeedMigration},
	{version: 30, name: "chain_token_logo_color_required", apply: chainTokenLogoColorMigration},
	{version: 31, name: "chain_token_logo_color_no_default", apply: chainTokenLogoColorNoDefaultMigration},
	{version: 32, name: "chain_token_seed_monad", apply: chainTokenSeedMonadMigration},
	{version: 33, name: "chain_scan_indexer", apply: chainScanIndexerMigration},
	{version: 34, name: "wallet_received_push_copy", apply: walletReceivedPushCopyMigration},
	{version: 35, name: "installation_runtime_report", apply: installationRuntimeReportMigration},
	{version: 36, name: "wallet_user_installation", apply: walletUserInstallationMigration},
	{version: 37, name: "ota_object_metadata", apply: otaObjectMetadataMigration},
	{version: 38, name: "release_notes_line_arrays", apply: releaseNotesLineArraysMigration},
	{version: 39, name: "release_canary", apply: releaseCanaryMigration},
	{version: 40, name: "build_jobs", apply: buildJobsMigration},
	{version: 41, name: "build_jobs_retryable", apply: buildJobsRetryableMigration},
	{version: 42, name: "build_jobs_release_notes", apply: buildJobsReleaseNotesMigration},
	{version: 43, name: "installation_device_integrity", apply: installationDeviceIntegrityMigration},
	{version: 44, name: "consistent_default_config", apply: consistentDefaultConfigMigration},
	{version: 45, name: "build_jobs_ota", apply: buildJobsOTAMigration},
	{version: 46, name: "diagnostic_reports", apply: diagnosticReportsMigration},
	{version: 47, name: "bootstrap_ttl_owns_refresh_interval", apply: bootstrapTTLOwnsRefreshIntervalMigration},
	// 邀请关系分三版：加可空列 -> 幂等回填 -> 索引与 CHECK。没有第四版，
	// invite_code 不收紧成 NOT NULL（见 referralColumnsMigration 的注释）
	{version: 48, name: "referral_columns", apply: referralColumnsMigration},
	{version: 49, name: "referral_code_backfill", apply: referralCodeBackfillMigration},
	{version: 50, name: "referral_indexes", apply: referralIndexesMigration},
	{version: 51, name: "tenant_neutral_platform_brand_copy", apply: tenantNeutralPlatformBrandCopyMigration},
	{version: 52, name: "drop_platform_app_name_copy", apply: dropPlatformAppNameCopyMigration},
	{version: 53, name: "platform_backups", apply: platformBackupsMigration},
}

// releaseCanaryMigration 给全量发布与 OTA 各加一个与 active 平行的 canary 状态和一列设备
// 白名单。灰度行只对名单里的安装可见，不参与"发布时收尾同平台其它 active"那条语句，
// 所以 status='active' 仍然只有一条、仍然是"所有人该拿的那一个"。
//
// 两处都必须先于任何写入 'canary' 的代码上线：ENUM 里没有这个值时，严格模式直接报错，
// 非严格模式会静默截断成空串——后者会把一条发布记录写坏。
// 列可空、ENUM 只加值，旧代码读到这两处都不受影响，因此回滚时不要删。
func releaseCanaryMigration(ctx context.Context, db *sql.DB) error {
	// 注释里不能出现单引号：它会提前终止 SQL 字符串字面量（集成测试在这上面挡了一次）
	const audienceComment = `灰度设备白名单：installation_id 字符串数组，仅 canary 状态下有意义；NULL 或空数组=该灰度行对所有设备不可见（fail-closed）。规模超过约 200 台时改为关联表`
	if _, err := db.ExecContext(ctx, `ALTER TABLE app_releases MODIFY COLUMN status ENUM('uploaded','verified','active','canary','paused','completed','rejected','rolled_back') NOT NULL COMMENT '发布状态'`); err != nil {
		return fmt.Errorf("release canary migration app_releases status: %w", err)
	}
	if err := addColumnIfMissing(ctx, db, "app_releases", "canary_installations", `ALTER TABLE app_releases ADD COLUMN canary_installations JSON NULL COMMENT '`+audienceComment+`' AFTER status`); err != nil {
		return fmt.Errorf("release canary migration app_releases audience: %w", err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE ota_releases MODIFY COLUMN status ENUM('draft','verified','active','canary','paused','superseded','rejected') NOT NULL COMMENT 'OTA状态'`); err != nil {
		return fmt.Errorf("release canary migration ota_releases status: %w", err)
	}
	if err := addColumnIfMissing(ctx, db, "ota_releases", "canary_installations", `ALTER TABLE ota_releases ADD COLUMN canary_installations JSON NULL COMMENT '`+audienceComment+`' AFTER status`); err != nil {
		return fmt.Errorf("release canary migration ota_releases audience: %w", err)
	}
	return nil
}

// addColumnIfMissing 让加列的迁移可以重复执行：MySQL 没有 ADD COLUMN IF NOT EXISTS。
func addColumnIfMissing(ctx context.Context, db *sql.DB, table, column, statement string) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?`, table, column).Scan(&count); err != nil {
		return fmt.Errorf("inspect: %w", err)
	}
	if count > 0 {
		return nil
	}
	_, err := db.ExecContext(ctx, statement)
	return err
}

// releaseNotesLineArraysMigration 修复 release_notes 里被写成字符串的发布说明。
// 正式形状是"语言 -> 行数组"：管理端按这个形状做 Zod 严格校验（一条不符就整份列表
// 打不开），bootstrap 也按 map[string][]string 解析（解析失败会让整段升级信息连同
// mandatory 标记一起消失）。写入侧现在会拒绝别的形状，历史数据在这里一次性改正，
// 不在读路径上容忍。字符串按单行数组处理，认不出的值（数字、对象、null）丢掉。
func releaseNotesLineArraysMigration(ctx context.Context, db *sql.DB) error {
	for _, table := range []string{"app_releases", "ota_releases"} {
		if err := repairReleaseNotesTable(ctx, db, table); err != nil {
			return err
		}
	}
	return nil
}

func repairReleaseNotesTable(ctx context.Context, db *sql.DB, table string) error {
	rows, err := db.QueryContext(ctx, "SELECT id, release_notes FROM "+table)
	if err != nil {
		return err
	}
	repairs := map[string][]byte{}
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		if len(raw) == 0 {
			continue
		}
		var canonical map[string][]string
		if json.Unmarshal(raw, &canonical) == nil {
			continue
		}
		var loose map[string]any
		if err := json.Unmarshal(raw, &loose); err != nil {
			// 连 JSON 都不是：留给人工处理，不猜内容
			rows.Close()
			return fmt.Errorf("%s %s: release_notes is not a JSON object", table, id)
		}
		fixed, err := json.Marshal(releaseNotesFromLooseShape(loose))
		if err != nil {
			rows.Close()
			return err
		}
		repairs[id] = fixed
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for id, fixed := range repairs {
		if _, err := db.ExecContext(ctx, "UPDATE "+table+" SET release_notes=? WHERE id=?", fixed, id); err != nil {
			return err
		}
	}
	return nil
}

// releaseNotesFromLooseShape 把历史上存进去的松散形状收敛成"语言 -> 行数组"：
// 字符串当成一行，数组里只留非空字符串，其它值没有可靠含义、直接丢。
func releaseNotesFromLooseShape(loose map[string]any) map[string][]string {
	notes := map[string][]string{}
	for language, value := range loose {
		code := strings.TrimSpace(language)
		if code == "" {
			continue
		}
		var lines []string
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				lines = []string{trimmed}
			}
		case []any:
			for _, item := range typed {
				line, ok := item.(string)
				if !ok {
					continue
				}
				if trimmed := strings.TrimSpace(line); trimmed != "" {
					lines = append(lines, trimmed)
				}
			}
		}
		if len(lines) > 0 {
			notes[code] = lines
		}
	}
	return notes
}

// chainTokenLogoColorNoDefaultMigration 去掉 logo_color 的空串默认值：字段已是必填，
// 表结构不该再邀请写入路径已经拒绝的值。
func chainTokenLogoColorNoDefaultMigration(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `ALTER TABLE chain_token_catalog MODIFY logo_color VARCHAR(16) NOT NULL COMMENT '头像底色，#RRGGBB，必填'`); err != nil {
		return fmt.Errorf("chain token logo color no-default migration: %w", err)
	}
	return nil
}

// chainTokenLogoColorMigration 把没有头像底色的代币行补成所在链原生币的颜色。
//
// 从这次迁移起 logo_color 是必填项（服务端在写入时拒绝空值，App 的 bootstrap
// 校验也不接受空串）；这里是一次性的数据修正，不是读路径上的兜底。
func chainTokenLogoColorMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE chain_token_catalog SET logo_color = CASE chain
		WHEN 'bsc' THEN '#F0B90B'
		WHEN 'eth' THEN '#627EEA'
		WHEN 'base' THEN '#627EEA'
		WHEN 'op-sepolia' THEN '#627EEA'
		ELSE '#627EEA' END
		WHERE logo_color = ''`)
	if err != nil {
		return fmt.Errorf("chain token logo color migration: %w", err)
	}
	return nil
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
	{Chain: "monad", Address: "native", Symbol: "MON", Name: "Monad", Decimals: 18, DisplayDecimals: 4, LogoColor: "#836EF9", SortWeight: 1000},
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
		chain VARCHAR(32) NOT NULL COMMENT '链 id，与平台链目录一致：bsc/eth/base/op-sepolia/monad',
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
	return seedChainTokens(ctx, db)
}

// seedChainTokens 把平台预置代币写进目录；已存在的行原样保留（ON DUPLICATE KEY
// UPDATE id=id），所以每次新增一条链都可以用一个只调用它的迁移把原生币补上。
func seedChainTokens(ctx context.Context, db *sql.DB) error {
	for _, row := range ChainTokenSeed {
		if _, err := db.ExecContext(ctx, `INSERT INTO chain_token_catalog(tenant_id,chain,contract_address,symbol,name,decimals,display_decimals,logo_color,sort_weight,enabled,metadata_synced_at,ctime,mtime,deleted)
			VALUES(0,?,?,?,?,?,?,?,?,1,NULL,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE id=id`,
			row.Chain, row.Address, row.Symbol, row.Name, row.Decimals, row.DisplayDecimals, row.LogoColor, row.SortWeight); err != nil {
			return fmt.Errorf("seed chain token %s/%s: %w", row.Chain, row.Symbol, err)
		}
	}
	return nil
}

// chainTokenSeedMonadMigration 补上 monad 的原生币行。链目录（supportedNetworks）
// 里每条启用的链都必须有启用的原生币条目，否则 bootstrap 对该链返回 503。
func chainTokenSeedMonadMigration(ctx context.Context, db *sql.DB) error {
	return seedChainTokens(ctx, db)
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

// walletReceivedPushCopyMigration 钱包收款推送文案（占位符 {amount} {symbol} {chain}），
// 与其它推送文案一样放 language_document type=14、tenant 0，租户可覆盖。
func walletReceivedPushCopyMigration(ctx context.Context, db *sql.DB) error {
	items := []struct{ lang, key, content, meta string }{
		{"zh-CN", "wallet.receivedTitle", "收到入账", "推送标题"},
		{"zh-CN", "wallet.receivedBody", "{chain} 上收到 {amount} {symbol}。", "推送正文；占位符 {amount} {symbol} {chain}"},
		{"zh-CN", "wallet.receivedUnattributedBody", "{chain} 上收到 {amount} {symbol}，来源待确认。", "推送正文（余额差额、交易待定位）；占位符 {amount} {symbol} {chain}"},
		{"en-US", "wallet.receivedTitle", "Funds received", "Push title"},
		{"en-US", "wallet.receivedBody", "Received {amount} {symbol} on {chain}.", "Push body; placeholders {amount} {symbol} {chain}"},
		{"en-US", "wallet.receivedUnattributedBody", "Received {amount} {symbol} on {chain} (source pending).", "Push body for balance-diff receipts; placeholders {amount} {symbol} {chain}"},
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

// otaObjectMetadataMigration：OTA 资源对象的入库大小与 ETag，下载前 Head 比对，发现对象存储被改写即拒绝下发。
// 已有记录为 NULL：它们只受 manifest 内容 hash（服务端）与资源 hash（expo-updates 客户端）保护。
func otaObjectMetadataMigration(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='ota_releases' AND COLUMN_NAME='object_metadata'`).Scan(&count); err != nil {
		return fmt.Errorf("ota object metadata migration inspect: %w", err)
	}
	if count > 0 {
		return nil
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE ota_releases ADD COLUMN object_metadata JSON NULL COMMENT '入库时各资源对象的校验元数据：{"<包内相对路径>":{"size":字节数,"etag":"对象存储 ETag（objectstore.Stat，去引号；分段上传形如 md5-n）"}}，不含 manifest.json（manifest 由 manifest_sha256 全文校验）；下发前 Stat 比对；NULL=迁移 37 之前入库的记录，只受内容 hash 保护' AFTER manifest_sha256`); err != nil {
		return fmt.Errorf("ota object metadata migration add column: %w", err)
	}
	return nil
}

func normalizeRNAppLocalizationKeysMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE language_document SET `+"`key`"+`=LOWER(`+"`key`"+`) WHERE type=14`)
	return err
}

// tenantNeutralPlatformBrandCopyMigration 把**平台全局**（tenant_id=0）文案里的
// 租户品牌名清空。早期的文案迁移（13、15）把当时唯一那个租户的名字写成了平台默认值：
// launch.title 与 app.name 全局行都是「AnyFun」。全局行是所有没自己配的租户继承的
// 那一份，而 bootstrap 的 branding.launch.title 就是取 launch.title 这个键——任何
// 新租户的启动页和关于页都会显示别人的品牌。
//
// 清成空串而不是删行：键不存在会让 branding.launch.title 下发 null，而 App 侧
// schema 是 z.string() 非空，现网所有安装会直接解析失败。
//
// 只动 tenant_id=0。租户自己写的覆盖是运营的选择，不碰。
//
// 后续：清成空串之后 compiledMessages 会把**键名本身**当缺失标记下发，界面上就是
// 一行「launch.title」。launch.title 那一侧由 resolveBranding 的 brandingCopy 拦掉；
// app.name 那一侧的行由迁移 52 删掉（见那里的说明）。
func tenantNeutralPlatformBrandCopyMigration(ctx context.Context, db *sql.DB) error {
	for _, key := range []string{"launch.title", "app.name"} {
		if _, err := db.ExecContext(ctx, "UPDATE language_document SET content='',mtime=UTC_TIMESTAMP(3) WHERE tenant_id=0 AND `key`=? AND type=14 AND content<>''", key); err != nil {
			return fmt.Errorf("clear platform brand copy %s: %w", key, err)
		}
	}
	return nil
}

// dropPlatformAppNameCopyMigration 删掉 app.name 的全局行。
//
// 迁移 51 把它清成了空串，但 compiledMessages 对没有内容的键返回**键名本身**
// （那是管理端列表里的缺失标记），于是 bootstrap 下发 messages["app.name"]="app.name"，
// **已装机的旧版本包**还在 t("app.name") 上取值，界面上就显示字面量「app.name」。
// 删掉之后服务端根本不下发这个键，旧包用自己内置的那份，对现有租户仍然是对的。
//
// 为什么 app.name 能删、launch.title 不能：已经没有代码读 app.name 了（App 侧的
// 显示位置都改成读原生应用名，服务端只有邀请落地页读，而它读的是 app_configs
// 那一份）；launch.title 还要留着让运营在管理端编辑，而且它要作为
// branding.launch.title 下发，少一个字段会让现网安装解析失败。
func dropPlatformAppNameCopyMigration(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "DELETE FROM language_document WHERE tenant_id=0 AND `key`='app.name' AND type=14"); err != nil {
		return fmt.Errorf("drop platform app name copy: %w", err)
	}
	return nil
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
	// 内嵌的 RN-App 文案种子每次启动都跟全局文案目录对齐：补缺键、改过的值跟着更新。
	// 只动全局行，运营在 RN-Admin 的租户覆盖不受影响（见 localization_seed.go 的说明）。
	// 迁移 29 只在 2026-09-02 跑过一次，之后同步的新键一直没进库，App 只能显示键名；
	// 现在同步种子 + 部署就够了，不用再记得加迁移版本
	if err := currentRNAppLocalizationSeedMigration(ctx, s.DB); err != nil {
		return fmt.Errorf("apply RN-App localization seed: %w", err)
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

// chainScanIndexerMigration 建扫链模块的表与列（设计 RN-App/docs/design/wallet-receive-index-2026-09-06.md §4.9）：
// 每链一行的运行状态、扫链得到的转账记录，以及 wallet_user / wallet_session 的两个新列。
// 扫链配置不建表，放 app_configs(tenant_id=0, config_key='chain-scan.<chain>')。
func chainScanIndexerMigration(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS chain_scan_state (
			chain VARCHAR(32) NOT NULL COMMENT '链 id，与平台链目录 supportedNetworks 及 app_configs 的 chain-scan.<chain> 一致',
			scanned_to_block BIGINT UNSIGNED NOT NULL COMMENT '已完整索引到的区块号（含）；与记录同一事务推进，是追块的唯一断点',
			scanned_to_hash CHAR(66) NOT NULL COMMENT 'scanned_to_block 的区块哈希；每轮核对，不一致即判定重组',
			scanned_to_time DATETIME(3) NULL COMMENT 'scanned_to_block 的区块时间戳（UTC），来自链、随游标同一事务写；移动端"落后秒数"= now − 该值，是唯一来源；NULL 表示尚未推进过游标',
			head_block BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '最近一次从端点观察到的链头区块号，用于计算落后',
			state ENUM('idle','scanning','catching_up','stalled','paused','unconfigured') NOT NULL COMMENT '运行状态：idle 追平等待；scanning 正在扫本轮；catching_up 落后追块中；stalled 全部端点不可用；paused 手动暂停；unconfigured 配置行不存在或 enabled=false',
			lease_owner VARCHAR(80) NOT NULL DEFAULT '' COMMENT '持有租约的索引器实例标识（主机名+进程 id）；空表示无人持有',
			lease_until DATETIME(3) NULL COMMENT '租约到期时间（UTC）；到期后其他实例可接管',
			last_error VARCHAR(512) NOT NULL DEFAULT '' COMMENT '最近一次错误（已截断），成功一轮后清空',
			error_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '连续失败轮数；成功后归零',
			reorg_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '累计检测到的重组次数，用于告警与排查',
			endpoint_health JSON NOT NULL COMMENT '端点健康度数组，按配置顺序：[{label,urlHash,health(healthy|cooling|mismatch|unknown),consecutiveFailures,coolingUntil,lastOkAt,lastError,latencyMs,headBlock,spanRejected}]；urlHash = url 的 SHA-256，不含明文；由 worker 每轮写、管理端读',
			jobs JSON NOT NULL COMMENT '后台任务数组：[{id,kind(rescan|attribute),fromBlock,toBlock,progressBlock,state(pending|running|failed),createdBy,reason,lastError,createdAt}]；由持租约的 worker 串行执行；done/cancelled 后移出数组并写 audit_events',
			open_alerts JSON NOT NULL COMMENT '未恢复的告警数组：[{kind(stalled|lagging|reorg|endpoint_mismatch|job_failed),message,raisedAt,webhookSentAt}]；恢复即移出并写 audit_events；管理端横幅与 webhook 读它',
			updated_at DATETIME(3) NOT NULL COMMENT '最后更新时间（UTC）',
			PRIMARY KEY(chain)
		) ENGINE=InnoDB COMMENT='每条链的扫描游标、运行状态、端点健康、后台任务与未恢复告警；每链一行，由持租约的索引器写，管理端与移动端接口读'`,
		`CREATE TABLE IF NOT EXISTS wallet_transfer_index (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '记录主键',
			tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户 ID，来自 wallet_user',
			chain VARCHAR(32) NOT NULL COMMENT '链 id',
			address_key VARCHAR(42) NOT NULL COMMENT '被监听的钱包地址（小写），同 wallet_user.address_key',
			direction ENUM('in','out') NOT NULL COMMENT '方向：in 入账（to = 本地址）；out 出账（from = 本地址）',
			asset ENUM('native','erc20') NOT NULL COMMENT '资产类型：native 原生币；erc20 目录内代币',
			contract_address VARCHAR(42) NOT NULL COMMENT '代币合约地址（EIP-55）；原生币为 native，与 chain_token_catalog 一致',
			amount_raw DECIMAL(65,0) NOT NULL COMMENT '金额，最小单位整数；精度看代币目录 decimals，此处不换算',
			counterparty VARCHAR(42) NOT NULL DEFAULT '' COMMENT '对手方地址（小写）：in 为 from，out 为 to；unattributed 为空',
			tx_hash CHAR(66) NOT NULL DEFAULT '' COMMENT '交易哈希；unattributed 为空',
			log_index INT NOT NULL DEFAULT -1 COMMENT 'ERC-20 为日志在区块内的序号；原生币为交易在区块内的序号；unattributed 为 -1',
			block_number BIGINT UNSIGNED NOT NULL COMMENT '区块号；unattributed 为覆盖区间的末块',
			block_hash CHAR(66) NOT NULL COMMENT '区块哈希，重组回滚时据此比对',
			block_time DATETIME(3) NOT NULL COMMENT '区块时间戳（UTC），来自链，不用服务器时钟',
			attribution ENUM('tx','unattributed') NOT NULL DEFAULT 'tx' COMMENT '归属：tx 已定位到交易；unattributed 只有余额差额、交易待后台任务定位（balance 模式）',
			gap_from_block BIGINT UNSIGNED NULL COMMENT 'unattributed 覆盖区间的起始区块；tx 行为 NULL',
			status ENUM('confirmed','orphaned') NOT NULL DEFAULT 'confirmed' COMMENT '有效性：confirmed 有效；orphaned 因重组作废，保留供排查，接口不返回',
			created_at DATETIME(3) NOT NULL COMMENT '入库时间（UTC）',
			PRIMARY KEY(id),
			UNIQUE KEY uq_transfer(tenant_id, chain, tx_hash, log_index, address_key, direction, block_number),
			KEY ix_transfer_address(tenant_id, address_key, chain, block_number DESC)
		) ENGINE=InnoDB COMMENT='扫链得到的钱包转账记录，唯一正式来源；App 本机账本只补充未上链的进行中状态'`,
	}
	for i, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("chain scan indexer migration statement %d: %w", i+1, err)
		}
	}
	columns := []struct{ table, column, ddl string }{
		{"wallet_user", "scan_state", `ALTER TABLE wallet_user ADD COLUMN scan_state JSON NULL COMMENT 'balance 模式的每链原生币余额快照：{"<chain>":{"balanceRaw":"最小单位整数","block":比对时的区块号}}；NULL 表示尚未读取；只对 nativeMode=balance 的链写'`},
		{"wallet_session", "installation_id", `ALTER TABLE wallet_session ADD COLUMN installation_id VARCHAR(80) NULL COMMENT '登录时的 App 安装实例 ID（app_installations.installation_id），定向推送用；旧会话为 NULL'`},
	}
	for _, item := range columns {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?`, item.table, item.column).Scan(&count); err != nil {
			return fmt.Errorf("chain scan indexer migration inspect %s.%s: %w", item.table, item.column, err)
		}
		if count > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, item.ddl); err != nil {
			return fmt.Errorf("chain scan indexer migration add %s.%s: %w", item.table, item.column, err)
		}
	}
	return nil
}

// installationRuntimeReportMigration 给安装实例加"设备实际在跑什么"的列（设计 RN-App/docs/design/device-account-aggregation-2026-09-07.md §4.1、§4.6）：
// 此前只有 bootstrap 下发的可用修订号 ota_revision，管理端把它当成运行版本展示是错的。
// 旧版 App 不上报这些字段时存 NULL，管理端显示"未上报"，不把 NULL 当内置包。
func installationRuntimeReportMigration(ctx context.Context, db *sql.DB) error {
	columns := []struct{ column, ddl string }{
		{"launch_source", `ALTER TABLE app_installations ADD COLUMN launch_source ENUM('embedded','ota') NULL COMMENT '心跳上报的启动来源：embedded=内置 bundle，ota=OTA bundle；NULL=旧版 App 未上报' AFTER ota_revision`},
		{"running_update_id", `ALTER TABLE app_installations ADD COLUMN running_update_id CHAR(36) NULL COMMENT '正在运行的 expo-updates update id；launch_source=embedded 时为 NULL' AFTER launch_source`},
		{"running_ota_revision", `ALTER TABLE app_installations ADD COLUMN running_ota_revision INT UNSIGNED NULL COMMENT '由 running_update_id 关联本租户 ota_releases.update_id 得到的修订号；关联不上为 NULL，管理端显示未知更新' AFTER running_update_id`},
		{"client_session_state", `ALTER TABLE app_installations ADD COLUMN client_session_state ENUM('signed_in','signed_out') NULL COMMENT '心跳上报的客户端登录态，只用于与 wallet_session 对账，不参与任何判定；NULL=旧版 App 未上报' AFTER running_ota_revision`},
	}
	for _, item := range columns {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='app_installations' AND COLUMN_NAME=?`, item.column).Scan(&count); err != nil {
			return fmt.Errorf("installation runtime report migration inspect %s: %w", item.column, err)
		}
		if count > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, item.ddl); err != nil {
			return fmt.Errorf("installation runtime report migration add %s: %w", item.column, err)
		}
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE app_installations MODIFY COLUMN ota_revision INT UNSIGNED NULL COMMENT 'bootstrap 下发的最新可用 OTA 修订号（服务端视角），不是运行中的版本；运行中的看 running_ota_revision'`); err != nil {
		return fmt.Errorf("installation runtime report migration comment ota_revision: %w", err)
	}
	return nil
}

// walletUserInstallationMigration 建"账号 × 安装实例"登录历史汇总表并补会话结束原因（设计 RN-App/docs/design/device-account-aggregation-2026-09-07.md §4.2、§4.6）：
// 当前账号仍从 wallet_session 派生（按安装实例的索引），汇总表只记历史；会话永久保留，不设清理任务，
// 所以 ended_reason 只记主动结束的原因，过期在读取时按 expires_at 判断。
func walletUserInstallationMigration(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS wallet_user_installation (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
		tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID',
		user_id BIGINT UNSIGNED NOT NULL COMMENT 'wallet_user.id',
		installation_id VARCHAR(80) NOT NULL COMMENT 'app_installations.installation_id',
		first_login_at DATETIME(3) NOT NULL COMMENT '该账号在该安装实例首次登录时间',
		last_login_at DATETIME(3) NOT NULL COMMENT '该账号在该安装实例最近登录时间',
		login_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '该账号在该安装实例的登录次数',
		last_connector VARCHAR(32) NOT NULL COMMENT '最近一次登录使用的钱包连接器',
		created_at DATETIME(3) NOT NULL COMMENT '创建时间',
		updated_at DATETIME(3) NOT NULL COMMENT '更新时间',
		PRIMARY KEY (id),
		UNIQUE KEY uq_user_installation (tenant_id, user_id, installation_id),
		KEY ix_installation_users (tenant_id, installation_id, last_login_at)
	) ENGINE=InnoDB COMMENT='账号与安装实例的登录历史汇总，登录时与会话同事务写入；当前账号不看此表，看 wallet_session'`); err != nil {
		return fmt.Errorf("wallet user installation migration create table: %w", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wallet_session' AND COLUMN_NAME='ended_reason'`).Scan(&count); err != nil {
		return fmt.Errorf("wallet user installation migration inspect ended_reason: %w", err)
	}
	if count == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE wallet_session ADD COLUMN ended_reason ENUM('logout','superseded','admin','blocked') NULL COMMENT '会话主动结束的原因：logout=用户登出，superseded=同安装实例新登录替代，admin=管理端撤销，blocked=封禁；NULL=未被主动结束（是否过期看 expires_at）' AFTER revoked_at`); err != nil {
			return fmt.Errorf("wallet user installation migration add ended_reason: %w", err)
		}
	}
	indexes := []struct{ table, index, ddl string }{
		{"wallet_session", "ix_wallet_session_installation", `ALTER TABLE wallet_session ADD INDEX ix_wallet_session_installation (tenant_id, installation_id, revoked_at, expires_at) COMMENT '按安装实例取当前有效会话'`},
		{"wallet_user", "ix_wallet_user_address", `ALTER TABLE wallet_user ADD INDEX ix_wallet_user_address (address_key) COMMENT '平台级按地址跨租户查找'`},
	}
	for _, item := range indexes {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND INDEX_NAME=?`, item.table, item.index).Scan(&count); err != nil {
			return fmt.Errorf("wallet user installation migration inspect %s: %w", item.index, err)
		}
		if count > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, item.ddl); err != nil {
			return fmt.Errorf("wallet user installation migration add %s: %w", item.index, err)
		}
	}
	// 平台级封禁表（设计 §4.5）：对所有租户生效，登录时先查它再查租户级 wallet_user.status
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_wallet_block (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
		address_key VARCHAR(42) NOT NULL COMMENT '小写地址，跨租户唯一',
		address VARCHAR(42) NOT NULL COMMENT 'EIP-55 校验和地址，展示用',
		reason VARCHAR(255) NOT NULL COMMENT '封禁原因，管理端必填',
		created_by VARCHAR(120) NOT NULL COMMENT '操作的平台管理员（x-admin-id）',
		created_at DATETIME(3) NOT NULL COMMENT '封禁时间',
		revoked_at DATETIME(3) NULL COMMENT '解除时间；NULL=生效中',
		revoked_by VARCHAR(120) NULL COMMENT '解除封禁的平台管理员',
		revoked_reason VARCHAR(255) NULL COMMENT '解除原因',
		PRIMARY KEY (id),
		KEY ix_platform_block_address (address_key, revoked_at)
	) ENGINE=InnoDB COMMENT='平台级钱包封禁，对所有租户生效；租户级封禁在 wallet_user.status'`); err != nil {
		return fmt.Errorf("wallet user installation migration create platform block table: %w", err)
	}
	// 从已有会话回填历史（只有 1.2.9 起带安装实例的会话有数据；上线时线上为 0 条，从此开始积累）
	if _, err := db.ExecContext(ctx, `INSERT IGNORE INTO wallet_user_installation(tenant_id,user_id,installation_id,first_login_at,last_login_at,login_count,last_connector,created_at,updated_at)
		SELECT tenant_id,user_id,installation_id,MIN(issued_at),MAX(issued_at),COUNT(*),SUBSTRING_INDEX(GROUP_CONCAT(connector ORDER BY issued_at DESC SEPARATOR ','),',',1),UTC_TIMESTAMP(3),UTC_TIMESTAMP(3)
		FROM wallet_session WHERE installation_id IS NOT NULL GROUP BY tenant_id,user_id,installation_id`); err != nil {
		return fmt.Errorf("wallet user installation migration backfill: %w", err)
	}
	return nil
}

// buildJobsMigration 建打包任务表（设计 docs/design/build-service-2026-09-11.md）。
//
// 为什么不复用 app_releases：那张表描述的是一个**已经存在的产物**，而构建任务可以
// 失败、可以重试、可以在没有任何产物的情况下结束。塞进去会把"失败的构建"写成
// "坏掉的发布记录"。
//
// 表里**没有命令字段**，这是有意的。任务只带参数（租户、提交、版本号），怎么构建由
// 打包机自己决定。让服务端能下发命令，等于 wallet 后端的任何一个 RCE 都拿到了那台
// 握着 Android keystore 的机器的执行权，而 keystore 泄露在 direct 分发下没有补救
// 办法——只能换包名，让每个用户手动卸载重装。
func buildJobsMigration(ctx context.Context, db *sql.DB) error {
	// 注释里不能出现单引号：它会提前终止 SQL 字符串字面量
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS build_jobs (
		id VARCHAR(80) NOT NULL COMMENT '主键，bld_ 前缀',
		tenant_id BIGINT UNSIGNED NOT NULL COMMENT '所属租户；构建参数与产物都只属于这个租户',
		platform ENUM('android','ios') NOT NULL COMMENT '目标平台',
		git_ref VARCHAR(200) NOT NULL COMMENT '要构建的分支名或提交 sha；代理解析出确切提交后回写 commit_sha',
		commit_sha VARCHAR(64) NULL COMMENT '代理实际检出的提交；NULL=还没认领或还没解析出来',
		version VARCHAR(40) NOT NULL COMMENT '语义版本，写进产物；与 app_releases.version 同义',
		build_number INT UNSIGNED NOT NULL COMMENT 'Android versionCode / iOS build；服务端保证同租户同平台严格递增',
		status ENUM('queued','claimed','running','succeeded','failed','canceled') NOT NULL COMMENT '任务状态：queued=待认领，claimed=已认领未开工，running=构建中，succeeded=有产物，failed=有失败原因，canceled=人工取消',
		claimed_by VARCHAR(120) NULL COMMENT '认领这个任务的打包机自报标识，只用于排查，不作为鉴权依据；NULL=还没被认领',
		claimed_at DATETIME(3) NULL COMMENT '认领时间 UTC；NULL=还没被认领',
		heartbeat_at DATETIME(3) NULL COMMENT '代理最近一次心跳 UTC；用于在列表里标出卡死的任务',
		release_id VARCHAR(80) NULL COMMENT '构建成功后落到 app_releases 的那条记录；NULL=还没产物',
		artifact_sha256 CHAR(64) NULL COMMENT '产物 sha256，由代理计算并回报；NULL=还没产物',
		log_tail JSON NULL COMMENT '失败定位用的日志尾部，字符串数组，最多 200 行；完整日志在对象存储。NULL=还没有日志',
		log_object_key VARCHAR(512) NULL COMMENT '完整日志在租户对象存储里的键；NULL=没有上传日志',
		failure_reason VARCHAR(500) NULL COMMENT '失败原因一句话；NULL=没失败',
		reason VARCHAR(500) NOT NULL COMMENT '发起这次构建的原因，管理端必填，同时写进 audit_events',
		created_by VARCHAR(120) NOT NULL COMMENT '发起人',
		created_at DATETIME(3) NOT NULL COMMENT '创建时间 UTC',
		updated_at DATETIME(3) NOT NULL COMMENT '更新时间 UTC',
		PRIMARY KEY (id),
		KEY ix_build_jobs_queue (status, created_at),
		KEY ix_build_jobs_tenant (tenant_id, platform, created_at),
		UNIQUE KEY ux_build_jobs_build_number (tenant_id, platform, build_number)
	) ENGINE=InnoDB COMMENT='打包任务：管理端写入，打包机代理认领与回报。只记参数与结果，不记命令——服务端不在打包机上执行任意命令'`); err != nil {
		return fmt.Errorf("build jobs migration create table: %w", err)
	}
	return nil
}

// buildJobsRetryableMigration 让失败的构建可以用同一个版本号重来。
//
// 迁移 40 把唯一键直接建在 (tenant, platform, build_number) 上，结果是最常见的那条
// 路径走不通：构建失败 → 改一行代码 → 用同一个版本号重新构建，第二次会被唯一键
// 顶回来。而失败的构建本来就没有产物，那个号根本没被用掉。
//
// 改成只约束"还活着的"任务：生成列在 failed / canceled 时取 NULL，MySQL 的唯一索引
// 不比较 NULL，于是同一个号可以重试任意多次，但同时排两个仍然不行。
func buildJobsRetryableMigration(ctx context.Context, db *sql.DB) error {
	if err := addColumnIfMissing(ctx, db, "build_jobs", "live_build_number",
		`ALTER TABLE build_jobs ADD COLUMN live_build_number INT UNSIGNED
		 GENERATED ALWAYS AS (CASE WHEN status IN ('queued','claimed','running','succeeded') THEN build_number ELSE NULL END) STORED
		 COMMENT '还活着的任务的 build 号：failed/canceled 时为 NULL。唯一索引建在它上面，失败的构建因此可以用同一个号重来'`); err != nil {
		return fmt.Errorf("build jobs retryable migration add column: %w", err)
	}
	// 老索引可能不存在（全新库按新定义建表），删不掉不算错
	if _, err := db.ExecContext(ctx, `ALTER TABLE build_jobs DROP INDEX ux_build_jobs_build_number`); err != nil && !strings.Contains(err.Error(), "check that column/key exists") {
		return fmt.Errorf("build jobs retryable migration drop old index: %w", err)
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND INDEX_NAME='ux_build_jobs_live_build_number'`).Scan(&exists); err != nil {
		return fmt.Errorf("build jobs retryable migration inspect index: %w", err)
	}
	if exists == 0 {
		if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX ux_build_jobs_live_build_number ON build_jobs (tenant_id, platform, live_build_number)`); err != nil {
			return fmt.Errorf("build jobs retryable migration create index: %w", err)
		}
	}
	return nil
}

// buildJobsReleaseNotesMigration 让打包任务带上发布说明。
//
// 发布记录一旦建好就没有改说明的接口，而产物是代理建的记录——结果 2026-09-11 的
// 1.3.9 是带着空说明发出去的，用户看到一个没有任何说明的更新。说明必须在排队时
// 就跟着任务走。
func buildJobsReleaseNotesMigration(ctx context.Context, db *sql.DB) error {
	if err := addColumnIfMissing(ctx, db, "build_jobs", "release_notes",
		`ALTER TABLE build_jobs ADD COLUMN release_notes JSON NULL COMMENT '发布说明：语言码到字符串数组，随产物一起落进 app_releases。NULL=排队时没填' AFTER reason`); err != nil {
		return fmt.Errorf("build jobs release notes migration: %w", err)
	}
	return nil
}

// installationDeviceIntegrityMigration 存设备完整性信号（安全评审 N31）。
//
// 这是**自报**的信号，不是安全控制：被攻破的客户端当然可以说自己没 root。它的用处
// 是舰队视角——"我们的用户里有多少跑在 root 过的设备上"这个问题此前完全没有答案。
// 所以它只入库、只在管理端看，不参与任何放行判定。
//
// 每一项都可以是 NULL：探针本身可能失败，而 expo-device 的 root 检测明确标着
// experimental。把"探不出来"和"没有"混成同一个值，统计出来的数就是假的。
func installationDeviceIntegrityMigration(ctx context.Context, db *sql.DB) error {
	if err := addColumnIfMissing(ctx, db, "app_installations", "device_integrity",
		`ALTER TABLE app_installations ADD COLUMN device_integrity JSON NULL COMMENT '客户端自报的设备完整性信号：rooted/emulator/sideLoaded/devBundle，每项 true/false/null（null=探针失败或旧版未上报）。只作舰队统计，不参与任何放行判定——被攻破的客户端可以谎报' AFTER client_session_state`); err != nil {
		return fmt.Errorf("installation device integrity migration: %w", err)
	}
	return nil
}

// consistentDefaultConfigMigration 让平台默认配置成为一份**自己能通过校验**的配置。
//
// 默认那份（tenant_id=0）一直是 modules.predict=true 而 services 为空。服务端的
// predictServiceFor 对这种组合是硬拒：写入 400、下发 503。后果不是"预测市场用不了"，
// 而是**每个继承默认配置的新租户都被整体卡住**——App 拉配置拿 503（界面上只显示
// "配置连接失败"），而运营想在控制台改任何东西，哪怕只改一个主题色，保存也会被拒，
// 报错还只说 services.predict 没配。
//
// 这里只修那个矛盾，不改变任何"本来就说得通"的默认：仅当 predict 开着而
// services.predict 确实不存在时，把模块关掉。谁要用预测市场，在控制台打开并配上
// 平台关联即可——默认不开，是因为它需要外部平台的域名和 scopeId，平台不可能替租户
// 猜一个。
func consistentDefaultConfigMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE app_configs
		SET config_value=JSON_SET(config_value,'$.modules.predict',CAST(false AS JSON)),
		    version=version+1, updated_by='system-default-consistency', updated_at=UTC_TIMESTAMP(3)
		WHERE config_key='mobile-bootstrap'
		  AND tenant_id=0
		  AND JSON_EXTRACT(config_value,'$.modules.predict')=CAST(true AS JSON)
		  AND JSON_EXTRACT(config_value,'$.services.predict') IS NULL`)
	return err
}

// bootstrapTTLOwnsRefreshIntervalMigration 把"App 多久重新拉一次配置"搬到它该在的地方。
//
// 这个节奏一直由语言设置里的 refreshIntervalSeconds 决定（平台默认 21600 秒），而
// mobile-bootstrap 里的 ttlSeconds 下发到了设备却没有任何人读——两个字段，一个管用
// 一个不管用，管理端还分在两个页面上。从这一版起 ttlSeconds 是唯一的那个。
//
// 必须先搬值再改下发口径，而且两件事要在同一个二进制里：存量 ttlSeconds 大多是种子
// 配置里的 300，直接改口径会把全量设备的重拉从 6 小时变成 5 分钟，请求量涨 72 倍。
//
// 取值按"现在生效的那个"：租户自己的覆盖 > 平台默认 > 21600，再夹到 [300,86400]，
// 保证迁移之后每一行都满足新的下限（客户端也按这个下限严格解析）。
func bootstrapTTLOwnsRefreshIntervalMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `UPDATE app_configs bootstrap_config`+
		bootstrapTTLLanguagesJoin+
		`SET bootstrap_config.config_value=JSON_SET(bootstrap_config.config_value,'$.ttlSeconds',`+bootstrapTTLInEffect+`),
		    bootstrap_config.version=bootstrap_config.version+1,
		    bootstrap_config.updated_by='system-bootstrap-ttl',
		    bootstrap_config.updated_at=UTC_TIMESTAMP(3)
		WHERE bootstrap_config.config_key='mobile-bootstrap'`)
	return err
}

// 取值与夹取分开命名，测试可以单独对这段表达式求值：搬错了的后果是全量设备的
// 重拉节奏被改掉，而那是线上才看得见的事故。
const bootstrapTTLLanguagesJoin = `
		LEFT JOIN app_configs tenant_languages
		       ON tenant_languages.tenant_id=bootstrap_config.tenant_id AND tenant_languages.config_key='languages'
		LEFT JOIN app_configs global_languages
		       ON global_languages.tenant_id=0 AND global_languages.config_key='languages'
		`

const bootstrapTTLInEffect = `LEAST(GREATEST(COALESCE(
			NULLIF(CAST(JSON_EXTRACT(tenant_languages.config_value,'$.refreshIntervalSeconds') AS UNSIGNED),0),
			NULLIF(CAST(JSON_EXTRACT(global_languages.config_value,'$.refreshIntervalSeconds') AS UNSIGNED),0),
			21600),300),86400)`

// buildJobsOTAMigration 让打包任务也能是"构建一个热更新包"。
//
// 复用 build_jobs 而不是新建表：这就是同一种实体——一个排队等打包机干的活，状态流转、
// 心跳、超时回收、日志尾部、取消全都一样（见 AGENTS.md「先复用再建表」）。
//
// 唯一索引必须跟着改，否则 OTA 任务会和**产生它基线的那条 APK 任务**撞号：
// live_build_number 原来对 queued/claimed/running/succeeded 都取 build_number，而基线那条
// APK 任务正是 succeeded。表现是排队直接 500，而报错完全看不出根因。OTA 不产生新的
// build 号，索引里干脆不收它。
//
// 同时加一条 OTA 自己的并发闸：live_ota_slot 让同租户同平台**同时只能有一条在跑的 OTA
// 任务**。APK 那边的并发上限是 build 号递增天然给的，OTA 没有这个约束——不加闸，一个
// 租户点十下就把跨租户的队列占满了。
func buildJobsOTAMigration(ctx context.Context, db *sql.DB) error {
	columns := []struct{ name, ddl string }{
		{"kind", `ALTER TABLE build_jobs ADD COLUMN kind ENUM('apk','ota') NOT NULL DEFAULT 'apk'
			COMMENT '任务类型：apk=编译安装包，ota=构建热更新包。老数据都是 apk' AFTER platform`},
		{"base_release_id", `ALTER TABLE build_jobs ADD COLUMN base_release_id VARCHAR(80) NULL
			COMMENT 'OTA 的基线安装包（app_releases.id）：热更新只发给装着这一版的设备。apk 任务为 NULL'`},
		{"channel", `ALTER TABLE build_jobs ADD COLUMN channel VARCHAR(40) NULL
			COMMENT 'OTA 发布 channel（production 等）；apk 任务为 NULL'`},
		{"apply_strategy", `ALTER TABLE build_jobs ADD COLUMN apply_strategy ENUM('next_launch','immediate') NULL
			COMMENT 'OTA 生效方式：next_launch=下次冷启动，immediate=拉到后立刻重启应用；apk 任务为 NULL'`},
		{"ota_release_id", `ALTER TABLE build_jobs ADD COLUMN ota_release_id VARCHAR(80) NULL
			COMMENT '构建成功后落到 ota_releases 的那条修订；NULL=还没有。apk 任务用 release_id'`},
	}
	for _, column := range columns {
		if err := addColumnIfMissing(ctx, db, "build_jobs", column.name, column.ddl); err != nil {
			return fmt.Errorf("build jobs ota migration add %s: %w", column.name, err)
		}
	}
	// 生成列的表达式改不了，只能连索引一起重建
	var current string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(GENERATION_EXPRESSION,'') FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND COLUMN_NAME='live_build_number'`).Scan(&current); err != nil {
		return fmt.Errorf("build jobs ota migration inspect generated column: %w", err)
	}
	if !strings.Contains(current, "kind") {
		if _, err := db.ExecContext(ctx, `ALTER TABLE build_jobs DROP INDEX ux_build_jobs_live_build_number`); err != nil &&
			!strings.Contains(err.Error(), "check that column/key exists") {
			return fmt.Errorf("build jobs ota migration drop build number index: %w", err)
		}
		if _, err := db.ExecContext(ctx, `ALTER TABLE build_jobs DROP COLUMN live_build_number`); err != nil {
			return fmt.Errorf("build jobs ota migration drop generated column: %w", err)
		}
		if _, err := db.ExecContext(ctx, `ALTER TABLE build_jobs ADD COLUMN live_build_number INT UNSIGNED
			GENERATED ALWAYS AS (CASE WHEN kind='apk' AND status IN ('queued','claimed','running','succeeded') THEN build_number ELSE NULL END) STORED
			COMMENT '还活着的 APK 任务的 build 号：失败/取消/以及全部 OTA 任务为 NULL。唯一索引建在它上面'`); err != nil {
			return fmt.Errorf("build jobs ota migration add generated column: %w", err)
		}
		if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX ux_build_jobs_live_build_number ON build_jobs (tenant_id, platform, live_build_number)`); err != nil {
			return fmt.Errorf("build jobs ota migration recreate build number index: %w", err)
		}
	}
	if err := addColumnIfMissing(ctx, db, "build_jobs", "live_ota_slot",
		`ALTER TABLE build_jobs ADD COLUMN live_ota_slot TINYINT UNSIGNED
			GENERATED ALWAYS AS (CASE WHEN kind='ota' AND status IN ('queued','claimed','running') THEN 1 ELSE NULL END) STORED
			COMMENT '在跑的 OTA 任务占位：同租户同平台同时只允许一条。做完（成功或失败）就释放'`); err != nil {
		return fmt.Errorf("build jobs ota migration add ota slot: %w", err)
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND INDEX_NAME='ux_build_jobs_live_ota'`).Scan(&exists); err != nil {
		return fmt.Errorf("build jobs ota migration inspect ota index: %w", err)
	}
	if exists == 0 {
		if _, err := db.ExecContext(ctx, `CREATE UNIQUE INDEX ux_build_jobs_live_ota ON build_jobs (tenant_id, platform, live_ota_slot)`); err != nil {
			return fmt.Errorf("build jobs ota migration create ota index: %w", err)
		}
	}
	return nil
}

// diagnosticReportsMigration 建一键上报的元数据表，并把 features.crashAutoReport 显式补进
// 每一份 mobile-bootstrap（设计 docs/design/diagnostic-report-2026-09-14.md，存于 RN-App）。
//
// 复用映射（AGENTS.md「先复用再建表」）：
//   - 报告本身是新实体：现有表里没有"用户/崩溃提交的一次诊断"，不能挂进 audit_events
//     （那是管理操作与系统事件的历史，报告有自己的状态流转和筛选维度）；
//   - 日志正文不进库，放对象存储，这里只存 object_key；
//   - 设备归并 ID、钱包地址**不复制**：前者由 installation_id 关联 app_installations 得到，
//     后者由 wallet_user_id 关联 wallet_user 得到（地址即账号，不会变）；
//   - 版本、渠道、系统这些列与 app_installations **不是**同一个事实：那边是最新状态、每次
//     心跳覆盖，这里是上报那一刻的快照——排查要的正是"出问题时跑的是哪一版"；
//   - running_ota_revision 同理：ota_releases 的行可以被清理掉，上报时解析出的修订号是历史事实。
//
// features.crashAutoReport 补 false：bootstrap 下发用 truth() 取值，缺键也是 false，所以不补
// 契约也成立；补是为了管理端「功能开关」区能看见这一项——那一区按 config.features 的键渲染。
// 只补缺的，已经有值的不动。
func diagnosticReportsMigration(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS app_diagnostic_reports (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
		tenant_id BIGINT UNSIGNED NOT NULL COMMENT '租户ID；由请求域名解析，不信任客户端',
		reference CHAR(8) NOT NULL COMMENT '给用户念给客服的参考号：Crockford base32，不含 I/L/O/U，租户内唯一',
		report_id VARCHAR(80) NOT NULL COMMENT '客户端生成的幂等键；同一安装实例重复提交返回同一条',
		installation_id VARCHAR(80) NOT NULL COMMENT '上报的安装实例（app_installations.installation_id），由安装凭证校验得出；设备归并 ID 由此关联，不复制',
		wallet_user_id BIGINT UNSIGNED NULL COMMENT '上报时该安装实例上有效会话的钱包用户（wallet_user.id），服务端由会话解析；NULL=未登录',
		kind ENUM('user','crash','crash_auto') NOT NULL COMMENT '来源：user=用户主动上报，crash=崩溃后用户确认上报，crash_auto=崩溃后下次启动自动上报',
		note VARCHAR(200) NULL COMMENT '用户填写的问题描述，截断到 200 字符；crash_auto 恒为 NULL',
		crash_fingerprint CHAR(16) NULL COMMENT '崩溃指纹：error.name + 顶层栈帧的哈希前 16 位十六进制，用于按同一崩溃聚合；非崩溃为 NULL',
		crash_error_name VARCHAR(80) NULL COMMENT '崩溃的错误类名（如 TypeError）；非崩溃为 NULL',
		platform ENUM('android','ios') NOT NULL COMMENT '上报时的平台（快照）',
		app_version VARCHAR(40) NOT NULL COMMENT '上报时的 App 版本（快照；app_installations 那边是最新值，会被心跳覆盖）',
		build_number VARCHAR(40) NOT NULL COMMENT '上报时的构建号（快照）',
		runtime_version VARCHAR(160) NOT NULL COMMENT '上报时的 expo 运行时版本（快照）',
		distribution_channel VARCHAR(40) NOT NULL COMMENT '上报时的分发渠道（快照）',
		ota_channel VARCHAR(40) NOT NULL COMMENT '上报时的 OTA channel（快照）',
		launch_source ENUM('embedded','ota') NULL COMMENT '上报时运行的 bundle 来源：embedded=内置包，ota=热更新包；NULL=客户端未上报',
		running_update_id CHAR(36) NULL COMMENT '上报时运行的 expo-updates update id；embedded 时为 NULL',
		running_ota_revision INT UNSIGNED NULL COMMENT '写入时由 running_update_id 关联本租户 ota_releases 得到的修订号；关联不上为 NULL。存下来是因为 OTA 发布记录可能被清理',
		locale VARCHAR(40) NULL COMMENT '上报时的界面语言，如 zh-CN',
		os_version VARCHAR(40) NULL COMMENT '上报时的系统版本',
		device_class VARCHAR(80) NULL COMMENT '上报时的设备类别，如 android-phone',
		context JSON NULL COMMENT '上报现场：{"screen":路由名,"lastRequestId":最近一次失败请求的ID,"networkType":网络类型}；键都可缺省',
		object_key VARCHAR(512) NULL COMMENT '日志正文在对象存储里的键（服务端重新序列化并 gzip 后的 NDJSON）；不存访问 URL。NULL=还没有日志',
		log_status ENUM('awaiting','stored','storage_unavailable','failed') NOT NULL DEFAULT 'awaiting' COMMENT '日志状态：awaiting=元数据已收、等日志；stored=已落盘；storage_unavailable=租户没有可用对象存储；failed=收到了但落盘失败。awaiting 超过 30 分钟由读取方显示为未上传，不回写',
		entry_count SMALLINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '落盘的日志条数（服务端解析、丢弃非法行之后）',
		byte_size INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '落盘对象大小，单位字节（gzip 后）；计入租户每日字节预算',
		dropped_lines SMALLINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '被丢弃的日志行数：解析失败、level/tag 不在枚举内、单行超长、超出总行数',
		redaction_hits SMALLINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '服务端二次脱敏命中的行数；>0 表示客户端那一遍没拦住（旧版本或被改过的客户端），管理端标红',
		status ENUM('new','triaged','closed') NOT NULL DEFAULT 'new' COMMENT '处理状态：new=未处理，triaged=已处理，closed=已关闭；变更写 audit_events',
		occurred_at DATETIME(3) NOT NULL COMMENT '客户端声明的问题发生时间（UTC）；仅作展示，排序与配额用 created_at',
		created_at DATETIME(3) NOT NULL COMMENT '服务端收到元数据的时间（UTC）',
		updated_at DATETIME(3) NOT NULL COMMENT '最后一次变更时间（UTC）：日志落盘或状态变更',
		PRIMARY KEY(id),
		UNIQUE KEY uq_diag_reference(tenant_id, reference),
		UNIQUE KEY uq_diag_idempotent(tenant_id, installation_id, report_id),
		KEY ix_diag_tenant_time(tenant_id, created_at, byte_size),
		KEY ix_diag_installation(tenant_id, installation_id, kind, created_at),
		KEY ix_diag_user(tenant_id, wallet_user_id, created_at),
		KEY ix_diag_fingerprint(tenant_id, crash_fingerprint, created_at)
	) ENGINE=InnoDB COMMENT='App 诊断上报元数据。移动端接口写入、管理端读取与处理；日志正文在对象存储，这里只存键。不设保留期'`); err != nil {
		return fmt.Errorf("create app_diagnostic_reports: %w", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE app_configs
		SET config_value=JSON_SET(config_value,'$.features.crashAutoReport',CAST(false AS JSON)),
		    version=version+1, updated_by='system-diagnostic-reports', updated_at=UTC_TIMESTAMP(3)
		WHERE config_key='mobile-bootstrap'
		  AND JSON_EXTRACT(config_value,'$.features') IS NOT NULL
		  AND JSON_EXTRACT(config_value,'$.features.crashAutoReport') IS NULL`); err != nil {
		return fmt.Errorf("backfill features.crashAutoReport: %w", err)
	}
	return nil
}

// ---------- 邀请关系（设计 RN-App/docs/design/referral-graph-2026-09-15.md §3.5、ADR 0018） ----------
//
// 三个独立版本，不是一条 ALTER。把加列与唯一键写在一起会先给已有行填空串，
// 唯一键随即全表冲突（实测 ERROR 1062）；而且失败后不幂等——ALTER 已自动提交，
// 重启会报 Duplicate column name，服务永久起不来，必须人工改库。
//
// 没有第四步：invite_code 永久可空，不收紧成 NOT NULL。理由见 referralColumnsMigration
// 的注释与 docs/database/REFERRAL_SCHEMA.md。

// referralColumnsMigration 加四列，全部可空。
func referralColumnsMigration(ctx context.Context, db *sql.DB) error {
	columns := []struct{ column, ddl string }{
		// invite_code 必须可空，而且永远不收紧：
		//  1. 登录是 INSERT ... ON DUPLICATE KEY UPDATE（api/wallet_auth.go）。MySQL 对
		//     任意唯一键冲突都走 ON DUPLICATE 分支，把 invite_code 放进那条语句，抽到的码
		//     撞上他人的码时会去更新"那一行"（实测 address 被改成新用户的地址、
		//     ROW_COUNT()=2），随后按 address_key 查不到自己 -> 500；且 ODUP 不抛 1062，
		//     "碰撞后重试"无从捕获。所以码由注册事务里一条独立 UPDATE 赋予。
		//  2. 改成 NOT NULL 无默认值，服务端回滚到旧二进制后旧 INSERT 不带该列，
		//     strict 模式报 ERROR 1364，老用户也登不上——回滚等于全站登录中断。
		//  3. NOT NULL DEFAULT '' 则两个并发新用户都插空串，在唯一键上互撞，回到第 1 条。
		// 可空列上的多个 NULL 在唯一索引里不冲突，这正是需要的。
		{"invite_code", `ALTER TABLE wallet_user ADD COLUMN invite_code CHAR(8) NULL COMMENT '该账号的邀请码，注册事务内生成、永不更换；Crockford Base32 大写（0-9A-Z 去掉 I L O U），租户内唯一。可空是为了与登录的 ON DUPLICATE KEY UPDATE 共存，人人有码由注册事务保证；读到 NULL 是事故' AFTER status`},
		{"inviter_user_id", `ALTER TABLE wallet_user ADD COLUMN inviter_user_id BIGINT UNSIGNED NULL COMMENT '直接邀请人的 wallet_user.id，必为同租户；NULL=没有邀请人。一次性写入，写入后不可改、不可解除' AFTER invite_code`},
		{"invited_at", `ALTER TABLE wallet_user ADD COLUMN invited_at DATETIME(3) NULL COMMENT '绑定邀请人的时刻（UTC）；与 inviter_user_id 同生共死。后续返佣按此时间分期' AFTER inviter_user_id`},
		{"invite_source", `ALTER TABLE wallet_user ADD COLUMN invite_source ENUM('code','link','admin') NULL COMMENT '绑定渠道：code 手输邀请码，link 邀请链接深链（相机扫二维码也走这条），admin 管理端补录；只用于运营统计，不参与任何判定' AFTER invited_at`},
	}
	for _, item := range columns {
		if err := addColumnIfMissing(ctx, db, "wallet_user", item.column, item.ddl); err != nil {
			return fmt.Errorf("referral columns migration %s: %w", item.column, err)
		}
	}
	return nil
}

// referralCodeBackfillMigration 给存量账号补邀请码。
//
// 只处理 invite_code IS NULL 的行，可以重复执行：中断后重跑不会给已经有码的行换码。
// 此时唯一键还没建（下一版才建），所以这里自己查重；真正的兜底是下一版建唯一键时
// 若仍有重复会失败，而不是悄悄放过。
//
// 不假设"线上只有个位数用户"：任何测试库、任何租户长到 2 人，这段都得照样正确。
func referralCodeBackfillMigration(ctx context.Context, db *sql.DB) error {
	for {
		rows, err := db.QueryContext(ctx, `SELECT id, tenant_id FROM wallet_user WHERE invite_code IS NULL LIMIT 500`)
		if err != nil {
			return fmt.Errorf("referral backfill select: %w", err)
		}
		type pending struct {
			id       uint64
			tenantID uint64
		}
		var batch []pending
		for rows.Next() {
			var item pending
			if err := rows.Scan(&item.id, &item.tenantID); err != nil {
				rows.Close()
				return fmt.Errorf("referral backfill scan: %w", err)
			}
			batch = append(batch, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("referral backfill rows: %w", err)
		}
		rows.Close()
		if len(batch) == 0 {
			return nil
		}
		for _, item := range batch {
			if err := backfillOneInviteCode(ctx, db, item.id, item.tenantID); err != nil {
				return err
			}
		}
	}
}

// backfillOneInviteCode 给一行补码，撞上同租户已有的码就换一个再试。
func backfillOneInviteCode(ctx context.Context, db *sql.DB, userID, tenantID uint64) error {
	for attempt := 0; attempt < referral.Attempts; attempt++ {
		code, err := referral.Generate()
		if err != nil {
			return fmt.Errorf("referral backfill generate: %w", err)
		}
		// 唯一键此时还不存在，自己查重；条件里带 invite_code IS NULL 让这条语句可重入
		result, err := db.ExecContext(ctx, `UPDATE wallet_user SET invite_code=?, updated_at=UTC_TIMESTAMP(3)
			WHERE id=? AND invite_code IS NULL
			  AND NOT EXISTS (SELECT 1 FROM (SELECT 1 FROM wallet_user WHERE tenant_id=? AND invite_code=?) AS taken)`,
			code, userID, tenantID, code)
		if err != nil {
			return fmt.Errorf("referral backfill update: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("referral backfill rows affected: %w", err)
		}
		if affected == 1 {
			return nil
		}
		// 0 行有两种可能：码被占（换一个重试），或这一行已经被并发的迁移补上了（直接算完成）
		var stillEmpty int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_user WHERE id=? AND invite_code IS NULL`, userID).Scan(&stillEmpty); err != nil {
			return fmt.Errorf("referral backfill recheck: %w", err)
		}
		if stillEmpty == 0 {
			return nil
		}
	}
	return fmt.Errorf("referral backfill: could not find a free invite code for wallet_user %d after %d attempts", userID, referral.Attempts)
}

// referralIndexesMigration 建三个新索引与 CHECK 约束。
//
// 三个索引不是两个：管理端的关系列表没有 inviter_user_id 等值条件，
// ix_wallet_user_inviter 的第二列断开，优化器会退回 filesort（实测 rows≈9918），
// 所以它需要自己的 (tenant_id, invited_at, id)。
//
// CHECK 不是锦上添花：漏写一列产生的 inviter_user_id 非空、invited_at 为 NULL 的行，
// 会被键集分页的游标条件（NULL < ts 不为真）全部排除，在上级的下级列表里永久不可见，
// 而 total 仍把它算进去。
func referralIndexesMigration(ctx context.Context, db *sql.DB) error {
	indexes := []struct{ index, ddl string }{
		{"uq_wallet_user_invite_code", `ALTER TABLE wallet_user ADD UNIQUE KEY uq_wallet_user_invite_code (tenant_id, invite_code) COMMENT '邀请码租户内唯一；生成碰撞由该键抛 1062，应用层换码重试。可空列上的多个 NULL 不冲突'`},
		{"ix_wallet_user_inviter", `ALTER TABLE wallet_user ADD KEY ix_wallet_user_inviter (tenant_id, inviter_user_id, invited_at, id) COMMENT '移动端「我的下级」：按绑定时间键集分页，末列 id 唯一决胜'`},
		{"ix_wallet_user_invited_at", `ALTER TABLE wallet_user ADD KEY ix_wallet_user_invited_at (tenant_id, invited_at, id) COMMENT '管理端关系列表：没有 inviter_user_id 等值条件，用不上 ix_wallet_user_inviter'`},
	}
	for _, item := range indexes {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wallet_user' AND INDEX_NAME=?`, item.index).Scan(&count); err != nil {
			return fmt.Errorf("referral indexes migration inspect %s: %w", item.index, err)
		}
		if count > 0 {
			continue
		}
		if _, err := db.ExecContext(ctx, item.ddl); err != nil {
			return fmt.Errorf("referral indexes migration add %s: %w", item.index, err)
		}
	}
	var checks int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wallet_user' AND CONSTRAINT_NAME='ck_wallet_user_referral_triple'`).Scan(&checks); err != nil {
		return fmt.Errorf("referral indexes migration inspect check: %w", err)
	}
	if checks == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE wallet_user ADD CONSTRAINT ck_wallet_user_referral_triple CHECK (
			(inviter_user_id IS NULL AND invited_at IS NULL AND invite_source IS NULL)
			OR (inviter_user_id IS NOT NULL AND invited_at IS NOT NULL AND invite_source IS NOT NULL))`); err != nil {
			return fmt.Errorf("referral indexes migration add check: %w", err)
		}
	}
	return nil
}

// platformBackupsMigration 建打包服务故障恢复备份的运行记录表
// （设计 platform-backup-recovery-2026-09-15 §8.4）。
//
// 为什么是新表而不是塞进 app_configs 或 audit_events：一次备份有生命周期
// （pending → running → succeeded/failed）、有四个写方（控制台建、打包机认领与上报、
// 服务端收尾、超时扫描）、条数随时间无界增长。app_configs 的一行 JSON 装不下多写方
// 加无界增长，audit_events 只能追加、表达不了在途状态。
//
// **整张表一条 CREATE TABLE IF NOT EXISTS 建完**，生成列和三个索引全部写在里面。
// 分步建的话，CREATE TABLE 成功、CREATE INDEX 失败会让 schema_migrations 那一行
// 永远写不进去（migrations.go 的 apply 失败就不记账），下次启动重跑撞
// ERROR 1050 Table already exists，然后**永久启动失败循环——倒下的不是备份功能，
// 是整个 wallet 后端**。build-concurrency-2026-09-15.md 逐字测过这条红线。
//
// seq 用 AUTO_INCREMENT 而不是 COALESCE(MAX(seq),0)+1：后者在 REPEATABLE READ 下是
// 一致性读，两个并发事务读到同一个值，第二个要**阻塞整个第一个事务的时长**才拿到
// 1062，而且报的索引是 seq 那个不是 live 那个（MySQL 对同时违反两个唯一索引的
// INSERT 报先建的那一个）。按契约只匹配 live 索引翻 409 的话，并发那条会掉进 500。
// 自增锁不参与事务，换成它之后唯一能冲突的就剩 live_slot，错误映射唯一。
func platformBackupsMigration(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS platform_backups (
		id VARCHAR(80) NOT NULL COMMENT '主键，pbk_ 前缀',
		seq INT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '编号，全局递增，进对象键；下载按它取，不接受外部传对象键。自增由数据库发号，回滚留下的号洞无害',
		status ENUM('pending','running','succeeded','failed') NOT NULL COMMENT '状态：pending=已建待办等打包机认领，running=打包机已认领在产出，succeeded=三组包都已上传，failed=任一环节失败',
		trigger_by ENUM('manual','schedule') NOT NULL COMMENT '触发来源：manual=控制台按钮，schedule=定时',
		requested_by VARCHAR(120) NOT NULL COMMENT '发起人；定时触发时写 system-backup',
		reason VARCHAR(500) NOT NULL COMMENT '发起原因，手动触发由人填；定时触发写固定常量 scheduled backup',
		claimed_by VARCHAR(120) NULL COMMENT '认领的打包机自报标识，只用于排查，不作为鉴权依据；NULL=还没被认领',
		claimed_at DATETIME(3) NULL COMMENT '认领时间 UTC；NULL=还没被认领',
		payload_received_at DATETIME(3) NULL COMMENT '打包机两份内层密文**都**到齐的时间 UTC；NULL=还没到齐。产出超时据它和 claimed_at 分段判断，卡住时才分得清该去哪台机器看',
		objects JSON NULL COMMENT '这一次产出的每一组包，固定三组：[{"pair":"AB","objectKey":"...","sha256":"...","sizeBytes":123}]。存成列表而不是三个固定列，是因为它要如实记下那一次实际产出了什么——换公钥、部分上传失败都会让某一次和别的不一样，控制台按这一列渲染而不是按当前配置。下载按 pair 从这里查键，不重新拼。NULL=还没上传成功',
		tenant_count INT UNSIGNED NULL COMMENT '这次备了几个租户的签名密钥，突然变少要人看一眼；NULL=还没产出',
		failure_reason VARCHAR(500) NULL COMMENT '失败原因一句话；NULL=没失败',
		created_at DATETIME(3) NOT NULL COMMENT '创建时间 UTC',
		updated_at DATETIME(3) NOT NULL COMMENT '更新时间 UTC',
		live_slot TINYINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN status IN ('pending','running') THEN 1 ELSE NULL END) STORED
			COMMENT '未结束的备份占位：pending/running 时为 1，其余为 NULL。唯一索引建在它上面，保证同时只有一条在途；MySQL 唯一索引不比较 NULL，所以结束后可以立刻建下一条。由数据库生成，无人写入',
		PRIMARY KEY (id),
		UNIQUE KEY ux_platform_backups_seq (seq),
		UNIQUE KEY ux_platform_backups_live (live_slot),
		KEY ix_platform_backups_status (status, created_at)
	) ENGINE=InnoDB COMMENT='平台备份运行记录：控制台或定时建待办，打包机认领并产出，服务端收尾。只记状态与结果，备份内容本身在对象存储里'`)
	if err != nil {
		return fmt.Errorf("platform backups migration: %w", err)
	}
	return nil
}
