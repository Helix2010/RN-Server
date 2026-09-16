package main

import (
	"fmt"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Helix2010/RN-Server/internal/config"
)

// printConfig 是 `rn-server config`：把这台机器上**实际生效**的配置打出来。
//
// 在此之前，回答"服务端现在到底跑在什么配置上"只有一条路：ssh 上去 grep
// /etc/rn-foundation.env，然后在脑子里和代码里的默认值做一次合并——而那份 env 里
// 有二十多行写的就是默认值，看不出哪些是真的覆盖。这条命令把合并的结果直接给出来。
//
// 机密只报"设了没有、多长"。打 DSN 用 RedactedMySQLDSN：口令打码走结构体复制，
// 不在字符串上做正则——口令里可以合法地含 '@'，正则会打错位置。
func printConfig(cfg config.Config) {
	fmt.Println("# 生效配置（机密只显示长度）")
	fmt.Println()

	fmt.Println("## 数据库")
	fmt.Printf("  来源           %s\n", cfg.MySQLSource)
	fmt.Printf("  连接           %s\n", cfg.RedactedMySQLDSN())
	if len(cfg.MySQLDefaulted) > 0 {
		// 补了什么必须说出来：驱动的默认值和我们的不一样，而差异要到运行时才发作
		fmt.Printf("  服务端补齐     %s\n", strings.Join(cfg.MySQLDefaulted, ", "))
	}
	section("", []entry{
		num("MYSQL_CONNECTION_LIMIT", cfg.MySQLConnectionLimit),
		num("MYSQL_MAX_IDLE_CONNECTIONS", cfg.MySQLMaxIdleConnections),
		num("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", cfg.MySQLConnectionMaxLifetime),
		num("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", cfg.MySQLConnectionMaxIdleTime),
		num("MYSQL_QUERY_TIMEOUT_SECONDS", cfg.MySQLQueryTimeout),
		num("MYSQL_INIT_TIMEOUT_SECONDS", cfg.MySQLInitTimeout),
		num("MYSQL_INIT_MAX_ATTEMPTS", cfg.MySQLInitMaxAttempts),
		num("MYSQL_INIT_RETRY_DELAY_SECONDS", cfg.MySQLInitRetryDelay),
		yesNo("MYSQL_AUTO_MIGRATE", cfg.MySQLAutoMigrate),
	})

	section("这台机器", []entry{
		text("APP_ENV", cfg.Environment),
		text("BIND_ADDRESS", cfg.BindAddress),
		text("PORT", cfg.Port),
		list("TRUSTED_PROXIES", cfg.TrustedProxies),
		list("PLATFORM_ADMIN_USERNAMES", cfg.PlatformAdminUsernames),
		list("CORS_ORIGINS", cfg.CORSOrigins),
		num("HTTP_READ_TIMEOUT_SECONDS", cfg.HTTPReadTimeout),
		num("HTTP_WRITE_TIMEOUT_SECONDS", cfg.HTTPWriteTimeout),
	})

	section("管理端", []entry{
		text("ADMIN_USERNAME", cfg.AdminUsername),
		secret("ADMIN_PASSWORD_HASH", cfg.AdminPasswordHash),
		secret("ADMIN_API_KEY", cfg.AdminAPIKey),
		text("ADMIN_API_ACTOR", cfg.AdminAPIActor),
		list("ADMIN_API_ALLOWED_IPS", cfg.AdminAPIAllowedIPs),
		num("ADMIN_SESSION_TTL_SECONDS", cfg.AdminSessionTTL),
		yesNo("ADMIN_COOKIE_SECURE", cfg.AdminCookieSecure),
		num("ADMIN_LOGIN_MAX_ATTEMPTS", cfg.AdminLoginMax),
		num("ADMIN_LOGIN_WINDOW_SECONDS", cfg.AdminLoginWindow),
	})

	section("机密与打包", []entry{
		secret("STORAGE_MASTER_KEY", cfg.StorageMasterKey),
		secret("BUILD_AGENT_TOKEN", cfg.BuildAgentToken),
		secret("DEVICE_IDENTITY_HMAC_KEY", os.Getenv("DEVICE_IDENTITY_HMAC_KEY")),
	})

	section("产物存储", []entry{
		num("ARTIFACT_MAX_SIZE_MB", int(cfg.ArtifactMaxSizeBytes/(1024*1024))),
		text("ARTIFACT_UPLOAD_MODE", cfg.ArtifactUploadMode),
		num("ARTIFACT_UPLOAD_TTL_SECONDS", cfg.ArtifactUploadTTL),
		num("ARTIFACT_MULTIPART_TTL_SECONDS", cfg.ArtifactMultipartTTL),
		num("ARTIFACT_VERIFY_TIMEOUT_SECONDS", cfg.ArtifactVerifyTimeout),
	})

	// 灾难当天要在一台起不来的机器上回答「这台机器认的是哪三把钥匙」。
	// 没有这一节，唯一的办法是自己 base64 解 env
	section("备份与恢复", []entry{
		yesNo("BACKUP_ENABLED", cfg.Backup.Enabled()),
		text("BACKUP_INSTANCE_ID", cfg.Backup.InstanceID),
		num("BACKUP_INTERVAL_HOURS", cfg.Backup.IntervalHours),
		text("BACKUP_BUCKET", cfg.Backup.Bucket.Bucket),
		text("BACKUP_BUCKET_REGION", cfg.Backup.Bucket.Region),
	})
	for i, slot := range backupcontainer.SlotNames {
		fingerprint := cfg.Backup.Recipients[i].Fingerprint
		if fingerprint == "" {
			fingerprint = "(未配置)"
		}
		fmt.Printf("  恢复公钥 %s 指纹: %s\n", slot, fingerprint)
	}
	fmt.Println("  （上面是 DER SPKI 的 SHA-256，64 字符。打包机公钥那个 16 字符的指纹")
	fmt.Println("   是另一回事，用 build-agent show-key 看，两者不要混。）")

	section("推送", []entry{
		yesNo("PUSH_DISPATCH_ENABLED", cfg.PushDispatchEnabled),
		num("PUSH_POLL_INTERVAL_SECONDS", cfg.PushPollInterval),
		num("PUSH_CONCURRENCY", cfg.PushConcurrency),
	})
	fmt.Println("  凭据按租户存在库里（app_configs 的 push.fcm / push.apns / push.hms），")
	fmt.Println("  不在这里；用管理端或 `rn-server push-credentials import-env` 查看与迁移。")
	if cfg.FCMProjectID != "" || cfg.FCMServiceAccountJSON != "" {
		fmt.Println("  ⚠ env 里还留着 FCM_PROJECT_ID / FCM_SERVICE_ACCOUNT_JSON：已弃用，见上一行")
	}

	section("扫链", []entry{
		// 按 `rn-server indexer` 那个入口报告：那才是这个键唯一起作用的地方
		yesNo("INDEXER_ENABLED", cfg.IndexerEnabledFor("indexer")),
		yesNo("INDEXER_ALLOW_PLAIN_HTTP", cfg.IndexerAllowPlainHTTP),
		secret("INDEXER_ALERT_WEBHOOK", cfg.IndexerAlertWebhook),
	})

	if cfg.MySQLSource != "MYSQL_DSN" {
		fmt.Println()
		fmt.Println("⚠ 没有设 MYSQL_DSN，用的是开发默认连接。生产上这会直接拒绝启动。")
	}
	if unknown := unknownMySQLKeys(); len(unknown) > 0 {
		fmt.Println()
		fmt.Printf("⚠ env 里有代码从不读取的键：%s\n", strings.Join(unknown, ", "))
	}
}

// unknownMySQLKeys 挑出那些看着像我们的、其实没人读的键。
//
// 这条存在是因为生产示例里躺了很久一个 INDEXER_MYSQL_CONNECTION_LIMIT=4，
// amos 上也照着填了——代码从来没读过它。配错了不报错的键，比配错了报错的键难查。
func unknownMySQLKeys() []string {
	known := map[string]bool{
		"MYSQL_DSN": true, "MYSQL_HOST": true, "MYSQL_PORT": true, "MYSQL_USER": true,
		"MYSQL_PASSWORD": true, "MYSQL_DATABASE": true, "MYSQL_CHARSET": true,
		"MYSQL_TIMEZONE": true, "MYSQL_PARSE_TIME": true, "MYSQL_CONNECT_TIMEOUT_SECONDS": true,
		"MYSQL_READ_TIMEOUT_SECONDS": true, "MYSQL_WRITE_TIMEOUT_SECONDS": true,
		"MYSQL_CONNECTION_LIMIT": true, "MYSQL_MAX_IDLE_CONNECTIONS": true,
		"MYSQL_CONNECTION_MAX_LIFETIME_SECONDS": true, "MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS": true,
		"MYSQL_QUERY_TIMEOUT_SECONDS": true, "MYSQL_INIT_TIMEOUT_SECONDS": true,
		"MYSQL_INIT_MAX_ATTEMPTS": true, "MYSQL_INIT_RETRY_DELAY_SECONDS": true,
		"MYSQL_AUTO_MIGRATE": true,
	}
	var unknown []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if strings.Contains(key, "MYSQL") && !known[key] && !strings.HasPrefix(key, "RN_TEST_") {
			unknown = append(unknown, key)
		}
	}
	sort.Strings(unknown)
	return unknown
}

type entry struct {
	key, value string
	// fromEnv 说明这个值是 env 给的还是代码默认的。写了等于默认值的那二十几行，
	// 正是这次收缩要删掉的——先得能看出它们是哪些。
	fromEnv bool
}

func section(title string, entries []entry) {
	if title != "" {
		fmt.Println()
		fmt.Println("## " + title)
	}
	for _, e := range entries {
		origin := "default"
		if e.fromEnv {
			origin = "env"
		}
		fmt.Printf("  %-40s %-28s %s\n", e.key, e.value, origin)
	}
}

func set(key string) bool { return strings.TrimSpace(os.Getenv(key)) != "" }

func text(key, value string) entry {
	if value == "" {
		value = "(空)"
	}
	return entry{key, value, set(key)}
}

func num(key string, value int) entry { return entry{key, strconv.Itoa(value), set(key)} }

func yesNo(key string, value bool) entry { return entry{key, strconv.FormatBool(value), set(key)} }

func list(key string, values []string) entry {
	joined := "(空)"
	if len(values) > 0 {
		joined = strings.Join(values, ",")
	}
	return entry{key, joined, set(key)}
}

// secret 只报长度。看的人要回答的是"设了没有、是不是被截断了"，而不是值本身。
func secret(key, value string) entry {
	shown := "(未设置)"
	if value != "" {
		shown = fmt.Sprintf("<已设置，%d 字符>", len(value))
	}
	return entry{key, shown, set(key)}
}
