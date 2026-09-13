package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Config struct {
	Environment string
	Port        string
	// 监听地址。空 = 所有网卡（Docker 部署靠端口映射限制暴露面）。裸机部署要显式
	// 填 127.0.0.1，否则应用端口会绕过反向代理直接对外，TLS 和它上面的一切都白设
	BindAddress      string
	HTTPReadTimeout  int
	HTTPWriteTimeout int
	// CORSOrigins 是**额外**放行的来源。租户自己的域名由 tenant_domain 表推导
	// （见 originAllowed），不需要写在这里；生产上这一项通常是空的。
	CORSOrigins     []string
	AdminAPIKey     string
	BuildAgentToken string
	AdminAPIActor   string
	// AdminAPIAllowedIPs limits the x-admin-key automation channel to these
	// networks (CIDR or bare IP). Empty means no restriction — see N17.
	AdminAPIAllowedIPs []string
	// TrustedProxies are the hops allowed to set X-Forwarded-For. Empty means
	// gin trusts nobody, so the client IP is the direct peer.
	TrustedProxies    []string
	AdminUsername     string
	AdminPasswordHash string
	AdminSessionTTL   int
	AdminCookieSecure bool
	AdminLoginMax     int
	AdminLoginWindow  int
	// MySQL 是驱动级连接配置，由 MYSQL_DSN 解析而来（缺的参数按 mysqlDefaults 补齐）。
	// 连接池、启动重试和查询超时不在这里：它们是 database/sql 和我们自己的事，
	// 驱动不认。
	MySQL *mysql.Config
	// MySQLSource 说明上面那份配置从哪儿来，只用于 `rn-server config` 的输出。
	MySQLSource string
	// MySQLDefaulted 列出 DSN 里没写、由服务端补上的参数，同样只用于输出——
	// 补了什么必须看得见，否则"我明明没配 parseTime"会变成一次线上排查。
	MySQLDefaulted             []string
	MySQLConnectionLimit       int
	MySQLMaxIdleConnections    int
	MySQLConnectionMaxLifetime int
	MySQLConnectionMaxIdleTime int
	MySQLQueryTimeout          int
	MySQLInitTimeout           int
	MySQLInitMaxAttempts       int
	MySQLInitRetryDelay        int
	MySQLAutoMigrate           bool
	StorageMasterKey           string
	DeviceIdentityKey          string
	ArtifactMaxSizeBytes       int64
	ArtifactUploadMode         string
	ArtifactUploadTTL          int
	ArtifactMultipartTTL       int
	ArtifactVerifyTimeout      int
	PushDispatchEnabled        bool
	PushPollInterval           int
	PushConcurrency            int
	// FCMProjectID / FCMServiceAccountJSON 是**弃用的**过渡键。推送凭据已经按租户
	// 存在 app_configs 的 push.fcm 里（见 docs/decisions/0017-per-tenant-push-credentials.md）；
	// 这两个只在库里一行都没有时兜底，且每次启动会打一条 WARN。
	FCMProjectID          string
	FCMServiceAccountJSON string
	APNsTeamID            string
	APNsKeyID             string
	APNsPrivateKey        string
	APNsBundleID          string
	APNsEnvironment       string
	HMSAppID              string
	HMSClientID           string
	HMSClientSecret       string
	// IndexerEnabled 是否运行扫链进程。别直接读它，用 IndexerEnabledFor——
	// 默认值取决于在哪个子命令里问。
	IndexerEnabled bool
	// indexerEnabledSet 记录 env 里到底写没写 INDEXER_ENABLED。
	indexerEnabledSet bool
	// IndexerAllowPlainHTTP 私网部署允许 http:// 扫链端点。
	IndexerAllowPlainHTTP bool
	// IndexerAlertWebhook 告警 webhook（企业微信 / Slack 通用 JSON）；空表示不发。
	IndexerAlertWebhook string
	// PlatformAdminUsernames 能进"扫链管理"等平台级页面的管理员用户名；空表示平台路由一律 403。
	PlatformAdminUsernames []string
}

// mysqlDefaults 是 DSN 里没写时服务端补上的值。
//
// 补齐这件事不是锦上添花：驱动的默认值和我们的**不一样**，而差异全都在启动之后
// 才发作。parseTime 驱动默认 false，那样每一个读 DATETIME 的接口都会 500，而启动
// 是绿的；三个 timeout 驱动默认 0（永不超时），库挂起时 handler 会一直等下去，
// 连接池占满，健康检查跟着死。照着 MySQL 文档随手写一行 DSN 的人拿到的正是这两样。
var mysqlDefaults = struct {
	parseTime    bool
	charset      string
	timeout      time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
}{parseTime: true, charset: "utf8mb4", timeout: 15 * time.Second, readTimeout: 30 * time.Second, writeTimeout: 30 * time.Second}

func Load() (Config, error) {
	l := &loader{}
	cfg := Config{
		Environment:                l.value("APP_ENV", "development"),
		Port:                       l.value("PORT", "3000"),
		BindAddress:                l.value("BIND_ADDRESS", ""),
		HTTPReadTimeout:            l.integer("HTTP_READ_TIMEOUT_SECONDS", 3600),
		HTTPWriteTimeout:           l.integer("HTTP_WRITE_TIMEOUT_SECONDS", 3600),
		AdminAPIKey:                os.Getenv("ADMIN_API_KEY"),
		AdminAPIActor:              l.value("ADMIN_API_ACTOR", "api-key-automation"),
		AdminAPIAllowedIPs:         splitList(os.Getenv("ADMIN_API_ALLOWED_IPS")),
		TrustedProxies:             splitList(os.Getenv("TRUSTED_PROXIES")),
		AdminUsername:              os.Getenv("ADMIN_USERNAME"),
		AdminPasswordHash:          os.Getenv("ADMIN_PASSWORD_HASH"),
		AdminSessionTTL:            l.integer("ADMIN_SESSION_TTL_SECONDS", 28800),
		AdminCookieSecure:          l.boolean("ADMIN_COOKIE_SECURE", true),
		AdminLoginMax:              l.integer("ADMIN_LOGIN_MAX_ATTEMPTS", 5),
		AdminLoginWindow:           l.integer("ADMIN_LOGIN_WINDOW_SECONDS", 900),
		MySQLConnectionLimit:       l.integer("MYSQL_CONNECTION_LIMIT", 10),
		MySQLMaxIdleConnections:    l.integer("MYSQL_MAX_IDLE_CONNECTIONS", 2),
		MySQLConnectionMaxLifetime: l.integer("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", 1800),
		MySQLConnectionMaxIdleTime: l.integer("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", 300),
		MySQLQueryTimeout:          l.integer("MYSQL_QUERY_TIMEOUT_SECONDS", 10),
		MySQLInitTimeout:           l.integer("MYSQL_INIT_TIMEOUT_SECONDS", 30),
		MySQLInitMaxAttempts:       l.integer("MYSQL_INIT_MAX_ATTEMPTS", 3),
		MySQLInitRetryDelay:        l.integer("MYSQL_INIT_RETRY_DELAY_SECONDS", 5),
		MySQLAutoMigrate:           l.boolean("MYSQL_AUTO_MIGRATE", true),
		StorageMasterKey:           strings.TrimSpace(os.Getenv("STORAGE_MASTER_KEY")),
		BuildAgentToken:            strings.TrimSpace(os.Getenv("BUILD_AGENT_TOKEN")),
		DeviceIdentityKey:          strings.TrimSpace(os.Getenv("DEVICE_IDENTITY_HMAC_KEY")),
		ArtifactMaxSizeBytes:       int64(l.integer("ARTIFACT_MAX_SIZE_MB", 512)) * 1024 * 1024,
		ArtifactUploadMode:         l.value("ARTIFACT_UPLOAD_MODE", "direct"),
		ArtifactUploadTTL:          l.integer("ARTIFACT_UPLOAD_TTL_SECONDS", 900),
		ArtifactMultipartTTL:       l.integer("ARTIFACT_MULTIPART_TTL_SECONDS", 7200),
		ArtifactVerifyTimeout:      l.integer("ARTIFACT_VERIFY_TIMEOUT_SECONDS", 300),
		PushDispatchEnabled:        l.boolean("PUSH_DISPATCH_ENABLED", false),
		PushPollInterval:           l.integer("PUSH_POLL_INTERVAL_SECONDS", 10),
		PushConcurrency:            l.integer("PUSH_CONCURRENCY", 8),
		FCMProjectID:               strings.TrimSpace(os.Getenv("FCM_PROJECT_ID")),
		FCMServiceAccountJSON:      strings.TrimSpace(os.Getenv("FCM_SERVICE_ACCOUNT_JSON")),
		APNsTeamID:                 strings.TrimSpace(os.Getenv("APNS_TEAM_ID")),
		APNsKeyID:                  strings.TrimSpace(os.Getenv("APNS_KEY_ID")),
		APNsPrivateKey:             strings.TrimSpace(os.Getenv("APNS_PRIVATE_KEY")),
		APNsBundleID:               strings.TrimSpace(os.Getenv("APNS_BUNDLE_ID")),
		APNsEnvironment:            l.value("APNS_ENVIRONMENT", "production"),
		HMSAppID:                   strings.TrimSpace(os.Getenv("HMS_APP_ID")),
		HMSClientID:                strings.TrimSpace(os.Getenv("HMS_CLIENT_ID")),
		HMSClientSecret:            strings.TrimSpace(os.Getenv("HMS_CLIENT_SECRET")),
		IndexerEnabled:             l.boolean("INDEXER_ENABLED", false),
		indexerEnabledSet:          strings.TrimSpace(os.Getenv("INDEXER_ENABLED")) != "",
		IndexerAllowPlainHTTP:      l.boolean("INDEXER_ALLOW_PLAIN_HTTP", false),
		IndexerAlertWebhook:        strings.TrimSpace(os.Getenv("INDEXER_ALERT_WEBHOOK")),
		PlatformAdminUsernames:     split(strings.TrimSpace(os.Getenv("PLATFORM_ADMIN_USERNAMES"))),
	}
	// CORS_ORIGINS 是额外放行项，不是"允许列表的全部"：租户域名由 tenant_domain
	// 表推导。开发环境默认放开，生产环境默认**空**——生产上继续默认 "*" 等于
	// 把这个改动做成一个洞。
	corsFallback := "*"
	if cfg.Environment == "production" {
		corsFallback = ""
	}
	cfg.CORSOrigins = split(l.value("CORS_ORIGINS", corsFallback))

	cfg.MySQL, cfg.MySQLSource, cfg.MySQLDefaulted = l.mysql()
	if cfg.MySQL != nil && cfg.Environment == "test" && !strings.HasSuffix(cfg.MySQL.DBName, "_test") {
		cfg.MySQL.DBName += "_test"
	}

	if cfg.Environment == "production" {
		if cfg.AdminUsername == "" || cfg.AdminPasswordHash == "" {
			l.fail("ADMIN_USERNAME and ADMIN_PASSWORD_HASH are required in production")
		}
		// 空是允许的（租户域名从表里推导）；显式写 "*" 不是——那放行的是所有人。
		for _, origin := range cfg.CORSOrigins {
			if origin == "*" {
				l.fail(`CORS_ORIGINS must not be "*" in production; leave it empty to allow only tenant domains`)
			}
		}
		if cfg.StorageMasterKey == "" {
			l.fail("STORAGE_MASTER_KEY is required in production")
		}
	}
	l.atLeast("HTTP_READ_TIMEOUT_SECONDS", cfg.HTTPReadTimeout, 1)
	l.atLeast("HTTP_WRITE_TIMEOUT_SECONDS", cfg.HTTPWriteTimeout, 1)
	l.atLeast("MYSQL_CONNECTION_LIMIT", cfg.MySQLConnectionLimit, 1)
	l.atLeast("MYSQL_MAX_IDLE_CONNECTIONS", cfg.MySQLMaxIdleConnections, 0)
	if cfg.MySQLMaxIdleConnections > cfg.MySQLConnectionLimit {
		l.fail(fmt.Sprintf("MYSQL_MAX_IDLE_CONNECTIONS (%d) cannot exceed MYSQL_CONNECTION_LIMIT (%d)",
			cfg.MySQLMaxIdleConnections, cfg.MySQLConnectionLimit))
	}
	l.atLeast("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", cfg.MySQLConnectionMaxLifetime, 1)
	l.atLeast("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", cfg.MySQLConnectionMaxIdleTime, 1)
	l.atLeast("MYSQL_QUERY_TIMEOUT_SECONDS", cfg.MySQLQueryTimeout, 1)
	l.atLeast("MYSQL_INIT_TIMEOUT_SECONDS", cfg.MySQLInitTimeout, 1)
	l.between("MYSQL_INIT_MAX_ATTEMPTS", cfg.MySQLInitMaxAttempts, 1, 10)
	l.atLeast("MYSQL_INIT_RETRY_DELAY_SECONDS", cfg.MySQLInitRetryDelay, 0)
	l.atLeast("ADMIN_SESSION_TTL_SECONDS", cfg.AdminSessionTTL, 300)
	l.atLeast("ADMIN_LOGIN_MAX_ATTEMPTS", cfg.AdminLoginMax, 3)
	l.atLeast("ADMIN_LOGIN_WINDOW_SECONDS", cfg.AdminLoginWindow, 60)
	if cfg.StorageMasterKey != "" && !validMasterKey(cfg.StorageMasterKey) {
		l.fail("STORAGE_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	if cfg.DeviceIdentityKey == "" {
		cfg.DeviceIdentityKey = cfg.StorageMasterKey
	}
	if cfg.ArtifactUploadMode != "direct" && cfg.ArtifactUploadMode != "proxy" {
		l.fail("ARTIFACT_UPLOAD_MODE must be direct or proxy")
	}
	l.between("PUSH_POLL_INTERVAL_SECONDS", cfg.PushPollInterval, 1, 300)
	l.between("PUSH_CONCURRENCY", cfg.PushConcurrency, 1, 64)
	if cfg.APNsEnvironment != "production" && cfg.APNsEnvironment != "sandbox" {
		l.fail("APNS_ENVIRONMENT must be production or sandbox")
	}
	l.between("ARTIFACT_MAX_SIZE_MB", int(cfg.ArtifactMaxSizeBytes/(1024*1024)), 1, 2048)
	l.between("ARTIFACT_UPLOAD_TTL_SECONDS", cfg.ArtifactUploadTTL, 60, 3600)
	l.between("ARTIFACT_MULTIPART_TTL_SECONDS", cfg.ArtifactMultipartTTL, 300, 86400)
	l.between("ARTIFACT_VERIFY_TIMEOUT_SECONDS", cfg.ArtifactVerifyTimeout, 30, 1800)
	if err := l.err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// mysql 组装驱动级连接配置。
//
// MYSQL_DSN 优先；没有它就用旧的 11 个键拼出一条**等价的 DSN**，再走同一条解析
// 路径。两条路合流而不是各拼一份 mysql.Config，是因为只有驱动自己知道每个参数
// 的语义（charset 就不落在 Params 里，而是驱动的私有字段）——自己拼第二份迟早
// 和它对不上。旧键留着是因为代码和 env 是分别部署的：CI 推上来的二进制只认 DSN
// 而 env 还没改的那一刻，迁移和服务都会连不上库，那次部署整个是红的。
func (l *loader) mysql() (*mysql.Config, string, []string) {
	raw := strings.TrimSpace(os.Getenv("MYSQL_DSN"))
	source := "MYSQL_DSN"
	if raw == "" {
		raw, source = l.legacyDSN(), "legacy MYSQL_* keys"
	}
	return l.parseDSN(raw, source)
}

func (l *loader) parseDSN(raw, source string) (*mysql.Config, string, []string) {
	parsed, err := mysql.ParseDSN(raw)
	if err != nil {
		l.fail(fmt.Sprintf("%s is not a valid DSN (%v); the shape is user:password@tcp(host:port)/database?params", source, err))
		return nil, source, nil
	}
	written := dsnParams(raw)
	// 显式 parseTime=false 不接受：整套代码把 DATETIME 扫进 time.Time，关掉它
	// 不会报错，只会让每一个读时间的接口 500。
	if _, explicit := written["parseTime"]; explicit && !parsed.ParseTime {
		l.fail(source + " must not set parseTime=false: every query that reads a DATETIME column scans into time.Time")
	}
	// 补默认值的办法是把缺的参数接回 DSN 再解析一遍，而不是去改解析结果：
	// charset 落在驱动的私有字段里，从外面写 Params["charset"] 会变成另一个参数。
	missing, defaulted := missingMySQLParams(written)
	if len(missing) > 0 {
		raw = appendDSNParams(raw, missing)
		if parsed, err = mysql.ParseDSN(raw); err != nil {
			l.fail(fmt.Sprintf("%s cannot be completed with our defaults (%v)", source, err))
			return nil, source, nil
		}
	}
	l.validateMySQL(parsed, raw, written, source)
	return parsed, source, defaulted
}

// missingMySQLParams 列出 DSN 里没写、需要补成我们默认值的参数。
func missingMySQLParams(written url.Values) (url.Values, []string) {
	missing, names := url.Values{}, []string{}
	add := func(name, value string) {
		if _, present := written[name]; present {
			return
		}
		missing.Set(name, value)
		names = append(names, name)
	}
	add("parseTime", strconv.FormatBool(mysqlDefaults.parseTime))
	add("timeout", mysqlDefaults.timeout.String())
	add("readTimeout", mysqlDefaults.readTimeout.String())
	add("writeTimeout", mysqlDefaults.writeTimeout.String())
	// charset 只在两个都没写时补：显式给了 collation 的人知道自己在做什么，
	// 再塞一个 charset 进去会多发一条 SET NAMES 并可能和它打架。
	if _, hasCollation := written["collation"]; !hasCollation {
		add("charset", mysqlDefaults.charset)
	}
	return missing, names
}

// appendDSNParams 把参数接到 DSN 后面。参数段的位置和驱动的判断一致：最后一个
// '/' 之后的第一个 '?'。
func appendDSNParams(dsn string, params url.Values) string {
	separator := "?"
	if slash := strings.LastIndex(dsn, "/"); slash >= 0 && strings.Contains(dsn[slash:], "?") {
		separator = "&"
	}
	return dsn + separator + params.Encode()
}

// legacyDSN 用弃用的 11 个 MYSQL_* 键拼一条等价的 DSN。它同时是启动时那条弃用
// 警告要打印的内容（口令打码后），运维照着它把一行加进 env 就完成了迁移。
func (l *loader) legacyDSN() string {
	base := mysql.NewConfig()
	base.User = l.value("MYSQL_USER", "root")
	base.Passwd = os.Getenv("MYSQL_PASSWORD")
	base.Net = "tcp"
	port := l.integer("MYSQL_PORT", 3306)
	l.between("MYSQL_PORT", port, 1, 65535)
	if port < 1 || port > 65535 {
		port = 3306
	}
	base.Addr = fmt.Sprintf("%s:%d", l.value("MYSQL_HOST", "127.0.0.1"), port)
	base.DBName = l.value("MYSQL_DATABASE", "rn_foundation")
	params := url.Values{}
	params.Set("parseTime", strconv.FormatBool(l.boolean("MYSQL_PARSE_TIME", mysqlDefaults.parseTime)))
	params.Set("charset", l.value("MYSQL_CHARSET", mysqlDefaults.charset))
	// "Z" 是 ISO-8601 的 UTC 记号，不是时区名，LoadLocation 不认它——而旧示例里
	// 写的就是 Z。这里翻译一下；DSN 那条路上它会被驱动直接拒掉，那是对的。
	zone := l.value("MYSQL_TIMEZONE", "UTC")
	if zone == "Z" {
		zone = "UTC"
	}
	params.Set("loc", zone)
	params.Set("timeout", l.seconds("MYSQL_CONNECT_TIMEOUT_SECONDS", mysqlDefaults.timeout))
	params.Set("readTimeout", l.seconds("MYSQL_READ_TIMEOUT_SECONDS", mysqlDefaults.readTimeout))
	params.Set("writeTimeout", l.seconds("MYSQL_WRITE_TIMEOUT_SECONDS", mysqlDefaults.writeTimeout))
	return appendDSNParams(base.FormatDSN(), params)
}

func (l *loader) seconds(key string, fallback time.Duration) string {
	got := l.integer(key, int(fallback/time.Second))
	l.atLeast(key, got, 1)
	if got < 1 {
		got = int(fallback / time.Second)
	}
	return (time.Duration(got) * time.Second).String()
}

// validateMySQL 挡住那些驱动不会报错、但结果不是我们想要的形状。
func (l *loader) validateMySQL(cfg *mysql.Config, raw string, written url.Values, source string) {
	// 漏写 tcp(host:port) 时驱动**不报错**：它默默把 Addr 补成 127.0.0.1:3306。
	// 在生产上那不是一个可接受的默认值，所以只能从原串上看地址到底写没写。
	if !dsnHasAddress(raw) {
		l.fail(source + ": the server address is missing; write it as tcp(host:port)")
	}
	if cfg.Net != "" && cfg.Net != "tcp" {
		l.fail(fmt.Sprintf("%s: only tcp is supported, got %q", source, cfg.Net))
	}
	if strings.TrimSpace(cfg.DBName) == "" {
		l.fail(source + ": the database name is missing")
	}
	if strings.ContainsAny(cfg.DBName+written.Get("charset"), "`'\"; ") {
		l.fail(source + ": the database name and charset must not contain quotes, semicolons or spaces")
	}
}

// dsnHasAddress 判断 DSN 里到底写没写服务器地址。拆法和驱动一致：最后一个 '/'
// 之前是 [user[:pass]@][net[(addr)]]，其中最后一个 '@' 之后那段就是网络与地址。
func dsnHasAddress(dsn string) bool {
	slash := strings.LastIndex(dsn, "/")
	if slash < 0 {
		return false
	}
	body := dsn[:slash]
	if at := strings.LastIndex(body, "@"); at >= 0 {
		body = body[at+1:]
	}
	return strings.Contains(body, "(")
}

// dsnParams 取出 DSN 里**显式写了**的参数，用来区分"没写"和"写成了默认值"。
// 找参数段的方式和驱动一致：最后一个 '/' 之后的第一个 '?'。
func dsnParams(dsn string) url.Values {
	slash := strings.LastIndex(dsn, "/")
	if slash < 0 {
		return url.Values{}
	}
	question := strings.Index(dsn[slash:], "?")
	if question < 0 {
		return url.Values{}
	}
	values, err := url.ParseQuery(dsn[slash+question+1:])
	if err != nil {
		return url.Values{}
	}
	return values
}

// RedactedMySQLDSN 是可以打印的 DSN：口令换成 ***。
//
// 打码走结构体而不是在字符串上做正则替换——口令里可以合法地含 '@'（驱动取的是
// 最后一个 '@'），正则会打错位置，把口令的一部分留在输出里。
func (c Config) RedactedMySQLDSN() string {
	if c.MySQL == nil {
		return ""
	}
	masked := c.MySQL.Clone()
	if masked.Passwd != "" {
		masked.Passwd = "***"
	}
	return masked.FormatDSN()
}

// IndexerEnabledFor 回答"这个进程要不要扫链"。
//
// `rn-server indexer` 这个子命令默认就扫——跑它就是要扫。别的入口默认不扫。
// 显式写了 INDEXER_ENABLED 时一律听 env 的。
//
// 从前这里只有一个默认 false，于是裸机部署要在 env 里写一行 INDEXER_ENABLED=true
// 才能让 rn-foundation-indexer 这个 unit 真的干活——启一个 unit 再让它空转，是给
// Docker Compose 防容器反复重启设计的，裸机上那一行只是一个能忘记写的地方。
func (c Config) IndexerEnabledFor(command string) bool {
	if c.indexerEnabledSet {
		return c.IndexerEnabled
	}
	return command == "indexer"
}

func validMasterKey(encoded string) bool {
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encoded)
	}
	return err == nil && len(key) == 32
}

// loader 收集所有配置问题，一次报完。
//
// 从前这里是二十几个键共用一句 "invalid MySQL numeric configuration"，而 integer()
// 解析失败会静默返回 -1 再被那句拦住——任何笔误得到的都是同一句话，看的人只能
// ssh 上去一个一个键地试。
type loader struct{ errs []string }

func (l *loader) fail(message string) { l.errs = append(l.errs, message) }

func (l *loader) err() error {
	if len(l.errs) == 0 {
		return nil
	}
	if len(l.errs) == 1 {
		return errors.New(l.errs[0])
	}
	return fmt.Errorf("%d configuration problems:\n  - %s", len(l.errs), strings.Join(l.errs, "\n  - "))
}

func (l *loader) atLeast(key string, got, min int) {
	if got < min {
		l.fail(fmt.Sprintf("%s must be at least %d, got %d", key, min, got))
	}
}

func (l *loader) between(key string, got, min, max int) {
	if got < min || got > max {
		l.fail(fmt.Sprintf("%s must be between %d and %d, got %d", key, min, max, got))
	}
}

func (l *loader) value(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (l *loader) integer(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		l.fail(fmt.Sprintf("%s must be a whole number, got %q", key, raw))
		return fallback
	}
	return v
}

func (l *loader) boolean(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		l.fail(fmt.Sprintf("%s must be true or false, got %q", key, raw))
		return fallback
	}
	return v
}

func split(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// splitList 解析逗号分隔的列表，去掉空白与空项。
func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
