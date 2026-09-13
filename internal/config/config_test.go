package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadParsesTheDSNAndKeepsPoolKeysSeparate(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("MYSQL_DSN", "app:secret@tcp(db.internal:13306)/foundation?parseTime=true&loc=UTC&charset=utf8mb4&timeout=23s&readTimeout=41s&writeTimeout=43s")
	t.Setenv("MYSQL_MAX_IDLE_CONNECTIONS", "2")
	t.Setenv("MYSQL_CONNECTION_MAX_LIFETIME_SECONDS", "601")
	t.Setenv("MYSQL_CONNECTION_MAX_IDLE_TIME_SECONDS", "61")
	t.Setenv("MYSQL_QUERY_TIMEOUT_SECONDS", "11")
	t.Setenv("MYSQL_INIT_TIMEOUT_SECONDS", "47")
	t.Setenv("MYSQL_INIT_MAX_ATTEMPTS", "4")
	t.Setenv("MYSQL_INIT_RETRY_DELAY_SECONDS", "7")
	t.Setenv("MYSQL_AUTO_MIGRATE", "false")
	t.Setenv("HTTP_READ_TIMEOUT_SECONDS", "901")
	t.Setenv("HTTP_WRITE_TIMEOUT_SECONDS", "902")
	t.Setenv("ARTIFACT_MULTIPART_TTL_SECONDS", "1800")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQL.Addr != "db.internal:13306" || cfg.MySQL.User != "app" || cfg.MySQL.Passwd != "secret" ||
		!cfg.MySQL.ParseTime || cfg.MySQL.Loc.String() != "UTC" ||
		cfg.MySQL.Timeout != 23*time.Second || cfg.MySQL.ReadTimeout != 41*time.Second || cfg.MySQL.WriteTimeout != 43*time.Second ||
		!cfg.MySQL.AllowNativePasswords {
		t.Fatalf("unexpected driver config: %#v", cfg.MySQL)
	}
	// charset 落在驱动的私有字段里，外面看不见；能看见的是它交回去的那条 DSN
	if !strings.Contains(cfg.MySQL.FormatDSN(), "charset=utf8mb4") {
		t.Fatalf("charset did not survive parsing: %s", cfg.RedactedMySQLDSN())
	}
	// APP_ENV=test 仍然给库名加后缀，否则一次 go test 会把开发库洗掉
	if cfg.MySQL.DBName != "foundation_test" {
		t.Fatalf("test runs must target the _test database, got %q", cfg.MySQL.DBName)
	}
	if len(cfg.MySQLDefaulted) != 0 {
		t.Fatalf("nothing should be defaulted when the DSN spells it all out: %v", cfg.MySQLDefaulted)
	}
	// 连接池和启动重试不属于 DSN：它们是 database/sql 和我们自己的事，驱动不认
	if cfg.MySQLMaxIdleConnections != 2 || cfg.MySQLConnectionMaxLifetime != 601 || cfg.MySQLConnectionMaxIdleTime != 61 ||
		cfg.MySQLQueryTimeout != 11 || cfg.MySQLInitTimeout != 47 || cfg.MySQLInitMaxAttempts != 4 ||
		cfg.MySQLInitRetryDelay != 7 || cfg.MySQLAutoMigrate {
		t.Fatalf("pool and startup keys must survive the DSN switch: %#v", cfg)
	}
	if cfg.HTTPReadTimeout != 901 || cfg.HTTPWriteTimeout != 902 || cfg.ArtifactMultipartTTL != 1800 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

// 这一条挡的是本次改动最容易出的事故：照着 MySQL 文档随手写一行最小 DSN。
//
// 驱动的默认值和我们的不一样——parseTime 默认 false，三个 timeout 默认 0（永不
// 超时）。两样都不会让启动失败：服务起来是绿的，然后每一个读 DATETIME 的接口
// 500，库一挂起 handler 就永远等下去。所以服务端必须补，而且要说它补了什么。
func TestMinimalDSNGetsOurDefaultsNotTheDriversDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_DSN", "app:secret@tcp(db.internal:3306)/foundation")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MySQL.ParseTime {
		t.Fatal("parseTime must be defaulted to true: every query that reads a DATETIME scans into time.Time")
	}
	if cfg.MySQL.Timeout != 15*time.Second || cfg.MySQL.ReadTimeout != 30*time.Second || cfg.MySQL.WriteTimeout != 30*time.Second {
		t.Fatalf("the three timeouts must be defaulted, got %v/%v/%v", cfg.MySQL.Timeout, cfg.MySQL.ReadTimeout, cfg.MySQL.WriteTimeout)
	}
	if !strings.Contains(cfg.MySQL.FormatDSN(), "charset=utf8mb4") {
		t.Fatalf("charset must be defaulted to utf8mb4: %s", cfg.RedactedMySQLDSN())
	}
	// 补了什么要能看见，否则"我明明没配 parseTime"会变成一次线上排查
	joined := strings.Join(cfg.MySQLDefaulted, ",")
	for _, want := range []string{"parseTime", "timeout", "readTimeout", "writeTimeout", "charset"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("%s was defaulted but not reported: %v", want, cfg.MySQLDefaulted)
		}
	}
}

func TestDSNProblemsAreRejectedWithTheKeyNamed(t *testing.T) {
	for name, tc := range map[string]struct{ dsn, want string }{
		// 显式关掉 parseTime 不会报错，只会让每个读时间的接口 500
		"parseTime=false": {"app:x@tcp(h:3306)/db?parseTime=false", "parseTime=false"},
		// loc=Z 是 ISO-8601 的记号，不是时区名；LoadLocation 不认
		"loc=Z": {"app:x@tcp(h:3306)/db?loc=Z", "MYSQL_DSN"},
		// 漏写 tcp(...) 时驱动**不报错**，它默默连 127.0.0.1:3306
		"漏写地址":                 {"app:x@/db", "address is missing"},
		"漏写库名":                 {"app:x@tcp(h:3306)/", "database name is missing"},
		"不是 unix socket 之外的网络": {"app:x@unix(/tmp/mysql.sock)/db", "only tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("APP_ENV", "development")
			t.Setenv("MYSQL_DSN", tc.dsn)
			_, err := Load()
			if err == nil {
				t.Fatalf("%q must be rejected", tc.dsn)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error must point at the problem (%q), got: %v", tc.want, err)
			}
		})
	}
}

// 口令里的 '@' 合法：驱动取的是最后一个 '@'。这一条同时钉住打码走结构体而不是
// 正则——正则会在第一个 '@' 上断开，把口令的后半截打印出来。
func TestPasswordWithAtSignSurvivesParsingAndRedaction(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_DSN", "app:p@ss/w0rd:x@tcp(db.internal:3306)/foundation")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQL.Passwd != "p@ss/w0rd:x" {
		t.Fatalf("the password must survive intact, got %q", cfg.MySQL.Passwd)
	}
	if cfg.MySQL.Addr != "db.internal:3306" || cfg.MySQL.DBName != "foundation" {
		t.Fatalf("unexpected driver config: %#v", cfg.MySQL)
	}
	redacted := cfg.RedactedMySQLDSN()
	if strings.Contains(redacted, "p@ss") || strings.Contains(redacted, "w0rd") {
		t.Fatalf("the redacted DSN still carries the password: %q", redacted)
	}
	if !strings.Contains(redacted, "db.internal:3306") || !strings.Contains(redacted, "foundation") {
		t.Fatalf("the redacted DSN must still be useful: %q", redacted)
	}
}

// 旧的十一个键已经不再被读取。**静默忽略它们是不行的**：那样会落到开发默认连接
// 上（本机 3306 的 rn_foundation），报错只会说"连不上"，而真正的原因是这台机器
// 的配置没有迁移过。
func TestLegacyMySQLKeysAreRefusedWithDirections(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_HOST", "db.internal")
	t.Setenv("MYSQL_PORT", "13306")
	t.Setenv("MYSQL_USER", "app")
	t.Setenv("MYSQL_PASSWORD", "secret")
	t.Setenv("MYSQL_DATABASE", "foundation")
	_, err := Load()
	if err == nil {
		t.Fatal("只剩旧键时必须拒绝启动，而不是连到开发默认的那个库上")
	}
	// 报错要点名是哪几个键，并给出该写成什么样
	for _, want := range []string{"MYSQL_DSN", "MYSQL_HOST", "MYSQL_DATABASE", "tcp(host:port)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("报错要包含 %q，得到：%v", want, err)
		}
	}

	// 写了 DSN 之后旧键就只是无人读取的噪声，不再拦着启动
	t.Setenv("MYSQL_DSN", "app:secret@tcp(db.internal:13306)/foundation")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("有 MYSQL_DSN 时旧键不该再拦路：%v", err)
	}
	if cfg.MySQL.Addr != "db.internal:13306" || cfg.MySQLSource != "MYSQL_DSN" {
		t.Fatalf("unexpected driver config: %#v", cfg.MySQL)
	}
}

// 生产上不给默认连接：默默连本机 3306 不是一个可接受的猜测。
func TestProductionRefusesToGuessTheDatabase(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("ADMIN_USERNAME", "admin")
	t.Setenv("ADMIN_PASSWORD_HASH", "$2a$10$abcdefghijklmnopqrstuv")
	t.Setenv("STORAGE_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MYSQL_DSN is required in production") {
		t.Fatalf("生产没有 MYSQL_DSN 必须拒绝启动：%v", err)
	}
}

// 本地不写 MYSQL_DSN 仍然能起来：`go test` 和裸跑 rn-server 不该先要一行配置。
func TestDevelopmentFallsBackToALocalDatabase(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MySQL.Addr != "127.0.0.1:3306" || cfg.MySQLSource == "MYSQL_DSN" {
		t.Fatalf("unexpected driver config: %#v (source %q)", cfg.MySQL, cfg.MySQLSource)
	}
	// 默认连接同样要补上那五项，否则本地会撞上和生产不同的驱动默认值
	if !cfg.MySQL.ParseTime || cfg.MySQL.Timeout == 0 {
		t.Fatalf("开发默认连接也要补默认参数：%#v", cfg.MySQL)
	}
}

func TestLoadRejectsIdlePoolLargerThanOpenPool(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_CONNECTION_LIMIT", "3")
	t.Setenv("MYSQL_MAX_IDLE_CONNECTIONS", "4")
	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid MySQL pool configuration")
	}
	if !strings.Contains(err.Error(), "MYSQL_MAX_IDLE_CONNECTIONS") || !strings.Contains(err.Error(), "MYSQL_CONNECTION_LIMIT") {
		t.Fatalf("the error must name both keys, got: %v", err)
	}
}

// 从前二十几个键共用一句 "invalid MySQL numeric configuration"，而解析失败会
// 静默变成 -1 再被那句拦住——任何笔误得到的都是同一句话。
func TestBadNumbersAndBooleansNameTheKeyAndTheValue(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("MYSQL_QUERY_TIMEOUT_SECONDS", "十秒")
	t.Setenv("ADMIN_COOKIE_SECURE", "yes-please")
	_, err := Load()
	if err == nil {
		t.Fatal("expected a configuration error")
	}
	for _, want := range []string{"MYSQL_QUERY_TIMEOUT_SECONDS", "十秒", "ADMIN_COOKIE_SECURE", "yes-please"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name %q, got: %v", want, err)
		}
	}
}

// CORS_ORIGINS 从"生产必填"改成可选：租户域名已经由 tenant_domain 表推导
// （见 originAllowed），env 只剩额外放行。但显式写 "*" 仍然不行——那放行所有人。
func TestProductionAllowsEmptyOriginsButNeverWildcard(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("ADMIN_USERNAME", "admin")
	t.Setenv("ADMIN_PASSWORD_HASH", "$2a$10$abcdefghijklmnopqrstuv")
	t.Setenv("STORAGE_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	t.Setenv("MYSQL_DSN", "app:x@tcp(db:3306)/foundation")

	t.Setenv("CORS_ORIGINS", "*")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CORS_ORIGINS") {
		t.Fatalf(`production must reject an explicit "*", got: %v`, err)
	}

	t.Setenv("CORS_ORIGINS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("an empty CORS_ORIGINS is allowed now that tenant domains are derived: %v", err)
	}
	if len(cfg.CORSOrigins) != 0 {
		t.Fatalf("production must not fall back to a wildcard, got %v", cfg.CORSOrigins)
	}
}

func TestProductionRequiresLoginAndMasterKey(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("MYSQL_DSN", "app:x@tcp(db:3306)/foundation")
	err := func() error { _, err := Load(); return err }()
	if err == nil {
		t.Fatal("expected production validation error")
	}
	for _, want := range []string{"ADMIN_USERNAME", "STORAGE_MASTER_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error must name %q, got: %v", want, err)
		}
	}
}

// 管理会话 cookie 默认只走 TLS，x-admin-key 通道的审计身份默认由配置绑定：
// 两个默认值都是安全评审 N17 的门禁项，改回不安全的默认必须先改测试。
func TestLoadAdminSecurityDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AdminCookieSecure {
		t.Fatal("ADMIN_COOKIE_SECURE must default to true")
	}
	if cfg.AdminAPIActor != "api-key-automation" {
		t.Fatalf("unexpected default api-key actor: %q", cfg.AdminAPIActor)
	}
	t.Setenv("ADMIN_COOKIE_SECURE", "false")
	t.Setenv("ADMIN_API_ACTOR", "release-bot")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminCookieSecure || cfg.AdminAPIActor != "release-bot" {
		t.Fatalf("environment must still win: %#v", cfg)
	}
}

// `rn-server indexer` 跑起来就该扫链。从前默认 false，于是裸机部署要在 env 里补
// 一行才能让那个 unit 真干活——而"启一个 unit 再让它空转"是给容器防重启设计的。
func TestIndexerSubcommandScansByDefaultButEnvStillWins(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IndexerEnabledFor("indexer") {
		t.Fatal("`rn-server indexer` 默认就该扫链")
	}
	if cfg.IndexerEnabledFor("serve") {
		t.Fatal("别的入口默认不扫")
	}

	t.Setenv("INDEXER_ENABLED", "false")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IndexerEnabledFor("indexer") {
		t.Fatal("显式写了 false 就要听 env 的——容器部署还靠它")
	}
}
