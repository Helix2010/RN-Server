package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("RN_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("RN_TEST_MYSQL_DSN not set; database-backed tests skipped")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	return db
}

// 迁移把"现在生效的刷新间隔"搬进 ttlSeconds。取错值的后果只有线上看得见：存量
// ttlSeconds 大多是种子里的 300，取成它就等于把全量设备的配置重拉从 6 小时改成
// 5 分钟。这里对迁移用的那段表达式逐种情况求值——租户覆盖、继承平台默认、越界。
func TestDBBootstrapTTLTakesTheIntervalThatWasInEffect(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 平台默认那一行由迁移种下（21600），这里只造租户侧的行
	base := int64(920000000) + now.Unix()%100000
	cases := []struct {
		name      string
		languages string
		want      int64
	}{
		{"租户覆盖了刷新间隔：用它", `{"refreshIntervalSeconds":1800}`, 1800},
		{"租户没有 languages 行：用平台默认", "", 21600},
		{"租户行里没写这个字段：用平台默认", `{"fallbackLanguage":"en-US"}`, 21600},
		{"字段是 0（历史脏数据）：当没写", `{"refreshIntervalSeconds":0}`, 21600},
		{"覆盖值低于下限：夹到 300", `{"refreshIntervalSeconds":30}`, 300},
		{"覆盖值高于上限：夹到 86400", `{"refreshIntervalSeconds":999999}`, 86400},
	}
	for index, item := range cases {
		tenant := base + int64(index)
		t.Run(item.name, func(t *testing.T) {
			if _, err := db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
				VALUES(?,'mobile-bootstrap','{"ttlSeconds":300}',1,'test-ttl',?)`, tenant, now); err != nil {
				t.Fatalf("seed bootstrap config: %v", err)
			}
			if item.languages != "" {
				if _, err := db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
					VALUES(?,'languages',?,1,'test-ttl',?)`, tenant, item.languages, now); err != nil {
					t.Fatalf("seed languages config: %v", err)
				}
			}
			t.Cleanup(func() {
				db.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=?`, tenant)
			})

			var got int64
			if err := db.QueryRowContext(ctx, `SELECT `+bootstrapTTLInEffect+` FROM app_configs bootstrap_config`+
				bootstrapTTLLanguagesJoin+
				`WHERE bootstrap_config.config_key='mobile-bootstrap' AND bootstrap_config.tenant_id=?`, tenant).Scan(&got); err != nil {
				t.Fatalf("evaluate migration expression: %v", err)
			}
			if got != item.want {
				t.Fatalf("ttlSeconds = %d, want %d", got, item.want)
			}
		})
	}
}
