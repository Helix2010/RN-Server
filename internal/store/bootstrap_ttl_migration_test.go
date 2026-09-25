package store

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/go-sql-driver/mysql"
)

// openStoreTestDB 是这个包所有库测的入口：连测试库，第一次连的时候把迁移跑一遍，之后复用同一个连接池
// （与 internal/api 的 openTestDB 同一个做法）。
//
// 以前 openMigrationTestDB 只连不迁移，有的用例用的表（app_configs 等）是 internal/api 的用例迁移出来的：
// 新库上先跑这个包就报表不存在，CI 里两步的先后顺序因此成了一条没写下来的约束（2026-09-25 本地复现）。
// Migrate 有 GET_LOCK、已应用的版本跳过，与 internal/api 在同一个库上各跑一遍是安全的。
var storeTestDB struct {
	once sync.Once
	db   *sql.DB
	err  error
}

func openStoreTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("RN_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("RN_TEST_MYSQL_DSN not set; database-backed tests skipped")
	}
	storeTestDB.once.Do(func() {
		driverCfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			storeTestDB.err = err
			return
		}
		st, err := Open(config.Config{
			MySQL:                driverCfg,
			MySQLConnectionLimit: 5, MySQLMaxIdleConnections: 2, MySQLConnectionMaxLifetime: 600,
			MySQLConnectionMaxIdleTime: 60, MySQLQueryTimeout: 10,
			MySQLInitTimeout: 60, MySQLInitMaxAttempts: 3, MySQLInitRetryDelay: 1, MySQLAutoMigrate: true,
		})
		if err != nil {
			storeTestDB.err = err
			return
		}
		storeTestDB.db = st.DB
	})
	if storeTestDB.err != nil {
		t.Fatalf("open and migrate the test database: %v", storeTestDB.err)
	}
	return storeTestDB.db
}

func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openStoreTestDB(t)
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
