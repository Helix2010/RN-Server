package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/go-sql-driver/mysql"
)

func openBackupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("RN_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("RN_TEST_MYSQL_DSN not set; database-backed tests skipped")
	}
	driverCfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("RN_TEST_MYSQL_DSN is not a valid DSN: %v", err)
	}
	st, err := Open(config.Config{
		MySQL:                driverCfg,
		MySQLConnectionLimit: 5, MySQLMaxIdleConnections: 2, MySQLConnectionMaxLifetime: 600,
		MySQLConnectionMaxIdleTime: 60, MySQLQueryTimeout: 10,
		MySQLInitTimeout: 60, MySQLInitMaxAttempts: 3, MySQLInitRetryDelay: 1, MySQLAutoMigrate: true,
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _, _ = st.DB.ExecContext(context.Background(), `DELETE FROM platform_backups`) })
	return st.DB
}

func insertBackup(t *testing.T, db *sql.DB, id, status string) error {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO platform_backups(id,status,trigger_by,requested_by,reason,created_at,updated_at)
		 VALUES(?,?,'manual','tester','test',?,?)`, id, status, now, now)
	return err
}

// 迁移必须幂等。不幂等的后果不是「备份功能没上线」：apply 失败就不记账
// （schema_migrations 那一行写不进去），而 MYSQL_AUTO_MIGRATE 默认开着，
// 下次启动重跑撞 ERROR 1050，然后**永久启动失败循环，倒下的是整个 wallet 后端**
func TestPlatformBackupsMigrationIsIdempotent(t *testing.T) {
	db := openBackupTestDB(t)
	for i := 0; i < 3; i++ {
		if err := platformBackupsMigration(context.Background(), db); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
}

// live_slot 的语义：任意多条已结束 + 至多一条在途。
// MySQL 唯一索引不比较 NULL，所以结束之后可以立刻建下一条
func TestOnlyOneBackupCanBeInFlight(t *testing.T) {
	db := openBackupTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	// 已结束的想放多少放多少
	if err := insertBackup(t, db, "pbk_done1", "succeeded"); err != nil {
		t.Fatalf("a finished row must not occupy the slot: %v", err)
	}
	// failed 同样不占槽——否则一次失败会把后续备份全堵死
	if err := insertBackup(t, db, "pbk_done2", "failed"); err != nil {
		t.Fatalf("a failed row must not occupy the slot: %v", err)
	}
	if err := insertBackup(t, db, "pbk_live", "pending"); err != nil {
		t.Fatalf("the first in-flight row must be accepted: %v", err)
	}

	// 第二条在途必须被挡下，而且必须撞在 live 那个索引上
	err := insertBackup(t, db, "pbk_live2", "pending")
	if err == nil {
		t.Fatal("a second in-flight backup was accepted: the in-flight gate is not working")
	}
	assertDuplicateOn(t, err, "ux_platform_backups_live")

	// running 也占槽
	if _, err := db.Exec(`UPDATE platform_backups SET status='running' WHERE id='pbk_live'`); err != nil {
		t.Fatal(err)
	}
	err = insertBackup(t, db, "pbk_live3", "pending")
	if err == nil {
		t.Fatal("a pending row was accepted while another was running")
	}
	assertDuplicateOn(t, err, "ux_platform_backups_live")

	// 结束之后立刻能建下一条
	if _, err := db.Exec(`UPDATE platform_backups SET status='succeeded' WHERE id='pbk_live'`); err != nil {
		t.Fatal(err)
	}
	if err := insertBackup(t, db, "pbk_live4", "pending"); err != nil {
		t.Fatalf("the slot must free up as soon as the previous run finishes: %v", err)
	}
}

// 这一条钉的是**错误映射**，不是并发本身。
//
// seq 如果还用 COALESCE(MAX(seq),0)+1，两条并发 INSERT 会同时违反 seq 和 live 两个
// 唯一索引，而 MySQL 报的是**先建的那一个**——于是按契约只匹配 live 索引翻 409 的
// 代码会把它掉进 500，控制台上看到的是「服务器错误」而不是「已经有一条在跑」。
// seq 改成 AUTO_INCREMENT 之后，唯一还能冲突的就只剩 live_slot。
func TestInFlightConflictReportsTheLiveIndexNotTheSeqIndex(t *testing.T) {
	db := openBackupTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	if err := insertBackup(t, db, "pbk_a", "pending"); err != nil {
		t.Fatal(err)
	}
	err := insertBackup(t, db, "pbk_b", "pending")
	if err == nil {
		t.Fatal("expected a duplicate-key error")
	}
	if strings.Contains(err.Error(), "ux_platform_backups_seq") {
		t.Fatalf("the conflict surfaced on the seq index, so a 409 mapping keyed on the live index would "+
			"turn into a 500: %v", err)
	}
	assertDuplicateOn(t, err, "ux_platform_backups_live")
}

// seq 由数据库发号，调用方不写
func TestSeqIsAssignedByTheDatabase(t *testing.T) {
	db := openBackupTestDB(t)
	if _, err := db.Exec(`DELETE FROM platform_backups`); err != nil {
		t.Fatal(err)
	}
	var first, second uint64
	if err := insertBackup(t, db, "pbk_s1", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT seq FROM platform_backups WHERE id='pbk_s1'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := insertBackup(t, db, "pbk_s2", "succeeded"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT seq FROM platform_backups WHERE id='pbk_s2'`).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if first == 0 || second <= first {
		t.Fatalf("seq must be assigned and increasing, got %d then %d", first, second)
	}
}

func assertDuplicateOn(t *testing.T, err error, index string) {
	t.Helper()
	var mysqlErr *mysql.MySQLError
	if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1062 {
		t.Fatalf("expected a 1062 duplicate-key error, got: %v", err)
	}
	if !strings.Contains(mysqlErr.Message, index) {
		t.Fatalf("expected the conflict on %s, got: %v", index, mysqlErr.Message)
	}
}
