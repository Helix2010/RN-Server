package store

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/referral"
)

// 邀请关系的三个迁移必须能重复执行。
//
// 把加列与唯一键写在一条 ALTER 里会先给已有行填空串再撞唯一键（实测 ERROR 1062），
// 而且失败后不幂等：ALTER 已自动提交，重启会报 Duplicate column name，服务永久
// 起不来、必须人工改库。这个测试就是守着那件事不再发生。
func TestDBReferralMigrationsAreIdempotent(t *testing.T) {
	db := openReferralTestDB(t)
	ctx := context.Background()

	// 造几行没有邀请码的账号，模拟迁移前的存量数据
	tenant := fmt.Sprintf("%d", 900_000_000_000+time.Now().UnixNano()%1_000_000_000)
	for i := 0; i < 3; i++ {
		address := fmt.Sprintf("0x%040x", time.Now().UnixNano()+int64(i))
		now := time.Now().UTC()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,created_at,updated_at)
			 VALUES(?,?,?,?,?,1,'active',?,?)`,
			tenant, address, address, now, now, now, now); err != nil {
			t.Fatalf("seed wallet_user: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `UPDATE wallet_user SET invite_code=NULL WHERE tenant_id=?`, tenant); err != nil {
		t.Fatalf("clear invite codes: %v", err)
	}

	// 建库时已经跑过一遍；这里再连跑两遍，每一步都必须是 no-op 或者补齐缺的部分
	for round := 0; round < 2; round++ {
		if err := referralColumnsMigration(ctx, db); err != nil {
			t.Fatalf("round %d columns: %v", round, err)
		}
		if err := referralCodeBackfillMigration(ctx, db); err != nil {
			t.Fatalf("round %d backfill: %v", round, err)
		}
		if err := referralIndexesMigration(ctx, db); err != nil {
			t.Fatalf("round %d indexes: %v", round, err)
		}
	}

	// 回填之后不该再有无码的行
	var missing int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM wallet_user WHERE invite_code IS NULL`).Scan(&missing); err != nil {
		t.Fatalf("count missing codes: %v", err)
	}
	if missing != 0 {
		t.Fatalf("%d wallet_user rows still have no invite code after the backfill", missing)
	}

	// 回填出来的码必须是合法的 Crockford Base32，而且租户内唯一
	rows, err := db.QueryContext(ctx, `SELECT invite_code FROM wallet_user WHERE tenant_id=?`, tenant)
	if err != nil {
		t.Fatalf("read codes: %v", err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			t.Fatalf("scan code: %v", err)
		}
		if normalized, ok := referral.Normalize(code); !ok || normalized != code {
			t.Fatalf("backfilled code %q is not in the canonical alphabet", code)
		}
		if seen[code] {
			t.Fatalf("backfill produced the duplicate code %q inside one tenant", code)
		}
		seen[code] = true
	}
}

// invite_code 必须**保持可空**。收紧成 NOT NULL 会让服务端回滚到旧二进制后
// 旧的 INSERT（不带该列）在 strict 模式下报 ERROR 1364，老用户也登不上——
// 回滚等于全站登录中断。
func TestDBInviteCodeStaysNullable(t *testing.T) {
	db := openReferralTestDB(t)
	var nullable string
	if err := db.QueryRow(
		`SELECT IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS
		  WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='wallet_user' AND COLUMN_NAME='invite_code'`).Scan(&nullable); err != nil {
		t.Fatalf("inspect invite_code: %v", err)
	}
	if nullable != "YES" {
		t.Fatal("invite_code must stay nullable: NOT NULL breaks rollback (ERROR 1364) and forces the column into the login upsert")
	}
}

// 旧二进制的登录 INSERT（不带 invite_code）在加了列之后仍然必须能跑通。
// 这是 §8.3 回滚路径的回归测试。
func TestDBLegacyLoginInsertStillWorks(t *testing.T) {
	db := openReferralTestDB(t)
	tenant := fmt.Sprintf("%d", 900_000_000_000+time.Now().UnixNano()%1_000_000_000)
	address := fmt.Sprintf("0x%040x", time.Now().UnixNano())
	now := time.Now().UTC()
	if _, err := db.Exec(
		`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,created_at,updated_at)
		 VALUES(?,?,?,?,?,1,'active',?,?)
		 ON DUPLICATE KEY UPDATE last_login_at=VALUES(last_login_at),login_count=login_count+1,address=VALUES(address),updated_at=VALUES(updated_at)`,
		tenant, address, address, now, now, now, now); err != nil {
		t.Fatalf("a pre-referral login insert must still succeed after the migration: %v", err)
	}
}

func openReferralTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return openStoreTestDB(t)
}
