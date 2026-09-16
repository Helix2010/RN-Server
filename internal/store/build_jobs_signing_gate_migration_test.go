package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// 迁移 54 必须能重复执行：apply 失败不记账，下次启动会从头再跑一遍。
// 跑完之后表结构要满足设计「构建任务的状态与字段」的每一条。
func TestDBBuildJobsSigningGateMigrationIsIdempotentAndComplete(t *testing.T) {
	db := openReferralTestDB(t)
	ctx := context.Background()
	for round := 0; round < 2; round++ {
		if err := buildJobsSigningGateMigration(ctx, db); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}

	var columnType string
	if err := db.QueryRowContext(ctx, `SELECT COLUMN_TYPE FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND COLUMN_NAME='status'`).Scan(&columnType); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"queued", "claimed", "running", "built", "signing", "succeeded", "failed", "canceled"} {
		if !strings.Contains(columnType, "'"+state+"'") {
			t.Fatalf("status enum is missing %q: %s", state, columnType)
		}
	}

	var expression string
	if err := db.QueryRowContext(ctx, `SELECT GENERATION_EXPRESSION FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND COLUMN_NAME='live_build_number'`).Scan(&expression); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"built", "signing"} {
		if !strings.Contains(expression, state) {
			t.Fatalf("live_build_number does not treat %s as live: %s", state, expression)
		}
	}
	// 唯一索引必须还是三列：分两步删列重建时，中间那一刻它会退化成 UNIQUE(tenant_id, platform)
	rows, err := db.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND INDEX_NAME='ux_build_jobs_live_build_number' ORDER BY SEQ_IN_INDEX`)
	if err != nil {
		t.Fatal(err)
	}
	var indexed []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		indexed = append(indexed, name)
	}
	rows.Close()
	if strings.Join(indexed, ",") != "tenant_id,platform,live_build_number" {
		t.Fatalf("ux_build_jobs_live_build_number covers %v", indexed)
	}

	// 每一列都带 COMMENT（AGENTS.md「数据库表设计原则」）
	commentless := []string{}
	rows, err = db.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND COALESCE(COLUMN_COMMENT,'')=''`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		commentless = append(commentless, name)
	}
	rows.Close()
	if len(commentless) > 0 {
		t.Fatalf("build_jobs columns without COMMENT: %v", commentless)
	}
	for _, column := range []string{"attempt", "claimed_machine_id", "unsigned_object_key", "unsigned_size", "unsigned_sha256",
		"sbom_object_key", "sbom_size", "sbom_sha256", "native_fingerprint", "provenance", "sign_attempt", "sign_failures",
		"signing_machine_id", "signing_claimed_at", "signing_heartbeat_at", "sign_outcome"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='build_jobs' AND COLUMN_NAME=?`, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("column %s is missing", column)
		}
	}
}

// 生成列在 built / signing 时占住 build 号：签名期间同一个号不能再排一条。
// failed / canceled 照旧放号，OTA 任务照旧不占号。
func TestDBLiveBuildNumberHoldsTheNumberWhileSigning(t *testing.T) {
	db := openReferralTestDB(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("%d", 930_000_000_000+time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM build_jobs WHERE tenant_id=?`, tenant) })

	insert := func(id, kind, status string, buildNumber int) error {
		now := time.Now().UTC()
		_, err := db.ExecContext(ctx, `INSERT INTO build_jobs(id,tenant_id,platform,kind,git_ref,version,build_number,status,log_tail,reason,created_by,created_at,updated_at)
			VALUES(?,?,'android',?,'main','1.0.0',?,?,JSON_ARRAY(),'migration test','tester',?,?)`, id, tenant, kind, buildNumber, status, now, now)
		return err
	}
	isDuplicate := func(err error) bool { return err != nil && strings.Contains(err.Error(), "ux_build_jobs_live_build_number") }

	for i, state := range []string{"built", "signing"} {
		number := 10 + i
		if err := insert(fmt.Sprintf("bld_hold_%s_%d", state, time.Now().UnixNano()), "apk", state, number); err != nil {
			t.Fatalf("seed %s: %v", state, err)
		}
		err := insert(fmt.Sprintf("bld_second_%s_%d", state, time.Now().UnixNano()), "apk", "queued", number)
		if !isDuplicate(err) {
			t.Fatalf("a %s job did not hold build number %d: %v", state, number, err)
		}
	}
	for i, state := range []string{"failed", "canceled"} {
		number := 20 + i
		if err := insert(fmt.Sprintf("bld_dead_%s_%d", state, time.Now().UnixNano()), "apk", state, number); err != nil {
			t.Fatalf("seed %s: %v", state, err)
		}
		if err := insert(fmt.Sprintf("bld_retry_%s_%d", state, time.Now().UnixNano()), "apk", "queued", number); err != nil {
			t.Fatalf("a %s job still holds build number %d: %v", state, number, err)
		}
	}
	// 生成列由数据库算，任何人写不进去
	var live sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT live_build_number FROM build_jobs WHERE tenant_id=? AND status='signing'`, tenant).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if !live.Valid || live.Int64 != 11 {
		t.Fatalf("live_build_number for a signing job = %v", live)
	}
}
