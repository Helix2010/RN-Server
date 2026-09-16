package store

import (
	"context"
	"testing"
)

// 迁移 69（第二次发布）：删表、删备份与打包机公钥的配置行、删旧格式的签名密钥检查记录，
// 别的配置一行不动；可以重复执行。
func TestDBDropPlatformBackupsMigration(t *testing.T) {
	db := openReferralTestDB(t)
	ctx := context.Background()
	// 打开测试库时 69 已经跑过：把迁移 53 的表建回来，再摆上要删和不该删的行
	if err := platformBackupsMigration(ctx, db); err != nil {
		t.Fatal(err)
	}
	const legacyTenant, currentTenant = 990551, 990552
	rows := []struct {
		tenant     int
		key, value string
	}{
		{0, "backup.bucket", `{"bucket":"old"}`},
		{0, "backup.recipients", `{"recipients":[]}`},
		{0, "build.agent.backup-sign", `{"sealed":"x"}`},
		{0, "build.agent.recipient", `{"publicKey":"x"}`},
		{0, "drop-backups-migration-keeper", `{"keep":true}`},
		{legacyTenant, "build.keystore.check", `{"version":3,"ok":true,"agent":"amos"}`},
		{currentTenant, "build.keystore.check", `{"format":2,"machines":{}}`},
	}
	cleanup := func() {
		for _, row := range rows {
			_, _ = db.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, row.tenant, row.key)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
	for _, row := range rows {
		if _, err := db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',UTC_TIMESTAMP(3))`,
			row.tenant, row.key, row.value); err != nil {
			t.Fatalf("seed %s: %v", row.key, err)
		}
	}

	for round := 0; round < 2; round++ {
		if err := dropPlatformBackupsMigration(ctx, db); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}

	var tables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='platform_backups'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatal("platform_backups is still there")
	}
	exists := func(tenant int, key string) bool {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, key).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	for _, key := range []string{"backup.bucket", "backup.recipients", "build.agent.backup-sign", "build.agent.recipient"} {
		if exists(0, key) {
			t.Fatalf("%s survived", key)
		}
	}
	if exists(legacyTenant, "build.keystore.check") {
		t.Fatal("a legacy build.keystore.check survived")
	}
	if !exists(currentTenant, "build.keystore.check") || !exists(0, "drop-backups-migration-keeper") {
		t.Fatal("the migration deleted rows it does not own")
	}
}
