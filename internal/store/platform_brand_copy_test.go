package store

import (
	"context"
	"testing"
	"time"
)

// 平台全局（tenant_id=0）文案是所有没自己配的租户继承的那一份，里头不能有任何
// 租户的品牌名。清成空串而不是删行：键不存在会让 bootstrap 下发 null，而 App 侧
// branding.launch.title 是 z.string() 非空，现网安装会直接解析失败。
func TestDBPlatformBrandCopyIsClearedNotDeleted(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()

	// 造出迁移 13/15 留下的状态：全局行写着某个租户的名字
	for _, key := range []string{"launch.title", "app.name"} {
		for _, lang := range []string{"zh-CN", "en-US"} {
			if _, err := db.ExecContext(ctx, "INSERT INTO language_document(lang,`key`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES(?,?,'AnyFun','启动页标题',14,1,0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0) ON DUPLICATE KEY UPDATE content='AnyFun'", lang, key); err != nil {
				t.Fatalf("seed %s/%s: %v", lang, key, err)
			}
		}
	}
	// 一个租户自己写的覆盖：那是运营的选择，迁移不该碰
	tenant := int64(990000000) + time.Now().UnixNano()%100000
	if _, err := db.ExecContext(ctx, "INSERT INTO language_document(lang,`key`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES('zh-CN','launch.title','某租户自己的名字','启动页标题',14,1,?,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0)", tenant); err != nil {
		t.Fatalf("insert tenant override: %v", err)
	}
	t.Cleanup(func() {
		db.ExecContext(context.Background(), "DELETE FROM language_document WHERE tenant_id=?", tenant)
	})

	if err := tenantNeutralPlatformBrandCopyMigration(ctx, db); err != nil {
		t.Fatalf("migration: %v", err)
	}
	// 启动种子在迁移之后跑，它不能把品牌名又写回来（app.name 已从 RN-App 种子里删掉）
	if err := currentRNAppLocalizationSeedMigration(ctx, db); err != nil {
		t.Fatalf("seed after migration: %v", err)
	}

	for _, key := range []string{"launch.title", "app.name"} {
		for _, lang := range []string{"zh-CN", "en-US"} {
			var content string
			if err := db.QueryRowContext(ctx, "SELECT content FROM language_document WHERE tenant_id=0 AND lang=? AND `key`=? AND type=14", lang, key).Scan(&content); err != nil {
				t.Fatalf("global row for %s/%s must still exist: %v", lang, key, err)
			}
			if content != "" {
				t.Fatalf("global %s/%s still carries a brand name: %q", lang, key, content)
			}
		}
	}

	var override string
	if err := db.QueryRowContext(ctx, "SELECT content FROM language_document WHERE tenant_id=? AND lang='zh-CN' AND `key`='launch.title' AND type=14", tenant).Scan(&override); err != nil {
		t.Fatalf("read tenant override: %v", err)
	}
	if override != "某租户自己的名字" {
		t.Fatalf("tenant override was clobbered: got %q", override)
	}
}
