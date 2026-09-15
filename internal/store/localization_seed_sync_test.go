package store

import (
	"context"
	"testing"
	"time"
)

// 全局文案目录（tenant_id=0）唯一的来源就是这份内嵌种子——管理端写文案只写
// tenantID(c)，租户 id 从 1 起，运营碰不到全局行。以前种子只插不改，于是代码里
// 改过的值永远到不了库里：action.refresh 从「刷新配置」改成「刷新」之后，没写
// 租户覆盖的租户拿到的还是旧文案。这里逐条钉住对齐后的行为。
func TestDBLocalizationSeedRepairsDriftedGlobalCopy(t *testing.T) {
	db := openMigrationTestDB(t)
	ctx := context.Background()

	seed, err := readRNAppLocaleSeed("zh-CN")
	if err != nil {
		t.Fatalf("read embedded seed: %v", err)
	}
	const key = "action.refresh"
	want, ok := seed.Messages[key]
	if !ok {
		t.Fatalf("embedded seed is missing %s", key)
	}

	// 先让全局行存在（新库上这一步就是插入）
	if err := currentRNAppLocalizationSeedMigration(ctx, db); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	var meta string
	if err := db.QueryRowContext(ctx, "SELECT meta FROM language_document WHERE tenant_id=0 AND lang='zh-CN' AND `key`=? AND type=14", key).Scan(&meta); err != nil {
		t.Fatalf("read global row: %v", err)
	}

	// 造出"库里是旧值"的状态，并放一个租户覆盖在旁边
	staleMtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := db.ExecContext(ctx, "UPDATE language_document SET content='刷新配置',mtime=? WHERE tenant_id=0 AND lang='zh-CN' AND `key`=? AND type=14", staleMtime, key); err != nil {
		t.Fatalf("drift global row: %v", err)
	}
	tenant := int64(990000000) + time.Now().UnixNano()%100000
	if _, err := db.ExecContext(ctx, "INSERT INTO language_document(lang,`key`,content,meta,type,edit,tenant_id,ctime,mtime,deleted) VALUES('zh-CN',?,'运营自己写的文案','运营改的',14,1,?,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3),0)", key, tenant); err != nil {
		t.Fatalf("insert tenant override: %v", err)
	}
	t.Cleanup(func() {
		db.ExecContext(context.Background(), "DELETE FROM language_document WHERE tenant_id=?", tenant)
	})

	if err := currentRNAppLocalizationSeedMigration(ctx, db); err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	var got, gotMeta string
	var mtime time.Time
	if err := db.QueryRowContext(ctx, "SELECT content,meta,mtime FROM language_document WHERE tenant_id=0 AND lang='zh-CN' AND `key`=? AND type=14", key).Scan(&got, &gotMeta, &mtime); err != nil {
		t.Fatalf("read repaired row: %v", err)
	}
	if got != want {
		t.Fatalf("global copy not repaired: got %q want %q", got, want)
	}
	// meta 是管理端列表里给人看的分类，早期迁移写过人工描述，种子里没有对应信息
	if gotMeta != meta {
		t.Fatalf("meta was overwritten: got %q want %q", gotMeta, meta)
	}
	if !mtime.After(staleMtime) {
		t.Fatalf("mtime should move when content changes: got %v", mtime)
	}

	var tenantContent string
	if err := db.QueryRowContext(ctx, "SELECT content FROM language_document WHERE tenant_id=? AND lang='zh-CN' AND `key`=? AND type=14", tenant, key).Scan(&tenantContent); err != nil {
		t.Fatalf("read tenant override: %v", err)
	}
	if tenantContent != "运营自己写的文案" {
		t.Fatalf("tenant override was clobbered: got %q", tenantContent)
	}

	// 内容本来就一致时不该动 mtime——否则每次启动都把全表 1245×2 行刷一遍
	if _, err := db.ExecContext(ctx, "UPDATE language_document SET mtime=? WHERE tenant_id=0 AND lang='zh-CN' AND `key`=? AND type=14", staleMtime, key); err != nil {
		t.Fatalf("pin mtime: %v", err)
	}
	if err := currentRNAppLocalizationSeedMigration(ctx, db); err != nil {
		t.Fatalf("seed rerun: %v", err)
	}
	if err := db.QueryRowContext(ctx, "SELECT mtime FROM language_document WHERE tenant_id=0 AND lang='zh-CN' AND `key`=? AND type=14", key).Scan(&mtime); err != nil {
		t.Fatalf("read mtime after rerun: %v", err)
	}
	if !mtime.Equal(staleMtime) {
		t.Fatalf("mtime moved on an unchanged row: got %v want %v", mtime, staleMtime)
	}
}
