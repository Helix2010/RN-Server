package store

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"
)

// 迁移 66：按 Team 存的旧行复制给用这个 Team 的每个租户，复制的行标 legacy（设计
// ios-tenant-owned-signing-material-2026-09-25 §3.5）。证书按 Team、描述文件按 bundle id（不分大小写）、
// 上传 Key 只给全托管的租户；旧行留着给还没升级的打包机。重跑不重复、不覆盖租户已经重传的那一份。
func TestDBIOSSigningMaterialByTenantMigrationCopiesLegacyRows(t *testing.T) {
	db := openStoreTestDB(t)
	ctx := context.Background()
	if err := iosSigningMaterialByTenantMigration(ctx, db); err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%09d", time.Now().UnixNano()%1_000_000_000)
	team, otherTeam := "M"+suffix, "N"+suffix
	base := 7_000_000_000 + time.Now().UnixNano()%1_000_000_000
	managed, selfUpload, elsewhere, deleted := base, base+1, base+2, base+3
	now := time.Now().UTC()
	for _, tenant := range []struct {
		id       int64
		team     string
		bundle   string
		delivery string
		deleted  int
	}{
		{managed, team, "com.migrate.managed", "", 0},
		{selfUpload, team, "com.migrate.self", `{"mode":"ipa"}`, 0},
		{elsewhere, otherTeam, "com.migrate.managed", "", 0},
		{deleted, team, "com.migrate.gone", "", 1},
	} {
		if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,?,1,'2026-01-01','2099-01-01',?,?,?)`,
			tenant.id, fmt.Sprintf("migrate-%d", tenant.id), tenant.deleted, now, now); err != nil {
			t.Fatal(err)
		}
		identity := fmt.Sprintf(`{"appleTeamId":%q,"bundleId":%q}`, tenant.team, tenant.bundle)
		if _, err := db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'release.ios',?,1,'test',?)`,
			tenant.id, identity, now); err != nil {
			t.Fatal(err)
		}
		if tenant.delivery != "" {
			if _, err := db.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'release.ios.delivery',?,1,'test',?)`,
				tenant.id, tenant.delivery, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() {
		ids := []any{managed, selfUpload, elsewhere, deleted}
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id IN (?,?,?,?)`, ids...)
		_, _ = db.Exec(`DELETE FROM tenants WHERE id IN (?,?,?,?)`, ids...)
		_, _ = db.Exec(`DELETE FROM ios_signing_material WHERE team_id IN (?,?)`, team, otherTeam)
	})
	legacy := func(kind, scope, purpose string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `INSERT INTO ios_signing_material(tenant_id,kind,team_id,scope,purpose,recipient_sha256,version,ciphertext,uploaded_by,uploaded_at)
			VALUES(0,?,?,?,?,REPEAT('a',64),42,'{"v":1}','platform-admin',?)`, kind, team, scope, purpose, now); err != nil {
			t.Fatal(err)
		}
	}
	legacy("certificate", "", "ios-builder-material")
	legacy("upload-key", "", "ios-uploader-material")
	legacy("profile", "COM.MIGRATE.MANAGED", "ios-builder-material")
	legacy("profile", "com.migrate.nobody", "ios-builder-material")

	for round := 0; round < 2; round++ {
		if err := iosSigningMaterialByTenantMigration(ctx, db); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT tenant_id,kind,scope,legacy,version,uploaded_by FROM ios_signing_material WHERE team_id=? ORDER BY tenant_id,kind,scope`, team)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := []string{}
	for rows.Next() {
		var tenant int64
		var kind, scope, by string
		var isLegacy bool
		var version int64
		if err := rows.Scan(&tenant, &kind, &scope, &isLegacy, &version, &by); err != nil {
			t.Fatal(err)
		}
		if tenant != 0 && (!isLegacy || version != 42 || by != "platform-admin") {
			t.Fatalf("a copied row must be legacy and keep the version and uploader: %d %s %v %d %s", tenant, kind, isLegacy, version, by)
		}
		name := map[int64]string{0: "legacy", managed: "managed", selfUpload: "self-upload"}[tenant]
		if name == "" {
			name = fmt.Sprint(tenant)
		}
		got = append(got, name+"/"+kind+"/"+scope)
	}
	sort.Strings(got)
	want := []string{
		"legacy/certificate/", "legacy/profile/COM.MIGRATE.MANAGED", "legacy/profile/com.migrate.nobody", "legacy/upload-key/",
		"managed/certificate/", "managed/profile/COM.MIGRATE.MANAGED", "managed/upload-key/",
		"self-upload/certificate/",
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("copied rows:\n got %v\nwant %v", got, want)
	}

	// 租户重传之后是它自己的 v2：再跑一次迁移不能拿旧行盖回去
	if _, err := db.ExecContext(ctx, `UPDATE ios_signing_material SET legacy=0,version=99 WHERE tenant_id=? AND kind='certificate' AND team_id=?`, managed, team); err != nil {
		t.Fatal(err)
	}
	if err := iosSigningMaterialByTenantMigration(ctx, db); err != nil {
		t.Fatal(err)
	}
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT version FROM ios_signing_material WHERE tenant_id=? AND kind='certificate' AND team_id=?`, managed, team).Scan(&version); err != nil || version != 99 {
		t.Fatalf("a re-uploaded certificate was overwritten by the migration: %d %v", version, err)
	}
}
