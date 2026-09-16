package api

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
)

// 导出这一步必须对着真库跑一次。
//
// 这个分支上它栽过两次，两次都是全绿交付出去的：
//
//  1. tenants 的 SELECT 列了 name / valid_from / valid_until 三个不存在的列。
//     真库上是 ERROR 1054，也就是说**每一次备份都必然失败**——两份内层密文都传上来
//     了、外层还没开始封就死，桶里一个对象都没有。
//  2. config_key 写的是 release.identity.android / release.identity.ios，而真键叫
//     release.android / release.ios。这个更阴：SQL 不报错，静默返回 0 行，备份照样
//     succeeded、控制台照样绿，直到恢复那天才发现包里没有包名和签名指纹。
//
// 两次都躲过了全部测试，因为在此之前没有任何一条测试用真库走到这个函数。
// 纯 Go 层的测试永远抓不到第一类（列名只有 MySQL 知道），也抓不到第二类
// （键名对不对只有库里的数据知道）。
func TestDBBackupExportMatchesRealSchema(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db}
	tenant := testTenant(41)
	slug := "bkexp-" + uniqueSuffix()

	if _, err := db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at)
		VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		tenant, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at)
		VALUES(?,?,1,'active',0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		tenant, slug+".example.com"); err != nil {
		t.Fatalf("insert tenant_domain: %v", err)
	}
	// 发布身份是恢复时最关键的一项：没有包名和 signerSha256，整条发布链对不回去
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		tenant, releaseAndroidIdentityConfigKey,
		`{"packageName":"com.example.bkexp","signerSha256":"aa:bb"}`); err != nil {
		t.Fatalf("insert release identity: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		tenant, buildConfigKey, `{"packageName":"com.example.bkexp"}`); err != nil {
		t.Fatalf("insert build config: %v", err)
	}
	// 一张真的 1x1 PNG：导出要把它解码落盘，测试要能认出 PNG 魔数
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		tenant, buildIconsConfigKey,
		`{"icon":{"data":"`+onePixelPNG+`","sha256":"x","width":1,"height":1,"size":68}}`); err != nil {
		t.Fatalf("insert icons: %v", err)
	}

	// 1054 会在这里现形
	out, err := s.exportBackupDatabaseConfig(context.Background())
	if err != nil {
		t.Fatalf("导出失败，说明 SQL 和真实表结构对不上，这会让每一次备份都失败: %v", err)
	}

	for _, name := range []string{"db/tenants.json", "db/tenant-domain.json"} {
		if len(out[name]) == 0 {
			t.Fatalf("%s 没有产出", name)
		}
	}

	// 设计 §4.5 的布局是每租户一个文件，不是一个扁平的大 JSON：
	// 恢复的人要能一眼看出哪个租户缺什么
	wantFiles := []string{
		"db/build-config/" + slug + ".json",
		"db/release-identity/" + slug + ".json",
		"db/build-icons/" + slug + "/icon.png",
	}
	for _, name := range wantFiles {
		if len(out[name]) == 0 {
			t.Errorf("包里没有 %s。有的是：%v", name, sortedKeys(out))
		}
	}

	// 发布身份里必须真有包名——这条挡的是「查询没报错但选不中任何行」
	var ident map[string]any
	if err := json.Unmarshal(out["db/release-identity/"+slug+".json"], &ident); err != nil {
		t.Fatalf("release-identity 不是合法 JSON: %v", err)
	}
	android, _ := ident["android"].(map[string]any)
	if android == nil || android["packageName"] != "com.example.bkexp" {
		t.Errorf("发布身份里没有包名，恢复时整条发布链对不回去: %v", ident)
	}

	// 图标必须是解码后的 PNG，不是 base64——埋在 JSON 里谁也确认不了
	png := out["db/build-icons/"+slug+"/icon.png"]
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Errorf("图标不是解码后的 PNG（前 8 字节 %q）", png[:min(8, len(png))])
	}

	// 键名要小驼峰
	var tenantRows []map[string]any
	if err := json.Unmarshal(out["db/tenants.json"], &tenantRows); err != nil {
		t.Fatalf("tenants.json 不是合法 JSON: %v", err)
	}
	if len(tenantRows) > 0 {
		if _, ok := tenantRows[0]["startDate"]; !ok {
			t.Errorf("键名没转成小驼峰，拿到的是 %v", sortedMapKeys(tenantRows[0]))
		}
	}

	// 软删标记必须带上：少了它，已软删的域名恢复后会变回生效
	var domains []map[string]any
	if err := json.Unmarshal(out["db/tenant-domain.json"], &domains); err != nil {
		t.Fatalf("tenant-domain.json 不是合法 JSON: %v", err)
	}
	if len(domains) > 0 {
		for _, column := range []string{"deleted", "isPrimary"} {
			if _, ok := domains[0][column]; !ok {
				t.Errorf("tenant-domain.json 少了 %s 列", column)
			}
		}
	}
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// 1x1 的透明 PNG，base64。用真的图片而不是随便一串 base64：
// 这条测试要断言导出的是**解码后的 PNG**，假数据验不了这件事
const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
