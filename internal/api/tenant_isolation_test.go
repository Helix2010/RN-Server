package api

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
)

// 租户会话开放之前要审的现有租户接口（设计 tenant-console-accounts-and-sso-2026-09-25 §3.4）：同一个接口，
// 租户会话看不到别的租户与平台的基础设施、改不了平台级的设置；平台会话照旧。

// activeTenantSession 在库里直接放一个成员（外部系统写的那种）和它的统一登录会话，返回会话令牌。
// 会话记为刚通过邮箱二次验证：这里测的是租户隔离，不是二次验证（那在 second_factor_test.go）。
func activeTenantSession(t *testing.T, db *sql.DB, tenant accountsTestTenant) string {
	t.Helper()
	now := time.Now().UTC()
	sfx := uniqueSuffix()
	subject := testSubject()
	result, err := db.Exec(`INSERT INTO tenant_admin_accounts (scope,tenant_id,display_name,email,idp_subject,created_by) VALUES (?,?,?,?,?,?)`,
		scopeTenant, tenant.id, "隔离测试", "iso-"+sfx+"@example.com", subject, "test")
	if err != nil {
		t.Fatalf("insert tenant account: %v", err)
	}
	id, _ := result.LastInsertId()
	account := strconv.FormatInt(id, 10)
	token := randomID(32)
	if _, err := db.Exec(`INSERT INTO admin_sessions (token_hash,actor_id,tenant_id,account_id,idp_subject,login_method,expires_at,created_at,second_factor_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		sha256Hex(token), tenantActor(tenant.id, account), tenant.id, account, subject, loginMethodCID, now.Add(time.Hour), now, now); err != nil {
		t.Fatalf("insert tenant session: %v", err)
	}
	return token
}

// seedPlatformRow 放一行平台级（tenant 0）配置，库里原来就有就沿用、不动它；只删自己放的那一行。
func seedPlatformRow(t *testing.T, db *sql.DB, key, value string) {
	t.Helper()
	var existing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_configs WHERE tenant_id=0 AND config_key=?`, key).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	if existing > 0 {
		return
	}
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(0,?,?,1,'platform-ops',?)`,
		key, value, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=0 AND config_key=? AND updated_by='platform-ops'`, key)
	})
}

// seedTenantConfig 放一行租户配置，测试结束删掉：测试库是共享、持久的，别的用例会扫全表
// （比如 TestDBMigrationMadeCrashAutoReportExplicit 要求每份 mobile-bootstrap 都有 features.crashAutoReport）。
func seedTenantConfig(t *testing.T, db *sql.DB, tenant, key, value string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',?)`,
		tenant, key, value, time.Now().UTC()); err != nil {
		t.Fatalf("seed %s: %v", key, err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, key) })
}

func TestDBTenantSessionIsolation(t *testing.T) {
	db := openTestDB(t)
	tenantA := accountsTestTenantRow(t, db, "isoa")
	tenantB := accountsTestTenantRow(t, db, "isob")
	var slugB string
	if err := db.QueryRow(`SELECT slug FROM tenants WHERE id=?`, tenantB.id).Scan(&slugB); err != nil {
		t.Fatal(err)
	}
	platformUser := "platform-iso-" + uniqueSuffix()
	platformHash, err := hashPassword("Platform-Pass-2026!")
	if err != nil {
		t.Fatal(err)
	}
	router := New(config.Config{
		Environment:            "test",
		StorageMasterKey:       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:      10,
		AdminUsername:          platformUser,
		AdminPasswordHash:      platformHash,
		PlatformAdminUsernames: []string{platformUser},
		AdminSessionTTL:        3600,
		AdminLoginMax:          1000,
		AdminLoginWindow:       900,
	}, &store.Store{DB: db})
	member := &browser{router: router, tenant: tenantA, cookies: map[string]string{adminSessionCookie: activeTenantSession(t, db, tenantA)}}
	platform := &browser{router: router, tenant: tenantA, cookies: map[string]string{}}
	platform.mustCode(t, platform.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
	member.mustCode(t, member.do("GET", "/v1/admin/tenant", nil, nil), 200)

	sfx := uniqueSuffix()
	teamID := fmt.Sprintf("Z%09d", time.Now().UnixNano()%1_000_000_000)
	bundleB := "com.iso.b" + sfx
	seedTenantConfig(t, db, tenantA.id, releaseIOSIdentityConfigKey, `{"appleTeamId":"`+teamID+`","bundleId":"com.iso.a`+sfx+`"}`)
	seedTenantConfig(t, db, tenantB.id, releaseIOSIdentityConfigKey, `{"appleTeamId":"`+teamID+`","bundleId":"`+bundleB+`"}`)

	t.Run("iOS 交付方式：租户只知道这个 Team 还有别人在用，不知道是谁", func(t *testing.T) {
		mine := member.do("GET", "/v1/admin/ios/delivery", nil, nil)
		view := member.mustCode(t, mine, 200)
		if view["teamSharedWithOtherTenants"] != true || len(view["teamSharedWithTestFlightTenants"].([]any)) != 0 || strings.Contains(mine.Body.String(), slugB) {
			t.Fatalf("tenant view = %s", mine.Body.String())
		}
		if !strings.Contains(platform.do("GET", "/v1/admin/ios/delivery", nil, nil).Body.String(), slugB) {
			t.Fatal("the platform session must still see which tenants share the team")
		}
		if strings.Contains(iosSharedTeamWarning([]string{slugB}, false), slugB) || !strings.Contains(iosSharedTeamWarning([]string{slugB}, true), slugB) {
			t.Fatal("the warning names other tenants only for the platform")
		}
	})

	t.Run("发布身份：bundle id、包名不能改成别的租户在用的", func(t *testing.T) {
		current := member.mustCode(t, member.do("GET", "/v1/admin/release-identity/ios", nil, nil), 200)
		wantProblem(t, member.do("PUT", "/v1/admin/release-identity/ios", map[string]any{
			"appleTeamId": teamID, "bundleId": strings.ToUpper(bundleB), "expectedVersion": current["version"], "reason": "改 bundle id", "confirm": true,
		}, nil), 409, "IOS_BUNDLE_ID_IN_USE")
		signer := strings.Repeat("ab", 32)
		seedTenantConfig(t, db, tenantB.id, releaseAndroidIdentityConfigKey, `{"packageName":"com.iso.pkg`+sfx+`","signerSha256":"`+signer+`"}`)
		wantProblem(t, member.do("PUT", "/v1/admin/release-identity/android", map[string]any{
			"packageName": "com.iso.pkg" + sfx, "signerSha256": strings.Repeat("cd", 32), "expectedVersion": 0, "reason": "改包名", "confirm": true,
		}, nil), 409, "ANDROID_PACKAGE_IN_USE")
		member.mustCode(t, member.do("PUT", "/v1/admin/release-identity/android", map[string]any{
			"packageName": "com.iso.own" + sfx, "signerSha256": strings.Repeat("cd", 32), "expectedVersion": 0, "reason": "自己的包名", "confirm": true,
		}, nil), 200)
	})

	t.Run("仓库目录只有平台管理员能改", func(t *testing.T) {
		save := func(b *browser, directory string, version int) map[string]any {
			return map[string]any{
				"repoDirectory": directory, "expectedVersion": version, "reason": "改打包配置", "confirm": true, "acknowledgeIdentityChange": true,
				"identity": map[string]any{"appName": "Iso", "scheme": "iso", "apiBaseUrl": "https://" + tenantA.api},
			}
		}
		wantProblem(t, member.do("PUT", "/v1/admin/build-config", save(member, "someone-else", 0), nil), 403, "REPO_DIRECTORY_PLATFORM_ONLY")
		// 留空 = slug，与没存过时的默认值相同：租户照常能存别的字段
		member.mustCode(t, member.do("PUT", "/v1/admin/build-config", save(member, "", 0), nil), 200)
		platform.mustCode(t, platform.do("PUT", "/v1/admin/build-config", save(platform, "iso-dir-"+sfx, 1), nil), 200)
		wantProblem(t, member.do("PUT", "/v1/admin/build-config", save(member, "", 2), nil), 403, "REPO_DIRECTORY_PLATFORM_ONLY")
		member.mustCode(t, member.do("PUT", "/v1/admin/build-config", save(member, "iso-dir-"+sfx, 2), nil), 200)
	})

	t.Run("预测平台的关联只有平台管理员能改；测试连接也只给平台", func(t *testing.T) {
		scope := "0x" + strings.Repeat("1", 64)
		// validConfig 要的最小形状
		base := func() map[string]any {
			return map[string]any{
				"ttlSeconds": 3600, "localization": map[string]any{}, "theme": map[string]any{}, "features": map[string]any{"crashAutoReport": false}, "support": map[string]any{},
				"updatePolicy": map[string]any{
					"minSupportedVersion": map[string]any{"android": "1.0.0", "ios": "1.0.0"},
					"latestVersion":       map[string]any{"android": "1.0.0", "ios": "1.0.0"},
				},
				"modules": map[string]any{"predict": false},
			}
		}
		seeded := base()
		seeded["services"] = map[string]any{"predict": map[string]any{"domain": "predict.iso.test", "scopeId": scope, "chain": "bsc"}}
		raw, _ := json.Marshal(seeded)
		seedTenantConfig(t, db, tenantA.id, "mobile-bootstrap", string(raw))
		version := 1
		patch := func(scopeID string) map[string]any {
			cfg := base()
			cfg["services"] = map[string]any{"predict": map[string]any{"domain": "predict.iso.test", "scopeId": scopeID, "chain": "bsc"}}
			return map[string]any{"expectedVersion": version, "reason": "改配置", "confirm": true, "config": cfg}
		}
		wantProblem(t, member.do("PATCH", "/v1/admin/app-config", patch("0x"+strings.Repeat("2", 64)), nil), 403, "SERVICES_CONFIG_PLATFORM_ONLY")
		// 原样带回（大小写不同也算同一个，归一化之后比）
		member.mustCode(t, member.do("PATCH", "/v1/admin/app-config", patch(strings.ToUpper(scope[:2])+scope[2:]), nil), 200)
		wantProblem(t, member.do("POST", "/v1/admin/predict/probe", map[string]any{"domain": "127.0.0.1"}, nil), 403, "PLATFORM_ADMIN_REQUIRED")
	})

	t.Run("推送凭据：继承平台那一行时，租户看不到平台的账号，也不能测它", func(t *testing.T) {
		seedPlatformRow(t, db, pushcreds.FCMConfigKey,
			`{"projectId":"platform-proj","clientEmail":"push@platform-proj.iam.gserviceaccount.com","privateKeyId":"abcdef0123456789","serviceAccountEncrypted":"x"}`)
		mine := member.do("GET", "/v1/admin/push/credentials", nil, nil)
		fcm := member.mustCode(t, mine, 200)["fcm"].(map[string]any)
		if fcm["inherited"] != true || strings.Contains(mine.Body.String(), "iam.gserviceaccount.com") || fcm["updatedBy"] != nil || fcm["privateKeyIdHint"] != nil {
			t.Fatalf("tenant sees the platform row: %s", mine.Body.String())
		}
		wantProblem(t, member.do("POST", "/v1/admin/push/credentials/fcm/test", map[string]any{}, nil), 403, "PUSH_CREDENTIALS_INHERITED")
		if !strings.Contains(platform.do("GET", "/v1/admin/push/credentials", nil, nil).Body.String(), "iam.gserviceaccount.com") {
			t.Fatal("the platform session still sees the platform row")
		}
	})

	t.Run("对象存储：继承平台存储时不回显平台的桶，也不能借平台的密钥换成自己的地址", func(t *testing.T) {
		seedPlatformRow(t, db, releaseStorageConfigKey,
			`{"provider":"s3","endpoint":"https://s3.platform.test","region":"r1","bucket":"platform-bucket","objectPrefix":"p","accessKeyIdEncrypted":"x","secretAccessKeyEncrypted":"y"}`)
		mine := member.do("GET", "/v1/admin/release-storage", nil, nil)
		view := member.mustCode(t, mine, 200)
		if view["inherited"] != true || view["bucket"] != "" || view["endpoint"] != nil || view["accessKeyHint"] != nil {
			t.Fatalf("tenant sees the platform storage: %s", mine.Body.String())
		}
		wantProblem(t, member.do("PUT", "/v1/admin/release-storage", map[string]any{
			"provider": "s3", "endpoint": "https://attacker.example", "region": "r1", "bucket": "b", "objectPrefix": "x",
			"expectedVersion": view["version"], "reason": "换存储", "confirm": true,
		}, nil), 422, "STORAGE_CREDENTIALS_REQUIRED")
		cors := member.do("GET", "/v1/admin/release-storage/cors", nil, nil)
		if cors.Code != 200 || strings.Contains(cors.Body.String(), tenantB.console) || !strings.Contains(cors.Body.String(), tenantA.console) {
			t.Fatalf("tenant CORS origins = %d %s", cors.Code, cors.Body.String())
		}
		if !strings.Contains(platform.do("GET", "/v1/admin/release-storage/cors", nil, nil).Body.String(), tenantB.console) {
			t.Fatal("the platform session gets the union of all tenants")
		}
	})

	t.Run("租户读自己的审计时看不到机器与别的租户", func(t *testing.T) {
		action := "build_keystore_check_update"
		target := "iso-audit-" + sfx
		if _, err := db.Exec(`INSERT INTO audit_events(id,tenant_id,actor_id,action,target_type,target_id,reason,request_id,summary,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			"aud_iso_"+sfx, tenantA.id, "signer", action, "app-config", target, "a signer reported", "",
			`{"machineId":"mch_iso","name":"signer-hk-1","decrypt":"ok","teamSharedWith":["`+slugB+`"]}`, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		mine := member.do("GET", "/v1/admin/audit-events?q="+target, nil, nil)
		body := mine.Body.String()
		if mine.Code != 200 || strings.Contains(body, "signer-hk-1") || strings.Contains(body, "mch_iso") || strings.Contains(body, slugB) || !strings.Contains(body, `"decrypt":"ok"`) {
			t.Fatalf("tenant audit view = %d %s", mine.Code, body)
		}
		if !strings.Contains(platform.do("GET", "/v1/admin/audit-events?q="+target, nil, nil).Body.String(), "signer-hk-1") {
			t.Fatal("the platform session still sees the machine in the audit")
		}
	})

	t.Run("原来不写审计的租户写接口现在写，操作者是成员", func(t *testing.T) {
		member.mustCode(t, member.do("POST", "/v1/admin/upload-sessions/cleanup-expired", map[string]any{}, nil), 200)
		var actorID string
		if err := db.QueryRow(`SELECT actor_id FROM audit_events WHERE tenant_id=? AND action='upload_session_cleanup' ORDER BY created_at DESC LIMIT 1`, tenantA.id).Scan(&actorID); err != nil ||
			!strings.HasPrefix(actorID, "tenant:"+tenantA.id+":") {
			t.Fatalf("cleanup audit actor = %q %v", actorID, err)
		}
	})
}

// 构建任务视图：租户会话里构建机、签名闸的名称与 id 都清掉；按机器搜也只给平台。
func TestBuildJobViewHidesMachinesFromTenants(t *testing.T) {
	view := buildJobViewWithMachines(buildJob{
		ClaimedBy:        sql.NullString{String: "mac-mini-3", Valid: true},
		ClaimedMachineID: sql.NullString{String: "mch_builder", Valid: true},
		SigningMachineID: sql.NullString{String: "mch_signer", Valid: true},
		SignOutcome:      []byte(`{"kind":"failed","code":"X","detail":"d","machineId":"mch_signer","at":"2026-09-27T00:00:00Z"}`),
	}, map[string]string{"mch_signer": "signer-hk-1"})
	redactMachinesForTenant(view)
	for _, key := range []string{"claimedBy", "claimedMachineId", "signingMachineId", "signingMachineName"} {
		if view[key] != nil {
			t.Fatalf("%s = %v", key, view[key])
		}
	}
	if view["signOutcome"].(gin.H)["machineId"] != nil {
		t.Fatalf("signOutcome = %v", view["signOutcome"])
	}
	tenantWhere, _ := buildJobListFilter{query: "mac-mini"}.where("7")
	platformWhere, _ := buildJobListFilter{query: "mac-mini", machineSearch: true}.where("7")
	if strings.Contains(tenantWhere, "claimed_by") || !strings.Contains(platformWhere, "claimed_by") {
		t.Fatalf("tenant where %q / platform where %q", tenantWhere, platformWhere)
	}
}

// keystore 视图：租户会话里签名闸的名称换成角色，机器 id 留着对行。
func TestAnonymizeSigners(t *testing.T) {
	view := gin.H{
		"signers":        []gin.H{{"machineId": "mch_a", "name": "signer-hk-1", "signerRole": string(signerRolePrimary)}},
		"missingSigners": []gin.H{{"machineId": "mch_b", "name": "signer-sg-2", "signerRole": string(signerRoleStandby)}},
		"recipients":     []gin.H{{"machineId": nil, "name": nil, "signerRole": nil}},
		"generator":      gin.H{"machineId": "mch_a", "name": "signer-hk-1"},
	}
	anonymizeSigners(view)
	if view["signers"].([]gin.H)[0]["name"] != "主签名闸" || view["missingSigners"].([]gin.H)[0]["name"] != "备签名闸" ||
		view["recipients"].([]gin.H)[0]["name"] != nil || view["generator"].(gin.H)["name"] != "签名闸" || view["signers"].([]gin.H)[0]["machineId"] != "mch_a" {
		t.Fatalf("anonymized = %v", view)
	}
}
