package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// 「Apple 证书与密钥」页的按租户总览（设计 RN-Admin docs/design/ios-credentials-overview-2026-09-24.md）。
// 这一组钉住：
//
//   - 匹配：证书、上传 Key 按 Team，描述文件按 Team + bundle id；材料的 bundle id 不分大小写，
//     机器装没装按原样（与认领同一个判据）；
//   - 共用 Team、bundle id 重复都标出来；上传 Key 的四种用途由服务端算；
//   - 打包机的分母只算 active 的 iOS 构建机；
//   - 没有租户在用的材料，只有清单完整、每个租户都读得出身份时才许删；删除带版本检查。
//
// 需要真实 MySQL（RN_TEST_MYSQL_DSN），否则整组跳过。

func profileMaterial(team, bundle string) iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TeamID: team, BundleID: bundle,
		ProfileBase64: base64.StdEncoding.EncodeToString([]byte("profile")),
	}
}

func teamCertificate(team string) iosmaterial.Material {
	m := certificateMaterial()
	m.TeamID = team
	return m
}

func teamUploadKey(team string) iosmaterial.Material {
	m := uploadMaterial()
	m.TeamID = team
	return m
}

// seedIOSTenant 另建一个配了 iOS 身份的租户；delivery 为空表示没配过（按全托管）。
func seedIOSTenant(t *testing.T, f *gateFixture, seed int, team, bundle, delivery string) string {
	t.Helper()
	tenant := testTenant(seed)
	slug := seedBuildTenant(t, f.s, tenant)
	raw, _ := json.Marshal(iosReleaseIdentity{AppleTeamID: team, BundleID: bundle})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		tenant, releaseIOSIdentityConfigKey, raw); err != nil {
		t.Fatal(err)
	}
	if delivery != "" {
		setIOSDelivery(t, f, tenant, delivery)
	}
	return slug
}

func setIOSDelivery(t *testing.T, f *gateFixture, tenant, mode string) {
	t.Helper()
	raw, _ := json.Marshal(iosDeliveryConfig{Mode: mode})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))
		ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=version+1`, tenant, iosDeliveryConfigKey, raw); err != nil {
		t.Fatal(err)
	}
}

func uploadSealed(t *testing.T, f *gateFixture, m iosmaterial.Material, key *sealedboxKey) {
	t.Helper()
	if code, body := uploadMaterialBox(t, f, sealMaterial(t, m, key)); code != http.StatusOK {
		t.Fatalf("upload %s: %d %v", m.Kind, code, body)
	}
}

// materialTenants 以夹具租户的身份调：路由那条路不带 Host，会落到默认租户上，"当前租户"就测不出来。
// 路由与平台管理员把关由 TestDBIOSMaterialByTenantIsPlatformOnly 单独钉。
func materialTenants(t *testing.T, f *gateFixture) map[string]any {
	t.Helper()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/platform/ios-material/tenants", nil)
	f.s.iosMaterialTenants(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("material by tenant: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// 走真实路由：平台级路由不经过按 Host 解析租户的中间件，"当前租户"要处理函数自己按 Host 认出来。
// 只调处理函数的用例测不出这一点（上线后才发现每一行都不是当前租户）。
func TestDBIOSMaterialByTenantKnowsTheCurrentTenantByHost(t *testing.T) {
	f, _ := newIOSPool(t, 157, 1)
	team := "H" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	seedGateIOSIdentity(t, f, team, "com.host.app")
	var slug string
	if err := f.db.QueryRow(`SELECT slug FROM tenants WHERE id=?`, f.tenant).Scan(&slug); err != nil {
		t.Fatal(err)
	}
	domain := "console-" + strings.ToLower(uniqueSuffix()) + ".example.test"
	if _, err := f.db.Exec(`INSERT INTO tenant_domain(tenant_id,domain,is_primary,status,deleted,created_at,updated_at) VALUES(?,?,0,'active',0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		f.tenant, domain); err != nil {
		t.Fatal(err)
	}
	get := func(host string) map[string]any {
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/platform/ios-material/tenants", nil)
		request.Host = host
		request.Header.Set("x-admin-key", gateAdminKey)
		recorder := httptest.NewRecorder()
		f.router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("material by tenant via %s: %d %s", host, recorder.Code, recorder.Body.String())
		}
		return decodeBody(t, recorder)
	}
	if row := materialTenantRow(t, get(domain), slug); row["current"] != true {
		t.Fatalf("the tenant the request came in on must be the current one: %v", row)
	}
	// 域名没登记：谁都不是当前租户，但总览照常给
	if row := materialTenantRow(t, get("unknown.example.test"), slug); row["current"] != false {
		t.Fatalf("an unknown host has no current tenant: %v", row)
	}
}

// 这份总览列出所有租户的 Team 与材料，只给平台管理员。
func TestDBIOSMaterialByTenantIsPlatformOnly(t *testing.T) {
	f, _ := newIOSPool(t, 156, 1)
	if r := f.do(http.MethodGet, "/v1/admin/platform/ios-material/tenants", "", nil, nil); r.Code != http.StatusUnauthorized && r.Code != http.StatusForbidden {
		t.Fatalf("an anonymous caller read the overview: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodGet, "/v1/admin/platform/ios-material/tenants", nil); r.Code != http.StatusOK {
		t.Fatalf("the platform admin must be able to read it: %d %s", r.Code, r.Body.String())
	}
}

func materialTenantRow(t *testing.T, body map[string]any, slug string) map[string]any {
	t.Helper()
	rows, _ := body["tenants"].([]any)
	for _, raw := range rows {
		if row, _ := raw.(map[string]any); row["slug"] == slug {
			return row
		}
	}
	t.Fatalf("tenant %s is not in the overview: %v", slug, rows)
	return nil
}

func slugList(value any) []string {
	out := []string{}
	for _, item := range value.([]any) {
		out = append(out, item.(string))
	}
	return out
}

func TestDBIOSMaterialByTenant(t *testing.T) {
	f, macs := newIOSPool(t, 150, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	// 测试库是共用的，别的用例留下的租户都在 poolTeamA 下：这里用只属于本用例的 Team
	team := "Q" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	seedGateIOSIdentity(t, f, team, "com.pool.alpha")
	var alpha string
	if err := f.db.QueryRow(`SELECT slug FROM tenants WHERE id=?`, f.tenant).Scan(&alpha); err != nil {
		t.Fatal(err)
	}
	// 同 Team 的两个自助上传租户，bundle id 只差大小写——bundle id 目前不查重
	beta := seedIOSTenant(t, f, 151, team, "com.pool.beta", iosDeliveryIPA)
	gamma := seedIOSTenant(t, f, 152, team, "com.pool.BETA", iosDeliveryIPA)

	uploadSealed(t, f, teamCertificate(team), builder)
	uploadSealed(t, f, teamUploadKey(team), uploader)
	// 描述文件的 bundle id 与 alpha 的身份只差大小写：照样算 alpha 的
	uploadSealed(t, f, profileMaterial(team, "COM.POOL.ALPHA"), builder)
	uploadSealed(t, f, profileMaterial(team, "com.pool.gone"), builder)

	// 分母只算 active 的 iOS 构建机：另登记一台吊销的 iOS 构建机与一台只打 Android 的
	mac := macs[0].record("")
	mac.Platforms = []string{buildPlatformIOS}
	revoked := newGateMachine(t, machineRoleBuilder, "mac-revoked-"+uniqueSuffix()).record("")
	revoked.Platforms, revoked.Status = []string{buildPlatformIOS}, machineStatusRevoked
	android := newGateMachine(t, machineRoleBuilder, "linux-"+uniqueSuffix()).record("")
	android.Platforms = []string{buildPlatformAndroid}
	f.writeMachines(f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby), mac, revoked, android)
	if r := iosClaim(f, macs[0], []appleTeamReport{{TeamID: team, BundleIDs: []string{"com.pool.alpha", "com.pool.beta"},
		ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeOK}}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}

	body := materialTenants(t, f)
	machines, _ := body["machines"].([]any)
	if len(machines) != 1 || machines[0].(map[string]any)["id"] != macs[0].ID || machines[0].(map[string]any)["online"] != true {
		t.Fatalf("only the active iOS builder counts: %v", machines)
	}

	row := materialTenantRow(t, body, alpha)
	if row["current"] != true || row["delivery"] != iosDeliveryTestFlight || row["uploadKeyUse"] != iosUploadKeyRequired {
		t.Fatalf("alpha is the current, fully managed tenant: %v", row)
	}
	if row["certificate"] == nil || row["uploadKey"] == nil || row["profile"] == nil {
		t.Fatalf("alpha's certificate, upload key and profile (bundle id in another case) are all stored: %v", row)
	}
	if certificate := row["certificate"].(map[string]any); certificate["stale"] != false || certificate["version"] != float64(1) {
		t.Fatalf("certificate slot: %v", certificate)
	}
	// 删除按表里存的原样精确匹配，所以 slot 要交回存的 scope，而不是租户身份里的写法
	if profile := row["profile"].(map[string]any); profile["scope"] != "COM.POOL.ALPHA" || profile["teamId"] != team {
		t.Fatalf("the profile slot must carry the stored team and scope: %v", profile)
	}
	if got := slugList(row["teamTenants"]); len(got) != 2 || len(slugList(row["teamTestFlightTenants"])) != 0 || len(slugList(row["bundleTenants"])) != 0 {
		t.Fatalf("alpha shares the team with the two self-upload tenants and nobody else: %v", row)
	}
	onMac := row["machines"].([]any)[0].(map[string]any)
	if onMac["installed"] != true || onMac["uploadProbe"] != uploadProbeOK || row["earliestExpiry"] != "2027-03-01T00:00:00Z" {
		t.Fatalf("alpha on the Mac: %v expiry %v", onMac, row["earliestExpiry"])
	}
	if readiness := row["readiness"].(map[string]any); readiness["ready"] != true {
		t.Fatalf("alpha can be queued: %v", readiness)
	}

	row = materialTenantRow(t, body, beta)
	if row["current"] != false || row["profile"] != nil || row["uploadKeyUse"] != iosUploadKeyKeptForOthers {
		t.Fatalf("beta has no profile and the team's upload key is kept for alpha: %v", row)
	}
	if got := slugList(row["teamTestFlightTenants"]); len(got) != 1 || got[0] != alpha {
		t.Fatalf("alpha is the fully managed tenant on beta's team: %v", got)
	}
	if got := slugList(row["bundleTenants"]); len(got) != 1 || got[0] != gamma {
		t.Fatalf("gamma registered the same bundle id: %v", got)
	}
	if readiness := row["readiness"].(map[string]any); readiness["ready"] != false || readiness["code"] != "NO_IPA_BUILDER_FOR_TEAM" {
		t.Fatalf("no builder can hand an .ipa back yet: %v", readiness)
	}
	// gamma 的 bundle id 大小写与 Mac 报的不一样：认领按原样比，任务派不出去，这里就该显示没装
	row = materialTenantRow(t, body, gamma)
	if row["machines"].([]any)[0].(map[string]any)["installed"] != false {
		t.Fatalf("a bundle id in another case is not what the Mac reported: %v", row)
	}

	orphans, _ := body["orphans"].([]any)
	if len(orphans) != 1 || orphans[0].(map[string]any)["scope"] != "com.pool.gone" {
		t.Fatalf("only the profile nobody uses is an orphan: %v", orphans)
	}
	invalid, _ := body["invalidTenants"].([]any)
	if body["orphansDeletable"] != (body["complete"] == true && len(invalid) == 0) {
		t.Fatalf("orphans are deletable only with a complete list and no unreadable tenant: %v", body)
	}

	// alpha 也切到自助上传：同 Team 没有全托管租户了，这把上传 Key 按设计就该撤下
	setIOSDelivery(t, f, f.tenant, iosDeliveryIPA)
	if row := materialTenantRow(t, materialTenants(t, f), beta); row["uploadKeyUse"] != iosUploadKeyWithdraw {
		t.Fatalf("an upload key nobody on the team needs should be withdrawn: %v", row)
	}
	remove := map[string]any{"kind": iosmaterial.KindUploadKey, "teamId": team, "scope": "", "reason": "withdrawn by hand", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusOK {
		t.Fatalf("remove the upload key: %d %s", r.Code, r.Body.String())
	}
	if row := materialTenantRow(t, materialTenants(t, f), alpha); row["uploadKeyUse"] != iosUploadKeyNotNeeded || row["uploadKey"] != nil {
		t.Fatalf("a self-upload tenant without an upload key needs none: %v", row)
	}

	// 换了平台加密公钥：存着的每一份都加密给了旧公钥
	materialKeys(t, f)
	if row := materialTenantRow(t, materialTenants(t, f), alpha); row["certificate"].(map[string]any)["stale"] != true {
		t.Fatalf("material sealed to the old key must be marked stale: %v", row)
	}
}

// 有一个租户的 release.ios 读不出来：不知道它用哪个 Team，"没有租户在用"就不可信，不许删。
func TestDBIOSMaterialOrphansAreNotDeletableWithAnUnreadableTenant(t *testing.T) {
	f, _ := newIOSPool(t, 153, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	team := "Z" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	uploadSealed(t, f, profileMaterial(team, "com.nobody.app"), builder)

	broken := testTenant(154)
	slug := seedBuildTenant(t, f.s, broken)
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		broken, releaseIOSIdentityConfigKey, `{"appleTeamId": 42}`); err != nil {
		t.Fatal(err)
	}
	// 共用库：别让这条坏配置留给后面的用例
	t.Cleanup(func() {
		_, _ = f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, broken, releaseIOSIdentityConfigKey)
	})

	body := materialTenants(t, f)
	found := false
	for _, raw := range body["invalidTenants"].([]any) {
		found = found || raw.(map[string]any)["slug"] == slug
	}
	if !found || body["orphansDeletable"] != false {
		t.Fatalf("an unreadable tenant must be listed and block deleting orphans: %v", body)
	}
	if orphans, _ := body["orphans"].([]any); len(orphans) != 1 {
		t.Fatalf("the orphan is still listed, just not deletable: %v", orphans)
	}
}

// 删除带版本：确认框开着的时候有人传了新版，删掉的不该是那份新的。
func TestDBIOSMaterialRemovalChecksTheVersion(t *testing.T) {
	f, _ := newIOSPool(t, 155, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	uploadSealed(t, f, certificateMaterial(), builder)
	uploadSealed(t, f, certificateMaterial(), builder)
	body := func(version int) map[string]any {
		return map[string]any{"kind": iosmaterial.KindCertificate, "teamId": materialTeam, "scope": "",
			"expectedVersion": version, "reason": "the certificate was revoked at Apple", "confirm": true}
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(1)); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_IOS_MATERIAL" {
		t.Fatalf("removing an older version than the stored one: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(2)); r.Code != http.StatusOK {
		t.Fatalf("removing the current version: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(2)); r.Code != http.StatusNotFound {
		t.Fatalf("removing twice: %d %s", r.Code, r.Body.String())
	}
}
