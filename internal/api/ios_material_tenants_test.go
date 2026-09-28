package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// 「Apple 证书与密钥」页的按租户总览（设计 RN-Admin docs/design/ios-credentials-overview-2026-09-24.md、
// RN-Server ios-tenant-owned-signing-material-2026-09-25 §3.4）。这一组钉住：
//
//   - 材料按租户匹配：每个租户只看自己那几格，描述文件再按 bundle id（不分大小写）；机器装没装与认领
//     同一个判据；
//   - 共用 Team、bundle id 重复都标出来；上传 Key 的三种用途由服务端算；
//   - 打包机的分母只算 active 的 iOS 构建机；Mac 核对不过的原因列出来；
//   - 没有租户在用的材料（含按 Team 存的旧行），只有清单完整、每个租户都读得出身份时才许删；
//     紧急删除带租户与版本检查。
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

// seedIOSTenant 另建一个配了 iOS 身份的租户，返回 id 与 slug；delivery 为空表示没配过（按全托管）。
func seedIOSTenant(t *testing.T, f *gateFixture, seed int, team, bundle, delivery string) (string, string) {
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
	return tenant, slug
}

func setIOSDelivery(t *testing.T, f *gateFixture, tenant, mode string) {
	t.Helper()
	raw, _ := json.Marshal(iosDeliveryConfig{Mode: mode})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))
		ON DUPLICATE KEY UPDATE config_value=VALUES(config_value),version=version+1`, tenant, iosDeliveryConfigKey, raw); err != nil {
		t.Fatal(err)
	}
}

// uploadSealed 直接把一份这个租户的材料存进库，不走租户接口的核对：这一组要摆出「bundle id 大小写不同」
// 「Team 已经改了」这类租户接口本来会拒的局面。tenant 为 "0" 时存成按 Team 的旧行（v1）。
func uploadSealed(t *testing.T, f *gateFixture, tenant string, m iosmaterial.Material, key *sealedboxKey) {
	t.Helper()
	if tenant != platformTenantID {
		m.TenantID = tenant
	}
	raw := sealMaterial(t, m, key)
	box, err := iosmaterial.ParseBox(raw)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := storeIOSMaterial(t.Context(), tx, tenant, box, raw, "tester@example.com", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// materialTenants 以夹具租户的身份调：路由那条路不带 Host，会落到默认租户上，"当前租户"就测不出来。
// 路由与平台管理员把关由 TestDBIOSMaterialByTenantIsPlatformOnly 单独钉。
// materialTenants 按 q 搜一页。测试库是共用的，别的用例留下的租户远超一页：要看某个租户就按
// 它独有的 Team 或 slug 搜，别指望它落在第一页
func materialTenants(t *testing.T, f *gateFixture, q string) map[string]any {
	t.Helper()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/platform/ios-material/tenants?q="+url.QueryEscape(q), nil)
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
		request := httptest.NewRequest(http.MethodGet, "/v1/admin/platform/ios-material/tenants?q="+url.QueryEscape(slug), nil)
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
	betaID, beta := seedIOSTenant(t, f, 151, team, "com.pool.beta", iosDeliveryIPA)
	gammaID, gamma := seedIOSTenant(t, f, 152, team, "com.pool.BETA", iosDeliveryIPA)

	uploadSealed(t, f, f.tenant, teamCertificate(team), builder)
	uploadSealed(t, f, f.tenant, teamUploadKey(team), uploader)
	// 描述文件的 bundle id 与 alpha 的身份只差大小写：照样算 alpha 的
	uploadSealed(t, f, f.tenant, profileMaterial(team, "COM.POOL.ALPHA"), builder)
	// alpha 名下一份别的 App 的描述文件：没人在用
	uploadSealed(t, f, f.tenant, profileMaterial(team, "com.pool.gone"), builder)
	// beta 交了自己的证书；gamma 什么都没交。alpha 的证书与 beta 无关
	uploadSealed(t, f, betaID, teamCertificate(team), builder)
	// 按 Team 存的旧行：不属于任何租户，只给还没升级的打包机
	uploadSealed(t, f, platformTenantID, teamCertificate(team), builder)

	// 分母只算 active 的 iOS 构建机：另登记一台吊销的 iOS 构建机与一台只打 Android 的
	mac := macs[0].record("")
	mac.Platforms = []string{buildPlatformIOS}
	revoked := newGateMachine(t, machineRoleBuilder, "mac-revoked-"+uniqueSuffix()).record("")
	revoked.Platforms, revoked.Status = []string{buildPlatformIOS}, machineStatusRevoked
	android := newGateMachine(t, machineRoleBuilder, "linux-"+uniqueSuffix()).record("")
	android.Platforms = []string{buildPlatformAndroid}
	f.writeMachines(f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby), mac, revoked, android)
	// 按租户自报：alpha 就绪；beta 的描述文件还没交，证书在；gamma 的 Mac 核对不过
	reports := []tenantMaterialReport{
		{TenantID: f.tenant, TeamID: team, BundleIDs: []string{"com.pool.alpha"}, CertificateSHA1: testCertificateSHA1,
			CertificateReady: true, ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeOK},
		{TenantID: betaID, TeamID: team, BundleIDs: []string{}, CertificateSHA1: testCertificateSHA1, CertificateReady: true,
			ExpiresAt: "2027-02-01T00:00:00Z", UploadProbe: uploadProbeMissing},
		{TenantID: gammaID, TeamID: team, BundleIDs: []string{}, UploadProbe: uploadProbeMissing,
			Problems: []string{"certificate: the certificate belongs to team ZZZZZZZZZZ"}},
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", macs[0].Token, nil, map[string]any{
		"platforms": []string{buildPlatformIOS}, "kinds": []string{jobKindAPK},
		"agentCommit": "1111111111111111111111111111111111111111", "os": machineOSDarwin,
		"appleTeams": teamReport(team, "com.pool.alpha", "com.pool.beta"), "tenantMaterial": reports, "freeGb": 120,
	}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}

	body := materialTenants(t, f, team)
	machines, _ := body["machines"].([]any)
	if len(machines) != 1 || machines[0].(map[string]any)["id"] != macs[0].ID || machines[0].(map[string]any)["online"] != true {
		t.Fatalf("only the active iOS builder counts: %v", machines)
	}

	row := materialTenantRow(t, body, alpha)
	if row["tenantId"] != f.tenant || row["current"] != true || row["delivery"] != iosDeliveryTestFlight || row["uploadKeyUse"] != iosUploadKeyRequired {
		t.Fatalf("alpha is the current, fully managed tenant: %v", row)
	}
	if row["certificate"] == nil || row["uploadKey"] == nil || row["profile"] == nil {
		t.Fatalf("alpha's certificate, upload key and profile (bundle id in another case) are all stored: %v", row)
	}
	if certificate := row["certificate"].(map[string]any); certificate["stale"] != false || certificate["legacy"] != false ||
		certificate["version"].(float64) < float64(materialVersionFloor) {
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

	// beta 有自己的证书，没有描述文件；alpha 的材料不算它的
	row = materialTenantRow(t, body, beta)
	if row["current"] != false || row["certificate"] == nil || row["profile"] != nil || row["uploadKey"] != nil ||
		row["uploadKeyUse"] != iosUploadKeyNotNeeded {
		t.Fatalf("beta holds its own certificate only: %v", row)
	}
	if got := slugList(row["teamTestFlightTenants"]); len(got) != 1 || got[0] != alpha {
		t.Fatalf("alpha is the fully managed tenant on beta's team: %v", got)
	}
	if got := slugList(row["bundleTenants"]); len(got) != 1 || got[0] != gamma {
		t.Fatalf("gamma registered the same bundle id: %v", got)
	}
	if onMac := row["machines"].([]any)[0].(map[string]any); onMac["installed"] != false || row["earliestExpiry"] != "2027-02-01T00:00:00Z" {
		t.Fatalf("beta has no profile on the Mac: %v", row)
	}
	// gamma：Mac 核对不过，原因原样列出来
	row = materialTenantRow(t, body, gamma)
	if onMac := row["machines"].([]any)[0].(map[string]any); onMac["installed"] != false || len(onMac["problems"].([]any)) != 1 {
		t.Fatalf("gamma on the Mac: %v", row)
	}
	rejected := false
	for _, raw := range row["problems"].([]any) {
		problem := raw.(map[string]any)
		rejected = rejected || (problem["code"] == "mac-rejected" && problem["count"] == float64(1) &&
			strings.HasPrefix(problem["detail"].(string), "certificate: "))
	}
	if !rejected {
		t.Fatalf("gamma's Mac rejection must be a problem: %v", row["problems"])
	}

	orphans, _ := body["orphans"].([]any)
	var scopes []string
	for _, raw := range orphans {
		orphan := raw.(map[string]any)
		scopes = append(scopes, orphan["tenantId"].(string)+"/"+orphan["kind"].(string)+"/"+orphan["scope"].(string))
	}
	sort.Strings(scopes)
	if len(scopes) != 2 || scopes[0] != "0/certificate/" || scopes[1] != f.tenant+"/profile/com.pool.gone" {
		t.Fatalf("the legacy row and alpha's unused profile are the orphans: %v", orphans)
	}
	invalid, _ := body["invalidTenants"].([]any)
	if body["orphansDeletable"] != (body["complete"] == true && len(invalid) == 0) {
		t.Fatalf("orphans are deletable only with a complete list and no unreadable tenant: %v", body)
	}

	// alpha 切到自助上传：它自己的上传 Key 该撤下，与同 Team 的别人无关
	setIOSDelivery(t, f, f.tenant, iosDeliveryIPA)
	if row := materialTenantRow(t, materialTenants(t, f, team), alpha); row["uploadKeyUse"] != iosUploadKeyWithdraw {
		t.Fatalf("a self-upload tenant still holding an upload key should withdraw it: %v", row)
	}
	remove := map[string]any{"tenantId": f.tenant, "kind": iosmaterial.KindUploadKey, "teamId": team, "scope": "",
		"reason": "withdrawn by hand", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusOK {
		t.Fatalf("remove the upload key: %d %s", r.Code, r.Body.String())
	}
	if row := materialTenantRow(t, materialTenants(t, f, team), alpha); row["uploadKeyUse"] != iosUploadKeyNotNeeded || row["uploadKey"] != nil {
		t.Fatalf("a self-upload tenant without an upload key needs none: %v", row)
	}

	// 换了平台加密公钥：存着的每一份都加密给了旧公钥
	materialKeys(t, f)
	if row := materialTenantRow(t, materialTenants(t, f, team), alpha); row["certificate"].(map[string]any)["stale"] != true {
		t.Fatalf("material sealed to the old key must be marked stale: %v", row)
	}
}

// 有一个租户的 release.ios 读不出来：不知道它用哪个 Team，"没有租户在用"就不可信，不许删。
func TestDBIOSMaterialOrphansAreNotDeletableWithAnUnreadableTenant(t *testing.T) {
	f, _ := newIOSPool(t, 153, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	team := "Z" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	uploadSealed(t, f, f.tenant, profileMaterial(team, "com.nobody.app"), builder)

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

	// 读不出来的租户与没人用的材料不分页，不带条件看全表
	body := materialTenants(t, f, "")
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
	version := func() int64 { return int64(uploadOwn(t, f, certificateMaterial(), builder)) }
	older, current := version(), version()
	body := func(version int64) map[string]any {
		return map[string]any{"tenantId": f.tenant, "kind": iosmaterial.KindCertificate, "teamId": materialTeam, "scope": "",
			"expectedVersion": version, "reason": "the certificate was revoked at Apple", "confirm": true}
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(older)); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_IOS_MATERIAL" {
		t.Fatalf("removing an older version than the stored one: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(current)); r.Code != http.StatusOK {
		t.Fatalf("removing the current version: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", body(current)); r.Code != http.StatusNotFound {
		t.Fatalf("removing twice: %d %s", r.Code, r.Body.String())
	}
}

func materialTenantsQuery(t *testing.T, f *gateFixture, query string) (int, map[string]any) {
	t.Helper()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/platform/ios-material/tenants?"+query, nil)
	f.s.iosMaterialTenants(c)
	return recorder.Code, decodeBody(t, recorder)
}

func problemCodes(row map[string]any) []string {
	out := []string{}
	for _, raw := range row["problems"].([]any) {
		out = append(out, raw.(map[string]any)["code"].(string))
	}
	return out
}

// 状态判定、筛选与分页都在服务端（设计 §10.1、§10.2）：齐了 / 缺材料 / 要处理由服务端算；
// q、status、machine 筛选与游标分页也在这里，控制台不拿全量自己切。
func TestDBIOSMaterialByTenantStatusFiltersAndPages(t *testing.T) {
	f, macs := newIOSPool(t, 158, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	team := "S" + strings.ToUpper(uniqueSuffix() + "000000000")[:9]
	seedGateIOSIdentity(t, f, team, "com.s.alpha")
	var alpha string
	if err := f.db.QueryRow(`SELECT slug FROM tenants WHERE id=?`, f.tenant).Scan(&alpha); err != nil {
		t.Fatal(err)
	}
	betaID, beta := seedIOSTenant(t, f, 159, team, "com.s.beta", iosDeliveryIPA)
	gammaID, gamma := seedIOSTenant(t, f, 160, team, "com.s.gamma", iosDeliveryIPA)
	// delta 没传描述文件、Mac 也没报它：缺材料，而且不算"这台机器没装上"
	deltaID, delta := seedIOSTenant(t, f, 161, team, "com.s.delta", iosDeliveryIPA)
	uploadSealed(t, f, f.tenant, teamCertificate(team), builder)
	uploadSealed(t, f, f.tenant, teamUploadKey(team), uploader)
	uploadSealed(t, f, f.tenant, profileMaterial(team, "com.s.alpha"), builder)
	for _, tenant := range []string{betaID, gammaID, deltaID} {
		uploadSealed(t, f, tenant, teamCertificate(team), builder)
	}
	uploadSealed(t, f, gammaID, profileMaterial(team, "com.s.gamma"), builder)
	// Mac 这一轮还是旧版代理，按 Team 报了 alpha 与 beta 的 bundle，没报 gamma：旧机器照旧按 Team 算
	if r := iosClaim(f, macs[0], []appleTeamReport{{TeamID: team, BundleIDs: []string{"com.s.alpha", "com.s.beta"},
		ExpiresAt: "2027-03-01T00:00:00Z", UploadProbe: uploadProbeOK}}); r.Code != http.StatusNoContent {
		t.Fatalf("claim: %d %s", r.Code, r.Body.String())
	}

	code, body := materialTenantsQuery(t, f, "q="+strings.ToLower(team))
	if code != http.StatusOK || body["total"] != float64(4) {
		t.Fatalf("searching by team finds its four tenants: %d %v", code, body)
	}
	if counts := body["counts"].(map[string]any); counts["ready"] != float64(1) || counts["missing"] != float64(2) || counts["attention"] != float64(1) {
		t.Fatalf("counts by status: %v", counts)
	}
	row := materialTenantRow(t, body, alpha)
	if row["status"] != iosMaterialReady || len(problemCodes(row)) != 0 {
		t.Fatalf("alpha has everything and can be queued: %v", row)
	}
	// beta 缺描述文件；排不进去的原因（没有能交回 .ipa 的机器）是另一件事，照样列出来
	row = materialTenantRow(t, body, beta)
	if codes := problemCodes(row); row["status"] != iosMaterialMissing || len(codes) != 2 || codes[0] != "profile-missing" || codes[1] != "not-ready" {
		t.Fatalf("beta misses its profile and no builder can hand back an .ipa: %v", row)
	}
	// delta 缺描述文件，Mac 也没报它；"没有打包机报过它"已经由缺描述文件说了，不再重复
	row = materialTenantRow(t, body, delta)
	if codes := problemCodes(row); row["status"] != iosMaterialMissing || len(codes) != 1 || codes[0] != "profile-missing" || row["delivered"] != false {
		t.Fatalf("delta misses its profile and nothing else needs saying: %v", row)
	}
	// gamma 的材料已下发、Mac 没装上；"没有打包机报过它"已经由 not-installed 说了，不再重复
	row = materialTenantRow(t, body, gamma)
	if codes := problemCodes(row); row["status"] != iosMaterialAttention || len(codes) != 1 || codes[0] != "not-installed" || row["delivered"] != true {
		t.Fatalf("gamma is delivered but not installed: %v", row)
	}

	_, body = materialTenantsQuery(t, f, "q="+team+"&status=missing")
	if rows := body["tenants"].([]any); len(rows) != 2 || body["total"] != float64(2) {
		t.Fatalf("status=missing: %v", body["tenants"])
	}
	// counts 不按 status 筛：点顶部汇总就是切状态
	if counts := body["counts"].(map[string]any); counts["ready"] != float64(1) {
		t.Fatalf("counts ignore the status filter: %v", counts)
	}
	// machine：已下发、这台没装上。缺材料的 delta 同样没装上，但不算——那是租户的事
	_, body = materialTenantsQuery(t, f, "q="+team+"&machine="+macs[0].ID)
	if rows := body["tenants"].([]any); len(rows) != 1 || rows[0].(map[string]any)["slug"] != gamma {
		t.Fatalf("machine filter lists delivered-but-not-installed tenants only: %v", body["tenants"])
	}

	// 按 slug 升序、一页一个，游标接着翻
	seen := []string{}
	cursor := ""
	for page := 0; page < 5; page++ {
		query := "q=" + team + "&limit=1"
		if cursor != "" {
			query += "&cursor=" + cursor
		}
		code, body := materialTenantsQuery(t, f, query)
		if code != http.StatusOK {
			t.Fatalf("page %d: %d %v", page, code, body)
		}
		for _, raw := range body["tenants"].([]any) {
			seen = append(seen, raw.(map[string]any)["slug"].(string))
		}
		next, _ := body["nextCursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 4 || !sort.StringsAreSorted(seen) {
		t.Fatalf("paging one by one must visit every tenant once, in slug order: %v", seen)
	}

	for _, bad := range []string{"status=bogus", "cursor=not-a-cursor!", "limit=0", "limit=201"} {
		if code, _ := materialTenantsQuery(t, f, bad); code != http.StatusBadRequest {
			t.Fatalf("%s must be refused: %d", bad, code)
		}
	}
}
