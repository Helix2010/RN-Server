package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 数据库集成测试（设计 device-account-aggregation-2026-09-07 §4.12）：
// 需要一个可清空的 MySQL 8，通过环境变量指定；没有配置时整组跳过，不算通过。
//   RN_TEST_MYSQL_HOST=127.0.0.1 RN_TEST_MYSQL_PORT=33061 RN_TEST_MYSQL_USER=root \
//   RN_TEST_MYSQL_PASSWORD=rn-test RN_TEST_MYSQL_DATABASE=rn_test go test ./internal/api/ -run TestDB
// 每个测试用自己的租户 ID，互不干扰；迁移只在首次打开时跑一遍。

var testDB *sql.DB

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	host := os.Getenv("RN_TEST_MYSQL_HOST")
	if host == "" {
		t.Skip("RN_TEST_MYSQL_HOST not set; database-backed tests skipped")
	}
	if testDB != nil {
		return testDB
	}
	port, _ := strconv.Atoi(os.Getenv("RN_TEST_MYSQL_PORT"))
	if port == 0 {
		port = 3306
	}
	env := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}
	cfg := config.Config{
		MySQLHost: host, MySQLPort: port, MySQLUser: env("RN_TEST_MYSQL_USER", "root"), MySQLPassword: os.Getenv("RN_TEST_MYSQL_PASSWORD"), MySQLDatabase: env("RN_TEST_MYSQL_DATABASE", "rn_test"),
		MySQLConnectionLimit: 5, MySQLMaxIdleConnections: 2, MySQLConnectionMaxLifetime: 600, MySQLConnectionMaxIdleTime: 60, MySQLQueryTimeout: 10,
		MySQLCharset: "utf8mb4", MySQLTimezone: "UTC", MySQLParseTime: true, MySQLConnectTimeout: 5, MySQLReadTimeout: 30, MySQLWriteTimeout: 30,
		MySQLInitTimeout: 60, MySQLInitMaxAttempts: 3, MySQLInitRetryDelay: 1, MySQLAutoMigrate: true,
	}
	st, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	testDB = st.DB
	return testDB
}

func testContext(t *testing.T, tenant, method, target string, body any) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	c.Request = httptest.NewRequest(method, target, reader)
	c.Request.Header.Set("content-type", "application/json")
	c.Set("tenantId", tenant)
	c.Set("actorId", "tester@example.com")
	c.Set("requestId", "req_test")
	return c, recorder
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON: %s", recorder.Body.String())
	}
	return out
}

func uniqueSuffix() string {
	return strconv.FormatInt(time.Now().UnixNano()%1_000_000_000, 36)
}

// testTenant 生成本次测试专用的数字租户 ID（tenant_id 是 BIGINT），避免多次运行互相干扰。
func testTenant(seed int) string {
	return strconv.FormatInt(900_000_000_000+time.Now().UnixNano()%1_000_000_000*10+int64(seed), 10)
}

// 下面这几个和 testTenant 是同一件事：测试库是持久的，写死的标识会把上一次运行的
// 数据带进这一次。表现是用例第一次绿、第二次红，而代码一个字没改——今天这两个用例
// 就是这样被当成"本次改动弄坏了什么"查了一轮。
//
// 用 nanoTime 派生的十六进制串，跑第二遍换一个值，互不相干。
func testHex(length int) string {
	digest := sha256.Sum256([]byte(strconv.FormatInt(time.Now().UnixNano(), 10) + uniqueSuffix()))
	return hex.EncodeToString(digest[:])[:length]
}

// testAddress 生成本次运行专用的钱包地址。平台级查询按地址跨租户归并，写死地址
// 会让"恰好两个租户"的断言看见历次运行累积下来的全部租户。
func testAddress() string { return "0x" + testHex(40) }

// testUpdateID 生成本次运行专用的 OTA update id。ota_releases.update_id 上有唯一键，
// 写死的值第二次插入直接 1062。
func testUpdateID() string {
	h := testHex(32)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

func insertTestUser(t *testing.T, db *sql.DB, tenant string, address string) uint64 {
	t.Helper()
	now := time.Now().UTC()
	result, err := db.Exec(`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,created_at,updated_at) VALUES(?,?,?,?,?,1,'active',?,?)`, tenant, address, strings.ToLower(address), now, now, now, now)
	if err != nil {
		t.Fatalf("insert wallet_user: %v", err)
	}
	id, _ := result.LastInsertId()
	return uint64(id)
}

func insertTestSession(t *testing.T, db *sql.DB, tenant string, userID uint64, installationID string, issued time.Time) string {
	t.Helper()
	id := "wses_" + uniqueSuffix() + randomID(6)
	if _, err := db.Exec(`INSERT INTO wallet_session(id,tenant_id,user_id,token_hash,connector,chains,issued_at,expires_at,last_seen_at,installation_id) VALUES(?,?,?,?,'embedded','bsc',?,?,?,?)`, id, tenant, userID, randomID(32), issued, issued.Add(7*24*time.Hour), issued, sqlNullable(installationID)); err != nil {
		t.Fatalf("insert wallet_session: %v", err)
	}
	return id
}

func sqlNullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// heartbeatInstallation 走真实的 saveInstallation（含设备归并）写一条安装实例。
func heartbeatInstallation(t *testing.T, s *server, tenant, installationID, deviceSource string, body installationHeartbeat) {
	t.Helper()
	body.InstallationID = installationID
	body.DeviceSourceHash = deviceSource
	if body.PackageID == "" {
		body.PackageID = "com.example.app"
	}
	if body.OTAChannel == "" {
		body.OTAChannel = "production"
	}
	if body.Locale == "" {
		body.Locale, body.Theme, body.OSVersion, body.DeviceClass = "zh-CN", "system", "35", "android-phone"
	}
	c, _ := testContext(t, tenant, http.MethodPost, "/v1/mobile/installations/heartbeat", nil)
	c.Request.Header.Set("x-platform", "android")
	c.Request.Header.Set("x-application-id", "dex-mobile")
	c.Request.Header.Set("x-app-version", "1.2.9")
	c.Request.Header.Set("x-build-number", "23")
	c.Request.Header.Set("x-runtime-version", "1.2.9")
	c.Request.Header.Set("x-distribution-channel", "direct")
	if code, detail := normalizeRuntimeReport(&body); code != "" {
		t.Fatalf("runtime report invalid: %s %s", code, detail)
	}
	if err := s.saveInstallation(c, body, randomID(32), 1, time.Now().Add(24*time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("save installation: %v", err)
	}
}

func testServer(db *sql.DB) *server {
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	return &server{db: db, cfg: config.Config{DeviceIdentityKey: key, PlatformAdminUsernames: []string{"tester@example.com"}}}
}

func str(v string) *string { return &v }

// 同一安装实例第二次登录后只剩一条有效会话，旧的标 superseded；登录历史累加
func TestDBLoginSupersedesSessionsAndAccumulatesHistory(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(0)
	user := insertTestUser(t, db, tenant, "0x1111111111111111111111111111111111111111")
	installation := "inst_" + strings.Repeat("a", 32)
	now := time.Now().UTC()
	first := insertTestSession(t, db, tenant, user, installation, now.Add(-time.Hour))
	second := insertTestSession(t, db, tenant, user, installation, now)
	if _, err := db.Exec(supersedeSessionsSQL, now, tenant, installation, second); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	var reason sql.NullString
	var revoked sql.NullTime
	if err := db.QueryRow(`SELECT revoked_at,ended_reason FROM wallet_session WHERE id=?`, first).Scan(&revoked, &reason); err != nil || !revoked.Valid || reason.String != "superseded" {
		t.Fatalf("first session must be superseded: %v %v %v", revoked, reason, err)
	}
	var live int
	if err := db.QueryRow(`SELECT COUNT(*) FROM wallet_session WHERE tenant_id=? AND installation_id=? AND revoked_at IS NULL`, tenant, installation).Scan(&live); err != nil || live != 1 {
		t.Fatalf("exactly one live session expected, got %d (%v)", live, err)
	}
	for range 2 {
		if _, err := db.Exec(walletUserInstallationUpsertSQL, tenant, user, installation, now, now, "embedded", now, now); err != nil {
			t.Fatalf("login history upsert: %v", err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT login_count FROM wallet_user_installation WHERE tenant_id=? AND user_id=? AND installation_id=?`, tenant, user, installation).Scan(&count); err != nil || count != 2 {
		t.Fatalf("login history must count both logins, got %d (%v)", count, err)
	}
}

// 租户级封禁：状态改为 blocked、结束本租户会话、写审计；解封不结束会话
func TestDBBlockWalletUserEndsSessionsAndAudits(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	tenant := testTenant(1)
	user := insertTestUser(t, db, tenant, "0x2222222222222222222222222222222222222222")
	insertTestSession(t, db, tenant, user, "", time.Now().UTC())
	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/wallet/users/x/block", map[string]any{"reason": "integration test block", "confirm": true})
	c.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(user, 10)}}
	s.blockWalletUser(true)(c)
	if recorder.Code != 200 {
		t.Fatalf("block failed: %d %s", recorder.Code, recorder.Body.String())
	}
	out := decodeBody(t, recorder)
	if out["status"] != "blocked" || out["sessionsEnded"] != float64(1) {
		t.Fatalf("unexpected block response: %v", out)
	}
	var reason sql.NullString
	if err := db.QueryRow(`SELECT ended_reason FROM wallet_session WHERE tenant_id=? AND user_id=?`, tenant, user).Scan(&reason); err != nil || reason.String != "blocked" {
		t.Fatalf("session must be ended with reason blocked: %v %v", reason, err)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='wallet_user_block' AND target_id=?`, tenant, strconv.FormatUint(user, 10)).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("block must write one audit event, got %d (%v)", audits, err)
	}
	c, recorder = testContext(t, tenant, http.MethodPost, "/v1/admin/wallet/users/x/unblock", map[string]any{"reason": "integration test unblock", "confirm": true})
	c.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(user, 10)}}
	s.blockWalletUser(false)(c)
	if recorder.Code != 200 || decodeBody(t, recorder)["status"] != "active" {
		t.Fatalf("unblock failed: %d %s", recorder.Code, recorder.Body.String())
	}
}

// 心跳带 OTA update id：关联得上存修订号，关联不上存 NULL（不猜）；内置包存 embedded
func TestDBHeartbeatResolvesRunningRevision(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	tenant := testTenant(2)
	installation := "inst_" + strings.Repeat("b", 32)
	unknownUpdate, knownUpdate := testUpdateID(), testUpdateID()
	heartbeatInstallation(t, s, tenant, installation, "", installationHeartbeat{LaunchSource: str("ota"), RunningUpdateID: str(unknownUpdate)})
	var source sql.NullString
	var revision sql.NullInt64
	if err := db.QueryRow(`SELECT launch_source,running_ota_revision FROM app_installations WHERE tenant_id=? AND installation_id=?`, tenant, installation).Scan(&source, &revision); err != nil || source.String != "ota" || revision.Valid {
		t.Fatalf("unknown update id must leave revision NULL: %v %v %v", source, revision, err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO ota_releases(id,tenant_id,platform,channel,runtime_version,revision,update_id,base_release_id,status,release_notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "ota_"+uniqueSuffix(), tenant, "android", "production", "1.2.9", 9, knownUpdate, "rel_test", "active", "{}", "tester", now, now); err != nil {
		t.Fatalf("insert ota release: %v", err)
	}
	heartbeatInstallation(t, s, tenant, installation, "", installationHeartbeat{LaunchSource: str("ota"), RunningUpdateID: str(knownUpdate), SessionState: str("signed_out")})
	var state sql.NullString
	if err := db.QueryRow(`SELECT running_ota_revision,client_session_state FROM app_installations WHERE tenant_id=? AND installation_id=?`, tenant, installation).Scan(&revision, &state); err != nil || !revision.Valid || revision.Int64 != 9 || state.String != "signed_out" {
		t.Fatalf("known update id must resolve revision 9 and keep session state: %v %v %v", revision, state, err)
	}
	heartbeatInstallation(t, s, tenant, installation, "", installationHeartbeat{LaunchSource: str("embedded")})
	if err := db.QueryRow(`SELECT launch_source,running_ota_revision FROM app_installations WHERE tenant_id=? AND installation_id=?`, tenant, installation).Scan(&source, &revision); err != nil || source.String != "embedded" || revision.Valid {
		t.Fatalf("embedded launch must clear the running revision: %v %v %v", source, revision, err)
	}
}

// 租户接口：同设备的其他安装实例可见，但设备归并 ID 不出现在响应里；列表带当前账号、活跃度与对账差异
func TestDBTenantViewsHideDeviceGroupIDAndDeriveCurrentAccount(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	tenant := testTenant(3)
	device := strings.Repeat("c", 64)
	primary := "inst_" + strings.Repeat("d", 32)
	sibling := "inst_" + strings.Repeat("e", 32)
	heartbeatInstallation(t, s, tenant, primary, device, installationHeartbeat{LaunchSource: str("embedded"), SessionState: str("signed_out")})
	heartbeatInstallation(t, s, tenant, sibling, device, installationHeartbeat{LaunchSource: str("embedded")})
	user := insertTestUser(t, db, tenant, "0x3333333333333333333333333333333333333333")
	now := time.Now().UTC()
	insertTestSession(t, db, tenant, user, primary, now)
	if _, err := db.Exec(walletUserInstallationUpsertSQL, tenant, user, primary, now, now, "embedded", now, now); err != nil {
		t.Fatalf("login history: %v", err)
	}

	c, recorder := testContext(t, tenant, http.MethodGet, "/v1/admin/installations/"+primary, nil)
	c.Params = gin.Params{{Key: "id", Value: primary}}
	s.installationDetail(c)
	if recorder.Code != 200 {
		t.Fatalf("detail failed: %d %s", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	if strings.Contains(raw, "deviceClientId") || strings.Contains(raw, "device_client_id") {
		t.Fatalf("tenant detail must not expose the device group id: %s", raw)
	}
	detail := decodeBody(t, recorder)
	if detail["installation"].(map[string]any)["hasDeviceGroup"] != true || len(detail["siblings"].([]any)) != 1 {
		t.Fatalf("detail must list the sibling installation without the group id: %v", detail)
	}
	if detail["currentAccount"] == nil || detail["activity"] != "active" || detail["sessionMismatch"] != "server_session_only" {
		t.Fatalf("detail must derive current account, activity and mismatch: current=%v activity=%v mismatch=%v", detail["currentAccount"], detail["activity"], detail["sessionMismatch"])
	}

	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/installations?q="+primary[:13], nil)
	s.listInstallations(c)
	if recorder.Code != 200 {
		t.Fatalf("list failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "deviceClientId") {
		t.Fatal("tenant list must not expose the device group id")
	}
	list := decodeBody(t, recorder)
	items := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected one installation, got %d", len(items))
	}
	item := items[0].(map[string]any)
	if item["currentAccount"].(map[string]any)["address"] != "0x3333333333333333333333333333333333333333" || item["accountsCount"] != float64(1) || item["sessionMismatch"] != "server_session_only" {
		t.Fatalf("list row must carry current account, accounts count and mismatch: %v", item)
	}
}

// 平台级查询：同一地址在两个租户各有账号，同一台设备上的两个安装实例跨租户归并到一组；每次查询写审计（租户 0）
func TestDBPlatformLookupGroupsAcrossTenantsAndAudits(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	tenantA, tenantB := testTenant(4), testTenant(5)
	now := time.Now().UTC()
	for _, tenant := range []string{tenantA, tenantB} {
		if _, err := db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,?,?)`, tenant, "t-"+tenant, now, now); err != nil {
			t.Fatalf("insert tenant %s: %v", tenant, err)
		}
	}
	address := testAddress()
	device := testHex(64)
	for index, tenant := range []string{tenantA, tenantB} {
		installation := "inst_" + strings.Repeat(string(rune('g'+index)), 32)
		heartbeatInstallation(t, s, tenant, installation, device, installationHeartbeat{LaunchSource: str("embedded")})
		user := insertTestUser(t, db, tenant, address)
		insertTestSession(t, db, tenant, user, installation, now)
		if _, err := db.Exec(walletUserInstallationUpsertSQL, tenant, user, installation, now, now, "embedded", now, now); err != nil {
			t.Fatalf("login history: %v", err)
		}
	}
	c, recorder := testContext(t, "", http.MethodGet, "/v1/admin/platform/wallet/lookup?address="+address, nil)
	s.platformWalletLookup(c)
	if recorder.Code != 200 {
		t.Fatalf("lookup failed: %d %s", recorder.Code, recorder.Body.String())
	}
	out := decodeBody(t, recorder)
	if len(out["tenants"].([]any)) != 2 {
		t.Fatalf("expected the address in two tenants: %v", out["tenants"])
	}
	devices := out["devices"].([]any)
	if len(devices) != 1 || len(devices[0].(map[string]any)["installations"].([]any)) != 2 || devices[0].(map[string]any)["deviceClientId"] == nil {
		t.Fatalf("two tenants on one device must merge into one group with the group id: %v", devices)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=0 AND action='platform_wallet_lookup' AND target_id=?`, strings.ToLower(address)).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("platform lookup must write one audit event, got %d (%v)", audits, err)
	}
	c, recorder = testContext(t, "", http.MethodGet, "/v1/admin/platform/wallet/lookup?address=0x4444", nil)
	s.platformWalletLookup(c)
	if recorder.Code != 422 {
		t.Fatalf("partial address must be rejected, got %d", recorder.Code)
	}
}

// 平台级封禁结束该地址在所有租户的会话；解除后不再命中
func TestDBPlatformBlockEndsSessionsInEveryTenant(t *testing.T) {
	db := openTestDB(t)
	s := testServer(db)
	address := fmt.Sprintf("0x5555555555555555555555555555555555%06d", time.Now().UnixNano()%1_000_000)
	for _, tenant := range []string{testTenant(6), testTenant(7)} {
		user := insertTestUser(t, db, tenant, address)
		insertTestSession(t, db, tenant, user, "", time.Now().UTC())
	}
	c, recorder := testContext(t, "", http.MethodPost, "/v1/admin/platform/wallet/blocks", map[string]any{"address": address, "reason": "integration platform block", "confirm": true})
	s.createPlatformWalletBlock(c)
	if recorder.Code != 201 {
		t.Fatalf("platform block failed: %d %s", recorder.Code, recorder.Body.String())
	}
	out := decodeBody(t, recorder)
	if out["sessionsEnded"] != float64(2) {
		t.Fatalf("platform block must end sessions in both tenants: %v", out)
	}
	if code := s.platformWalletBlocked(c, address); code != "WALLET_BLOCKED_PLATFORM" {
		t.Fatalf("blocked address must be rejected at sign-in, got %q", code)
	}
	c, recorder = testContext(t, "", http.MethodPost, "/v1/admin/platform/wallet/blocks/x/revoke", map[string]any{"reason": "integration unblock", "confirm": true})
	c.Params = gin.Params{{Key: "id", Value: strconv.FormatFloat(out["id"].(float64), 'f', 0, 64)}}
	s.revokePlatformWalletBlock(c)
	if recorder.Code != 200 {
		t.Fatalf("platform unblock failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if code := s.platformWalletBlocked(c, address); code != "" {
		t.Fatalf("revoked block must not reject sign-in, got %q", code)
	}
	_ = context.Background()
}
