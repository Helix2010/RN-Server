package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/objectstore"
)

const testMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

// ---- 不需要数据库的部分 ----

func TestSanitizeDiagnosticLogReserialisesInsteadOfStoringClientBytes(t *testing.T) {
	// 客户端的字段顺序、多余字段、对象型字段都不该原样落盘
	input := strings.Join([]string{
		`{"tag":"net","extra":"<script>","level":"error","at":1700000000000,"message":"request failed","fields":{"status":503,"path":"/v1/mobile/bootstrap","body":{"token":"tok_live"}}}`,
		`{"at":1700000000001,"level":"info","tag":"nav","message":"route","fields":{"name":"Settings"}}`,
	}, "\n")
	out, stats, err := sanitizeDiagnosticLog(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"at":1700000000000,"level":"error","tag":"net","message":"request failed","fields":{"path":"/v1/mobile/bootstrap","status":503}}` + "\n" +
		`{"at":1700000000001,"level":"info","tag":"nav","message":"route","fields":{"name":"Settings"}}` + "\n"
	if string(out) != want {
		t.Fatalf("canonical output\n got  %s\n want %s", out, want)
	}
	if stats.entries != 2 || stats.dropped != 0 {
		t.Fatalf("stats: %+v", stats)
	}
	if bytes.Contains(out, []byte("tok_live")) || bytes.Contains(out, []byte("<script>")) {
		t.Fatal("unknown fields and object-valued fields must not reach storage")
	}
}

func TestSanitizeDiagnosticLogDropsLinesThatBreakTheShape(t *testing.T) {
	lines := []string{
		`not json`,
		`{"at":1,"level":"debug","tag":"net","message":"unknown level"}`,
		`{"at":1,"level":"info","tag":"payments","message":"unknown tag"}`,
		`{"at":0,"level":"info","tag":"net","message":"no timestamp"}`,
		`{"at":1,"level":"info","tag":"net","message":"kept"}`,
		``,
	}
	out, stats, err := sanitizeDiagnosticLog(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if stats.entries != 1 || stats.dropped != 4 {
		t.Fatalf("expected 1 kept and 4 dropped (blank lines are not counted), got %+v", stats)
	}
	if !strings.Contains(string(out), `"kept"`) {
		t.Fatalf("the valid line must survive: %s", out)
	}
}

// bufio.Scanner 遇到超长行会中止整个扫描；这里要求只丢那一行，后面的照收
func TestSanitizeDiagnosticLogSkipsAnOverlongLineAndKeepsReading(t *testing.T) {
	long := `{"at":1,"level":"info","tag":"net","message":"` + strings.Repeat("x", diagnosticLineMaxBytes*2) + `"}`
	after := `{"at":2,"level":"info","tag":"net","message":"after"}`
	out, stats, err := sanitizeDiagnosticLog(strings.NewReader(long + "\n" + after))
	if err != nil {
		t.Fatal(err)
	}
	if stats.entries != 1 || stats.dropped != 1 || !strings.Contains(string(out), `"after"`) {
		t.Fatalf("overlong line must be dropped alone: %+v %s", stats, out)
	}
	// 超长行恰好是最后一行、没有换行符
	_, stats, err = sanitizeDiagnosticLog(strings.NewReader(after + "\n" + long))
	if err != nil || stats.entries != 1 || stats.dropped != 1 {
		t.Fatalf("trailing overlong line: %+v %v", stats, err)
	}
}

func TestSanitizeDiagnosticLogCapsLineCount(t *testing.T) {
	var input strings.Builder
	for i := 0; i < diagnosticMaxLines+7; i++ {
		fmt.Fprintf(&input, `{"at":%d,"level":"info","tag":"nav","message":"route"}`+"\n", i+1)
	}
	_, stats, err := sanitizeDiagnosticLog(strings.NewReader(input.String()))
	if err != nil || stats.entries != diagnosticMaxLines || stats.dropped != 7 {
		t.Fatalf("expected %d kept and 7 dropped, got %+v %v", diagnosticMaxLines, stats, err)
	}
}

func TestSanitizeDiagnosticLogRedactsAndCountsWhatTheClientMissed(t *testing.T) {
	input := strings.Join([]string{
		`{"at":1,"level":"error","tag":"wallet","message":"import failed: ` + testMnemonic + `"}`,
		`{"at":2,"level":"error","tag":"wallet","message":"failed","fields":{"input":"` + testMnemonic + `"}}`,
		`{"at":3,"level":"info","tag":"nav","message":"clean"}`,
	}, "\n")
	out, stats, err := sanitizeDiagnosticLog(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "sausage") {
		t.Fatalf("mnemonic reached storage: %s", out)
	}
	if stats.redactionHits != 2 {
		t.Fatalf("both leaking lines must be counted, got %+v", stats)
	}
}

func TestSanitizeDiagnosticLogTruncatesByCharacterNotByte(t *testing.T) {
	message := strings.Repeat("诊", diagnosticMessageMaxRunes+10)
	input := `{"at":1,"level":"info","tag":"net","message":"` + message + `"}`
	out, _, err := sanitizeDiagnosticLog(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	var line diagnosticLogLine
	if err := json.Unmarshal(bytes.TrimSpace(out), &line); err != nil {
		t.Fatal(err)
	}
	if got := len([]rune(line.Message)); got != diagnosticMessageMaxRunes {
		t.Fatalf("message must be clipped to %d characters, got %d", diagnosticMessageMaxRunes, got)
	}
}

func TestReadDiagnosticLineReportsOverlongWithoutLosingTheNext(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 100)+"\nok\n"), 32)
	line, tooLong, err := readDiagnosticLine(reader)
	if line != nil || !tooLong || err != nil {
		t.Fatalf("first: %q %v %v", line, tooLong, err)
	}
	line, tooLong, err = readDiagnosticLine(reader)
	if string(line) != "ok" || tooLong || err != nil {
		t.Fatalf("second: %q %v %v", line, tooLong, err)
	}
}

func TestDiagnosticIPLimiterWindow(t *testing.T) {
	var limiter diagnosticIPLimiter // 零值可用
	now := time.Now()
	for i := 0; i < diagnosticIPPerHour; i++ {
		if !limiter.allow("198.51.100.7", now) {
			t.Fatalf("request %d must be allowed", i+1)
		}
	}
	if limiter.allow("198.51.100.7", now) {
		t.Fatal("request over the hourly limit must be refused")
	}
	if !limiter.allow("198.51.100.8", now) {
		t.Fatal("another source must not share the window")
	}
	if !limiter.allow("198.51.100.7", now.Add(time.Hour+time.Second)) {
		t.Fatal("the window must reset after an hour")
	}
}

func TestDiagnosticObjectKeyStaysInsideTheTenant(t *testing.T) {
	created := time.Date(2026, 9, 14, 8, 0, 0, 0, time.UTC)
	key := diagnosticObjectKey("rn-prod", "42", "R7KQ3M2X", created)
	if key != "rn-prod/tenants/42/diagnostics/2026/09/14/R7KQ3M2X.ndjson.gz" {
		t.Fatalf("unexpected key %q", key)
	}
	if !diagnosticObjectBelongsTo(key, "rn-prod", "42") {
		t.Fatal("own key must pass")
	}
	for _, other := range []string{
		diagnosticObjectKey("rn-prod", "43", "R7KQ3M2X", created),
		"rn-prod/tenants/42/releases/rel_1/application.apk",
		"rn-prod/tenants/42/diagnostics/../../43/diagnostics/x.ndjson.gz",
	} {
		if diagnosticObjectBelongsTo(other, "rn-prod", "42") {
			t.Fatalf("foreign key must be refused: %s", other)
		}
	}
	if got := diagnosticObjectKey("", "42", "R7KQ3M2X", created); got != "tenants/42/diagnostics/2026/09/14/R7KQ3M2X.ndjson.gz" {
		t.Fatalf("key without a storage prefix: %q", got)
	}
}

func TestDiagnosticReferenceIsReadableAloud(t *testing.T) {
	for i := 0; i < 500; i++ {
		reference := newDiagnosticReference()
		if len(reference) != 8 || strings.ContainsAny(reference, "ILOU") {
			t.Fatalf("reference %q must be 8 characters without I, L, O or U", reference)
		}
	}
}

func TestDiagnosticReportRequestValidation(t *testing.T) {
	valid := func() diagnosticReportRequest {
		var r diagnosticReportRequest
		r.ReportID, r.Kind, r.OccurredAt = "rpt_0123456789abcdef", "user", "2026-09-14T08:00:00.000Z"
		r.App.Version, r.App.BuildNumber, r.App.RuntimeVersion, r.App.OTAChannel, r.App.DistributionChannel = "1.2.3", "45", "1.2.0", "production", "direct"
		return r
	}
	crash := func(r *diagnosticReportRequest, kind string) {
		r.Kind = kind
		r.Crash = &struct {
			Fingerprint string `json:"fingerprint"`
			ErrorName   string `json:"errorName"`
		}{Fingerprint: "a1b2c3d4e5f60718", ErrorName: "TypeError"}
	}
	cases := []struct {
		name   string
		mutate func(*diagnosticReportRequest)
		ok     bool
	}{
		{"valid user report", func(*diagnosticReportRequest) {}, true},
		{"valid automatic crash", func(r *diagnosticReportRequest) { crash(r, "crash_auto") }, true},
		{"short report id", func(r *diagnosticReportRequest) { r.ReportID = "short" }, false},
		{"unknown kind", func(r *diagnosticReportRequest) { r.Kind = "feedback" }, false},
		{"bad timestamp", func(r *diagnosticReportRequest) { r.OccurredAt = "yesterday" }, false},
		{"crash without crash block", func(r *diagnosticReportRequest) { r.Kind = "crash" }, false},
		{"user report with crash block", func(r *diagnosticReportRequest) { crash(r, "crash"); r.Kind = "user" }, false},
		{"fingerprint not hex", func(r *diagnosticReportRequest) { crash(r, "crash"); r.Crash.Fingerprint = "not-a-fingerprint" }, false},
		{"error name with spaces", func(r *diagnosticReportRequest) { crash(r, "crash"); r.Crash.ErrorName = "leak 0xabc" }, false},
		{"automatic crash with a note", func(r *diagnosticReportRequest) { crash(r, "crash_auto"); r.Note = "hello" }, false},
		{"missing version", func(r *diagnosticReportRequest) { r.App.Version = "" }, false},
		{"embedded launch with update id", func(r *diagnosticReportRequest) {
			r.App.LaunchSource, r.App.RunningUpdateID = str("embedded"), str("7c5c1363-8685-42b2-864e-38b6790471ca")
		}, false},
	}
	for _, tc := range cases {
		r := valid()
		tc.mutate(&r)
		if detail := r.validate(); (detail == "") != tc.ok {
			t.Errorf("%s: ok=%v detail=%q", tc.name, tc.ok, detail)
		}
	}
	long := valid()
	long.Note = strings.Repeat("问", diagnosticNoteMaxRunes+20)
	if detail := long.validate(); detail != "" || len([]rune(long.Note)) != diagnosticNoteMaxRunes {
		t.Fatalf("long note must be clipped, not rejected: %q %d", detail, len([]rune(long.Note)))
	}
}

// ---- 数据库集成 ----

type failingObjectFactory struct{}

func (failingObjectFactory) New(objectstore.Config) (objectstore.Client, error) {
	return nil, errors.New("storage is not configured")
}

type diagnosticDevice struct {
	installationID, credential string
}

func diagnosticServer(t *testing.T, db *sql.DB, tenant string, store *fakeObjectStore) *server {
	t.Helper()
	s := testServer(db)
	s.cfg.Environment = "test"
	s.objects = fixedObjectFactory{client: store}
	value, _ := json.Marshal(storedReleaseStorage{Provider: "s3", Region: "us-east-1", Bucket: "rn-test"})
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',?) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`, tenant, releaseStorageConfigKey, value, time.Now().UTC()); err != nil {
		t.Fatalf("seed release storage config: %v", err)
	}
	return s
}

// registerDiagnosticDevice 写一条带已知凭证的安装实例，并让它"心跳过"。
func registerDiagnosticDevice(t *testing.T, s *server, tenant string, heartbeated bool) diagnosticDevice {
	t.Helper()
	credential, hash, err := newInstallationCredential()
	if err != nil {
		t.Fatal(err)
	}
	device := diagnosticDevice{installationID: "inst_" + testHex(24), credential: credential}
	body := installationHeartbeat{InstallationID: device.installationID, DeviceSourceHash: testHex(64), PackageID: "com.example.app", OTAChannel: "production", Locale: "zh-CN", Theme: "system", OSVersion: "35", DeviceClass: "android-phone"}
	c, _ := testContext(t, tenant, http.MethodPost, "/v1/mobile/installations/register", nil)
	for key, value := range map[string]string{"x-platform": "android", "x-application-id": "dex-mobile", "x-app-version": "1.2.3", "x-build-number": "45", "x-runtime-version": "1.2.0", "x-distribution-channel": "direct"} {
		c.Request.Header.Set(key, value)
	}
	if err := s.saveInstallation(c, body, hash, 1, time.Now().Add(24*time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("save installation: %v", err)
	}
	if heartbeated {
		if _, err := s.db.Exec(`UPDATE app_installations SET first_seen_at=first_seen_at - INTERVAL 1 HOUR WHERE tenant_id=? AND installation_id=?`, tenant, device.installationID); err != nil {
			t.Fatal(err)
		}
	}
	return device
}

func diagnosticRequest(t *testing.T, tenant string, device diagnosticDevice, method, target string, body io.Reader) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, target, body)
	c.Request.Header.Set("content-type", "application/json")
	c.Request.Header.Set("x-platform", "android")
	c.Request.Header.Set("x-application-id", "dex-mobile")
	c.Request.Header.Set("X-Installation-ID", device.installationID)
	c.Request.Header.Set("Authorization", "Installation "+device.credential)
	c.Set("tenantId", tenant)
	c.Set("requestId", "req_test")
	return c, recorder
}

func reportPayload(reportID, kind string, extra map[string]any) map[string]any {
	payload := map[string]any{
		"reportId": reportID, "kind": kind, "occurredAt": "2026-09-14T08:00:00.000Z",
		"app": map[string]any{"version": "1.2.3", "buildNumber": "45", "runtimeVersion": "1.2.0", "otaChannel": "production", "distributionChannel": "direct", "locale": "zh-CN"},
	}
	if kind != "user" {
		payload["crash"] = map[string]any{"fingerprint": "a1b2c3d4e5f60718", "errorName": "TypeError"}
	}
	for key, value := range extra {
		payload[key] = value
	}
	return payload
}

func postReport(t *testing.T, s *server, tenant string, device diagnosticDevice, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(payload)
	c, recorder := diagnosticRequest(t, tenant, device, http.MethodPost, "/v1/mobile/diagnostics/reports", bytes.NewReader(raw))
	s.createDiagnosticReport(c)
	return recorder
}

func putLog(t *testing.T, s *server, tenant string, device diagnosticDevice, reportID, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	c, recorder := diagnosticRequest(t, tenant, device, http.MethodPut, "/v1/mobile/diagnostics/reports/"+reportID+"/log", strings.NewReader(body))
	c.Request.Header.Set("content-type", "application/x-ndjson")
	for key, value := range headers {
		c.Request.Header.Set(key, value)
	}
	c.Params = gin.Params{{Key: "reportId", Value: reportID}}
	s.uploadDiagnosticLog(c)
	return recorder
}

func newReportID() string { return "rpt_" + testHex(24) }

func TestDBDiagnosticReportEndToEnd(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(80)
	store := newFakeObjectStore()
	s := diagnosticServer(t, db, tenant, store)
	device := registerDiagnosticDevice(t, s, tenant, true)

	// 身份由会话解析：这台设备上登录着一个钱包用户
	userID := insertTestUser(t, db, tenant, testAddress())
	insertTestSession(t, db, tenant, userID, device.installationID, time.Now().UTC())
	updateID := testUpdateID()
	insertPurgeRelease(t, db, tenant, scoped(tenant, "rel_diag"), "1.2.3", 45, "completed", "1.2.0", "tenants/"+tenant+"/releases/x/application.apk")
	insertPurgeOTA(t, db, tenant, scoped(tenant, "ota_diag"), scoped(tenant, "rel_diag"), "1.2.0", "active", "tenants/"+tenant+"/ota/m.json", 12)
	if _, err := db.Exec(`UPDATE ota_releases SET update_id=? WHERE tenant_id=? AND id=?`, updateID, tenant, scoped(tenant, "ota_diag")); err != nil {
		t.Fatal(err)
	}

	reportID := newReportID()
	app := reportPayload(reportID, "user", nil)["app"].(map[string]any)
	app["launchSource"], app["runningUpdateId"] = "ota", updateID
	recorder := postReport(t, s, tenant, device, reportPayload(reportID, "user", map[string]any{"note": "转账一直转圈", "app": app, "context": map[string]any{"screen": "Transfer"}}))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", recorder.Code, recorder.Body.String())
	}
	created := decodeBody(t, recorder)
	reference, _ := created["reference"].(string)
	if len(reference) != 8 || object(created["logUpload"])["required"] != true {
		t.Fatalf("unexpected creation response: %v", created)
	}

	var gotUser sql.NullInt64
	var gotRevision sql.NullInt64
	var status string
	if err := db.QueryRow(`SELECT wallet_user_id,running_ota_revision,log_status FROM app_diagnostic_reports WHERE tenant_id=? AND reference=?`, tenant, reference).Scan(&gotUser, &gotRevision, &status); err != nil {
		t.Fatal(err)
	}
	if !gotUser.Valid || uint64(gotUser.Int64) != userID {
		t.Fatalf("wallet user must be resolved from the session, got %v", gotUser)
	}
	if !gotRevision.Valid || gotRevision.Int64 != 12 {
		t.Fatalf("running OTA revision must be resolved at write time, got %v", gotRevision)
	}
	if status != "awaiting" {
		t.Fatalf("log status %q", status)
	}

	// 重试同一个 reportId：同一个参考号，不新建
	replay := postReport(t, s, tenant, device, reportPayload(reportID, "user", nil))
	if replay.Code != http.StatusOK || decodeBody(t, replay)["reference"] != reference {
		t.Fatalf("replay must return the same reference: %d %s", replay.Code, replay.Body.String())
	}

	log := strings.Join([]string{
		`{"at":1700000000000,"level":"error","tag":"net","message":"request failed","fields":{"status":503}}`,
		`{"at":1700000000001,"level":"error","tag":"wallet","message":"import failed: ` + testMnemonic + `"}`,
	}, "\n")
	if gzipped := putLog(t, s, tenant, device, reportID, log, map[string]string{"Content-Encoding": "gzip"}); gzipped.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("compressed uploads must be refused, got %d", gzipped.Code)
	}
	upload := putLog(t, s, tenant, device, reportID, log, nil)
	if upload.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", upload.Code, upload.Body.String())
	}
	if strings.Contains(upload.Body.String(), "redaction") {
		t.Fatal("the client must not learn whether it tripped server-side redaction")
	}

	var key string
	var entries, hits int
	var size int64
	if err := db.QueryRow(`SELECT object_key,entry_count,redaction_hits,byte_size,log_status FROM app_diagnostic_reports WHERE tenant_id=? AND reference=?`, tenant, reference).Scan(&key, &entries, &hits, &size, &status); err != nil {
		t.Fatal(err)
	}
	if status != "stored" || entries != 2 || hits != 1 || !diagnosticObjectBelongsTo(key, "", tenant) {
		t.Fatalf("stored row: status=%s entries=%d hits=%d key=%s", status, entries, hits, key)
	}
	object, ok := store.objects[key]
	if !ok || int64(len(object.body)) != size {
		t.Fatalf("object must be stored under the recorded key with the recorded size")
	}
	reader, err := gzip.NewReader(bytes.NewReader(object.body))
	if err != nil {
		t.Fatalf("stored object must be gzip: %v", err)
	}
	stored, _ := io.ReadAll(reader)
	if strings.Contains(string(stored), "sausage") || !strings.Contains(string(stored), redactedSecret) {
		t.Fatalf("stored log must be redacted: %s", stored)
	}

	// 已经有日志了，不能再传一份覆盖
	if again := putLog(t, s, tenant, device, reportID, log, nil); again.Code != http.StatusConflict {
		t.Fatalf("second upload must conflict, got %d", again.Code)
	}
}

func TestDBDiagnosticReportRejectsIdentityInTheBody(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(81)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)
	for _, field := range []string{"tenantId", "userId", "walletAddress", "installationId"} {
		recorder := postReport(t, s, tenant, device, reportPayload(newReportID(), "user", map[string]any{field: "forged"}))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("a body carrying %s must be refused, got %d", field, recorder.Code)
		}
	}
}

func TestDBDiagnosticReportRequiresAHeartbeatedLiveInstallation(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(82)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())

	fresh := registerDiagnosticDevice(t, s, tenant, false)
	if recorder := postReport(t, s, tenant, fresh, reportPayload(newReportID(), "user", nil)); recorder.Code != http.StatusForbidden {
		t.Fatalf("an installation that never heartbeated must be refused, got %d", recorder.Code)
	}

	device := registerDiagnosticDevice(t, s, tenant, true)
	wrong := device
	wrong.credential = "not-the-credential"
	if recorder := postReport(t, s, tenant, wrong, reportPayload(newReportID(), "user", nil)); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong credential must be refused, got %d", recorder.Code)
	}
	if _, err := db.Exec(`UPDATE app_installations SET status='revoked',credential_revoked_at=? WHERE tenant_id=? AND installation_id=?`, time.Now().UTC(), tenant, device.installationID); err != nil {
		t.Fatal(err)
	}
	if recorder := postReport(t, s, tenant, device, reportPayload(newReportID(), "user", nil)); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked installation must be refused, got %d", recorder.Code)
	}
}

func TestDBDiagnosticQuotasCountManualAndAutomaticSeparately(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(83)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	expect := func(device diagnosticDevice, kind string, count, status int) {
		t.Helper()
		for i := 0; i < count; i++ {
			if recorder := postReport(t, s, tenant, device, reportPayload(newReportID(), kind, nil)); recorder.Code != status {
				t.Fatalf("%s report %d: expected %d, got %d %s", kind, i+1, status, recorder.Code, recorder.Body.String())
			}
		}
	}

	// 两个方向都要验：只验一个方向的话，"两类合并计数"这种改坏法照样绿（变异测试抓出来过）
	manualFirst := registerDiagnosticDevice(t, s, tenant, true)
	expect(manualFirst, "user", diagnosticManualPerHour, http.StatusCreated)
	expect(manualFirst, "crash", 1, http.StatusTooManyRequests) // user 与 crash 共用手动额度
	expect(manualFirst, "crash_auto", diagnosticAutoPerDay, http.StatusCreated)
	expect(manualFirst, "crash_auto", 1, http.StatusTooManyRequests)

	autoFirst := registerDiagnosticDevice(t, s, tenant, true)
	expect(autoFirst, "crash_auto", diagnosticAutoPerDay, http.StatusCreated)
	expect(autoFirst, "user", diagnosticManualPerHour, http.StatusCreated) // 自动上报不占手动额度
	expect(autoFirst, "user", 1, http.StatusTooManyRequests)
}

func TestDBDiagnosticLogCannotBeUploadedForAnotherInstallation(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(84)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	owner := registerDiagnosticDevice(t, s, tenant, true)
	intruder := registerDiagnosticDevice(t, s, tenant, true)
	reportID := newReportID()
	if recorder := postReport(t, s, tenant, owner, reportPayload(reportID, "user", nil)); recorder.Code != http.StatusCreated {
		t.Fatalf("create: %d", recorder.Code)
	}
	body := `{"at":1,"level":"info","tag":"nav","message":"route"}`
	if recorder := putLog(t, s, tenant, intruder, reportID, body, nil); recorder.Code != http.StatusNotFound {
		t.Fatalf("another installation's report must look nonexistent, got %d", recorder.Code)
	}
}

func TestDBDiagnosticReportWithoutStorageStillGetsAReference(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(85)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)
	s.objects = failingObjectFactory{}

	reportID := newReportID()
	recorder := postReport(t, s, tenant, device, reportPayload(reportID, "user", nil))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", recorder.Code, recorder.Body.String())
	}
	created := decodeBody(t, recorder)
	if created["reference"] == "" || object(created["logUpload"])["required"] != false {
		t.Fatalf("no storage: still a reference, but no log upload: %v", created)
	}
	if again := putLog(t, s, tenant, device, reportID, `{"at":1,"level":"info","tag":"nav","message":"x"}`, nil); again.Code != http.StatusConflict {
		t.Fatalf("a report without storage is not waiting for a log, got %d", again.Code)
	}
}

func TestDBDiagnosticReportsCanBeSwitchedOffPerTenant(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(86)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)

	var raw []byte
	if err := db.QueryRow(`SELECT config_value FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id=0`).Scan(&raw); err != nil {
		t.Fatalf("platform config: %v", err)
	}
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	features := object(value["features"])
	features["diagnosticsEnabled"] = false
	value["features"] = features
	disabled, _ := json.Marshal(value)
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?, 'mobile-bootstrap', ?, 1, 'tester', ?)`, tenant, disabled, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if recorder := postReport(t, s, tenant, device, reportPayload(newReportID(), "user", nil)); recorder.Code != http.StatusNotFound {
		t.Fatalf("switched off must look like the endpoint does not exist, got %d", recorder.Code)
	}
}

// ---- 管理端 ----

// createStoredReport 走真实的两步接口造一条带日志的报告，返回库里的 id。
func createStoredReport(t *testing.T, s *server, tenant string, device diagnosticDevice, log string) (string, string) {
	t.Helper()
	reportID := newReportID()
	recorder := postReport(t, s, tenant, device, reportPayload(reportID, "user", nil))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", recorder.Code, recorder.Body.String())
	}
	reference := decodeBody(t, recorder)["reference"].(string)
	if upload := putLog(t, s, tenant, device, reportID, log, nil); upload.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", upload.Code, upload.Body.String())
	}
	var id uint64
	if err := s.db.QueryRow(`SELECT id FROM app_diagnostic_reports WHERE tenant_id=? AND reference=?`, tenant, reference).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(id), reference
}

func insertBareReport(t *testing.T, db *sql.DB, tenant, installationID, kind, logStatus string, created time.Time) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO app_diagnostic_reports(tenant_id,reference,report_id,installation_id,kind,platform,app_version,build_number,runtime_version,distribution_channel,ota_channel,log_status,occurred_at,created_at,updated_at) VALUES(?,?,?,?,?,'android','1.2.3','45','1.2.0','direct','production',?,?,?,?)`,
		tenant, newDiagnosticReference(), newReportID(), installationID, kind, logStatus, created, created, created)
	if err != nil {
		t.Fatalf("insert report: %v", err)
	}
}

func TestDBAdminDiagnosticListPaginatesAndResolvesAccounts(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(90)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)
	address := testAddress()
	insertTestSession(t, db, tenant, insertTestUser(t, db, tenant, address), device.installationID, time.Now().UTC())

	base := time.Now().UTC().Add(-2 * time.Hour)
	for i := 0; i < 5; i++ {
		insertBareReport(t, db, tenant, device.installationID, "user", "stored", base.Add(time.Duration(i)*time.Minute))
	}
	// 一条"元数据收到了、日志一直没来"的：读取时应显示成 missing，库里仍是 awaiting
	insertBareReport(t, db, tenant, device.installationID, "crash", "awaiting", base.Add(10*time.Minute))
	_, reference := createStoredReport(t, s, tenant, device, `{"at":1,"level":"info","tag":"nav","message":"route"}`)

	seen := map[string]bool{}
	cursor, pages := "", 0
	for {
		target := "/v1/admin/diagnostics/reports?limit=3"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		c, recorder := testContext(t, tenant, http.MethodGet, target, nil)
		s.listDiagnosticReports(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("list: %d %s", recorder.Code, recorder.Body.String())
		}
		page := decodeBody(t, recorder)
		items := page["items"].([]any)
		pages++
		for _, item := range items {
			seen[object(item)["id"].(string)] = true
		}
		if page["hasMore"] != true {
			if page["nextCursor"] != nil {
				t.Fatal("last page must not carry a cursor")
			}
			break
		}
		cursor = page["nextCursor"].(string)
		if pages > 5 {
			t.Fatal("pagination does not terminate")
		}
	}
	if len(seen) != 7 || pages != 3 {
		t.Fatalf("expected 7 reports over 3 pages, got %d over %d", len(seen), pages)
	}

	c, recorder := testContext(t, tenant, http.MethodGet, "/v1/admin/diagnostics/reports?q="+strings.ToLower(address), nil)
	s.listDiagnosticReports(c)
	byAddress := decodeBody(t, recorder)["items"].([]any)
	if len(byAddress) != 1 || object(object(byAddress[0])["wallet"])["address"] != address {
		t.Fatalf("search by address must find the report and show the joined address: %v", byAddress)
	}
	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/diagnostics/reports?q="+strings.ToLower(reference), nil)
	s.listDiagnosticReports(c)
	if items := decodeBody(t, recorder)["items"].([]any); len(items) != 1 {
		t.Fatalf("a reference read out in lower case must still match, got %d", len(items))
	}
	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/diagnostics/reports?logStatus=missing", nil)
	s.listDiagnosticReports(c)
	missing := decodeBody(t, recorder)["items"].([]any)
	if len(missing) != 1 || object(object(missing[0])["log"])["status"] != "missing" {
		t.Fatalf("an old awaiting report must be shown as missing: %v", missing)
	}
}

func TestDBAdminDiagnosticLogViewerAndRawDownload(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(91)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)
	log := strings.Join([]string{
		`{"at":1,"level":"info","tag":"nav","message":"route","fields":{"name":"Transfer"}}`,
		`{"at":2,"level":"error","tag":"net","message":"request failed","fields":{"status":503}}`,
		`{"at":3,"level":"error","tag":"wallet","message":"<img src=x onerror=alert(1)>"}`,
	}, "\n")
	id, reference := createStoredReport(t, s, tenant, device, log)
	params := gin.Params{{Key: "id", Value: id}}

	c, recorder := testContext(t, tenant, http.MethodGet, "/v1/admin/diagnostics/reports/"+id+"/log?level=error&limit=1&offset=1", nil)
	c.Params = params
	s.diagnosticReportLog(c)
	page := decodeBody(t, recorder)
	items := page["items"].([]any)
	if recorder.Code != http.StatusOK || page["total"] != float64(2) || len(items) != 1 || object(items[0])["tag"] != "wallet" {
		t.Fatalf("filtered page: %d %v", recorder.Code, page)
	}

	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/diagnostics/reports/"+id+"/log/raw", nil)
	c.Params = params
	s.diagnosticReportRawLog(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("raw: %d", recorder.Code)
	}
	for header, want := range map[string]string{
		"Content-Type":           "text/plain; charset=utf-8",
		"Content-Disposition":    `attachment; filename="` + reference + `.ndjson"`,
		"X-Content-Type-Options": "nosniff",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Fatalf("%s: got %q want %q", header, got, want)
		}
	}
	if strings.Contains(recorder.Body.String(), "<img") {
		t.Fatal("the stored file must not contain raw HTML (json.Marshal escapes it)")
	}

	// 另一个租户看不到，也读不到日志
	other := testTenant(92)
	c, recorder = testContext(t, other, http.MethodGet, "/v1/admin/diagnostics/reports/"+id+"/log", nil)
	c.Params = params
	s.diagnosticReportLog(c)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("another tenant must get 404, got %d", recorder.Code)
	}
}

func TestDBAdminDiagnosticStatusIsAudited(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(93)
	s := diagnosticServer(t, db, tenant, newFakeObjectStore())
	device := registerDiagnosticDevice(t, s, tenant, true)
	id, _ := createStoredReport(t, s, tenant, device, `{"at":1,"level":"info","tag":"nav","message":"route"}`)

	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/diagnostics/reports/"+id+"/status", map[string]any{"status": "triaged", "note": "已联系用户"})
	c.Params = gin.Params{{Key: "id", Value: id}}
	s.updateDiagnosticReportStatus(c)
	if recorder.Code != http.StatusOK || object(decodeBody(t, recorder)["report"])["status"] != "triaged" {
		t.Fatalf("status: %d %s", recorder.Code, recorder.Body.String())
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='diagnostic_report_status' AND target_id=?`, tenant, id).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("status change must be audited, got %d (%v)", audits, err)
	}
}

func TestDBAdminDiagnosticDeleteRemovesObjectRowAndAudits(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(94)
	store := newFakeObjectStore()
	s := diagnosticServer(t, db, tenant, store)
	device := registerDiagnosticDevice(t, s, tenant, true)
	id, _ := createStoredReport(t, s, tenant, device, `{"at":1,"level":"info","tag":"nav","message":"route"}`)
	var key string
	if err := db.QueryRow(`SELECT object_key FROM app_diagnostic_reports WHERE id=?`, id).Scan(&key); err != nil {
		t.Fatal(err)
	}

	c, recorder := testContext(t, tenant, http.MethodDelete, "/v1/admin/diagnostics/reports/"+id, map[string]any{"reason": "contains user data"})
	c.Params = gin.Params{{Key: "id", Value: id}}
	s.deleteDiagnosticReports(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("delete without confirm must be refused, got %d", recorder.Code)
	}

	c, recorder = testContext(t, tenant, http.MethodDelete, "/v1/admin/diagnostics/reports/"+id, map[string]any{"reason": "contains user data", "confirm": true})
	c.Params = gin.Params{{Key: "id", Value: id}}
	s.deleteDiagnosticReports(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.objects[key]; ok {
		t.Fatal("the stored log must be deleted with the report")
	}
	var rows, audits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM app_diagnostic_reports WHERE tenant_id=? AND id=?`, tenant, id).Scan(&rows)
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='diagnostic_report_delete' AND target_id=?`, tenant, id).Scan(&audits)
	if rows != 0 || audits != 1 {
		t.Fatalf("row must be gone and the delete audited: rows=%d audits=%d", rows, audits)
	}
}

// 对象删不掉的那条必须保留行：先删行的话，那份日志就再也没人找得到，而它不会过期
func TestDBAdminDiagnosticBulkDeleteKeepsRowsWhoseObjectSurvives(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(95)
	store := newFakeObjectStore()
	s := diagnosticServer(t, db, tenant, store)
	device := registerDiagnosticDevice(t, s, tenant, true)
	first, _ := createStoredReport(t, s, tenant, device, `{"at":1,"level":"info","tag":"nav","message":"a"}`)
	second, _ := createStoredReport(t, s, tenant, device, `{"at":1,"level":"info","tag":"nav","message":"b"}`)
	var secondKey string
	_ = db.QueryRow(`SELECT object_key FROM app_diagnostic_reports WHERE id=?`, second).Scan(&secondKey)
	// 把第二条的键改到租户前缀之外：删除必须拒绝碰它
	if _, err := db.Exec(`UPDATE app_diagnostic_reports SET object_key=? WHERE id=?`, "tenants/other/diagnostics/x.ndjson.gz", second); err != nil {
		t.Fatal(err)
	}

	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/diagnostics/reports/bulk-delete", map[string]any{"ids": []string{first, second}, "reason": "cleanup", "confirm": true})
	s.deleteDiagnosticReports(c)
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("partial delete must be 207, got %d %s", recorder.Code, recorder.Body.String())
	}
	result := decodeBody(t, recorder)
	if failed := result["failed"].([]any); len(failed) != 1 || failed[0] != second {
		t.Fatalf("the report whose object could not be removed must be reported: %v", result)
	}
	var remaining int
	_ = db.QueryRow(`SELECT COUNT(*) FROM app_diagnostic_reports WHERE tenant_id=? AND id IN (?,?)`, tenant, first, second).Scan(&remaining)
	if remaining != 1 {
		t.Fatalf("only the deletable report may go, %d remain", remaining)
	}

	c, recorder = testContext(t, tenant, http.MethodPost, "/v1/admin/diagnostics/reports/bulk-delete", map[string]any{"ids": []string{}, "reason": "cleanup", "confirm": true})
	s.deleteDiagnosticReports(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("an empty id list must be refused, got %d", recorder.Code)
	}
}

func TestBootstrapFeaturesCarryCrashAutoReportClosedByDefault(t *testing.T) {
	stored := map[string]any{"updateCenter": true, "otaEnabled": true, "diagnosticsEnabled": true}
	features := bootstrapFeatures(stored, true)
	if value, ok := features["crashAutoReport"]; !ok || value != false {
		t.Fatalf("crashAutoReport must always be delivered and default to false, got %v (%v)", value, ok)
	}
	stored["crashAutoReport"] = true
	if bootstrapFeatures(stored, true)["crashAutoReport"] != true {
		t.Fatal("an explicitly enabled tenant must get true")
	}
	stored["crashAutoReport"] = "yes"
	if bootstrapFeatures(stored, true)["crashAutoReport"] != false {
		t.Fatal("anything but a JSON true must be delivered as false")
	}
}

// 迁移 v46 给每份 mobile-bootstrap 补上了显式的 false；管理端的功能开关区按键渲染，缺键就看不见
func TestDBMigrationMadeCrashAutoReportExplicit(t *testing.T) {
	db := openTestDB(t)
	var missing int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_configs WHERE config_key='mobile-bootstrap' AND JSON_EXTRACT(config_value,'$.features') IS NOT NULL AND JSON_EXTRACT(config_value,'$.features.crashAutoReport') IS NULL`).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing != 0 {
		t.Fatalf("%d bootstrap configs still lack features.crashAutoReport", missing)
	}
	var initial map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &initial); err != nil {
		t.Fatal(err)
	}
	if value, ok := object(initial["features"])["crashAutoReport"]; !ok || value != false {
		t.Fatalf("a fresh platform config must carry crashAutoReport=false, got %v", value)
	}
}
