package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// 全托管构建传进 App Store Connect 之后，回收循环用租户的 ASC 密钥**只读**地查处理状态
// （ios_testflight_poll.go）。需要真实 MySQL（RN_TEST_MYSQL_DSN）。

// fakeTestFlight 是一个只认 GET /v1/apps 与 GET /v1/builds 的假 App Store Connect。
type fakeTestFlight struct {
	mu       sync.Mutex
	builds   []map[string]any
	status   int
	requests []string
	methods  map[string]bool
}

func newFakeTestFlight(t *testing.T) (*fakeTestFlight, *httptest.Server) {
	fake := &fakeTestFlight{methods: map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.requests = append(fake.requests, r.URL.Path)
		fake.methods[r.Method] = true
		if fake.status != 0 {
			w.WriteHeader(fake.status)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"slow down"}]}`))
			return
		}
		switch r.URL.Path {
		case "/v1/apps":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "app-1", "attributes": map[string]any{"bundleId": poolBundle}}}})
		case "/v1/builds":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": fake.builds})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return fake, srv
}

func (f *fakeTestFlight) set(builds ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds = builds
}

func (f *fakeTestFlight) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func appleBuild(version, state string) map[string]any {
	return map[string]any{"id": "build-" + version, "attributes": map[string]any{
		"version": version, "processingState": state, "expired": false,
		"expirationDate": "2026-12-27T08:00:00Z", "uploadedDate": "2026-09-28T08:00:00Z",
	}}
}

// seedASCKey 按生产的存法（STORAGE_MASTER_KEY 加密、按租户 AAD）给租户装一把 ASC 密钥。
func seedASCKey(t *testing.T, f *gateFixture) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := f.s.secrets.Encrypt(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), iosASCAAD(f.tenant))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(iosASC{IssuerID: "69a6de70-0000-0000-0000-000000000000", KeyID: "ABCDEFGHIJ",
		PrivateKeyEncrypted: base64.RawStdEncoding.EncodeToString(ciphertext)})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
		f.tenant, iosASCConfigKey, raw); err != nil {
		t.Fatal(err)
	}
}

// succeededTestFlightJob 排一条全托管的 iOS 任务，直接把它改成"已传进 Apple、完成于 done"。
func succeededTestFlightJob(t *testing.T, f *gateFixture, mac gateMachine, version string, build int, done time.Time) string {
	t.Helper()
	if recorder := iosClaim(f, mac, teamReport(poolTeamA, poolBundle)); recorder.Code != http.StatusNoContent && recorder.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	recorder := queueIOS(f, version, build)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	id := decodeBody(t, recorder)["id"].(string)
	if _, err := f.db.Exec(`UPDATE build_jobs SET status='succeeded',heartbeat_at=? WHERE id=?`, done, id); err != nil {
		t.Fatal(err)
	}
	return id
}

func testFlightStateOf(t *testing.T, f *gateFixture, id string) testFlightState {
	t.Helper()
	var raw []byte
	if err := f.db.QueryRow(`SELECT testflight_state FROM build_jobs WHERE id=?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return parseTestFlightState(raw)
}

func TestDBTestFlightPollerFollowsAppleUntilTheBuildIsValid(t *testing.T) {
	f, macs := newIOSPool(t, 161, 1)
	fake, srv := newFakeTestFlight(t)
	f.s.ascBaseURL = srv.URL
	now := time.Now().UTC().Truncate(time.Second)
	id := succeededTestFlightJob(t, f, macs[0], "4.0.0", 4000, now.Add(-time.Minute))

	// 没交密钥：一次请求都不发，记下原因，6 小时后再看
	if written := f.s.pollTestFlightStates(context.Background(), now); !containsString(written, id) || fake.count() != 0 {
		t.Fatalf("written %v, %d requests to Apple", written, fake.count())
	}
	if state := testFlightStateOf(t, f, id); state.Unavailable != testFlightUnavailableNoKey || state.NextCheckAt != iso(now.Add(testFlightTenantBackoff)) {
		t.Fatalf("a tenant without a key: %+v", state)
	}
	if written := f.s.pollTestFlightStates(context.Background(), now.Add(time.Minute)); containsString(written, id) {
		t.Fatal("a parked build was checked again before its time")
	}

	// 交了密钥：到点之后查，Apple 还在处理
	seedASCKey(t, f)
	fake.set(appleBuild("3999", "VALID"), appleBuild("4000", "PROCESSING"))
	later := now.Add(testFlightTenantBackoff + time.Second)
	if written := f.s.pollTestFlightStates(context.Background(), later); !containsString(written, id) {
		t.Fatalf("the build was not checked once the key exists: %v", written)
	}
	state := testFlightStateOf(t, f, id)
	if state.ProcessingState != "PROCESSING" || state.BuildID != "build-4000" || state.Unavailable != "" || state.FinalAt != "" ||
		state.Checks != 1 || state.NextCheckAt != iso(later.Add(2*time.Minute)) {
		t.Fatalf("after the first check: %+v", state)
	}
	// 服务端只读 Apple
	if fake.methods[http.MethodPost] || fake.methods[http.MethodPatch] || fake.methods[http.MethodDelete] || !fake.methods[http.MethodGet] {
		t.Fatalf("the poller must only read App Store Connect: %v", fake.methods)
	}
	before := fake.count()
	if written := f.s.pollTestFlightStates(context.Background(), later.Add(time.Minute)); containsString(written, id) || fake.count() != before {
		t.Fatal("a build was checked before its next check time")
	}

	// 处理完：VALID 是终态，之后不再查；构建列表上看得到
	fake.set(appleBuild("4000", "VALID"))
	if written := f.s.pollTestFlightStates(context.Background(), later.Add(3*time.Minute)); !containsString(written, id) {
		t.Fatal("the second check did not happen")
	}
	if state := testFlightStateOf(t, f, id); state.ProcessingState != "VALID" || state.FinalAt == "" || state.ExpirationDate == "" {
		t.Fatalf("a valid build: %+v", state)
	}
	before = fake.count()
	if written := f.s.pollTestFlightStates(context.Background(), later.Add(24*time.Hour)); containsString(written, id) || fake.count() != before {
		t.Fatal("a build in a final state was checked again")
	}
	view, _ := buildDetail(f, id)["testflight"].(map[string]any)
	if view["processingState"] != "VALID" || view["final"] != true || view["expirationDate"] == nil {
		t.Fatalf("testflight view: %v", view)
	}
	var problems int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_testflight_processing_problem'`, f.tenant).Scan(&problems); err != nil || problems != 0 {
		t.Fatalf("a valid build must not raise a problem: %d %v", problems, err)
	}
}

func TestDBTestFlightPollerReportsProblemsAndBacksOff(t *testing.T) {
	f, macs := newIOSPool(t, 162, 1)
	fake, srv := newFakeTestFlight(t)
	f.s.ascBaseURL = srv.URL
	seedASCKey(t, f)
	now := time.Now().UTC().Truncate(time.Second)
	rejected := succeededTestFlightJob(t, f, macs[0], "4.1.0", 4100, now.Add(-10*time.Minute))
	missing := succeededTestFlightJob(t, f, macs[0], "4.1.1", 4101, now.Add(-25*time.Hour))
	young := succeededTestFlightJob(t, f, macs[0], "4.1.2", 4102, now.Add(-5*time.Minute))
	old := succeededTestFlightJob(t, f, macs[0], "4.1.3", 4103, now.Add(-8*24*time.Hour))

	// 密钥被拒：整个租户停 6 小时，谁都不再查
	fake.status = http.StatusUnauthorized
	f.s.pollTestFlightStates(context.Background(), now)
	for _, id := range []string{rejected, missing, young} {
		if state := testFlightStateOf(t, f, id); state.LastError == "" || state.NextCheckAt != iso(now.Add(testFlightTenantBackoff)) {
			t.Fatalf("a tenant whose key is rejected must back off: %s %+v", id, state)
		}
	}
	// 完成超过 7 天的不查
	if state := testFlightStateOf(t, f, old); state.NextCheckAt != "" {
		t.Fatalf("a build older than the poll window was checked: %+v", state)
	}

	fake.status = 0
	fake.set(appleBuild("4100", "INVALID"))
	later := now.Add(testFlightTenantBackoff + time.Second)
	f.s.pollTestFlightStates(context.Background(), later)
	if state := testFlightStateOf(t, f, rejected); state.ProcessingState != "INVALID" || state.FinalAt == "" || state.LastError != "" {
		t.Fatalf("an invalid build: %+v", state)
	}
	// 一天都查不到：记 NOT_FOUND 收手；刚完成的查不到只是还没出现，继续等
	if state := testFlightStateOf(t, f, missing); state.ProcessingState != testFlightStateNotFound || state.FinalAt == "" {
		t.Fatalf("a build Apple never showed: %+v", state)
	}
	if state := testFlightStateOf(t, f, young); state.ProcessingState != "" || state.FinalAt != "" || state.Checks != 1 {
		t.Fatalf("a young build that is not visible yet: %+v", state)
	}
	var problems int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='ios_testflight_processing_problem'`, f.tenant).Scan(&problems); err != nil || problems != 2 {
		t.Fatalf("an invalid and a missing build must each raise one problem: %d %v", problems, err)
	}
}
