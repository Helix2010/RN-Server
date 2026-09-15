package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// "这份配置是哪一版"只有一个答案：配置行的数据库版本。历史上这是管理端手填的
// 字符串，可以重复、可以往回写，而且没有任何读它的人能发现填错了。
func TestDerivedConfigVersionComesFromTheRowIdentity(t *testing.T) {
	at := time.Date(2026, 9, 15, 3, 4, 5, 0, time.UTC)
	if got := derivedConfigVersion(at, 7); got != "20260915-v7" {
		t.Fatalf("configVersion = %q", got)
	}
	// 同一天里改两次也必须是两个值，否则"配置没生效"的排查会卡在这里
	if derivedConfigVersion(at, 7) == derivedConfigVersion(at, 8) {
		t.Fatal("同一天的两个版本派生出了同一个 configVersion")
	}
	// 本地时区不能影响结果：同一时刻在东八区和 UTC 下必须是同一个版本号
	if derivedConfigVersion(at.In(time.FixedZone("CST", 8*3600)), 7) != "20260915-v7" {
		t.Fatal("configVersion 跟着本地时区变了")
	}
}

// 管理端不再提交这个字段，保存时也就不能再要求它。
func TestValidConfigNoLongerRequiresATypedConfigVersion(t *testing.T) {
	var cfg map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &cfg); err != nil {
		t.Fatal(err)
	}
	if _, present := cfg["configVersion"]; present {
		t.Fatal("平台种子配置里还留着手填的 configVersion")
	}
	if !validConfig(cfg) {
		t.Fatal("没有 configVersion 的配置被判为不合法")
	}
}

// 保存之后，下发和管理端看到的 configVersion 必须是新的数据库版本，而且这个值
// 不进 config_value——存一份就是第二个事实源，下次谁改了行版本它就开始说谎。
func TestDBSavedConfigVersionFollowsTheDatabaseVersion(t *testing.T) {
	db := openTestDB(t)
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	result, err := db.Exec(`INSERT INTO tenants(slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,1,?,?,0,?,?)`,
		"cfgver-"+uniqueSuffix(), now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	id, _ := result.LastInsertId()
	tenant := strconv.FormatInt(id, 10)

	var stored map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &stored); err != nil {
		t.Fatal(err)
	}
	stored["modules"] = map[string]any{"predict": false, "dex": true}
	// 历史数据里手填的那个字符串还在，读出来的必须已经不是它
	stored["configVersion"] = "2026.08.24.1"
	raw, _ := json.Marshal(stored)
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,5,'test',?)`, tenant, raw, now); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	s := &server{db: db}
	seeded, err := s.appConfigView(context.Background(), tenant)
	if err != nil {
		t.Fatalf("appConfigView: %v", err)
	}
	if got := seeded["config"].(map[string]any)["configVersion"]; got != derivedConfigVersion(now, 5) {
		t.Fatalf("读出来的还是库里手填的那个: %v", got)
	}

	submitted := map[string]any{}
	for k, v := range stored {
		submitted[k] = v
	}
	body, _ := json.Marshal(map[string]any{
		"config": submitted, "expectedVersion": 5, "reason": "改缓存时长", "confirm": true,
	})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Set("tenantId", tenant)
	c.Set("actorId", "tester")
	c.Request = httptest.NewRequest("PATCH", "/v1/admin/app-config", strings.NewReader(string(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	s.updateAppConfig(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}

	var saved struct {
		Config   map[string]any `json:"config"`
		Metadata struct {
			DatabaseVersion int `json:"databaseVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Metadata.DatabaseVersion != 6 {
		t.Fatalf("databaseVersion = %d", saved.Metadata.DatabaseVersion)
	}
	if !strings.HasSuffix(saved.Config["configVersion"].(string), "-v6") {
		t.Fatalf("保存后的 configVersion 没跟上数据库版本: %v", saved.Config["configVersion"])
	}

	var persisted []byte
	if err := db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key='mobile-bootstrap'`, tenant).Scan(&persisted); err != nil {
		t.Fatalf("read back: %v", err)
	}
	var onDisk map[string]any
	if err := json.Unmarshal(persisted, &onDisk); err != nil {
		t.Fatal(err)
	}
	if _, present := onDisk["configVersion"]; present {
		t.Fatal("configVersion 又被存回了 config_value")
	}

	// 审计和推送事件报的是同一个版本：排查时这三处对不上就没法定位
	var summary string
	if err := db.QueryRow(`SELECT summary FROM audit_events WHERE tenant_id=? AND action='config_update' ORDER BY id DESC LIMIT 1`, tenant).Scan(&summary); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(summary, saved.Config["configVersion"].(string)) {
		t.Fatalf("审计里的 configVersion 和下发的不一致: %s", summary)
	}
}
