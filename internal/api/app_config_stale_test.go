package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 拿一份过期的配置提交时，回的必须是"你那份旧了"，而不是内容校验的报错。
//
// 真踩过：一条迁移刚把平台默认配置里的 predict 关掉，运营页面上还开着旧的那份，
// 保存就一直报 "the Predict module is enabled but services.predict is not
// configured"——而那说的是他浏览器里那份旧配置的毛病，库里的现状早就没这个问题了。
// 人会照着报错去修一个已经不存在的问题。
func TestDBSaveConfigReportsStalenessBeforeContentProblems(t *testing.T) {
	db := openTestDB(t)
	gin.SetMode(gin.TestMode)
	now := time.Now().UTC()
	result, err := db.Exec(`INSERT INTO tenants(slug,status,start_date,expiry_date,deleted,created_at,updated_at) VALUES(?,1,?,?,0,?,?)`,
		"stale-"+uniqueSuffix(), now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0), now, now)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	id, _ := result.LastInsertId()
	tenant := strconv.FormatInt(id, 10)

	var stored map[string]any
	if err := json.Unmarshal([]byte(initialConfig), &stored); err != nil {
		t.Fatal(err)
	}
	stored["wallet"] = map[string]any{"chains": []string{"bsc"}, "onchainSends": false}
	stored["modules"] = map[string]any{"predict": false, "dex": true}
	raw, _ := json.Marshal(stored)
	// 库里是第 5 版
	if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,'mobile-bootstrap',?,5,'test',?)`, tenant, raw, now); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// 提交的是第 4 版，而且内容本身也有毛病（predict 开着没配服务）——两个问题同时
	// 存在时，要先说版本旧了，那才是他该做的动作
	submitted := map[string]any{}
	for k, v := range stored {
		submitted[k] = v
	}
	submitted["modules"] = map[string]any{"predict": true, "dex": true}
	submitted["services"] = map[string]any{}
	body, _ := json.Marshal(map[string]any{
		"config": submitted, "expectedVersion": 4, "reason": "用过期的版本提交", "confirm": true,
	})

	s := &server{db: db}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Set("tenantId", tenant)
	c.Set("actorId", "tester")
	c.Request = httptest.NewRequest("PATCH", "/v1/admin/app-config", strings.NewReader(string(body)))
	c.Request.Header.Set("Content-Type", "application/json")
	s.updateAppConfig(c)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "STALE_APP_CONFIG") {
		t.Fatalf("回的不是版本冲突: %s", recorder.Body.String())
	}
	// 内容校验的那句话不该出现——它说的是旧配置的毛病
	if strings.Contains(recorder.Body.String(), "services.predict") {
		t.Fatalf("报的是内容问题而不是版本旧了: %s", recorder.Body.String())
	}
}
