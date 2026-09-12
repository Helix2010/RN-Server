package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 生成出来的哈希必须能被登录那条路径verify——两边写在不同文件里，参数范围各自
// 独立（verifyPassword 只接受 N<=32768），对不上的话结果是"生成成功、登不进去"
func TestGeneratedPasswordHashVerifiesWithTheLoginPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/admin/platform/password-hash",
		strings.NewReader(`{"password":"Correct-Horse-9-Battery"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	s.generateAdminPasswordHash(c)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Hash    string `json:"hash"`
		EnvLine string `json:"envLine"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !verifyPassword("Correct-Horse-9-Battery", body.Hash) {
		t.Fatalf("生成的哈希验不过: %s", body.Hash)
	}
	if verifyPassword("Correct-Horse-9-Batter", body.Hash) {
		t.Fatal("错误口令也验过了")
	}
	// 值里有 $，不带单引号写进 .env，任何 source 它的脚本都会把 $32768 吃掉
	if !strings.HasPrefix(body.EnvLine, "ADMIN_PASSWORD_HASH='") || !strings.HasSuffix(body.EnvLine, "'") {
		t.Fatalf("给出的 .env 行没有加单引号: %s", body.EnvLine)
	}
}

// 每次生成必须换盐，否则相同口令产出相同哈希，等于把"两个环境用了同一把口令"
// 这件事写在配置文件里给人看
func TestPasswordHashUsesAFreshSaltEveryTime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{}
	hash := func() string {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/x", strings.NewReader(`{"password":"Correct-Horse-9-Battery"}`))
		c.Request.Header.Set("Content-Type", "application/json")
		s.generateAdminPasswordHash(c)
		var body struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(recorder.Body.Bytes(), &body)
		return body.Hash
	}
	if a, b := hash(), hash(); a == b || a == "" {
		t.Fatalf("两次生成得到了相同的哈希: %s", a)
	}
}

// 这把口令背后是 platformAdmin，弱口令在这里的代价和别处不一样
func TestPasswordStrengthGateRejectsWhatIsTooEasy(t *testing.T) {
	for name, password := range map[string]string{
		"太短":   "Ab3-short",
		"只有小写": "abcdefghijklmnopqrst",
		"只有两类": "abcdefghijklmnop1234",
		"空":    "",
	} {
		if err := checkAdminPasswordStrength(password); err == nil {
			t.Fatalf("%s 被接受了", name)
		}
	}
	if err := checkAdminPasswordStrength("Correct-Horse-9-Battery"); err != nil {
		t.Fatalf("合格的口令被拒了: %v", err)
	}
	// 首尾空格是口令的一部分，不该被当成非法
	if err := checkAdminPasswordStrength(" Correct-Horse-9-Battery "); err != nil {
		t.Fatalf("带空格的口令被拒了: %v", err)
	}
}
