package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 租户会话的邮箱二次验证（设计 tenant-console-accounts-and-sso §4.5，second_factor.go）。
func TestDBSecondFactor(t *testing.T) {
	db := openTestDB(t)
	tenant := accountsTestTenantRow(t, db, "sf")
	platformUser := "platform-sf-" + uniqueSuffix()
	platformHash, err := hashPassword("Platform-Pass-2026!")
	if err != nil {
		t.Fatal(err)
	}
	// mail.smtp 是平台级的一份，测试库又是持久的：开始前与结束后都清掉
	clearMail := func() {
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, mailConfigKey)
	}
	clearMail()
	t.Cleanup(clearMail)
	router := New(config.Config{
		Environment:            "test",
		StorageMasterKey:       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout:      10,
		AdminUsername:          platformUser,
		AdminPasswordHash:      platformHash,
		PlatformAdminUsernames: []string{platformUser},
		AdminSessionTTL:        3600,
		AdminLoginMax:          1000,
		AdminLoginWindow:       900,
	}, &store.Store{DB: db})
	smtpServer := startTestSMTP(t)
	memberToken := activeTenantSession(t, db, tenant)
	// 夹具把会话记成刚验过；这里要从没验过开始
	if _, err := db.Exec(`UPDATE admin_sessions SET second_factor_at=NULL WHERE token_hash=?`, sha256Hex(memberToken)); err != nil {
		t.Fatal(err)
	}
	var memberEmail, loginName string
	if err := db.QueryRow(`SELECT a.email, a.login_name FROM admin_sessions s JOIN tenant_admin_accounts a ON a.id=s.account_id WHERE s.token_hash=?`,
		sha256Hex(memberToken)).Scan(&memberEmail, &loginName); err != nil {
		t.Fatal(err)
	}
	member := &browser{router: router, tenant: tenant, cookies: map[string]string{adminSessionCookie: memberToken}}
	platform := &browser{router: router, tenant: tenant, cookies: map[string]string{}}
	platform.mustCode(t, platform.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
	sfx := uniqueSuffix()
	identity := func(bundle string, version any) map[string]any {
		return map[string]any{"appleTeamId": "SF" + strings.ToUpper(sfx + "00000000")[:8], "bundleId": bundle, "expectedVersion": version, "reason": "改 iOS 身份", "confirm": true}
	}

	// 没验过：敏感操作 403，会话视图里没有有效期
	wantProblem(t, member.do("PUT", "/v1/admin/release-identity/ios", identity("com.sf.a"+sfx, 0), nil), 403, "SECOND_FACTOR_REQUIRED")
	wantProblem(t, member.do("PUT", "/v1/admin/ios/delivery", map[string]any{"mode": "ipa", "expectedVersion": 0, "reason": "切换", "confirm": true}, nil), 403, "SECOND_FACTOR_REQUIRED")
	if view := member.mustCode(t, member.do("GET", "/v1/admin/auth/session", nil, nil), 200); view["secondFactorUntil"] != nil {
		t.Fatalf("session = %v", view)
	}
	// 平台会话不用二次验证
	platform.mustCode(t, platform.do("PUT", "/v1/admin/release-identity/ios", identity("com.sf.p"+sfx, 0), nil), 200)
	wantProblem(t, platform.do("POST", "/v1/admin/auth/second-factor/code", map[string]any{}, nil), 400, "SECOND_FACTOR_NOT_APPLICABLE")

	// 钱包段（RPC、WalletConnect、转出上链开关）下发给所有用户：改它也要二次验证；原样带回不算改
	appConfig := func(projectID string) map[string]any {
		return map[string]any{"expectedVersion": 1, "reason": "改钱包", "confirm": true, "config": map[string]any{
			"ttlSeconds": 3600, "localization": map[string]any{}, "theme": map[string]any{}, "support": map[string]any{},
			"features": map[string]any{"crashAutoReport": false},
			"updatePolicy": map[string]any{
				"minSupportedVersion": map[string]any{"android": "1.0.0", "ios": "1.0.0"},
				"latestVersion":       map[string]any{"android": "1.0.0", "ios": "1.0.0"},
			},
			"modules": map[string]any{"predict": false},
			"wallet":  map[string]any{"walletConnectProjectId": projectID},
		}}
	}
	seed, _ := json.Marshal(appConfig("sfproject0000000" + sfx)["config"])
	seedTenantConfig(t, db, tenant.id, "mobile-bootstrap", string(seed))
	wantProblem(t, member.do("PATCH", "/v1/admin/app-config", appConfig("attackerproject00000"), nil), 403, "SECOND_FACTOR_REQUIRED")
	member.mustCode(t, member.do("PATCH", "/v1/admin/app-config", appConfig("sfproject0000000"+sfx), nil), 200)

	// 没配发信就发不了码，也就做不了敏感操作（不退回不校验）
	wantProblem(t, member.do("POST", "/v1/admin/auth/second-factor/code", map[string]any{}, nil), 503, "MAIL_NOT_CONFIGURED")
	platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("二次验证要发信", 0), nil), 200)

	sent := member.mustCode(t, member.do("POST", "/v1/admin/auth/second-factor/code", map[string]any{}, nil), 200)
	token, _ := sent["codeToken"].(string)
	if token == "" || sent["email"] != maskEmail(memberEmail) {
		t.Fatalf("code response = %v", sent)
	}
	body := smtpServer.last(t, memberEmail)
	if !strings.Contains(body, loginName) || !strings.Contains(body, tenant.console) {
		t.Fatalf("second factor mail:\n%s", body)
	}
	wantProblem(t, member.do("POST", "/v1/admin/auth/second-factor/code", map[string]any{}, nil), 429, "SECOND_FACTOR_CODE_RATE_LIMITED")
	code := mailCode(t, body)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	wantProblem(t, member.do("POST", "/v1/admin/auth/second-factor/verify", map[string]any{"codeToken": token, "code": wrong}, nil), 400, "SECOND_FACTOR_CODE_INVALID")
	var failures int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='tenant_account_second_factor_failed'`, tenant.id).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("failed verification audits = %d %v", failures, err)
	}
	verified := member.mustCode(t, member.do("POST", "/v1/admin/auth/second-factor/verify", map[string]any{"codeToken": token, "code": code}, nil), 200)
	if verified["secondFactorUntil"] == nil {
		t.Fatalf("verify = %v", verified)
	}
	// 用过就作废
	wantProblem(t, member.do("POST", "/v1/admin/auth/second-factor/verify", map[string]any{"codeToken": token, "code": code}, nil), 400, "SECOND_FACTOR_CODE_INVALID")
	if view := member.mustCode(t, member.do("GET", "/v1/admin/auth/session", nil, nil), 200); view["secondFactorUntil"] == nil {
		t.Fatalf("session after verify = %v", view)
	}

	// 验过之后敏感操作放行（平台会话刚改过一版，按当前版本提交）
	current := member.mustCode(t, member.do("GET", "/v1/admin/release-identity/ios", nil, nil), 200)
	member.mustCode(t, member.do("PUT", "/v1/admin/release-identity/ios", identity("com.sf.a"+sfx, current["version"]), nil), 200)

	// 审计：发码与验证都有，收件人掩码、没有验证码
	var summaries string
	if err := db.QueryRow(`SELECT COALESCE(GROUP_CONCAT(CONCAT(action,' ',summary) SEPARATOR '\n'),'') FROM audit_events WHERE tenant_id=? AND action LIKE 'tenant_account_second_factor_%'`, tenant.id).Scan(&summaries); err != nil ||
		!strings.Contains(summaries, "tenant_account_second_factor_code_sent") || !strings.Contains(summaries, "tenant_account_second_factor_verified") ||
		strings.Contains(summaries, memberEmail) || strings.Contains(summaries, code) {
		t.Fatalf("second factor audits = %q %v", summaries, err)
	}

	// 过了 15 分钟又要验
	if _, err := db.Exec(`UPDATE admin_sessions SET second_factor_at=? WHERE token_hash=?`, time.Now().UTC().Add(-secondFactorWindow-time.Minute), sha256Hex(memberToken)); err != nil {
		t.Fatal(err)
	}
	current = member.mustCode(t, member.do("GET", "/v1/admin/release-identity/ios", nil, nil), 200)
	wantProblem(t, member.do("PUT", "/v1/admin/release-identity/ios", identity("com.sf.b"+sfx, current["version"]), nil), 403, "SECOND_FACTOR_REQUIRED")
	if view := member.mustCode(t, member.do("GET", "/v1/admin/auth/session", nil, nil), 200); view["secondFactorUntil"] != nil {
		t.Fatalf("expired second factor still shown: %v", view)
	}
}
