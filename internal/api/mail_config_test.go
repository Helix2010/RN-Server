package api

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	netmail "net/mail"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/store"
)

// 平台发信（ADR-0022）与绑定验证码存储的回归。

// testSMTP 是本机 127.0.0.1 上的假 SMTP 服务（明文、不认证，internal/mail 允许本机明文），收到的邮件留在内存里。
type testSMTP struct {
	host string
	port int
	mu   sync.Mutex
	mail []testSMTPMessage
}

type testSMTPMessage struct {
	to   string
	body string // 解码后的正文（所有部分拼起来）
}

func startTestSMTP(t *testing.T) *testSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	f := &testSMTP{host: host, port: p}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *testSMTP) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	say("220 test")
	var rcpt string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "RCPT TO:"):
			rcpt = strings.Trim(cmd[len("RCPT TO:"):], " <>")
			say("250 ok")
		case upper == "DATA":
			say("354 go")
			var raw strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				raw.WriteString(l)
			}
			f.mu.Lock()
			f.mail = append(f.mail, testSMTPMessage{to: rcpt, body: decodeTestMail(raw.String())})
			f.mu.Unlock()
			say("250 queued")
		case upper == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// decodeTestMail 把各个 base64 部分解出来拼在一起，够测试里找验证码与文字用。
func decodeTestMail(raw string) string {
	msg, err := netmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return raw
	}
	body, _ := io.ReadAll(msg.Body)
	var out bytes.Buffer
	for _, chunk := range regexp.MustCompile(`(?m)^[A-Za-z0-9+/=]{16,}(?:\r?\n[A-Za-z0-9+/=]+)*`).FindAllString(string(body), -1) {
		if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.ReplaceAll(chunk, "\r", ""), "\n", "")); err == nil {
			out.Write(decoded)
			out.WriteString("\n")
		}
	}
	return out.String()
}

// last 等最后一封寄给 to 的邮件（投递是同步的，这里只为稳妥）。
func (f *testSMTP) last(t *testing.T, to string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		for i := len(f.mail) - 1; i >= 0; i-- {
			if f.mail[i].to == to {
				body := f.mail[i].body
				f.mu.Unlock()
				return body
			}
		}
		f.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no mail to %s", to)
	return ""
}

func (f *testSMTP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.mail)
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

func mailCode(t *testing.T, body string) string {
	t.Helper()
	code := sixDigits.FindString(body)
	if code == "" {
		t.Fatalf("no 6-digit code in:\n%s", body)
	}
	return code
}

func (f *testSMTP) settings(reason string, version int) map[string]any {
	return map[string]any{"host": f.host, "port": f.port, "fromAddress": "noreply@rn.test", "fromName": "RN 平台",
		"expectedVersion": version, "reason": reason}
}

func TestDBPlatformMailConfig(t *testing.T) {
	db := openTestDB(t)
	tenant := accountsTestTenantRow(t, db, "mail")
	platformUser := "platform-mail-" + uniqueSuffix()
	platformHash, err := hashPassword("Platform-Pass-2026!")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Environment: "test", StorageMasterKey: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		MySQLQueryTimeout: 10, AdminUsername: platformUser, AdminPasswordHash: platformHash, PlatformAdminUsernames: []string{platformUser},
		AdminSessionTTL: 3600, AdminLoginMax: 1000, AdminLoginWindow: 900,
	}
	// mail.smtp 是平台级的一份，测试库又是持久的：开始前与结束后都清掉
	clearMail := func() {
		_, _ = db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, mailConfigKey)
	}
	clearMail()
	t.Cleanup(clearMail)
	router := New(cfg, &store.Store{DB: db})
	platform := &browser{router: router, tenant: tenant, cookies: map[string]string{}}
	platform.mustCode(t, platform.do("POST", "/v1/admin/auth/login", map[string]string{"username": platformUser, "password": "Platform-Pass-2026!"}, nil), 200)
	smtpServer := startTestSMTP(t)

	// 没存过时管理端用服务端声明的默认端口预填
	if view := platform.mustCode(t, platform.do("GET", "/v1/admin/platform/mail", nil, nil), 200); view["configured"] != false || view["defaultPort"] != float64(587) {
		t.Fatalf("mail = %v", view)
	}
	wantProblem(t, platform.do("POST", "/v1/admin/platform/mail/test", map[string]any{"to": "ops@rn.test", "reason": "试发"}, nil), 409, "MAIL_NOT_CONFIGURED")

	// 写入时校验：带端口的主机名、带显示名的发件地址、有用户名没口令，都当场拒绝
	for _, bad := range []map[string]any{
		{"host": "smtp.rn.test:587", "fromAddress": "noreply@rn.test", "expectedVersion": 0, "reason": "坏主机名"},
		{"host": "smtp.rn.test", "fromAddress": "RN <noreply@rn.test>", "expectedVersion": 0, "reason": "坏发件地址"},
		{"host": "smtp.rn.test", "fromAddress": "noreply@rn.test", "username": "mailer", "expectedVersion": 0, "reason": "缺口令"},
	} {
		wantProblem(t, platform.do("PUT", "/v1/admin/platform/mail", bad, nil), 422, "INVALID_MAIL_CONFIG")
	}

	// 带用户名与口令保存：口令加密存、从不回显
	withAuth := smtpServer.settings("配发信", 0)
	withAuth["username"], withAuth["password"] = "mailer", "Smtp-Pass-2026"
	view := platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/mail", withAuth, nil), 200)
	if object(view["config"])["hasPassword"] != true || view["version"] != float64(1) {
		t.Fatalf("saved = %v", view)
	}
	var raw string
	if err := db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, mailConfigKey).Scan(&raw); err != nil ||
		strings.Contains(raw, "Smtp-Pass-2026") || !strings.Contains(raw, "passwordEncrypted") {
		t.Fatalf("stored value must hold only the encrypted password: %s %v", raw, err)
	}
	if strings.Contains(platform.do("GET", "/v1/admin/platform/mail", nil, nil).Body.String(), "Smtp-Pass-2026") {
		t.Fatal("the password must never be returned")
	}
	// 留空口令 = 沿用；版本不对 = 409
	keep := smtpServer.settings("改发件人名", 1)
	keep["username"], keep["fromName"] = "mailer", "RN"
	if view := platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/mail", keep, nil), 200); object(view["config"])["hasPassword"] != true {
		t.Fatalf("an empty password must keep the stored one: %v", view)
	}
	// 改了服务器或用户名就不沿用：否则改个地址再试发，口令就被送到别的服务器
	for _, change := range []map[string]any{{"host": "smtp.elsewhere.test"}, {"port": 465}, {"username": "mailer2"}} {
		changed := smtpServer.settings("改地址不给口令", 2)
		changed["username"] = "mailer"
		for k, v := range change {
			changed[k] = v
		}
		wantProblem(t, platform.do("PUT", "/v1/admin/platform/mail", changed, nil), 422, "MAIL_PASSWORD_REQUIRED")
	}
	wantProblem(t, platform.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("过期版本", 1), nil), 409, "STALE_MAIL_CONFIG")
	// 本机假 SMTP 不要认证：去掉用户名，口令一起清掉
	if view := platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/mail", smtpServer.settings("本机中继不认证", 2), nil), 200); object(view["config"])["hasPassword"] != false {
		t.Fatalf("no username means no stored password: %v", view)
	}

	// 发一封测试邮件
	platform.mustCode(t, platform.do("POST", "/v1/admin/platform/mail/test", map[string]any{"to": "ops@rn.test", "reason": "试发"}, nil), 200)
	if body := smtpServer.last(t, "ops@rn.test"); !strings.Contains(body, "RN platform email settings work") {
		t.Fatalf("test mail body:\n%s", body)
	}
	// 连不上：固定的 Problem，不回显对方原话
	unreachable := map[string]any{"host": "127.0.0.1", "port": 1, "fromAddress": "noreply@rn.test", "expectedVersion": 3, "reason": "指向没人监听的端口"}
	platform.mustCode(t, platform.do("PUT", "/v1/admin/platform/mail", unreachable, nil), 200)
	wantProblem(t, platform.do("POST", "/v1/admin/platform/mail/test", map[string]any{"to": "ops@rn.test", "reason": "试发"}, nil), 502, "MAIL_CONNECT_FAILED")

	// 审计：配置改动与试发都有记录，口令不进审计
	var audits int
	var summaries string
	_ = db.QueryRow(`SELECT COUNT(*), COALESCE(GROUP_CONCAT(summary SEPARATOR ' '), '') FROM audit_events
		WHERE tenant_id=? AND action IN ('mail_config_update','mail_test_sent') AND actor_id LIKE ?`, platformTenantID, "%"+platformUser+"%").Scan(&audits, &summaries)
	if audits < 6 || strings.Contains(summaries, "Smtp-Pass-2026") || strings.Contains(summaries, "ops@rn.test") {
		t.Fatalf("audits = %d: %s", audits, summaries)
	}

	platform.mustCode(t, platform.do("DELETE", "/v1/admin/platform/mail?reason=撤掉发信", nil, nil), 200)
	wantProblem(t, platform.do("DELETE", "/v1/admin/platform/mail?reason=撤掉发信", nil, nil), 404, "MAIL_NOT_CONFIGURED")
}

func TestBindCodeStore(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	var store bindCodeStore
	put := func() {
		store.sent("acc-1", bindCode{token: "tok", code: "123456", subject: "sub", email: "a@x.test", expiresAt: now.Add(bindCodeTTL)}, now)
	}

	// 输错 4 次后输对：通过，而且只能用一次
	put()
	for i := 0; i < bindCodeMaxAttempts-1; i++ {
		if store.verify("acc-1", "tok", "000000", "sub", "a@x.test", now) {
			t.Fatal("a wrong code verified")
		}
	}
	if !store.verify("acc-1", "tok", "123456", "sub", "a@x.test", now) || store.verify("acc-1", "tok", "123456", "sub", "a@x.test", now) {
		t.Fatal("the right code must work once")
	}
	// 输错 5 次作废
	put()
	for i := 0; i < bindCodeMaxAttempts; i++ {
		store.verify("acc-1", "tok", "000000", "sub", "a@x.test", now)
	}
	if store.verify("acc-1", "tok", "123456", "sub", "a@x.test", now) {
		t.Fatal("the code must be dropped after 5 wrong guesses")
	}
	// codeToken 不对不计次数
	put()
	for i := 0; i < bindCodeMaxAttempts*2; i++ {
		store.verify("acc-1", "other", "000000", "sub", "a@x.test", now)
	}
	if !store.verify("acc-1", "tok", "123456", "sub", "a@x.test", now) {
		t.Fatal("wrong tokens must not use up the attempts")
	}
	// 过期、换了统一账号（别的邮箱、别的 subject）都不行
	for _, check := range []struct {
		at             time.Time
		subject, email string
	}{
		{now.Add(bindCodeTTL + time.Second), "sub", "a@x.test"},
		{now, "other-sub", "a@x.test"},
		{now, "sub", "b@x.test"},
	} {
		put()
		if store.verify("acc-1", "tok", "123456", check.subject, check.email, check.at) {
			t.Fatalf("%+v must not verify", check)
		}
	}

	// 发码限流：同一个账号 1 分钟 1 次、1 小时 5 次；同一个 IP 1 小时 20 次
	var limits bindCodeStore
	send := func(at time.Time) bool {
		if !limits.allowSend("acc-1", "10.0.0.1", at) {
			return false
		}
		limits.sent("acc-1", bindCode{token: "tok", code: "123456", subject: "sub", email: "a@x.test", expiresAt: at.Add(bindCodeTTL)}, at)
		return true
	}
	if !send(now) || send(now.Add(30*time.Second)) {
		t.Fatal("one code per minute per account")
	}
	sent := 1
	for i := 1; i <= 10; i++ {
		if send(now.Add(time.Duration(i) * 61 * time.Second)) {
			sent++
		}
	}
	if sent != bindCodePerHour {
		t.Fatalf("an account gets %d codes per hour, got %d", bindCodePerHour, sent)
	}
	var perIP bindCodeStore
	allowed := 0
	for i := 0; i < 30; i++ {
		if perIP.allowSend("acc-"+strconv.Itoa(i), "10.0.0.2", now) {
			allowed++
		}
	}
	if allowed != bindCodeIPPerHour {
		t.Fatalf("an IP gets %d codes per hour, got %d", bindCodeIPPerHour, allowed)
	}

	// 投递失败（allowSend 之后没有 sent）：不开始 1 分钟的重发间隔，已经发到邮箱里的旧码继续有效
	var retry bindCodeStore
	retry.sent("acc-1", bindCode{token: "old", code: "111111", subject: "sub", email: "a@x.test", expiresAt: now.Add(bindCodeTTL)}, now)
	later := now.Add(2 * time.Minute)
	if !retry.allowSend("acc-1", "10.0.0.3", later) || !retry.allowSend("acc-1", "10.0.0.3", later.Add(time.Second)) {
		t.Fatal("a failed delivery must not start the resend interval")
	}
	if !retry.verify("acc-1", "old", "111111", "sub", "a@x.test", later) {
		t.Fatal("a failed delivery must keep the code already in the inbox")
	}
}

// 验证码不能经 %v、%#v、slog 漏出去
func TestBindCodeNeverPrintsCode(t *testing.T) {
	code := bindCode{token: "Sentinel-Token-9c1d", code: "987654", subject: "sub", email: "someone@x.test", expiresAt: time.Now()}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("bind", "code", code)
	for _, out := range []string{fmt.Sprintf("%v %+v %#v %s", code, code, code, code), logged.String()} {
		if strings.Contains(out, "987654") || strings.Contains(out, "Sentinel-Token-9c1d") || strings.Contains(out, "someone@") {
			t.Fatalf("bind code leaked: %s", out)
		}
	}
}
