package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/mail"
	"github.com/gin-gonic/gin"
)

// 绑定验证码（2026-09-26 用户决定，与 pm 商户后台一致）：确认绑定前给认证中心返回的统一认证账号邮箱
// 发验证码，能收到这个邮箱的信才能绑上。防的是浏览器里残留别人（或自己另一个）统一账号的认证中心
// 登录态时绑错——单点登录不再问口令，确认页虽然显示邮箱，人可能不看就点了。防不住「会话被盗后绑到
// 攻击者自己的统一账号」：验证码会发到他自己的邮箱。
//
//	POST /v1/admin/auth/cid/bind/code     {} → {codeToken, expiresAt, resendAfter}；平台没配发信 503 MAIL_NOT_CONFIGURED
//	POST /v1/admin/auth/cid/bind/confirm  {codeToken, code}；不对 400 CID_BIND_CODE_INVALID
//
// 验证码只属于「这个账号 + 这个统一认证账号」，10 分钟，用一次作废，输错 5 次作废。存在进程内存里
// （RN-Server 单实例；重启后重发即可）。

const (
	bindCodeTTL         = 10 * time.Minute
	bindCodeMaxAttempts = 5
	bindCodeResendAfter = time.Minute
	bindCodePerHour     = 5  // 每个账号
	bindCodeIPPerHour   = 20 // 每个来源 IP
)

type bindCode struct {
	token     string
	code      string
	subject   string
	email     string
	expiresAt time.Time
	attempts  int
}

// 验证码不能经 %v、%#v、slog 打出去（白名单，见 AGENTS.md「机密的操作纪律」）。
func (b bindCode) safeSummary() string {
	return fmt.Sprintf("bindCode{email:%s expiresAt:%s attempts:%d}", maskEmail(b.email), b.expiresAt.Format(time.RFC3339), b.attempts)
}
func (b bindCode) String() string       { return b.safeSummary() }
func (b bindCode) GoString() string     { return b.safeSummary() }
func (b bindCode) LogValue() slog.Value { return slog.StringValue(b.safeSummary()) }

// bindCodeStore 按账号 id 存当前有效的那一个验证码。零值可用。
type bindCodeStore struct {
	mu      sync.Mutex
	codes   map[string]bindCode
	resend  windowCounter
	account windowCounter
	ip      windowCounter
}

// allowSend 在投递前判断。每小时的两个配额按尝试计（投递失败也算，免得拿它反复打 SMTP）；
// 1 分钟的重发间隔只在投递成功后由 sent 记——没送出去的那次不该让人干等一分钟。
func (b *bindCodeStore) allowSend(accountID, ip string, now time.Time) bool {
	return !b.resend.exhausted(accountID, 1, now) &&
		b.account.allow(accountID, bindCodePerHour, time.Hour, now) &&
		b.ip.allow(ip, bindCodeIPPerHour, time.Hour, now)
}

// sent 在投递成功后换上新码并开始重发间隔。投递失败不调用：已经发到邮箱里的旧码继续有效。
func (b *bindCodeStore) sent(accountID string, code bindCode, now time.Time) {
	b.resend.allow(accountID, 1, bindCodeResendAfter, now)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.codes == nil {
		b.codes = map[string]bindCode{}
	}
	b.codes[accountID] = code
}

// verify 核对并在成功时作废。codeToken 不对不计次数（它碰不到别人的码）；码不对计一次，满 5 次作废。
func (b *bindCodeStore) verify(accountID, token, code, subject, email string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.codes[accountID]
	if !ok || !constantEqual(entry.token, token) {
		return false
	}
	if now.After(entry.expiresAt) || entry.subject != subject || entry.email != email {
		delete(b.codes, accountID)
		return false
	}
	if !constantEqual(entry.code, code) {
		entry.attempts++
		if entry.attempts >= bindCodeMaxAttempts {
			delete(b.codes, accountID)
		} else {
			b.codes[accountID] = entry
		}
		return false
	}
	delete(b.codes, accountID)
	return true
}

func newBindCode() (code, token string, err error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", "", err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), hex.EncodeToString(raw), nil
}

// bindCodeMessage 中英双语：成员的控制台语言在这里拿不到，收件人也未必是同一个人。
func bindCodeMessage(to, code, loginName, console string) mail.Message {
	text := fmt.Sprintf(`控制台 %s 的成员账号 %s 正在绑定这个统一登录账号（%s）。绑定后，可以用这个统一登录账号进入该控制台。

验证码：%s
%d 分钟内有效。如果不是您本人在绑定，请忽略这封邮件，不要把验证码告诉任何人。

The console member %s on %s is being bound to this unified login account (%s). Once bound, this account can sign in to that console.

Code: %s
Valid for %d minutes. If you are not the one binding, ignore this email and do not share the code.
`, console, loginName, to, code, int(bindCodeTTL.Minutes()), loginName, console, to, code, int(bindCodeTTL.Minutes()))
	e := html.EscapeString
	htmlBody := fmt.Sprintf(`<!doctype html><html><body style="font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif;color:#0f172a;line-height:1.6">
<p>控制台 <b>%s</b> 的成员账号 <b>%s</b> 正在绑定这个统一登录账号（%s）。绑定后，可以用这个统一登录账号进入该控制台。</p>
<p style="font-size:32px;font-weight:700;letter-spacing:8px;font-family:'Courier New',monospace">%s</p>
<p>%d 分钟内有效。如果不是您本人在绑定，请忽略这封邮件，不要把验证码告诉任何人。</p>
<hr style="border:none;border-top:1px solid #e2e8f0">
<p>The console member <b>%s</b> on <b>%s</b> is being bound to this unified login account (%s). Once bound, this account can sign in to that console.</p>
<p>Valid for %d minutes. If you are not the one binding, ignore this email and do not share the code.</p>
</body></html>`, e(console), e(loginName), e(to), code, int(bindCodeTTL.Minutes()), e(loginName), e(console), e(to), int(bindCodeTTL.Minutes()))
	return mail.Message{To: to, Subject: "绑定统一登录账号验证码 / Unified login binding code", Text: text, HTML: htmlBody}
}

func (s *server) sendCIDBindCode(c *gin.Context) {
	pending, session := s.pendingBindFor(c)
	if pending == nil {
		problem(c, 404, "CID_BIND_NOT_PENDING", "There is no unified login account waiting to be bound; start binding again")
		return
	}
	if !strings.Contains(pending.Email, "@") {
		problem(c, 409, "CID_ACCOUNT_NO_EMAIL", "The unified login account has no email; ask the platform administrator")
		return
	}
	ctx := c.Request.Context()
	cfg, err := s.mailConfig(ctx)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_INVALID", "Stored "+mailConfigKey+" configuration is invalid")
		return
	}
	if cfg == nil {
		problem(c, 503, "MAIL_NOT_CONFIGURED", "Email sending is not configured; ask the platform administrator")
		return
	}
	now := s.now()
	if !s.bindCodes.allowSend(session.AccountID, c.ClientIP(), now) {
		problem(c, 429, "CID_BIND_CODE_RATE_LIMITED", "Too many codes requested; wait a minute and try again")
		return
	}
	code, token, err := newBindCode()
	if err != nil {
		problem(c, 500, "CID_BIND_CODE_FAILED", "Unable to create a verification code")
		return
	}
	expiresAt := now.Add(bindCodeTTL)
	problemCode, sendErr := s.sendMail(ctx, *cfg, bindCodeMessage(pending.Email, code, session.Account.LoginName, s.consoleHost(c)))
	s.auditNow(newAudit(session.TenantID, session.Actor, "tenant_account_bind_code_sent", "tenant-account", session.AccountID, "发送绑定验证码", requestID(c),
		map[string]any{"to": maskEmail(pending.Email), "sent": sendErr == nil, "problem": nullableString(problemCode)}))
	if sendErr != nil {
		problem(c, 502, mailProblemSendFail, "Unable to send the verification code; try again later")
		return
	}
	s.bindCodes.sent(session.AccountID, bindCode{token: token, code: code, subject: pending.Subject, email: pending.Email, expiresAt: expiresAt}, now)
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"codeToken": token, "expiresAt": iso(expiresAt), "resendAfter": int(bindCodeResendAfter.Seconds())})
}
