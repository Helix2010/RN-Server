package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/mail"
	"github.com/gin-gonic/gin"
)

// 账号会话的二次验证（设计 tenant-console-accounts-and-sso §4.5；2026-09-27 用户定为邮箱验证码，不用验证器 App）。
//
// 认证中心不告诉我们对方怎么登录、何时登录的，统一账号口令泄露就等于进了控制台。所以做敏感操作前，
// 再给账号**登记的邮箱**（外部系统写在 tenant_admin_accounts.email 里的）发一个验证码：验过之后这个会话
// 15 分钟内可以做敏感操作。
//
// 平台管理员账号也要验，而且范围更大（设计 platform-accounts-and-console-login §3.5）：统一账号口令泄露，
// 拿到的就是整个平台。平台维护的写操作一律要求（requireSecondFactorOnWrite）。
// 自动化通道（管理密钥）不用：它没有会话，也没有邮箱。
//
//	POST /v1/admin/auth/second-factor/code    {} → {codeToken, expiresAt, resendAfter, email（掩码）}；没配发信 503 MAIL_NOT_CONFIGURED
//	POST /v1/admin/auth/second-factor/verify  {codeToken, code} → {secondFactorUntil}；不对 400 SECOND_FACTOR_CODE_INVALID
//
// 验证码存在进程内存里（emailCodeStore，RN-Server 单实例，重启后重发即可）：10 分钟、用一次、错 5 次作废；
// 每账号 1 分钟 1 次、1 小时 5 次，每 IP 1 小时 20 次；而且只属于发码的那个会话：换个会话拿着 codeToken 也验不过。

const secondFactorWindow = 15 * time.Minute

const (
	emailCodeTTL         = 10 * time.Minute
	emailCodeMaxAttempts = 5
	emailCodeResendAfter = time.Minute
	emailCodePerHour     = 5  // 每个账号
	emailCodeIPPerHour   = 20 // 每个来源 IP
)

type emailCode struct {
	token     string
	code      string
	subject   string
	email     string
	expiresAt time.Time
	attempts  int
}

// 验证码不能经 %v、%#v、slog 打出去（白名单，见 AGENTS.md「机密的操作纪律」）。
func (b emailCode) safeSummary() string {
	return fmt.Sprintf("emailCode{email:%s expiresAt:%s attempts:%d}", maskEmail(b.email), b.expiresAt.Format(time.RFC3339), b.attempts)
}
func (b emailCode) String() string       { return b.safeSummary() }
func (b emailCode) GoString() string     { return b.safeSummary() }
func (b emailCode) LogValue() slog.Value { return slog.StringValue(b.safeSummary()) }

// emailCodeStore 按账号 id 存当前有效的那一个验证码。零值可用。
type emailCodeStore struct {
	mu      sync.Mutex
	codes   map[string]emailCode
	resend  windowCounter
	account windowCounter
	ip      windowCounter
}

// allowSend 在投递前判断。每小时的两个配额按尝试计（投递失败也算，免得拿它反复打 SMTP）；
// 1 分钟的重发间隔只在投递成功后由 sent 记——没送出去的那次不该让人干等一分钟。
func (b *emailCodeStore) allowSend(accountID, ip string, now time.Time) bool {
	return !b.resend.exhausted(accountID, 1, now) &&
		b.account.allow(accountID, emailCodePerHour, time.Hour, now) &&
		b.ip.allow(ip, emailCodeIPPerHour, time.Hour, now)
}

// sent 在投递成功后换上新码并开始重发间隔。投递失败不调用：已经发到邮箱里的旧码继续有效。
func (b *emailCodeStore) sent(accountID string, code emailCode, now time.Time) {
	b.resend.allow(accountID, 1, emailCodeResendAfter, now)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.codes == nil {
		b.codes = map[string]emailCode{}
	}
	b.codes[accountID] = code
}

// verify 核对并在成功时作废。codeToken 不对不计次数（它碰不到别人的码）；码不对计一次，满 5 次作废。
func (b *emailCodeStore) verify(accountID, token, code, subject, email string, now time.Time) bool {
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
		if entry.attempts >= emailCodeMaxAttempts {
			delete(b.codes, accountID)
		} else {
			b.codes[accountID] = entry
		}
		return false
	}
	delete(b.codes, accountID)
	return true
}

func newEmailCode() (code, token string, err error) {
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

// secondFactorFresh：这个会话 15 分钟内验过。
func secondFactorFresh(session *adminSession, now time.Time) bool {
	return !session.SecondFactorAt.IsZero() && now.Before(session.SecondFactorAt.Add(secondFactorWindow))
}

// requireSecondFactor 挂在敏感路由上：会话要 15 分钟内验过，自动化通道（没有会话）直接放行。
// 不为「没配发信」放行：那样二次验证就只剩名字（AGENTS.md「不写回退」）。
func (s *server) requireSecondFactor() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.secondFactorSatisfied(c) {
			c.Next()
			return
		}
		secondFactorRequired(c)
	}
}

// requireSecondFactorOnWrite 挂在平台维护那组路由上：读照常，写要 15 分钟内验过。
func (s *server) requireSecondFactorOnWrite() gin.HandlerFunc {
	return func(c *gin.Context) {
		if safeMethod(c.Request.Method) || s.secondFactorSatisfied(c) {
			c.Next()
			return
		}
		secondFactorRequired(c)
	}
}

func (s *server) secondFactorSatisfied(c *gin.Context) bool {
	session := currentAdminSession(c)
	return session == nil || secondFactorFresh(session, s.now())
}

func secondFactorRequired(c *gin.Context) {
	problem(c, http.StatusForbidden, "SECOND_FACTOR_REQUIRED",
		"This operation needs email verification within the last 15 minutes; request a code and verify it first")
	c.Abort()
}

func secondFactorMessage(to, code, account, console string) mail.Message {
	minutes := int(emailCodeTTL.Minutes())
	text := fmt.Sprintf(`控制台 %s 上的账号 %s 正在做需要二次验证的操作。

验证码：%s
%d 分钟内有效。如果不是您本人在操作，您的统一登录账号可能已被别人使用：请立即联系平台管理员停用这个控制台账号，不要把验证码告诉任何人。

The console account %s on %s is about to perform an operation that needs a second verification.

Code: %s
Valid for %d minutes. If this is not you, your unified login account may be in someone else's hands: contact the platform administrator right away to disable this console account, and do not share the code.
`, console, account, code, minutes, account, console, code, minutes)
	e := html.EscapeString
	htmlBody := fmt.Sprintf(`<!doctype html><html><body style="font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif;color:#0f172a;line-height:1.6">
<p>控制台 <b>%s</b> 上的账号 <b>%s</b> 正在做需要二次验证的操作。</p>
<p style="font-size:32px;font-weight:700;letter-spacing:8px;font-family:'Courier New',monospace">%s</p>
<p>%d 分钟内有效。如果不是您本人在操作，您的统一登录账号可能已被别人使用：请立即联系平台管理员停用这个控制台账号，不要把验证码告诉任何人。</p>
<hr style="border:none;border-top:1px solid #e2e8f0">
<p>The console account <b>%s</b> on <b>%s</b> is about to perform an operation that needs a second verification. Valid for %d minutes. If this is not you, contact the platform administrator right away to disable this console account, and do not share the code.</p>
</body></html>`, e(console), e(account), code, minutes, e(account), e(console), minutes)
	return mail.Message{To: to, Subject: "控制台二次验证码 / Console verification code", Text: text, HTML: htmlBody}
}

func (s *server) sendSecondFactorCode(c *gin.Context) {
	session := currentAdminSession(c)
	if session == nil {
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_NOT_APPLICABLE", "The automation channel does not use the email second factor")
		return
	}
	to := strings.TrimSpace(session.Account.Email)
	if !strings.Contains(to, "@") {
		problem(c, http.StatusConflict, "SECOND_FACTOR_NO_EMAIL", "This console account has no email; ask the platform administrator")
		return
	}
	ctx := c.Request.Context()
	cfg, err := s.mailConfig(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "MAIL_CONFIG_INVALID", "Stored "+mailConfigKey+" configuration is invalid")
		return
	}
	if cfg == nil {
		problem(c, http.StatusServiceUnavailable, "MAIL_NOT_CONFIGURED", "Email sending is not configured; ask the platform administrator")
		return
	}
	now := s.now()
	if !s.secondFactorCodes.allowSend(session.AccountID, c.ClientIP(), now) {
		problem(c, http.StatusTooManyRequests, "SECOND_FACTOR_CODE_RATE_LIMITED", "Too many codes requested; wait a minute and try again")
		return
	}
	code, token, err := newEmailCode()
	if err != nil {
		problem(c, http.StatusInternalServerError, "SECOND_FACTOR_CODE_FAILED", "Unable to create a verification code")
		return
	}
	expiresAt := now.Add(emailCodeTTL)
	problemCode, sendErr := s.sendMail(ctx, *cfg, secondFactorMessage(to, code, session.Account.label(), s.consoleHost(c)))
	s.auditNow(newAudit(session.auditTenant(), session.Actor, session.Account.auditAction("second_factor_code_sent"), session.Account.auditTarget(), session.AccountID, "发送二次验证码", requestID(c),
		map[string]any{"to": maskEmail(to), "sent": sendErr == nil, "problem": nullableString(problemCode)}))
	if sendErr != nil {
		problem(c, http.StatusBadGateway, mailProblemSendFail, "Unable to send the verification code; try again later")
		return
	}
	// 码只属于这个会话（subject = 会话令牌的哈希）
	s.secondFactorCodes.sent(session.AccountID, emailCode{token: token, code: code, subject: session.TokenHash, email: to, expiresAt: expiresAt}, now)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"codeToken": token, "expiresAt": iso(expiresAt), "resendAfter": int(emailCodeResendAfter.Seconds()), "email": maskEmail(to)})
}

func (s *server) verifySecondFactor(c *gin.Context) {
	var body struct {
		CodeToken string `json:"codeToken"`
		Code      string `json:"code"`
	}
	if decodeLimited(c, &body, 4<<10) != nil {
		problem(c, http.StatusBadRequest, "INVALID_SECOND_FACTOR", "codeToken and code are required")
		return
	}
	session := currentAdminSession(c)
	if session == nil {
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_NOT_APPLICABLE", "The automation channel does not use the email second factor")
		return
	}
	now := s.now()
	if !s.secondFactorCodes.verify(session.AccountID, body.CodeToken, body.Code, session.TokenHash, strings.TrimSpace(session.Account.Email), now) {
		// 失败也留痕（不记验证码）：每账号每小时最多 25 次猜测，事后要查得到
		s.auditNow(newAudit(session.auditTenant(), session.Actor, session.Account.auditAction("second_factor_failed"), session.Account.auditTarget(), session.AccountID, "二次验证码不对或已过期", requestID(c),
			map[string]any{}))
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_CODE_INVALID", "The verification code is invalid or expired")
		return
	}
	ctx := c.Request.Context()
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_sessions SET second_factor_at=? WHERE token_hash=?`, now, session.TokenHash); err != nil {
		problem(c, http.StatusInternalServerError, "SECOND_FACTOR_SAVE_FAILED", "Unable to record the verification")
		return
	}
	s.auditNow(newAudit(session.auditTenant(), session.Actor, session.Account.auditAction("second_factor_verified"), session.Account.auditTarget(), session.AccountID, "通过二次验证", requestID(c),
		map[string]any{"validUntil": iso(now.Add(secondFactorWindow))}))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"secondFactorUntil": iso(now.Add(secondFactorWindow))})
}
