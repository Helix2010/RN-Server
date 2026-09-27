package api

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/mail"
	"github.com/gin-gonic/gin"
)

// 租户会话的二次验证（设计 tenant-console-accounts-and-sso §4.5；2026-09-27 用户定为邮箱验证码，不用验证器 App）。
//
// 认证中心不告诉我们对方怎么登录、何时登录的，统一账号口令泄露就等于进了控制台。所以做敏感操作前，
// 再给成员**自己登记的邮箱**（平台管理员建号时填的，不是统一账号的邮箱）发一个验证码：验过之后这个会话
// 15 分钟内可以做敏感操作。待绑定的成员发起绑定前也要先验，挡住「初始口令泄露、被别人抢先绑定」。
// 平台会话（ADMIN_USERNAME、管理密钥）不用：它没有邮箱，而且口令本身只在平台手里。
//
//	POST /v1/admin/auth/second-factor/code    {} → {codeToken, expiresAt, resendAfter, email（掩码）}；没配发信 503 MAIL_NOT_CONFIGURED
//	POST /v1/admin/auth/second-factor/verify  {codeToken, code} → {secondFactorUntil}；不对 400 SECOND_FACTOR_CODE_INVALID
//
// 验证码沿用绑定验证码那套存法与限流（bindCodeStore：10 分钟、用一次、错 5 次作废；每账号 1 分钟 1 次、
// 1 小时 5 次，每 IP 1 小时 20 次），而且只属于发码的那个会话：换个会话拿着 codeToken 也验不过。

const secondFactorWindow = 15 * time.Minute

// secondFactorFresh：租户会话 15 分钟内验过。
func secondFactorFresh(session *adminSession, now time.Time) bool {
	return !session.SecondFactorAt.IsZero() && now.Before(session.SecondFactorAt.Add(secondFactorWindow))
}

// requireSecondFactor 挂在敏感路由上：租户会话要 15 分钟内验过，平台会话直接放行。
// 不为「没配发信」放行：那样二次验证就只剩名字（AGENTS.md「不写回退」）。
func (s *server) requireSecondFactor() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := currentAdminSession(c)
		if !session.tenantScoped() || secondFactorFresh(session, s.now()) {
			c.Next()
			return
		}
		problem(c, http.StatusForbidden, "SECOND_FACTOR_REQUIRED",
			"This operation needs email verification within the last 15 minutes; request a code and verify it first")
		c.Abort()
	}
}

func secondFactorMessage(to, code, loginName, console string) mail.Message {
	minutes := int(bindCodeTTL.Minutes())
	text := fmt.Sprintf(`控制台 %s 的成员账号 %s 正在做需要二次验证的操作。

验证码：%s
%d 分钟内有效。如果不是您本人在操作，您的统一登录账号可能已被别人使用：请立即联系平台管理员停用这个控制台账号，不要把验证码告诉任何人。

The console member %s on %s is about to perform an operation that needs a second verification.

Code: %s
Valid for %d minutes. If this is not you, your unified login account may be in someone else's hands: contact the platform administrator right away to disable this console account, and do not share the code.
`, console, loginName, code, minutes, loginName, console, code, minutes)
	e := html.EscapeString
	htmlBody := fmt.Sprintf(`<!doctype html><html><body style="font-family:-apple-system,BlinkMacSystemFont,'PingFang SC','Microsoft YaHei',sans-serif;color:#0f172a;line-height:1.6">
<p>控制台 <b>%s</b> 的成员账号 <b>%s</b> 正在做需要二次验证的操作。</p>
<p style="font-size:32px;font-weight:700;letter-spacing:8px;font-family:'Courier New',monospace">%s</p>
<p>%d 分钟内有效。如果不是您本人在操作，您的统一登录账号可能已被别人使用：请立即联系平台管理员停用这个控制台账号，不要把验证码告诉任何人。</p>
<hr style="border:none;border-top:1px solid #e2e8f0">
<p>The console member <b>%s</b> on <b>%s</b> is about to perform an operation that needs a second verification. Valid for %d minutes. If this is not you, contact the platform administrator right away to disable this console account, and do not share the code.</p>
</body></html>`, e(console), e(loginName), code, minutes, e(loginName), e(console), minutes)
	return mail.Message{To: to, Subject: "控制台二次验证码 / Console verification code", Text: text, HTML: htmlBody}
}

func (s *server) sendSecondFactorCode(c *gin.Context) {
	session := currentAdminSession(c)
	if !session.tenantScoped() {
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_NOT_APPLICABLE", "Platform sessions do not use the email second factor")
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
	code, token, err := newBindCode()
	if err != nil {
		problem(c, http.StatusInternalServerError, "SECOND_FACTOR_CODE_FAILED", "Unable to create a verification code")
		return
	}
	expiresAt := now.Add(bindCodeTTL)
	problemCode, sendErr := s.sendMail(ctx, *cfg, secondFactorMessage(to, code, session.Account.LoginName, s.consoleHost(c)))
	s.auditNow(newAudit(session.TenantID, session.Actor, "tenant_account_second_factor_code_sent", "tenant-account", session.AccountID, "发送二次验证码", requestID(c),
		map[string]any{"to": maskEmail(to), "sent": sendErr == nil, "problem": nullableString(problemCode)}))
	if sendErr != nil {
		problem(c, http.StatusBadGateway, mailProblemSendFail, "Unable to send the verification code; try again later")
		return
	}
	// 码只属于这个会话（subject = 会话令牌的哈希）
	s.secondFactorCodes.sent(session.AccountID, bindCode{token: token, code: code, subject: session.TokenHash, email: to, expiresAt: expiresAt}, now)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"codeToken": token, "expiresAt": iso(expiresAt), "resendAfter": int(bindCodeResendAfter.Seconds()), "email": maskEmail(to)})
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
	if !session.tenantScoped() {
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_NOT_APPLICABLE", "Platform sessions do not use the email second factor")
		return
	}
	now := s.now()
	if !s.secondFactorCodes.verify(session.AccountID, body.CodeToken, body.Code, session.TokenHash, strings.TrimSpace(session.Account.Email), now) {
		problem(c, http.StatusBadRequest, "SECOND_FACTOR_CODE_INVALID", "The verification code is invalid or expired")
		return
	}
	ctx := c.Request.Context()
	if _, err := s.db.ExecContext(ctx, `UPDATE admin_sessions SET second_factor_at=? WHERE token_hash=?`, now, session.TokenHash); err != nil {
		problem(c, http.StatusInternalServerError, "SECOND_FACTOR_SAVE_FAILED", "Unable to record the verification")
		return
	}
	s.auditNow(newAudit(session.TenantID, session.Actor, "tenant_account_second_factor_verified", "tenant-account", session.AccountID, "通过二次验证", requestID(c),
		map[string]any{"validUntil": iso(now.Add(secondFactorWindow))}))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"secondFactorUntil": iso(now.Add(secondFactorWindow))})
}
