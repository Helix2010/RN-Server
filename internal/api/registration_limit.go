package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

/*
注册链路的限流（设计 referral-graph-2026-09-15 §6 第 2 条 / ADR 0018 决策 D13）。

三步 `installations/register` -> `auth/nonce` -> `auth/verify` 全部免鉴权，在此之前
零限流：3 个 HTTP 请求就能造出一个 wallet_user。邀请关系上线后这条链路等于给
Sybil 关系树配了出口，而**关系永久不可解绑**、封禁也不清 inviter_user_id，
事后无法结构化清理。所以设计把这条限流定为与邀请关系同窗口上线的发布门禁。

阈值按"真人几乎不可能碰到、脚本一定碰到"取：

  - 真人一次安装只注册一次 installation，一次登录一对 nonce/verify；
    网络抖动下的重试是个位数。
  - 账号创建的实际瓶颈是 auth/verify——wallet_user 在它这里创建。
    60 次/小时/IP 把单 IP 的造号速度从"无上限"压到 60/小时。

阈值取得偏松是有意的：运营商级 NAT 与办公室出口会让几十个真人共用一个 IP，
宁可放过也不误伤——这条闸的目的是掐掉脚本化的批量造号，不是精确风控。
真要收紧，等线上有了分布形状再调，别凭空拍一个更小的数。

计数器与邀请那套共用 windowCounter（固定窗口、超出不再累加、超一万个 key 顺手清）。
*/

const (
	// registerInstallPerHour 安装注册：每小时每 IP。
	registerInstallPerHour = 30
	// registerInstallPerMinute 同上的突发上限。
	registerInstallPerMinute = 10
	// authNoncePerHour 取 nonce：每小时每 IP。一次登录一个。
	authNoncePerHour = 60
	// authNoncePerMinute 同上的突发上限。
	authNoncePerMinute = 20
	// authVerifyPerHour 校验签名：每小时每 IP。账号在这一步创建，是造号的真正瓶颈。
	authVerifyPerHour = 60
	// authVerifyPerMinute 同上的突发上限。
	authVerifyPerMinute = 20
)

// registrationLimiter 注册链路三步各自的每小时 / 每分钟计数。零值可用。
type registrationLimiter struct {
	installHour, installMinute windowCounter
	nonceHour, nonceMinute     windowCounter
	verifyHour, verifyMinute   windowCounter
}

func (l *registrationLimiter) allowInstall(ip string, now time.Time) bool {
	return l.installMinute.allow(ip, registerInstallPerMinute, time.Minute, now) &&
		l.installHour.allow(ip, registerInstallPerHour, time.Hour, now)
}

func (l *registrationLimiter) allowNonce(ip string, now time.Time) bool {
	return l.nonceMinute.allow(ip, authNoncePerMinute, time.Minute, now) &&
		l.nonceHour.allow(ip, authNoncePerHour, time.Hour, now)
}

func (l *registrationLimiter) allowVerify(ip string, now time.Time) bool {
	return l.verifyMinute.allow(ip, authVerifyPerMinute, time.Minute, now) &&
		l.verifyHour.allow(ip, authVerifyPerHour, time.Hour, now)
}

// throttleRegistration 把一条注册链路的配额包成中间件。
//
// 拒绝返回 429 REGISTRATION_RATE_LIMITED，并且**告警**：真人碰不到这条线，
// 一旦有人碰到，要么是脚本，要么是阈值定错了，两种都需要有人看见。
func throttleRegistration(step string, allow func(ip string, now time.Time) bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !allow(c.ClientIP(), time.Now().UTC()) {
			slog.Error("registration step throttled",
				"step", step, "tenant", tenantID(c), "clientIp", c.ClientIP(), "requestId", requestID(c))
			problem(c, http.StatusTooManyRequests, "REGISTRATION_RATE_LIMITED",
				"Too many attempts from this address; try again later")
			c.Abort()
			return
		}
		c.Next()
	}
}
