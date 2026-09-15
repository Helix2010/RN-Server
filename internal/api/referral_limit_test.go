package api

import (
	"testing"
	"time"
)

// 未命中子配额是设计 §4.3 的核心分离手段（真实用户几乎不会未命中，扫描器 100% 未命中）。
// 它曾经算出来却只写进日志，等于闸门是假的——这条守住"耗尽之后必须返回 false"。
func TestReferralLookupMissQuotaExhausts(t *testing.T) {
	var l referralLimiter
	now := time.Now().UTC()
	for i := 0; i < referralLookupMissPerHour; i++ {
		if !l.allowLookupMiss("203.0.113.7", now) {
			t.Fatalf("miss %d should still be inside the quota", i+1)
		}
	}
	if l.allowLookupMiss("203.0.113.7", now) {
		t.Fatal("the miss past the quota must be rejected, otherwise the stricter sub-quota does nothing")
	}
	// 配额是按 IP 分的，另一个 IP 不受影响
	if !l.allowLookupMiss("203.0.113.8", now) {
		t.Fatal("the quota must be per-IP")
	}
	// 窗口到点自然放行
	if !l.allowLookupMiss("203.0.113.7", now.Add(time.Hour+time.Second)) {
		t.Fatal("the quota must reset when the window rolls over")
	}
}

// 补录配额限的是"今天改成了多少条关系"，不是"今天按错几次键"：
// 地址打错 20 次之后，当天真正要补的那条还得能补。
func TestReferralAdminBindQuotaCountsSuccessesOnly(t *testing.T) {
	var l referralLimiter
	now := time.Now().UTC()
	tenant := "tnt_demo"
	// 只查不记：失败的补录走的就是这条路径
	for i := 0; i < 100; i++ {
		if l.adminBindQuotaExhausted(tenant, now) {
			t.Fatalf("checking the quota must not consume it (iteration %d)", i)
		}
	}
	for i := 0; i < referralAdminBindPerDay; i++ {
		if l.adminBindQuotaExhausted(tenant, now) {
			t.Fatalf("success %d should still be inside the quota", i+1)
		}
		l.recordAdminBind(tenant, now)
	}
	if !l.adminBindQuotaExhausted(tenant, now) {
		t.Fatal("the quota must be exhausted after the configured number of successful backfills")
	}
	if l.adminBindQuotaExhausted("tnt_other", now) {
		t.Fatal("the quota must be per-tenant")
	}
}

// 绑定配额：会话与 IP 两条都要过。
func TestReferralBindQuotaCoversSessionAndIP(t *testing.T) {
	var l referralLimiter
	now := time.Now().UTC()
	for i := 0; i < referralBindPerHourSession; i++ {
		if !l.allowBind("ses_a", "198.51.100.4", now) {
			t.Fatalf("bind %d should be allowed", i+1)
		}
	}
	if l.allowBind("ses_a", "198.51.100.4", now) {
		t.Fatal("the per-session quota must stop the same session")
	}
	// 换个会话、同一个 IP：IP 那条还没满，应当放行
	if !l.allowBind("ses_b", "198.51.100.4", now) {
		t.Fatal("a different session on the same IP is still inside the IP quota")
	}
}

// 注册链路的限流是邀请关系的发布门禁（设计 §6 第 2 条 / D13）：
// 造号的真正瓶颈是 auth/verify，wallet_user 在它这里创建。
func TestRegistrationLimiterCapsAccountCreation(t *testing.T) {
	var l registrationLimiter
	now := time.Now().UTC()
	ip := "192.0.2.9"
	allowed := 0
	// 一小时里逐分钟推进，避免撞上每分钟的突发上限，量到每小时那条真正的上界
	for minute := 0; minute < 60; minute++ {
		at := now.Add(time.Duration(minute) * time.Minute)
		for i := 0; i < authVerifyPerMinute; i++ {
			if l.allowVerify(ip, at) {
				allowed++
			}
		}
	}
	if allowed != authVerifyPerHour {
		t.Fatalf("an IP got %d verifies in one hour, want the hourly cap %d", allowed, authVerifyPerHour)
	}
	if l.allowVerify("192.0.2.10", now) != true {
		t.Fatal("the cap must be per-IP")
	}
}

// 每分钟的突发上限必须比每小时先咬住，否则一秒钟就能把一小时的额度打光。
func TestRegistrationLimiterBurstStopsBeforeHourly(t *testing.T) {
	var l registrationLimiter
	now := time.Now().UTC()
	ip := "192.0.2.11"
	for i := 0; i < authNoncePerMinute; i++ {
		if !l.allowNonce(ip, now) {
			t.Fatalf("nonce %d should be inside the burst allowance", i+1)
		}
	}
	if l.allowNonce(ip, now) {
		t.Fatal("the per-minute burst cap must reject the next request in the same minute")
	}
	if !l.allowNonce(ip, now.Add(time.Minute+time.Second)) {
		t.Fatal("the next minute must open up again")
	}
}
