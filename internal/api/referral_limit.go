package api

import (
	"sync"
	"time"
)

/*
邀请接口的限流（设计 §4.3）。

形态照 diagnostics.go 的 diagnosticIPLimiter：内存里的窗口计数。**它按实例计数、
只挡单一来源**——如实记着这一点，不要把它当成强闸。真正的成本壁垒是 32^8 的码空间
与"codes 只返回 valid"这两件事，限流只是别让扫描器白嫖。

两个容易漏的点：
  - 落地页 GET /app/invite/:code 与 GET /v1/mobile/referral/codes/:code 必须共用
    同一个计数器。它们是同一个 oracle，分开计等于限流白做。
  - 未命中单独再记一份更严的配额。真实用户一生解析一两个码、几乎不会未命中，
    扫描器 100% 未命中，两类人群在这个阈值上干净分离（照 server.go 的 failedLogin
    只计失败的既有做法）。
*/

const (
	// referralLookupPerHour 解析邀请码：每小时每 IP。真实用户一生一两次，留了千倍余量。
	referralLookupPerHour = 30
	// referralLookupPerMinute 同上的突发上限。
	referralLookupPerMinute = 10
	// referralLookupMissPerHour 其中"未命中"的更严子配额；超出则该窗口内全部拒绝。
	referralLookupMissPerHour = 10
	// referralBindPerHourSession 绑定：每小时每会话。绑定一生一次，5 次足够覆盖手误。
	referralBindPerHourSession = 5
	// referralBindPerHourIP 绑定：每小时每 IP。
	referralBindPerHourIP = 20
	// referralUnknownPerDayTenant 租户级底线：未知码查询每天每租户。**告警不阻断**，
	// 用来发现"正在被扫"，不用来拦人（照 diagnosticTenantPerDay 的形态）。
	referralUnknownPerDayTenant = 50000
)

// windowCounter 一个固定窗口的计数。零值可用。
type windowCounter struct {
	mu      sync.Mutex
	windows map[string]windowEntry
}

type windowEntry struct {
	count    int
	resetsAt time.Time
}

// exhausted 只看配额用完没有，**不记数**。给"先判断能不能做、做成了再计数"的
// 调用方用（见 allowAdminBind / recordAdminBind）。
func (w *windowCounter) exhausted(key string, limit int, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.windows[key]
	if !ok || now.After(entry.resetsAt) {
		return false
	}
	return entry.count >= limit
}

// allow 记一次并返回是否还在配额内。超出配额时**不再累加**，避免持续攻击把窗口
// 末尾的正常请求也算进去（窗口到点就自然放行）。
func (w *windowCounter) allow(key string, limit int, window time.Duration, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.windows == nil {
		w.windows = map[string]windowEntry{}
	}
	// 过期窗口顺手清掉，否则每个来过一次的 key 都会永久占一格
	if len(w.windows) > 10_000 {
		for k, entry := range w.windows {
			if now.After(entry.resetsAt) {
				delete(w.windows, k)
			}
		}
	}
	entry := w.windows[key]
	if now.After(entry.resetsAt) {
		entry = windowEntry{resetsAt: now.Add(window)}
	}
	if entry.count >= limit {
		w.windows[key] = entry
		return false
	}
	entry.count++
	w.windows[key] = entry
	return true
}

// referralLimiter 把上面几个配额聚在一起。零值可用（测试里的 server 不初始化它）。
type referralLimiter struct {
	lookupHour   windowCounter
	lookupMinute windowCounter
	lookupMiss   windowCounter
	bindSession  windowCounter
	bindIP       windowCounter
	unknownDay   windowCounter
	adminBindDay windowCounter
}

// allowLookup 解析邀请码（接口与落地页共用）。key 用来源 IP。
func (l *referralLimiter) allowLookup(ip string, now time.Time) bool {
	if !l.lookupMinute.allow(ip, referralLookupPerMinute, time.Minute, now) {
		return false
	}
	return l.lookupHour.allow(ip, referralLookupPerHour, time.Hour, now)
}

// allowLookupMiss 在一次解析未命中之后调用，返回 false 表示该 IP 的未命中配额已耗尽。
func (l *referralLimiter) allowLookupMiss(ip string, now time.Time) bool {
	return l.lookupMiss.allow(ip, referralLookupMissPerHour, time.Hour, now)
}

// allowBind 绑定。会话与 IP 两条都要过。
func (l *referralLimiter) allowBind(sessionID, ip string, now time.Time) bool {
	if !l.bindSession.allow(sessionID, referralBindPerHourSession, time.Hour, now) {
		return false
	}
	return l.bindIP.allow(ip, referralBindPerHourIP, time.Hour, now)
}

// withinTenantUnknownBudget 记一次未知码查询，返回 false 表示这个租户今天的未知码
// 查询已经超过底线——调用方**只告警不阻断**。
func (l *referralLimiter) withinTenantUnknownBudget(tenant string, now time.Time) bool {
	return l.unknownDay.allow(tenant, referralUnknownPerDayTenant, 24*time.Hour, now)
}

// adminBindQuotaExhausted 管理端补录的租户级日配额，**只看不记**。补录豁免绑定
// 窗口、不可回滚，而管理端除登录外全线无限流——这条是它自己的闸（设计 §4.4）。
//
// 配额记在 recordAdminBind，也就是补录真的成功之后。这条闸限的是"今天改了多少条
// 关系"，不是"今天按错几次键"：地址打错、人还没登录过这类失败不该吃配额，否则
// 运营连打错 20 次，当天真正要补的那条就被自己挡在门外了。
func (l *referralLimiter) adminBindQuotaExhausted(tenant string, now time.Time) bool {
	return l.adminBindDay.exhausted(tenant, referralAdminBindPerDay, now)
}

// recordAdminBind 在补录成功之后记一次配额。
func (l *referralLimiter) recordAdminBind(tenant string, now time.Time) {
	l.adminBindDay.allow(tenant, referralAdminBindPerDay, 24*time.Hour, now)
}
