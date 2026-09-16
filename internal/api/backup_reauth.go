package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// 「跑一次」和「下载」要重新输一次管理员口令。
//
// 理由写在设计 §6 最后一段：控制台只有一个登录账号，平台管理员白名单实际等于
// 「凡是能登录的人都看得见」，而会话 TTL 默认 8 小时。没有这一道，一个被偷走的
// cookie 在 8 小时内可以把桶里每一条 succeeded 记录的包逐个拉走——每一个包都是
// 全平台每个租户的签名密钥。
//
// 它不能阻止一个同时拿到 cookie 和口令的人，但它把攻击面从「一个 cookie + 一把
// 私钥」抬回「一个 cookie + 口令 + 一把私钥」。设计把这条叫「今天便宜的补偿」。

const (
	backupTicketTTL      = 2 * time.Minute
	backupReauthWindow   = 5 * time.Minute
	backupReauthMaxTries = 5
)

type backupTicket struct {
	seq     uint64
	pair    string
	actor   string
	expires time.Time
}

// 零值可用：服务端在测试里有很多条直接造 &server{} 的路，让这个结构必须被
// 构造函数初始化，等于给自己留一条 nil 解引用
type backupReauth struct {
	mu      sync.Mutex
	tickets map[string]backupTicket
	// fails 是按操作者计的失败次数。口令校验没有任何限速时，一个拿到 cookie 的人
	// 可以在同一个会话里不限次数地猜口令——而口令是这道补偿的全部内容
	fails map[string][]time.Time
}

// init 在锁内补齐 map。调用方全都已经持锁
func (r *backupReauth) init() {
	if r.tickets == nil {
		r.tickets = map[string]backupTicket{}
	}
	if r.fails == nil {
		r.fails = map[string][]time.Time{}
	}
}

// checkPassword 校验口令并计失败次数。返回 false 时调用方直接拒绝。
func (r *backupReauth) checkPassword(actor, password, hash string) (ok bool, throttled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	now := time.Now()
	recent := r.fails[actor][:0]
	for _, at := range r.fails[actor] {
		if now.Sub(at) < backupReauthWindow {
			recent = append(recent, at)
		}
	}
	r.fails[actor] = recent
	if len(recent) >= backupReauthMaxTries {
		return false, true
	}
	if !verifyPassword(password, hash) {
		r.fails[actor] = append(r.fails[actor], now)
		return false, false
	}
	delete(r.fails, actor)
	return true, false
}

// issue 发一张一次性票据。下载走的是普通链接（包有几十 MB，让浏览器流式落盘
// 比在内存里攒 blob 靠谱），链接带不了请求体，所以口令换票、票换文件。
func (r *backupReauth) issue(seq uint64, pair, actor string) string {
	token := randomID(32)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	now := time.Now()
	for key, ticket := range r.tickets {
		if now.After(ticket.expires) {
			delete(r.tickets, key)
		}
	}
	r.tickets[token] = backupTicket{seq: seq, pair: pair, actor: actor, expires: now.Add(backupTicketTTL)}
	return token
}

// redeem 用掉一张票据。一次性：用过就删，防止链接被复制之后反复下载。
func (r *backupReauth) redeem(token string, seq uint64, pair, actor string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	ticket, ok := r.tickets[token]
	if !ok {
		return false
	}
	delete(r.tickets, token)
	return time.Now().Before(ticket.expires) &&
		ticket.seq == seq && ticket.pair == pair && constantEqual(ticket.actor, actor)
}

// requireBackupPassword 是 run / 发票据 这两个动作共用的口令闸。
func (s *server) requireBackupPassword(c *gin.Context, password string) bool {
	if strings.TrimSpace(s.cfg.AdminPasswordHash) == "" {
		// 没配口令哈希时不能静默放行：那等于这道闸不存在，而调用方以为它在
		problem(c, http.StatusPreconditionFailed, "BACKUP_REAUTH_UNAVAILABLE",
			"ADMIN_PASSWORD_HASH is not configured, so the password check cannot run")
		return false
	}
	ok, throttled := s.backupReauth.checkPassword(actor(c), password, s.cfg.AdminPasswordHash)
	if throttled {
		problem(c, http.StatusTooManyRequests, "BACKUP_REAUTH_THROTTLED",
			"too many wrong passwords; wait a few minutes")
		return false
	}
	if !ok {
		s.auditNow(newAudit(platformTenantID, actor(c), "backup_reauth_failed", "platform-backup", "",
			"a wrong password was entered for a backup action", requestID(c), nil))
		problem(c, http.StatusForbidden, "BACKUP_REAUTH_FAILED", "the password does not match")
		return false
	}
	return true
}

// issueBackupDownloadTicket 用口令换一张两分钟的一次性票据。
func (s *server) issueBackupDownloadTicket(c *gin.Context) {
	var body struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		problem(c, http.StatusBadRequest, "BACKUP_TICKET_INVALID", "password is required")
		return
	}
	run, found, ok := s.backupObjectFor(c)
	if !ok {
		return
	}
	if !s.requireBackupPassword(c, body.Password) {
		return
	}
	token := s.backupReauth.issue(run.Seq, found.Pair, actor(c))
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"ticket":    token,
		"expiresIn": int(backupTicketTTL.Seconds()),
	})
}
