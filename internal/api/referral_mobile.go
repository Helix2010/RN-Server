package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/referral"
	"github.com/gin-gonic/gin"
)

/*
移动端的邀请接口（设计 §4.2）。

一条贯穿全文件的规则：**响应里不出现任何地址派生值**。
shortenAddress 的前 6 后 4 是 8 个 hex nibble = 32 bit，候选集 1e6 时期望碰撞 2.3e-4，
对任何现实候选集都等同于唯一键——把下级列表变成去匿名化接口。所以：
  - 邀请人身份用**邀请码**表示（用户本来就是拿着那个码来的）；
  - 下级用 per-viewer 别名；
  - codes/:code 只返回 valid。
*/

// referralAliasKey 派生别名用的子密钥。
//
// 不新增环境变量（AGENTS.md：新增 env 之前先问"这个值别处能不能知道"），
// 从已有的 STORAGE_MASTER_KEY 用固定标签派生一把专用子钥，与设备归并那把
// DEVICE_IDENTITY_HMAC_KEY 做域分离，互不影响。
func (s *server) referralAliasKey() ([]byte, error) {
	raw := strings.TrimSpace(s.cfg.StorageMasterKey)
	if raw == "" {
		return nil, errors.New("referral alias key: STORAGE_MASTER_KEY is not configured")
	}
	master, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		master, err = base64.StdEncoding.DecodeString(raw)
	}
	if err != nil || len(master) != 32 {
		return nil, errors.New("referral alias key: STORAGE_MASTER_KEY is not a 32-byte base64 value")
	}
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte("rn-referral-alias-v1"))
	return mac.Sum(nil), nil
}

// referralInviteLinkBase 邀请链接的基址。由服务端算，App 不自己拼——落地页是服务端的，
// 路径规则只该有一个来源（设计 §3.6）。
func referralInviteLinkBase(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil && strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "http") {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host + referralInvitePath
}

// referralInvitePath 落地页与 App Links 的路径前缀。**带尾斜杠**：
// Android 的 pathPrefix 是前缀匹配，不带斜杠会把 /app/invitexyz 也吃进来。
const referralInvitePath = "/app/invite/"

// ---------- GET /v1/mobile/referral/me ----------

func (s *server) referralMe(c *gin.Context) {
	session, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	tenant := tenantID(c)
	settings, err := s.referralSettingsOf(c.Request.Context(), tenant)
	if err != nil {
		slog.Error("referral settings read failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}

	var inviteCode sql.NullString
	var firstSeen time.Time
	var inviterID sql.NullInt64
	var invitedAt sql.NullTime
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT invite_code, first_seen_at, inviter_user_id, invited_at FROM wallet_user WHERE id=? AND tenant_id=?`,
		session.UserID, tenant).Scan(&inviteCode, &firstSeen, &inviterID, &invitedAt); err != nil {
		slog.Error("referral me read failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}
	// 不变量：提交后的每一行都有码。读到 NULL 是事故，按正式场景原则报错，
	// 不在读路径上现场补一个（设计 §3.3）。
	if !inviteCode.Valid {
		slog.Error("wallet user has no invite code", "tenant", tenant, "userId", session.UserID, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}

	var inviter any
	if inviterID.Valid {
		var inviterCode sql.NullString
		if err := s.db.QueryRowContext(c.Request.Context(),
			`SELECT invite_code FROM wallet_user WHERE id=? AND tenant_id=?`, inviterID.Int64, tenant).Scan(&inviterCode); err != nil {
			slog.Error("referral inviter read failed", "error", err, "requestId", requestID(c))
			problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
			return
		}
		inviter = gin.H{"inviteCode": inviterCode.String, "boundAt": iso(invitedAt.Time)}
	}

	var inviteeCount int
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT COUNT(*) FROM wallet_user WHERE tenant_id=? AND inviter_user_id=?`, tenant, session.UserID).Scan(&inviteeCount); err != nil {
		slog.Error("referral invitee count failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}

	closesAt := firstSeen.Add(time.Duration(settings.BindWindowHours) * time.Hour)
	c.JSON(http.StatusOK, gin.H{
		"inviteCode": inviteCode.String,
		"inviteLink": referralInviteLinkBase(c) + inviteCode.String,
		"inviter":    inviter,
		"bindWindow": gin.H{
			// settings.Enabled 必须算进 open：租户关掉邀请之后仍报 open=true，
			// App 会照常显示输入框，用户填完拿到 403 REFERRAL_DISABLED。
			// open 的语义是"现在提交会被接受吗"，不是"窗口期过了没有"
			"open":     settings.Enabled && !inviterID.Valid && time.Now().UTC().Before(closesAt),
			"closesAt": iso(closesAt),
		},
		"inviteeCount": inviteeCount,
	})
}

// ---------- POST /v1/mobile/referral/bind ----------

func (s *server) referralBind(c *gin.Context) {
	session, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	var body struct {
		Code   string `json:"code"`
		Source string `json:"source"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_REFERRAL_BIND", "Invalid bind payload")
		return
	}
	// source 只用于运营统计、不参与判定，但取值仍然限死：admin 只能由管理端路径写入
	source := strings.ToLower(strings.TrimSpace(body.Source))
	if source != "code" && source != "link" {
		problem(c, 422, "INVALID_REFERRAL_BIND", "source must be either code or link")
		return
	}
	if !s.referrals.allowBind(session.ID, c.ClientIP(), time.Now().UTC()) {
		problem(c, 429, "REFERRAL_RATE_LIMITED", "Too many bind attempts; try again later")
		return
	}

	result, outcome := s.bindReferral(c, bindRequest{
		Tenant:    tenantID(c),
		InviteeID: session.UserID,
		RawCode:   body.Code,
		Source:    source,
		ActorID:   "system-referral",
		Reason:    "self-service bind via " + source,
	})
	if outcome != nil {
		// 失败也要留痕：全仓没有访问日志中间件，problem() 也不写日志，
		// 照原样实现的话失败绑定在应用层零记录（设计 §4.5）。不记完整邀请码。
		slog.Warn("referral bind rejected",
			"tenant", tenantID(c), "code", outcome.Code, "source", source,
			"clientIp", c.ClientIP(), "requestId", requestID(c))
		problem(c, outcome.Status, outcome.Code, outcome.Detail)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"inviter": gin.H{"inviteCode": result.InviterCode, "boundAt": iso(result.BoundAt)},
		"boundAt": iso(result.BoundAt),
	})
}

// ---------- GET /v1/mobile/referral/invitees ----------

func (s *server) referralInvitees(c *gin.Context) {
	session, ok := s.authenticateWalletSession(c)
	if !ok {
		return
	}
	tenant := tenantID(c)
	page, invalid := parseListPage(c, sortKey{"invited_at", cursorTime}, sortKey{"id", cursorUint})
	if invalid != "" {
		problem(c, 422, "INVALID_REFERRAL_FILTER", invalid)
		return
	}
	aliasKey, err := s.referralAliasKey()
	if err != nil {
		slog.Error("referral alias key unavailable", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}

	rows, total, err := s.referralInviteesPage(c.Request.Context(), tenant, session.UserID, page)
	if err != nil {
		slog.Error("referral invitees query failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_READ_FAILED", "Unable to read referral state")
		return
	}

	items, cursors := []gin.H{}, []string{}
	for _, row := range rows {
		items = append(items, gin.H{
			"alias":    referralAlias(aliasKey, session.UserID, row.ID),
			"joinedAt": iso(row.JoinedAt),
		})
		cursors = append(cursors, encodeListCursor(row.JoinedAt, row.ID))
	}
	items, next := finishListPage(items, cursors, page.limit)
	c.JSON(http.StatusOK, listResponse(items, total, next, page.limit))
}

// inviteeRow 是下级列表的一行原始数据。地址与任何地址派生值都不出现在这里：
// 别名由调用方按观察者算（referralAlias）。
type inviteeRow struct {
	ID       uint64
	JoinedAt time.Time
}

// referralInviteesPage 是下级列表的查询部分：where、总数、键集翻页多取一行。
//
// handler 与库测共用它。测试如果自己抄一份 where，handler 哪天漏掉
// invited_at IS NOT NULL，测试照样全绿——而那恰好是这条测试要守的东西
// （设计 §8.1 点名"验证 inviter_user_id IS NOT NULL 这条"）。
func (s *server) referralInviteesPage(ctx context.Context, tenant string, viewerID uint64, page listPage) ([]inviteeRow, int, error) {
	where := sqlWhere{}
	where.add("tenant_id=?", tenant)
	where.add("inviter_user_id=?", viewerID)
	// 显式排除 invited_at 为空的行：键集分页的游标条件里 NULL<? 不为真，这类行会被
	// 翻页全部跳过，而 COUNT(*) 仍把它算进去，total 与可翻页数就对不上。CHECK 约束
	// 已经挡住新数据，这一条是让查询自身也成立（设计 §4.2）。
	where.add("invited_at IS NOT NULL")

	total, err := s.countListRows(ctx, "wallet_user", where)
	if err != nil {
		return nil, 0, err
	}

	query := where.and(page.after)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, invited_at FROM wallet_user WHERE `+query.sql()+` ORDER BY invited_at DESC, id DESC LIMIT ?`,
		append(query.args, page.limit+1)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []inviteeRow{}
	for rows.Next() {
		var row inviteeRow
		if err := rows.Scan(&row.ID, &row.JoinedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ---------- GET /v1/mobile/referral/codes/:code ----------

// referralCodeLookup 免登录的邀请码校验。
//
// **只返回 valid**。原先设计里返回邀请人脱敏地址，评审指出那等于提供一个
// "码 -> 32 bit 地址指纹"的 oracle；现在它只回答"这个码有效吗"，风险来自
// 返回内容而不是尝试次数（盲枚举本来就不可行：命中率 N/1.1e12）。
//
// 落地页 GET /app/invite/:code 走同一个函数体，共用同一个限流计数器。
func (s *server) referralCodeLookup(c *gin.Context) {
	if _, outcome := s.lookupInviteCode(c, c.Param("code")); outcome != nil {
		problem(c, outcome.Status, outcome.Code, outcome.Detail)
		return
	}
	// 走到这里就是命中：无效的码在上面已经按 404 / 422 / 429 返回了，
	// 200 只有 valid=true 一种取值
	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// lookupInviteCode 是解析邀请码的公共实现：限流、归一化、查库、留痕。
// 第一个返回值是归一化后的码，调用方直接用，不要再 Normalize 一遍；
// outcome 非 nil 即未命中，此时码为空串。
func (s *server) lookupInviteCode(c *gin.Context, rawCode string) (string, *referralBindOutcome) {
	now := time.Now().UTC()
	ip := c.ClientIP()
	if !s.referrals.allowLookup(ip, now) {
		s.auditNow(auditEvent{
			ID: "aud_" + randomID(16), TenantID: tenantID(c), ActorID: "system-referral",
			Action: "referral_enumeration_throttled", TargetType: "referral-code", TargetID: "",
			Reason: "invite code lookup rate limit reached", RequestID: requestID(c), CreatedAt: iso(now),
			Summary: map[string]any{"clientIp": ip},
		})
		return "", &referralErrLookupLimited
	}

	settings, err := s.referralSettingsOf(c.Request.Context(), tenantID(c))
	if err != nil {
		slog.Error("referral settings read failed", "error", err, "requestId", requestID(c))
		return "", &referralBindOutcome{"REFERRAL_READ_FAILED", http.StatusInternalServerError, "Unable to read referral state"}
	}
	// 租户没开启就当这个码不存在：不透露"这个租户存在但没开"
	if !settings.Enabled {
		return "", &referralErrUnknown
	}

	code, ok := referral.Normalize(rawCode)
	if !ok {
		if !s.recordInviteCodeMiss(c, ip, now, "malformed") {
			return "", &referralErrLookupLimited
		}
		return "", &referralErrMalformed
	}
	var exists int
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT COUNT(*) FROM wallet_user WHERE tenant_id=? AND invite_code=?`, tenantID(c), code).Scan(&exists); err != nil {
		slog.Error("referral code lookup failed", "error", err, "requestId", requestID(c))
		return "", &referralBindOutcome{"REFERRAL_READ_FAILED", http.StatusInternalServerError, "Unable to read referral state"}
	}
	if exists == 0 {
		if !s.recordInviteCodeMiss(c, ip, now, "unknown") {
			return "", &referralErrLookupLimited
		}
		return "", &referralErrUnknown
	}
	return code, nil
}

// recordInviteCodeMiss 未命中的留痕与更严的子配额，返回 false 表示该 IP 的未命中
// 配额已耗尽，调用方必须改回 429（设计 §4.3：**超出则该窗口内全部拒绝**）。
//
// 真实用户几乎不会未命中，扫描器 100% 未命中，两类人群在这个阈值上干净分离——
// 这条分离只有在返回值真被用来拒绝时才成立，只记日志等于闸门是假的。
// 租户级那条不一样，**只告警不阻断**：它用来发现"正在被扫"，不用来拦人。
func (s *server) recordInviteCodeMiss(c *gin.Context, ip string, now time.Time, kind string) bool {
	slog.Warn("invite code lookup miss",
		"tenant", tenantID(c), "kind", kind, "clientIp", ip, "requestId", requestID(c))
	if !s.referrals.withinTenantUnknownBudget(tenantID(c), now) {
		slog.Error("invite code lookup misses exceeded the tenant daily budget",
			"tenant", tenantID(c), "budget", referralUnknownPerDayTenant, "requestId", requestID(c))
	}
	if !s.referrals.allowLookupMiss(ip, now) {
		slog.Warn("invite code lookup miss quota exhausted", "tenant", tenantID(c), "clientIp", ip)
		return false
	}
	return true
}
