package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/referral"
	"github.com/Helix2010/RN-Server/internal/siwe"
	"github.com/gin-gonic/gin"
)

/*
管理端的邀请关系接口（设计 §4.4）。

与移动端相反，这里返回完整地址——管理员有权看。

补录（POST /referral/bind）是全文影响最大的一个入口：它豁免绑定窗口，而窗口是
"存量用户能被追溯挂多少"的唯一上界，再叠加关系不可解绑，一次脚本化误用永久不可
回滚。当前管理凭证是全平台唯一一份、租户隔离只在 Host 头这一层、管理端除登录外
全线无限流，所以补录自己要把闸带齐：confirm + 乐观锁 + 租户日配额 + 禁 x-admin-key。
*/

// referralAdminBindPerDay 补录的租户级日配额。形态照 diagnosticTenantPerDay。
// 20 条/天够客服补录用；真要批量补说明该走一次性数据订正，不该走这个入口。
const referralAdminBindPerDay = 20

// listReferralRelations GET /v1/admin/referral/relations
func (s *server) listReferralRelations(c *gin.Context) {
	tenant := tenantID(c)
	where, page, invalid := parseReferralListFilter(c, tenant)
	if invalid != "" {
		problem(c, 422, "INVALID_REFERRAL_FILTER", invalid)
		return
	}
	total, err := s.countListRows(c.Request.Context(), referralRelationsFrom, where)
	if err != nil {
		slog.Error("referral relations count failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_QUERY_FAILED", "Unable to load referral relations")
		return
	}
	query := where.and(page.after)
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT invitee.id, invitee.address, invitee.status, invitee.invited_at, invitee.invite_source,
		        inviter.id, inviter.address, inviter.status, inviter.invite_code,
		        (platform_block.address_key IS NOT NULL) AS inviter_platform_blocked,
		        (invitee_block.address_key IS NOT NULL) AS invitee_platform_blocked
		   FROM `+referralRelationsFrom+`
		  WHERE `+query.sql()+`
		  ORDER BY invitee.invited_at DESC, invitee.id DESC LIMIT ?`,
		append(query.args, page.limit+1)...)
	if err != nil {
		slog.Error("referral relations query failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_QUERY_FAILED", "Unable to load referral relations")
		return
	}
	defer rows.Close()

	items, cursors := []gin.H{}, []string{}
	for rows.Next() {
		var inviteeID, inviterID uint64
		var inviteeAddress, inviteeStatus, inviterAddress, inviterStatus string
		var inviterCode sql.NullString
		var invitedAt time.Time
		var source string
		var inviterPlatformBlocked, inviteePlatformBlocked bool
		if err := rows.Scan(&inviteeID, &inviteeAddress, &inviteeStatus, &invitedAt, &source,
			&inviterID, &inviterAddress, &inviterStatus, &inviterCode,
			&inviterPlatformBlocked, &inviteePlatformBlocked); err != nil {
			slog.Error("referral relations scan failed", "error", err, "requestId", requestID(c))
			problem(c, 500, "REFERRAL_QUERY_FAILED", "Unable to read referral relations")
			return
		}
		items = append(items, gin.H{
			"invitee": gin.H{
				"userId": inviteeID, "address": inviteeAddress,
				"status": inviteeStatus, "platformBlocked": inviteePlatformBlocked,
			},
			"inviter": gin.H{
				"userId": inviterID, "address": inviterAddress, "inviteCode": inviterCode.String,
				"status": inviterStatus, "platformBlocked": inviterPlatformBlocked,
			},
			"boundAt": iso(invitedAt),
			"source":  source,
		})
		cursors = append(cursors, encodeListCursor(invitedAt, inviteeID))
	}
	if err := rows.Err(); err != nil {
		slog.Error("referral relations rows failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_QUERY_FAILED", "Unable to read referral relations")
		return
	}
	items, next := finishListPage(items, cursors, page.limit)
	c.JSON(http.StatusOK, listResponse(items, total, next, page.limit))
}

// referralRelationsFrom 关系列表的 FROM。平台级封禁用 LEFT JOIN 带出来，
// 让管理端能一眼看出双方的封禁状态（关系本身不受封禁影响，设计 §3.4）。
const referralRelationsFrom = `wallet_user invitee
	JOIN wallet_user inviter ON inviter.id=invitee.inviter_user_id AND inviter.tenant_id=invitee.tenant_id
	LEFT JOIN platform_wallet_block platform_block
	       ON platform_block.address_key=LOWER(inviter.address) AND platform_block.revoked_at IS NULL
	LEFT JOIN platform_wallet_block invitee_block
	       ON invitee_block.address_key=LOWER(invitee.address) AND invitee_block.revoked_at IS NULL`

func parseReferralListFilter(c *gin.Context, tenant string) (sqlWhere, listPage, string) {
	where := sqlWhere{}
	where.add("invitee.tenant_id=?", tenant)
	// 这条查询走 ix_wallet_user_invited_at（没有 inviter_user_id 等值条件，
	// ix_wallet_user_inviter 的第二列断开，用不上）。显式排除 invited_at 为空的行：
	// 键集游标里 NULL<? 不为真，这类行翻页时会被跳过而 COUNT(*) 仍算进去。
	where.add("invitee.invited_at IS NOT NULL")
	if address := strings.TrimSpace(c.Query("inviterAddress")); address != "" {
		if !addressPattern.MatchString(address) {
			return where, listPage{}, "inviterAddress must be a 0x-prefixed 20-byte address"
		}
		where.add("LOWER(inviter.address)=?", strings.ToLower(address))
	}
	if address := strings.TrimSpace(c.Query("inviteeAddress")); address != "" {
		if !addressPattern.MatchString(address) {
			return where, listPage{}, "inviteeAddress must be a 0x-prefixed 20-byte address"
		}
		where.add("LOWER(invitee.address)=?", strings.ToLower(address))
	}
	if invalid := addEnumFilter(c, &where, "source", "invitee.invite_source", "code", "link", "admin"); invalid != "" {
		return where, listPage{}, invalid
	}
	if invalid := addTimeRange(c, &where, "invitee.invited_at"); invalid != "" {
		return where, listPage{}, invalid
	}
	page, invalid := parseListPage(c, sortKey{"invitee.invited_at", cursorTime}, sortKey{"invitee.id", cursorUint})
	return where, page, invalid
}

// adminBindReferral POST /v1/admin/referral/bind
//
// 补录豁免绑定窗口，**只豁免这一条**。其余条件照判，否则会破坏关系图的不变量。
func (s *server) adminBindReferral(c *gin.Context) {
	// x-admin-key 是长期有效、不绑账号、只靠 IP 白名单的自动化通道。补录是
	// 不可回滚的人工动作，自动化没有补录需求，这条通道直接拒掉（设计 §4.4）。
	if method, _ := c.Get("authMethod"); method == "api-key" {
		problem(c, http.StatusForbidden, "REFERRAL_ADMIN_KEY_FORBIDDEN",
			"Backfilling a referral requires an interactive admin session, not the automation key")
		return
	}
	var body struct {
		InviteeAddress string `json:"inviteeAddress"`
		InviterCode    string `json:"inviterCode"`
		InviterAddress string `json:"inviterAddress"`
		Reason         string `json:"reason"`
		Confirm        bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_ACTION", "Invalid action payload")
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if !body.Confirm || len(body.Reason) < 3 {
		problem(c, 422, "INVALID_ACTION", "reason (at least 3 characters) and confirm=true are required")
		return
	}
	body.InviterCode = strings.TrimSpace(body.InviterCode)
	body.InviterAddress = strings.TrimSpace(body.InviterAddress)
	// 恰好给一个：两个都给会让"以哪个为准"变成隐式规则
	if (body.InviterCode == "") == (body.InviterAddress == "") {
		problem(c, 422, "INVALID_ACTION", "provide exactly one of inviterCode or inviterAddress")
		return
	}
	if !addressPattern.MatchString(strings.TrimSpace(body.InviteeAddress)) {
		problem(c, 422, "INVALID_ACTION", "inviteeAddress must be a 0x-prefixed 20-byte address")
		return
	}

	tenant := tenantID(c)
	now := time.Now().UTC()
	if !s.referrals.allowAdminBind(tenant, now) {
		slog.Error("referral admin backfill exceeded the tenant daily quota",
			"tenant", tenant, "quota", referralAdminBindPerDay, "actor", actor(c), "requestId", requestID(c))
		problem(c, http.StatusTooManyRequests, "REFERRAL_ADMIN_QUOTA",
			"This tenant has reached today's backfill quota; a bulk correction should not go through this endpoint")
		return
	}

	// 被邀请人必须已有账号。账号在**首次登录时**才创建，所以"这个地址没登录过"
	// 是运营最常撞到的一条，文案要直说（设计 §4.4）。
	var inviteeID uint64
	err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT id FROM wallet_user WHERE tenant_id=? AND address_key=?`,
		tenant, strings.ToLower(siwe.ChecksumAddress(body.InviteeAddress))).Scan(&inviteeID)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, referralErrInviteeUnknown.Status, referralErrInviteeUnknown.Code, referralErrInviteeUnknown.Detail)
		return
	}
	if err != nil {
		slog.Error("referral admin bind invitee lookup failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_BIND_FAILED", "Unable to bind the inviter")
		return
	}

	code := body.InviterCode
	if body.InviterAddress != "" {
		var stored sql.NullString
		err := s.db.QueryRowContext(c.Request.Context(),
			`SELECT invite_code FROM wallet_user WHERE tenant_id=? AND address_key=?`,
			tenant, strings.ToLower(siwe.ChecksumAddress(body.InviterAddress))).Scan(&stored)
		if errors.Is(err, sql.ErrNoRows) {
			problem(c, referralErrInviterUnknown.Status, referralErrInviterUnknown.Code, referralErrInviterUnknown.Detail)
			return
		}
		if err != nil {
			slog.Error("referral admin bind inviter lookup failed", "error", err, "requestId", requestID(c))
			problem(c, 500, "REFERRAL_BIND_FAILED", "Unable to bind the inviter")
			return
		}
		if !stored.Valid {
			// 不变量被破坏了：提交后的每一行都该有码。报错而不是现场补一个
			slog.Error("wallet user has no invite code", "tenant", tenant, "address", body.InviterAddress, "requestId", requestID(c))
			problem(c, 500, "REFERRAL_BIND_FAILED", "Unable to bind the inviter")
			return
		}
		code = stored.String
	}

	// 乐观锁：把"这个人当前没有邀请人"写成显式前置条件，而不是让脚本反复试。
	// bindReferral 内部也会再判一次（持锁之后），这里先挡住明显的误用。
	var current sql.NullInt64
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT inviter_user_id FROM wallet_user WHERE id=? AND tenant_id=?`, inviteeID, tenant).Scan(&current); err != nil {
		slog.Error("referral admin bind state read failed", "error", err, "requestId", requestID(c))
		problem(c, 500, "REFERRAL_BIND_FAILED", "Unable to bind the inviter")
		return
	}
	if current.Valid {
		problem(c, referralErrAlreadyBound.Status, referralErrAlreadyBound.Code, referralErrAlreadyBound.Detail)
		return
	}

	result, outcome := s.bindReferral(c, bindRequest{
		Tenant:     tenant,
		InviteeID:  inviteeID,
		RawCode:    code,
		Source:     "admin",
		SkipWindow: true,
		ActorID:    actor(c),
		Reason:     body.Reason,
	})
	if outcome != nil {
		slog.Warn("referral admin bind rejected",
			"tenant", tenant, "code", outcome.Code, "actor", actor(c), "requestId", requestID(c))
		problem(c, outcome.Status, outcome.Code, outcome.Detail)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"inviteeUserId": inviteeID,
		"inviterUserId": result.InviterUserID,
		"inviterCode":   referral.Format(result.InviterCode),
		"boundAt":       iso(result.BoundAt),
	})
}

// referralOfWalletUser 给账号详情补一段邀请信息（设计 §4.4：扩展既有响应，不新开接口）。
func (s *server) referralOfWalletUser(c *gin.Context, tenant string, userID uint64) (gin.H, error) {
	var inviteCode sql.NullString
	var inviterID sql.NullInt64
	var invitedAt sql.NullTime
	var source sql.NullString
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT invite_code, inviter_user_id, invited_at, invite_source FROM wallet_user WHERE id=? AND tenant_id=?`,
		userID, tenant).Scan(&inviteCode, &inviterID, &invitedAt, &source); err != nil {
		return nil, err
	}
	view := gin.H{"inviteCode": inviteCode.String, "inviter": nil}
	if inviterID.Valid {
		var address string
		var status string
		var code sql.NullString
		if err := s.db.QueryRowContext(c.Request.Context(),
			`SELECT address, status, invite_code FROM wallet_user WHERE id=? AND tenant_id=?`,
			inviterID.Int64, tenant).Scan(&address, &status, &code); err != nil {
			return nil, err
		}
		view["inviter"] = gin.H{
			"userId": uint64(inviterID.Int64), "address": address, "status": status,
			"inviteCode": code.String, "boundAt": iso(invitedAt.Time), "source": source.String,
		}
	}
	var inviteeCount int
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT COUNT(*) FROM wallet_user WHERE tenant_id=? AND inviter_user_id=?`, tenant, userID).Scan(&inviteeCount); err != nil {
		return nil, err
	}
	view["inviteeCount"] = inviteeCount
	return view, nil
}
