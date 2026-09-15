package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/referral"
	"github.com/gin-gonic/gin"
)

/*
邀请关系（设计 RN-App/docs/design/referral-graph-2026-09-15.md、ADR 0018）。

一期只做关系，不做返佣，接口里不出现任何金额。

三条容易写错的地方，都在下面各自的注释里展开：
  - 邀请码不能进登录那条 ON DUPLICATE KEY UPDATE；
  - 条件更新只保证"最多一个邀请人"，不保证无环，绑定必须按租户串行化；
  - 移动端响应不返回任何地址派生值——前 6 后 4 的"脱敏"地址是 32 bit，
    对现实候选集等同唯一键。
*/

const (
	// referralMaxDepth 上溯上界。服务端常量而不是租户配置：本期没有任何功能
	// 按层级分叉，做成旋钮运营也无从判断该填几（设计 D6）。取个位数还因为
	// 绑定在 GET_LOCK 里串行执行，链路越短持锁越短。
	referralMaxDepth = 8

	// referralBindLockSeconds 取绑定锁的等待上限。绑定一生一次，等不到就让客户端重试。
	referralBindLockSeconds = 5

	// referralLockReleaseTimeout 释放绑定锁的超时。请求已经结束了，这条 exec 不能
	// 跟着请求的 context 被取消（锁会跟着连接回池），但也不能没有上限。
	referralLockReleaseTimeout = 3 * time.Second

	// referralAliasLength 下级列表里 per-viewer 别名的长度（hex 字符数）。
	referralAliasLength = 6
)

// 租户配置的声明式默认（设计 §3.6）。租户未配置时生效，管理端显示实际生效值。
const (
	referralDefaultEnabled         = false
	referralDefaultBindWindowHours = 168
	referralMinBindWindowHours     = 1
	referralMaxBindWindowHours     = 8760
)

// referralSettings 是某个租户当前生效的邀请配置。
type referralSettings struct {
	Enabled         bool
	BindWindowHours int
}

// referralSettingsOf 从 mobile-bootstrap 的 referral 段读配置。
//
// 读路径不修复坏数据：非法值在写入时就被 validateReferralSection 拒了，
// 这里读到的要么是缺省（用声明式默认），要么是合法值。
func (s *server) referralSettingsOf(ctx context.Context, tenant string) (referralSettings, error) {
	settings := referralSettings{Enabled: referralDefaultEnabled, BindWindowHours: referralDefaultBindWindowHours}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT config_value FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`, tenant, tenant).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return settings, nil
	}
	if err != nil {
		return settings, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return settings, err
	}
	return parseReferralSection(object(value["referral"])), nil
}

// ---------- 邀请码 ----------

// referralCodeCandidates 预抽若干候选码，供注册事务按顺序试。
func referralCodeCandidates() ([]string, error) {
	codes := make([]string, 0, referral.Attempts)
	for i := 0; i < referral.Attempts; i++ {
		code, err := referral.Generate()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// assignInviteCode 在注册事务里给这一行赋码，撞上唯一键就换下一个候选。
//
// 这条语句会抛真正的 1062，所以"碰撞后重试"在这里成立；把 invite_code 放进登录那条
// ON DUPLICATE KEY UPDATE 则不会抛，只会去更新撞上的那一行（设计 §3.3）。
func assignInviteCode(c *gin.Context, tx *sql.Tx, tenant string, userID uint64, candidates []string) error {
	for _, code := range candidates {
		result, err := tx.ExecContext(c.Request.Context(),
			`UPDATE wallet_user SET invite_code=?, updated_at=? WHERE id=? AND tenant_id=? AND invite_code IS NULL`,
			code, time.Now().UTC(), userID, tenant)
		if err == nil {
			// 显式断言影响了一行。当前调用点在事务里、行已被自己的 upsert 锁住，
			// 0 行发生不了；但"人人有码"是整个设计的基石不变量（没有码就没有
			// 邀请入口），不能靠"调用点恰好安全"来保证——将来换调用点时，
			// err==nil 就返回成功会让它静默塌掉。
			affected, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if affected != 1 {
				return fmt.Errorf("invite code assignment touched %d rows, want 1", affected)
			}
			return nil
		}
		if !isDuplicateEntry(err) {
			return err
		}
	}
	return fmt.Errorf("no free invite code after %d attempts", len(candidates))
}

// ---------- 别名 ----------

// referralAlias 是下级在某一个观察者眼里的标识。
//
// 不返回地址、也不返回地址的任何派生值：shortenAddress 的前 6 后 4 是 8 个 hex
// nibble = 32 bit，候选集 1e6 时期望碰撞 2.3e-4，对任何现实候选集都等同于唯一键，
// 拿去公链索引器一查就还原出完整地址、余额与交易史（设计 §4.2）。
//
// 每个观察者看到的别名不同（viewer 进 HMAC 的消息），所以两个邀请人无法拿各自
// 看到的别名互相 join，也无法反查地址。
func referralAlias(secret []byte, viewerID, inviteeID uint64) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "referral-alias:%d:%d", viewerID, inviteeID)
	return hex.EncodeToString(mac.Sum(nil))[:referralAliasLength]
}

// ---------- 上溯与防环 ----------

// referralAncestors 返回 userID 的祖先链（由近及远），最多 referralMaxDepth 跳。
//
// 这就是设计 §7 说的 ancestorsOf：返佣模块日后直接取前 N 级，不另写一份。
//
// 第二个返回值为 false 表示跳满上界仍未到根——链路超限，绑定要拒绝。调用方把它
// 和"成环"合并成 REFERRAL_CYCLE，这是设计 §4.1 条件 8 明写的合并（一条码在用户
// 眼里只有"能绑/不能绑"，两种拒绝理由都不该让他改输入）。
//
// 循环跳满 referralMaxDepth 次就判 false，从不确认第 referralMaxDepth 跳是否是根，
// 所以邀请人自身祖先数的实际上界是 referralMaxDepth-1、绑定后的总深度上界是
// referralMaxDepth。这是有意的，别照字面读成"祖先可以有 referralMaxDepth 个"。
//
// 调用方必须已持有本租户的绑定锁，否则读到的是快照，结论不作数（见 bindReferral）。
func referralAncestors(ctx context.Context, q rowQuerier, tenant string, userID uint64) ([]uint64, bool, error) {
	chain := make([]uint64, 0, referralMaxDepth)
	current := userID
	for i := 0; i < referralMaxDepth; i++ {
		var parent sql.NullInt64
		err := q.QueryRowContext(ctx, `SELECT inviter_user_id FROM wallet_user WHERE id=? AND tenant_id=?`, current, tenant).Scan(&parent)
		if errors.Is(err, sql.ErrNoRows) {
			return chain, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		if !parent.Valid {
			return chain, true, nil
		}
		current = uint64(parent.Int64)
		chain = append(chain, current)
	}
	return chain, false, nil
}

// rowQuerier 让上溯既能在 *sql.Tx 上跑，也能在钉住的 *sql.Conn 上跑。
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ---------- 绑定 ----------

// referralBindOutcome 绑定失败的原因，映射到 problem 的错误码与状态。
type referralBindOutcome struct {
	Code   string
	Status int
	Detail string
}

var (
	referralErrDisabled       = referralBindOutcome{"REFERRAL_DISABLED", http.StatusForbidden, "Referrals are not enabled for this tenant"}
	referralErrMalformed      = referralBindOutcome{"REFERRAL_CODE_MALFORMED", http.StatusUnprocessableEntity, "The invite code is not in a valid format"}
	referralErrUnknown        = referralBindOutcome{"REFERRAL_CODE_UNKNOWN", http.StatusNotFound, "No such invite code in this tenant"}
	referralErrAlreadyBound   = referralBindOutcome{"REFERRAL_ALREADY_BOUND", http.StatusConflict, "This account already has an inviter"}
	referralErrSelf           = referralBindOutcome{"REFERRAL_SELF", http.StatusUnprocessableEntity, "An account cannot invite itself"}
	referralErrWindowClosed   = referralBindOutcome{"REFERRAL_WINDOW_CLOSED", http.StatusConflict, "The window for choosing an inviter has closed"}
	referralErrInviterBlocked = referralBindOutcome{"REFERRAL_INVITER_BLOCKED", http.StatusForbidden, "The inviter is not allowed to invite"}
	referralErrCycle          = referralBindOutcome{"REFERRAL_CYCLE", http.StatusUnprocessableEntity, "This would create a cycle in the referral graph"}
	referralErrInviteeUnknown = referralBindOutcome{"REFERRAL_INVITEE_UNKNOWN", http.StatusNotFound, "That address has never signed in on this tenant, so it has no account to bind"}
	referralErrInviterUnknown = referralBindOutcome{"REFERRAL_INVITER_UNKNOWN", http.StatusNotFound, "No account with that address in this tenant"}
	referralErrLookupLimited  = referralBindOutcome{"REFERRAL_RATE_LIMITED", http.StatusTooManyRequests, "Too many lookups; try again later"}
)

// bindRequest 一次绑定的输入。管理端补录与用户自助走同一条路径，只有 SkipWindow 不同。
type bindRequest struct {
	Tenant     string
	InviteeID  uint64
	RawCode    string
	Source     string
	SkipWindow bool
	// ActorID 写进审计：自助绑定是 system-referral，补录是管理员账号
	ActorID string
	Reason  string
}

// bindResult 绑定成功后的事实，供响应与审计使用。
type bindResult struct {
	InviterUserID uint64
	InviterCode   string
	BoundAt       time.Time
}

// bindReferral 执行一次绑定。
//
// 为什么要按租户串行化：条件更新 `WHERE inviter_user_id IS NULL` 只保证"最多一个
// 邀请人"，**不保证无环**。默认 REPEATABLE READ 下事务内普通 SELECT 走快照，A、B
// 同时互扫对方的码时，两边上溯都看不到对方的写入，最后各自更新不相交的一行，
// 零锁冲突地造出一个环——而关系不可解绑，环就永久留下（设计 §3.4）。
//
// 为什么不用逐跳 SELECT ... FOR UPDATE：wallet_user 还有第三个写方，链上索引器在一个
// 事务里按 Go map 的随机顺序批量 UPDATE（internal/indexer），逐行加锁必然与它形成
// 交叉加锁顺序而死锁。绑定一生一次，整租户串行零成本。
//
// 锁必须在钉住的连接上取和放：在连接池上取、在另一条连接上 RELEASE_LOCK 会静默落空。
func (s *server) bindReferral(c *gin.Context, req bindRequest) (bindResult, *referralBindOutcome) {
	ctx := c.Request.Context()
	settings, err := s.referralSettingsOf(ctx, req.Tenant)
	if err != nil {
		slog.Error("referral settings read failed", "error", err, "requestId", requestID(c))
		return bindResult{}, &referralBindOutcome{"REFERRAL_BIND_FAILED", http.StatusInternalServerError, "Unable to bind the inviter"}
	}
	if !settings.Enabled {
		return bindResult{}, &referralErrDisabled
	}
	code, ok := referral.Normalize(req.RawCode)
	if !ok {
		return bindResult{}, &referralErrMalformed
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		slog.Error("referral bind cannot pin a connection", "error", err, "requestId", requestID(c))
		return bindResult{}, &referralBindOutcome{"REFERRAL_BIND_FAILED", http.StatusInternalServerError, "Unable to bind the inviter"}
	}
	defer conn.Close()

	lockName := "rn_referral_bind_" + req.Tenant
	var acquired sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?,?)`, lockName, referralBindLockSeconds).Scan(&acquired); err != nil {
		slog.Error("referral bind lock failed", "error", err, "requestId", requestID(c))
		return bindResult{}, &referralBindOutcome{"REFERRAL_BIND_FAILED", http.StatusInternalServerError, "Unable to bind the inviter"}
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		return bindResult{}, &referralBindOutcome{"REFERRAL_BIND_BUSY", http.StatusConflict, "Another bind is in progress; retry"}
	}
	defer func() {
		// WithoutCancel 是必要的：请求被取消/超时后，如果 RELEASE_LOCK 跟着失败，
		// defer conn.Close() 会把**仍然持着这把锁**的连接还回池子，下一个借到它的
		// 请求就带着别人的锁，该租户后续绑定全部 REFERRAL_BIND_BUSY 直到连接被回收。
		// 但不能连 deadline 一起丢掉——那样 MySQL 挂起时这条 exec 无限期阻塞请求
		// goroutine，所以单独给它一个短超时。
		release, cancel := context.WithTimeout(context.WithoutCancel(ctx), referralLockReleaseTimeout)
		defer cancel()
		if _, err := conn.ExecContext(release, `SELECT RELEASE_LOCK(?)`, lockName); err != nil {
			slog.Error("referral bind lock release failed", "error", err, "lock", lockName)
		}
	}()

	result, outcome := s.bindReferralLocked(c, conn, req, settings, code)
	if outcome != nil {
		return bindResult{}, outcome
	}
	return result, nil
}

// bindReferralLocked 是持有本租户绑定锁之后的那一段。锁保证同租户绑定串行，
// 所以这里读到的 inviter_user_id 就是最新已提交的值，上溯结论在提交前不会失效。
func (s *server) bindReferralLocked(c *gin.Context, conn *sql.Conn, req bindRequest, settings referralSettings, code string) (bindResult, *referralBindOutcome) {
	ctx := c.Request.Context()
	fail := func(err error) *referralBindOutcome {
		slog.Error("referral bind failed", "error", err, "requestId", requestID(c))
		return &referralBindOutcome{"REFERRAL_BIND_FAILED", http.StatusInternalServerError, "Unable to bind the inviter"}
	}

	// 被邀请人：必须存在（管理端补录最常撞到这条——账号在首次登录时才创建）
	var inviteeFirstSeen time.Time
	var inviteeInviter sql.NullInt64
	var inviteeAddress string
	err := conn.QueryRowContext(ctx, `SELECT first_seen_at, inviter_user_id, address FROM wallet_user WHERE id=? AND tenant_id=?`, req.InviteeID, req.Tenant).
		Scan(&inviteeFirstSeen, &inviteeInviter, &inviteeAddress)
	if errors.Is(err, sql.ErrNoRows) {
		return bindResult{}, &referralErrInviteeUnknown
	}
	if err != nil {
		return bindResult{}, fail(err)
	}
	if inviteeInviter.Valid {
		return bindResult{}, &referralErrAlreadyBound
	}

	// 邀请人：按归一化后的码在本租户内找。查询恒带 tenant_id，跨租户的 id 拿不到
	var inviterID uint64
	var inviterStatus, inviterAddress string
	err = conn.QueryRowContext(ctx, `SELECT id, status, address FROM wallet_user WHERE tenant_id=? AND invite_code=?`, req.Tenant, code).
		Scan(&inviterID, &inviterStatus, &inviterAddress)
	if errors.Is(err, sql.ErrNoRows) {
		return bindResult{}, &referralErrUnknown
	}
	if err != nil {
		return bindResult{}, fail(err)
	}
	if inviterID == req.InviteeID {
		return bindResult{}, &referralErrSelf
	}

	now := time.Now().UTC()
	// 窗口从首次登录起算。管理端补录豁免这一条，而且只豁免这一条——补录存在的
	// 意义就是处理过期的存量；其余条件豁免会破坏不变量（设计 §4.1）。
	if !req.SkipWindow {
		if now.After(inviteeFirstSeen.Add(time.Duration(settings.BindWindowHours) * time.Hour)) {
			return bindResult{}, &referralErrWindowClosed
		}
	}

	// 封禁：平台级与租户级都查。封禁只影响能否新建关系，不改变已有关系（设计 §3.4）
	if inviterStatus != "active" {
		return bindResult{}, &referralErrInviterBlocked
	}
	blocked, err := s.platformBlockedAddress(ctx, conn, inviterAddress)
	if err != nil {
		return bindResult{}, fail(err)
	}
	if blocked {
		return bindResult{}, &referralErrInviterBlocked
	}

	// 防环：从候选邀请人往上溯，遇到被邀请人自己就是环；跳满上界就是链路超限。
	// 持锁期间读到的是最新已提交值，结论在本次提交前不会被并发改写。
	ancestors, withinDepth, err := referralAncestors(ctx, conn, req.Tenant, inviterID)
	if err != nil {
		return bindResult{}, fail(err)
	}
	if !withinDepth {
		return bindResult{}, &referralErrCycle
	}
	for _, ancestor := range ancestors {
		if ancestor == req.InviteeID {
			return bindResult{}, &referralErrCycle
		}
	}

	result, err := conn.ExecContext(ctx,
		`UPDATE wallet_user SET inviter_user_id=?, invited_at=?, invite_source=?, updated_at=?
		 WHERE id=? AND tenant_id=? AND inviter_user_id IS NULL`,
		inviterID, now, req.Source, now, req.InviteeID, req.Tenant)
	if err != nil {
		return bindResult{}, fail(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return bindResult{}, fail(err)
	}
	if affected == 0 {
		// 持锁期间不该发生：说明有人绕过了锁，或锁没真正生效。防环结论已经不作数，
		// 所以这里不能静默当成普通的"已绑定"，要留下告警（设计 §4.1）。
		slog.Error("referral bind lost a race while holding the tenant lock",
			"tenant", req.Tenant, "invitee", req.InviteeID, "requestId", requestID(c))
		return bindResult{}, &referralErrAlreadyBound
	}

	s.auditNow(auditEvent{
		ID:         "aud_" + randomID(16),
		TenantID:   req.Tenant,
		ActorID:    req.ActorID,
		Action:     referralAuditAction(req.Source),
		TargetType: "wallet-user",
		TargetID:   fmt.Sprintf("%d", req.InviteeID),
		Reason:     req.Reason,
		RequestID:  requestID(c),
		CreatedAt:  iso(now),
		Summary:    s.referralBindSummary(c, req, inviterID, code),
	})
	return bindResult{InviterUserID: inviterID, InviterCode: code, BoundAt: now}, nil
}

func referralAuditAction(source string) string {
	if source == "admin" {
		return "referral_bind_admin"
	}
	return "referral_bind"
}

// referralBindSummary 是绑定留证（设计 §6）。
//
// 一期不做滥用判定，但必须留证：关系不可解绑，返佣上线后在结构上无法追溯清理，
// 只能靠绑定当时记下的事实来判定。等返佣立项再想采集，这批数据已经永久缺失。
//
// 不写完整地址：audit_events 会在管理端列表里展示，而"脱敏"地址等同唯一键。
func (s *server) referralBindSummary(c *gin.Context, req bindRequest, inviterID uint64, code string) map[string]any {
	summary := map[string]any{
		"inviteCode":    code,
		"source":        req.Source,
		"inviterUserId": inviterID,
		"inviteeUserId": req.InviteeID,
		"bindIp":        c.ClientIP(),
	}
	var inviterFirstSeen, inviteeFirstSeen time.Time
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT
		   (SELECT first_seen_at FROM wallet_user WHERE id=? AND tenant_id=?),
		   (SELECT first_seen_at FROM wallet_user WHERE id=? AND tenant_id=?)`,
		inviterID, req.Tenant, req.InviteeID, req.Tenant).Scan(&inviterFirstSeen, &inviteeFirstSeen); err == nil {
		summary["inviterFirstSeenAt"] = iso(inviterFirstSeen)
		summary["inviteeFirstSeenAt"] = iso(inviteeFirstSeen)
		summary["registrationGapSeconds"] = int64(inviteeFirstSeen.Sub(inviterFirstSeen).Seconds())
	}
	// 双方是否用过同一个安装实例。这是留证不是判定：设备标识可伪造，ADR 0014 §3
	// 已定它不参与任何安全判定，这里只把事实记下来供日后复核。
	var shared int
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT COUNT(*) FROM wallet_user_installation a
		   JOIN wallet_user_installation b ON a.installation_id=b.installation_id AND a.tenant_id=b.tenant_id
		  WHERE a.tenant_id=? AND a.user_id=? AND b.user_id=?`,
		req.Tenant, inviterID, req.InviteeID).Scan(&shared); err == nil {
		summary["sharedInstallations"] = shared
	}
	return summary
}

// platformBlockedAddress 是平台级封禁的唯一判据，登录路径（platformWalletBlocked）
// 与绑定路径都走它。
//
// 收 rowQuerier 而不是写死 s.db：绑定要跑在钉住的 *sql.Conn 上（那条连接持着本租户
// 的绑定锁，换一条连接读到的就不是同一个串行视图了）。
func (s *server) platformBlockedAddress(ctx context.Context, q rowQuerier, address string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM platform_wallet_block WHERE address_key=? AND revoked_at IS NULL`,
		strings.ToLower(address)).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// ---------- 租户配置的写入校验与下发 ----------

// validateReferralSection 在**写入时**拒绝非法的 referral 段。
//
// 读路径不修复坏数据（AGENTS.md「正式场景开发原则」）。这里拦下来还有第二个理由：
// 新版 App 的 bootstrap schema 会校验 referral 的取值范围，下发一个越界值会让
// 新版 App 整份 safeParse 失败——未知字段被 zod strip 掉是安全的，已知字段的
// 取值校验仍然严格（设计 §2.1）。
func validateReferralSection(raw any) error {
	section, ok := raw.(map[string]any)
	if !ok {
		return errors.New("referral 必须是一个对象")
	}
	for key := range section {
		if !oneOf(key, "enabled", "bindWindowHours") {
			return fmt.Errorf("referral.%s 不是可配置项（只有 enabled 与 bindWindowHours）", key)
		}
	}
	if value, present := section["enabled"]; present {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("referral.enabled 必须是布尔值，收到 %v", value)
		}
	}
	if value, present := section["bindWindowHours"]; present {
		hours, ok := value.(float64)
		if !ok || hours != float64(int(hours)) {
			return fmt.Errorf("referral.bindWindowHours 必须是整数小时，收到 %v", value)
		}
		if int(hours) < referralMinBindWindowHours || int(hours) > referralMaxBindWindowHours {
			return fmt.Errorf("referral.bindWindowHours 必须在 %d 到 %d 之间，收到 %d",
				referralMinBindWindowHours, referralMaxBindWindowHours, int(hours))
		}
	}
	return nil
}

// parseReferralSection 把 referral 段读成 referralSettings。
//
// 解析只有这一处。绑定时判窗口（referralSettingsOf）、管理端回显（normalizeReferral）、
// 下发给 App（referralBootstrapSection）走的必须是同一份解析，否则"App 以为还开着"
// 和"服务端判定已关闭"会是两个值，用户看到的就是点了绑定却返回 409。
//
// 只做"未配置时用声明式默认"，不修复非法值——非法值在写入时已被
// validateReferralSection 拒绝（AGENTS.md「正式场景开发原则」）。
//
// 数字两种类型都认：float64 来自 json.Unmarshal，int 来自本进程里已经归一化过一遍的
// map——bootstrap 复用 appConfigView 的结果，referral 段会被归一化两遍。这不是
// "读路径修复坏数据"，两种都是本进程自己产出的合法形态；只认 float64 的话，第二遍
// 会静默丢掉租户配的窗口、退回默认 168 小时。
func parseReferralSection(raw map[string]any) referralSettings {
	settings := referralSettings{Enabled: referralDefaultEnabled, BindWindowHours: referralDefaultBindWindowHours}
	if raw == nil {
		return settings
	}
	if enabled, ok := raw["enabled"].(bool); ok {
		settings.Enabled = enabled
	}
	switch hours := raw["bindWindowHours"].(type) {
	case float64:
		settings.BindWindowHours = int(hours)
	case int:
		settings.BindWindowHours = hours
	}
	return settings
}

// normalizeReferral 是管理端配置中心回显的 referral 段：**只有可编辑项**。
//
// 配置中心是"整份配置 PATCH 回去"，回显里出现的键会被原样发回来。所以这里出现的
// 每个键都必须能通过 validateReferralSection，否则管理员改任何一项配置都会 400
// ——不止邀请功能，是整个配置中心存不下去。服务端算出来的 inviteLinkBase 因此
// 不放在这里，它只属于下发链路（见 referralBootstrapSection）。
func normalizeReferral(raw map[string]any) map[string]any {
	settings := parseReferralSection(raw)
	return map[string]any{"enabled": settings.Enabled, "bindWindowHours": settings.BindWindowHours}
}

// referralBootstrapSection 是下发给 App 的 referral 段：可编辑项 + 服务端算出的链接基址。
//
// inviteLinkBase 由服务端按请求 Host 算，App 不自己拼——落地页是服务端的，
// 路径规则只该有一个来源（设计 §3.6）。它是只读的，不进管理端的可编辑视图。
func referralBootstrapSection(raw map[string]any, linkBase string) map[string]any {
	section := normalizeReferral(raw)
	section["inviteLinkBase"] = linkBase
	return section
}
