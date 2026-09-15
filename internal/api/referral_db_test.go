package api

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/referral"
	"github.com/gin-gonic/gin"
)

/*
邀请关系的库测。需要 RN_TEST_MYSQL_DSN，没有就跳过。

这里覆盖的是"只有真数据库才能证伪"的那几条：
  - 并发互绑不成环（设计 §3.4 的回归测试，必须真并发）；
  - 迁移幂等、CHECK 约束真的在挡；
  - 键集分页翻完不重不漏且 total 对得上；
  - 注册路径不会因为新唯一键而改错行。
*/

// referralTestServer 造一个带测试库与别名密钥的 server。
func referralTestServer(t *testing.T) *server {
	t.Helper()
	db := openTestDB(t)
	s := &server{db: db}
	// 别名密钥从 STORAGE_MASTER_KEY 派生，测试里给一把固定的 32 字节值
	s.cfg.StorageMasterKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	return s
}

// makeWalletUser 直接插一行账号，返回它的 id 与邀请码。
func makeWalletUser(t *testing.T, db *sql.DB, tenant string, firstSeen time.Time) (uint64, string) {
	t.Helper()
	code, err := referral.Generate()
	if err != nil {
		t.Fatalf("generate invite code: %v", err)
	}
	address := fmt.Sprintf("0x%040x", time.Now().UnixNano()%(1<<62))
	now := time.Now().UTC()
	result, err := db.Exec(
		`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,invite_code,created_at,updated_at)
		 VALUES(?,?,?,?,?,1,'active',?,?,?)`,
		tenant, address, address, firstSeen, now, code, now, now)
	if err != nil {
		t.Fatalf("insert wallet_user: %v", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return uint64(id), code
}

// enableReferral 给租户打开邀请并设定窗口。
func enableReferral(t *testing.T, db *sql.DB, tenant string, windowHours int) {
	t.Helper()
	raw := fmt.Sprintf(`{"referral":{"enabled":true,"bindWindowHours":%d}}`, windowHours)
	now := time.Now().UTC()
	if _, err := db.Exec(
		`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		 VALUES(?, 'mobile-bootstrap', ?, 1, 'test', ?)
		 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value), version=version+1`,
		tenant, raw, now); err != nil {
		t.Fatalf("enable referral: %v", err)
	}
}

// referralBindContext 造一个绑定用的上下文。
// gin.SetMode 写的是包级变量，并发调用会被 -race 判为数据竞争，
// 所以并发测试必须在启动 goroutine **之前**把上下文都建好。
func referralBindContext(t *testing.T, tenant string) *gin.Context {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/mobile/referral/bind", nil)
	c.Set("tenantId", tenant)
	c.Set("requestId", "req_test")
	return c
}

// TestDBReferralBindHappyPath 一条正常绑定：关系落库、审计留证、下级数变化。
func TestDBReferralBindHappyPath(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(41)
	enableReferral(t, s.db, tenant, 168)
	inviterID, inviterCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	inviteeID, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	result, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
		Tenant: tenant, InviteeID: inviteeID, RawCode: inviterCode,
		Source: "code", ActorID: "system-referral", Reason: "test",
	})
	if outcome != nil {
		t.Fatalf("bind rejected: %s %s", outcome.Code, outcome.Detail)
	}
	if result.InviterUserID != inviterID {
		t.Fatalf("bound to %d, want %d", result.InviterUserID, inviterID)
	}

	var storedInviter sql.NullInt64
	var storedAt sql.NullTime
	var storedSource sql.NullString
	if err := s.db.QueryRow(`SELECT inviter_user_id, invited_at, invite_source FROM wallet_user WHERE id=?`, inviteeID).
		Scan(&storedInviter, &storedAt, &storedSource); err != nil {
		t.Fatalf("read back: %v", err)
	}
	// 三列同生共死
	if !storedInviter.Valid || !storedAt.Valid || !storedSource.Valid {
		t.Fatalf("the referral triple must be written together, got %v %v %v", storedInviter, storedAt, storedSource)
	}
	if storedSource.String != "code" {
		t.Fatalf("invite_source = %q, want code", storedSource.String)
	}

	// 绑定留证进审计：关系不可解绑，返佣上线后判定滥用只能靠这批数据（设计 §6）
	var summary []byte
	if err := s.db.QueryRow(
		`SELECT summary FROM audit_events WHERE tenant_id=? AND action='referral_bind' AND target_id=?`,
		tenant, strconv.FormatUint(inviteeID, 10)).Scan(&summary); err != nil {
		t.Fatalf("bind must leave an audit event: %v", err)
	}
	for _, want := range []string{"inviteCode", "bindIp", "registrationGapSeconds", "sharedInstallations"} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Fatalf("audit summary %s is missing the evidence field %q", summary, want)
		}
	}
}

// TestDBReferralConcurrentMutualBindDoesNotCycle 是设计 §3.4 的回归测试。
//
// 没有按租户串行化时，A、B 同时互扫对方的码会在 REPEATABLE READ 快照下各自
// 上溯到根、各自更新不相交的一行，**零锁冲突**地造出一个环；而关系不可解绑，
// 环就永久留下。必须真并发，串行跑不出来。
func TestDBReferralConcurrentMutualBindDoesNotCycle(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(42)
	enableReferral(t, s.db, tenant, 168)
	aID, aCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	bID, bCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	var wg sync.WaitGroup
	outcomes := make([]*referralBindOutcome, 2)
	start := make(chan struct{})
	contexts := []*gin.Context{referralBindContext(t, tenant), referralBindContext(t, tenant)}
	bind := func(slot int, invitee uint64, code string) {
		defer wg.Done()
		<-start
		_, outcome := s.bindReferral(contexts[slot], bindRequest{
			Tenant: tenant, InviteeID: invitee, RawCode: code,
			Source: "code", ActorID: "system-referral", Reason: "test",
		})
		outcomes[slot] = outcome
	}
	wg.Add(2)
	go bind(0, aID, bCode) // A 绑 B
	go bind(1, bID, aCode) // B 绑 A
	close(start)
	wg.Wait()

	succeeded := 0
	for _, outcome := range outcomes {
		if outcome == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("exactly one of the two mutual binds must succeed, %d did (outcomes: %v, %v)",
			succeeded, outcomes[0], outcomes[1])
	}

	// 真正要断言的是图里没有环：从任意一头上溯都要能到根
	for _, start := range []uint64{aID, bID} {
		chain, withinDepth, err := referralAncestors(context.Background(), s.db, tenant, start)
		if err != nil {
			t.Fatalf("walk ancestors: %v", err)
		}
		if !withinDepth {
			t.Fatalf("the referral graph has a cycle: walking up from %d never reached a root (%v)", start, chain)
		}
		seen := map[uint64]bool{start: true}
		for _, ancestor := range chain {
			if seen[ancestor] {
				t.Fatalf("the referral graph has a cycle through %d: %v", ancestor, chain)
			}
			seen[ancestor] = true
		}
	}
}

// TestDBReferralConcurrentBindSameInviteeOnlyOnce 同一个人被并发绑两次，只能成一次。
func TestDBReferralConcurrentBindSameInviteeOnlyOnce(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(43)
	enableReferral(t, s.db, tenant, 168)
	_, firstCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	_, secondCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	inviteeID, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	var wg sync.WaitGroup
	outcomes := make([]*referralBindOutcome, 2)
	start := make(chan struct{})
	contexts := []*gin.Context{referralBindContext(t, tenant), referralBindContext(t, tenant)}
	for slot, code := range []string{firstCode, secondCode} {
		wg.Add(1)
		go func(slot int, code string) {
			defer wg.Done()
			<-start
			_, outcome := s.bindReferral(contexts[slot], bindRequest{
				Tenant: tenant, InviteeID: inviteeID, RawCode: code,
				Source: "code", ActorID: "system-referral", Reason: "test",
			})
			outcomes[slot] = outcome
		}(slot, code)
	}
	close(start)
	wg.Wait()

	succeeded := 0
	for _, outcome := range outcomes {
		if outcome == nil {
			succeeded++
			continue
		}
		if outcome.Code != referralErrAlreadyBound.Code {
			t.Fatalf("the losing bind must report ALREADY_BOUND, got %s", outcome.Code)
		}
	}
	if succeeded != 1 {
		t.Fatalf("exactly one bind must succeed, %d did", succeeded)
	}
}

// TestDBReferralRejections 逐条验证绑定条件。
func TestDBReferralRejections(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(44)
	enableReferral(t, s.db, tenant, 168)
	inviterID, inviterCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	t.Run("自己的码", func(t *testing.T) {
		_, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: inviterID, RawCode: inviterCode, Source: "code", ActorID: "system-referral",
		})
		if outcome == nil || outcome.Code != referralErrSelf.Code {
			t.Fatalf("expected REFERRAL_SELF, got %v", outcome)
		}
	})

	t.Run("格式非法与码不存在是两个错误码", func(t *testing.T) {
		invitee, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())
		// U 被 Crockford 排除在字母表外、不做映射，出现即输错；长度不足同理。
		// 注意 "not-a-code!!" 不是反例：归一化会去掉分隔符、把 O 映射成 0，
		// 结果正好是 8 位合法字符，它属于"码不存在"而不是"格式非法"。
		for _, bad := range []string{"ABCU1234", "ABC", "ABCD12345"} {
			_, malformed := s.bindReferral(referralBindContext(t, tenant), bindRequest{
				Tenant: tenant, InviteeID: invitee, RawCode: bad, Source: "code", ActorID: "system-referral",
			})
			if malformed == nil || malformed.Code != referralErrMalformed.Code {
				t.Fatalf("expected REFERRAL_CODE_MALFORMED for %q, got %v", bad, malformed)
			}
		}
		// 格式合法但不存在的码
		_, unknown := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: invitee, RawCode: "ZZZZZZZZ", Source: "code", ActorID: "system-referral",
		})
		if unknown == nil || unknown.Code != referralErrUnknown.Code {
			t.Fatalf("expected REFERRAL_CODE_UNKNOWN, got %v", unknown)
		}
	})

	t.Run("窗口已关", func(t *testing.T) {
		stale, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC().Add(-200*time.Hour))
		_, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: stale, RawCode: inviterCode, Source: "code", ActorID: "system-referral",
		})
		if outcome == nil || outcome.Code != referralErrWindowClosed.Code {
			t.Fatalf("expected REFERRAL_WINDOW_CLOSED, got %v", outcome)
		}
		// 补录豁免窗口——**只豁免这一条**
		_, admin := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: stale, RawCode: inviterCode, Source: "admin",
			SkipWindow: true, ActorID: "ops@example.com", Reason: "customer ticket 123",
		})
		if admin != nil {
			t.Fatalf("admin backfill must be allowed past the window, got %v", admin)
		}
	})

	t.Run("邀请人被封禁", func(t *testing.T) {
		blockedID, blockedCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
		if _, err := s.db.Exec(`UPDATE wallet_user SET status='blocked' WHERE id=?`, blockedID); err != nil {
			t.Fatalf("block inviter: %v", err)
		}
		invitee, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())
		_, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: invitee, RawCode: blockedCode, Source: "code", ActorID: "system-referral",
		})
		if outcome == nil || outcome.Code != referralErrInviterBlocked.Code {
			t.Fatalf("expected REFERRAL_INVITER_BLOCKED, got %v", outcome)
		}
	})

	t.Run("租户没开启", func(t *testing.T) {
		closed := testTenant(45)
		invitee, _ := makeWalletUser(t, s.db, closed, time.Now().UTC())
		_, code := makeWalletUser(t, s.db, closed, time.Now().UTC())
		_, outcome := s.bindReferral(referralBindContext(t, closed), bindRequest{
			Tenant: closed, InviteeID: invitee, RawCode: code, Source: "code", ActorID: "system-referral",
		})
		if outcome == nil || outcome.Code != referralErrDisabled.Code {
			t.Fatalf("expected REFERRAL_DISABLED, got %v", outcome)
		}
	})
}

// TestDBReferralCycleAcrossChain 三级链上回绑祖先要被拒。
func TestDBReferralCycleAcrossChain(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(46)
	enableReferral(t, s.db, tenant, 168)
	aID, aCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	bID, bCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	cID, cCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	// B 的邀请人是 A，C 的邀请人是 B
	for _, step := range []struct {
		invitee uint64
		code    string
	}{{bID, aCode}, {cID, bCode}} {
		if _, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: step.invitee, RawCode: step.code, Source: "code", ActorID: "system-referral",
		}); outcome != nil {
			t.Fatalf("setup bind failed: %v", outcome)
		}
	}
	// A 再拿 C 的码就成环
	_, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
		Tenant: tenant, InviteeID: aID, RawCode: cCode, Source: "code", ActorID: "system-referral",
	})
	if outcome == nil || outcome.Code != referralErrCycle.Code {
		t.Fatalf("expected REFERRAL_CYCLE, got %v", outcome)
	}
}

// TestDBReferralTripleCheckConstraint CHECK 约束真的在挡。
//
// 没有它，漏写一列产生的 inviter 非空、invited_at 为 NULL 的行会被键集游标
// 全部排除，在上级的下级列表里永久不可见，而 total 仍把它算进去。
func TestDBReferralTripleCheckConstraint(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(47)
	inviterID, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	inviteeID, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	_, err := s.db.Exec(`UPDATE wallet_user SET inviter_user_id=? WHERE id=?`, inviterID, inviteeID)
	if err == nil {
		t.Fatal("writing inviter_user_id without invited_at / invite_source must be rejected by ck_wallet_user_referral_triple")
	}
}

// TestDBReferralInviteesPaginationIsExhaustive 键集分页翻完不重不漏，total 对得上。
func TestDBReferralInviteesPaginationIsExhaustive(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(48)
	enableReferral(t, s.db, tenant, 168)
	inviterID, inviterCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())

	const total = 7
	for i := 0; i < total; i++ {
		invitee, _ := makeWalletUser(t, s.db, tenant, time.Now().UTC())
		if _, outcome := s.bindReferral(referralBindContext(t, tenant), bindRequest{
			Tenant: tenant, InviteeID: invitee, RawCode: inviterCode, Source: "code", ActorID: "system-referral",
		}); outcome != nil {
			t.Fatalf("bind %d failed: %v", i, outcome)
		}
	}

	aliasKey, err := s.referralAliasKey()
	if err != nil {
		t.Fatalf("alias key: %v", err)
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < total+2; page++ {
		target := "/v1/mobile/referral/invitees?limit=2"
		if cursor != "" {
			target += "&cursor=" + cursor
		}
		gin.SetMode(gin.TestMode)
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("GET", target, nil)
		c.Set("tenantId", tenant)
		c.Set("requestId", "req_test")

		listed, reported, next := s.inviteesPageForTest(t, c, inviterID, aliasKey)
		if reported != total {
			t.Fatalf("total = %d, want %d", reported, total)
		}
		for _, alias := range listed {
			if seen[alias] {
				t.Fatalf("alias %q appeared on two pages", alias)
			}
			seen[alias] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != total {
		t.Fatalf("paging returned %d distinct invitees, want %d", len(seen), total)
	}
}

// inviteesPageForTest 直接跑下级列表的查询部分，绕开会话鉴权。
// 它和 referralInvitees 共用同一套 where / 排序 / 游标，改一处两处都会动。
func (s *server) inviteesPageForTest(t *testing.T, c *gin.Context, viewerID uint64, aliasKey []byte) ([]string, int, string) {
	t.Helper()
	tenant := tenantID(c)
	page, invalid := parseListPage(c, sortKey{"invited_at", cursorTime}, sortKey{"id", cursorUint})
	if invalid != "" {
		t.Fatalf("parse page: %s", invalid)
	}
	where := sqlWhere{}
	where.add("tenant_id=?", tenant)
	where.add("inviter_user_id=?", viewerID)
	where.add("invited_at IS NOT NULL")
	total, err := s.countListRows(c.Request.Context(), "wallet_user", where)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	query := where.and(page.after)
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT id, invited_at FROM wallet_user WHERE `+query.sql()+` ORDER BY invited_at DESC, id DESC LIMIT ?`,
		append(query.args, page.limit+1)...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	aliases, cursors := []string{}, []string{}
	for rows.Next() {
		var id uint64
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			t.Fatalf("scan: %v", err)
		}
		aliases = append(aliases, referralAlias(aliasKey, viewerID, id))
		cursors = append(cursors, encodeListCursor(at, id))
	}
	aliases, next := finishListPage(aliases, cursors, page.limit)
	if next == nil {
		return aliases, total, ""
	}
	return aliases, total, next.(string)
}

// TestDBReferralRegistrationAssignsCodeWithoutTouchingOtherRows 注册路径的回归。
//
// invite_code 一旦进了登录那条 ON DUPLICATE KEY UPDATE，碰撞时 MySQL 会去更新
// 撞上的**那一行**（把它的 address 改成新用户的），这里断言那种事不会发生。
func TestDBReferralRegistrationAssignsCodeWithoutTouchingOtherRows(t *testing.T) {
	s := referralTestServer(t)
	tenant := testTenant(49)
	existingID, existingCode := makeWalletUser(t, s.db, tenant, time.Now().UTC())
	var addressBefore string
	if err := s.db.QueryRow(`SELECT address FROM wallet_user WHERE id=?`, existingID).Scan(&addressBefore); err != nil {
		t.Fatalf("read address: %v", err)
	}

	// 造一个"新注册"：先按登录路径 upsert（不带 invite_code），再单独赋码，
	// 而且第一个候选故意与已有的码相同，逼出 1062 并走重试
	newAddress := fmt.Sprintf("0x%040x", time.Now().UnixNano())
	now := time.Now().UTC()
	result, err := s.db.Exec(
		`INSERT INTO wallet_user(tenant_id,address,address_key,first_seen_at,last_login_at,login_count,status,created_at,updated_at)
		 VALUES(?,?,?,?,?,1,'active',?,?)
		 ON DUPLICATE KEY UPDATE last_login_at=VALUES(last_login_at),login_count=login_count+1,address=VALUES(address),updated_at=VALUES(updated_at)`,
		tenant, newAddress, newAddress, now, now, now, now)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	newID, _ := result.LastInsertId()

	tx, err := s.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	fresh, err := referral.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := assignInviteCode(referralBindContext(t, tenant), tx, tenant, uint64(newID), []string{existingCode, fresh}); err != nil {
		t.Fatalf("assign must retry past the collision: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var addressAfter, assigned string
	if err := s.db.QueryRow(`SELECT address FROM wallet_user WHERE id=?`, existingID).Scan(&addressAfter); err != nil {
		t.Fatalf("re-read address: %v", err)
	}
	if addressAfter != addressBefore {
		t.Fatalf("the colliding row was modified: address went from %q to %q", addressBefore, addressAfter)
	}
	if err := s.db.QueryRow(`SELECT invite_code FROM wallet_user WHERE id=?`, newID).Scan(&assigned); err != nil {
		t.Fatalf("read assigned code: %v", err)
	}
	if assigned != fresh {
		t.Fatalf("assigned code = %q, want the second candidate %q", assigned, fresh)
	}
}
