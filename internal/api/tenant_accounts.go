package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"math/big"
	"net/http"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// 控制台账号：租户成员（设计 tenant-console-accounts-and-sso-2026-09-25 §3.2、§3.5、§4.3）与
// 平台管理员（设计 platform-accounts-and-console-login-2026-09-27 §3.1、§3.6），同一张表，scope 区分。
//
// 只有平台管理员能在控制台添加、停用、解绑重置（用户 2026-09-25 定）。租户成员操作的是**当前域名的租户**，
// 与控制台其它按租户的设置一样；平台管理员账号不属于任何租户（tenant_id 为 NULL）。第一个平台管理员
// 用 amos 上的建号命令建（CreatePlatformAccount）。
//
// 生命周期：建号 → pending_bind（发初始口令，72 小时有效，只能用来登录后去绑定）→ 绑定统一认证 →
// active（本地口令作废，只走统一登录）。停用立即生效；换绑只能「解绑并重置初始口令」，本人重新绑定。

const (
	accountPendingBind = "pending_bind"
	accountActive      = "active"
	accountDisabled    = "disabled"

	scopeTenant   = "tenant"
	scopePlatform = "platform"

	idpChainupCID = "chainup-cid"

	initialPasswordTTL = 72 * time.Hour
	initialPasswordLen = 16
)

// 初始口令字母表：去掉 0O1lI 这些抄的时候容易看错的
const initialPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

var loginNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

type tenantAccount struct {
	ID                string
	Scope             string
	TenantID          string // 平台管理员为空
	DisplayName       string
	LoginName         string
	Email             string
	IDP               string
	IDPSubject        string
	IDPEmail          string
	Status            string
	PasswordExpiresAt *time.Time
	CreatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	BoundAt           *time.Time
	LastLoginAt       *time.Time
}

const tenantAccountColumns = `id,scope,tenant_id,display_name,login_name,email,idp,idp_subject,idp_email,status,password_expires_at,created_by,created_at,updated_at,bound_at,last_login_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanTenantAccount(row rowScanner, extra ...any) (*tenantAccount, error) {
	var acc tenantAccount
	var tenant, idp, subject, idpEmail sql.NullString
	var expires, bound, lastLogin sql.NullTime
	dest := append([]any{&acc.ID, &acc.Scope, &tenant, &acc.DisplayName, &acc.LoginName, &acc.Email, &idp, &subject, &idpEmail,
		&acc.Status, &expires, &acc.CreatedBy, &acc.CreatedAt, &acc.UpdatedAt, &bound, &lastLogin}, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	acc.TenantID = tenant.String
	acc.IDP, acc.IDPSubject, acc.IDPEmail = idp.String, subject.String, idpEmail.String
	acc.PasswordExpiresAt = nullTimePointer(expires)
	acc.BoundAt = nullTimePointer(bound)
	acc.LastLoginAt = nullTimePointer(lastLogin)
	return &acc, nil
}

func (a *tenantAccount) platform() bool { return a != nil && a.Scope == scopePlatform }

// actor 是这个账号在会话与审计里的身份：平台管理员 platform:<id>，租户成员 tenant:<租户>:<id>。
func (a *tenantAccount) actor() string {
	if a.platform() {
		return platformActor(a.ID)
	}
	return tenantActor(a.TenantID, a.ID)
}

// auditTenant 是这个账号的审计记在哪个租户下：平台管理员记在平台（0）。
func (a *tenantAccount) auditTenant() string {
	if a.platform() {
		return platformTenantID
	}
	return a.TenantID
}

// auditAction 给账号相关的审计动作加前缀：platform_account_* 或 tenant_account_*。
func (a *tenantAccount) auditAction(verb string) string {
	if a.platform() {
		return "platform_account_" + verb
	}
	return "tenant_account_" + verb
}

func (a *tenantAccount) auditTarget() string {
	if a.platform() {
		return "platform-account"
	}
	return "tenant-account"
}

func nullTimePointer(v sql.NullTime) *time.Time {
	if !v.Valid {
		return nil
	}
	t := v.Time.UTC()
	return &t
}

func isoPointer(t *time.Time) any {
	if t == nil {
		return nil
	}
	return iso(*t)
}

// sessionView 是会话接口里给本人看的那一份：不带统一认证的账号 id，只带绑定时的邮箱。
func (a *tenantAccount) sessionView() gin.H {
	return gin.H{
		"id":          a.ID,
		"scope":       a.Scope,
		"displayName": a.DisplayName,
		"loginName":   a.LoginName,
		"email":       a.Email,
		"status":      a.Status,
		"boundEmail":  nullableString(a.IDPEmail),
	}
}

// adminView 是成员页给平台管理员看的那一份。
func (a *tenantAccount) adminView() gin.H {
	return gin.H{
		"id":                a.ID,
		"scope":             a.Scope,
		"displayName":       a.DisplayName,
		"loginName":         a.LoginName,
		"email":             a.Email,
		"status":            a.Status,
		"bound":             a.IDPSubject != "",
		"boundSubject":      nullableString(a.IDPSubject),
		"boundEmail":        nullableString(a.IDPEmail),
		"boundAt":           isoPointer(a.BoundAt),
		"passwordExpiresAt": isoPointer(a.PasswordExpiresAt),
		"lastLoginAt":       isoPointer(a.LastLoginAt),
		"createdBy":         a.CreatedBy,
		"createdAt":         iso(a.CreatedAt),
		"updatedAt":         iso(a.UpdatedAt),
	}
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanOne(row *sql.Row, extra ...any) (*tenantAccount, error) {
	acc, err := scanTenantAccount(row, extra...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return acc, err
}

func (s *server) tenantAccountByID(ctx context.Context, tenant, id string) (*tenantAccount, error) {
	return scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND tenant_id=? LIMIT 1`, id, tenant))
}

func platformAccountByID(ctx context.Context, db querier, id string) (*tenantAccount, error) {
	return scanOne(db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND scope=? LIMIT 1`, id, scopePlatform))
}

// tenantAccountForLogin 按 (租户, 登录名) 取账号与初始口令哈希。
func (s *server) tenantAccountForLogin(ctx context.Context, tenant, loginName string) (*tenantAccount, string, error) {
	var hash sql.NullString
	acc, err := scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+`,password_hash FROM tenant_admin_accounts WHERE tenant_id=? AND login_name=? LIMIT 1`, tenant, loginName), &hash)
	return acc, hash.String, err
}

// platformAccountForLogin 按登录名取平台管理员账号与初始口令哈希。平台账号的登录名全局唯一，
// 而且不与任何租户成员重名（建号时两边互查），所以先找它不会挡掉某个租户的成员。
func (s *server) platformAccountForLogin(ctx context.Context, loginName string) (*tenantAccount, string, error) {
	var hash sql.NullString
	acc, err := scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+`,password_hash FROM tenant_admin_accounts WHERE scope=? AND login_name=? LIMIT 1`, scopePlatform, loginName), &hash)
	return acc, hash.String, err
}

// tenantAccountBySubject 按 (租户, 统一认证账号) 取已绑定的账号。
func (s *server) tenantAccountBySubject(ctx context.Context, tenant, subject string) (*tenantAccount, error) {
	return scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE tenant_id=? AND idp=? AND idp_subject=? LIMIT 1`, tenant, idpChainupCID, subject))
}

// platformAccountBySubject 取绑定了这个统一认证账号的平台管理员。
func (s *server) platformAccountBySubject(ctx context.Context, subject string) (*tenantAccount, error) {
	return scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE scope=? AND idp=? AND idp_subject=? LIMIT 1`, scopePlatform, idpChainupCID, subject))
}

// subjectIsTenantMember：这个统一认证账号是不是任何一个租户的成员。
func (s *server) subjectIsTenantMember(ctx context.Context, subject string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_admin_accounts WHERE scope=? AND idp=? AND idp_subject=?`,
		scopeTenant, idpChainupCID, subject).Scan(&n)
	return n > 0, err
}

func (s *server) touchTenantAccountLogin(ctx context.Context, id string) {
	now := time.Now().UTC()
	// 只是「最近登录」的显示用字段，写失败不影响登录
	_, _ = s.db.ExecContext(ctx, `UPDATE tenant_admin_accounts SET last_login_at=? WHERE id=?`, now, id)
}

// newInitialPassword 生成初始口令与它的哈希。
func newInitialPassword() (string, string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(initialPasswordAlphabet)))
	for i := 0; i < initialPasswordLen; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", "", err
		}
		b.WriteByte(initialPasswordAlphabet[n.Int64()])
	}
	password := b.String()
	hash, err := hashPassword(password)
	return password, hash, err
}

// ---- 建号、停用、重置（界面与建号命令共用） ----

// accountSpace 是一次操作针对的账号范围：某个租户的成员，或平台管理员（tenant 为空）。
type accountSpace struct {
	scope  string
	tenant string
}

func tenantSpace(tenant string) accountSpace { return accountSpace{scope: scopeTenant, tenant: tenant} }

var platformSpace = accountSpace{scope: scopePlatform}

// key 是唯一键里的 tenant_key：平台管理员记作 0。
func (sp accountSpace) key() string {
	if sp.scope == scopePlatform {
		return "0"
	}
	return sp.tenant
}

func (sp accountSpace) auditTenant() string {
	if sp.scope == scopePlatform {
		return platformTenantID
	}
	return sp.tenant
}

func (sp accountSpace) codePrefix() string {
	if sp.scope == scopePlatform {
		return "PLATFORM_ACCOUNT"
	}
	return "TENANT_ACCOUNT"
}

func (sp accountSpace) auditAction(verb string) string {
	if sp.scope == scopePlatform {
		return "platform_account_" + verb
	}
	return "tenant_account_" + verb
}

func (sp accountSpace) auditTarget() string {
	if sp.scope == scopePlatform {
		return "platform-account"
	}
	return "tenant-account"
}

// accountError 是建号、停用、重置失败时要回给调用方的 problem。
type accountError struct {
	status int
	code   string
	detail string
}

func (e *accountError) Error() string { return e.code + ": " + e.detail }

func accountFailed(sp accountSpace, verb string) *accountError {
	return &accountError{500, sp.codePrefix() + "_" + verb + "_FAILED", "Unable to " + strings.ToLower(verb) + " the account"}
}

type accountInput struct {
	DisplayName string `json:"displayName"`
	LoginName   string `json:"loginName"`
	Email       string `json:"email"`
}

// accountIssued 是建号或重置之后给出去的东西：账号与只出现这一次的初始口令。
type accountIssued struct {
	Account         *tenantAccount
	InitialPassword string
	ExpiresAt       time.Time
}

// createAccount 建一个待绑定的账号。reservedLogin 是环境变量里的管理员用户名（登录时它先走平台口令那条路，
// 同名的账号永远登不进来）。
func createAccount(ctx context.Context, db *sql.DB, sp accountSpace, in accountInput, actorID, reqID, reservedLogin string) (*accountIssued, *accountError) {
	displayName := strings.TrimSpace(in.DisplayName)
	loginName := strings.ToLower(strings.TrimSpace(in.LoginName))
	email := strings.TrimSpace(in.Email)
	switch {
	case displayName == "" || utf8.RuneCountInString(displayName) > 120:
		return nil, &accountError{422, "INVALID_TENANT_ACCOUNT", "displayName must be 1-120 characters"}
	case !loginNamePattern.MatchString(loginName):
		return nil, &accountError{422, "INVALID_LOGIN_NAME", "loginName must be 3-64 characters: lowercase letters, digits, dot, underscore or hyphen, starting with a letter or digit"}
	case reservedLogin != "" && strings.EqualFold(loginName, reservedLogin):
		return nil, &accountError{422, "INVALID_LOGIN_NAME", "loginName is reserved"}
	case !validEmail(email):
		return nil, &accountError{422, "INVALID_EMAIL", "email is not a valid address"}
	}
	password, hash, err := newInitialPassword()
	if err != nil {
		return nil, accountFailed(sp, "CREATE")
	}
	now := time.Now().UTC()
	expires := now.Add(initialPasswordTTL)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, accountFailed(sp, "CREATE")
	}
	defer tx.Rollback()
	// 初始口令登录先找平台账号、再找租户成员：平台账号的登录名不能与任何账号重名，租户成员不能与平台账号重名。
	// FOR UPDATE 锁住这个登录名（ix_tenant_admin_login_name），两边同时建同名账号时后一个等前一个提交
	clash := `SELECT COUNT(*) FROM tenant_admin_accounts WHERE login_name=? AND scope=? FOR UPDATE`
	args := []any{loginName, scopePlatform}
	if sp.scope == scopePlatform {
		clash = `SELECT COUNT(*) FROM tenant_admin_accounts WHERE login_name=? FOR UPDATE`
		args = args[:1]
	}
	var taken int
	if err := tx.QueryRowContext(ctx, clash, args...).Scan(&taken); err != nil {
		return nil, accountFailed(sp, "CREATE")
	}
	if taken > 0 {
		if sp.scope == scopePlatform {
			return nil, &accountError{409, "LOGIN_NAME_TAKEN", "This login name is already used by a platform administrator or a tenant member"}
		}
		return nil, &accountError{409, "LOGIN_NAME_TAKEN", "This login name is used by a platform administrator"}
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO tenant_admin_accounts (scope,tenant_id,display_name,login_name,email,status,password_hash,password_expires_at,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		sp.scope, nullIfEmpty(sp.tenant), displayName, loginName, email, accountPendingBind, hash, expires, actorID, now, now)
	if isDuplicateEntry(err) {
		return nil, &accountError{409, "LOGIN_NAME_TAKEN", "This login name is already used in this tenant"}
	}
	if err != nil {
		return nil, accountFailed(sp, "CREATE")
	}
	id, _ := result.LastInsertId()
	accountID := strconv.FormatInt(id, 10)
	summaryReason := "添加控制台成员"
	if sp.scope == scopePlatform {
		summaryReason = "添加平台管理员"
	}
	// 审计不记初始口令
	event := newAudit(sp.auditTenant(), actorID, sp.auditAction("create"), sp.auditTarget(), accountID, summaryReason, reqID,
		map[string]any{"loginName": loginName, "displayName": displayName, "email": email})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		return nil, accountFailed(sp, "CREATE")
	}
	acc, err := accountInSpace(ctx, db, sp, accountID)
	if err != nil || acc == nil {
		return nil, accountFailed(sp, "CREATE")
	}
	return &accountIssued{Account: acc, InitialPassword: password, ExpiresAt: expires}, nil
}

func accountInSpace(ctx context.Context, db querier, sp accountSpace, id string) (*tenantAccount, error) {
	return scanOne(db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND tenant_key=? AND scope=? LIMIT 1`, id, sp.key(), sp.scope))
}

// accountGuard 在停用、重置落库之前、同一个事务里再挡一次（平台管理员不能动自己、不能动最后一个）。
type accountGuard func(ctx context.Context, tx *sql.Tx, before *tenantAccount) *accountError

// changeAccount 做停用与重置：两者都立刻删掉这个账号的全部会话。
// 重置 = 解除统一认证绑定 + 新的初始口令 + 回到待绑定，本人重新走一遍绑定；也用来让停用的账号复用。
func changeAccount(ctx context.Context, db *sql.DB, sp accountSpace, id, verb, reason, actorID, reqID string, guard accountGuard) (*accountIssued, *accountError) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	defer tx.Rollback()
	before, err := scanOne(tx.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND tenant_key=? AND scope=? FOR UPDATE`, id, sp.key(), sp.scope))
	if err != nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	if before == nil {
		return nil, &accountError{404, sp.codePrefix() + "_NOT_FOUND", "Account not found"}
	}
	if guard != nil {
		if problem := guard(ctx, tx, before); problem != nil {
			return nil, problem
		}
	}
	now := time.Now().UTC()
	issued := &accountIssued{}
	summary := map[string]any{"loginName": before.LoginName, "fromStatus": before.Status}
	if verb == "disable" {
		if before.Status == accountDisabled {
			return nil, &accountError{409, sp.codePrefix() + "_ALREADY_DISABLED", "The account is already disabled"}
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_admin_accounts SET status=?,password_hash=NULL,password_expires_at=NULL,updated_at=? WHERE id=?`,
			accountDisabled, now, id)
	} else {
		password, hash, genErr := newInitialPassword()
		if genErr != nil {
			return nil, accountFailed(sp, "UPDATE")
		}
		expires := now.Add(initialPasswordTTL)
		_, err = tx.ExecContext(ctx,
			`UPDATE tenant_admin_accounts SET status=?,idp=NULL,idp_subject=NULL,idp_email=NULL,bound_at=NULL,password_hash=?,password_expires_at=?,updated_at=? WHERE id=?`,
			accountPendingBind, hash, expires, now, id)
		issued.InitialPassword, issued.ExpiresAt = password, expires
		summary["unboundSubject"] = nullableString(before.IDPSubject)
	}
	if err != nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions WHERE account_id=?`, id); err != nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	event := newAudit(sp.auditTenant(), actorID, sp.auditAction(verb), sp.auditTarget(), id, reason, reqID, summary)
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	acc, err := accountInSpace(ctx, db, sp, id)
	if err != nil || acc == nil {
		return nil, accountFailed(sp, "UPDATE")
	}
	issued.Account = acc
	return issued, nil
}

// ---- 平台管理员的成员页接口 ----

func (s *server) listAccounts(c *gin.Context, sp accountSpace) {
	query, args := `SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE tenant_id=? ORDER BY id`, []any{sp.tenant}
	if sp.scope == scopePlatform {
		query, args = `SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE scope=? ORDER BY id`, []any{scopePlatform}
	}
	rows, err := s.db.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		problem(c, 500, sp.codePrefix()+"S_READ_FAILED", "Unable to list accounts")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		acc, err := scanTenantAccount(rows)
		if err != nil {
			problem(c, 500, sp.codePrefix()+"S_READ_FAILED", "Unable to list accounts")
			return
		}
		items = append(items, acc.adminView())
	}
	if rows.Err() != nil {
		problem(c, 500, sp.codePrefix()+"S_READ_FAILED", "Unable to list accounts")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}

func (s *server) createAccountHTTP(c *gin.Context, sp accountSpace) {
	var body accountInput
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_TENANT_ACCOUNT", "displayName, loginName and email are required")
		return
	}
	issued, failure := createAccount(c.Request.Context(), s.db, sp, body, actor(c), requestID(c), s.cfg.AdminUsername)
	if failure != nil {
		problem(c, failure.status, failure.code, failure.detail)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(201, gin.H{"account": issued.Account.adminView(), "initialPassword": issued.InitialPassword, "passwordExpiresAt": iso(issued.ExpiresAt)})
}

func (s *server) changeAccountHTTP(c *gin.Context, sp accountSpace, verb string, guard accountGuard) {
	id, ok := parseAccountID(c.Param("id"))
	if !ok {
		problem(c, 404, sp.codePrefix()+"_NOT_FOUND", "Account not found")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if decode(c, &body) != nil || utf8.RuneCountInString(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "REASON_REQUIRED", "reason is required (at least 3 characters); it is written to the audit log")
		return
	}
	issued, failure := changeAccount(c.Request.Context(), s.db, sp, id, verb, strings.TrimSpace(body.Reason), actor(c), requestID(c), guard)
	if failure != nil {
		problem(c, failure.status, failure.code, failure.detail)
		return
	}
	response := gin.H{"account": issued.Account.adminView()}
	if issued.InitialPassword != "" {
		response["initialPassword"] = issued.InitialPassword
		response["passwordExpiresAt"] = iso(issued.ExpiresAt)
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, response)
}

// 租户成员（current 组，按域名的租户）

func (s *server) listTenantAccounts(c *gin.Context) { s.listAccounts(c, tenantSpace(tenantID(c))) }
func (s *server) createTenantAccount(c *gin.Context) {
	s.createAccountHTTP(c, tenantSpace(tenantID(c)))
}
func (s *server) disableTenantAccount(c *gin.Context) {
	s.changeAccountHTTP(c, tenantSpace(tenantID(c)), "disable", nil)
}
func (s *server) resetTenantAccount(c *gin.Context) {
	s.changeAccountHTTP(c, tenantSpace(tenantID(c)), "reset", nil)
}

// 平台管理员（platform 组）

func (s *server) listPlatformAccounts(c *gin.Context)  { s.listAccounts(c, platformSpace) }
func (s *server) createPlatformAccount(c *gin.Context) { s.createAccountHTTP(c, platformSpace) }
func (s *server) disablePlatformAccount(c *gin.Context) {
	s.changeAccountHTTP(c, platformSpace, "disable", platformAccountGuard(currentAdminSession(c)))
}
func (s *server) resetPlatformAccount(c *gin.Context) {
	s.changeAccountHTTP(c, platformSpace, "reset", platformAccountGuard(currentAdminSession(c)))
}

// platformAccountGuard：不能停用、重置自己（要换绑自己的，请另一位平台管理员来，或在 amos 上用建号命令）；
// 也不能让最后一个可用的平台管理员失效——否则控制台里就没有人能再管平台了。
func platformAccountGuard(session *adminSession) accountGuard {
	return func(ctx context.Context, tx *sql.Tx, before *tenantAccount) *accountError {
		if session != nil && session.AccountID == before.ID {
			return &accountError{409, "CANNOT_CHANGE_OWN_ACCOUNT", "You cannot disable or reset your own platform account; ask another platform administrator"}
		}
		if before.Status != accountActive {
			return nil
		}
		// 锁住其余可用的平台账号：两位管理员同时停用对方时，后一个会等前一个提交、看到它的结果
		rows, err := tx.QueryContext(ctx, `SELECT id FROM tenant_admin_accounts WHERE scope=? AND status=? AND id<>? FOR UPDATE`,
			scopePlatform, accountActive, before.ID)
		if err != nil {
			return accountFailed(platformSpace, "UPDATE")
		}
		others := 0
		for rows.Next() {
			others++
		}
		failed := rows.Err() != nil
		rows.Close()
		if failed {
			return accountFailed(platformSpace, "UPDATE")
		}
		if others == 0 {
			return &accountError{409, "LAST_PLATFORM_ADMIN", "This is the last active platform administrator; add and bind another one first"}
		}
		return nil
	}
}

// ---- amos 上的建号命令（cmd/server「admin platform-account」） ----

// PlatformAccountIssued 是建号命令打印给执行者的东西。
type PlatformAccountIssued struct {
	ID              string
	LoginName       string
	Email           string
	InitialPassword string
	ExpiresAt       time.Time
}

// CreatePlatformAccount 建一个待绑定的平台管理员账号。控制台里一个平台管理员都没有时（第一个、或全部失效之后），
// 只能在服务器上这样建。actor 写进审计（建号人）。
func CreatePlatformAccount(ctx context.Context, db *sql.DB, loginName, email, displayName, actorID, reservedLogin string) (*PlatformAccountIssued, error) {
	issued, failure := createAccount(ctx, db, platformSpace, accountInput{DisplayName: displayName, LoginName: loginName, Email: email},
		actorID, "cli-"+randomID(6), reservedLogin)
	if failure != nil {
		return nil, failure
	}
	return platformIssued(issued), nil
}

// ResetPlatformAccount 把平台管理员账号解绑、回到待绑定并给新的初始口令。命令行是最后的找回手段，
// 所以不受「最后一个平台管理员」的限制。
func ResetPlatformAccount(ctx context.Context, db *sql.DB, loginName, reason, actorID string) (*PlatformAccountIssued, error) {
	var id string
	err := db.QueryRowContext(ctx, `SELECT id FROM tenant_admin_accounts WHERE scope=? AND login_name=? LIMIT 1`,
		scopePlatform, strings.ToLower(strings.TrimSpace(loginName))).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &accountError{404, "PLATFORM_ACCOUNT_NOT_FOUND", "No platform account with this login name"}
	}
	if err != nil {
		return nil, err
	}
	issued, failure := changeAccount(ctx, db, platformSpace, id, "reset", reason, actorID, "cli-"+randomID(6), nil)
	if failure != nil {
		return nil, failure
	}
	return platformIssued(issued), nil
}

func platformIssued(issued *accountIssued) *PlatformAccountIssued {
	return &PlatformAccountIssued{ID: issued.Account.ID, LoginName: issued.Account.LoginName, Email: issued.Account.Email,
		InitialPassword: issued.InitialPassword, ExpiresAt: issued.ExpiresAt}
}

func validEmail(v string) bool {
	if v == "" || len(v) > 255 || strings.ContainsAny(v, " <>") {
		return false
	}
	addr, err := mail.ParseAddress(v)
	return err == nil && addr.Address == v && strings.Contains(v[strings.LastIndex(v, "@")+1:], ".")
}
