package api

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 控制台账号：租户成员与平台管理员，同一张表，scope 区分
// （设计 console-accounts-external-maintenance-2026-09-27）。
//
// 账号由外部系统（统一登录的平台端）分配、停用、换人，直接写 tenant_admin_accounts；RN 只读，按自己的
// 规则鉴别（cid_login.go 的回调、admin_session.go 的每个请求），唯一写的是 last_login_at。控制台里只有
// 只读列表，只给平台管理员看。

const (
	// accountActive 是能登录的状态；另一个状态 disabled 由外部系统写，RN 只认 active（表上有 CHECK）
	accountActive = "active"

	scopeTenant   = "tenant"
	scopePlatform = "platform"
)

type tenantAccount struct {
	ID          string
	Scope       string
	TenantID    string // 平台管理员为空
	DisplayName string
	Email       string
	IDPSubject  string
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	LastLoginAt *time.Time
}

const tenantAccountColumns = `id,scope,tenant_id,display_name,email,idp_subject,status,created_by,created_at,last_login_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanTenantAccount(row rowScanner) (*tenantAccount, error) {
	var acc tenantAccount
	var tenant sql.NullString
	var lastLogin sql.NullTime
	if err := row.Scan(&acc.ID, &acc.Scope, &tenant, &acc.DisplayName, &acc.Email, &acc.IDPSubject,
		&acc.Status, &acc.CreatedBy, &acc.CreatedAt, &lastLogin); err != nil {
		return nil, err
	}
	acc.TenantID = tenant.String
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

// label 是邮件里称呼这个账号用的：显示名，没有就用邮箱（显示名由外部系统写，可以为空）。
func (a *tenantAccount) label() string {
	if name := strings.TrimSpace(a.DisplayName); name != "" {
		return name
	}
	return a.Email
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

// sessionView 是会话接口里给本人看的那一份（控制台右上角用）：不带统一认证的账号 id。
func (a *tenantAccount) sessionView() gin.H {
	return gin.H{"id": a.ID, "displayName": a.DisplayName, "email": a.Email}
}

// adminView 是只读列表给平台管理员看的那一份。平台管理员与租户成员各有各的接口，scope、租户不用再给。
func (a *tenantAccount) adminView() gin.H {
	return gin.H{
		"id":          a.ID,
		"displayName": a.DisplayName,
		"email":       a.Email,
		"subject":     a.IDPSubject,
		"status":      a.Status,
		"lastLoginAt": isoPointer(a.LastLoginAt),
		"createdBy":   a.CreatedBy,
		"createdAt":   iso(a.CreatedAt),
	}
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func scanOne(row *sql.Row) (*tenantAccount, error) {
	acc, err := scanTenantAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return acc, err
}

func (s *server) tenantAccountByID(ctx context.Context, tenant, id string) (*tenantAccount, error) {
	return scanOne(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND scope=? AND tenant_id=? LIMIT 1`, id, scopeTenant, tenant))
}

func platformAccountByID(ctx context.Context, db querier, id string) (*tenantAccount, error) {
	return scanOne(db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND scope=? LIMIT 1`, id, scopePlatform))
}

// accountsBySubject 取这个统一认证账号在平台与各租户的全部记录（uq_tenant_admin_subject），回调据此认人。
func (s *server) accountsBySubject(ctx context.Context, subject string) ([]*tenantAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE idp_subject=? ORDER BY id`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []*tenantAccount
	for rows.Next() {
		acc, err := scanTenantAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}

// touchTenantAccountLogin 写最近登录时间：这张表里 RN 唯一写的列。
func (s *server) touchTenantAccountLogin(ctx context.Context, id string) {
	now := time.Now().UTC()
	// 只是「最近登录」的显示用字段，写失败不影响登录
	_, _ = s.db.ExecContext(ctx, `UPDATE tenant_admin_accounts SET last_login_at=? WHERE id=?`, now, id)
}

// ---- 只读列表（只给平台管理员） ----

func (s *server) listAccounts(c *gin.Context, codePrefix, where string, args ...any) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		problem(c, 500, codePrefix+"S_READ_FAILED", "Unable to list accounts")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		acc, err := scanTenantAccount(rows)
		if err != nil {
			problem(c, 500, codePrefix+"S_READ_FAILED", "Unable to list accounts")
			return
		}
		items = append(items, acc.adminView())
	}
	if rows.Err() != nil {
		problem(c, 500, codePrefix+"S_READ_FAILED", "Unable to list accounts")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}

// listTenantAccounts 列当前域名所属租户的成员（current 组）。
func (s *server) listTenantAccounts(c *gin.Context) {
	s.listAccounts(c, "TENANT_ACCOUNT", `scope=? AND tenant_id=?`, scopeTenant, tenantID(c))
}

// listPlatformAccounts 列平台管理员（platform 组）。
func (s *server) listPlatformAccounts(c *gin.Context) {
	s.listAccounts(c, "PLATFORM_ACCOUNT", `scope=?`, scopePlatform)
}
