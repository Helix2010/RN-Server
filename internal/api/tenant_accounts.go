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

// 租户控制台账号（设计 tenant-console-accounts-and-sso-2026-09-25 §3.2、§3.5、§4.3）。
//
// 只有平台管理员能在控制台添加、停用、解绑重置（用户 2026-09-25 定）。操作的是**当前域名的租户**，
// 与控制台其它按租户的设置一样：平台管理员在哪个租户的控制台上，就管哪个租户的成员。
//
// 生命周期：建号 → pending_bind（发初始口令，72 小时有效，只能用来登录后去绑定）→ 绑定统一认证 →
// active（本地口令作废，只走统一登录）。停用立即生效；换绑只能「解绑并重置初始口令」，本人重新绑定。

const (
	accountPendingBind = "pending_bind"
	accountActive      = "active"
	accountDisabled    = "disabled"

	idpChainupCID = "chainup-cid"

	initialPasswordTTL = 72 * time.Hour
	initialPasswordLen = 16
)

// 初始口令字母表：去掉 0O1lI 这些抄的时候容易看错的
const initialPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

var loginNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

type tenantAccount struct {
	ID                string
	TenantID          string
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

const tenantAccountColumns = `id,tenant_id,display_name,login_name,email,idp,idp_subject,idp_email,status,password_expires_at,created_by,created_at,updated_at,bound_at,last_login_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanTenantAccount(row rowScanner, extra ...any) (*tenantAccount, error) {
	var acc tenantAccount
	var idp, subject, idpEmail sql.NullString
	var expires, bound, lastLogin sql.NullTime
	dest := append([]any{&acc.ID, &acc.TenantID, &acc.DisplayName, &acc.LoginName, &acc.Email, &idp, &subject, &idpEmail,
		&acc.Status, &expires, &acc.CreatedBy, &acc.CreatedAt, &acc.UpdatedAt, &bound, &lastLogin}, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	acc.IDP, acc.IDPSubject, acc.IDPEmail = idp.String, subject.String, idpEmail.String
	acc.PasswordExpiresAt = nullTimePointer(expires)
	acc.BoundAt = nullTimePointer(bound)
	acc.LastLoginAt = nullTimePointer(lastLogin)
	return &acc, nil
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

func (s *server) tenantAccountByID(ctx context.Context, tenant, id string) (*tenantAccount, error) {
	acc, err := scanTenantAccount(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND tenant_id=? LIMIT 1`, id, tenant))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return acc, err
}

// tenantAccountForLogin 按 (租户, 登录名) 取账号与初始口令哈希。
func (s *server) tenantAccountForLogin(ctx context.Context, tenant, loginName string) (*tenantAccount, string, error) {
	var hash sql.NullString
	acc, err := scanTenantAccount(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+`,password_hash FROM tenant_admin_accounts WHERE tenant_id=? AND login_name=? LIMIT 1`, tenant, loginName), &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return acc, hash.String, nil
}

// tenantAccountBySubject 按 (租户, 统一认证账号) 取已绑定的账号。
func (s *server) tenantAccountBySubject(ctx context.Context, tenant, subject string) (*tenantAccount, error) {
	acc, err := scanTenantAccount(s.db.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE tenant_id=? AND idp=? AND idp_subject=? LIMIT 1`, tenant, idpChainupCID, subject))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return acc, err
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

// ---- 平台管理员的成员页接口（current 组，按域名的租户） ----

func (s *server) listTenantAccounts(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE tenant_id=? ORDER BY id`, tenantID(c))
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list tenant accounts")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		acc, err := scanTenantAccount(rows)
		if err != nil {
			problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list tenant accounts")
			return
		}
		items = append(items, acc.adminView())
	}
	if rows.Err() != nil {
		problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list tenant accounts")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}

func (s *server) createTenantAccount(c *gin.Context) {
	var body struct {
		DisplayName string `json:"displayName"`
		LoginName   string `json:"loginName"`
		Email       string `json:"email"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_TENANT_ACCOUNT", "displayName, loginName and email are required")
		return
	}
	displayName := strings.TrimSpace(body.DisplayName)
	loginName := strings.ToLower(strings.TrimSpace(body.LoginName))
	email := strings.TrimSpace(body.Email)
	switch {
	case displayName == "" || utf8.RuneCountInString(displayName) > 120:
		problem(c, 422, "INVALID_TENANT_ACCOUNT", "displayName must be 1-120 characters")
		return
	case !loginNamePattern.MatchString(loginName):
		problem(c, 422, "INVALID_LOGIN_NAME", "loginName must be 3-64 characters: lowercase letters, digits, dot, underscore or hyphen, starting with a letter or digit")
		return
	case s.cfg.AdminUsername != "" && strings.EqualFold(loginName, s.cfg.AdminUsername):
		// 登录时用户名等于 ADMIN_USERNAME 会先走平台账号那条路，这个租户账号永远登不进来
		problem(c, 422, "INVALID_LOGIN_NAME", "loginName is reserved")
		return
	case !validEmail(email):
		problem(c, 422, "INVALID_EMAIL", "email is not a valid address")
		return
	}
	password, hash, err := newInitialPassword()
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_CREATE_FAILED", "Unable to create the account")
		return
	}
	now := time.Now().UTC()
	expires := now.Add(initialPasswordTTL)
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_CREATE_FAILED", "Unable to create the account")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(),
		`INSERT INTO tenant_admin_accounts (tenant_id,display_name,login_name,email,status,password_hash,password_expires_at,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		tenantID(c), displayName, loginName, email, accountPendingBind, hash, expires, actor(c), now, now)
	if isDuplicateEntry(err) {
		problem(c, 409, "LOGIN_NAME_TAKEN", "This login name is already used in this tenant")
		return
	}
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_CREATE_FAILED", "Unable to create the account")
		return
	}
	id, _ := result.LastInsertId()
	accountID := strconv.FormatInt(id, 10)
	// 审计不记初始口令
	event := newAudit(tenantID(c), actor(c), "tenant_account_create", "tenant-account", accountID, "添加控制台成员", requestID(c),
		map[string]any{"loginName": loginName, "displayName": displayName, "email": email})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TENANT_ACCOUNT_CREATE_FAILED", "Unable to create the account")
		return
	}
	acc, err := s.tenantAccountByID(c.Request.Context(), tenantID(c), accountID)
	if err != nil || acc == nil {
		problem(c, 500, "TENANT_ACCOUNT_CREATE_FAILED", "Unable to read the created account")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(201, gin.H{"account": acc.adminView(), "initialPassword": password, "passwordExpiresAt": iso(expires)})
}

func (s *server) disableTenantAccount(c *gin.Context) {
	s.changeTenantAccount(c, "tenant_account_disable")
}

func (s *server) resetTenantAccount(c *gin.Context) {
	s.changeTenantAccount(c, "tenant_account_reset")
}

// changeTenantAccount 做停用与重置：两者都立刻删掉这个账号的全部会话。
// 重置 = 解除统一认证绑定 + 新的初始口令 + 回到待绑定，本人重新走一遍绑定；也用来让停用的账号复用。
func (s *server) changeTenantAccount(c *gin.Context, action string) {
	id, ok := parseAccountID(c.Param("id"))
	if !ok {
		problem(c, 404, "TENANT_ACCOUNT_NOT_FOUND", "Tenant account not found")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if decode(c, &body) != nil || utf8.RuneCountInString(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "REASON_REQUIRED", "reason is required (at least 3 characters); it is written to the audit log")
		return
	}
	reason := strings.TrimSpace(body.Reason)
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
		return
	}
	defer tx.Rollback()
	before, err := scanTenantAccount(tx.QueryRowContext(ctx,
		`SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE id=? AND tenant_id=? FOR UPDATE`, id, tenantID(c)))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "TENANT_ACCOUNT_NOT_FOUND", "Tenant account not found")
		return
	}
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
		return
	}
	now := time.Now().UTC()
	response := gin.H{}
	summary := map[string]any{"loginName": before.LoginName, "fromStatus": before.Status}
	if action == "tenant_account_disable" {
		if before.Status == accountDisabled {
			problem(c, 409, "TENANT_ACCOUNT_ALREADY_DISABLED", "The account is already disabled")
			return
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_admin_accounts SET status=?,password_hash=NULL,password_expires_at=NULL,updated_at=? WHERE id=?`,
			accountDisabled, now, id)
	} else {
		password, hash, genErr := newInitialPassword()
		if genErr != nil {
			problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
			return
		}
		expires := now.Add(initialPasswordTTL)
		_, err = tx.ExecContext(ctx,
			`UPDATE tenant_admin_accounts SET status=?,idp=NULL,idp_subject=NULL,idp_email=NULL,bound_at=NULL,password_hash=?,password_expires_at=?,updated_at=? WHERE id=?`,
			accountPendingBind, hash, expires, now, id)
		response["initialPassword"] = password
		response["passwordExpiresAt"] = iso(expires)
		summary["unboundSubject"] = nullableString(before.IDPSubject)
	}
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
		return
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_sessions WHERE account_id=?`, id); err != nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
		return
	}
	event := newAudit(tenantID(c), actor(c), action, "tenant-account", id, reason, requestID(c), summary)
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to update the account")
		return
	}
	acc, err := s.tenantAccountByID(ctx, tenantID(c), id)
	if err != nil || acc == nil {
		problem(c, 500, "TENANT_ACCOUNT_UPDATE_FAILED", "Unable to read the account")
		return
	}
	response["account"] = acc.adminView()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, response)
}

func validEmail(v string) bool {
	if v == "" || len(v) > 255 || strings.ContainsAny(v, " <>") {
		return false
	}
	addr, err := mail.ParseAddress(v)
	return err == nil && addr.Address == v && strings.Contains(v[strings.LastIndex(v, "@")+1:], ".")
}
