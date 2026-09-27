package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/mail"
	"github.com/gin-gonic/gin"
)

// 平台发信（ADR-0022）：发件的 SMTP 账号是 app_configs 平台级 mail.smtp，口令用 secretbox 加密。
// 目前只有控制台账号的邮箱二次验证码用它；没配就过不了二次验证（不为「没配」退回不校验，见 AGENTS.md「不写回退」）。
//
//	GET    /v1/admin/platform/mail          配置；口令永不返回，只说有没有
//	PUT    /v1/admin/platform/mail          host、port（空 = 587）、username、password（留空沿用）、fromAddress、fromName、expectedVersion、reason
//	DELETE /v1/admin/platform/mail?reason=  删掉
//	POST   /v1/admin/platform/mail/test     {to, reason}：用已保存的配置发一封测试邮件

const (
	mailConfigKey       = "mail.smtp"
	mailSendTimeout     = 20 * time.Second
	mailTestPerHour     = 10
	mailProblemSendFail = "MAIL_SEND_FAILED"
)

func mailPasswordAAD() string { return "mail-smtp:password" }

// mailStored 是 app_configs 平台级 mail.smtp 的 config_value。
type mailStored struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Username          string `json:"username"`
	PasswordEncrypted string `json:"passwordEncrypted"`
	FromAddress       string `json:"fromAddress"`
	FromName          string `json:"fromName"`
}

type mailRecord struct {
	Value     mailStored
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func (s *server) mailRecord(ctx context.Context) (*mailRecord, error) {
	var raw []byte
	var record mailRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		platformTenantID, mailConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *server) decryptMailPassword(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	if s.secrets == nil {
		return "", errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", errors.New("stored SMTP password is not valid base64")
	}
	return s.secrets.Decrypt(ciphertext, mailPasswordAAD())
}

// mailConfig 取发件账号（口令已解密）。没配返回 (nil, nil)。
func (s *server) mailConfig(ctx context.Context) (*mail.Config, error) {
	record, err := s.mailRecord(ctx)
	if err != nil || record == nil {
		return nil, err
	}
	password, err := s.decryptMailPassword(record.Value.PasswordEncrypted)
	if err != nil {
		return nil, err
	}
	return &mail.Config{Host: record.Value.Host, Port: record.Value.Port, Username: record.Value.Username, Password: password,
		FromAddress: record.Value.FromAddress, FromName: record.Value.FromName}, nil
}

// sendMail 用平台发件账号投递。返回的 problem code 给界面分辨「查哪一项」；对方服务器的原话只进日志。
func (s *server) sendMail(ctx context.Context, cfg mail.Config, msg mail.Message) (problemCode string, err error) {
	ctx, cancel := context.WithTimeout(ctx, mailSendTimeout)
	defer cancel()
	err = mail.Send(ctx, cfg, msg)
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, mail.ErrConnect):
		problemCode = "MAIL_CONNECT_FAILED"
	case errors.Is(err, mail.ErrTLS):
		problemCode = "MAIL_TLS_FAILED"
	case errors.Is(err, mail.ErrAuth):
		problemCode = "MAIL_AUTH_FAILED"
	case errors.Is(err, mail.ErrRejected):
		problemCode = "MAIL_REJECTED"
	default:
		problemCode = mailProblemSendFail
	}
	slog.Warn("mail not sent", "host", cfg.Host, "port", cfg.Port, "to", maskEmail(msg.To), "error", err)
	return problemCode, err
}

// maskEmail 留首字母与域名，日志与审计里用。
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}

func mailConfigView(record *mailRecord) gin.H {
	// defaultPort 是服务端声明的默认端口，管理端没存过时拿它预填，而不是自己猜
	if record == nil {
		return gin.H{"configured": false, "config": nil, "defaultPort": mail.DefaultPort, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured":  true,
		"defaultPort": mail.DefaultPort,
		"config": gin.H{
			"host":        record.Value.Host,
			"port":        record.Value.Port,
			"username":    record.Value.Username,
			"hasPassword": record.Value.PasswordEncrypted != "",
			"fromAddress": record.Value.FromAddress,
			"fromName":    record.Value.FromName,
		},
		"version":   record.Version,
		"updatedBy": record.UpdatedBy,
		"updatedAt": iso(record.UpdatedAt),
	}
}

func (s *server) getMailConfig(c *gin.Context) {
	record, err := s.mailRecord(c.Request.Context())
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_INVALID", "Stored "+mailConfigKey+" configuration is invalid")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, mailConfigView(record))
}

// updateMailConfig 保存发件账号。password 留空表示沿用已存的口令。
func (s *server) updateMailConfig(c *gin.Context) {
	var body struct {
		Host            string `json:"host"`
		Port            int    `json:"port"`
		Username        string `json:"username"`
		Password        string `json:"password"`
		FromAddress     string `json:"fromAddress"`
		FromName        string `json:"fromName"`
		ExpectedVersion int    `json:"expectedVersion"`
		Reason          string `json:"reason"`
	}
	if decodeLimited(c, &body, 16<<10) != nil || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, 400, "INVALID_MAIL_CONFIG", "host, fromAddress, expectedVersion and reason are required")
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "STORAGE_MASTER_KEY must be configured before saving the SMTP password")
		return
	}
	ctx := c.Request.Context()
	current, err := s.mailRecord(ctx)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_INVALID", "Stored "+mailConfigKey+" configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, 409, "STALE_MAIL_CONFIG", "The email settings changed; reload and retry")
		return
	}
	password := body.Password
	encrypted := ""
	if password == "" && strings.TrimSpace(body.Username) != "" && current != nil && current.Value.Username != "" {
		// 只有服务器、端口、用户名都没变才沿用旧口令：否则改个地址再发测试邮件，就能把口令送到别的服务器
		port := body.Port
		if port == 0 {
			port = mail.DefaultPort
		}
		if strings.ToLower(strings.TrimSpace(body.Host)) != current.Value.Host || port != current.Value.Port ||
			strings.TrimSpace(body.Username) != current.Value.Username {
			problem(c, 422, "MAIL_PASSWORD_REQUIRED", "Enter the password again when the host, port or username changes")
			return
		}
		if password, err = s.decryptMailPassword(current.Value.PasswordEncrypted); err != nil {
			problem(c, 500, "MAIL_CONFIG_INVALID", "Stored SMTP password cannot be decrypted; enter it again")
			return
		}
		encrypted = current.Value.PasswordEncrypted
	}
	cfg, err := mail.Config{Host: body.Host, Port: body.Port, Username: body.Username, Password: password,
		FromAddress: body.FromAddress, FromName: body.FromName}.Normalize()
	if err != nil {
		problem(c, 422, "INVALID_MAIL_CONFIG", err.Error())
		return
	}
	if cfg.Username == "" {
		encrypted = "" // 不认证的服务器（内网中继）不存口令
	} else if encrypted == "" {
		ciphertext, err := s.secrets.Encrypt(cfg.Password, mailPasswordAAD())
		if err != nil {
			problem(c, 500, "MAIL_CONFIG_SAVE_FAILED", "Unable to encrypt the SMTP password")
			return
		}
		encrypted = base64.RawStdEncoding.EncodeToString(ciphertext)
	}
	value := mailStored{Host: cfg.Host, Port: cfg.Port, Username: cfg.Username, PasswordEncrypted: encrypted,
		FromAddress: cfg.FromAddress, FromName: cfg.FromName}
	stored, _ := json.Marshal(value)
	now := s.now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_SAVE_FAILED", "Unable to save the email settings")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	if currentVersion > 0 {
		result, err = tx.ExecContext(ctx,
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, actor(c), now, platformTenantID, mailConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			platformTenantID, mailConfigKey, stored, actor(c), now, platformTenantID, mailConfigKey)
	}
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_SAVE_FAILED", "Unable to save the email settings")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 409, "STALE_MAIL_CONFIG", "The email settings changed; reload and retry")
		return
	}
	event := newAudit(platformTenantID, actor(c), "mail_config_update", "app-config", mailConfigKey, body.Reason, requestID(c),
		map[string]any{"host": cfg.Host, "port": cfg.Port, "username": cfg.Username, "fromAddress": cfg.FromAddress, "fromName": cfg.FromName,
			"passwordChanged": body.Password != "", "databaseVersion": currentVersion + 1})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "MAIL_CONFIG_SAVE_FAILED", "Unable to save the email settings")
		return
	}
	c.JSON(200, mailConfigView(&mailRecord{Value: value, Version: currentVersion + 1, UpdatedBy: actor(c), UpdatedAt: now}))
}

// deleteMailConfig 删掉发件账号：之后控制台账号过不了二次验证，直到重新配置。
func (s *server) deleteMailConfig(c *gin.Context) {
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) < 3 {
		problem(c, 400, "INVALID_MAIL_CONFIG", "reason is required")
		return
	}
	ctx := c.Request.Context()
	// 平台管理员账号做写操作都要过邮箱二次验证，验证码靠这份配置发出去：删了就再没人能改回来
	// （只剩服务器上的管理密钥）。要换发信账号直接改，不用先删
	var platformAccounts int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenant_admin_accounts WHERE scope=? AND status=?`, scopePlatform, accountActive).Scan(&platformAccounts); err != nil {
		problem(c, 500, "MAIL_CONFIG_DELETE_FAILED", "Unable to delete the email settings")
		return
	}
	if platformAccounts > 0 {
		problem(c, 409, "MAIL_REQUIRED_FOR_SECOND_FACTOR", "Platform administrators need email to pass the second factor; change the settings instead of deleting them")
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_DELETE_FAILED", "Unable to delete the email settings")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, platformTenantID, mailConfigKey)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_DELETE_FAILED", "Unable to delete the email settings")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 404, "MAIL_NOT_CONFIGURED", "Email sending is not configured")
		return
	}
	event := newAudit(platformTenantID, actor(c), "mail_config_delete", "app-config", mailConfigKey, reason, requestID(c), map[string]any{})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, 500, "MAIL_CONFIG_DELETE_FAILED", "Unable to delete the email settings")
		return
	}
	c.JSON(200, mailConfigView(nil))
}

// sendTestMail 用已保存的配置发一封测试邮件，确认账号、端口、TLS 都对。
func (s *server) sendTestMail(c *gin.Context) {
	var body struct {
		To     string `json:"to"`
		Reason string `json:"reason"`
	}
	if decodeLimited(c, &body, 4<<10) != nil || strings.TrimSpace(body.To) == "" || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "INVALID_MAIL_TEST", "to and reason are required")
		return
	}
	ctx := c.Request.Context()
	cfg, err := s.mailConfig(ctx)
	if err != nil {
		problem(c, 500, "MAIL_CONFIG_INVALID", "Stored "+mailConfigKey+" configuration is invalid")
		return
	}
	if cfg == nil {
		problem(c, 409, "MAIL_NOT_CONFIGURED", "Save the email settings first")
		return
	}
	if !s.mailTests.allow(actor(c), mailTestPerHour, time.Hour, s.now()) {
		problem(c, 429, "MAIL_TEST_RATE_LIMITED", "Too many test emails; try again later")
		return
	}
	code, err := s.sendMail(ctx, *cfg, mail.Message{
		To:      strings.TrimSpace(body.To),
		Subject: "RN 平台发信测试 / RN platform email test",
		Text:    "这是一封测试邮件，说明 RN 平台的发信配置可用。\nThis is a test email: the RN platform email settings work.",
	})
	event := newAudit(platformTenantID, actor(c), "mail_test_sent", "app-config", mailConfigKey, body.Reason, requestID(c),
		map[string]any{"to": maskEmail(strings.TrimSpace(body.To)), "sent": err == nil, "problem": nullableString(code)})
	s.auditNow(event)
	if err != nil {
		mailProblem(c, code)
		return
	}
	c.JSON(200, gin.H{"sent": true})
}

// mailProblem 把发信失败的种类翻成固定的 Problem；不回显对方服务器的原话。
func mailProblem(c *gin.Context, code string) {
	switch code {
	case "MAIL_CONNECT_FAILED":
		problem(c, 502, code, "Cannot reach the SMTP server; check host and port")
	case "MAIL_TLS_FAILED":
		problem(c, 502, code, "TLS with the SMTP server failed; use port 465 or a server with STARTTLS")
	case "MAIL_AUTH_FAILED":
		problem(c, 502, code, "The SMTP server rejected the username or password")
	case "MAIL_REJECTED":
		problem(c, 502, code, "The SMTP server rejected the message; check the sender and recipient")
	default:
		problem(c, 502, mailProblemSendFail, "Unable to send the email")
	}
}
