// Package mail 通过 SMTP 发平台邮件（ADR-0022）。只管「连上、认证、投递」，发件账号的保存
// （app_configs 平台级 mail.smtp，口令加密）与邮件内容都在调用方。
//
// 传输安全：465 端口走隐式 TLS；其它端口必须 STARTTLS。只有本机地址允许明文（本地调试用的
// 假 SMTP），不为「对方不支持 TLS」退回明文——验证码与账号口令都不该明文过网。
package mail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// 失败的种类，调用方用 errors.Is 区分，好给出「查哪一项」的提示；原始错误（含对方服务器的原话）只进日志。
var (
	ErrConnect  = errors.New("cannot reach the SMTP server")
	ErrTLS      = errors.New("TLS with the SMTP server failed")
	ErrAuth     = errors.New("SMTP authentication failed")
	ErrRejected = errors.New("the SMTP server rejected the message")
)

// testRootCAs 替换 TLS 校验用的根证书，只有测试会设；nil = 系统根证书。
var testRootCAs *x509.CertPool

func tlsConfig(host string) *tls.Config {
	return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: testRootCAs}
}

// Config 是一个发件账号。Password 只在内存里出现，保存时由调用方加密。
type Config struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
}

// safeSummary 只列能打印的字段（白名单，见 AGENTS.md「机密的操作纪律」）：口令永远不出现，新加的字段默认也不出现。
func (c Config) safeSummary() string {
	return fmt.Sprintf("mail.Config{Host:%s Port:%d Username:%s FromAddress:%s FromName:%s}",
		c.Host, c.Port, c.Username, c.FromAddress, c.FromName)
}

func (c Config) String() string { return c.safeSummary() }

// GoString 挡住 %#v——`t.Fatalf("%#v", cfg)` 是最容易被写出来的那一种。
func (c Config) GoString() string { return c.safeSummary() }

// LogValue 挡住 slog.Info("...", "cfg", cfg)。
func (c Config) LogValue() slog.Value { return slog.StringValue(c.safeSummary()) }

// DefaultPort 是没填端口时用的提交端口（STARTTLS）。
const DefaultPort = 587

// Normalize 校验并补默认值。错误信息说明是哪一项、为什么，给管理端直接显示。
func (c Config) Normalize() (Config, error) {
	c.Host = strings.TrimSpace(strings.ToLower(c.Host))
	c.Username = strings.TrimSpace(c.Username)
	c.FromAddress = strings.TrimSpace(c.FromAddress)
	c.FromName = strings.TrimSpace(c.FromName)
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	switch {
	case c.Host == "" || len(c.Host) > 253 || strings.ContainsAny(c.Host, " /:@\r\n\t"):
		return c, errors.New("host must be a bare host name such as smtp.example.com")
	case c.Port < 1 || c.Port > 65535:
		return c, fmt.Errorf("port %d is out of range", c.Port)
	case strings.ContainsAny(c.Username, "\r\n") || len(c.Username) > 256:
		return c, errors.New("username must be a single line")
	case c.Username != "" && c.Password == "":
		return c, errors.New("password is required when a username is set")
	case strings.ContainsAny(c.FromName, "\r\n") || utf8.RuneCountInString(c.FromName) > 100:
		return c, errors.New("fromName must be a single line of at most 100 characters")
	}
	if _, err := validAddress(c.FromAddress); err != nil {
		return c, fmt.Errorf("fromAddress: %w", err)
	}
	return c, nil
}

// Message 是一封邮件。HTML 与 Text 至少要有一个；两个都有时发 multipart/alternative。
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Send 投递一封邮件。ctx 的截止时间约束整个会话（没有截止时间就用 30 秒）。
func Send(ctx context.Context, cfg Config, msg Message) error {
	to, err := validAddress(msg.To)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	if strings.ContainsAny(msg.Subject, "\r\n") {
		return errors.New("subject must be a single line")
	}
	if msg.Text == "" && msg.HTML == "" {
		return errors.New("message has no body")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Deadline: deadline}
	var conn net.Conn
	if cfg.Port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig(cfg.Host))
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrConnect, addr, err)
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("%w: greeting: %w", ErrConnect, err)
	}
	defer client.Close()
	if cfg.Port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig(cfg.Host)); err != nil {
				return fmt.Errorf("%w: %w", ErrTLS, err)
			}
		} else if !isLoopback(cfg.Host) {
			return fmt.Errorf("%w: the server does not offer STARTTLS; use port 465 or a server with STARTTLS", ErrTLS)
		}
	}
	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("%w: %w", ErrAuth, err)
		}
	}
	if err := client.Mail(cfg.FromAddress); err != nil {
		return fmt.Errorf("%w: MAIL: %w", ErrRejected, err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("%w: RCPT: %w", ErrRejected, err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("%w: DATA: %w", ErrRejected, err)
	}
	if _, err := w.Write(build(cfg, to, msg)); err != nil {
		return fmt.Errorf("%w: write: %w", ErrConnect, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: DATA end: %w", ErrRejected, err)
	}
	// DATA 结束得到 250 就是已经收下了；QUIT 没回 221 不代表没送到，不能当失败（调用方会据此作废验证码）
	_ = client.Quit()
	return nil
}

func validAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := netmail.ParseAddress(raw)
	if err != nil || parsed.Name != "" || parsed.Address != raw {
		return "", errors.New("must be a plain email address such as noreply@example.com")
	}
	return parsed.Address, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// build 拼出 RFC 5322 报文：非 ASCII 的标题与发件人名按 RFC 2047 编码，正文 UTF-8 + base64。
func build(cfg Config, to string, msg Message) []byte {
	from := (&netmail.Address{Name: cfg.FromName, Address: cfg.FromAddress}).String()
	var b strings.Builder
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from)
	header("To", to)
	header("Subject", mime.BEncoding.Encode("UTF-8", msg.Subject))
	header("Date", time.Now().UTC().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	part := func(contentType, body string) {
		header("Content-Type", contentType+"; charset=UTF-8")
		header("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		b.WriteString(wrapBase64(body))
	}
	switch {
	case msg.HTML != "" && msg.Text != "":
		boundary := "rn-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		header("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
		b.WriteString("\r\n")
		b.WriteString("--" + boundary + "\r\n")
		part("text/plain", msg.Text)
		b.WriteString("--" + boundary + "\r\n")
		part("text/html", msg.HTML)
		b.WriteString("--" + boundary + "--\r\n")
	case msg.HTML != "":
		part("text/html", msg.HTML)
	default:
		part("text/plain", msg.Text)
	}
	return []byte(b.String())
}

// wrapBase64 按 RFC 2045 每行 76 个字符。
func wrapBase64(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	var b strings.Builder
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String()
}
