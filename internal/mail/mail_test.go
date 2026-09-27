package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http/httptest"
	netmail "net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeServer 是一个最小的 SMTP 服务：可选 STARTTLS（用 httptest 的自签证书）与 AUTH PLAIN。
type fakeServer struct {
	addr     string
	startTLS *tls.Config
	wantAuth string // "user\x00pass"；空 = 不要求认证
	mu       sync.Mutex
	messages []string
	authed   bool
	usedTLS  bool
}

func startFake(t *testing.T, listenIP string, startTLS *tls.Config, wantAuth string) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(listenIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	f := &fakeServer{addr: ln.Addr().String(), startTLS: startTLS, wantAuth: wantAuth}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := conn
	say := func(line string) { _, _ = w.Write([]byte(line + "\r\n")) }
	secure := false
	say("220 fake")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			if f.startTLS != nil && !secure {
				say("250-fake")
				say("250 STARTTLS")
			} else if f.wantAuth != "" {
				say("250-fake")
				say("250 AUTH PLAIN")
			} else {
				say("250 fake")
			}
		case upper == "STARTTLS":
			say("220 go ahead")
			tlsConn := tls.Server(conn, f.startTLS)
			if tlsConn.Handshake() != nil {
				return
			}
			conn, secure = tlsConn, true
			r, w = bufio.NewReader(tlsConn), tlsConn
			f.mu.Lock()
			f.usedTLS = true
			f.mu.Unlock()
		case strings.HasPrefix(upper, "AUTH PLAIN "):
			raw, _ := base64.StdEncoding.DecodeString(cmd[len("AUTH PLAIN "):])
			if strings.TrimPrefix(string(raw), "\x00") != f.wantAuth {
				say("535 bad credentials")
				continue
			}
			f.mu.Lock()
			f.authed = true
			f.mu.Unlock()
			say("235 ok")
		case upper == "DATA":
			say("354 go")
			var msg strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				msg.WriteString(l)
			}
			f.mu.Lock()
			f.messages = append(f.messages, msg.String())
			f.mu.Unlock()
			say("250 queued")
		case upper == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (f *fakeServer) config(t *testing.T, host string) Config {
	t.Helper()
	_, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	return Config{Host: host, Port: p, FromAddress: "noreply@example.com", FromName: "RN 平台"}
}

func decodedBody(t *testing.T, raw string) (subject, body string) {
	t.Helper()
	parsed, err := netmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid message: %v\n%s", err, raw)
	}
	subject, err = new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	rawBody, _ := io.ReadAll(parsed.Body)
	encoded := strings.ReplaceAll(string(rawBody), "\r\n", "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	return subject, string(decoded)
}

func TestSendOnLoopbackWithoutTLS(t *testing.T) {
	f := startFake(t, "127.0.0.1", nil, "")
	err := Send(context.Background(), f.config(t, "127.0.0.1"), Message{To: "ops@example.com", Subject: "绑定验证码 123", HTML: "<p>验证码 482913</p>"})
	if err != nil {
		t.Fatal(err)
	}
	subject, body := decodedBody(t, f.messages[0])
	if subject != "绑定验证码 123" || body != "<p>验证码 482913</p>" {
		t.Fatalf("subject %q body %q", subject, body)
	}
	if !strings.Contains(f.messages[0], "To: ops@example.com\r\n") || !strings.Contains(f.messages[0], "noreply@example.com") {
		t.Fatalf("headers:\n%s", f.messages[0])
	}
}

func TestSendUpgradesWithSTARTTLSAndAuthenticates(t *testing.T) {
	cert := httptest.NewTLSServer(nil) // 只为拿一张对 127.0.0.1 有效的自签证书
	defer cert.Close()
	serverTLS := cert.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Certificate())
	testRootCAs = roots
	t.Cleanup(func() { testRootCAs = nil })

	f := startFake(t, "127.0.0.1", serverTLS, "mailer\x00s3cret")
	cfg := f.config(t, "127.0.0.1")
	cfg.Username, cfg.Password = "mailer", "s3cret"
	if err := Send(context.Background(), cfg, Message{To: "ops@example.com", Subject: "hi", Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	if !f.usedTLS || !f.authed || len(f.messages) != 1 {
		t.Fatalf("tls=%v auth=%v messages=%d", f.usedTLS, f.authed, len(f.messages))
	}
	cfg.Password = "wrong"
	if err := Send(context.Background(), cfg, Message{To: "ops@example.com", Subject: "hi", Text: "hello"}); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong credentials must fail as ErrAuth, got %v", err)
	}
}

// 不是本机地址、对方又不支持 STARTTLS：不退回明文
func TestSendRefusesPlaintextToARemoteServer(t *testing.T) {
	ip := firstNonLoopbackIPv4(t)
	f := startFake(t, ip, nil, "")
	err := Send(context.Background(), f.config(t, ip), Message{To: "ops@example.com", Subject: "hi", Text: "code 482913"})
	if !errors.Is(err, ErrTLS) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected a STARTTLS refusal, got %v", err)
	}
	if len(f.messages) != 0 {
		t.Fatal("nothing may be sent in plaintext")
	}
}

func firstNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
			return ipNet.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 interface on this machine")
	return ""
}

func TestSendRejectsHeaderInjection(t *testing.T) {
	f := startFake(t, "127.0.0.1", nil, "")
	cfg := f.config(t, "127.0.0.1")
	for _, msg := range []Message{
		{To: "ops@example.com\r\nBcc: evil@example.com", Subject: "hi", Text: "x"},
		{To: "Ops <ops@example.com>", Subject: "hi", Text: "x"},
		{To: "ops@example.com", Subject: "hi\r\nBcc: evil@example.com", Text: "x"},
		{To: "ops@example.com", Subject: "hi"},
	} {
		if err := Send(context.Background(), cfg, msg); err == nil {
			t.Fatalf("expected %q to be rejected", msg.To+" / "+msg.Subject)
		}
	}
	if len(f.messages) != 0 {
		t.Fatal("nothing may be sent")
	}
}

func TestSendHonoursTheContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // 接了连接不说话
		conn, err := ln.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = Send(ctx, Config{Host: "127.0.0.1", Port: p, FromAddress: "noreply@example.com"}, Message{To: "ops@example.com", Subject: "hi", Text: "x"})
	if !errors.Is(err, ErrConnect) || time.Since(started) > time.Second {
		t.Fatalf("expected a timeout within the deadline, got %v after %s", err, time.Since(started))
	}
}

// 口令不能经 %v、%+v、%#v、slog 漏出去：测试输出进 CI 日志
func TestConfigNeverPrintsPassword(t *testing.T) {
	const sentinel = "Sentinel-Smtp-Pass-7f3a"
	cfg := Config{Host: "smtp.example.com", Port: 465, Username: "mailer", Password: sentinel, FromAddress: "noreply@example.com"}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("mail", "cfg", cfg)
	for _, out := range []string{fmt.Sprint(cfg), fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, cfg), fmt.Sprintf("%+v", &cfg), logged.String()} {
		if strings.Contains(out, sentinel) {
			t.Fatalf("password leaked: %s", out)
		}
		if !strings.Contains(out, "smtp.example.com") {
			t.Fatalf("summary lost the host: %s", out)
		}
	}
}

func TestNormalize(t *testing.T) {
	good, err := Config{Host: " SMTP.Example.com ", FromAddress: "noreply@example.com"}.Normalize()
	if err != nil || good.Host != "smtp.example.com" || good.Port != DefaultPort {
		t.Fatalf("normalize = %+v %v", good, err)
	}
	// 发件人名按字符数计，不按字节：100 个汉字是 300 字节
	if _, err := (Config{Host: "smtp.example.com", FromAddress: "noreply@example.com", FromName: strings.Repeat("名", 100)}).Normalize(); err != nil {
		t.Fatalf("100-character name rejected: %v", err)
	}
	for _, bad := range []Config{
		{Host: "smtp.example.com:587", FromAddress: "noreply@example.com"},
		{Host: "", FromAddress: "noreply@example.com"},
		{Host: "smtp.example.com", Port: 70000, FromAddress: "noreply@example.com"},
		{Host: "smtp.example.com", FromAddress: "Noreply <noreply@example.com>"},
		{Host: "smtp.example.com", FromAddress: "not-an-address"},
		{Host: "smtp.example.com", FromAddress: "noreply@example.com", Username: "u"},
		{Host: "smtp.example.com", FromAddress: "noreply@example.com", FromName: "a\r\nBcc: x"},
		{Host: "smtp.example.com", FromAddress: "noreply@example.com", FromName: strings.Repeat("名", 101)},
	} {
		if _, err := bad.Normalize(); err == nil {
			t.Fatalf("expected %+v to be rejected", bad)
		}
	}
}
