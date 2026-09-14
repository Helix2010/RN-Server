package api

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// 一键上报（设计 docs/design/diagnostic-report-2026-09-14.md，存于 RN-App）。
//
// 两步：先收元数据并立刻给出参考号，再收日志正文。报告在第一步就成立——参考号、版本、
// 设备、账号、用户描述都已经在库里，日志是增强项。
//
// 身份一律由服务端解析：租户按域名，安装实例按安装凭证，账号按该安装实例上的有效会话。
// 请求体里没有任何身份字段，带了就 400（decodeLimited 拒绝未知字段）。

const (
	diagnosticMetaMaxBytes      = 8 << 10
	diagnosticLogMaxBytes       = 512 << 10
	diagnosticLineMaxBytes      = 8 << 10
	diagnosticMaxLines          = 2000
	diagnosticMessageMaxRunes   = 512
	diagnosticMaxFields         = 8
	diagnosticFieldMaxRunes     = 128
	diagnosticNoteMaxRunes      = 200
	diagnosticLogUploadWindow   = 30 * time.Minute
	diagnosticManualPerHour     = 5
	diagnosticManualPerDay      = 20
	diagnosticAutoPerDay        = 3
	diagnosticIPPerHour         = 20
	diagnosticTenantPerDay      = 2000
	diagnosticTenantBytesPerDay = 200 << 20
)

var (
	diagnosticReportIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`)
	diagnosticFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	diagnosticErrorNamePattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,79}$`)
	diagnosticLevels             = map[string]bool{"info": true, "warn": true, "error": true}
	diagnosticTags               = map[string]bool{"net": true, "config": true, "ota": true, "wallet": true, "nav": true, "crash": true}
)

// crockfordAlphabet 不含 I、L、O、U：参考号是要念给客服听的，1/I/L、0/O 念出来分不清。
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newDiagnosticReference() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	for i, b := range raw {
		out[i] = crockfordAlphabet[int(b)%len(crockfordAlphabet)]
	}
	return string(out)
}

// diagnosticIPLimiter 是按来源 IP 的小时窗口计数。零值可用（测试里的 server 不初始化它）。
// 只在内存里：多实例部署时每个实例各计各的，这一道只是挡住单一来源刷凭证，真正的闸是
// 按安装实例与按租户的库内配额。
type diagnosticIPLimiter struct {
	mu      sync.Mutex
	windows map[string]diagnosticIPWindow
}

type diagnosticIPWindow struct {
	count    int
	resetsAt time.Time
}

func (l *diagnosticIPLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windows == nil {
		l.windows = map[string]diagnosticIPWindow{}
	}
	// 过期窗口顺手清掉，否则每个来过一次的 IP 都会永久占一格
	if len(l.windows) > 10_000 {
		for key, window := range l.windows {
			if now.After(window.resetsAt) {
				delete(l.windows, key)
			}
		}
	}
	window := l.windows[ip]
	if now.After(window.resetsAt) {
		window = diagnosticIPWindow{resetsAt: now.Add(time.Hour)}
	}
	if window.count >= diagnosticIPPerHour {
		return false
	}
	window.count++
	l.windows[ip] = window
	return true
}

type diagnosticReportRequest struct {
	ReportID   string `json:"reportId"`
	Kind       string `json:"kind"`
	Note       string `json:"note"`
	OccurredAt string `json:"occurredAt"`
	Crash      *struct {
		Fingerprint string `json:"fingerprint"`
		ErrorName   string `json:"errorName"`
	} `json:"crash"`
	App struct {
		Version             string  `json:"version"`
		BuildNumber         string  `json:"buildNumber"`
		RuntimeVersion      string  `json:"runtimeVersion"`
		OTAChannel          string  `json:"otaChannel"`
		DistributionChannel string  `json:"distributionChannel"`
		LaunchSource        *string `json:"launchSource"`
		RunningUpdateID     *string `json:"runningUpdateId"`
		Locale              string  `json:"locale"`
		OSVersion           string  `json:"osVersion"`
		DeviceClass         string  `json:"deviceClass"`
	} `json:"app"`
	Context struct {
		Screen        string `json:"screen"`
		LastRequestID string `json:"lastRequestId"`
		NetworkType   string `json:"networkType"`
	} `json:"context"`
}

// validate 校验并就地规范化；返回失败原因（空 = 通过）。
func (r *diagnosticReportRequest) validate() string {
	r.ReportID = strings.TrimSpace(r.ReportID)
	if !diagnosticReportIDPattern.MatchString(r.ReportID) {
		return "reportId must be 16-80 URL-safe characters"
	}
	if !oneOf(r.Kind, "user", "crash", "crash_auto") {
		return "kind must be user, crash or crash_auto"
	}
	if _, err := time.Parse(time.RFC3339Nano, r.OccurredAt); err != nil {
		return "occurredAt must be an RFC 3339 timestamp"
	}
	isCrash := r.Kind != "user"
	if isCrash != (r.Crash != nil) {
		return "crash is required for crash reports and not allowed otherwise"
	}
	if r.Crash != nil && (!diagnosticFingerprintPattern.MatchString(r.Crash.Fingerprint) || !diagnosticErrorNamePattern.MatchString(r.Crash.ErrorName)) {
		return "crash.fingerprint must be 16 hex characters and crash.errorName a class name"
	}
	if r.Kind == "crash_auto" && strings.TrimSpace(r.Note) != "" {
		return "automatic crash reports carry no note"
	}
	app := &r.App
	for _, field := range []struct {
		value string
		max   int
	}{{app.Version, 40}, {app.BuildNumber, 40}, {app.RuntimeVersion, 160}, {app.OTAChannel, 40}, {app.DistributionChannel, 40}} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > field.max {
			return "app version, build, runtime and channels are required"
		}
	}
	if len(app.Locale) > 40 || len(app.OSVersion) > 40 || len(app.DeviceClass) > 80 {
		return "app locale, osVersion or deviceClass is too long"
	}
	// launchSource / runningUpdateId 与心跳同一套规则，不另写一份
	probe := installationHeartbeat{LaunchSource: app.LaunchSource, RunningUpdateID: app.RunningUpdateID}
	if code, detail := normalizeRuntimeReport(&probe); code != "" {
		return detail
	}
	app.LaunchSource, app.RunningUpdateID = probe.LaunchSource, probe.RunningUpdateID
	r.Note = clipRunes(strings.TrimSpace(r.Note), diagnosticNoteMaxRunes)
	return ""
}

// diagnosticsEnabled 是这组接口的总闸：租户关了就当接口不存在（404）。
func (s *server) diagnosticsEnabled(ctx context.Context, tenant string) (bool, error) {
	view, err := s.appConfigView(ctx, tenant)
	if err != nil {
		return false, err
	}
	config, _ := view["config"].(map[string]any)
	return truth(object(config["features"])["diagnosticsEnabled"]), nil
}

// diagnosticInstallation 校验安装凭证，并要求这个实例心跳成功过至少一次：
// 注册接口是开放的，刚注册、从没心跳过的实例不给上报——否则刷凭证就能绕过按实例的配额。
func (s *server) diagnosticInstallation(c *gin.Context) (string, bool) {
	installationID := strings.TrimSpace(c.GetHeader("X-Installation-ID"))
	if installationID == "" {
		problem(c, 401, "INSTALLATION_CREDENTIAL_REQUIRED", "Installation credential is required")
		return "", false
	}
	if _, ok := s.authenticateInstallation(c, installationID); !ok {
		return "", false
	}
	var heartbeated bool
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT last_active_at>first_seen_at FROM app_installations WHERE tenant_id=? AND application_id=? AND platform=? AND installation_id=? LIMIT 1`, tenantID(c), text(c.GetHeader("x-application-id"), "unknown"), strings.ToLower(c.GetHeader("x-platform")), installationID).Scan(&heartbeated)
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to check the installation")
		return "", false
	}
	if !heartbeated {
		problem(c, 403, "DIAGNOSTIC_NOT_ELIGIBLE", "This installation has not completed a heartbeat yet")
		return "", false
	}
	return installationID, true
}

func (s *server) createDiagnosticReport(c *gin.Context) {
	ctx, tenant := c.Request.Context(), tenantID(c)
	if enabled, err := s.diagnosticsEnabled(ctx, tenant); err != nil {
		problem(c, 503, "DIAGNOSTIC_REPORT_UNAVAILABLE", "Diagnostic reports are unavailable")
		return
	} else if !enabled {
		problem(c, 404, "NOT_FOUND", "Not found")
		return
	}
	var body diagnosticReportRequest
	if err := decodeLimited(c, &body, diagnosticMetaMaxBytes); err != nil {
		if requestTooLarge(err) {
			problem(c, 413, "DIAGNOSTIC_REPORT_TOO_LARGE", "Report metadata is too large")
			return
		}
		problem(c, 400, "INVALID_DIAGNOSTIC_REPORT", "Invalid report payload")
		return
	}
	if detail := body.validate(); detail != "" {
		problem(c, 422, "INVALID_DIAGNOSTIC_REPORT", detail)
		return
	}
	installationID, ok := s.diagnosticInstallation(c)
	if !ok {
		return
	}

	// 幂等：同一实例同一 reportId 重复提交（App 重试）返回同一条，不占配额
	if existing, found, err := s.diagnosticReportByClientID(ctx, tenant, installationID, body.ReportID); err != nil {
		problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to record the report")
		return
	} else if found {
		c.JSON(http.StatusOK, existing.creationResponse())
		return
	}

	now := time.Now().UTC()
	if !s.diagnosticIPs.allow(c.ClientIP(), now) {
		problem(c, 429, "DIAGNOSTIC_QUOTA_EXCEEDED", "Too many reports from this network; try again later")
		return
	}
	if code := s.diagnosticQuotaExceeded(ctx, tenant, installationID, body.Kind, now); code != "" {
		problem(c, 429, code, "Too many reports; try again later")
		return
	}

	var walletUserID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT user_id FROM wallet_session WHERE tenant_id=? AND installation_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY last_seen_at DESC LIMIT 1`, tenant, installationID, now).Scan(&walletUserID); err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to record the report")
		return
	}
	var runningRevision sql.NullInt64
	if body.App.RunningUpdateID != nil {
		if err := s.db.QueryRowContext(ctx, `SELECT revision FROM ota_releases WHERE tenant_id=? AND update_id=? LIMIT 1`, tenant, *body.App.RunningUpdateID).Scan(&runningRevision); err != nil && !errors.Is(err, sql.ErrNoRows) {
			problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to record the report")
			return
		}
	}
	logStatus := "awaiting"
	if _, _, err := s.storageClientForTenant(ctx, tenant); err != nil {
		logStatus = "storage_unavailable"
	}

	contextJSON, _ := json.Marshal(nonEmptyStrings(map[string]string{
		"screen":        clipRunes(body.Context.Screen, 80),
		"lastRequestId": clipRunes(body.Context.LastRequestID, 80),
		"networkType":   clipRunes(body.Context.NetworkType, 20),
	}))
	occurred, _ := time.Parse(time.RFC3339Nano, body.OccurredAt)
	var fingerprint, errorName any
	if body.Crash != nil {
		fingerprint, errorName = body.Crash.Fingerprint, body.Crash.ErrorName
	}

	// 参考号碰撞（32^8 空间里概率极低）重抽；幂等键冲突说明并发的同一次重试已经写进去了
	for attempt := 0; attempt < 5; attempt++ {
		reference := newDiagnosticReference()
		_, err := s.db.ExecContext(ctx, `INSERT INTO app_diagnostic_reports(tenant_id,reference,report_id,installation_id,wallet_user_id,kind,note,crash_fingerprint,crash_error_name,platform,app_version,build_number,runtime_version,distribution_channel,ota_channel,launch_source,running_update_id,running_ota_revision,locale,os_version,device_class,context,log_status,occurred_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			tenant, reference, body.ReportID, installationID, walletUserID, body.Kind, sqlNullString(body.Note), fingerprint, errorName,
			strings.ToLower(c.GetHeader("x-platform")), body.App.Version, body.App.BuildNumber, body.App.RuntimeVersion, body.App.DistributionChannel, body.App.OTAChannel,
			body.App.LaunchSource, body.App.RunningUpdateID, runningRevision, sqlNullString(body.App.Locale), sqlNullString(body.App.OSVersion), sqlNullString(body.App.DeviceClass),
			contextJSON, logStatus, occurred.UTC(), now, now)
		if err == nil {
			c.JSON(http.StatusCreated, diagnosticReportRecord{ReportID: body.ReportID, Reference: reference, LogStatus: logStatus, CreatedAt: now}.creationResponse())
			return
		}
		if !isDuplicateEntry(err) {
			slog.Error("diagnostic report insert failed", "error", err, "requestId", requestID(c), "tenant", tenant)
			problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to record the report")
			return
		}
		if existing, found, lookupErr := s.diagnosticReportByClientID(ctx, tenant, installationID, body.ReportID); lookupErr == nil && found {
			c.JSON(http.StatusOK, existing.creationResponse())
			return
		}
	}
	problem(c, 500, "DIAGNOSTIC_REPORT_FAILED", "Unable to allocate a report reference")
}

type diagnosticReportRecord struct {
	ID        uint64
	ReportID  string
	Reference string
	LogStatus string
	CreatedAt time.Time
}

func (r diagnosticReportRecord) creationResponse() gin.H {
	required := r.LogStatus == "awaiting"
	upload := gin.H{"required": required}
	if required {
		upload["maxBytes"] = diagnosticLogMaxBytes
		upload["expiresAt"] = iso(r.CreatedAt.Add(diagnosticLogUploadWindow))
	}
	return gin.H{"reportId": r.ReportID, "reference": r.Reference, "logUpload": upload}
}

func (s *server) diagnosticReportByClientID(ctx context.Context, tenant, installationID, reportID string) (diagnosticReportRecord, bool, error) {
	var record diagnosticReportRecord
	err := s.db.QueryRowContext(ctx, `SELECT id,report_id,reference,log_status,created_at FROM app_diagnostic_reports WHERE tenant_id=? AND installation_id=? AND report_id=? LIMIT 1`, tenant, installationID, reportID).Scan(&record.ID, &record.ReportID, &record.Reference, &record.LogStatus, &record.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return record, false, nil
	}
	return record, err == nil, err
}

// diagnosticQuotaExceeded 查库内配额，返回失败码（空 = 未超）。
//
// crash_auto 单独计：它不需要用户操作，客户端的闸一旦有 bug，它是唯一能持续产生流量的类型。
func (s *server) diagnosticQuotaExceeded(ctx context.Context, tenant, installationID, kind string, now time.Time) string {
	hourAgo, dayAgo := now.Add(-time.Hour), now.Add(-24*time.Hour)
	if kind == "crash_auto" {
		var today int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_diagnostic_reports WHERE tenant_id=? AND installation_id=? AND kind='crash_auto' AND created_at>?`, tenant, installationID, dayAgo).Scan(&today); err != nil || today >= diagnosticAutoPerDay {
			return "DIAGNOSTIC_QUOTA_EXCEEDED"
		}
	} else {
		var lastHour, today int
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(created_at>?),0),COUNT(*) FROM app_diagnostic_reports WHERE tenant_id=? AND installation_id=? AND kind IN ('user','crash') AND created_at>?`, hourAgo, tenant, installationID, dayAgo).Scan(&lastHour, &today); err != nil || lastHour >= diagnosticManualPerHour || today >= diagnosticManualPerDay {
			return "DIAGNOSTIC_QUOTA_EXCEEDED"
		}
	}
	var count int
	var bytes int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(byte_size),0) FROM app_diagnostic_reports WHERE tenant_id=? AND created_at>?`, tenant, dayAgo).Scan(&count, &bytes); err != nil {
		return "DIAGNOSTIC_QUOTA_EXCEEDED"
	}
	if count >= diagnosticTenantPerDay || bytes >= diagnosticTenantBytesPerDay {
		slog.Warn("tenant diagnostic report budget exhausted", "tenant", tenant, "reports", count, "bytes", bytes)
		return "DIAGNOSTIC_TENANT_QUOTA_EXCEEDED"
	}
	return ""
}

func (s *server) uploadDiagnosticLog(c *gin.Context) {
	ctx, tenant := c.Request.Context(), tenantID(c)
	if enabled, err := s.diagnosticsEnabled(ctx, tenant); err != nil {
		problem(c, 503, "DIAGNOSTIC_REPORT_UNAVAILABLE", "Diagnostic reports are unavailable")
		return
	} else if !enabled {
		problem(c, 404, "NOT_FOUND", "Not found")
		return
	}
	// 不收任何压缩流：收了就要解压，而解压炸弹几 KB 就能展开成几 GB。服务端落盘时自己压
	if encoding := strings.TrimSpace(c.GetHeader("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		problem(c, 415, "DIAGNOSTIC_LOG_ENCODING_UNSUPPORTED", "Upload the log uncompressed")
		return
	}
	reportID := strings.TrimSpace(c.Param("reportId"))
	if !diagnosticReportIDPattern.MatchString(reportID) {
		problem(c, 404, "DIAGNOSTIC_REPORT_NOT_FOUND", "Report not found")
		return
	}
	installationID, ok := s.diagnosticInstallation(c)
	if !ok {
		return
	}
	record, found, err := s.diagnosticReportByClientID(ctx, tenant, installationID, reportID)
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_LOG_FAILED", "Unable to store the log")
		return
	}
	if !found {
		problem(c, 404, "DIAGNOSTIC_REPORT_NOT_FOUND", "Report not found")
		return
	}
	now := time.Now().UTC()
	if record.LogStatus != "awaiting" || now.After(record.CreatedAt.Add(diagnosticLogUploadWindow)) {
		problem(c, 409, "DIAGNOSTIC_LOG_NOT_ACCEPTED", "This report is not waiting for a log")
		return
	}
	client, prefix, err := s.storageClientForTenant(ctx, tenant)
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Log storage is unavailable")
		return
	}

	canonical, stats, err := sanitizeDiagnosticLog(http.MaxBytesReader(c.Writer, c.Request.Body, diagnosticLogMaxBytes))
	if err != nil {
		if requestTooLarge(err) {
			problem(c, 413, "DIAGNOSTIC_LOG_TOO_LARGE", "The log is too large")
			return
		}
		problem(c, 400, "INVALID_DIAGNOSTIC_LOG", "Unable to read the log")
		return
	}
	temporary, size, err := gzipToTemporary(canonical)
	if err != nil {
		slog.Error("diagnostic log compression failed", "error", err, "requestId", requestID(c), "tenant", tenant)
		problem(c, 500, "DIAGNOSTIC_LOG_FAILED", "Unable to store the log")
		return
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()

	// 字节预算按落盘的真实大小再算一次：元数据阶段还不知道日志多大
	var spent int64
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(byte_size),0) FROM app_diagnostic_reports WHERE tenant_id=? AND created_at>?`, tenant, now.Add(-24*time.Hour)).Scan(&spent); err != nil || spent+size > diagnosticTenantBytesPerDay {
		problem(c, 429, "DIAGNOSTIC_TENANT_QUOTA_EXCEEDED", "Too many reports; try again later")
		return
	}

	key := diagnosticObjectKey(prefix, tenant, record.Reference, record.CreatedAt)
	if err := client.Put(ctx, key, temporary, size, "application/gzip"); err != nil {
		slog.Error("diagnostic log upload failed", "error", err, "requestId", requestID(c), "tenant", tenant)
		_, _ = s.db.ExecContext(ctx, `UPDATE app_diagnostic_reports SET log_status='failed',updated_at=? WHERE id=? AND log_status='awaiting'`, now, record.ID)
		problem(c, 502, "DIAGNOSTIC_LOG_FAILED", "Unable to store the log")
		return
	}
	result, err := s.db.ExecContext(ctx, `UPDATE app_diagnostic_reports SET object_key=?,log_status='stored',entry_count=?,byte_size=?,dropped_lines=?,redaction_hits=?,updated_at=? WHERE id=? AND log_status='awaiting'`,
		key, stats.entries, size, stats.dropped, stats.redactionHits, now, record.ID)
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_LOG_FAILED", "Unable to store the log")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		// 并发的另一次上传先落了：删掉自己这份，库里那条指向的是对方的
		_ = client.Delete(ctx, key)
		problem(c, 409, "DIAGNOSTIC_LOG_NOT_ACCEPTED", "This report is not waiting for a log")
		return
	}
	if stats.redactionHits > 0 {
		// 客户端那一遍没拦住。不打内容，只打是哪条报告，管理端按 redaction_hits 标红
		slog.Warn("diagnostic log needed server-side redaction", "tenant", tenant, "reference", record.Reference, "lines", stats.redactionHits)
	}
	// 命中数不回给客户端：告诉对方"这次被发现了"没有好处
	c.JSON(http.StatusOK, gin.H{"reportId": reportID, "reference": record.Reference, "entryCount": stats.entries, "droppedLines": stats.dropped})
}

func diagnosticObjectKey(prefix, tenant, reference string, created time.Time) string {
	return strings.TrimLeft(path.Join(prefix, "tenants", tenant, "diagnostics", created.Format("2006/01/02"), reference+".ndjson.gz"), "/")
}

// diagnosticObjectBelongsTo 在读对象前再核一次键：行已经按租户查过了，这是第二道。
// 带上存储前缀比较——hasTenantObjectPrefix 只认无前缀的键。
func diagnosticObjectBelongsTo(key, prefix, tenant string) bool {
	expected := strings.TrimLeft(path.Join(prefix, "tenants", tenant, "diagnostics"), "/") + "/"
	return strings.HasPrefix(key, expected) && !strings.Contains(key, "..")
}

type diagnosticLogStats struct {
	entries, dropped, redactionHits int
}

// diagnosticLogLine 是落盘的规范形状。字段顺序固定，fields 由 json.Marshal 按键排序。
type diagnosticLogLine struct {
	At      int64          `json:"at"`
	Level   string         `json:"level"`
	Tag     string         `json:"tag"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// sanitizeDiagnosticLog 逐行解析客户端的 NDJSON，丢弃不合规的行，脱敏、截断后
// **重新序列化**。落进桶里的字节因此全部由服务端生成：内容类型混淆、夹带未知字段、
// 超长行这些问题在这里一次性消失。
func sanitizeDiagnosticLog(body io.Reader) ([]byte, diagnosticLogStats, error) {
	var out bytes.Buffer
	var stats diagnosticLogStats
	reader := bufio.NewReaderSize(body, diagnosticLineMaxBytes+1)
	for {
		line, tooLong, err := readDiagnosticLine(reader)
		if len(line) > 0 || tooLong {
			switch {
			case tooLong || stats.entries >= diagnosticMaxLines:
				stats.dropped++
			default:
				if canonical, hit, ok := canonicalDiagnosticLine(line); ok {
					out.Write(canonical)
					out.WriteByte('\n')
					stats.entries++
					if hit {
						stats.redactionHits++
					}
				} else {
					stats.dropped++
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return out.Bytes(), stats, nil
		}
		if err != nil {
			return nil, stats, err
		}
	}
}

// readDiagnosticLine 读一行（不含换行符）。超过单行上限的行整行吞掉并报告 tooLong——
// bufio.Scanner 遇到超长行会直接中止整个扫描，一行坏掉就丢掉后面全部，所以不用它。
func readDiagnosticLine(reader *bufio.Reader) ([]byte, bool, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = reader.ReadSlice('\n')
		}
		return nil, true, err
	}
	trimmed := bytes.TrimSpace(line)
	return append([]byte(nil), trimmed...), false, err
}

func canonicalDiagnosticLine(raw []byte) ([]byte, bool, bool) {
	var input struct {
		At      int64                      `json:"at"`
		Level   string                     `json:"level"`
		Tag     string                     `json:"tag"`
		Message string                     `json:"message"`
		Fields  map[string]json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input.At <= 0 || !diagnosticLevels[input.Level] || !diagnosticTags[input.Tag] || !utf8.ValidString(input.Message) {
		return nil, false, false
	}
	message, hit := redactSecrets(input.Message)
	line := diagnosticLogLine{At: input.At, Level: input.Level, Tag: input.Tag, Message: clipRunes(message, diagnosticMessageMaxRunes)}
	keys := make([]string, 0, len(input.Fields))
	for key := range input.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(line.Fields) >= diagnosticMaxFields {
			break
		}
		if len(key) == 0 || len(key) > 40 {
			continue
		}
		var value any
		if json.Unmarshal(input.Fields[key], &value) != nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			redacted, fieldHit := redactSecrets(typed)
			hit = hit || fieldHit
			value = clipRunes(redacted, diagnosticFieldMaxRunes)
		case float64, bool:
		default:
			// 只收标量：对象和数组是把整个响应体塞进日志的那条路
			continue
		}
		if line.Fields == nil {
			line.Fields = map[string]any{}
		}
		line.Fields[key] = value
	}
	encoded, err := json.Marshal(line)
	if err != nil {
		return nil, false, false
	}
	return encoded, hit, true
}

func gzipToTemporary(content []byte) (*os.File, int64, error) {
	temporary, err := os.CreateTemp("", "rn-diagnostic-log-*")
	if err != nil {
		return nil, 0, err
	}
	writer := gzip.NewWriter(temporary)
	if _, err := writer.Write(content); err != nil {
		temporary.Close()
		os.Remove(temporary.Name())
		return nil, 0, err
	}
	if err := writer.Close(); err != nil {
		temporary.Close()
		os.Remove(temporary.Name())
		return nil, 0, err
	}
	size, err := temporary.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = temporary.Seek(0, io.SeekStart)
	}
	if err != nil {
		temporary.Close()
		os.Remove(temporary.Name())
		return nil, 0, err
	}
	return temporary, size, nil
}

func nonEmptyStrings(values map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range values {
		if strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	return out
}

func sqlNullString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
