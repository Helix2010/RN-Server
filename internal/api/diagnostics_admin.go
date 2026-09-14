package api

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 管理端的诊断上报（设计 diagnostic-report-2026-09-14 §5.8 / §6）。挂在现有 /v1/admin 租户路由组下。
//
// 日志正文一律由服务端代理读取、解压、分页后回给管理端，**不下发预签名 URL**：URL 是字符串
// 形态的持有型凭证，会进工单、进截图、进日志。

const (
	// 读回对象时的解压上限。对象是服务端自己写的、原文 ≤512KB，但桶可能被别的途径改过——
	// 读路径不假定内容可信，解压炸弹在这一侧同样要挡
	diagnosticReadMaxBytes    = 8 << 20
	diagnosticReadLineMax     = 64 << 10
	diagnosticLogPageDefault  = 200
	diagnosticLogPageMax      = 500
	diagnosticListPageDefault = 50
	diagnosticListPageMax     = 100
	diagnosticBulkDeleteMax   = 200
)

const diagnosticReportColumns = `r.id,r.reference,r.kind,r.note,r.crash_fingerprint,r.crash_error_name,r.installation_id,r.wallet_user_id,w.address,
	r.platform,r.app_version,r.build_number,r.runtime_version,r.distribution_channel,r.ota_channel,r.launch_source,r.running_update_id,r.running_ota_revision,
	r.locale,r.os_version,r.device_class,r.context,r.object_key,r.log_status,r.entry_count,r.byte_size,r.dropped_lines,r.redaction_hits,
	r.status,r.occurred_at,r.created_at,r.updated_at`

// 地址按 wallet_user_id 关联读出来，不在报告表里存副本（AGENTS.md「一个事实只有一个存放处」）
const diagnosticReportFrom = ` FROM app_diagnostic_reports r LEFT JOIN wallet_user w ON w.tenant_id=r.tenant_id AND w.id=r.wallet_user_id `

type diagnosticReportRow struct {
	ID                                                          uint64
	Reference, Kind, InstallationID                             string
	Note, Fingerprint, ErrorName, Address                       sql.NullString
	WalletUserID, RunningRevision                               sql.NullInt64
	Platform, Version, Build, Runtime, Distribution, OTAChannel string
	LaunchSource, RunningUpdateID, Locale, OSVersion, Device    sql.NullString
	Context                                                     []byte
	ObjectKey                                                   sql.NullString
	LogStatus                                                   string
	EntryCount, ByteSize, Dropped, RedactionHits                int64
	Status                                                      string
	OccurredAt, CreatedAt, UpdatedAt                            time.Time
}

func scanDiagnosticReport(scanner interface{ Scan(...any) error }) (diagnosticReportRow, error) {
	var r diagnosticReportRow
	err := scanner.Scan(&r.ID, &r.Reference, &r.Kind, &r.Note, &r.Fingerprint, &r.ErrorName, &r.InstallationID, &r.WalletUserID, &r.Address,
		&r.Platform, &r.Version, &r.Build, &r.Runtime, &r.Distribution, &r.OTAChannel, &r.LaunchSource, &r.RunningUpdateID, &r.RunningRevision,
		&r.Locale, &r.OSVersion, &r.Device, &r.Context, &r.ObjectKey, &r.LogStatus, &r.EntryCount, &r.ByteSize, &r.Dropped, &r.RedactionHits,
		&r.Status, &r.OccurredAt, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// displayLogStatus 把"等太久没等到日志"在读取时显示成 missing，不回写库——零新增后台进程
func (r diagnosticReportRow) displayLogStatus(now time.Time) string {
	if r.LogStatus == "awaiting" && now.After(r.CreatedAt.Add(diagnosticLogUploadWindow)) {
		return "missing"
	}
	return r.LogStatus
}

func nullableText(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

func (r diagnosticReportRow) view(now time.Time) gin.H {
	var crash, wallet any
	if r.Fingerprint.Valid {
		crash = gin.H{"fingerprint": r.Fingerprint.String, "errorName": r.ErrorName.String}
	}
	if r.WalletUserID.Valid {
		wallet = gin.H{"userId": strconv.FormatInt(r.WalletUserID.Int64, 10), "address": nullableText(r.Address)}
	}
	var revision any
	if r.RunningRevision.Valid {
		revision = r.RunningRevision.Int64
	}
	context := map[string]any{}
	_ = json.Unmarshal(r.Context, &context)
	return gin.H{
		"id": strconv.FormatUint(r.ID, 10), "reference": r.Reference, "kind": r.Kind, "note": nullableText(r.Note), "crash": crash,
		"installationId": r.InstallationID, "wallet": wallet,
		"app": gin.H{"platform": r.Platform, "version": r.Version, "buildNumber": r.Build, "runtimeVersion": r.Runtime, "distributionChannel": r.Distribution,
			"otaChannel": r.OTAChannel, "launchSource": nullableText(r.LaunchSource), "runningUpdateId": nullableText(r.RunningUpdateID), "runningOtaRevision": revision},
		"device":  gin.H{"locale": nullableText(r.Locale), "osVersion": nullableText(r.OSVersion), "deviceClass": nullableText(r.Device)},
		"context": context,
		"log": gin.H{"status": r.displayLogStatus(now), "entryCount": r.EntryCount, "byteSize": r.ByteSize,
			"droppedLines": r.Dropped, "redactionHits": r.RedactionHits},
		"status": r.Status, "occurredAt": iso(r.OccurredAt), "createdAt": iso(r.CreatedAt), "updatedAt": iso(r.UpdatedAt),
	}
}

func (s *server) listDiagnosticReports(c *gin.Context) {
	ctx, tenant, now := c.Request.Context(), tenantID(c), time.Now().UTC()
	where, args := []string{"r.tenant_id=?"}, []any{tenant}
	invalid := func(detail string) { problem(c, 400, "INVALID_DIAGNOSTIC_FILTER", detail) }

	if kind := c.Query("kind"); kind != "" {
		if !oneOf(kind, "user", "crash", "crash_auto") {
			invalid("kind is invalid")
			return
		}
		where, args = append(where, "r.kind=?"), append(args, kind)
	}
	if status := c.Query("status"); status != "" {
		if !oneOf(status, "new", "triaged", "closed") {
			invalid("status is invalid")
			return
		}
		where, args = append(where, "r.status=?"), append(args, status)
	}
	switch logStatus, cutoff := c.Query("logStatus"), now.Add(-diagnosticLogUploadWindow); logStatus {
	case "":
	case "missing":
		where, args = append(where, "r.log_status='awaiting' AND r.created_at<?"), append(args, cutoff)
	case "awaiting":
		where, args = append(where, "r.log_status='awaiting' AND r.created_at>=?"), append(args, cutoff)
	case "stored", "storage_unavailable", "failed":
		where, args = append(where, "r.log_status=?"), append(args, logStatus)
	default:
		invalid("logStatus is invalid")
		return
	}
	if version := strings.TrimSpace(c.Query("version")); version != "" {
		where, args = append(where, "r.app_version=?"), append(args, version)
	}
	if fingerprint := strings.TrimSpace(c.Query("fingerprint")); fingerprint != "" {
		if !diagnosticFingerprintPattern.MatchString(fingerprint) {
			invalid("fingerprint is invalid")
			return
		}
		where, args = append(where, "r.crash_fingerprint=?"), append(args, fingerprint)
	}
	if installationID := strings.TrimSpace(c.Query("installationId")); installationID != "" {
		where, args = append(where, "r.installation_id=?"), append(args, installationID)
	}
	if redacted := c.Query("redacted"); redacted == "true" {
		where = append(where, "r.redaction_hits>0")
	}
	// 关键字只做精确匹配：参考号、安装实例 ID、钱包地址。客服拿到的就是这三样之一
	if q := strings.TrimSpace(c.Query("q")); q != "" {
		where, args = append(where, "(r.reference=? OR r.installation_id=? OR w.address_key=?)"), append(args, strings.ToUpper(q), q, strings.ToLower(q))
	}
	for _, bound := range []struct{ param, clause string }{{"from", "r.created_at>=?"}, {"to", "r.created_at<?"}} {
		if raw := c.Query(bound.param); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				invalid(bound.param + " must be an RFC 3339 timestamp")
				return
			}
			where, args = append(where, bound.clause), append(args, at.UTC())
		}
	}
	if cursor := c.Query("cursor"); cursor != "" {
		at, id, err := decodeInstallationCursor(cursor)
		if err != nil {
			invalid("cursor is invalid")
			return
		}
		where, args = append(where, "(r.created_at<? OR (r.created_at=? AND r.id<?))"), append(args, at, at, id)
	}
	limit := diagnosticListPageDefault
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > diagnosticListPageMax {
			invalid("limit must be between 1 and 100")
			return
		}
		limit = parsed
	}

	rows, err := s.db.QueryContext(ctx, `SELECT `+diagnosticReportColumns+diagnosticReportFrom+`WHERE `+strings.Join(where, " AND ")+` ORDER BY r.created_at DESC, r.id DESC LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		slog.Error("diagnostic report list failed", "error", err, "requestId", requestID(c), "tenant", tenant)
		problem(c, 500, "DIAGNOSTIC_REPORT_QUERY_FAILED", "Unable to load reports")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	var last diagnosticReportRow
	hasMore := false
	for rows.Next() {
		// 多查的那一行只用来判断还有没有下一页，不返回
		if len(items) == limit {
			hasMore = true
			break
		}
		row, err := scanDiagnosticReport(rows)
		if err != nil {
			problem(c, 500, "DIAGNOSTIC_REPORT_QUERY_FAILED", "Unable to load reports")
			return
		}
		items, last = append(items, row.view(now)), row
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "DIAGNOSTIC_REPORT_QUERY_FAILED", "Unable to load reports")
		return
	}
	var nextCursor any
	if hasMore {
		nextCursor = encodeInstallationCursor(last.CreatedAt, last.ID)
	}

	var reportsToday int
	var bytesToday int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(byte_size),0) FROM app_diagnostic_reports WHERE tenant_id=? AND created_at>?`, tenant, now.Add(-24*time.Hour)).Scan(&reportsToday, &bytesToday); err != nil {
		problem(c, 500, "DIAGNOSTIC_REPORT_QUERY_FAILED", "Unable to load reports")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "nextCursor": nextCursor, "hasMore": hasMore,
		"budget": gin.H{"reportsLast24h": reportsToday, "reportLimit": diagnosticTenantPerDay, "bytesLast24h": bytesToday, "byteLimit": diagnosticTenantBytesPerDay,
			"exhausted": reportsToday >= diagnosticTenantPerDay || bytesToday >= diagnosticTenantBytesPerDay}})
}

func (s *server) diagnosticReportForAdmin(c *gin.Context) (diagnosticReportRow, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		problem(c, 404, "DIAGNOSTIC_REPORT_NOT_FOUND", "Report not found")
		return diagnosticReportRow{}, false
	}
	row, err := scanDiagnosticReport(s.db.QueryRowContext(c.Request.Context(), `SELECT `+diagnosticReportColumns+diagnosticReportFrom+`WHERE r.tenant_id=? AND r.id=?`, tenantID(c), id))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "DIAGNOSTIC_REPORT_NOT_FOUND", "Report not found")
		return row, false
	}
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_REPORT_QUERY_FAILED", "Unable to load the report")
		return row, false
	}
	return row, true
}

func (s *server) diagnosticReportDetail(c *gin.Context) {
	row, ok := s.diagnosticReportForAdmin(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"report": row.view(time.Now().UTC())})
}

// openDiagnosticLog 打开一条报告的日志正文（已解压、有上限）。调用方负责 Close。
func (s *server) openDiagnosticLog(c *gin.Context, row diagnosticReportRow) (io.ReadCloser, bool) {
	if !row.ObjectKey.Valid || row.LogStatus != "stored" {
		problem(c, 404, "DIAGNOSTIC_LOG_NOT_AVAILABLE", "This report has no stored log")
		return nil, false
	}
	ctx, tenant := c.Request.Context(), tenantID(c)
	client, prefix, err := s.storageClientForTenant(ctx, tenant)
	if err != nil {
		problem(c, 503, "STORAGE_UNAVAILABLE", "Log storage is unavailable")
		return nil, false
	}
	// 行已经按租户查过了，这是第二道：键不在本租户的诊断前缀下就当不存在
	if !diagnosticObjectBelongsTo(row.ObjectKey.String, prefix, tenant) {
		slog.Error("diagnostic report points outside its tenant prefix", "tenant", tenant, "report", row.ID)
		problem(c, 404, "DIAGNOSTIC_LOG_NOT_AVAILABLE", "This report has no stored log")
		return nil, false
	}
	body, err := client.Get(ctx, row.ObjectKey.String)
	if err != nil {
		problem(c, 404, "DIAGNOSTIC_LOG_NOT_AVAILABLE", "This report has no stored log")
		return nil, false
	}
	reader, err := gzip.NewReader(body)
	if err != nil {
		body.Close()
		problem(c, 500, "DIAGNOSTIC_LOG_UNREADABLE", "The stored log cannot be read")
		return nil, false
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(reader, diagnosticReadMaxBytes), body}, true
}

func (s *server) diagnosticReportLog(c *gin.Context) {
	row, ok := s.diagnosticReportForAdmin(c)
	if !ok {
		return
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, err := strconv.Atoi(c.DefaultQuery("limit", strconv.Itoa(diagnosticLogPageDefault)))
	if offset < 0 || err != nil || limit < 1 || limit > diagnosticLogPageMax {
		problem(c, 400, "INVALID_DIAGNOSTIC_FILTER", "offset must be >= 0 and limit between 1 and 500")
		return
	}
	level, tag, q := c.Query("level"), c.Query("tag"), strings.ToLower(strings.TrimSpace(c.Query("q")))
	if (level != "" && !diagnosticLevels[level]) || (tag != "" && !diagnosticTags[tag]) {
		problem(c, 400, "INVALID_DIAGNOSTIC_FILTER", "level or tag is invalid")
		return
	}
	body, ok := s.openDiagnosticLog(c, row)
	if !ok {
		return
	}
	defer body.Close()

	items, total := []diagnosticLogLine{}, 0
	reader := bufio.NewReaderSize(body, diagnosticReadLineMax)
	for {
		raw, tooLong, readErr := readDiagnosticLine(reader)
		if len(raw) > 0 && !tooLong {
			var line diagnosticLogLine
			if json.Unmarshal(raw, &line) == nil && (level == "" || line.Level == level) && (tag == "" || line.Tag == tag) && (q == "" || diagnosticLineContains(line, q)) {
				if total >= offset && len(items) < limit {
					items = append(items, line)
				}
				total++
			}
		}
		if readErr != nil {
			break
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "offset": offset, "limit": limit})
}

func diagnosticLineContains(line diagnosticLogLine, q string) bool {
	if strings.Contains(strings.ToLower(line.Message), q) {
		return true
	}
	for _, value := range line.Fields {
		if text, ok := value.(string); ok && strings.Contains(strings.ToLower(text), q) {
			return true
		}
	}
	return false
}

// diagnosticReportRawLog 下载原文件。三个响应头一个都不能少：纯文本类型、附件、nosniff——
// 否则浏览器可能把一行 message 里的 HTML 当页面渲染，打到管理员会话上。
func (s *server) diagnosticReportRawLog(c *gin.Context) {
	row, ok := s.diagnosticReportForAdmin(c)
	if !ok {
		return
	}
	body, ok := s.openDiagnosticLog(c, row)
	if !ok {
		return
	}
	defer body.Close()
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+row.Reference+`.ndjson"`)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, body)
}

func (s *server) updateDiagnosticReportStatus(c *gin.Context) {
	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if decode(c, &body) != nil || !oneOf(body.Status, "new", "triaged", "closed") {
		problem(c, 400, "INVALID_DIAGNOSTIC_STATUS", "status must be new, triaged or closed")
		return
	}
	row, ok := s.diagnosticReportForAdmin(c)
	if !ok {
		return
	}
	ctx, tenant, now := c.Request.Context(), tenantID(c), time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_STATUS_FAILED", "Unable to update the report")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE app_diagnostic_reports SET status=?,updated_at=? WHERE tenant_id=? AND id=?`, body.Status, now, tenant, row.ID); err != nil {
		problem(c, 500, "DIAGNOSTIC_STATUS_FAILED", "Unable to update the report")
		return
	}
	audit := newAudit(tenant, actor(c), "diagnostic_report_status", "diagnostic_report", strconv.FormatUint(row.ID, 10), clipRunes(strings.TrimSpace(body.Note), 500), requestID(c),
		map[string]any{"reference": row.Reference, "from": row.Status, "to": body.Status})
	if err := insertAudit(ctx, tx, audit); err != nil || tx.Commit() != nil {
		problem(c, 500, "DIAGNOSTIC_STATUS_FAILED", "Unable to update the report")
		return
	}
	row.Status, row.UpdatedAt = body.Status, now
	c.JSON(http.StatusOK, gin.H{"report": row.view(now)})
}

type diagnosticDeleteRequest struct {
	IDs     []string `json:"ids"`
	Reason  string   `json:"reason"`
	Confirm bool     `json:"confirm"`
}

// deleteDiagnosticObjects 删对象存储里的日志，返回对象已删（或本来就没有日志）的行与删不掉的 ID。
//
// 必须先删对象、再删行：反过来的话，对象删失败就成了一份没有任何指针指向、又永远不会过期
// （无保留期，设计 D14）的日志。对象删不掉的那几条保留行，让管理员重试。
func (s *server) deleteDiagnosticObjects(ctx context.Context, tenant string, rows []diagnosticReportRow) (removable []diagnosticReportRow, failed []string) {
	client, prefix, clientErr := s.storageClientForTenant(ctx, tenant)
	for _, row := range rows {
		if row.ObjectKey.Valid {
			if clientErr != nil || !diagnosticObjectBelongsTo(row.ObjectKey.String, prefix, tenant) || client.Delete(ctx, row.ObjectKey.String) != nil {
				failed = append(failed, strconv.FormatUint(row.ID, 10))
				continue
			}
		}
		removable = append(removable, row)
	}
	return removable, failed
}

func (s *server) deleteDiagnosticReports(c *gin.Context) {
	var body diagnosticDeleteRequest
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, 400, "CONFIRMATION_REQUIRED", "reason and confirm=true are required")
		return
	}
	// 单条删除走路径参数，批量走 ids。批量只收明确的 ID 列表，不收"按筛选条件删"：
	// 筛选条件写错一个就是整个租户的报告没了，而这些报告没有保留期、删了就找不回
	if id := c.Param("id"); id != "" {
		body.IDs = []string{id}
	}
	if len(body.IDs) == 0 || len(body.IDs) > diagnosticBulkDeleteMax {
		problem(c, 400, "INVALID_DIAGNOSTIC_DELETE", "ids must list 1 to 200 reports")
		return
	}
	ctx, tenant := c.Request.Context(), tenantID(c)
	placeholders, args := make([]string, 0, len(body.IDs)), []any{tenant}
	for _, raw := range body.IDs {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			problem(c, 400, "INVALID_DIAGNOSTIC_DELETE", "ids must be report ids")
			return
		}
		placeholders, args = append(placeholders, "?"), append(args, id)
	}
	result, err := s.db.QueryContext(ctx, `SELECT `+diagnosticReportColumns+diagnosticReportFrom+`WHERE r.tenant_id=? AND r.id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		problem(c, 500, "DIAGNOSTIC_DELETE_FAILED", "Unable to load the reports")
		return
	}
	var rows []diagnosticReportRow
	for result.Next() {
		row, scanErr := scanDiagnosticReport(result)
		if scanErr != nil {
			result.Close()
			problem(c, 500, "DIAGNOSTIC_DELETE_FAILED", "Unable to load the reports")
			return
		}
		rows = append(rows, row)
	}
	result.Close()
	if c.Param("id") != "" && len(rows) == 0 {
		problem(c, 404, "DIAGNOSTIC_REPORT_NOT_FOUND", "Report not found")
		return
	}

	removable, failed := s.deleteDiagnosticObjects(ctx, tenant, rows)
	references := make([]string, 0, len(removable))
	if len(removable) > 0 {
		ids := make([]string, 0, len(removable))
		deleteArgs := []any{tenant}
		for _, row := range removable {
			references, ids = append(references, row.Reference), append(ids, "?")
			deleteArgs = append(deleteArgs, row.ID)
		}
		target := "bulk"
		if len(removable) == 1 {
			target = strconv.FormatUint(removable[0].ID, 10)
		}
		// 删行与审计同一个事务：不允许出现"删了但没有记录是谁删的"
		tx, txErr := s.db.BeginTx(ctx, nil)
		if txErr == nil {
			defer tx.Rollback()
			_, txErr = tx.ExecContext(ctx, `DELETE FROM app_diagnostic_reports WHERE tenant_id=? AND id IN (`+strings.Join(ids, ",")+`)`, deleteArgs...)
		}
		if txErr == nil {
			txErr = insertAudit(ctx, tx, newAudit(tenant, actor(c), "diagnostic_report_delete", "diagnostic_report", target, strings.TrimSpace(body.Reason), requestID(c),
				map[string]any{"references": references, "failed": failed}))
		}
		if txErr == nil {
			txErr = tx.Commit()
		}
		if txErr != nil {
			// 对象已经删了、行还在：查看日志会得到"没有日志"，再删一次即可收尾
			slog.Error("diagnostic report delete failed", "error", txErr, "requestId", requestID(c), "tenant", tenant)
			problem(c, 500, "DIAGNOSTIC_DELETE_FAILED", "Unable to delete the reports; retry")
			return
		}
	}
	status := http.StatusOK
	if len(failed) > 0 {
		status = http.StatusMultiStatus
	}
	c.JSON(status, gin.H{"deleted": references, "failed": failed})
}
