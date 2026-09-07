package api

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *server) installationOverview(c *gin.Context) {
	now := time.Now().UTC()
	var total, active1d, active7d, active30d int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*), COALESCE(SUM(status='active' AND last_active_at>=?),0), COALESCE(SUM(status='active' AND last_active_at>=?),0), COALESCE(SUM(status='active' AND last_active_at>=?),0) FROM app_installations WHERE tenant_id=?`, now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour), tenantID(c)).Scan(&total, &active1d, &active7d, &active30d); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation overview")
		return
	}
	versions, err := s.installationVersionDistribution(c)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation versions")
		return
	}
	otaRevisions, launchSources, err := s.installationOTADistribution(c)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation OTA distribution")
		return
	}
	var signedIn, accounts1d, accounts7d, accounts30d int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(DISTINCT installation_id) FROM wallet_session WHERE tenant_id=? AND installation_id IS NOT NULL AND revoked_at IS NULL AND expires_at>?`, tenantID(c), now).Scan(&signedIn); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to count signed-in installations")
		return
	}
	// 活跃账号按会话最近使用时间算（每次会话校验都会刷新），不是登录时间
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(DISTINCT CASE WHEN last_seen_at>=? THEN user_id END),COUNT(DISTINCT CASE WHEN last_seen_at>=? THEN user_id END),COUNT(DISTINCT CASE WHEN last_seen_at>=? THEN user_id END) FROM wallet_session WHERE tenant_id=? AND last_seen_at>=?`, now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour), tenantID(c), now.Add(-30*24*time.Hour)).Scan(&accounts1d, &accounts7d, &accounts30d); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to count active accounts")
		return
	}
	c.JSON(http.StatusOK, gin.H{"generatedAt": iso(now), "total": total, "active": gin.H{"oneDay": active1d, "sevenDays": active7d, "thirtyDays": active30d}, "versions": versions, "otaRevisions": otaRevisions, "launchSources": launchSources, "signedInInstallations": signedIn, "activeAccounts": gin.H{"oneDay": accounts1d, "sevenDays": accounts7d, "thirtyDays": accounts30d}})
}

func (s *server) installationVersionDistribution(c *gin.Context) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT platform,app_version,build_number,COUNT(*) FROM app_installations WHERE tenant_id=? GROUP BY platform,app_version,build_number ORDER BY platform,COUNT(*) DESC`, tenantID(c))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	versions := []gin.H{}
	for rows.Next() {
		var platform, version, build string
		var count int
		if err := rows.Scan(&platform, &version, &build, &count); err != nil {
			return nil, err
		}
		versions = append(versions, gin.H{"platform": platform, "version": version, "buildNumber": build, "count": count})
	}
	return versions, rows.Err()
}

// installationOTADistribution 回答"这版 OTA 生效了多少设备、还有多少待生效"：
// running 按心跳上报的运行中修订号统计（只算 launch_source=ota 的实例，关联不上的归入 revision=null），
// available 按 bootstrap 下发的可用修订号统计；两者之差就是待生效。
// launchSources 里 unreported 是旧版 App，没有上报启动来源，不能当成内置。
func (s *server) installationOTADistribution(c *gin.Context) ([]gin.H, gin.H, error) {
	type bucket struct {
		revision  sql.NullInt64
		running   int
		available int
	}
	buckets := map[int64]*bucket{}
	unknown := &bucket{}
	get := func(revision sql.NullInt64) *bucket {
		if !revision.Valid {
			return unknown
		}
		if item, ok := buckets[revision.Int64]; ok {
			return item
		}
		item := &bucket{revision: revision}
		buckets[revision.Int64] = item
		return item
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT running_ota_revision,COUNT(*) FROM app_installations WHERE tenant_id=? AND launch_source='ota' GROUP BY running_ota_revision`, tenantID(c))
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var revision sql.NullInt64
		var count int
		if err := rows.Scan(&revision, &count); err != nil {
			rows.Close()
			return nil, nil, err
		}
		get(revision).running = count
	}
	rows.Close()
	rows, err = s.db.QueryContext(c.Request.Context(), `SELECT ota_revision,COUNT(*) FROM app_installations WHERE tenant_id=? AND ota_revision IS NOT NULL GROUP BY ota_revision`, tenantID(c))
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var revision sql.NullInt64
		var count int
		if err := rows.Scan(&revision, &count); err != nil {
			rows.Close()
			return nil, nil, err
		}
		get(revision).available = count
	}
	rows.Close()
	keys := make([]int64, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })
	otaRevisions := make([]gin.H, 0, len(keys)+1)
	for _, key := range keys {
		item := buckets[key]
		otaRevisions = append(otaRevisions, gin.H{"revision": key, "running": item.running, "available": item.available})
	}
	if unknown.running > 0 {
		otaRevisions = append(otaRevisions, gin.H{"revision": nil, "running": unknown.running, "available": 0})
	}
	launchSources := gin.H{"embedded": 0, "ota": 0, "unreported": 0}
	rows, err = s.db.QueryContext(c.Request.Context(), `SELECT COALESCE(launch_source,'unreported'),COUNT(*) FROM app_installations WHERE tenant_id=? GROUP BY COALESCE(launch_source,'unreported')`, tenantID(c))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var source string
		var count int
		if err := rows.Scan(&source, &count); err != nil {
			return nil, nil, err
		}
		launchSources[source] = count
	}
	return otaRevisions, launchSources, rows.Err()
}

const installationListMaxLimit = 200

type installationListFilter struct {
	query        string
	platform     string
	appVersion   string
	launchSource string
	otaRevision  sql.NullInt64
	activeSince  time.Time
	status       string
	limit        int
	cursorAt     time.Time
	cursorID     uint64
	hasCursor    bool
}

// parseInstallationListFilter 解析列表参数；不合法的值直接 422，不静默忽略。
func parseInstallationListFilter(c *gin.Context, now time.Time) (installationListFilter, string) {
	f := installationListFilter{query: strings.TrimSpace(c.Query("q")), platform: strings.ToLower(strings.TrimSpace(c.Query("platform"))), appVersion: strings.TrimSpace(c.Query("appVersion")), launchSource: strings.ToLower(strings.TrimSpace(c.Query("launchSource"))), status: strings.ToLower(strings.TrimSpace(c.Query("status"))), limit: 50}
	if f.platform != "" && f.platform != "android" && f.platform != "ios" {
		return f, "platform must be android or ios"
	}
	if f.launchSource != "" && f.launchSource != "embedded" && f.launchSource != "ota" && f.launchSource != "unreported" {
		return f, "launchSource must be embedded, ota or unreported"
	}
	if raw := strings.TrimSpace(c.Query("runningOtaRevision")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return f, "runningOtaRevision must be a non-negative integer"
		}
		f.otaRevision = sql.NullInt64{Int64: value, Valid: true}
	}
	switch strings.TrimSpace(c.Query("activeWithin")) {
	case "":
	case "1d":
		f.activeSince = now.Add(-24 * time.Hour)
	case "7d":
		f.activeSince = now.Add(-7 * 24 * time.Hour)
	case "30d":
		f.activeSince = now.Add(-30 * 24 * time.Hour)
	default:
		return f, "activeWithin must be 1d, 7d or 30d"
	}
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > installationListMaxLimit {
			return f, "limit must be between 1 and 200"
		}
		f.limit = value
	}
	if raw := strings.TrimSpace(c.Query("cursor")); raw != "" {
		at, id, err := decodeInstallationCursor(raw)
		if err != nil {
			return f, "cursor is invalid"
		}
		f.cursorAt, f.cursorID, f.hasCursor = at, id, true
	}
	return f, ""
}

// 游标按 (last_active_at DESC, id DESC) 定位：编码成 base64url("<毫秒时间戳>:<内部id>")。
func encodeInstallationCursor(at time.Time, id uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%d", at.UnixMilli(), id)))
}

func decodeInstallationCursor(raw string) (time.Time, uint64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, 0, err
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return time.Time{}, 0, errors.New("cursor must have two parts")
	}
	millis, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, 0, err
	}
	id, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return time.Time{}, 0, err
	}
	return time.UnixMilli(millis).UTC(), id, nil
}

// where 生成针对别名 i（app_installations）的条件；列都带前缀，子查询里同名列不会串。
func (f installationListFilter) where(tenant string) (string, []any) {
	clauses := []string{"i.tenant_id=?"}
	args := []any{tenant}
	if f.query != "" {
		clauses = append(clauses, "(i.installation_id LIKE ? OR i.package_id LIKE ?)")
		args = append(args, f.query+"%", "%"+f.query+"%")
	}
	if f.platform != "" {
		clauses = append(clauses, "i.platform=?")
		args = append(args, f.platform)
	}
	if f.appVersion != "" {
		clauses = append(clauses, "i.app_version=?")
		args = append(args, f.appVersion)
	}
	switch f.launchSource {
	case "unreported":
		clauses = append(clauses, "i.launch_source IS NULL")
	case "embedded", "ota":
		clauses = append(clauses, "i.launch_source=?")
		args = append(args, f.launchSource)
	}
	if f.otaRevision.Valid {
		clauses = append(clauses, "i.running_ota_revision=?")
		args = append(args, f.otaRevision.Int64)
	}
	if !f.activeSince.IsZero() {
		clauses = append(clauses, "i.last_active_at>=?")
		args = append(args, f.activeSince)
	}
	if f.status != "" {
		clauses = append(clauses, "i.status=?")
		args = append(args, f.status)
	}
	return strings.Join(clauses, " AND "), args
}

func (s *server) listInstallations(c *gin.Context) {
	now := time.Now().UTC()
	filter, invalid := parseInstallationListFilter(c, now)
	if invalid != "" {
		problem(c, 422, "INVALID_INSTALLATION_FILTER", invalid)
		return
	}
	where, args := filter.where(tenantID(c))
	var total int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM app_installations i WHERE `+where, args...).Scan(&total); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to count installations")
		return
	}
	pageWhere, pageArgs := where, append([]any{}, args...)
	if filter.hasCursor {
		pageWhere += " AND (i.last_active_at<? OR (i.last_active_at=? AND i.id<?))"
		pageArgs = append(pageArgs, filter.cursorAt, filter.cursorAt, filter.cursorID)
	}
	pageArgs = append(pageArgs, filter.limit+1)
	// 当前账号只从有效会话派生（设计 §4.3）：一个安装实例最多一条有效会话，子查询按安装实例索引命中
	pageArgs = append([]any{now, now, now, now}, pageArgs...)
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT i.id,i.installation_id,i.application_id,i.package_id,i.platform,i.app_version,i.build_number,i.runtime_version,i.ota_revision,i.launch_source,i.running_update_id,i.running_ota_revision,i.client_session_state,i.localization_version,i.branding_version,i.locale,i.theme,i.os_version,i.device_class,i.last_active_at,i.status,
		(SELECT s.id FROM wallet_session s WHERE s.tenant_id=i.tenant_id AND s.installation_id=i.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1),
		(SELECT s.user_id FROM wallet_session s WHERE s.tenant_id=i.tenant_id AND s.installation_id=i.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1),
		(SELECT u.address FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id WHERE s.tenant_id=i.tenant_id AND s.installation_id=i.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1),
		(SELECT s.last_seen_at FROM wallet_session s WHERE s.tenant_id=i.tenant_id AND s.installation_id=i.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1),
		(SELECT COUNT(*) FROM wallet_user_installation r WHERE r.tenant_id=i.tenant_id AND r.installation_id=i.installation_id)
		FROM app_installations i WHERE `+pageWhere+` ORDER BY i.last_active_at DESC, i.id DESC LIMIT ?`, pageArgs...)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installations")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	var nextCursor any
	for rows.Next() {
		var rowID uint64
		var id, applicationID, packageID, platform, version, build, runtime, locale, theme, osVersion, deviceClass, status string
		var otaRevision, runningRevision, brandingVersion, currentUserID sql.NullInt64
		var launchSource, runningUpdateID, sessionState, localizationVersion, currentSessionID, currentAddress sql.NullString
		var active time.Time
		var currentLastSeen sql.NullTime
		var accountsCount int
		if err := rows.Scan(&rowID, &id, &applicationID, &packageID, &platform, &version, &build, &runtime, &otaRevision, &launchSource, &runningUpdateID, &runningRevision, &sessionState, &localizationVersion, &brandingVersion, &locale, &theme, &osVersion, &deviceClass, &active, &status, &currentSessionID, &currentUserID, &currentAddress, &currentLastSeen, &accountsCount); err != nil {
			problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to read installations")
			return
		}
		if len(items) == filter.limit {
			// 多取的一行只用来判断还有下一页，游标指向本页最后一行
			previous := items[len(items)-1]
			nextCursor = previous["cursor"]
			break
		}
		var current *currentSession
		if currentSessionID.Valid {
			current = &currentSession{ID: currentSessionID.String, UserID: uint64(currentUserID.Int64), Address: currentAddress.String, LastSeenAt: currentLastSeen.Time}
		}
		items = append(items, gin.H{"installationId": id, "applicationId": applicationID, "packageId": packageID, "platform": platform, "appVersion": version, "buildNumber": build, "runtimeVersion": runtime, "otaRevision": nullableInt64(otaRevision), "availableOtaRevision": nullableInt64(otaRevision), "launchSource": nullableSQLString(launchSource), "runningUpdateId": nullableSQLString(runningUpdateID), "runningOtaRevision": nullableInt64(runningRevision), "clientSessionState": nullableSQLString(sessionState), "localizationVersion": nullableSQLString(localizationVersion), "brandingVersion": nullableInt64(brandingVersion), "locale": locale, "theme": theme, "osVersion": osVersion, "deviceClass": deviceClass, "lastActiveAt": iso(active), "status": status, "currentAccount": currentSessionJSON(current), "accountsCount": accountsCount, "activity": installationActivity(current, active, now), "sessionMismatch": nullableString(sessionMismatch(sessionState, current)), "cursor": encodeInstallationCursor(active, rowID)})
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to read installations")
		return
	}
	for _, item := range items {
		delete(item, "cursor")
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "nextCursor": nextCursor, "limit": filter.limit})
}

func (s *server) listPushOutbox(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT o.id,o.event_type,o.status,o.attempts,o.last_error,o.created_at,o.sent_at,COALESCE(SUM(d.status='sent'),0),COALESCE(SUM(d.status='failed'),0) FROM app_push_outbox o LEFT JOIN app_push_deliveries d ON d.event_id=o.id AND d.tenant_id=o.tenant_id WHERE o.tenant_id=? GROUP BY o.id ORDER BY o.created_at DESC LIMIT 200`, tenantID(c))
	if err != nil {
		problem(c, 500, "PUSH_QUERY_FAILED", "Unable to load push events")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, eventType, status string
		var attempts, sent, failed int
		var lastError sql.NullString
		var created, sentAt sql.NullTime
		if err := rows.Scan(&id, &eventType, &status, &attempts, &lastError, &created, &sentAt, &sent, &failed); err != nil {
			problem(c, 500, "PUSH_QUERY_FAILED", "Unable to read push events")
			return
		}
		items = append(items, gin.H{"id": id, "eventType": eventType, "status": status, "attempts": attempts, "lastError": nullableSQLString(lastError), "createdAt": nullableOTAFieldTime(created), "sentAt": nullableOTAFieldTime(sentAt), "sent": sent, "failed": failed})
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "PUSH_QUERY_FAILED", "Unable to read push events")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func (s *server) listPushDeliveries(c *gin.Context) {
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT d.event_id,d.installation_id,d.provider,d.provider_message_id,d.status,d.failure_code,d.sent_at,d.delivered_at,d.created_at FROM app_push_deliveries d WHERE d.tenant_id=? AND (?='' OR d.status=?) ORDER BY d.created_at DESC LIMIT 500`, tenantID(c), status, status)
	if err != nil {
		problem(c, 500, "PUSH_QUERY_FAILED", "Unable to load push deliveries")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var eventID, installationID, provider, status string
		var messageID, failure sql.NullString
		var sent, delivered, created sql.NullTime
		if err := rows.Scan(&eventID, &installationID, &provider, &messageID, &status, &failure, &sent, &delivered, &created); err != nil {
			problem(c, 500, "PUSH_QUERY_FAILED", "Unable to read push deliveries")
			return
		}
		items = append(items, gin.H{"eventId": eventID, "installationId": installationID, "provider": provider, "providerMessageId": nullableSQLString(messageID), "status": status, "failureCode": nullableSQLString(failure), "sentAt": nullableOTAFieldTime(sent), "deliveredAt": nullableOTAFieldTime(delivered), "createdAt": nullableOTAFieldTime(created)})
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}
