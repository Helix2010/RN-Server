package api

import (
	"database/sql"
	"net/http"
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
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT platform,app_version,build_number,COUNT(*) FROM app_installations WHERE tenant_id=? GROUP BY platform,app_version,build_number ORDER BY platform,COUNT(*) DESC`, tenantID(c))
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation versions")
		return
	}
	defer rows.Close()
	versions := []gin.H{}
	for rows.Next() {
		var platform, version, build string
		var count int
		if err := rows.Scan(&platform, &version, &build, &count); err != nil {
			problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation versions")
			return
		}
		versions = append(versions, gin.H{"platform": platform, "version": version, "buildNumber": build, "count": count})
	}
	c.JSON(http.StatusOK, gin.H{"generatedAt": iso(now), "total": total, "active": gin.H{"oneDay": active1d, "sevenDays": active7d, "thirtyDays": active30d}, "versions": versions})
}

func (s *server) listInstallations(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT installation_id,application_id,package_id,platform,app_version,build_number,runtime_version,ota_revision,localization_version,branding_version,locale,theme,os_version,device_class,last_active_at,status FROM app_installations WHERE tenant_id=? ORDER BY last_active_at DESC LIMIT 500`, tenantID(c))
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installations")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, applicationID, packageID, platform, version, build, runtime, locale, theme, osVersion, deviceClass, status string
		var otaRevision, brandingVersion sql.NullInt64
		var localizationVersion sql.NullString
		var active time.Time
		if err := rows.Scan(&id, &applicationID, &packageID, &platform, &version, &build, &runtime, &otaRevision, &localizationVersion, &brandingVersion, &locale, &theme, &osVersion, &deviceClass, &active, &status); err != nil {
			problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to read installations")
			return
		}
		items = append(items, gin.H{"installationId": id, "applicationId": applicationID, "packageId": packageID, "platform": platform, "appVersion": version, "buildNumber": build, "runtimeVersion": runtime, "otaRevision": nullableInt64(otaRevision), "localizationVersion": nullableSQLString(localizationVersion), "brandingVersion": nullableInt64(brandingVersion), "locale": locale, "theme": theme, "osVersion": osVersion, "deviceClass": deviceClass, "lastActiveAt": iso(active), "status": status})
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to read installations")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
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
