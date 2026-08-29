package api

import (
	"database/sql"
	"net/http"
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
