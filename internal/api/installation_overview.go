package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func (s *server) installationOverview(c *gin.Context) {
	now := time.Now().UTC()
	var total, active1d, active7d, active30d int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*), COALESCE(SUM(last_active_at>=?),0), COALESCE(SUM(last_active_at>=?),0), COALESCE(SUM(last_active_at>=?),0) FROM app_installations WHERE tenant_id=?`, now.Add(-24*time.Hour), now.Add(-7*24*time.Hour), now.Add(-30*24*time.Hour), tenantID(c)).Scan(&total, &active1d, &active7d, &active30d); err != nil {
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
