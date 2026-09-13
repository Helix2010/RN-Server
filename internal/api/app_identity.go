package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

// getAppIdentity 返回服务端为这个租户合成的 tenant.json——和打包任务里下发给打包机
// 的是同一份（tenantManifestFor）。
//
// 为什么需要这个接口：热更新包在导出时会把这份身份烧进 manifest 的 extra
// （apiBaseUrl、scopeKey、appVersion、buildNumber 等，见 RN-App scripts/build-ota.mjs），
// 而 App 应用 OTA 之后读的就是那一份，不是 APK 里内嵌的那一份。也就是说，构建 OTA
// 的人必须拿到与正在分发的那个 APK 完全一致的身份。
//
// 仓库里的 tenants/<slug>/tenant.json 已经不是权威来源了（2026-09-12 起身份由控制台
// 维护、服务端合成）：它在仓库里停在 anyfun 1.3.7，而线上分发的是 1.3.14；照它构建
// 出来的包 appVersion 会倒退，客户端拿这个值去问"要不要升级"，答案就全错了。手工拼
// 一份同样不行——这正是"控制台改了、文件忘了改"那类漂移，结构上要让它不可能发生。
//
// 版本与 build 号取当前在分发的那一版 Android 发布：OTA 的 runtimeVersion 必须对准
// 它，否则一台设备都收不到。
//
// 返回的全是公开身份（包名、签名指纹、bootstrap 签名地址都编进每一个 APK），没有任何
// 私钥。
func (s *server) getAppIdentity(c *gin.Context) {
	ctx := c.Request.Context()
	tenant := tenantID(c)
	slug, err := s.tenantSlug(ctx, tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANT_NOT_FOUND", "Unable to read the tenant")
		return
	}
	buildCfg, _, err := s.buildConfigFor(ctx, tenant, slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	var releaseID, version string
	var buildNumber int
	err = s.db.QueryRowContext(ctx,
		`SELECT id, version, build_number FROM app_releases
		  WHERE tenant_id=? AND platform='android' AND status='active'
		  ORDER BY build_number DESC LIMIT 1`, tenant).Scan(&releaseID, &version, &buildNumber)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusConflict, "APP_IDENTITY_NO_ACTIVE_RELEASE",
			"This tenant has no active Android release yet; publish a package before building an OTA against it")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_QUERY_FAILED", "Unable to read the active release")
		return
	}
	manifest, err := s.tenantManifestFor(ctx, tenant, buildCfg, version, buildNumber)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			problem(c, http.StatusConflict, "APP_IDENTITY_INCOMPLETE", missing.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "APP_IDENTITY_INVALID", "Unable to compose the tenant app identity")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"tenantDirectory": buildCfg.RepoDirectory,
		"release":         gin.H{"id": releaseID, "version": version, "buildNumber": buildNumber},
		"manifest":        manifest,
	})
}
