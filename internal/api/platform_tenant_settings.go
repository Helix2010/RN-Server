package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/gin-gonic/gin"
)

// 平台控制台上的平台级设置（设计 service-and-console-split-2026-09-27 §4.2、§7）。平台控制台不进入任何租户：
// 按租户的东西一律在这里以「租户 → 值」的表出现，改的时候路径里带租户 id。
//
//   - 租户列表：给各页分组、选租户用；
//   - 控制台成员：跨租户只读，按租户分组（§7 第 3 条）；
//   - 租户打包目录（repoDirectory）：只有这里能改，值仍存在各租户的 build.android（§7 第 1 条）；
//   - 外部系统关联（services.predict）：只有这里能改，值仍存在各租户的 mobile-bootstrap（§7 第 2 条）；
//   - 平台推送默认、平台发布存储默认与 CORS 汇总：原来是平台会话在租户页面上的特权，挪到这里（§5）。

// platformTenant 是租户列表的一行。
type platformTenant struct {
	ID      string   `json:"id"`
	Slug    string   `json:"slug"`
	Status  string   `json:"status"`
	AppName string   `json:"appName"`
	Domains []string `json:"domains"`
}

// platformTenants 列出没删除的租户，带启用状态（与 tenantResolver 同一个判据）、App 名与生效中的域名。
func (s *server) platformTenants(ctx context.Context) ([]platformTenant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT CAST(t.id AS CHAR), t.slug,
		       CASE WHEN (CAST(t.status AS UNSIGNED)=1 OR t.status='active')
		                  AND CURRENT_DATE >= t.start_date AND CURRENT_DATE <= t.expiry_date
		            THEN 'active' ELSE 'disabled' END
		FROM tenants t WHERE t.deleted=0 ORDER BY t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tenants := []platformTenant{}
	index := map[string]int{}
	for rows.Next() {
		var item platformTenant
		if err := rows.Scan(&item.ID, &item.Slug, &item.Status); err != nil {
			return nil, err
		}
		item.Domains = []string{}
		index[item.ID] = len(tenants)
		tenants = append(tenants, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	domains, err := s.db.QueryContext(ctx, `
		SELECT CAST(tenant_id AS CHAR), LOWER(TRIM(TRAILING '.' FROM domain)) FROM tenant_domain
		WHERE status='active' AND deleted=0 ORDER BY is_primary DESC, domain`)
	if err != nil {
		return nil, err
	}
	defer domains.Close()
	for domains.Next() {
		var tenant, domain string
		if err := domains.Scan(&tenant, &domain); err != nil {
			return nil, err
		}
		if i, ok := index[tenant]; ok {
			tenants[i].Domains = append(tenants[i].Domains, domain)
		}
	}
	if err := domains.Err(); err != nil {
		return nil, err
	}
	names, err := s.appNamesByTenant(ctx)
	if err != nil {
		return nil, err
	}
	for i := range tenants {
		tenants[i].AppName = names[tenants[i].ID]
	}
	return tenants, nil
}

// platformTenantParam 核对路径里的租户存在（没删除），返回列表里那一行的形状（不含域名）。
func (s *server) platformTenantParam(c *gin.Context) (platformTenant, bool) {
	ctx := c.Request.Context()
	item := platformTenant{ID: strings.TrimSpace(c.Param("tenantId")), Domains: []string{}}
	err := s.db.QueryRowContext(ctx, `
		SELECT t.slug,
		       CASE WHEN (CAST(t.status AS UNSIGNED)=1 OR t.status='active')
		                  AND CURRENT_DATE >= t.start_date AND CURRENT_DATE <= t.expiry_date
		            THEN 'active' ELSE 'disabled' END
		FROM tenants t WHERE t.id=? AND t.deleted=0 LIMIT 1`, item.ID).Scan(&item.Slug, &item.Status)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "TENANT_NOT_FOUND", "Tenant not found")
		return item, false
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANT_QUERY_FAILED", "Unable to load the tenant")
		return item, false
	}
	cfg, _, err := s.buildConfigFor(ctx, item.ID, item.Slug)
	if err == nil {
		item.AppName = strings.TrimSpace(cfg.Identity.AppName)
	}
	return item, true
}

// listPlatformTenants GET /v1/admin/platform/tenants
func (s *server) listPlatformTenants(c *gin.Context) {
	tenants, err := s.platformTenants(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANTS_QUERY_FAILED", "Unable to list tenants")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": tenants})
}

// listAllTenantAccounts GET /v1/admin/platform/tenant-accounts：全部租户的控制台成员，只读，每行带租户 id，
// 控制台按租户分组（账号由外部系统维护，设计 console-accounts-external-maintenance-2026-09-27）。
func (s *server) listAllTenantAccounts(c *gin.Context) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT `+tenantAccountColumns+` FROM tenant_admin_accounts WHERE scope=? ORDER BY tenant_id, id`, scopeTenant)
	if err != nil {
		problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list accounts")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		acc, err := scanTenantAccount(rows)
		if err != nil {
			problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list accounts")
			return
		}
		view := acc.adminView()
		view["tenantId"] = acc.TenantID
		items = append(items, view)
	}
	if rows.Err() != nil {
		problem(c, 500, "TENANT_ACCOUNTS_READ_FAILED", "Unable to list accounts")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{"items": items})
}

// ---- 租户打包目录 ----

// buildDirectoryView：repoDirectory 是生效值（没配过就是 slug），defaulted 说明它是不是退回的 slug。
// version 是这个租户 build.android 那一行的版本（0 = 还没有这一行），改的时候原样带回。
func buildDirectoryView(tenant platformTenant, cfg buildConfig, stored string, version int) gin.H {
	return gin.H{
		"tenantId": tenant.ID, "slug": tenant.Slug, "appName": tenant.AppName, "status": tenant.Status,
		"repoDirectory": cfg.RepoDirectory, "defaulted": strings.TrimSpace(stored) == "", "version": version,
	}
}

// listBuildDirectories GET /v1/admin/platform/build-directories
func (s *server) listBuildDirectories(c *gin.Context) {
	ctx := c.Request.Context()
	tenants, err := s.platformTenants(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANTS_QUERY_FAILED", "Unable to list tenants")
		return
	}
	stored := map[string]struct {
		directory string
		version   int
	}{}
	rows, err := s.db.QueryContext(ctx, `SELECT CAST(tenant_id AS CHAR),config_value,version FROM app_configs WHERE config_key=? AND tenant_id<>0`, buildConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_QUERY_FAILED", "Unable to load build configurations")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tenant string
		var raw []byte
		var version int
		if err := rows.Scan(&tenant, &raw, &version); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_CONFIG_QUERY_FAILED", "Unable to load build configurations")
			return
		}
		var cfg buildConfig
		// 读不懂的行按没配目录显示：这一页只管目录，别的字段坏了由租户页去报
		_ = json.Unmarshal(raw, &cfg)
		stored[tenant] = struct {
			directory string
			version   int
		}{cfg.RepoDirectory, version}
	}
	if rows.Err() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_QUERY_FAILED", "Unable to load build configurations")
		return
	}
	items := make([]gin.H, 0, len(tenants))
	for _, tenant := range tenants {
		row := stored[tenant.ID]
		directory := row.directory
		if strings.TrimSpace(directory) == "" {
			directory = tenant.Slug
		}
		items = append(items, buildDirectoryView(tenant, buildConfig{RepoDirectory: directory}, row.directory, row.version))
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// updateBuildDirectory PUT /v1/admin/platform/build-directories/:tenantId
//
// 只改 build.android 的 repoDirectory，其余字段原样保留；租户还没保存过构建配置时新建一行，只带目录——
// 读取那一侧按结构体读，缺的字段是零值，和没有这一行一样，只是目录不再退回 slug。租户页上目录只读、原样带回。
func (s *server) updateBuildDirectory(c *gin.Context) {
	target, ok := s.platformTenantParam(c)
	if !ok {
		return
	}
	tenant, slug := target.ID, target.Slug
	var body struct {
		RepoDirectory   string `json:"repoDirectory"`
		ExpectedVersion int    `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_DIRECTORY", "repoDirectory, expectedVersion, reason and confirm=true are required")
		return
	}
	directory := strings.TrimSpace(body.RepoDirectory)
	if directory == "" {
		directory = slug
	}
	// 这个值会被打包机拼进文件路径（同 saveBuildConfig）
	if !repoDirectoryPattern.MatchString(directory) || strings.Contains(directory, "..") {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_DIRECTORY", "repoDirectory must be a plain directory name under tenants/")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_DIRECTORY_SAVE_FAILED", "Unable to save the build directory")
		return
	}
	defer tx.Rollback()
	var raw []byte
	current := 0
	err = tx.QueryRowContext(ctx, `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1 FOR UPDATE`, tenant, buildConfigKey).Scan(&raw, &current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "BUILD_DIRECTORY_SAVE_FAILED", "Unable to save the build directory")
		return
	}
	if current != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	var cfg buildConfig
	if len(raw) > 0 && json.Unmarshal(raw, &cfg) != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	previous := cfg.RepoDirectory
	cfg.RepoDirectory, cfg.DefaultGitRef = directory, buildGitRef
	value, _ := json.Marshal(cfg)
	now := time.Now().UTC()
	var result sql.Result
	if current == 0 {
		result, err = tx.ExecContext(ctx, `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenant, buildConfigKey, value, actor(c), now, tenant, buildConfigKey)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, tenant, buildConfigKey, current)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_DIRECTORY_SAVE_FAILED", "Unable to save the build directory")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	// 记在这个租户名下：租户的审计里看得到平台改了它的目录
	event := newAudit(tenant, actor(c), "build_directory_update", "app-config", buildConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"repoDirectory": directory, "previous": nullableString(previous), "databaseVersion": current + 1})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_DIRECTORY_SAVE_FAILED", "Unable to save the build directory")
		return
	}
	c.JSON(http.StatusOK, buildDirectoryView(target, cfg, directory, current+1))
}

// ---- 外部系统关联（预测平台） ----

// mobileBootstrapFor 读租户生效的 mobile-bootstrap：自己的那一行，没有就是平台默认（tenant 0）。
// version 是那一行的版本：租户页保存与这里的改动都拿它做乐观并发。
func mobileBootstrapFor(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, tenant string, forUpdate bool) (map[string]any, int, error) {
	query := `SELECT config_value,version FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var raw []byte
	var version int
	if err := q.QueryRowContext(ctx, query, tenant, tenant).Scan(&raw, &version); err != nil {
		return nil, 0, err
	}
	config := map[string]any{}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, version, err
	}
	return config, version, nil
}

// predictLinkView：predict 是规范化后的关联（没配或配坏了是 null），predictEnabled 是租户开没开预测市场模块——
// 开着的租户不能取消关联，否则 App 拿不到配置；chains 是租户启用的链，预测市场模块开着时关联的链必须在里面。
func predictLinkView(tenant platformTenant, config map[string]any, version int) gin.H {
	services := normalizeServices(config["services"])
	modules := normalizeModules(object(config["modules"]))
	chains, _ := normalizeWallet(object(config["wallet"]))["chains"].([]any)
	if chains == nil {
		chains = []any{}
	}
	return gin.H{
		"tenantId": tenant.ID, "slug": tenant.Slug, "appName": tenant.AppName, "status": tenant.Status,
		"predict": services["predict"], "predictEnabled": truth(modules["predict"]), "chains": chains, "version": version,
	}
}

// listPredictLinks GET /v1/admin/platform/predict-links
func (s *server) listPredictLinks(c *gin.Context) {
	ctx := c.Request.Context()
	tenants, err := s.platformTenants(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANTS_QUERY_FAILED", "Unable to list tenants")
		return
	}
	items := make([]gin.H, 0, len(tenants))
	for _, tenant := range tenants {
		config, version, err := mobileBootstrapFor(ctx, s.db, tenant.ID, false)
		if errors.Is(err, sql.ErrNoRows) {
			config, version = map[string]any{}, 0
		} else if err != nil {
			problem(c, http.StatusInternalServerError, "APP_CONFIG_QUERY_FAILED", "Unable to load the tenants' app configuration")
			return
		}
		items = append(items, predictLinkView(tenant, config, version))
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// updatePredictLink PUT /v1/admin/platform/predict-links/:tenantId
//
// 只动 mobile-bootstrap 的 services.predict，其余原样；写法与租户页保存同一套：版本先判、预测市场模块开着
// 就必须有完整合法的关联且链在租户启用的链里、租户还没有自己那一行时从平台默认复制一行、通知 App 配置变了。
// predict 为 null 是取消关联。
func (s *server) updatePredictLink(c *gin.Context) {
	target, ok := s.platformTenantParam(c)
	if !ok {
		return
	}
	tenant := target.ID
	var body struct {
		Predict         map[string]any `json:"predict"`
		ExpectedVersion int            `json:"expectedVersion"`
		Reason          string         `json:"reason"`
		Confirm         bool           `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 1 {
		problem(c, http.StatusBadRequest, "INVALID_PREDICT_LINK", "predict (or null), expectedVersion, reason and confirm=true are required")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	defer tx.Rollback()
	config, storedVersion, err := mobileBootstrapFor(ctx, tx, tenant, true)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusConflict, "APP_CONFIG_MISSING", "This platform has no default app configuration yet")
		return
	}
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	if body.ExpectedVersion != storedVersion {
		problem(c, http.StatusConflict, "STALE_APP_CONFIG",
			fmt.Sprintf("这个租户的应用配置在你打开之后被改过（你的版本 %d，当前 %d）。刷新之后再改。", body.ExpectedVersion, storedVersion))
		return
	}
	services := map[string]any{}
	for key, value := range object(config["services"]) {
		services[key] = value
	}
	summary := map[string]any{"linked": body.Predict != nil}
	if body.Predict == nil {
		delete(services, "predict")
	} else {
		predict, err := parsePredictService(body.Predict)
		if err != nil {
			problem(c, 400, "INVALID_SERVICES_CONFIG", err.Error())
			return
		}
		services["predict"] = predict.asMap()
		summary["domain"], summary["scopeId"], summary["chain"] = predict.Domain, predict.ScopeID, predict.Chain
	}
	config["services"] = services
	if _, err := predictServiceFor(normalizeModules(object(config["modules"])), services, normalizeWallet(object(config["wallet"]))); err != nil {
		problem(c, 400, "INVALID_SERVICES_CONFIG", err.Error())
		return
	}
	delete(config, "configVersion")
	raw, _ := json.Marshal(config)
	now := time.Now().UTC()
	newVersion, err := writeMobileBootstrapRow(ctx, tx, tenant, raw, actor(c), now, storedVersion)
	if errors.Is(err, errStaleAppConfig) {
		problem(c, 409, "STALE_APP_CONFIG", "App config changed since it was loaded; refresh and retry")
		return
	}
	if err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	savedConfigVersion := derivedConfigVersion(now, newVersion)
	summary["databaseVersionBefore"], summary["databaseVersionAfter"], summary["configVersion"] = storedVersion, newVersion, savedConfigVersion
	// 记在这个租户名下：租户的审计里看得到平台改了它的预测平台关联
	if insertAudit(ctx, tx, newAudit(tenant, actor(c), "predict_link_update", "app-config", "mobile-bootstrap", strings.TrimSpace(body.Reason), requestID(c), summary)) != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config audit")
		return
	}
	if err := enqueuePushEvent(ctx, tx, tenant, "bootstrap_updated", map[string]any{"configVersion": savedConfigVersion}); err != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to enqueue config notification")
		return
	}
	if tx.Commit() != nil {
		problem(c, 500, "CONFIG_SAVE_FAILED", "Unable to save app config")
		return
	}
	c.JSON(http.StatusOK, predictLinkView(target, config, newVersion))
}

// ---- 平台推送默认、平台发布存储默认 ----

// getPlatformPushCredentials GET /v1/admin/platform/push/credentials：平台默认那一行，加上有多少个租户在继承它。
func (s *server) getPlatformPushCredentials(c *gin.Context) {
	view, err := s.platformPushView(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIALS_QUERY_FAILED", "Unable to load push credentials")
		return
	}
	c.JSON(http.StatusOK, view)
}

// platformPushView 是平台控制台上的推送凭据视图（GET 与写、删之后的响应共用）。
func (s *server) platformPushView(ctx context.Context) (gin.H, error) {
	view, err := s.pushCredentialsView(ctx, pushcreds.PlatformTenant, true)
	if err != nil {
		return nil, err
	}
	// 平台那一行没有 google-services.json 与 bundle id 可对，这几项对它没有意义
	fcm, apns := view["fcm"].(gin.H), view["apns"].(gin.H)
	delete(fcm, "googleServicesProjectId")
	delete(fcm, "projectMatches")
	delete(apns, "topic")
	fcm["inheritors"], apns["inheritors"] = s.pushCredentialInheritors(ctx), s.apnsCredentialInheritors(ctx)
	return view, nil
}

// releaseStorageInheritors 数有多少个没删除的租户没有自己的发布存储——也就是在用平台默认那一行的。
func (s *server) releaseStorageInheritors(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenants t WHERE t.deleted=0
		   AND NOT EXISTS (SELECT 1 FROM app_configs c WHERE c.tenant_id=t.id AND c.config_key=?)`,
		releaseStorageConfigKey).Scan(&count)
	return count, err
}

// getPlatformReleaseStorage GET /v1/admin/platform/release-storage
func (s *server) getPlatformReleaseStorage(c *gin.Context) {
	ctx := c.Request.Context()
	record, err := s.releaseStorageRecord(ctx, platformTenantID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_QUERY_FAILED", "Unable to load release storage configuration")
		return
	}
	inheritors, err := s.releaseStorageInheritors(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "STORAGE_CONFIG_QUERY_FAILED", "Unable to load release storage configuration")
		return
	}
	view := releaseStorageView(record, platformTenantID, true)
	view["inheritors"] = inheritors
	c.JSON(http.StatusOK, view)
}

// updatePlatformReleaseStorage PUT /v1/admin/platform/release-storage：改平台默认那一行，所有没单独配的租户都继承它。
func (s *server) updatePlatformReleaseStorage(c *gin.Context) {
	s.writeReleaseStorage(c, platformTenantID, true)
}

// testPlatformReleaseStorage POST /v1/admin/platform/release-storage/test
func (s *server) testPlatformReleaseStorage(c *gin.Context) {
	s.checkReleaseStorage(c, platformTenantID, true)
}

// platformBucketCORS GET /v1/admin/platform/release-storage/cors：全平台所有租户域名的并集（共用的桶要放行所有租户）。
func (s *server) platformBucketCORS(c *gin.Context) {
	origins, err := s.tenantConsoleOrigins(c.Request.Context(), "")
	if err != nil {
		problem(c, http.StatusInternalServerError, "TENANT_DOMAIN_QUERY_FAILED", "Unable to list tenant domains")
		return
	}
	c.JSON(http.StatusOK, bucketCORSView(origins))
}
