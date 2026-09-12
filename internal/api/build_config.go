package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 每租户的构建配置（`app_configs` 的 `build.android`）。
//
// 存在的理由是 2026-09-11 部署时撞到的一件事：服务端的租户 slug 是 `Predict.Kim`，
// 而仓库里的租户目录叫 `anyfun`。两边是**两套命名**，代理拿 slug 去找
// `tenants/<slug>/tenant.json` 必然找不到。
//
// 不能靠"把某一边改成和另一边一样"来解决：slug 是本平台的身份，仓库目录是另一个
// 系统的目录名，两者恰好相等是现状不是规则（RN-Admin AGENTS.md 对外部系统 id 的
// 同一条约束）。所以对应关系必须是一条**显式配置**。
const buildConfigKey = "build.android"

var repoDirectoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type buildConfig struct {
	// RepoDirectory 是仓库里 tenants/ 下的目录名，不是本平台的 slug。
	RepoDirectory string `json:"repoDirectory"`
	// DefaultGitRef 保留是为了读得懂历史配置行。构建分支现在固定 main，不再由
	// 租户选：能选分支就意味着能从任意分支出一个用生产密钥签名的包。
	DefaultGitRef string `json:"defaultGitRef"`
	// GoogleServicesJSON 是 google-services.json 的 base64。它**不是机密**——
	// 同一份内容会原样编进每一个 APK——但它按租户不同，所以放在这里而不是放到
	// 每台打包机上。这样"新加一台打包机"仍然只需要一个封装口令。
	GoogleServicesJSON string `json:"googleServicesJson"`
	// Identity 是原先写在仓库 tenants/<目录>/tenant.json 里的那几个字段。搬过来的
	// 理由和代价见 tenant_manifest.go 顶部。
	Identity appIdentity `json:"identity"`
}

// appIdentity 只放**必须由人决定、而且别处没有**的字段。
//
// 包名和 bundleId 不在这里：它们已经是「发布身份」的内容（服务端拿它校验上传的
// APK 是不是这个租户的包），在这边再配一次就是两份可以对不上的真相——配歪了构建
// 会成功，产物却在入库那一步被拒，而报错完全看不出是"两个页面填了不同的包名"。
// 合成身份文件时从发布身份取，见 tenantManifestFor。
//
// 签名地址、签名指纹、版本号同理，服务端自己知道，不让人填也就不会填错。
type appIdentity struct {
	AppName             string `json:"appName"`
	Scheme              string `json:"scheme"`
	APIBaseURL          string `json:"apiBaseUrl"`
	IconBackgroundColor string `json:"iconBackgroundColor"`
}

// buildGitRef 是所有构建用的分支。固定值，不是默认值。
const buildGitRef = "main"

// validate 只挡住会让构建在很后面才失败、或者会产出一个身份不对的包的输入。
func (a appIdentity) validate() error {
	name := strings.TrimSpace(a.AppName)
	if name == "" || len([]rune(name)) > 64 {
		return errors.New("appName must be 1-64 characters")
	}
	if strings.TrimSpace(a.Scheme) != "" && !schemePattern.MatchString(a.Scheme) {
		// scheme 决定这个 App 认领哪些深链。写松了就是去抢别人的链接
		return errors.New("scheme must be lowercase letters, digits, . + - and start with a letter")
	}
	if err := validateAPIBaseURL(a.APIBaseURL); err != nil {
		return err
	}
	if color := strings.TrimSpace(a.IconBackgroundColor); color != "" && !hexColorPattern.MatchString(color) {
		return errors.New("iconBackgroundColor must be #RRGGBB")
	}
	return nil
}

// App 启动时拿这个地址取配置。允许 http 等于允许把整份配置放在明文链路上，而
// 客户端对这份配置的信任来自签名——签名挡不住"根本没连到我们"
func validateAPIBaseURL(raw string) error {
	value := strings.TrimRight(strings.TrimSpace(raw), "/")
	if value == "" {
		return errors.New("apiBaseUrl is required")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return errors.New("apiBaseUrl must be an https origin")
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("apiBaseUrl must be an origin with no path")
	}
	return nil
}

func (s *server) buildConfigFor(ctx context.Context, tenant, fallbackSlug string) (buildConfig, int, error) {
	var raw []byte
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, buildConfigKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		// 没配过就退回 slug——两边名字恰好一样的租户不必为此专门配一条
		return buildConfig{RepoDirectory: fallbackSlug, DefaultGitRef: buildGitRef}, 0, nil
	}
	if err != nil {
		return buildConfig{}, 0, err
	}
	var cfg buildConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return buildConfig{}, version, err
	}
	if strings.TrimSpace(cfg.RepoDirectory) == "" {
		cfg.RepoDirectory = fallbackSlug
	}
	cfg.DefaultGitRef = buildGitRef
	return cfg, version, nil
}

func (s *server) getBuildConfig(c *gin.Context) {
	slug, err := s.tenantSlug(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_QUERY_FAILED", "Unable to resolve this tenant")
		return
	}
	cfg, version, err := s.buildConfigFor(c.Request.Context(), tenantID(c), slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"repoDirectory": cfg.RepoDirectory,
		"defaultGitRef": cfg.DefaultGitRef,
		// 只报有没有配、多大，不把整段 base64 塞进每一次列表请求
		"googleServicesConfigured": cfg.GoogleServicesJSON != "",
		"tenantSlug":               slug,
		"version":                  version,
		"identity": gin.H{
			"appName":             cfg.Identity.AppName,
			"scheme":              cfg.Identity.Scheme,
			"apiBaseUrl":          cfg.Identity.APIBaseURL,
			"iconBackgroundColor": cfg.Identity.IconBackgroundColor,
		},
		"identityConfigured": cfg.Identity.validate() == nil,
	})
}

func (s *server) saveBuildConfig(c *gin.Context) {
	var body struct {
		RepoDirectory      string      `json:"repoDirectory"`
		GoogleServicesJSON string      `json:"googleServicesJson"`
		Identity           appIdentity `json:"identity"`
		ExpectedVersion    int         `json:"expectedVersion"`
		Reason             string      `json:"reason"`
		Confirm            bool        `json:"confirm"`
		// AcknowledgeIdentityChange：改包名或 scheme 时必须显式带上。见下面的说明。
		AcknowledgeIdentityChange bool `json:"acknowledgeIdentityChange"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "repoDirectory, expectedVersion, reason and confirm=true are required")
		return
	}
	directory := strings.TrimSpace(body.RepoDirectory)
	// 这个值会被代理拼进文件路径。放开一点点就等于给一条"跳出 tenants/ 目录"的路。
	if !repoDirectoryPattern.MatchString(directory) || strings.Contains(directory, "..") {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "repoDirectory must be a plain directory name under tenants/")
		return
	}
	if err := body.Identity.validate(); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_APP_IDENTITY", err.Error())
		return
	}
	googleServices := strings.TrimSpace(body.GoogleServicesJSON)
	if googleServices != "" {
		decoded, err := base64.StdEncoding.DecodeString(googleServices)
		if err != nil || !json.Valid(decoded) {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "googleServicesJson must be base64-encoded JSON")
			return
		}
		if len(decoded) > 256*1024 {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "googleServicesJson is too large")
			return
		}
	}
	value, _ := json.Marshal(buildConfig{
		RepoDirectory:      directory,
		DefaultGitRef:      buildGitRef,
		GoogleServicesJSON: googleServices,
		Identity:           body.Identity,
	})
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	defer tx.Rollback()
	var current int
	err = tx.QueryRowContext(c.Request.Context(), `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenantID(c), buildConfigKey).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	if current != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	// 改包名或 scheme 不是改配置，是换一个 App：Android 按「包名 + 签名证书」认
	// 身份，装着旧包的设备升不上去，只能卸载重装——direct 分发下没有商店替我们
	// 处理这件事。所以要显式带 acknowledgeIdentityChange，不给它一个默认值。
	previous, _, err := s.buildConfigFor(c.Request.Context(), tenantID(c), directory)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	changed := identityBreakingChanges(previous.Identity, body.Identity)
	if len(changed) > 0 && !body.AcknowledgeIdentityChange {
		problem(c, http.StatusConflict, "APP_IDENTITY_CHANGE",
			"Changing "+strings.Join(changed, " and ")+" makes this a different app; existing installs cannot upgrade into it. Resend with acknowledgeIdentityChange=true.")
		return
	}
	var result sql.Result
	newVersion := current + 1
	if current == 0 {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), buildConfigKey, value, actor(c), now, tenantID(c), buildConfigKey)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, tenantID(c), buildConfigKey, current)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_CONFIG", "Build configuration changed; refresh and retry")
		return
	}
	event := newAudit(tenantID(c), actor(c), "build_config_update", "app-config", buildConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{
			"repoDirectory": directory, "gitRef": buildGitRef,
			"googleServicesConfigured": googleServices != "",
			"scheme":                   body.Identity.Scheme,
			// 身份真的变了才记，事后翻审计时这一条要显眼
			"identityBreakingChanges": changed,
			"databaseVersion":         newVersion,
		})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"repoDirectory":            directory,
		"defaultGitRef":            buildGitRef,
		"googleServicesConfigured": googleServices != "",
		"identity": gin.H{
			"appName":             body.Identity.AppName,
			"scheme":              body.Identity.Scheme,
			"apiBaseUrl":          body.Identity.APIBaseURL,
			"iconBackgroundColor": body.Identity.IconBackgroundColor,
		},
		"identityConfigured": true,
		"version":            newVersion,
	})
}

// identityBreakingChanges 只列真正会让已装设备升不上去、或者会改变这个 App 认领
// 什么的字段。appName 改了不算——那只是显示名。
// 包名变更不在这里判：它归发布身份管，而真正的闸在排队那一刻——queueBuild 会拿
// 要打的包和**正在分发**的那一版对一遍，无论是谁在哪个页面改的都拦得住。
func identityBreakingChanges(before, after appIdentity) []string {
	var changed []string
	// scheme 决定这个 App 认领哪些深链。改了它，已经发出去的链接会打不开
	if b := strings.TrimSpace(before.Scheme); b != "" && b != strings.TrimSpace(after.Scheme) {
		changed = append(changed, "scheme")
	}
	return changed
}

func (s *server) tenantSlug(ctx context.Context, tenant string) (string, error) {
	var slug string
	err := s.db.QueryRowContext(ctx, `SELECT slug FROM tenants WHERE id=? LIMIT 1`, tenant).Scan(&slug)
	return slug, err
}
