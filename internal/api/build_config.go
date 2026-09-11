package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
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
	// DefaultGitRef 只是管理端新建构建时的默认值，不参与任何校验。
	DefaultGitRef string `json:"defaultGitRef"`
}

func (s *server) buildConfigFor(ctx context.Context, tenant, fallbackSlug string) (buildConfig, int, error) {
	var raw []byte
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, buildConfigKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		// 没配过就退回 slug——两边名字恰好一样的租户不必为此专门配一条
		return buildConfig{RepoDirectory: fallbackSlug, DefaultGitRef: "main"}, 0, nil
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
	if strings.TrimSpace(cfg.DefaultGitRef) == "" {
		cfg.DefaultGitRef = "main"
	}
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
		"tenantSlug":    slug,
		"version":       version,
	})
}

func (s *server) saveBuildConfig(c *gin.Context) {
	var body struct {
		RepoDirectory   string `json:"repoDirectory"`
		DefaultGitRef   string `json:"defaultGitRef"`
		ExpectedVersion int    `json:"expectedVersion"`
		Reason          string `json:"reason"`
		Confirm         bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "repoDirectory, expectedVersion, reason and confirm=true are required")
		return
	}
	directory := strings.TrimSpace(body.RepoDirectory)
	gitRef := strings.TrimSpace(body.DefaultGitRef)
	if gitRef == "" {
		gitRef = "main"
	}
	// 这个值会被代理拼进文件路径。放开一点点就等于给一条"跳出 tenants/ 目录"的路。
	if !repoDirectoryPattern.MatchString(directory) || strings.Contains(directory, "..") {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "repoDirectory must be a plain directory name under tenants/")
		return
	}
	if len(gitRef) > 200 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CONFIG", "defaultGitRef is too long")
		return
	}
	value, _ := json.Marshal(buildConfig{RepoDirectory: directory, DefaultGitRef: gitRef})
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
		map[string]any{"repoDirectory": directory, "defaultGitRef": gitRef, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_SAVE_FAILED", "Unable to save the build configuration")
		return
	}
	c.JSON(http.StatusOK, gin.H{"repoDirectory": directory, "defaultGitRef": gitRef, "version": newVersion})
}

func (s *server) tenantSlug(ctx context.Context, tenant string) (string, error) {
	var slug string
	err := s.db.QueryRowContext(ctx, `SELECT slug FROM tenants WHERE id=? LIMIT 1`, tenant).Scan(&slug)
	return slug, err
}
