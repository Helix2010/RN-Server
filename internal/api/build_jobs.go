package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 打包服务（设计 docs/design/build-service-2026-09-11.md）。
//
// 这里只做一件事：把"为租户 X 在提交 Y 上出一个包"这个请求排进队列，让打包机来认领。
//
// ## 任务里没有命令，这是有意的
//
// 原始提案是"服务端直接调用打包机的命令进行打包"。不能那么做：让 wallet 后端能在
// 打包机上执行任意命令，等于它的任何一个 RCE 都拿到了那台握着 Android keystore 的
// 机器的执行权。而 keystore 泄露在 direct 分发下没有补救办法——Android 用
// （包名 + 签名证书）认身份，对方能签一个同签名的 APK 在用户设备上原地覆盖安装、
// 数据目录（含钱包）完整保留，补救只能换包名，也就是让每个用户手动卸载重装。
//
// 所以接口的语义被压到最窄：任务带的是参数（租户、提交、版本号），不是 shell。
// 怎么构建由打包机自己决定，密钥由它自己持有，服务端知道的是产物指纹。
//
// ## 什么能从数据库来，什么不能
//
//   - OTA 签名证书：能，而且应该。它本来就在 app_configs，是公开材料。代理自己去取，
//     "包里的证书"与"服务端当前签名用的密钥"就永远一致——今天这个一致性靠人拷文件，
//     而不一致的症状是所有设备静默停在内置 bundle。
//   - version / buildNumber：能。它们是发布协调数据不是身份，放进来还顺手让服务端
//     能管 buildNumber 单调递增——今天这件事没人管。
//   - applicationId / 包名 / 权限清单：不能。它们定义产物**是什么**，必须来自提交。
//     服务端能在构建时改它们，等于一次数据库注入就产出一个身份不同、却用你的密钥
//     签名的 APK。

const buildJobLogTailMax = 200

var semverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

type buildJob struct {
	ID             string
	TenantID       string
	Platform       string
	GitRef         string
	CommitSHA      sql.NullString
	Version        string
	BuildNumber    int
	Status         string
	ClaimedBy      sql.NullString
	ClaimedAt      sql.NullTime
	HeartbeatAt    sql.NullTime
	ReleaseID      sql.NullString
	ArtifactSHA256 sql.NullString
	LogTail        []byte
	FailureReason  sql.NullString
	Reason         string
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const buildJobColumns = `id,tenant_id,platform,git_ref,commit_sha,version,build_number,status,claimed_by,claimed_at,heartbeat_at,release_id,artifact_sha256,log_tail,failure_reason,reason,created_by,created_at,updated_at`

func scanBuildJob(row interface{ Scan(...any) error }) (buildJob, error) {
	var j buildJob
	err := row.Scan(&j.ID, &j.TenantID, &j.Platform, &j.GitRef, &j.CommitSHA, &j.Version, &j.BuildNumber,
		&j.Status, &j.ClaimedBy, &j.ClaimedAt, &j.HeartbeatAt, &j.ReleaseID, &j.ArtifactSHA256, &j.LogTail,
		&j.FailureReason, &j.Reason, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}

func buildJobView(j buildJob) map[string]any {
	var tail []string
	if len(j.LogTail) > 0 {
		_ = json.Unmarshal(j.LogTail, &tail)
	}
	return map[string]any{
		"id":             j.ID,
		"platform":       j.Platform,
		"gitRef":         j.GitRef,
		"commitSha":      nullableString(j.CommitSHA.String),
		"version":        j.Version,
		"buildNumber":    j.BuildNumber,
		"status":         j.Status,
		"claimedBy":      nullableString(j.ClaimedBy.String),
		"claimedAt":      nullableTime(j.ClaimedAt.Time),
		"heartbeatAt":    nullableTime(j.HeartbeatAt.Time),
		"releaseId":      nullableString(j.ReleaseID.String),
		"artifactSha256": nullableString(j.ArtifactSHA256.String),
		"logTail":        tail,
		"failureReason":  nullableString(j.FailureReason.String),
		"reason":         j.Reason,
		"createdBy":      j.CreatedBy,
		"createdAt":      iso(j.CreatedAt),
		"updatedAt":      iso(j.UpdatedAt),
	}
}

// clampLogTail 只留尾部若干行。日志是代理送上来的，不设上限的话一次失败就能把这一行
// 撑到几十兆，而这张表是管理端列表要扫的。
func clampLogTail(lines []string) []byte {
	if len(lines) > buildJobLogTailMax {
		lines = lines[len(lines)-buildJobLogTailMax:]
	}
	for i, line := range lines {
		if len(line) > 2000 {
			lines[i] = line[:2000]
		}
	}
	if lines == nil {
		lines = []string{}
	}
	raw, _ := json.Marshal(lines)
	return raw
}

// nextBuildNumberFloor 返回这个租户这个平台已经用掉的最大 build 号。产物表和任务表
// 都要看：只看产物表的话，一个还在队列里的同号任务不会被发现，两个人各自排一个
// build 34，装到设备上哪个赢取决于谁后装。
func (s *server) nextBuildNumberFloor(c *gin.Context, tenant, platform string) (int, error) {
	var fromReleases, fromJobs sql.NullInt64
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT MAX(build_number) FROM app_releases WHERE tenant_id=? AND platform=?`, tenant, platform).Scan(&fromReleases); err != nil {
		return 0, err
	}
	if err := s.db.QueryRowContext(c.Request.Context(),
		// 失败与取消的任务不占号：失败的构建没有产物，那个号根本没被用掉，
		// 而"改一行再用同一个版本号重来"是最常见的那条路径
		`SELECT MAX(build_number) FROM build_jobs WHERE tenant_id=? AND platform=? AND status NOT IN ('canceled','failed')`, tenant, platform).Scan(&fromJobs); err != nil {
		return 0, err
	}
	floor := 0
	if fromReleases.Valid && int(fromReleases.Int64) > floor {
		floor = int(fromReleases.Int64)
	}
	if fromJobs.Valid && int(fromJobs.Int64) > floor {
		floor = int(fromJobs.Int64)
	}
	return floor, nil
}

type buildJobCreate struct {
	Platform    string `json:"platform"`
	GitRef      string `json:"gitRef"`
	Version     string `json:"version"`
	BuildNumber int    `json:"buildNumber"`
	Reason      string `json:"reason"`
	Confirm     bool   `json:"confirm"`
}

func (s *server) createBuildJob(c *gin.Context) {
	var body buildJobCreate
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "platform, gitRef, version, buildNumber, reason and confirm=true are required")
		return
	}
	platform := strings.ToLower(strings.TrimSpace(body.Platform))
	gitRef := strings.TrimSpace(body.GitRef)
	version := strings.TrimSpace(body.Version)
	reason := strings.TrimSpace(body.Reason)
	if !body.Confirm || (platform != "android" && platform != "ios") || gitRef == "" || len(gitRef) > 200 ||
		!semverPattern.MatchString(version) || body.BuildNumber < 1 || len(reason) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "platform must be android or ios, version must be semver, buildNumber must be positive, reason and confirm=true are required")
		return
	}
	floor, err := s.nextBuildNumberFloor(c, tenantID(c), platform)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to inspect existing build numbers")
		return
	}
	// 严格递增。装到设备上的 APK 靠 versionCode 决定谁能覆盖谁，重号意味着"哪个赢"
	// 取决于谁后装——这不是一个应该留给运气的问题。
	if body.BuildNumber <= floor {
		problem(c, http.StatusConflict, "BUILD_NUMBER_NOT_INCREASING",
			fmt.Sprintf("buildNumber must be greater than %d, the highest already used for %s", floor, platform))
		return
	}
	now := time.Now().UTC()
	id := "bld_" + randomID(16)
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(c.Request.Context(),
		`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,version,build_number,status,log_tail,reason,created_by,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,'queued',JSON_ARRAY(),?,?,?,?)`,
		id, tenantID(c), platform, gitRef, version, body.BuildNumber, reason, actor(c), now, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	event := newAudit(tenantID(c), actor(c), "build_job_create", "build-job", id, reason, requestID(c),
		map[string]any{"platform": platform, "gitRef": gitRef, "version": version, "buildNumber": body.BuildNumber})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	c.JSON(http.StatusCreated, buildJobView(buildJob{
		ID: id, TenantID: tenantID(c), Platform: platform, GitRef: gitRef, Version: version,
		BuildNumber: body.BuildNumber, Status: "queued", Reason: reason, CreatedBy: actor(c),
		CreatedAt: now, UpdatedAt: now,
	}))
}

func (s *server) listBuildJobs(c *gin.Context) {
	limit := 50
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT `+buildJobColumns+` FROM build_jobs WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?`, tenantID(c), limit)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		job, err := scanBuildJob(rows)
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
			return
		}
		items = append(items, buildJobView(job))
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *server) buildJobDetail(c *gin.Context) {
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, buildJobView(job))
}

// loadBuildJob 读一条任务并在失败时自己写好响应。tenant 为空表示不按租户过滤——
// 只有代理通道这么用，它的任务 id 是服务端发的，而且它本来就跨租户工作。
func (s *server) loadBuildJob(c *gin.Context, tenant, id string) (buildJob, error) {
	query := `SELECT ` + buildJobColumns + ` FROM build_jobs WHERE id=?`
	args := []any{strings.TrimSpace(id)}
	if tenant != "" {
		query += ` AND tenant_id=?`
		args = append(args, tenant)
	}
	job, err := scanBuildJob(s.db.QueryRowContext(c.Request.Context(), query+` LIMIT 1`, args...))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "BUILD_JOB_NOT_FOUND", "Build job not found")
		return job, err
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to load the build")
		return job, err
	}
	return job, nil
}

func (s *server) cancelBuildJob(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	// 只取消还没开工的。running 的任务取消了也停不下打包机上那个进程，状态会骗人。
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='canceled',failure_reason=?,updated_at=? WHERE id=? AND tenant_id=? AND status IN ('queued','claimed')`,
		strings.TrimSpace(body.Reason), now, c.Param("id"), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to cancel the build")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_CANCELABLE", "Only queued or claimed builds can be canceled")
		return
	}
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, buildJobView(job))
}

// ---- 打包机代理通道 ----

// buildAgentAuth 是与管理端**完全分开**的一条凭据。不复用 x-admin-key：管理端密钥
// 能改配置、能发版、能读安装明细，而打包机只需要认领任务和回报结果。一台构建机被
// 拿下时，拿到的应该只是构建队列，不是整个管理面。
func (s *server) buildAgentAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("x-build-agent-token")
		if s.cfg.BuildAgentToken == "" || !constantEqual(token, s.cfg.BuildAgentToken) {
			problem(c, http.StatusUnauthorized, "BUILD_AGENT_AUTH_REQUIRED", "Build agent authentication required")
			c.Abort()
			return
		}
		c.Next()
	}
}

// claimBuildJob 原子地领走一条排队中的任务。用 FOR UPDATE SKIP LOCKED：两台构建机
// 同时轮询时，第二台跳过被锁住的行去拿下一条，而不是等锁或者拿到同一条。
func (s *server) claimBuildJob(c *gin.Context) {
	var body struct {
		Agent     string   `json:"agent"`
		Platforms []string `json:"platforms"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.Agent) == "" {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "agent is required")
		return
	}
	platforms := []string{}
	for _, p := range body.Platforms {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "android" || p == "ios" {
			platforms = append(platforms, p)
		}
	}
	if len(platforms) == 0 {
		platforms = []string{"android", "ios"}
	}
	agent := strings.TrimSpace(body.Agent)
	if len(agent) > 120 {
		agent = agent[:120]
	}

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	defer tx.Rollback()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(platforms)), ",")
	args := []any{}
	for _, p := range platforms {
		args = append(args, p)
	}
	var id string
	err = tx.QueryRowContext(c.Request.Context(),
		`SELECT id FROM build_jobs WHERE status='queued' AND platform IN (`+placeholders+`) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED`, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		c.Status(http.StatusNoContent)
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='claimed',claimed_by=?,claimed_at=?,heartbeat_at=?,updated_at=? WHERE id=?`,
		agent, now, now, now, id); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
		return
	}
	job, err := scanBuildJob(tx.QueryRowContext(c.Request.Context(), `SELECT `+buildJobColumns+` FROM build_jobs WHERE id=? LIMIT 1`, id))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	// 解析不出租户（租户被删了、任务是脏数据）时不能把这条任务留在队列里报 500：
	// 认领总是取最早那条，一条解析不了的任务会把**整个队列**堵死，而队列是跨租户的。
	// 直接判它失败，让代理立刻去拿下一条。
	var slug string
	switch err := tx.QueryRowContext(c.Request.Context(), `SELECT slug FROM tenants WHERE id=? LIMIT 1`, job.TenantID).Scan(&slug); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(c.Request.Context(),
			`UPDATE build_jobs SET status='failed',failure_reason=?,updated_at=? WHERE id=?`,
			"tenant no longer exists", now, id); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
			return
		}
		if err := tx.Commit(); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
			return
		}
		c.Status(http.StatusNoContent)
		return
	case err != nil:
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to resolve the tenant of this build")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
		return
	}

	// 证书随任务一起下发：代理不该去猜哪张证书该编进包里。这样"包里的证书"与
	// "服务端当前签名用的密钥"由同一条记录保证一致——今天这个一致性靠人拷文件，
	// 而不一致的症状是所有设备静默停在内置 bundle。私钥当然不下发。
	// 仓库里的租户目录名与本平台 slug 是两套命名，必须显式配置：线上 slug 是
	// Predict.Kim，而仓库里的目录叫 anyfun，拿 slug 去找文件必然找不到。
	buildCfg, _, err := s.buildConfigFor(c.Request.Context(), job.TenantID, slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	view := buildJobView(job)
	view["tenantSlug"] = slug
	view["tenantDirectory"] = buildCfg.RepoDirectory
	record, err := s.otaSigningRecord(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_CONFIG_INVALID", "Stored ota.signing configuration is invalid")
		return
	}
	if record == nil {
		view["otaCertificatePem"] = nil
		view["otaCertificateSha256"] = nil
	} else {
		fingerprint, _ := certificateFingerprint(record.Value.Certificate)
		view["otaCertificatePem"] = nullableString(record.Value.Certificate)
		view["otaCertificateSha256"] = nullableString(fingerprint)
	}
	c.JSON(http.StatusOK, view)
}

func (s *server) buildJobHeartbeat(c *gin.Context) {
	var body struct {
		LogTail []string `json:"logTail"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_PROGRESS", "logTail must be an array of strings")
		return
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='running',heartbeat_at=?,log_tail=?,updated_at=? WHERE id=? AND status IN ('claimed','running')`,
		now, clampLogTail(body.LogTail), now, c.Param("id"))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record build progress")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_RUNNING", "This build is not claimed or running")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *server) completeBuildJob(c *gin.Context) {
	var body struct {
		CommitSHA      string   `json:"commitSha"`
		ArtifactSHA256 string   `json:"artifactSha256"`
		ReleaseID      string   `json:"releaseId"`
		LogTail        []string `json:"logTail"`
	}
	commit := ""
	digest := ""
	if decode(c, &body) == nil {
		commit = strings.ToLower(strings.TrimSpace(body.CommitSHA))
		digest = strings.ToLower(strings.TrimSpace(body.ArtifactSHA256))
	}
	if !isHex(commit, 40, 64) || !isHex(digest, 64, 64) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha and artifactSha256 must be hex digests")
		return
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='succeeded',commit_sha=?,artifact_sha256=?,release_id=?,log_tail=?,heartbeat_at=?,updated_at=? WHERE id=? AND status IN ('claimed','running')`,
		commit, digest, sqlNullableString(strings.TrimSpace(body.ReleaseID)), clampLogTail(body.LogTail), now, now, c.Param("id"))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the build result")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_RUNNING", "This build is not claimed or running")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *server) failBuildJob(c *gin.Context) {
	var body struct {
		FailureReason string   `json:"failureReason"`
		CommitSHA     string   `json:"commitSha"`
		LogTail       []string `json:"logTail"`
	}
	reason := ""
	commit := ""
	if decode(c, &body) == nil {
		reason = strings.TrimSpace(body.FailureReason)
		commit = strings.ToLower(strings.TrimSpace(body.CommitSHA))
	}
	if reason == "" {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "failureReason is required")
		return
	}
	if len(reason) > 500 {
		reason = reason[:500]
	}
	// 失败的构建也要记下它到底检出了哪个提交——没有这一条，排查只能靠猜分支当时
	// 指向哪里。解析提交之前就失败的任务没有这个值，那时保留 NULL。
	if !isHex(commit, 40, 64) {
		commit = ""
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='failed',failure_reason=?,commit_sha=COALESCE(?,commit_sha),log_tail=?,heartbeat_at=?,updated_at=? WHERE id=? AND status IN ('claimed','running')`,
		reason, sqlNullableString(commit), clampLogTail(body.LogTail), now, now, c.Param("id"))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the build failure")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_RUNNING", "This build is not claimed or running")
		return
	}
	c.Status(http.StatusNoContent)
}

func isHex(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func sqlNullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
