package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	ReleaseNotes   []byte
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

const buildJobColumns = `id,tenant_id,platform,git_ref,commit_sha,version,build_number,status,claimed_by,claimed_at,heartbeat_at,release_id,artifact_sha256,log_tail,failure_reason,reason,release_notes,created_by,created_at,updated_at`

func scanBuildJob(row interface{ Scan(...any) error }) (buildJob, error) {
	var j buildJob
	err := row.Scan(&j.ID, &j.TenantID, &j.Platform, &j.GitRef, &j.CommitSHA, &j.Version, &j.BuildNumber,
		&j.Status, &j.ClaimedBy, &j.ClaimedAt, &j.HeartbeatAt, &j.ReleaseID, &j.ArtifactSHA256, &j.LogTail,
		&j.FailureReason, &j.Reason, &j.ReleaseNotes, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt)
	return j, err
}

func buildJobView(j buildJob) map[string]any {
	// 初值是空切片而不是 nil：nil 的 []string 序列化出来是 null，不是 []。刚排进
	// 队列的任务还没有任何日志，于是新建任务的那个响应里 logTail 是 null——控制台
	// 按契约（数组）解，整个响应校验失败，界面上显示"排队失败"，而任务其实已经建好
	// 并且打包机已经开始跑了。这种谎最贵：人会以为没排上，再排一次，第二次才撞上
	// build 号不递增。releaseNotes 那边一直是对的（初值就是空 map），这里漏了。
	tail := []string{}
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
		"releaseNotes":   buildJobReleaseNotes(j),
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

// buildFloor 是"下一个包必须越过的线"：版本号和 build 号都要严格大于它。
type buildFloor struct {
	Version     string // 已用掉的最高版本号；一个都没有时为空
	BuildNumber int    // 已用掉的最大 build 号；一个都没有时为 0
}

// next 返回照着这条线该填的下一组值。
//
// 第一个包给 1.0.0/1；之后版本号进一位修订、build 号加一。发版想跳小版本或大版本
// 是常事，所以这只是**默认值**，控制台上仍然可以改——这里只负责让"下一个"不必靠人
// 去翻上一次发了什么。
func (f buildFloor) next() (string, int) {
	if f.Version == "" && f.BuildNumber == 0 {
		return "1.0.0", 1
	}
	return nextPatchVersion(f.Version), f.BuildNumber + 1
}

func nextPatchVersion(version string) string {
	parts := strings.Split(strings.TrimSpace(version), ".")
	if len(parts) != 3 {
		return "1.0.0"
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "1.0.0"
	}
	return parts[0] + "." + parts[1] + "." + strconv.Itoa(patch+1)
}

// buildFloorFor 同时算出版本号和 build 号的下限。
//
// **两张表都要看**：已经入库的发布（app_releases），加上排着队还没落地的任务
// （build_jobs，除掉取消和失败的——那些没有产物，号根本没被用掉，"改一行用同一个号
// 重来"是最常见的那条路径）。
//
// 只看发布表的后果不一样但都很实：build 号那一侧是两个人各排一个 34，装到设备上哪个
// 赢取决于谁后装；版本号那一侧是连排两个任务拿到同一个版本号，第二个要等六分钟编译完
// 才在上传那一刻被拒。
//
// 取最近 50 条再在 Go 里比：版本号是 semver，SQL 的字符串序会把 1.3.9 排在 1.3.10
// 后面。build 号单调递增，最高的版本号不可能落在这 50 条之外。
func (s *server) buildFloorFor(ctx context.Context, tenant, platform string) (buildFloor, error) {
	var floor buildFloor
	rows, err := s.db.QueryContext(ctx, `
		(SELECT version,build_number FROM app_releases WHERE tenant_id=? AND platform=? ORDER BY build_number DESC LIMIT 50)
		UNION ALL
		(SELECT version,build_number FROM build_jobs WHERE tenant_id=? AND platform=? AND status NOT IN ('canceled','failed') ORDER BY build_number DESC LIMIT 50)`,
		tenant, platform, tenant, platform)
	if err != nil {
		return floor, err
	}
	defer rows.Close()
	for rows.Next() {
		var version sql.NullString
		var number sql.NullInt64
		if err := rows.Scan(&version, &number); err != nil {
			return floor, err
		}
		if number.Valid && int(number.Int64) > floor.BuildNumber {
			floor.BuildNumber = int(number.Int64)
		}
		candidate := strings.TrimSpace(version.String)
		if !semverPattern.MatchString(candidate) {
			continue
		}
		if floor.Version == "" || compareVersion(candidate, floor.Version) > 0 {
			floor.Version = candidate
		}
	}
	return floor, rows.Err()
}

type buildJobCreate struct {
	Platform    string `json:"platform"`
	GitRef      string `json:"gitRef"`
	Version     string `json:"version"`
	BuildNumber int    `json:"buildNumber"`
	// ReleaseNotes 跟着任务走：发布记录由代理创建，而记录建好之后没有改说明的
	// 接口——2026-09-11 的 1.3.9 就是带着空说明发出去的。
	ReleaseNotes map[string]any `json:"releaseNotes"`
	Reason       string         `json:"reason"`
	Confirm      bool           `json:"confirm"`
	// AcknowledgeIdentityChange：这次构建会改变包名或签名指纹时必须显式带上。
	AcknowledgeIdentityChange bool `json:"acknowledgeIdentityChange"`
}

// activeReleaseIdentity 取该平台正在分发那一版的包名与签名指纹，用来和这次要打的
// 包比对。没有 active 版本（新租户）就返回空，比对自然跳过。
func (s *server) activeReleaseIdentity(ctx context.Context, tenant, platform string) (string, string, error) {
	var raw []byte
	// 列名是 file_metadata。app_releases 上叫这个，ota_releases 上才叫
	// object_metadata——写错了的表现是排队直接 500，而且只在"该租户已经有 active
	// 版本"时才触发，新租户一路顺畅，所以很容易漏掉
	err := s.db.QueryRowContext(ctx,
		`SELECT file_metadata FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`,
		tenant, platform).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	pkg, _ := storedMetadataString(raw, "packageName")
	signer, _ := storedMetadataString(raw, "signerSha256")
	return pkg, signer, nil
}

// buildJobReleaseNotes 读出任务上的发布说明；没填就是空对象，不是 null——
// 前端按对象渲染，null 会多一处判空。
func buildJobReleaseNotes(j buildJob) map[string][]string {
	notes := map[string][]string{}
	if len(j.ReleaseNotes) > 0 {
		_ = json.Unmarshal(j.ReleaseNotes, &notes)
	}
	return notes
}

func (s *server) createBuildJob(c *gin.Context) {
	var body buildJobCreate
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "platform, gitRef, version, buildNumber, reason and confirm=true are required")
		return
	}
	platform := strings.ToLower(strings.TrimSpace(body.Platform))
	// 分支固定 main，请求里带什么都不看。能选分支就等于能从任意分支出一个用生产
	// 签名密钥签的包，而那个包和正式版在设备上无法区分。
	gitRef := buildGitRef
	version := strings.TrimSpace(body.Version)
	reason := strings.TrimSpace(body.Reason)
	if !body.Confirm || (platform != "android" && platform != "ios") ||
		!semverPattern.MatchString(version) || body.BuildNumber < 1 || len(reason) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "platform must be android or ios, version must be semver, buildNumber must be positive, reason and confirm=true are required")
		return
	}
	// 与人工发布用同一套校验：两边写进 app_releases 的形状必须一样
	notes, notesCode, notesDetail := normalizeReleaseNotes(body.ReleaseNotes)
	if notesCode != "" {
		problem(c, http.StatusUnprocessableEntity, notesCode, notesDetail)
		return
	}
	encodedNotes, _ := json.Marshal(notes)

	floor, err := s.buildFloorFor(c.Request.Context(), tenantID(c), platform)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to inspect existing build numbers")
		return
	}
	// 严格递增。装到设备上的 APK 靠 versionCode 决定谁能覆盖谁，重号意味着"哪个赢"
	// 取决于谁后装——这不是一个应该留给运气的问题。
	if body.BuildNumber <= floor.BuildNumber {
		problem(c, http.StatusConflict, "BUILD_NUMBER_NOT_INCREASING",
			fmt.Sprintf("buildNumber must be greater than %d, the highest already used for %s", floor.BuildNumber, platform))
		return
	}
	// 版本号也要递增，而且**必须在这里就查**。入库那一侧
	// （createReleaseFromArtifact 的 RELEASE_VERSION_NOT_INCREASING）要求版本和
	// build 号双双大于上一条发布，这里却只看 build 号——于是"1.3.12 build 42"能排
	// 进队列、能占住机器、能编译出一个签好名的 APK，最后在上传完成的那一刻被拒。
	// 2026-09-12 实测：六分钟的构建白跑，产物随 worktree 一起删掉，任务停在 failed。
	// 两道闸的判据不一样，靠后的那道就成了"先干完活再告诉你不行"。
	if floor.Version != "" && compareVersion(version, floor.Version) <= 0 {
		problem(c, http.StatusConflict, "BUILD_VERSION_NOT_INCREASING",
			fmt.Sprintf("version must be greater than %s, the highest already used for %s (the build would be rejected on upload)", floor.Version, platform))
		return
	}
	// 身份在排队这一刻就要能合成出来。留到代理认领才发现，运维已经等了一轮队列，
	// 而缺的往往是"签名密钥没配"这种在控制台点两下就好的事
	slug, err := s.tenantSlug(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to resolve this tenant")
		return
	}
	buildCfg, _, err := s.buildConfigFor(c.Request.Context(), tenantID(c), slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	manifest, err := s.tenantManifestFor(c.Request.Context(), tenantID(c), buildCfg, version, body.BuildNumber)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			problem(c, http.StatusConflict, "APP_IDENTITY_INCOMPLETE", missing.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "APP_IDENTITY_INVALID", "Unable to compose the tenant app identity")
		return
	}
	// 和正在分发的那一版比一遍。包名或签名指纹变了，装着旧版的设备升不上去——
	// 那是另一个 App，不是新版本，得有人明确说"我知道"
	activePackage, activeSigner, err := s.activeReleaseIdentity(c.Request.Context(), tenantID(c), platform)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to inspect the active release")
		return
	}
	if drift := tenantIdentityDrift(manifest, activePackage, activeSigner); len(drift) > 0 && !body.AcknowledgeIdentityChange {
		problem(c, http.StatusConflict, "APP_IDENTITY_DRIFT",
			"This build would change "+strings.Join(drift, "；")+"，装着当前版本的设备升不上去。确认要这么做就带 acknowledgeIdentityChange=true 重发。")
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
		`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,version,build_number,status,log_tail,reason,release_notes,created_by,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,'queued',JSON_ARRAY(),?,?,?,?,?)`,
		id, tenantID(c), platform, gitRef, version, body.BuildNumber, reason, encodedNotes, actor(c), now, now); err != nil {
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
		BuildNumber: body.BuildNumber, Status: "queued", Reason: reason, ReleaseNotes: encodedNotes,
		CreatedBy: actor(c), CreatedAt: now, UpdatedAt: now,
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
	// 下一个包该填什么，由服务端算——控制台不该自己去推。它要看的两张表里有一张
	// （build_jobs 里排队中的任务）根本不在列表这一页上，而且 semver 的比较规则
	// 客户端复制一份就会漂。默认值给出来，页面上仍然可以改。
	next := gin.H{}
	for _, platform := range []string{"android", "ios"} {
		floor, err := s.buildFloorFor(c.Request.Context(), tenantID(c), platform)
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
			return
		}
		version, buildNumber := floor.next()
		next[platform] = gin.H{"version": version, "buildNumber": buildNumber}
	}
	// 分支固定 main：排队时根本不看请求里带什么（见 createBuildJob）。告诉控制台
	// 这件事，省得它画一个改了也没用的输入框。
	c.JSON(http.StatusOK, gin.H{"items": items, "next": next, "gitRef": buildGitRef})
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
	view["googleServicesJson"] = nullableString(buildCfg.GoogleServicesJSON)
	// tenant.json 由服务端合成随任务下发，仓库里不再有这个文件。合成不出来就让
	// 这条任务当场失败：缺的是签名密钥或发布身份这类东西，硬打出来的包装上去也
	// 起不来，而那时候报的是"配置连接失败"，看不出根因（见 tenant_manifest.go）
	manifest, err := s.tenantManifestFor(c.Request.Context(), job.TenantID, buildCfg, job.Version, job.BuildNumber)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			s.markBuildJobFailed(c.Request.Context(), job.ID, missing.Error())
			problem(c, http.StatusConflict, "APP_IDENTITY_INCOMPLETE", missing.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "APP_IDENTITY_INVALID", "Unable to compose the tenant app identity")
		return
	}
	view["tenantFile"] = manifest
	// 签名密钥以**服务端打不开的盒子**下发。打包机本地持有封装口令，自己开。
	// 没配就留 null，代理会当场失败并说清楚缺什么。
	sealedKeystore, keyAlias, err := s.sealedBuildKeystoreFor(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration cannot be read")
		return
	}
	if len(sealedKeystore) == 0 {
		view["sealedKeystore"] = nil
		view["keyAlias"] = nil
	} else {
		view["sealedKeystore"] = sealedKeystore
		view["keyAlias"] = nullableString(keyAlias)
	}
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

// markBuildJobFailed 在没有代理上报的情况下判一条任务失败。认领时就发现缺配置的
// 任务必须落到 failed：留在 claimed 会被心跳超时慢慢回收，队列是跨租户的，一条
// 卡住的任务拖的是所有人。
func (s *server) markBuildJobFailed(ctx context.Context, id, reason string) {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE build_jobs SET status='failed',failure_reason=?,heartbeat_at=?,updated_at=? WHERE id=? AND status IN ('pending','claimed','running')`,
		reason, now, now, id); err != nil {
		slog.Error("unable to fail a build job with an incomplete tenant identity", "jobId", id, "error", err)
	}
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

// ---- 产物回传 ----
//
// 代理不自己拼一条入库路径，而是**复用人工上传的那条**：APK 身份解析、ETag 固定、
// 签名指纹比对、权限清单核对，一条都不少。复制一份出来迟早会漏掉其中一条，而漏掉
// 的那条正是门禁存在的理由。
//
// 做法是把任务的租户放进上下文，然后交给现成的处理函数。代理通道的身份是固定的
// `build-agent`，不采用它自报的机器名——自报身份任何持钥者都能随便写，写进审计
// 就成了攻击者可控的字段（与 x-admin-id 同一条教训）。哪台机器干的，看任务行的
// claimed_by。

const buildAgentActor = "build-agent"

// buildAgentJobScope 校验任务还在进行中，并把它的租户装进上下文。
func (s *server) buildAgentJobScope(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		job, err := s.loadBuildJob(c, "", c.Param("id"))
		if err != nil {
			return
		}
		if job.Status != "claimed" && job.Status != "running" {
			problem(c, http.StatusConflict, "BUILD_JOB_NOT_RUNNING", "This build is not claimed or running")
			return
		}
		c.Set("tenantId", job.TenantID)
		c.Set("actorId", buildAgentActor)
		c.Set("buildAgent", true)
		c.Set("buildJob", job)
		next(c)
	}
}

// buildAgentUploadsArtifact 告诉产物上传票据：回传地址要给代理通道的那一条，
// 不是管理端那条——代理没有管理端凭据。
func buildAgentUploadsArtifact(c *gin.Context) bool {
	_, ok := c.Get("buildAgent")
	return ok
}

// buildAgentReleaseFromArtifact 让代理用任务参数落一条发布记录。平台、版本、
// build 号一律取**任务行上的值**，不采信请求体——那三个字段决定产物身份，而任务
// 行上的那份是管理端排队时就定下、并且过了递增校验的。
func (s *server) buildAgentReleaseFromArtifact(c *gin.Context) {
	item, _ := c.Get("buildJob")
	job, ok := item.(buildJob)
	if !ok {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to read the build job")
		return
	}
	var body struct {
		ArtifactToken string `json:"artifactToken"`
		// SBOM 与产物一起传上来，同一张票据机制，不同的对象。代理生成不出来时
		// 整个任务就失败了，所以走到这里它一般是有值的——留空只为兼容手工重放。
		SBOMToken string `json:"sbomToken"`
	}
	if decode(c, &body) != nil || strings.TrimSpace(body.ArtifactToken) == "" {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE", "artifactToken is required")
		return
	}
	// 说明和平台、版本、build 号一样取任务行上的值：它在排队时就过了校验，
	// 而代理没有理由知道该写什么说明
	notes := map[string]any{}
	for language, lines := range buildJobReleaseNotes(job) {
		notes[language] = lines
	}
	payload, _ := json.Marshal(map[string]any{
		"artifactToken": body.ArtifactToken,
		"sbomToken":     body.SBOMToken,
		"platform":      job.Platform,
		"version":       job.Version,
		"buildNumber":   job.BuildNumber,
		"releaseNotes":  notes,
		"mandatory":     false,
	})
	c.Request.Body = io.NopCloser(bytes.NewReader(payload))
	c.Request.ContentLength = int64(len(payload))
	s.createReleaseFromArtifact(c)
}
