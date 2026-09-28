package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/gin-gonic/gin"
)

// 构建机通道 /v1/build-agent（设计 android-signing-gate-2026-09-16「接口」、约定 5.2）。
//
// 构建机执行第三方代码，按不可信处理。它拿到的只有任务参数、公开的 OTA 证书与图标，
// **没有任何签名密钥密文**；交付的是未签名包、SBOM 与出处签名，任务转为 built，由签名闸
// 接着签。它的每个上报都带认领编号（x-build-attempt），与任务行的 attempt、
// claimed_machine_id 对不上一律 409 BUILD_ATTEMPT_STALE：任务被回收重排之后，挂掉又回来的
// 那台机器不能再改这条任务。

const (
	buildAttemptHeader = "x-build-attempt"
	// maxBuildAttempts：apk 任务最多被认领 3 次（重排 2 次），回收时到了就判失败
	maxBuildAttempts = 3
	// SBOM 实测约 2.3 MB，超过 1 MiB 的 JSON 请求体上限，所以走流式上传
	buildSBOMMaxBytes     = 16 << 20
	unsignedAPKObjectName = "app-release-unsigned.apk"
	sbomObjectName        = "sbom.cdx.json"
	octetStream           = "application/octet-stream"
)

var (
	commitSHAPattern         = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	nativeFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// attemptFromHeader 读认领编号头。缺失或不是正整数返回 false。
func attemptFromHeader(c *gin.Context, header string) (int, bool) {
	raw := strings.TrimSpace(c.GetHeader(header))
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || strconv.Itoa(value) != raw {
		return 0, false
	}
	return value, true
}

// buildJobObjectKey 是构建与签名产物的对象键：<prefix>/tenants/<tenant>/build-jobs/<job>/<segment>/<name>。
// segment 是 a<attempt>/<随机段>（构建机交付）或 s<signAttempt>/<随机段>（签名闸交回），见
// deliveryObjectSegment：键里带编号，过期的认领写不到新认领的键上；每次上传一个新键，迟到的
// 上传碰不到已被引用的对象。
func buildJobObjectKey(prefix, tenant, jobID, segment, name string) string {
	return strings.TrimLeft(path.Join(prefix, "tenants", tenant, "build-jobs", jobID, segment, name), "/")
}

// ---- 认领 ----

// claimBuildJob 原子地领走一条排队中的任务。
//
// 每台构建机同时只派一条：本机已有 claimed/running 的任务时回 409，带上那条任务的 id 与
// 编号，构建机据此决定续报还是放弃。检查与认领在同一把按机器的命名锁里做，同一个令牌
// 并发来两次认领也只会拿到一条。
func (s *server) claimBuildJob(c *gin.Context) {
	machine, ok := machineFromContext(c)
	if !ok {
		problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
		return
	}
	var body struct {
		Platforms []string `json:"platforms"`
		Kinds     []string `json:"kinds"`
		// 以下四项是机器的自报（设计 ios-mac-builders-home-network-2026-09-18 §5.2、§5.4）。
		// 旧版代理不带，零值即"没报"——请求体是 DisallowUnknownFields 严格解析，所以
		// **服务端要先于新代理上线**，反过来新代理先上会被 400 顶回去。
		AgentCommit string            `json:"agentCommit"`
		OS          string            `json:"os"`
		AppleTeams  []appleTeamReport `json:"appleTeams"`
		FreeGb      int64             `json:"freeGb"`
		// Paused：这台机器现在不领活（磁盘不够等），但仍然来报到。它照样记一行在线，
		// 只是不派任务——让它干脆别来问的话，控制台只能看到"离线"，而"磁盘满了"和
		// "关机了"要做的处理完全不同
		Paused       bool   `json:"paused"`
		PausedReason string `json:"pausedReason"`
		// UpgradeError：上一次自升级失败的原因。升级是 root 的那个程序做的，它失败时
		// 代理还在跑旧版，控制台只会看到"版本追不上审批值"——不报上来就只能上机器看日志
		UpgradeError string `json:"upgradeError"`
		// Capabilities：这台机器的构建机程序会做哪些"新"事情（例如 ios-ipa-delivery：能把 .ipa
		// 交回服务端）。服务端据此决定派不派需要它的任务；旧版代理不报
		Capabilities []string `json:"capabilities"`
		// TenantMaterial：按租户的签名材料自报（设计 ios-tenant-owned-signing-material-2026-09-25 §12.3）。
		// 只有收到过按租户清单的打包机才报；报了就只按 (租户, Team, bundle id) 派 iOS 任务
		TenantMaterial []tenantMaterialReport `json:"tenantMaterial"`
	}
	if decode(c, &body) != nil || len(body.Platforms) == 0 || len(body.Kinds) == 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "platforms (android, ios) and kinds (apk, ota) are required")
		return
	}
	for _, p := range body.Platforms {
		if p != buildPlatformAndroid && p != buildPlatformIOS {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "platforms must be android or ios")
			return
		}
	}
	for _, k := range body.Kinds {
		if k != jobKindAPK && k != jobKindOTA {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "kinds must be apk or ota")
			return
		}
	}
	if body.AgentCommit != "" && !commitSHAPattern.MatchString(body.AgentCommit) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "agentCommit must be a full commit sha")
		return
	}
	if body.OS != "" && body.OS != machineOSDarwin && body.OS != machineOSLinux {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "os must be darwin or linux")
		return
	}
	if body.FreeGb < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "freeGb must not be negative")
		return
	}
	teams, ok := normalizeAppleTeamReports(body.AppleTeams)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM",
			"appleTeams must carry 10-character Apple Team IDs with bundle ids and an optional RFC3339 expiresAt")
		return
	}
	capabilities, ok := normalizeMachineCapabilities(body.Capabilities)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM", "capabilities must be a short list of lowercase names")
		return
	}
	tenantMaterial, ok := normalizeTenantMaterialReports(body.TenantMaterial)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_CLAIM",
			"tenantMaterial must carry tenant ids, 10-character Apple Team IDs, bundle ids, a 40-character certificate sha1 and at most 8 problems")
		return
	}
	ctx := c.Request.Context()
	// 在 GET_LOCK 与事务**之外**、在"队列空回 204"提前返回**之前**记一次在线与自报盘点。
	// 认领这条路径上绝大多数请求都是空转（队列是空的），而"这台机器还活着、手上有这些
	// 材料"恰恰是那些空转唯一的产出；控制台据它显示"最近在线"与"这台缺哪个 Team"。
	freeGB := sql.NullInt64{Valid: body.FreeGb > 0, Int64: body.FreeGb}
	pausedReason := ""
	if body.Paused {
		pausedReason = sanitizeSignerText(body.PausedReason, machinePausedReasonMaxRunes)
		if pausedReason == "" {
			pausedReason = "paused by the machine"
		}
	}
	s.recordMachineLiveness(ctx, machineLiveness{
		MachineID: machine.ID, LastSeenAt: s.now(), AgentCommit: body.AgentCommit, OS: body.OS,
		// 记自报的平台，不是下面收窄之后的：收窄掉的恰恰是"它想干但干不了"，
		// 而那正是要在控制台上看见的东西
		Platforms: body.Platforms, Capabilities: capabilities, AppleTeams: teams, TenantMaterial: tenantMaterial,
		SigningExpiresAt: earliestSigningExpiry(teams), FreeGB: freeGB, PausedReason: pausedReason,
		UpgradeError: sanitizeSignerText(body.UpgradeError, machineUpgradeErrorMaxRunes),
	})
	// 版本闸在**选任务之前**（设计 ios-mac-builders-home-network-2026-09-18 §5.6）。
	//
	// 初稿是"认领响应里带上 approvedAgentCommit"，走不通：队列空时响应是 204 无正文，
	// 空闲的机器永远收不到；而收到的时候它已经领到任务了。改成这里直接 409、不派任务，
	// 升级于是总是发生在空闲的时候，手上正在跑的构建自然做完。
	//
	// 这不是安全边界——挡住"服务端被攻破后下发恶意程序"的是离线签名的清单与单调序号。
	if registry, err := s.machineRegistry(ctx); err == nil {
		if target := strings.TrimSpace(string(registry.ApprovedAgentCommit)); target != "" && body.AgentCommit != target {
			problemWith(c, http.StatusConflict, "AGENT_UPGRADE_REQUIRED",
				"这台机器上的构建机程序不是平台批准的那一版，先升级再来领任务",
				gin.H{"agentCommit": target, "reported": nullableString(body.AgentCommit)})
			return
		}
	}
	// 暂停的机器在这里就回去了：登记了在线、登记了原因，但不派活
	if body.Paused {
		c.Status(http.StatusNoContent)
		return
	}

	// 自报的平台只能**收窄**登记里的能力，不能扩张它：一台没装 Xcode 的 Linux 机器
	// 报了 ios，领走的 iOS 任务只会失败、退回排队、再被它领走——一个自愈不了的循环，
	// 而队列是跨租户的。登记是平台管理员维护的，自报只是"我这次想干什么"。
	capable := machine.buildPlatforms()
	args := []any{}
	claimed := []string{}
	// 可签对：按租户自报的机器是 "<租户>:TEAM.bundle"，只算这个租户自己交、Mac 核对通过的材料；旧机器是
	// "TEAM.bundle"（同 Team 的租户共用）。下面 SQL 里拼的那一列跟着换（signingKey）
	pairs, uploadPairs := signingPairs(teams), uploadablePairs(teams)
	signingKey := `CONCAT(UPPER(JSON_UNQUOTE(JSON_EXTRACT(c.config_value,'$.appleTeamId'))),'.',JSON_UNQUOTE(JSON_EXTRACT(c.config_value,'$.bundleId')))`
	if tenantMaterial != nil {
		pairs, uploadPairs = tenantSigningPairs(tenantMaterial), tenantUploadablePairs(tenantMaterial)
		signingKey = `CONCAT(c.tenant_id,':',UPPER(JSON_UNQUOTE(JSON_EXTRACT(c.config_value,'$.appleTeamId'))),'.',JSON_UNQUOTE(JSON_EXTRACT(c.config_value,'$.bundleId')))`
	}
	for _, p := range body.Platforms {
		if !containsString(capable, p) {
			continue
		}
		// iOS 还要再收窄一次：一台手上一个 Team 的签名材料都没有的 Mac 领走任何
		// iOS 任务都只会失败三次、烧掉一个 build 号。它不算"没登记"（登记没错，
		// 是材料没装），所以不报 409，安静地当作队列里没有它能干的活——控制台上
		// 它的 apple_teams 是空的，缺口一眼就看得见
		if p == buildPlatformIOS && len(pairs) == 0 {
			continue
		}
		claimed = append(claimed, p)
		args = append(args, p)
	}
	if len(claimed) == 0 {
		if containsString(body.Platforms, buildPlatformIOS) && containsString(capable, buildPlatformIOS) {
			c.Status(http.StatusNoContent)
			return
		}
		problemWith(c, http.StatusConflict, "MACHINE_PLATFORM_NOT_REGISTERED",
			"This machine is not registered to build any of the platforms it asked for; a platform admin changes that in the console",
			gin.H{"requested": body.Platforms, "registered": capable})
		return
	}
	platformPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(claimed)), ",")
	for _, k := range body.Kinds {
		args = append(args, k)
	}
	kindPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(body.Kinds)), ",")
	// 自报盘点摊平成 "TEAMID.bundleid"，进认领 SQL 的 IN 列表。没有 iOS 能力的机器
	// 这里是空的，SQL 里那一支被 platform<>'ios' 短路掉，但 IN () 是语法错误，
	// 所以放一个永远不会等于任何 "TEAM.bundle" 的占位值
	if len(pairs) == 0 {
		pairs = []string{""}
	}
	pairPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(pairs)), ",")
	for _, pair := range pairs {
		args = append(args, pair)
	}
	// 全托管的任务只派给这个租户（旧机器：这个 Team）的上传 Key 可用的机器；自助上传的任务只派给能把
	// .ipa 交回服务端的机器（ios_delivery.go）。同样的 IN () 占位
	if len(uploadPairs) == 0 {
		uploadPairs = []string{""}
	}
	uploadPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(uploadPairs)), ",")
	for _, pair := range uploadPairs {
		args = append(args, pair)
	}
	ipaCapable := 0
	if containsString(capabilities, machineCapabilityIPADelivery) {
		ipaCapable = 1
	}
	args = append(args, ipaCapable)

	conn, err := s.db.Conn(ctx)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	defer conn.Close()
	lockName := "rn_build_claim_" + machine.ID
	var locked sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT GET_LOCK(?,5)`, lockName).Scan(&locked); err != nil || !locked.Valid || locked.Int64 != 1 {
		problem(c, http.StatusConflict, "BUILDER_CLAIM_IN_PROGRESS", "Another claim from this machine is in progress")
		return
	}
	defer conn.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, lockName)

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	defer tx.Rollback()
	var activeID string
	var activeAttempt int
	switch err := tx.QueryRowContext(ctx,
		`SELECT id,attempt FROM build_jobs WHERE claimed_machine_id=? AND status IN (`+sqlBuilderActive+`) ORDER BY claimed_at LIMIT 1`,
		machine.ID).Scan(&activeID, &activeAttempt); {
	case err == nil:
		problemWith(c, http.StatusConflict, "BUILDER_HAS_ACTIVE_JOB",
			"This machine already has a claimed or running build; finish or fail it before claiming another",
			gin.H{"jobId": activeID, "attempt": activeAttempt})
		return
	case !errors.Is(err, sql.ErrNoRows):
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}

	// 选一条能派给这台机器的任务。平台与类型之外，iOS 还有四条自己的条件
	// （设计 ios-mac-builders-home-network-2026-09-18 §5.2、§5.3，ios-tenant-delivery-tiers-2026-09-24 §3.2）：
	//
	//  1. **同租户没有别的 iOS 安装包任务在途**：iOS 的发布记录入库要过
	//     RELEASE_VERSION_NOT_INCREASING（版本与 build 号都要大于上一条）。同租户排两条
	//     被两台 Mac 并行领走，高号先落库、低号的 /ios-release 被拒——而它的 .ipa 已经传进
	//     App Store Connect，撤不回来。Android 那侧有签名闸按 versionCode 的记录兜着这件事，
	//     所以这条只对 iOS 加：给 Android 加上会把"两台构建机同时打同一个租户的两条任务"
	//     也串起来，而那是今天就成立、也有用例盯着的行为。
	//  2. 这台机器手上确实有这个租户那个 Team、那个 bundle id 的签名材料（自报盘点）。
	//  3. **同租户按排队顺序**：这个租户有更早的排队中 iOS 安装包任务时，这一条不能先领。
	//     第 1 条只挡"同时在跑两条"，排队顺序原先是碰巧成立的——同租户的 iOS 任务领取条件
	//     完全一样。交付方式按任务分路由之后不再一样：全托管的 N 号因为没有能上传的机器卡住时，
	//     自助上传的 N+1 号会先打完落库，N 号之后传进 TestFlight 却在 /ios-release 被
	//     RELEASE_VERSION_NOT_INCREASING 拒掉，包撤不回来。有了这一条，卡住的那条挡住后面的，
	//     积压告警报出来，由人取消或补上机器。
	//  4. 交付方式对得上这台机器：全托管要这个 Team 的上传 Key 可用，自助上传要能交回 .ipa。
	//
	// 第 2、4 条用子查询而不是 JOIN，并且把锁**限定在 build_jobs 上**（FOR UPDATE OF j）：
	// MySQL 的锁定读会把子查询里读到的行一起锁上，不限定的话每次认领都会锁住 app_configs
	// 里各租户的 release.ios 那几行，而认领是每台机器每 10 秒一次的高频路径——控制台保存
	// iOS 发布身份会被它挡住。同理第 1 条里的 build_jobs 别名 o 也不该被锁。
	var id string
	err = tx.QueryRowContext(ctx,
		`SELECT j.id FROM build_jobs j
		  WHERE j.status='queued' AND j.platform IN (`+platformPlaceholders+`) AND j.kind IN (`+kindPlaceholders+`)
		    AND (j.platform<>'`+buildPlatformIOS+`' OR (
		          NOT EXISTS (SELECT 1 FROM build_jobs o
		                       WHERE o.tenant_id=j.tenant_id AND o.platform=j.platform AND o.kind='`+jobKindAPK+`'
		                         AND o.status IN (`+sqlBuilderActive+`))
		          AND (j.kind<>'`+jobKindAPK+`' OR NOT EXISTS (SELECT 1 FROM build_jobs e
		                       WHERE e.tenant_id=j.tenant_id AND e.platform=j.platform AND e.kind='`+jobKindAPK+`' AND e.status='queued'
		                         AND (e.created_at<j.created_at OR (e.created_at=j.created_at AND e.id<j.id))))
		          AND EXISTS (SELECT 1 FROM app_configs c
		                       WHERE c.tenant_id=j.tenant_id AND c.config_key='`+releaseIOSIdentityConfigKey+`'
		                         AND `+signingKey+` IN (`+pairPlaceholders+`)
		                         AND (j.kind<>'`+jobKindAPK+`'
		                              OR (COALESCE(j.delivery,'`+iosDeliveryTestFlight+`')='`+iosDeliveryTestFlight+`'
		                                  AND `+signingKey+` IN (`+uploadPlaceholders+`))
		                              OR (j.delivery='`+iosDeliveryIPA+`' AND ?=1)))))
		  ORDER BY j.created_at LIMIT 1 FOR UPDATE OF j SKIP LOCKED`, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		c.Status(http.StatusNoContent)
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	now := time.Now().UTC()
	// 每次认领清掉上一次认领交付的东西：未签名包、SBOM、出处与提交都属于那一次认领，
	// 这一次的交付必须完整重来，/built 才能要求"本次认领下都已上传"。上一次认领留下的对象
	// 在认领提交之后删掉（回收时一般已经删过，这里兜住其它路径留下的）
	var previous jobObjectKeys
	if err := tx.QueryRowContext(ctx, `SELECT `+jobObjectKeyColumns+` FROM build_jobs WHERE id=? FOR UPDATE`, id).
		Scan(&previous.Unsigned, &previous.SBOM, &previous.Signed); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE build_jobs SET status='claimed',claimed_by=?,claimed_machine_id=?,claimed_at=?,heartbeat_at=?,attempt=attempt+1,
		        commit_sha=NULL,unsigned_object_key=NULL,unsigned_size=NULL,unsigned_sha256=NULL,
		        sbom_object_key=NULL,sbom_size=NULL,sbom_sha256=NULL,native_fingerprint=NULL,provenance=NULL,updated_at=?
		  WHERE id=? AND status='queued'`,
		machine.Name, machine.ID, now, now, now, id); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
		return
	}
	job, err := scanBuildJob(tx.QueryRowContext(ctx, `SELECT `+buildJobColumns+` FROM build_jobs WHERE id=? LIMIT 1`, id))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to claim a build")
		return
	}
	// 下发的分支必须是我们自己那一个，不认库里那一列（`build-concurrency-2026-09-15.md` §9）。
	//
	// 写入路径上每一条用的都是 buildGitRef 这个常量，所以这一列出现别的值只有
	// 两种可能：常量上线之前的历史脏数据，或者**有人直接写了库**。后者是一条
	// 完整的提权路径：让构建机检出一个带后门的提交，构建时就执行了攻击者的代码。
	//
	// 判死而不是改写成 main：改写会让这条任务构建出和记录不符的东西，
	// 而记录是事后追查唯一的依据。判死并写明原因，让人看得见发生过什么。
	if job.GitRef != buildGitRef {
		if _, err := tx.ExecContext(ctx,
			`UPDATE build_jobs SET status='failed',failure_reason=?,updated_at=? WHERE id=?`,
			"refusing to build a git ref that is not "+buildGitRef, now, id); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
			return
		}
		if err := tx.Commit(); err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to claim a build")
			return
		}
		slog.Error("refused to dispatch a build job whose git ref is not the fixed branch",
			"jobId", id, "tenant", job.TenantID, "machineId", machine.ID)
		s.auditNow(newAudit(platformTenantID, builderSystemActor, "build_job_ref_refused", "build-job", id,
			"a build job carried a git ref that is not the fixed branch", requestID(c),
			map[string]any{"expected": buildGitRef, "jobId": id, "machineId": machine.ID}))
		c.Status(http.StatusNoContent)
		return
	}
	// 解析不出租户（租户被删了、任务是脏数据）时不能把这条任务留在队列里报 500：
	// 认领总是取最早那条，一条解析不了的任务会把**整个队列**堵死，而队列是跨租户的。
	var slug string
	switch err := tx.QueryRowContext(ctx, `SELECT slug FROM tenants WHERE id=? LIMIT 1`, job.TenantID).Scan(&slug); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx, `UPDATE build_jobs SET status='failed',failure_reason=?,updated_at=? WHERE id=?`,
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
	s.deleteDeliveryObjects(job.TenantID, job.ID, previous.pick(releaseBuildDelivery))

	// 仓库里的租户目录名与本平台 slug 是两套命名，必须显式配置
	buildCfg, _, err := s.buildConfigFor(ctx, job.TenantID, slug)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_CONFIG_INVALID", "Stored build.android configuration is invalid")
		return
	}
	view := buildJobView(job)
	// tenantId：按租户落签名材料的 Mac 用它找本租户的描述文件、证书与上传 Key（设计
	// ios-tenant-owned-signing-material-2026-09-25 §4.1）。目录用租户 id，不用 slug 或 tenantDirectory：
	// 那两个要么租户自己能改，要么会与别的租户撞
	view["tenantId"] = job.TenantID
	view["tenantSlug"] = slug
	view["tenantDirectory"] = buildCfg.RepoDirectory
	view["googleServicesJson"] = nullableString(buildCfg.GoogleServicesJSON)
	// 图标只给文件名，构建机逐张去 GET /jobs/:id/icons/:name 取（见 build_icons.go）
	icons, err := s.buildIconsForJob(ctx, job.TenantID, buildCfg.Identity)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_ICONS_INVALID", "Stored build.icons configuration is invalid")
		return
	}
	view["icons"] = icons
	// tenant.json 由服务端合成随任务下发。合成不出来就让这条任务当场失败
	manifest, err := s.tenantManifestFor(ctx, job.TenantID, buildCfg, job.Version, job.BuildNumber)
	if err != nil {
		var missing *missingIdentity
		if errors.As(err, &missing) {
			s.markBuildJobFailed(ctx, job, missing.Error())
			problem(c, http.StatusConflict, "APP_IDENTITY_INCOMPLETE", missing.Error())
			return
		}
		problem(c, http.StatusInternalServerError, "APP_IDENTITY_INVALID", "Unable to compose the tenant app identity")
		return
	}
	// 排队之后有人把 iOS 身份删了：当场判失败，别让这条任务占着 Mac 跑一趟必然失败的构建
	if job.Platform == buildPlatformIOS {
		if detail := s.iosBuildIdentityProblem(ctx, job.TenantID); detail != "" {
			s.markBuildJobFailed(ctx, job, detail)
			problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE", detail)
			return
		}
	}
	view["tenantFile"] = manifest
	// OTA 证书两种任务都要：它编进包里的 expo-updates 配置，也因此进原生指纹。
	// 证书是公开材料，私钥不下发
	record, err := s.otaSigningRecord(ctx, job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_CONFIG_INVALID", "Stored ota.signing configuration is invalid")
		return
	}
	if record == nil {
		view["otaCertificatePem"] = nil
		view["otaCertificateSha256"] = nil
	} else {
		certificateSHA256, _ := certificateFingerprint(record.Value.Certificate)
		view["otaCertificatePem"] = nullableString(record.Value.Certificate)
		view["otaCertificateSha256"] = nullableString(certificateSHA256)
	}
	// runtimeVersion 取基线那一版：热更新包必须对准它，否则一台设备都收不到
	if job.Kind == jobKindOTA {
		base, baseErr := s.otaJobBaseFor(ctx, job.TenantID, job.BaseReleaseID.String)
		if baseErr != nil {
			detail := "这条热更新任务的基线安装包已经不可用了：" + baseErr.Error()
			s.markBuildJobFailed(ctx, job, detail)
			problem(c, http.StatusConflict, "OTA_BASE_RELEASE_INVALID", detail)
			return
		}
		view["runtimeVersion"] = base.RuntimeVersion
	}
	// 安装包任务不下发任何签名密钥材料：签名在签名闸上做，构建机从头到尾碰不到
	c.JSON(http.StatusOK, view)
}

// markBuildJobFailed 在认领那一刻就发现缺配置时判一条任务失败。队列是跨租户的，
// 一条卡住的任务占着 build 号，拖的是所有人。
func (s *server) markBuildJobFailed(ctx context.Context, job buildJob, reason string) {
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE build_jobs SET status='failed',failure_reason=?,heartbeat_at=?,updated_at=?
		  WHERE id=? AND status IN (`+sqlDispatchFailure+`) AND attempt=? AND claimed_machine_id=?`,
		clipRunes(reason, 500), now, now, job.ID, job.Attempt, job.ClaimedMachineID.String); err != nil {
		slog.Error("unable to fail a build job that cannot be dispatched", "jobId", job.ID, "error", err)
	}
}

// ---- 任务作用域 ----

// builderJobScope 校验"这台机器、这次认领、这条任务还在构建中"，并把任务的租户装进上下文。
// 热更新那几条复用管理端处理函数，它们靠上下文里的 tenantId 定位租户。
func (s *server) builderJobScope(next gin.HandlerFunc) gin.HandlerFunc {
	return s.builderJobScopeWith(false, next)
}

// builderResultScope 是报结果那一条用的：同一台机器、同一次认领、任务**已经成功**也放行，
// 交给处理函数自己判断是不是同一份结果的重报。重试是常态——结果报上去了、回应在路上丢了，
// 构建机会再报一次；不放行的话它拿到的是 409 BUILD_ATTEMPT_STALE，日志里写成"认领过期了"，
// 而真实情况是"已经收下了"。
func (s *server) builderResultScope(next gin.HandlerFunc) gin.HandlerFunc {
	return s.builderJobScopeWith(true, next)
}

func (s *server) builderJobScopeWith(allowSucceeded bool, next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		machine, ok := machineFromContext(c)
		if !ok {
			problem(c, http.StatusUnauthorized, "MACHINE_AUTH_REQUIRED", "Machine authentication required")
			return
		}
		attempt, ok := attemptFromHeader(c, buildAttemptHeader)
		if !ok {
			problem(c, http.StatusBadRequest, "INVALID_BUILD_ATTEMPT", "x-build-attempt must carry the attempt number returned by claim")
			return
		}
		job, err := s.loadBuildJob(c, "", c.Param("id"))
		if err != nil {
			return
		}
		active := buildJobTransitionAllowed(eventBuilderHeartbeat, job.Kind, job.Status) || allowSucceeded && job.Status == jobSucceeded
		if !active || job.Attempt != attempt || job.ClaimedMachineID.String != machine.ID {
			problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
			return
		}
		c.Set("tenantId", job.TenantID)
		c.Set("actorId", buildAgentActor)
		c.Set("buildJob", job)
		next(c)
	}
}

func builderJobFromContext(c *gin.Context) (buildJob, bool) {
	item, _ := c.Get("buildJob")
	job, ok := item.(buildJob)
	if !ok {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to read the build job")
	}
	return job, ok
}

// retiredAPKArtifactRoute 接住安装包旧的交付路径（/artifact-uploads、/artifact、/release）。
// 那条路径由构建机直接落发布记录，而构建机现在没有签名能力，交出来的只能是未签名包。
func (s *server) retiredAPKArtifactRoute(c *gin.Context) {
	problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH",
		"Installable packages are delivered unsigned through /unsigned/upload, /sbom/upload and /built; the signer creates the release")
}

// ---- 心跳与失败 ----

func (s *server) buildJobHeartbeat(c *gin.Context) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, buildAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_ATTEMPT", "x-build-attempt must carry the attempt number returned by claim")
		return
	}
	var body struct {
		LogTail []string `json:"logTail"`
	}
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_PROGRESS", "logTail must be an array of strings")
		return
	}
	now := s.now()
	// 心跳也算"最近在线"：构建跑满两小时的那台 Mac 期间一次认领都不会发（一机一活），
	// 只有这里能证明它还活着。只动 last_seen_at——请求体里没有材料盘点，用认领那条写入
	// 会把 apple_teams 抹成 NULL，控制台上这台机器会在构建期间突然"什么材料都没有"
	s.touchMachineLiveness(c.Request.Context(), machine.ID, now)
	guard := `id=? AND status IN (` + sqlBuilderActive + `) AND attempt=? AND claimed_machine_id=?`
	guardArgs := []any{c.Param("id"), attempt, machine.ID}
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='running',heartbeat_at=?,log_tail=?,updated_at=? WHERE `+guard,
		append([]any{now, clampLogTail(body.LogTail), now}, guardArgs...)...)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record build progress")
		return
	}
	// 同一毫秒里两次心跳、日志尾部相同：值没变，RowsAffected 是 0，但编号是对的（rowsMatched）
	if matched, err := rowsMatched(c.Request.Context(), s.db, result, "build_jobs", guard, guardArgs...); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record build progress")
		return
	} else if !matched {
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *server) failBuildJob(c *gin.Context) {
	machine, _ := machineFromContext(c)
	attempt, ok := attemptFromHeader(c, buildAttemptHeader)
	if !ok {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_ATTEMPT", "x-build-attempt must carry the attempt number returned by claim")
		return
	}
	var body struct {
		FailureReason string   `json:"failureReason"`
		CommitSHA     string   `json:"commitSha"`
		LogTail       []string `json:"logTail"`
		// Orphaned：这台机器手上有这条任务的认领，但**它一行都没跑过**——认领的回应在
		// 路上丢了，构建机根本不知道自己领了活。这种情形该重排，不该判死（见下）
		Orphaned bool `json:"orphaned"`
	}
	reason := ""
	commit := ""
	if decode(c, &body) == nil {
		reason = strings.TrimSpace(sanitizeReportedText(body.FailureReason))
		commit = strings.ToLower(strings.TrimSpace(body.CommitSHA))
	}
	if reason == "" {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "failureReason is required")
		return
	}
	if body.Orphaned && s.requeueOrphanedBuildJob(c, machine, attempt) {
		return
	}
	// 失败的构建也要记下它到底检出了哪个提交；解析提交之前就失败的任务没有这个值
	if !commitSHAPattern.MatchString(commit) {
		commit = ""
	}
	now := time.Now().UTC()
	// 已经传上来的未签名包与 SBOM 不会再有人用，随失败一起删
	_, matched, err := s.transitionBuildJob(c.Request.Context(), c.Param("id"), jobTransition{
		Where:     `WHERE id=? AND status IN (` + sqlBuilderActive + `) AND attempt=? AND claimed_machine_id=?`,
		WhereArgs: []any{c.Param("id"), attempt, machine.ID},
		Set:       `status='failed',failure_reason=?,commit_sha=COALESCE(?,commit_sha),log_tail=?,heartbeat_at=?,updated_at=?`,
		SetArgs:   []any{clipRunes(reason, 500), sqlNullableString(commit), clampLogTail(body.LogTail), now, now},
		Release:   releaseBuildDelivery,
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the build failure")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}

// requeueOrphanedBuildJob 把"派出去了、但构建机从来没开始跑"的任务放回队列。
//
// 2026-09-20 真机上第一条 iOS 任务就是这么死的：认领请求到了服务端、任务派了出去，
// **回应在路上丢了**（构建机那侧 30 秒超时），于是构建机不知道自己领了活。七分钟后
// 它再来认领，服务端说"你手上还挂着一条"，它按那条路把任务判了死——而那条任务一行
// 都没跑过。
//
// 回收定时器遇到同样的局面是**重排**（build_reaper.go，attempt < maxBuildAttempts 时
// 置回 queued）。这里用的是同一条规则，只是不必干等心跳超时。"半截的构建不续跑"那条
// 性质没有变——重排是从头再来，不是接着跑。
//
// 守卫条件里带上 kind 与 attempt，判断交给数据库：读一遍再决定会留下一个窗口，期间
// 回收定时器可能已经动过这一行。回 true 表示这次请求已经答完。
func (s *server) requeueOrphanedBuildJob(c *gin.Context, machine buildMachine, attempt int) bool {
	id := c.Param("id")
	now := time.Now().UTC()
	locked, matched, err := s.transitionBuildJob(c.Request.Context(), id, jobTransition{
		Where: `WHERE id=? AND status IN (` + sqlBuilderActive + `) AND attempt=? AND claimed_machine_id=? ` +
			`AND kind=? AND attempt<?`,
		WhereArgs: []any{id, attempt, machine.ID, jobKindAPK, maxBuildAttempts},
		// 与回收定时器同一组赋值：attempt 不在这里加，下一次认领才加
		Set:     `status='queued',claimed_at=NULL,heartbeat_at=NULL,updated_at=?`,
		SetArgs: []any{now},
		// 这一次认领传上来的未签名包与 SBOM 不会再有人用：重排后下一次认领从头交付
		Release: releaseBuildDelivery,
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to requeue the build")
		return true
	}
	if !matched {
		// 守卫不成立（次数用完了、任务已经不在跑了、或者不是安装包任务）：交给调用方
		// 按普通失败记下去
		return false
	}
	slog.Warn("requeued a build job whose claim never reached the builder",
		"job", id, "attempt", attempt, "machineId", machine.ID)
	s.auditNow(newAudit(locked.TenantID, builderSystemActor, "build_job_requeued", "build-job", id,
		"the builder never received this claim; requeued", "",
		map[string]any{"jobId": id, "attempt": attempt, "machineId": machine.ID}))
	c.Status(http.StatusNoContent)
	return true
}

// completeOTABuildJob 收热更新任务的结果。安装包任务不走这里（它们交付到 built 为止）。
func (s *server) completeOTABuildJob(c *gin.Context) {
	job, ok := builderJobFromContext(c)
	if !ok {
		return
	}
	if job.Kind != jobKindOTA {
		s.retiredAPKArtifactRoute(c)
		return
	}
	machine, _ := machineFromContext(c)
	var body struct {
		CommitSHA      string   `json:"commitSha"`
		ArtifactSHA256 string   `json:"artifactSha256"`
		ReleaseID      string   `json:"releaseId"`
		LogTail        []string `json:"logTail"`
	}
	commit, digest := "", ""
	if decode(c, &body) == nil {
		commit = strings.ToLower(strings.TrimSpace(body.CommitSHA))
		digest = strings.ToLower(strings.TrimSpace(body.ArtifactSHA256))
	}
	if !commitSHAPattern.MatchString(commit) || !fingerprint.Valid(digest) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha and artifactSha256 must be hex digests")
		return
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(),
		`UPDATE build_jobs SET status='succeeded',commit_sha=?,artifact_sha256=?,ota_release_id=?,log_tail=?,heartbeat_at=?,updated_at=?
		  WHERE id=? AND kind='ota' AND status IN (`+sqlStatusList(buildJobEventFrom(eventBuilderComplete, jobKindOTA))+`) AND attempt=? AND claimed_machine_id=?`,
		commit, digest, sqlNullableString(strings.TrimSpace(body.ReleaseID)), clampLogTail(body.LogTail), now, now, job.ID, job.Attempt, machine.ID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the build result")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- 未签名包与 SBOM ----

func (s *server) uploadUnsignedArtifact(c *gin.Context) {
	// iOS 没有未签名包。自助上传的 .ipa 也记在 unsigned_* 这几列上，但只能走 /ipa/upload——
	// 那条路会解包核对身份；从这里进来的话，/ios-release 会把一个没核过的文件当成交付件
	if job, ok := builderJobFromContext(c); !ok {
		return
	} else if job.Platform != buildPlatformAndroid {
		problem(c, http.StatusConflict, "BUILD_PLATFORM_MISMATCH", "Only Android builds deliver an unsigned package; iOS delivers its .ipa through /ipa/upload")
		return
	}
	s.receiveBuildDelivery(c, "unsigned", unsignedAPKObjectName, s.cfg.ArtifactMaxSizeBytes)
}

func (s *server) uploadBuildSBOM(c *gin.Context) {
	s.receiveBuildDelivery(c, "sbom", sbomObjectName, buildSBOMMaxBytes)
}

// deliveryObjectSegment 是一次上传的对象键中间段：编号 + 随机段。
//
// 随机段不能省。键只由编号决定时，同一次认领里的两次上传写的是同一个键：前一次请求在
// 反向代理那里超时、客户端重传成功并往下走了（/built、complete），前一次这才写完，
// 既覆盖了已经被任务行或发布记录引用的对象，又因为状态已经往前走、改不到行而把它删掉。
// 每次上传一个新键之后，迟到的上传只可能删掉自己写的那个对象。
func deliveryObjectSegment(prefix string, attempt int) string {
	return prefix + strconv.Itoa(attempt) + "/" + randomID(9)
}

// recordDeliveredObject 锁住任务行、确认认领仍然有效（lockQuery 带编号与机器条件，只选出
// 本列当前的对象键），再执行 update 记下新对象，一个事务。认领已经无效时 current=false，
// 调用方删掉自己刚写的对象。返回被替换下来的旧键，调用方在提交之后删除。
func (s *server) recordDeliveredObject(ctx context.Context, lockQuery string, lockArgs []any, update string, updateArgs []any) (replaced sql.NullString, current bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sql.NullString{}, false, err
	}
	defer tx.Rollback()
	switch err := tx.QueryRowContext(ctx, lockQuery+` FOR UPDATE`, lockArgs...).Scan(&replaced); {
	case errors.Is(err, sql.ErrNoRows):
		return sql.NullString{}, false, nil
	case err != nil:
		return sql.NullString{}, false, err
	}
	if _, err := tx.ExecContext(ctx, update, updateArgs...); err != nil {
		return sql.NullString{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return sql.NullString{}, false, err
	}
	return replaced, true, nil
}

// deleteReplacedObject 删掉同一次认领里被重传替换下来的旧对象。尽力而为：删不掉只留一个
// 没人引用的孤儿对象，不影响任务。
func deleteReplacedObject(client objectstore.Client, replaced sql.NullString, key, jobID string) {
	if !replaced.Valid || replaced.String == "" || replaced.String == key {
		return
	}
	if err := client.Delete(context.Background(), replaced.String); err != nil {
		slog.Warn("cannot delete an object replaced by a re-upload", "job", jobID, "key", replaced.String, "error", err)
	}
}

// receiveBuildDelivery 流式收下未签名包或 SBOM，写进租户发布存储（每次上传一个新键），然后在
// 锁住任务行的同一个事务里校验认领编号并记下对象键、大小与 sha256。编号在收流期间过期
// （任务被回收、被取消、已经交付）时改不到行，刚写的对象删掉，回 409。
func (s *server) receiveBuildDelivery(c *gin.Context, what, objectName string, limit int64) {
	job, ok := builderJobFromContext(c)
	if !ok {
		return
	}
	if job.Kind != jobKindAPK {
		problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH", "Only installable-package builds deliver an unsigned package or SBOM")
		return
	}
	machine, _ := machineFromContext(c)
	client, prefix, err := s.storageClientForTenant(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_UNAVAILABLE", "Release storage is not configured")
		return
	}
	key := buildJobObjectKey(prefix, job.TenantID, job.ID, deliveryObjectSegment("a", job.Attempt), objectName)
	received, status, code, detail := s.receiveStreamToObject(c, client, key, limit)
	if status != 0 {
		problem(c, status, code, detail)
		return
	}
	if what == "sbom" {
		if detail := received.cycloneDXProblem(); detail != "" {
			_ = client.Delete(context.Background(), key)
			problem(c, http.StatusUnprocessableEntity, "BUILD_SBOM_INVALID", detail)
			return
		}
	}
	received.cleanup()
	column := "unsigned"
	if what == "sbom" {
		column = "sbom"
	}
	// 列名来自上面两个常量之一，不是输入。请求可能已经断开，落库不跟着请求取消
	replaced, current, err := s.recordDeliveredObject(context.Background(),
		`SELECT `+column+`_object_key FROM build_jobs
		  WHERE id=? AND kind='apk' AND status IN (`+sqlStatusList(buildJobEventFrom(eventBuilderUpload, jobKindAPK))+`) AND attempt=? AND claimed_machine_id=?`,
		[]any{job.ID, job.Attempt, machine.ID},
		`UPDATE build_jobs SET `+column+`_object_key=?,`+column+`_size=?,`+column+`_sha256=?,updated_at=? WHERE id=?`,
		[]any{key, received.size, received.sha256, time.Now().UTC(), job.ID})
	if err != nil {
		// 不删对象：提交报错时事务可能其实已经提交，删了就是删一个被引用的键
		slog.Error("cannot record a delivered build file", "job", job.ID, "what", what, "error", err)
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the delivered file")
		return
	}
	if !current {
		_ = client.Delete(context.Background(), key)
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	deleteReplacedObject(client, replaced, key, job.ID)
	c.JSON(http.StatusOK, gin.H{"sha256": received.sha256, "size": received.size})
}

// receivedStream 是收下来的一个流：临时文件、大小、sha256。
type receivedStream struct {
	path   string
	size   int64
	sha256 string
}

func (r receivedStream) cleanup() {
	if r.path != "" {
		_ = os.Remove(r.path)
	}
}

// cycloneDXProblem 只看形状：是一个 bomFormat=CycloneDX 的 JSON 对象。内容由构建机自报，
// 服务端不据此做任何判定，记进发布记录只为以后回答"线上那个版本用了哪些依赖"。
func (r receivedStream) cycloneDXProblem() string {
	defer r.cleanup()
	file, err := os.Open(r.path)
	if err != nil {
		return "the SBOM could not be read back"
	}
	defer file.Close()
	var head struct {
		BOMFormat string `json:"bomFormat"`
	}
	if err := json.NewDecoder(file).Decode(&head); err != nil || head.BOMFormat != "CycloneDX" {
		return "the SBOM must be a CycloneDX JSON document"
	}
	return ""
}

// receiveStreamToObject 把请求体按上限收进临时文件、边收边算 sha256，再写进对象存储并
// 核对落盘大小。返回的临时文件由调用方清理。status 非 0 表示失败，临时文件已清理。
func (s *server) receiveStreamToObject(c *gin.Context, client objectstore.Client, key string, limit int64) (receivedStream, int, string, string) {
	received, status, code, detail := receiveStreamToTemp(c, limit)
	if status != 0 {
		return receivedStream{}, status, code, detail
	}
	if status, code, detail := s.storeReceivedStream(client, key, received); status != 0 {
		received.cleanup()
		return receivedStream{}, status, code, detail
	}
	return received, 0, "", ""
}

// receiveStreamToTemp 只做"收"的那一半：请求体按上限进临时文件、边收边算 sha256。要先核对
// 内容再决定存不存的调用方（自助上传的 .ipa）单独用它。status 非 0 表示失败，临时文件已清理。
func receiveStreamToTemp(c *gin.Context, limit int64) (receivedStream, int, string, string) {
	if mediaType, _, err := mime.ParseMediaType(c.GetHeader("content-type")); err != nil || mediaType != octetStream {
		return receivedStream{}, http.StatusUnsupportedMediaType, "UPLOAD_CONTENT_TYPE_INVALID", "The body must be sent as application/octet-stream"
	}
	if c.Request.ContentLength > limit {
		return receivedStream{}, http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE", fmt.Sprintf("The body exceeds the %d byte limit", limit)
	}
	temporary, err := os.CreateTemp("", "rn-build-delivery-*")
	if err != nil {
		return receivedStream{}, http.StatusInternalServerError, "UPLOAD_FAILED", "Unable to prepare the upload"
	}
	received := receivedStream{path: temporary.Name()}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), http.MaxBytesReader(c.Writer, c.Request.Body, limit))
	closeErr := temporary.Close()
	if copyErr != nil {
		received.cleanup()
		if requestTooLarge(copyErr) {
			return receivedStream{}, http.StatusRequestEntityTooLarge, "UPLOAD_TOO_LARGE", fmt.Sprintf("The body exceeds the %d byte limit", limit)
		}
		return receivedStream{}, http.StatusBadRequest, "UPLOAD_INTERRUPTED", "The upload body could not be read completely"
	}
	if closeErr != nil {
		received.cleanup()
		return receivedStream{}, http.StatusInternalServerError, "UPLOAD_FAILED", "Unable to store the upload"
	}
	if written == 0 {
		received.cleanup()
		return receivedStream{}, http.StatusBadRequest, "UPLOAD_EMPTY", "The upload body is empty"
	}
	if c.Request.ContentLength >= 0 && c.Request.ContentLength != written {
		received.cleanup()
		return receivedStream{}, http.StatusBadRequest, "UPLOAD_INTERRUPTED", "The upload body is shorter than Content-Length"
	}
	received.size, received.sha256 = written, hex.EncodeToString(hash.Sum(nil))
	return received, 0, "", ""
}

// storeReceivedStream 把收下的临时文件写进对象存储并核对落盘大小。临时文件不在这里清理。
func (s *server) storeReceivedStream(client objectstore.Client, key string, received receivedStream) (int, string, string) {
	file, err := os.Open(received.path)
	if err != nil {
		return http.StatusInternalServerError, "UPLOAD_FAILED", "Unable to store the upload"
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.ArtifactVerifyTimeout)*time.Second)
	defer cancel()
	if err := client.Put(ctx, key, file, received.size, octetStream); err != nil {
		slog.Error("cannot write a build delivery to object storage", "objectKey", key, "error", err)
		return http.StatusFailedDependency, "UPLOAD_STORAGE_FAILED", "Unable to write the upload to object storage"
	}
	stored, err := client.Stat(ctx, key)
	if err != nil || stored.Size != received.size {
		return http.StatusFailedDependency, "UPLOAD_STORAGE_FAILED", "Object storage does not hold the complete upload"
	}
	return 0, "", ""
}

// ---- 交付 ----

type buildProvenanceRecord struct {
	Statement              string `json:"statement"`
	Signature              string `json:"signature"`
	BuilderID              string `json:"builderId"`
	BuilderPublicKey       string `json:"builderPublicKey"`
	BuilderPublicKeySHA256 string `json:"builderPublicKeySha256"`
}

// markBuildJobBuilt 收下出处声明，任务转为 built（待签名）。
//
// 服务端也验一遍出处：签名用这台机器登记的 active 公钥验过，声明里的每个字段与任务行、
// 请求、已上传的文件一致。签名闸会独立再验一次（只认本机 pin 的构建机）——服务端这一道
// 是为了让伪造或错配的交付在控制台上就能看见，而不是等签名闸拒签。
func (s *server) markBuildJobBuilt(c *gin.Context) {
	job, ok := builderJobFromContext(c)
	if !ok {
		return
	}
	if job.Kind != jobKindAPK {
		problem(c, http.StatusConflict, "BUILD_KIND_MISMATCH", "Only installable-package builds are delivered to the signer")
		return
	}
	// iOS 没有"未签名包"这个东西可以交付：签名在 Mac 上的 xcodebuild 里就发生了。
	// 放过去的话任务会停在 built，而签名闸的认领带着 platform='android'，永远不会来领它
	if job.Platform != buildPlatformAndroid {
		problem(c, http.StatusConflict, "BUILD_PLATFORM_MISMATCH",
			"Only Android builds are delivered to the signer; iOS builds report to /ios-release")
		return
	}
	machine, _ := machineFromContext(c)
	var body struct {
		CommitSHA         string              `json:"commitSha"`
		NativeFingerprint string              `json:"nativeFingerprint"`
		Provenance        provenance.Envelope `json:"provenance"`
		LogTail           []string            `json:"logTail"`
	}
	if err := decode(c, &body); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha, nativeFingerprint, provenance {statement, signature} and logTail are required")
		return
	}
	commit := strings.TrimSpace(body.CommitSHA)
	native := strings.TrimSpace(body.NativeFingerprint)
	if !commitSHAPattern.MatchString(commit) || !nativeFingerprintPattern.MatchString(native) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_RESULT", "commitSha must be a lowercase git object id and nativeFingerprint lowercase hex")
		return
	}
	invalid := func(detail string) {
		problem(c, http.StatusUnprocessableEntity, "BUILD_PROVENANCE_INVALID", detail)
	}
	if !job.UnsignedSHA256.Valid || !job.UnsignedSize.Valid || !job.SBOMSHA256.Valid {
		invalid("the unsigned package and the SBOM must both be uploaded under this claim before delivery")
		return
	}
	publicKey, err := base64.StdEncoding.DecodeString(string(machine.PublicKey))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		invalid("this machine has no usable accepted provenance key")
		return
	}
	statement, err := provenance.Verify(body.Provenance, ed25519.PublicKey(publicKey))
	if err != nil {
		invalid("the provenance signature does not verify with this machine's accepted key, or the statement is malformed")
		return
	}
	slug, err := s.tenantSlug(c.Request.Context(), job.TenantID)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to resolve the tenant of this build")
		return
	}
	identity, err := s.androidReleaseIdentityRecord(c.Request.Context(), job.TenantID)
	if err != nil || identity == nil {
		invalid("the tenant has no registered Android release identity to compare the package name with")
		return
	}
	mismatches := []string{}
	check := func(field string, equal bool) {
		if !equal {
			mismatches = append(mismatches, field)
		}
	}
	check("jobId", statement.JobID == job.ID)
	check("attempt", statement.Attempt == job.Attempt)
	check("tenantSlug", statement.TenantSlug == slug)
	check("packageName", statement.PackageName == identity.Value.PackageName)
	check("versionCode", statement.VersionCode == int64(job.BuildNumber))
	check("versionName", statement.VersionName == job.Version)
	check("commitSha", statement.CommitSHA == commit)
	check("unsignedSha256", statement.UnsignedSHA256 == job.UnsignedSHA256.String)
	check("unsignedSize", statement.UnsignedSize == job.UnsignedSize.Int64)
	check("sbomSha256", statement.SBOMSHA256 == job.SBOMSHA256.String)
	check("nativeFingerprint", statement.NativeFingerprint == native)
	check("builderId", statement.BuilderID == machine.ID)
	if len(mismatches) > 0 {
		invalid("the provenance statement does not match this build: " + strings.Join(mismatches, ", "))
		return
	}
	record, _ := json.Marshal(buildProvenanceRecord{
		Statement: body.Provenance.Statement, Signature: body.Provenance.Signature, BuilderID: machine.ID,
		BuilderPublicKey: string(machine.PublicKey), BuilderPublicKeySHA256: string(machine.PublicKeySHA256),
	})
	ctx := c.Request.Context()
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the delivery")
		return
	}
	defer tx.Rollback()
	// 交付物在这条 UPDATE 里再比一次：收流与交付之间不能被同一次认领的另一次上传换掉
	result, err := tx.ExecContext(ctx,
		`UPDATE build_jobs SET status='built',commit_sha=?,native_fingerprint=?,provenance=?,log_tail=?,heartbeat_at=?,updated_at=?
		  WHERE id=? AND kind='apk' AND status IN (`+sqlStatusList(buildJobEventFrom(eventBuilderBuilt, jobKindAPK))+`) AND attempt=? AND claimed_machine_id=?
		    AND unsigned_sha256=? AND unsigned_size=? AND sbom_sha256=?`,
		commit, native, record, clampLogTail(body.LogTail), now, now,
		job.ID, job.Attempt, machine.ID, job.UnsignedSHA256.String, job.UnsignedSize.Int64, job.SBOMSHA256.String)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the delivery")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "BUILD_ATTEMPT_STALE", "This claim is no longer current for this machine; stop working on the job")
		return
	}
	event := newAudit(job.TenantID, builderSystemActor, "build_job_built", "build-job", job.ID, "a builder delivered an unsigned package with provenance", requestID(c),
		map[string]any{"jobId": job.ID, "attempt": job.Attempt, "builderId": machine.ID, "builderPublicKeySha256": string(machine.PublicKeySHA256),
			"commitSha": commit, "unsignedSha256": job.UnsignedSHA256.String, "sbomSha256": job.SBOMSHA256.String, "nativeFingerprint": native})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the delivery")
		return
	}
	c.Status(http.StatusNoContent)
}

// rewriteJSONBody 把请求体换成服务端自己拼的那一份，供内部转调的处理器读。
// 构建机只送它确实知道的东西（票据、提交）；决定产物发给谁的参数一律来自任务行。
func rewriteJSONBody(c *gin.Context, payload map[string]any) {
	raw, _ := json.Marshal(payload)
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	c.Request.ContentLength = int64(len(raw))
}

// problemWith 是带额外字段的 Problem Details（例如 409 BUILDER_HAS_ACTIVE_JOB 带上任务 id）。
func problemWith(c *gin.Context, status int, code, detail string, extra gin.H) {
	c.Header("Content-Type", "application/problem+json")
	body := gin.H{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": detail, "requestId": requestID(c)}
	for key, value := range extra {
		if _, reserved := body[key]; !reserved {
			body[key] = value
		}
	}
	c.JSON(status, body)
}
