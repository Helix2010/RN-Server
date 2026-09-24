package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
// 怎么构建由打包机自己决定，服务端知道的是产物指纹。
//
// ## 构建机没有签名能力（签名闸，设计 android-signing-gate-2026-09-16）
//
// 构建机执行几千个依赖包的代码，按不可信处理：它只交付未签名包、SBOM 与出处签名，
// 任务转为 built；主签名闸领走、在本机核对后签名，同一个事务里落发布记录并把任务改为
// succeeded。签名密钥只以加密给签名闸的密文存在库里，构建机与服务端都打不开。
// 状态机见 build_job_states.go，构建机接口见 build_agent.go，签名闸接口见 signer.go。
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
	ID       string
	TenantID string
	Platform string
	// Kind 区分"编译安装包"和"构建热更新包"。两者共用这张表、这套状态流转和这套
	// 回收：它们是同一种实体——一个排队等打包机干的活。
	Kind string
	// Delivery 只对 iOS 安装包任务有意义：排队时从租户配置抄来的交付方式（ios_delivery.go）。
	// 其余任务与迁移之前的 iOS 任务为 NULL，iOS 的 NULL 按 testflight 处理
	Delivery sql.NullString
	// DeliveryState 是自助上传任务交出 .ipa 之后租户标记的进展（ios_ipa_status.go）
	DeliveryState  []byte
	BaseReleaseID  sql.NullString
	Channel        sql.NullString
	ApplyStrategy  sql.NullString
	OTAReleaseID   sql.NullString
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
	// 构建段（迁移 54）：认领编号、认领的构建机、未签名包与 SBOM、原生指纹、出处
	Attempt           int
	ClaimedMachineID  sql.NullString
	UnsignedObjectKey sql.NullString
	UnsignedSize      sql.NullInt64
	UnsignedSHA256    sql.NullString
	SBOMObjectKey     sql.NullString
	SBOMSize          sql.NullInt64
	SBOMSHA256        sql.NullString
	NativeFingerprint sql.NullString
	Provenance        []byte
	// 签名段（迁移 54）
	SignAttempt        int
	SignFailures       int
	SigningMachineID   sql.NullString
	SigningClaimedAt   sql.NullTime
	SigningHeartbeatAt sql.NullTime
	SignOutcome        []byte
	SignedObjectKey    sql.NullString
}

const buildJobColumns = `id,tenant_id,platform,kind,delivery,delivery_state,base_release_id,channel,apply_strategy,ota_release_id,git_ref,commit_sha,version,build_number,status,claimed_by,claimed_at,heartbeat_at,release_id,artifact_sha256,log_tail,failure_reason,reason,release_notes,created_by,created_at,updated_at,` +
	`attempt,claimed_machine_id,unsigned_object_key,unsigned_size,unsigned_sha256,sbom_object_key,sbom_size,sbom_sha256,native_fingerprint,provenance,` +
	`sign_attempt,sign_failures,signing_machine_id,signing_claimed_at,signing_heartbeat_at,sign_outcome,signed_object_key`

func scanBuildJob(row interface{ Scan(...any) error }) (buildJob, error) {
	var j buildJob
	err := row.Scan(&j.ID, &j.TenantID, &j.Platform, &j.Kind, &j.Delivery, &j.DeliveryState, &j.BaseReleaseID, &j.Channel, &j.ApplyStrategy,
		&j.OTAReleaseID, &j.GitRef, &j.CommitSHA, &j.Version, &j.BuildNumber,
		&j.Status, &j.ClaimedBy, &j.ClaimedAt, &j.HeartbeatAt, &j.ReleaseID, &j.ArtifactSHA256, &j.LogTail,
		&j.FailureReason, &j.Reason, &j.ReleaseNotes, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt,
		&j.Attempt, &j.ClaimedMachineID, &j.UnsignedObjectKey, &j.UnsignedSize, &j.UnsignedSHA256,
		&j.SBOMObjectKey, &j.SBOMSize, &j.SBOMSHA256, &j.NativeFingerprint, &j.Provenance,
		&j.SignAttempt, &j.SignFailures, &j.SigningMachineID, &j.SigningClaimedAt, &j.SigningHeartbeatAt, &j.SignOutcome, &j.SignedObjectKey)
	return j, err
}

// buildJobSignOutcome 是 sign_outcome 列的形状（约定 5.4）。
type buildJobSignOutcome struct {
	Kind      string `json:"kind"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	MachineID string `json:"machineId"`
	At        string `json:"at"`
}

// buildJobView 是没有机器名称可查时的视图（刚建好的任务还没有被任何机器碰过）。
func buildJobView(j buildJob) map[string]any {
	return buildJobViewWithMachines(j, nil)
}

// buildJobViewWithMachines 带上签名闸名称。名称取自机器登记，查不到（被删、未登记）就是 null。
//
// 视图里**没有**出处签名、对象键与任何密文：列表是给租户管理员看的。
func buildJobViewWithMachines(j buildJob, machineNames map[string]string) map[string]any {
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
		"kind":           j.Kind,
		"delivery":       buildJobDeliveryView(j),
		"baseReleaseId":  nullableString(j.BaseReleaseID.String),
		"channel":        nullableString(j.Channel.String),
		"applyStrategy":  nullableString(j.ApplyStrategy.String),
		"otaReleaseId":   nullableString(j.OTAReleaseID.String),
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
		// 签名闸（迁移 54）
		"attempt":            j.Attempt,
		"claimedMachineId":   nullableString(j.ClaimedMachineID.String),
		"unsignedSha256":     nullableString(j.UnsignedSHA256.String),
		"unsignedSize":       nullableInt64(j.UnsignedSize),
		"sbomSha256":         nullableString(j.SBOMSHA256.String),
		"nativeFingerprint":  nullableString(j.NativeFingerprint.String),
		"signAttempt":        j.SignAttempt,
		"signFailures":       j.SignFailures,
		"signingMachineId":   nullableString(j.SigningMachineID.String),
		"signingMachineName": nullableString(machineNames[j.SigningMachineID.String]),
		"signingClaimedAt":   nullableTime(j.SigningClaimedAt.Time),
		"signingHeartbeatAt": nullableTime(j.SigningHeartbeatAt.Time),
		"signOutcome":        buildJobSignOutcomeView(j.SignOutcome),
		// commit 由构建机自报，服务端没有 GitHub 凭据去核对（设计「构建机 → 每个任务的隔离」）
		"commitSelfReported": true,
		// 自助上传任务交出的 .ipa 与租户标记的进展；"已被取代"要看同租户后面的构建，列表与
		// 详情另算后覆盖这一项（withIPASupersession）
		"ipaDelivery": ipaDeliveryView(j, 0),
	}
}

// withIPASupersession 用这个租户最高的成功 iOS build 号重算列表里每一行的 ipaDelivery。
func withIPASupersession(items []map[string]any, jobs []buildJob, latest int) {
	for i, job := range jobs {
		if i < len(items) && jobDelivery(job) == iosDeliveryIPA {
			items[i]["ipaDelivery"] = ipaDeliveryView(job, latest)
		}
	}
}

func buildJobSignOutcomeView(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	var outcome buildJobSignOutcome
	if err := json.Unmarshal(raw, &outcome); err != nil || outcome.Kind == "" {
		return nil
	}
	return gin.H{"kind": outcome.Kind, "code": outcome.Code, "detail": outcome.Detail, "machineId": nullableString(outcome.MachineID), "at": outcome.At}
}

// clipRunes 按**字符**截断，不是按字节。
//
// 按字节切会把一个多字节字符切成两半，JSON 编码时那半个字符变成 U+FFFD——三个字节，
// 比切掉的还长，结果是"限长 300"的字段存进去 304 字节。这段文字几乎一定是中文。
func clipRunes(text string, max int) string {
	runes := []rune(text)
	if len(runes) <= max {
		return text
	}
	return string(runes[:max])
}

// clampLogTail 只留尾部若干行。日志是代理送上来的，不设上限的话一次失败就能把这一行
// 撑到几十兆，而这张表是管理端列表要扫的。
func clampLogTail(lines []string) []byte {
	if len(lines) > buildJobLogTailMax {
		lines = lines[len(lines)-buildJobLogTailMax:]
	}
	// 日志尾部来自构建机，按不可信文本清洗（控制字符、双向覆盖字符），再按字节截断
	for i, line := range lines {
		lines[i] = clipBytes(sanitizeReportedText(line), 2000)
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
		(SELECT version,build_number FROM build_jobs WHERE tenant_id=? AND platform=? AND status IN (`+sqlInFlight+`,'succeeded') ORDER BY build_number DESC LIMIT 50)`,
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
	// Kind 空或 "apk" 走安装包那条；"ota" 走热更新那条（见 build_ota_jobs.go），
	// 那条不看 version / buildNumber，改看 baseReleaseId / applyStrategy。
	Kind          string `json:"kind"`
	BaseReleaseID string `json:"baseReleaseId"`
	ApplyStrategy string `json:"applyStrategy"`
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
	if strings.TrimSpace(body.Kind) == "ota" {
		s.createOTABuildJob(c, body)
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
			"这次构建会改变 App 身份（"+strings.Join(drift, "；")+"）：装着当前版本的设备无法覆盖升级，只能卸载重装。确认确实要换身份后再排队。")
		return
	}
	// 没有一台能构建这个平台的机器，就别把任务排进去。
	//
	// 这条闸是对称于 OTA 那侧（build_ota_jobs.go 的「打包机只做 android」）补上的，
	// 但判据换成了登记而不是硬编码的平台名：iOS 打包机是一台装了 Xcode 的 Mac，接进来
	// 之后这里不该还写着"iOS 不行"。
	//
	// 不加这道闸的后果不是"任务失败"，而是"任务永远 queued"——reapStaleBuildJobs 只回收
	// claimed/running，一条没人认领的任务不会被回收，却**占着一个 build 号**
	// （生成列 live_build_number 把 queued 也算活着），于是这个租户这个平台后面的每一次
	// 排队都要跳过它。
	registry, err := s.machineRegistry(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to read the machine registry")
		return
	}
	if !registry.hasLiveBuilderFor(platform) {
		problem(c, http.StatusConflict, "NO_BUILDER_FOR_PLATFORM",
			"没有登记任何能构建 "+platform+" 的构建机，排进去的任务不会有人认领。"+
				"到「平台维护 → 构建机」登记一台并勾上这个平台（iOS 需要一台装了 Xcode 的 Mac）。")
		return
	}
	// iOS 的签名身份不在签名闸上，在那台 Mac 的钥匙串里，所以它有自己的一套必填项
	warnings := []string{}
	var delivery any
	if platform == buildPlatformIOS {
		if detail := s.iosBuildIdentityProblem(c.Request.Context(), tenantID(c)); detail != "" {
			problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE", detail)
			return
		}
		// 登记说"有一台能打 iOS"还不够：池子模型下每台 Mac 都该能打任何租户，但
		// 材料是人一台台导进钥匙串的，漏一台就漏一个 Team。判据是机器自己报上来的
		// 盘点（§5.2），不是登记——登记里没有、也不该有"这台能打哪些 Team"这一列。
		identity, err := s.iosReleaseIdentityRecord(c.Request.Context(), tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to read the iOS release identity")
			return
		}
		// 交付方式在这一刻抄进任务：之后改配置只影响新排的任务（ios_delivery.go）
		mode, err := s.iosDeliveryModeFor(c.Request.Context(), tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "IOS_DELIVERY_CONFIG_INVALID", "Stored "+iosDeliveryConfigKey+" configuration is invalid")
			return
		}
		delivery = mode
		if identity != nil {
			coverage, err := s.iosSigningCoverage(c.Request.Context(), registry,
				identity.Value.AppleTeamID, identity.Value.BundleID, s.now())
			if err != nil {
				problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to read build machine liveness")
				return
			}
			// 有没有机器能接按"登记语义"判：登记在用的机器最近一次上报过就算，不看在不在线。
			// 掉线不拦——家里的 Mac 合上盖子就没了，任务照常排队等它回来，只把这件事说出来
			readiness := iosDeliveryReadiness{coverage: coverage}
			if code, detail := readiness.problem(mode, identity.Value.AppleTeamID, identity.Value.BundleID); code != "" {
				problem(c, http.StatusConflict, code, detail)
				return
			}
			if !readiness.online(mode) {
				warnings = append(warnings, "no_ios_builder_online")
			}
		}
	}
	// 主签名闸没有就绪，这个包出得来也签不了——别让它占构建机，停在「待签名」里。
	// 判据与签名认领用的是同一个函数（signerReadinessFor）：两边说法不一致时，
	// 排进去的任务会永远等不到签名闸。租户改了 apiBaseUrl 或 OTA 密钥之后，在主签名闸
	// 重新确认之前这里同样挡住。
	if platform == "android" {
		readiness, err := s.signerReadinessFor(c.Request.Context(), tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to check whether the primary signer is ready")
			return
		}
		if !readiness.Ready {
			problemWith(c, http.StatusConflict, "SIGNER_NOT_READY",
				"主签名闸还不能为这个租户签名，构建出来也签不了，所以没有排进队列："+readiness.problemDetails(),
				gin.H{"readinessProblems": readiness.problemList()})
			return
		}
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
		`INSERT INTO build_jobs(id,tenant_id,platform,delivery,git_ref,version,build_number,status,log_tail,reason,release_notes,created_by,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,'queued',JSON_ARRAY(),?,?,?,?,?)`,
		id, tenantID(c), platform, delivery, gitRef, version, body.BuildNumber, reason, encodedNotes, actor(c), now, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	event := newAudit(tenantID(c), actor(c), "build_job_create", "build-job", id, reason, requestID(c),
		map[string]any{"platform": platform, "gitRef": gitRef, "version": version, "buildNumber": body.BuildNumber, "delivery": delivery})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to queue the build")
		return
	}
	// Kind 必须显式给。这里的结构体是手工拼的、不是从库里读的，漏掉的字段就是零值：
	// 2026-09-13 加 OTA 类型之后，这个响应一直带着 "kind": ""，而管理端按 apk|ota 校验
	// 响应——于是每一次**成功的** APK 排队都显示成"排队失败"，重试一次就真的多排一个包。
	// 库里那一行没问题（列默认 'apk'），坏的只是这份响应。
	deliveryColumn := sql.NullString{}
	if mode, ok := delivery.(string); ok {
		deliveryColumn = sql.NullString{Valid: true, String: mode}
	}
	view := buildJobView(buildJob{
		ID: id, TenantID: tenantID(c), Platform: platform, Kind: "apk", Delivery: deliveryColumn, GitRef: gitRef, Version: version,
		BuildNumber: body.BuildNumber, Status: "queued", Reason: reason, ReleaseNotes: encodedNotes,
		CreatedBy: actor(c), CreatedAt: now, UpdatedAt: now,
	})
	// warnings 恒为数组，不是 null：管理端按 z.array 解析，而 zod 的 .default([])
	// 只对 undefined 生效、对 null 不生效（viewPlatforms 那条教训）
	view["warnings"] = warnings
	c.JSON(http.StatusCreated, view)
}

func (s *server) listBuildJobs(c *gin.Context) {
	filter, invalid := parseBuildJobListFilter(c)
	if invalid != "" {
		problem(c, http.StatusUnprocessableEntity, "INVALID_BUILD_FILTER", invalid)
		return
	}
	where, args := filter.where(tenantID(c))
	var total int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM build_jobs WHERE `+where, args...).Scan(&total); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to count builds")
		return
	}
	pageWhere, pageArgs := where, append([]any{}, args...)
	if filter.hasCursor {
		pageWhere += ` AND (created_at<? OR (created_at=? AND id<?))`
		pageArgs = append(pageArgs, filter.cursorAt, filter.cursorAt, filter.cursorID)
	}
	pageArgs = append(pageArgs, filter.limit+1)
	rows, err := s.db.QueryContext(c.Request.Context(),
		`SELECT `+buildJobColumns+` FROM build_jobs WHERE `+pageWhere+` ORDER BY created_at DESC,id DESC LIMIT ?`, pageArgs...)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
		return
	}
	defer rows.Close()
	jobs := []buildJob{}
	for rows.Next() {
		job, err := scanBuildJob(rows)
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
			return
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to read builds")
		return
	}
	hasMore := len(jobs) > filter.limit
	if hasMore {
		jobs = jobs[:filter.limit]
	}
	names := s.machineNamesForView(c.Request.Context())
	items := make([]map[string]any, 0, len(jobs))
	for _, job := range jobs {
		items = append(items, buildJobViewWithMachines(job, names))
	}
	latest, err := s.iosLatestBuildNumber(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to list builds")
		return
	}
	withIPASupersession(items, jobs, latest)
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
	var nextCursor any
	if hasMore && len(jobs) > 0 {
		last := jobs[len(jobs)-1]
		nextCursor = encodeBuildCursor(last.CreatedAt, last.ID)
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "next": next, "gitRef": buildGitRef, "total": total, "limit": filter.limit, "nextCursor": nextCursor, "hasMore": hasMore})
}

const buildJobListMaxLimit = 100

type buildJobListFilter struct {
	kind, platform, status, version, query string
	limit                                  int
	cursorAt                               time.Time
	cursorID                               string
	hasCursor                              bool
}

func parseBuildJobListFilter(c *gin.Context) (buildJobListFilter, string) {
	f := buildJobListFilter{
		kind:     strings.ToLower(strings.TrimSpace(c.Query("kind"))),
		platform: strings.ToLower(strings.TrimSpace(c.Query("platform"))),
		status:   strings.ToLower(strings.TrimSpace(c.Query("status"))),
		version:  strings.TrimSpace(c.Query("version")),
		query:    strings.TrimSpace(c.Query("q")),
		limit:    20,
	}
	if f.kind != "" && f.kind != "apk" && f.kind != "ota" {
		return f, "kind must be apk or ota"
	}
	if f.platform != "" && f.platform != "android" && f.platform != "ios" {
		return f, "platform must be android or ios"
	}
	if f.status != "" && !containsString(buildJobStatuses, f.status) {
		return f, "status must be one of " + strings.Join(buildJobStatuses, ", ")
	}
	if len(f.version) > 128 || len(f.query) > 200 {
		return f, "version and q are too long"
	}
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > buildJobListMaxLimit {
			return f, fmt.Sprintf("limit must be between 1 and %d", buildJobListMaxLimit)
		}
		f.limit = value
	}
	if raw := strings.TrimSpace(c.Query("cursor")); raw != "" {
		at, id, err := decodeBuildCursor(raw)
		if err != nil {
			return f, "cursor is invalid"
		}
		f.cursorAt, f.cursorID, f.hasCursor = at, id, true
	}
	return f, ""
}

func encodeBuildCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%s", at.UnixNano(), id)))
}

func decodeBuildCursor(raw string) (time.Time, string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return time.Time{}, "", errors.New("cursor must have timestamp:id")
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Unix(0, nanos).UTC(), parts[1], nil
}

func (f buildJobListFilter) where(tenant string) (string, []any) {
	clauses := []string{"tenant_id=?"}
	args := []any{tenant}
	if f.kind != "" {
		clauses = append(clauses, "kind=?")
		args = append(args, f.kind)
	}
	if f.platform != "" {
		clauses = append(clauses, "platform=?")
		args = append(args, f.platform)
	}
	if f.status != "" {
		clauses = append(clauses, "status=?")
		args = append(args, f.status)
	}
	if f.version != "" {
		clauses = append(clauses, "version=?")
		args = append(args, f.version)
	}
	if f.query != "" {
		pattern := "%" + f.query + "%"
		// claimed_by 是构建机名称，两个 *_machine_id 是登记 id：按哪一个搜都要搜得到
		clauses = append(clauses, "(id LIKE ? OR version LIKE ? OR git_ref LIKE ? OR commit_sha LIKE ? OR claimed_by LIKE ? OR claimed_machine_id LIKE ? OR signing_machine_id LIKE ?)")
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
	}
	return strings.Join(clauses, " AND "), args
}

func (s *server) buildJobDetail(c *gin.Context) {
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	view := buildJobViewWithMachines(job, s.machineNamesForView(c.Request.Context()))
	if jobDelivery(job) == iosDeliveryIPA {
		latest, err := s.iosLatestBuildNumber(c.Request.Context(), tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to load the build")
			return
		}
		view["ipaDelivery"] = ipaDeliveryView(job, latest)
	}
	c.JSON(http.StatusOK, view)
}

// machineNamesForView 给任务视图补签名闸名称。读不到登记不影响列表：名称只是显示用的，
// id 仍然在视图里。
func (s *server) machineNamesForView(ctx context.Context) map[string]string {
	registry, err := s.machineRegistry(ctx)
	if err != nil {
		slog.Warn("build job view has no machine names: the machine registry cannot be read", "error", err)
		return nil
	}
	return registry.names()
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
	reason := clipRunes(strings.TrimSpace(body.Reason), 500)
	ctx := c.Request.Context()
	now := time.Now().UTC()
	// 取消还没开工的、正在构建的、或者已经构建完还没开始签的。signing 的签名闸可能正在签，
	// 要放弃走 force-fail。
	//
	// running 原先不让取消，理由是"停不下构建机上那个进程，状态会骗人"。其实停得下：被取消的
	// claimed / running 任务，构建机下一次心跳就拿到 409 BUILD_ATTEMPT_STALE，经 sudo 给执行
	// 进程发 SIGTERM，执行进程连同它的进程组一起结束（agent.go runJob、runnerexec.go）；之后
	// 它对这条任务的任何上报也都是 409。不让取消的代价倒是真的：2026-09-23 一条 iOS 任务的
	// pnpm install 挂死 50 分钟，心跳照常、控制台停不掉，只能有人上 Mac 去 pkill。
	// 已经交付的未签名包与 SBOM 随取消一起删。
	_, matched, err := s.transitionBuildJob(ctx, c.Param("id"), jobTransition{
		Where:     `WHERE id=? AND tenant_id=? AND ((kind='apk' AND status IN (` + sqlCancelableAPK + `)) OR (kind='ota' AND status IN (` + sqlCancelableOTA + `)))`,
		WhereArgs: []any{c.Param("id"), tenantID(c)},
		Set:       `status='canceled',failure_reason=?,updated_at=?`,
		SetArgs:   []any{reason, now},
		Release:   releaseAllDeliveries,
		After: func(tx *sql.Tx, _ lockedJob) error {
			return insertAudit(ctx, tx, newAudit(tenantID(c), actor(c), "build_job_cancel", "build-job", c.Param("id"), reason, requestID(c), map[string]any{"jobId": c.Param("id")}))
		},
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to cancel the build")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_CANCELABLE", "Only queued, claimed, running or built builds can be canceled")
		return
	}
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, buildJobViewWithMachines(job, s.machineNamesForView(ctx)))
}

// forceFailBuildJob 放弃一条卡在「签名中」的任务（设计「机器挂了怎么办」最后一行）。
//
// signing 不能直接取消：签名闸可能正在签，取消之后它照样会交回一个已签名包。强制判失败
// 之后，签名闸的迟到上报（心跳、上传、完成）都按状态与签名编号拒绝，不会落成发布记录。
func (s *server) forceFailBuildJob(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_JOB", "reason and confirm=true are required")
		return
	}
	reason := clipRunes(strings.TrimSpace(body.Reason), 400)
	ctx := c.Request.Context()
	now := time.Now().UTC()
	// 未签名包、SBOM 与签名闸可能已经交回的已签名包都不会再有人用，随强制失败一起删
	_, matched, err := s.transitionBuildJob(ctx, c.Param("id"), jobTransition{
		Where:     `WHERE id=? AND tenant_id=? AND kind='apk' AND status IN (` + sqlStatusList(buildJobEventFrom(eventAdminForceFail, jobKindAPK)) + `)`,
		WhereArgs: []any{c.Param("id"), tenantID(c)},
		Set:       `status='failed',failure_reason=?,updated_at=?`,
		SetArgs:   []any{clipRunes("管理员强制判失败："+reason, 500), now},
		Release:   releaseAllDeliveries,
		After: func(tx *sql.Tx, locked lockedJob) error {
			return insertAudit(ctx, tx, newAudit(tenantID(c), actor(c), "build_job_force_fail", "build-job", c.Param("id"), reason, requestID(c),
				map[string]any{"jobId": c.Param("id"), "signingMachineId": nullableString(locked.SigningMachineID.String), "signAttempt": locked.SignAttempt}))
		},
	})
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to fail the build")
		return
	}
	if !matched {
		problem(c, http.StatusConflict, "BUILD_JOB_NOT_FORCE_FAILABLE", "Only builds that are being signed can be force-failed; cancel queued, claimed, running or built builds instead")
		return
	}
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, buildJobViewWithMachines(job, s.machineNamesForView(ctx)))
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
