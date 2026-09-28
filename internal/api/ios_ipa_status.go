package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 自助上传的 .ipa 交出去之后（设计 ios-tenant-delivery-tiers-2026-09-24 §3.7、§3.8）。
//
// 平台手里没有租户的 Key，看不到 Apple 那边发生了什么：传没传、处理完没有、审核过没过。
// 所以进展靠租户在控制台上标记，记在任务行的 delivery_state 上：
//
//   - uploaded：租户已经传进 App Store Connect。交付件从这一刻起 7 天后清理（不再需要）；
//   - installable：审核过了、测试员装得上。版本策略只能把最低支持版本调到这样的版本；
//   - rejected：Apple 拒了（上传校验或审核）。拒信原文贴回来，平台才看得见问题出在哪。
//
// 公开链接跨 build 不变，所以"链接填好了"不代表新 build 能装，要以 installable 为准。

const (
	iosIPAStatusUploaded    = "uploaded"
	iosIPAStatusInstallable = "installable"
	iosIPAStatusRejected    = "rejected"
	// iosIPARetention：交付件保留这么久（从出包算）；租户标了 uploaded 之后再留 iosIPAUploadedRetention
	iosIPARetention         = 30 * 24 * time.Hour
	iosIPAUploadedRetention = 7 * 24 * time.Hour
	// testFlightBuildLifetime：TestFlight build 从上传起 90 天过期
	testFlightBuildLifetime = 90 * 24 * time.Hour
	iosIPARejectionMaxRunes = 2000
)

type iosDeliveryState struct {
	UploadedAt    string `json:"uploadedAt,omitempty"`
	UploadedBy    string `json:"uploadedBy,omitempty"`
	InstallableAt string `json:"installableAt,omitempty"`
	InstallableBy string `json:"installableBy,omitempty"`
	Rejection     string `json:"rejection,omitempty"`
	RejectedAt    string `json:"rejectedAt,omitempty"`
	PurgedAt      string `json:"purgedAt,omitempty"`
}

func parseIOSDeliveryState(raw []byte) iosDeliveryState {
	var state iosDeliveryState
	if len(raw) > 0 {
		// 读坏了当作没有标记：这是给人看的进展，一行坏 JSON 不该让构建列表打不开
		_ = json.Unmarshal(raw, &state)
	}
	return state
}

// iosLatestBuildNumber 是这个租户已经成功出过的最高 iOS build 号。
//
// 平台排队时要求版本号与 build 号**都**比上一个大（createBuildJob），所以更新的构建一出来，
// 旧交付件就没有再传的意义了：同一版本号下 App Store Connect 只收更高的 build，而更低的版本号
// 就算还能传，也只会让测试员装到一个旧版本。控制台据此把旧交付件标成"已被取代，只传最新的"。
func (s *server) iosLatestBuildNumber(ctx context.Context, tenant string) (int, error) {
	var latest sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(build_number) FROM build_jobs WHERE tenant_id=? AND platform='`+buildPlatformIOS+`' AND kind='`+jobKindAPK+`' AND status='`+jobSucceeded+`'`, tenant).Scan(&latest)
	return int(latest.Int64), err
}

// ipaDeliveryView 是自助上传任务在构建列表上多出来的一块；别的任务是 null。
func ipaDeliveryView(j buildJob, latest int) any {
	if jobDelivery(j) != iosDeliveryIPA {
		return nil
	}
	state := parseIOSDeliveryState(j.DeliveryState)
	succeeded := j.Status == jobSucceeded
	view := gin.H{
		"available":     succeeded && j.UnsignedObjectKey.Valid && j.UnsignedObjectKey.String != "",
		"sha256":        nullableString(j.UnsignedSHA256.String),
		"size":          nullableInt64(j.UnsignedSize),
		"uploadedAt":    nullableString(state.UploadedAt),
		"installableAt": nullableString(state.InstallableAt),
		"rejection":     nullableString(state.Rejection),
		"rejectedAt":    nullableString(state.RejectedAt),
		"purgedAt":      nullableString(state.PurgedAt),
		// Windows / Linux 上用 iTMSTransporter 上传要带的 AppStoreInfo.plist；旧版打包机不交，就是 null
		"appStoreInfo": appStoreInfoView(j, succeeded),
		"superseded":   succeeded && latest > j.BuildNumber,
		// 最早可能的过期时刻：TestFlight 从上传起算 90 天，上传不会早于出包，所以按出包算只会
		// 比真实的早——告警宁早勿晚。不用租户标的 uploadedAt：人往往是传完过几天才来标，
		// 按它算会比真实的晚
		"testflightExpiresNoEarlierThan": nil,
		"retainedUntil":                  nil,
	}
	if succeeded && j.HeartbeatAt.Valid {
		done := j.HeartbeatAt.Time.UTC()
		view["testflightExpiresNoEarlierThan"] = iso(done.Add(testFlightBuildLifetime))
		retained := done.Add(iosIPARetention)
		if at, err := time.Parse(time.RFC3339, state.UploadedAt); err == nil && at.Add(iosIPAUploadedRetention).Before(retained) {
			retained = at.Add(iosIPAUploadedRetention)
		}
		if state.PurgedAt == "" {
			view["retainedUntil"] = iso(retained)
		}
	}
	return view
}

func appStoreInfoView(j buildJob, succeeded bool) any {
	if !succeeded || !j.AppStoreInfoObjectKey.Valid || j.AppStoreInfoObjectKey.String == "" {
		return nil
	}
	return gin.H{"sha256": nullableString(j.AppStoreInfoSHA256.String), "size": nullableInt64(j.AppStoreInfoSize)}
}

// markIOSIPAStatus 让租户标记一个自助上传构建的进展。
func (s *server) markIOSIPAStatus(c *gin.Context) {
	var body struct {
		Status    string `json:"status"`
		Rejection string `json:"rejection"`
		Reason    string `json:"reason"`
		Confirm   bool   `json:"confirm"`
	}
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 ||
		(body.Status != iosIPAStatusUploaded && body.Status != iosIPAStatusInstallable && body.Status != iosIPAStatusRejected) {
		problem(c, http.StatusBadRequest, "INVALID_IOS_IPA_STATUS", "status (uploaded, installable or rejected), reason and confirm=true are required")
		return
	}
	rejection := clipRunes(strings.TrimSpace(sanitizeReportedText(body.Rejection)), iosIPARejectionMaxRunes)
	if body.Status == iosIPAStatusRejected && rejection == "" {
		problem(c, http.StatusBadRequest, "INVALID_IOS_IPA_STATUS", "rejection must carry Apple's message when status is rejected")
		return
	}
	ctx := c.Request.Context()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the status")
		return
	}
	defer tx.Rollback()
	var platform, kind, status string
	var delivery sql.NullString
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT platform,kind,status,delivery,delivery_state FROM build_jobs WHERE tenant_id=? AND id=? FOR UPDATE`,
		tenantID(c), c.Param("id")).Scan(&platform, &kind, &status, &delivery, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusNotFound, "BUILD_JOB_NOT_FOUND", "Build job not found")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to load the build")
		return
	}
	if platform != buildPlatformIOS || kind != jobKindAPK || delivery.String != iosDeliveryIPA || status != jobSucceeded {
		problem(c, http.StatusConflict, "IOS_IPA_STATUS_NOT_APPLICABLE", "只有成功出包的「自助上传」iOS 构建能标记进展")
		return
	}
	state := parseIOSDeliveryState(raw)
	now := iso(time.Now().UTC())
	switch body.Status {
	case iosIPAStatusUploaded:
		state.UploadedAt, state.UploadedBy = now, actor(c)
	case iosIPAStatusInstallable:
		// 能装了当然也传上去了；拒信作废
		if state.UploadedAt == "" {
			state.UploadedAt, state.UploadedBy = now, actor(c)
		}
		state.InstallableAt, state.InstallableBy = now, actor(c)
		state.Rejection, state.RejectedAt = "", ""
	case iosIPAStatusRejected:
		// 被拒了就不算能装：版本策略不能再以它为准
		state.Rejection, state.RejectedAt = rejection, now
		state.InstallableAt, state.InstallableBy = "", ""
	}
	encoded, _ := json.Marshal(state)
	if _, err := tx.ExecContext(ctx, `UPDATE build_jobs SET delivery_state=?,updated_at=? WHERE id=?`, encoded, time.Now().UTC(), c.Param("id")); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the status")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ios_ipa_status", "build-job", c.Param("id"), clipRunes(strings.TrimSpace(body.Reason), 500), requestID(c),
		map[string]any{"jobId": c.Param("id"), "status": body.Status, "rejection": nullableString(rejection)})
	if insertAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_SAVE_FAILED", "Unable to record the status")
		return
	}
	job, err := s.loadBuildJob(c, tenantID(c), c.Param("id"))
	if err != nil {
		return
	}
	latest, err := s.iosLatestBuildNumber(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_JOB_QUERY_FAILED", "Unable to read later builds")
		return
	}
	view := tenantJobView(job)
	view["ipaDelivery"] = ipaDeliveryView(job, latest)
	c.JSON(http.StatusOK, view)
}

// purgeExpiredIPADeliveries 清掉过了保留期的自助上传交付件：出包 30 天，或租户标了已上传之后 7 天。
//
// 只删对象、保留任务行与发布记录：发布记录是 OTA 基线与审计依据，删发布（purgeRelease）连记录
// 一起删，不是这里要的。对象键置空、delivery_state 记下清理时刻，下载接口据此说"过了保留期"。
func (s *server) purgeExpiredIPADeliveries(ctx context.Context, now time.Time) []string {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,tenant_id,unsigned_object_key,delivery_state,heartbeat_at FROM build_jobs
		  WHERE platform='`+buildPlatformIOS+`' AND kind='`+jobKindAPK+`' AND delivery='`+iosDeliveryIPA+`'
		    AND status='`+jobSucceeded+`' AND unsigned_object_key IS NOT NULL
		    AND (heartbeat_at < ? OR delivery_state IS NOT NULL)
		  ORDER BY heartbeat_at LIMIT 100`, now.Add(-iosIPAUploadedRetention))
	if err != nil {
		slog.Error("cannot look for expired self-upload packages", "error", err)
		return nil
	}
	type candidate struct {
		id, tenant, key string
		state           iosDeliveryState
	}
	var due []candidate
	for rows.Next() {
		var item candidate
		var raw []byte
		var done sql.NullTime
		if err := rows.Scan(&item.id, &item.tenant, &item.key, &raw, &done); err != nil {
			slog.Error("cannot read a self-upload package", "error", err)
			continue
		}
		item.state = parseIOSDeliveryState(raw)
		expired := done.Valid && now.Sub(done.Time) >= iosIPARetention
		if at, err := time.Parse(time.RFC3339, item.state.UploadedAt); err == nil && now.Sub(at) >= iosIPAUploadedRetention {
			expired = true
		}
		if expired {
			due = append(due, item)
		}
	}
	rows.Close()
	purged := []string{}
	for _, item := range due {
		// 只补一个 purgedAt，不整段写回：上面那次读在事务外，而每清一条都要同步删对象，两步之间
		// 租户可能刚标了"已可安装"——整段覆盖会把那个标记冲掉，强更阈值校验就当这一版没标过
		_, matched, err := s.transitionBuildJob(ctx, item.id, jobTransition{
			Where:     `WHERE id=? AND status='` + jobSucceeded + `' AND unsigned_object_key=?`,
			WhereArgs: []any{item.id, item.key},
			Set:       `delivery_state=JSON_SET(COALESCE(delivery_state,JSON_OBJECT()),'$.purgedAt',?),updated_at=?`,
			SetArgs:   []any{iso(now), now},
			Release:   releaseIOSPackage,
		})
		if err != nil {
			slog.Error("cannot purge an expired self-upload package", "job", item.id, "error", err)
			continue
		}
		if matched {
			purged = append(purged, item.id)
			s.auditNow(newAudit(item.tenant, reaperActor, "ios_ipa_purged", "build-job", item.id, "the self-upload package passed its retention period", "",
				map[string]any{"jobId": item.id, "uploadedAt": nullableString(item.state.UploadedAt)}))
		}
	}
	return purged
}

// iosMinVersionProblem 回答"把 iOS 最低支持版本调到这个值，会不会把用户锁在外面"，不会就返回空串。
//
// 只对自助上传的租户、只在调高时查。平台看不到 Apple 那边：包打出来了不等于测试员装得到。
// 最低支持版本一旦高过 TestFlight 上能装的版本，App 会把用户引到 TestFlight，而那里只有旧 build，
// 用户就被锁在外面了。能装的版本 = 全托管时期平台传上去的构建 + 租户标了"已可安装"的自助上传构建。
func (s *server) iosMinVersionProblem(ctx context.Context, tenant string, stored []byte, incoming map[string]any) (string, error) {
	wanted := text(versionPolicyShape(object(incoming["updatePolicy"])["minSupportedVersion"])["ios"], "")
	if !validVersion(wanted) {
		return "", nil
	}
	var previous map[string]any
	_ = json.Unmarshal(stored, &previous)
	before := text(versionPolicyShape(object(previous["updatePolicy"])["minSupportedVersion"])["ios"], "0.0.0")
	if validVersion(before) && compareVersion(wanted, before) <= 0 {
		return "", nil
	}
	mode, err := s.iosDeliveryModeFor(ctx, tenant)
	if err != nil || mode != iosDeliveryIPA {
		return "", err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT version,COALESCE(delivery,'`+iosDeliveryTestFlight+`'),delivery_state FROM build_jobs
		  WHERE tenant_id=? AND platform='`+buildPlatformIOS+`' AND kind='`+jobKindAPK+`' AND status='`+jobSucceeded+`'`, tenant)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	highest := ""
	for rows.Next() {
		var version, delivery string
		var raw []byte
		if err := rows.Scan(&version, &delivery, &raw); err != nil {
			return "", err
		}
		if delivery == iosDeliveryIPA && parseIOSDeliveryState(raw).InstallableAt == "" {
			continue
		}
		if validVersion(version) && (highest == "" || compareVersion(version, highest) > 0) {
			highest = version
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if highest != "" && compareVersion(wanted, highest) <= 0 {
		return "", nil
	}
	shown := highest
	if shown == "" {
		shown = "（还没有）"
	}
	return "这个租户是「自助上传」，平台看不到 TestFlight 上实际能装哪一版。iOS 最低支持版本 " + wanted +
		" 高过了标记为「已可安装」的最高版本 " + shown + "：调过去的话，App 会把用户引到 TestFlight，而那里还没有这一版，用户会被锁在外面。" +
		"等租户在构建列表上把这一版标成「已可安装」再调。", nil
}
