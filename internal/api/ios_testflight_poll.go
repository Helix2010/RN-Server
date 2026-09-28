package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/ascapi"
)

// 全托管 iOS 构建在 App Store Connect 上的处理状态（设计 ios-platform-testflight-upload-2026-09-23 §3.3）。
//
// 打包机把包传进 Apple 就算完成，之后 Apple 还要处理十几分钟到半小时：VALID 才能进测试组，INVALID /
// FAILED 要有人去看原因。原来只有人点「同步」才看得到，现在回收循环每分钟看一眼到期该查的构建，用
// 租户交的 ASC 密钥**只读**地查（2026-09-28 决定：提审、测试组、公开链接仍由人在 ASC 上操作，服务端不写
// Apple），结果写在任务行的 testflight_state 上，构建列表直接显示。
//
// 节奏：刚完成的构建 2 分钟后查第一次，之后 5、15、30、60 分钟；到终态（VALID/INVALID/FAILED）或完成
// 24 小时还查不到（NOT_FOUND）就不再查，只看最近 7 天完成的。一个租户一轮只调一次 LatestBuilds，按
// build 号对上这一轮到期的所有构建。密钥被拒时整个租户 6 小时后再试；别的错误（网络、Apple 5xx、429 限流）
// 按每条构建自己的节奏退避，最慢一小时一次，远低于 Apple 按密钥计的限额。没交密钥的租户一次请求都不发，
// 记 unavailable，6 小时后再看一眼（期间交了密钥就会开始查）。
//
// 429 没有单独识别：那要改 internal/ascapi，而它是打包机的构建输入（ios-upload 用它），改了就要重签打包机。
//
// 多个平台进程同时跑时同一个构建可能被查两次：只是多一次只读请求，不值得为它加锁。

const (
	testFlightPollWindow       = 7 * 24 * time.Hour
	testFlightNotFoundAfter    = 24 * time.Hour
	testFlightTenantBackoff    = 6 * time.Hour
	testFlightPollBatch        = 200
	testFlightLatestBuildLimit = 50
	testFlightStateNotFound    = "NOT_FOUND"
	testFlightUnavailableNoKey = "no-asc-key"
	testFlightUnavailableNoID  = "no-ios-identity"
)

// testFlightCheckDelays 是第 n 次查之后隔多久再查（n 从 1 起，超出的都按最后一档）。
var testFlightCheckDelays = []time.Duration{2 * time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}

type testFlightState struct {
	BuildID         string `json:"buildId,omitempty"`
	ProcessingState string `json:"processingState,omitempty"`
	Expired         bool   `json:"expired,omitempty"`
	ExpirationDate  string `json:"expirationDate,omitempty"`
	UploadedDate    string `json:"uploadedDate,omitempty"`
	CheckedAt       string `json:"checkedAt,omitempty"`
	NextCheckAt     string `json:"nextCheckAt"`
	Checks          int    `json:"checks"`
	FinalAt         string `json:"finalAt,omitempty"`
	LastError       string `json:"lastError,omitempty"`
	Unavailable     string `json:"unavailable,omitempty"`
}

func parseTestFlightState(raw []byte) testFlightState {
	var state testFlightState
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &state)
	}
	return state
}

// testFlightFinal：Apple 的处理到头了（能测 / 被拒 / 失败），之后不会再变。
func testFlightFinal(processingState string) bool {
	switch processingState {
	case "VALID", "INVALID", "FAILED":
		return true
	}
	return false
}

func testFlightDelay(checks int) time.Duration {
	if checks < 1 {
		checks = 1
	}
	if checks > len(testFlightCheckDelays) {
		checks = len(testFlightCheckDelays)
	}
	return testFlightCheckDelays[checks-1]
}

// testFlightStateView 是构建列表上的一块；不是全托管 iOS 构建、或者还没查过的是 null。
func testFlightStateView(j buildJob) any {
	if len(j.TestFlightState) == 0 || j.Platform != buildPlatformIOS || jobDelivery(j) != iosDeliveryTestFlight {
		return nil
	}
	state := parseTestFlightState(j.TestFlightState)
	return map[string]any{
		"processingState": nullableString(state.ProcessingState),
		"expired":         state.Expired,
		"expirationDate":  nullableString(state.ExpirationDate),
		"checkedAt":       nullableString(state.CheckedAt),
		"final":           state.FinalAt != "",
		"lastError":       nullableString(state.LastError),
		"unavailable":     nullableString(state.Unavailable),
	}
}

type testFlightDue struct {
	id, tenant string
	build      int
	done       time.Time
	state      testFlightState
}

// pollTestFlightStates 查一轮到期的全托管构建，返回这一轮写了状态的任务 id（给测试与日志用）。
func (s *server) pollTestFlightStates(ctx context.Context, now time.Time) []string {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,tenant_id,build_number,heartbeat_at,testflight_state FROM build_jobs
		  WHERE kind='`+jobKindAPK+`' AND platform='`+buildPlatformIOS+`' AND (delivery IS NULL OR delivery='`+iosDeliveryTestFlight+`')
		    AND status='`+jobSucceeded+`' AND heartbeat_at >= ?
		    AND (testflight_state IS NULL OR (JSON_EXTRACT(testflight_state,'$.finalAt') IS NULL
		         AND JSON_UNQUOTE(JSON_EXTRACT(testflight_state,'$.nextCheckAt')) <= ?))
		  ORDER BY heartbeat_at LIMIT `+strconv.Itoa(testFlightPollBatch),
		now.Add(-testFlightPollWindow), iso(now))
	if err != nil {
		slog.Error("cannot look for TestFlight builds to check", "error", err)
		return nil
	}
	byTenant := map[string][]testFlightDue{}
	tenants := []string{}
	for rows.Next() {
		var item testFlightDue
		var done sql.NullTime
		var raw []byte
		if err := rows.Scan(&item.id, &item.tenant, &item.build, &done, &raw); err != nil {
			slog.Error("cannot read a TestFlight build to check", "error", err)
			continue
		}
		if !done.Valid {
			continue
		}
		item.done, item.state = done.Time.UTC(), parseTestFlightState(raw)
		if _, seen := byTenant[item.tenant]; !seen {
			tenants = append(tenants, item.tenant)
		}
		byTenant[item.tenant] = append(byTenant[item.tenant], item)
	}
	rows.Close()
	written := []string{}
	for _, tenant := range tenants {
		if ctx.Err() != nil {
			break
		}
		written = append(written, s.pollTenantTestFlight(ctx, now, tenant, byTenant[tenant])...)
	}
	return written
}

func (s *server) pollTenantTestFlight(ctx context.Context, now time.Time, tenant string, due []testFlightDue) []string {
	// 整个租户这一轮查不了：没密钥、密钥坏了、被拒。每条都记下原因，6 小时后再看
	parkAll := func(unavailable, lastError string) []string {
		ids := []string{}
		for _, item := range due {
			state := item.state
			state.Unavailable, state.LastError = unavailable, lastError
			state.NextCheckAt = iso(now.Add(testFlightTenantBackoff))
			if s.saveTestFlightState(ctx, item, state, now) {
				ids = append(ids, item.id)
			}
		}
		return ids
	}
	client, record, err := s.ascClientFor(ctx, tenant)
	if err != nil {
		return parkAll("", err.Error())
	}
	if client == nil || record == nil {
		return parkAll(testFlightUnavailableNoKey, "")
	}
	appID := strings.TrimSpace(record.Value.AppID)
	if appID == "" {
		identity, err := s.iosReleaseIdentityRecord(ctx, tenant)
		if err != nil || identity == nil {
			return parkAll(testFlightUnavailableNoID, "")
		}
		app, err := client.FindApp(ctx, identity.Value.BundleID)
		if err != nil {
			return parkAll("", err.Error())
		}
		appID = app.ID
	}
	builds, err := client.LatestBuilds(ctx, appID, testFlightLatestBuildLimit)
	if errors.Is(err, ascapi.ErrKeyRejected) {
		return parkAll("", err.Error())
	}
	byVersion := map[string]ascapi.Build{}
	for _, build := range builds {
		if _, seen := byVersion[build.Version]; !seen {
			byVersion[build.Version] = build
		}
	}
	ids := []string{}
	for _, item := range due {
		state := item.state
		state.Unavailable = ""
		state.Checks++
		state.CheckedAt = iso(now)
		state.NextCheckAt = iso(now.Add(testFlightDelay(state.Checks)))
		if err != nil {
			// 别的错误（网络、Apple 5xx、429）：按这条构建自己的节奏退避
			state.LastError = err.Error()
		} else if build, found := byVersion[strconv.Itoa(item.build)]; found {
			state.LastError = ""
			state.BuildID, state.ProcessingState, state.Expired = build.ID, build.ProcessingState, build.Expired
			state.ExpirationDate, state.UploadedDate = optionalISO(build.ExpirationDate), optionalISO(build.UploadedDate)
			if testFlightFinal(build.ProcessingState) {
				state.FinalAt = iso(now)
			}
		} else {
			state.LastError = ""
			if now.Sub(item.done) >= testFlightNotFoundAfter {
				state.ProcessingState, state.FinalAt = testFlightStateNotFound, iso(now)
			}
		}
		if s.saveTestFlightState(ctx, item, state, now) {
			ids = append(ids, item.id)
			if state.FinalAt != "" && state.ProcessingState != "VALID" {
				// 被 Apple 拒了、处理失败、或者一天都查不到：要有人去 ASC 看原因
				s.auditNow(newAudit(tenant, reaperActor, "ios_testflight_processing_problem", "build-job", item.id,
					"App Store Connect reports a problem with an uploaded build", "",
					map[string]any{"jobId": item.id, "buildNumber": item.build, "processingState": state.ProcessingState, "buildId": nullableString(state.BuildID)}))
			}
		}
	}
	return ids
}

// saveTestFlightState 只在任务还是成功状态时写（不动 updated_at：这是 Apple 那边的观察，不是任务本身的变化）。
func (s *server) saveTestFlightState(ctx context.Context, item testFlightDue, state testFlightState, now time.Time) bool {
	raw, err := json.Marshal(state)
	if err != nil {
		return false
	}
	result, err := s.db.ExecContext(ctx, `UPDATE build_jobs SET testflight_state=? WHERE id=? AND status='`+jobSucceeded+`'`, raw, item.id)
	if err != nil {
		slog.Error("cannot record a TestFlight processing state", "job", item.id, "error", err)
		return false
	}
	affected, _ := result.RowsAffected()
	return affected > 0
}

func optionalISO(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return iso(*t)
}
