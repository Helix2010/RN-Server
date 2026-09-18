package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// 构建机的「最近在线」与自报盘点（设计 ios-mac-builders-home-network-2026-09-18 §5.2、§5.4）。
//
// 登记（app_configs 的 build.machines）回答的是"这台机器是谁、能不能鉴权、允许干哪些平台"，
// 由平台管理员维护，很少变。这里回答的是两个高频、由机器自己说了算的事实：
//
//   - **最近在线**：家里的 Mac 会睡着、会掉线、会被拔网线。
//   - **手上有哪些 Team 的签名材料**：池子模型下每台 Mac 都应该能打任何租户的包，
//     所以登记里没有"这台能打哪些 Team"这一列（它的正确值永远是"全部"）；真正要
//     回答的是"哪台现在缺哪个 Team"，而这件事只有 Mac 自己知道。
//
// **自报是运维仪表，不是安全边界**：持有机器令牌的人可以谎报手里有全部 Team 的材料，
// 领走任一租户的任务再让它失败。这不是新增面（持令牌本来就能认领并失败任意任务），
// 但因此这张表的值不用于任何授权判断——它只决定"派不派这条任务给这台机器"和控制台
// 显示什么。
const (
	// machineOfflineAfter：超过它没有认领也没有心跳就算掉线。代理每 10 秒认领一次、
	// 每 30 秒心跳一次，写入按 60 秒节流，所以 5 分钟没有任何写入是真的没在跑
	machineOfflineAfter = 5 * time.Minute
	// machineLivenessThrottle：认领每 10 秒一次，不值得每次都写一行。节流靠 IF()——
	// ON DUPLICATE KEY UPDATE 没有 WHERE，只能让新值在窗口内等于旧值，让整条语句变成空转。
	// 写成字符串是因为它只出现在 SQL 常量里，不是参数
	machineLivenessThrottle = "60"
	// 自报盘点的规模上限：它会被展开成认领 SQL 的 IN 列表。租户数是几十的量级，
	// 一台 Mac 上的 Team 数不会超过它
	maxAppleTeamReports   = 64
	maxBundleIDsPerTeam   = 64
	appleSigningNeverEnds = ""
)

// 机器自报的操作系统。装机脚本、自升级归档（builder-darwin-arm64.tar.gz）与控制台
// 的安装命令都按它分；取值与 runtime.GOOS 一致。
const (
	machineOSDarwin = "darwin"
	machineOSLinux  = "linux"
)

// appleTeamReport 是一台 Mac 自报的一个 Team 的签名材料：证书在钥匙串里、描述文件在
// profiles/<TEAMID>/ 下、上传 Key 在 /var/rn-build-upload/<TEAMID>/ 都齐了才报。
type appleTeamReport struct {
	TeamID string `json:"teamId"`
	// BundleIDs 是这个 Team 下有可用描述文件的 bundle id。任务要打的那个不在里面，
	// 这台机器就领不走它——描述文件是按 bundle id 发的，缺一个就签不出来
	BundleIDs []string `json:"bundleIds"`
	// ExpiresAt 是这个 Team 里最早到期的证书或描述文件（RFC3339）。空=没报
	ExpiresAt string `json:"expiresAt"`
}

// machineLiveness 是表里的一行。
type machineLiveness struct {
	MachineID        string
	LastSeenAt       time.Time
	AgentCommit      string
	OS               string
	Platforms        []string
	AppleTeams       []appleTeamReport
	SigningExpiresAt sql.NullTime
	FreeGB           sql.NullInt64
}

func (l machineLiveness) online(now time.Time) bool {
	return now.Sub(l.LastSeenAt) <= machineOfflineAfter
}

// signingPairs 把自报盘点摊平成 "TEAMID.bundleid" 的集合：认领 SQL 拿它当 IN 列表，
// 控制台拿它对租户求差集。Team ID 归一成大写，与 release.ios 里存的形状一致。
func signingPairs(reports []appleTeamReport) []string {
	out := make([]string, 0, len(reports))
	for _, report := range reports {
		team := strings.ToUpper(strings.TrimSpace(report.TeamID))
		for _, bundle := range report.BundleIDs {
			out = append(out, team+"."+strings.TrimSpace(bundle))
		}
	}
	return out
}

// normalizeAppleTeamReports 校验并归一自报盘点。返回 false 表示请求体不合法——
// 认领是每 10 秒一次的高频路径，不合法的自报当场 400，不进库。
func normalizeAppleTeamReports(reports []appleTeamReport) ([]appleTeamReport, bool) {
	if len(reports) > maxAppleTeamReports {
		return nil, false
	}
	seen := map[string]bool{}
	out := make([]appleTeamReport, 0, len(reports))
	for _, report := range reports {
		team := strings.ToUpper(strings.TrimSpace(report.TeamID))
		if !appleTeamIDPattern.MatchString(team) || seen[team] {
			return nil, false
		}
		seen[team] = true
		if len(report.BundleIDs) > maxBundleIDsPerTeam {
			return nil, false
		}
		bundles := make([]string, 0, len(report.BundleIDs))
		for _, bundle := range report.BundleIDs {
			bundle = strings.TrimSpace(bundle)
			if !iosBundleIDPattern.MatchString(bundle) || containsString(bundles, bundle) {
				return nil, false
			}
			bundles = append(bundles, bundle)
		}
		expires := strings.TrimSpace(report.ExpiresAt)
		if expires != appleSigningNeverEnds {
			at, err := time.Parse(time.RFC3339, expires)
			if err != nil {
				return nil, false
			}
			expires = at.UTC().Format(time.RFC3339)
		}
		out = append(out, appleTeamReport{TeamID: team, BundleIDs: bundles, ExpiresAt: expires})
	}
	return out, true
}

// earliestSigningExpiry 是自报盘点里最早的那个到期日：控制台在它进入 30 天内时标黄。
func earliestSigningExpiry(reports []appleTeamReport) sql.NullTime {
	var earliest sql.NullTime
	for _, report := range reports {
		if report.ExpiresAt == appleSigningNeverEnds {
			continue
		}
		at, err := time.Parse(time.RFC3339, report.ExpiresAt)
		if err != nil {
			continue
		}
		if !earliest.Valid || at.Before(earliest.Time) {
			earliest = sql.NullTime{Valid: true, Time: at.UTC()}
		}
	}
	return earliest
}

// recordMachineLiveness 记一次认领带来的自报。
//
// 调用点在 GET_LOCK 与事务**之外**、在"队列空回 204"提前返回**之前**：认领这条路径
// 上绝大多数请求都是空转（队列是空的），而"这台机器还活着、手上有这些材料"恰恰是
// 那些空转唯一的产出。写失败只记日志，不影响认领——在线状态是仪表，认领是主路径。
func (s *server) recordMachineLiveness(ctx context.Context, live machineLiveness) {
	platforms, err := json.Marshal(live.Platforms)
	if err != nil {
		platforms = []byte("null")
	}
	var teams any
	if live.AppleTeams != nil {
		encoded, err := json.Marshal(live.AppleTeams)
		if err == nil {
			teams = string(encoded)
		}
	}
	now := live.LastSeenAt
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO build_machine_liveness(machine_id,last_seen_at,agent_commit,os,platforms,apple_teams,signing_expires_at,free_gb,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		   last_seen_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(last_seen_at), last_seen_at),
		   agent_commit=VALUES(agent_commit),os=VALUES(os),platforms=VALUES(platforms),
		   apple_teams=VALUES(apple_teams),signing_expires_at=VALUES(signing_expires_at),free_gb=VALUES(free_gb),
		   updated_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(updated_at), updated_at)`,
		live.MachineID, now, nullableString(live.AgentCommit), nullableString(live.OS), string(platforms),
		teams, live.SigningExpiresAt, live.FreeGB, now); err != nil {
		slog.Warn("unable to record build machine liveness", "machineId", live.MachineID, "error", err)
	}
}

// touchMachineLiveness 是心跳那一条：只动"最近在线"，不碰自报的盘点。
//
// 心跳的请求体里没有盘点（它是每 30 秒一次的进度上报），用 recordMachineLiveness 会把
// 认领时报上来的 apple_teams 抹成 NULL——控制台上这台机器会在构建期间"突然什么材料都没有"。
func (s *server) touchMachineLiveness(ctx context.Context, machineID string, now time.Time) {
	if strings.TrimSpace(machineID) == "" {
		return
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO build_machine_liveness(machine_id,last_seen_at,updated_at) VALUES(?,?,?)
		 ON DUPLICATE KEY UPDATE
		   last_seen_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(last_seen_at), last_seen_at),
		   updated_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(updated_at), updated_at)`,
		machineID, now, now); err != nil {
		slog.Warn("unable to record build machine heartbeat liveness", "machineId", machineID, "error", err)
	}
}

// machineLivenessByID 读全表。行数等于登记过的机器数（上限 64），一次全取比按 id 查几十次便宜。
func (s *server) machineLivenessByID(ctx context.Context) (map[string]machineLiveness, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT machine_id,last_seen_at,agent_commit,os,platforms,apple_teams,signing_expires_at,free_gb FROM build_machine_liveness`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]machineLiveness{}
	for rows.Next() {
		var live machineLiveness
		var agentCommit, os sql.NullString
		var platforms, teams []byte
		if err := rows.Scan(&live.MachineID, &live.LastSeenAt, &agentCommit, &os, &platforms, &teams,
			&live.SigningExpiresAt, &live.FreeGB); err != nil {
			return nil, err
		}
		live.LastSeenAt = live.LastSeenAt.UTC()
		live.AgentCommit = agentCommit.String
		live.OS = os.String
		// 解析不了当作没报：这一列是机器自报的展示值，一行坏 JSON 不该让控制台整页 500
		if len(platforms) > 0 {
			_ = json.Unmarshal(platforms, &live.Platforms)
		}
		if len(teams) > 0 {
			_ = json.Unmarshal(teams, &live.AppleTeams)
		}
		out[live.MachineID] = live
	}
	return out, rows.Err()
}

// iosSigningCoverage 回答"池子里有没有哪台 Mac 手上有这个租户的签名材料"，
// 以及"其中还有没有在线的"。排队时用（设计 §5.2 的排队那一行）。
type iosSigningCoverage struct {
	// Reported：有 active 的 iOS 构建机在最近一次认领里报过这个 (Team, bundleId)。
	// 没有任何一台报过 = 材料没装，排进去永远没人领，当场 409。
	Reported bool
	// Online：报过它的机器里至少有一台还在线。都不在线**照常排队**——家里的 Mac
	// 会睡着、会掉线，队列要能等它回来（这是已定的决策，不是尽力而为）。
	Online bool
}

func (s *server) iosSigningCoverage(ctx context.Context, registry buildMachinesDoc, teamID, bundleID string, now time.Time) (iosSigningCoverage, error) {
	var coverage iosSigningCoverage
	rows, err := s.machineLivenessByID(ctx)
	if err != nil {
		return coverage, err
	}
	want := strings.ToUpper(strings.TrimSpace(teamID)) + "." + strings.TrimSpace(bundleID)
	for _, m := range registry.Machines {
		if m.Role != machineRoleBuilder || m.Status != machineStatusActive || !m.canBuild(buildPlatformIOS) {
			continue
		}
		live, ok := rows[m.ID]
		if !ok || !containsString(signingPairs(live.AppleTeams), want) {
			continue
		}
		coverage.Reported = true
		if live.online(now) {
			coverage.Online = true
			return coverage, nil
		}
	}
	return coverage, nil
}
