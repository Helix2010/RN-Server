package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	// machinePausedReasonMaxRunes：一句话，够说清"磁盘只剩 12 GiB，低于 40"
	machinePausedReasonMaxRunes = 200
	// machineUpgradeErrorMaxRunes：升级程序写的一句话，比暂停原因宽一点（它可能带上
	// 下载或校验失败的细节）
	machineUpgradeErrorMaxRunes = 300
	maxAppleTeamReports         = 64
	maxBundleIDsPerTeam         = 64
	appleSigningNeverEnds       = ""
)

// 上传 Key 的只读探测结果。取值由代理报，服务端只校验是不是这几个之一。
const (
	uploadProbeUnknown   = ""
	uploadProbeOK        = "ok"
	uploadProbeForbidden = "forbidden"
	uploadProbeError     = "error"
	// uploadProbeMissing：这台机器上没装这个 Team 的上传 Key。以前开着上传的机器缺 Key 就干脆
	// 不报这个 Team（于是也领不到它的任务），自助上传的租户根本不交上传 Key，所以要能报"没有"，
	// 并且和"装了但探不通"（error）分开
	uploadProbeMissing = "missing"
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
	// UploadProbe 是启动时那次只读探测的结果（设计 §4.3 第 3 条）：ok=这把上传 Key 能用
	// Build Uploads 那套端点；forbidden=角色不够（Developer 不行就换 App Manager 的 Team Key）；
	// error=探不通（网络、Key 坏了）；missing=没装这个 Team 的上传 Key。空=没探（这台机器没开上传）。
	//
	// 记它的意义在于**第一次构建之前**就知道传不上去：上传发生在一次构建的最后一步，
	// 等到那时才发现权限不够，已经烧掉了一个 build 号和半小时。
	UploadProbe string `json:"uploadProbe"`
}

// machineLiveness 是表里的一行。
type machineLiveness struct {
	MachineID   string
	LastSeenAt  time.Time
	AgentCommit string
	OS          string
	Platforms   []string
	// Capabilities 是这次认领自报的能力（例如 ios-ipa-delivery）。旧版代理不报
	Capabilities     []string
	AppleTeams       []appleTeamReport
	SigningExpiresAt sql.NullTime
	FreeGB           sql.NullInt64
	// PausedReason 是机器自己报的"我现在不领活"的原因（磁盘不够等）。空=没暂停。
	// 暂停的机器**仍然算在线**：它每 10 秒还来问一次，只是带着 paused。把它显示成离线
	// 会把"磁盘满了"和"关机了"混成一件事，而这两件事要做的处理完全不同
	PausedReason string
	// UpgradeError 是上一次自升级失败的原因。空=没失败过。升级是 root 那个程序做的，
	// 它失败时代理还在跑旧版——不报上来的话，控制台看到的只是"版本一直追不上审批值"
	UpgradeError string
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
		switch report.UploadProbe {
		case uploadProbeUnknown, uploadProbeOK, uploadProbeForbidden, uploadProbeError, uploadProbeMissing:
		default:
			return nil, false
		}
		out = append(out, appleTeamReport{TeamID: team, BundleIDs: bundles, ExpiresAt: expires, UploadProbe: report.UploadProbe})
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
	var capabilities any
	if live.Capabilities != nil {
		if encoded, err := json.Marshal(live.Capabilities); err == nil {
			capabilities = string(encoded)
		}
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
		`INSERT INTO build_machine_liveness(machine_id,last_seen_at,agent_commit,os,platforms,capabilities,apple_teams,signing_expires_at,free_gb,upgrade_error,paused_reason,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON DUPLICATE KEY UPDATE
		   last_seen_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(last_seen_at), last_seen_at),
		   agent_commit=VALUES(agent_commit),os=VALUES(os),platforms=VALUES(platforms),capabilities=VALUES(capabilities),
		   apple_teams=VALUES(apple_teams),signing_expires_at=VALUES(signing_expires_at),free_gb=VALUES(free_gb),
		   upgrade_error=VALUES(upgrade_error),paused_reason=VALUES(paused_reason),
		   updated_at=IF(last_seen_at < VALUES(last_seen_at) - INTERVAL `+machineLivenessThrottle+` SECOND, VALUES(updated_at), updated_at)`,
		live.MachineID, now, nullableString(live.AgentCommit), nullableString(live.OS), string(platforms),
		capabilities, teams, live.SigningExpiresAt, live.FreeGB, nullableString(live.UpgradeError), nullableString(live.PausedReason), now); err != nil {
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
		`SELECT machine_id,last_seen_at,agent_commit,os,platforms,capabilities,apple_teams,signing_expires_at,free_gb,upgrade_error,paused_reason FROM build_machine_liveness`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]machineLiveness{}
	for rows.Next() {
		var live machineLiveness
		var agentCommit, os, upgradeError, paused sql.NullString
		var platforms, capabilities, teams []byte
		if err := rows.Scan(&live.MachineID, &live.LastSeenAt, &agentCommit, &os, &platforms, &capabilities, &teams,
			&live.SigningExpiresAt, &live.FreeGB, &upgradeError, &paused); err != nil {
			return nil, err
		}
		live.UpgradeError = upgradeError.String
		live.PausedReason = paused.String
		live.LastSeenAt = live.LastSeenAt.UTC()
		live.AgentCommit = agentCommit.String
		live.OS = os.String
		// 解析不了当作没报：这一列是机器自报的展示值，一行坏 JSON 不该让控制台整页 500
		if len(platforms) > 0 {
			_ = json.Unmarshal(platforms, &live.Platforms)
		}
		if len(capabilities) > 0 {
			_ = json.Unmarshal(capabilities, &live.Capabilities)
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
	// Uploadable：报过它的机器里有一台这个 Team 的上传 Key 装着、Apple 没拒（ok 或 error）。
	// 全托管的任务只派给这样的机器（ios_delivery.go 的 uploadablePairs 是同一个判据）
	Uploadable       bool
	UploadableOnline bool
	// IPACapable：报过它的机器里有一台的构建机程序能把 .ipa 交回服务端。自助上传的任务只派给这样的机器
	IPACapable       bool
	IPACapableOnline bool
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
		online := live.online(now)
		coverage.Reported = true
		coverage.Online = coverage.Online || online
		// 按"登记语义"判：登记在用、最近一次上报里有，就算数；在不在线只影响提示
		if containsString(uploadablePairs(live.AppleTeams), want) {
			coverage.Uploadable = true
			coverage.UploadableOnline = coverage.UploadableOnline || online
		}
		if containsString(live.Capabilities, machineCapabilityIPADelivery) {
			coverage.IPACapable = true
			coverage.IPACapableOnline = coverage.IPACapableOnline || online
		}
	}
	return coverage, nil
}

// iosSigningTarget 是一个租户要的签名材料：哪个 Team、哪个 bundle id。
type iosSigningTarget struct {
	TenantID string
	Slug     string
	TeamID   string
	BundleID string
}

// iosSigningTargets 列出所有登记了 iOS 发布身份的租户。
//
// 控制台拿它与每台机器的自报盘点求差集，得出"这台缺 <租户> 的签名材料"。这是**池子**
// 这个不变量唯一的监视器：设计里每台 Mac 都应该能打任何租户的包，而材料是人一台台导进
// 钥匙串的——漏一台就漏一个租户，不看差集的话要等到那个租户排任务时才发现。
func (s *server) iosSigningTargets(ctx context.Context) ([]iosSigningTarget, error) {
	// 只算还在的租户：删掉的租户留下的 release.ios 会在每台机器上变成一条永远补不上的
	// 缺口，而那个租户再也不会排任务
	rows, err := s.db.QueryContext(ctx,
		`SELECT c.tenant_id,t.slug,c.config_value FROM app_configs c
		  JOIN tenants t ON t.id=c.tenant_id AND t.deleted=0
		  WHERE c.config_key=? AND c.tenant_id<>0`, releaseIOSIdentityConfigKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []iosSigningTarget{}
	for rows.Next() {
		var target iosSigningTarget
		var raw []byte
		if err := rows.Scan(&target.TenantID, &target.Slug, &raw); err != nil {
			return nil, err
		}
		// 一条读不出来的配置不该让整页打不开：它在别处（排队、认领）会自己报出来
		identity, err := parseIOSReleaseIdentity(raw)
		if err != nil || identity.AppleTeamID == "" || identity.BundleID == "" {
			continue
		}
		target.TeamID, target.BundleID = identity.AppleTeamID, identity.BundleID
		out = append(out, target)
	}
	return out, rows.Err()
}

// machineLivenessView 是控制台机器卡片要的那一块。
//
// 恒有值（机器从没报到过时各项为 null / 空数组）：一个新字段不该有能力让整页打不开，
// 而"从来没上线过"本身就是要显示出来的状态。
func machineLivenessView(live machineLiveness, machine gin.H, wanted []iosSigningTarget, now time.Time) gin.H {
	role, _ := machine["role"].(string)
	platforms, _ := machine["platforms"].([]string)
	view := gin.H{
		"lastSeenAt":  nil,
		"online":      false,
		"agentCommit": nil,
		"freeGb":      nil,
		"appleTeams":  []gin.H{},
		// capabilities 是机器自报的能力（例如能不能把 .ipa 交回平台）
		"capabilities": []string{},
		// missingTenants 是这台机器缺材料的租户（只对能打 iOS 的构建机算）
		"missingTenants":   []gin.H{},
		"signingExpiresAt": nil,
		"pausedReason":     nil,
		"upgradeError":     nil,
	}
	if live.MachineID != "" {
		view["lastSeenAt"] = live.LastSeenAt.UTC().Format(time.RFC3339)
		view["online"] = live.online(now)
		view["agentCommit"] = nullableString(live.AgentCommit)
		view["pausedReason"] = nullableString(live.PausedReason)
		view["upgradeError"] = nullableString(live.UpgradeError)
		if live.Capabilities != nil {
			view["capabilities"] = live.Capabilities
		}
		if live.FreeGB.Valid {
			view["freeGb"] = live.FreeGB.Int64
		}
		if live.SigningExpiresAt.Valid {
			view["signingExpiresAt"] = live.SigningExpiresAt.Time.UTC().Format(time.RFC3339)
		}
		teams := make([]gin.H, 0, len(live.AppleTeams))
		for _, team := range live.AppleTeams {
			teams = append(teams, gin.H{
				"teamId": team.TeamID, "bundleIds": team.BundleIDs,
				"expiresAt": nullableString(team.ExpiresAt), "uploadProbe": nullableString(team.UploadProbe),
			})
		}
		view["appleTeams"] = teams
	}
	// 差集只对"能打 iOS 的构建机"算：签名闸与只打 Android 的机器没有这个概念，
	// 给它们算一份缺口只会让控制台上出现一片与它们无关的黄色
	if role != machineRoleBuilder || !containsString(platforms, buildPlatformIOS) {
		return view
	}
	held := signingPairs(live.AppleTeams)
	missing := []gin.H{}
	for _, target := range wanted {
		if containsString(held, strings.ToUpper(target.TeamID)+"."+target.BundleID) {
			continue
		}
		missing = append(missing, gin.H{
			"tenantId": target.TenantID, "slug": target.Slug,
			"teamId": target.TeamID, "bundleId": target.BundleID,
		})
	}
	view["missingTenants"] = missing
	return view
}
