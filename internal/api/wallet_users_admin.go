package api

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 设计 RN-App/docs/design/device-account-aggregation-2026-09-07.md §4.2–4.5、§4.7（租户级）：
// 账号即钱包地址；"当前账号"只从 wallet_session 派生（一个安装实例同一时刻最多一条有效会话）；
// 登录历史看 wallet_user_installation；设备归并 ID 永不返回给租户。

// activeDeviceWindow：会话有效但设备超过 7 天没有心跳，按"会话有效 · 设备不活跃"展示，
// 避免已卸载设备的有效会话被算成活跃（设计 §3）。
const activeDeviceWindow = 7 * 24 * time.Hour

type currentSession struct {
	ID         string
	UserID     uint64
	Address    string
	LastSeenAt time.Time
}

// installationActivity 三档活跃度（设计 §3）。
func installationActivity(current *currentSession, lastActive, now time.Time) string {
	if current == nil {
		return "signed_out"
	}
	if now.Sub(lastActive) <= activeDeviceWindow {
		return "active"
	}
	return "session_active_device_idle"
}

// sessionMismatch 把心跳上报的客户端登录态和服务端会话比对，不一致就标出来（设计 §4.9 对账），
// 只展示不判定；客户端没上报返回空。
func sessionMismatch(clientState sql.NullString, current *currentSession) string {
	if !clientState.Valid {
		return ""
	}
	switch {
	case clientState.String == "signed_in" && current == nil:
		return "client_signed_in_only"
	case clientState.String == "signed_out" && current != nil:
		return "server_session_only"
	}
	return ""
}

func (s *server) currentSessionOf(c *gin.Context, tenant, installationID string, now time.Time) (*currentSession, error) {
	var record currentSession
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT s.id,s.user_id,u.address,s.last_seen_at FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id WHERE s.tenant_id=? AND s.installation_id=? AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1`, tenant, installationID, now).Scan(&record.ID, &record.UserID, &record.Address, &record.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func currentSessionJSON(current *currentSession) any {
	if current == nil {
		return nil
	}
	return gin.H{"sessionId": current.ID, "userId": current.UserID, "address": current.Address, "lastSeenAt": iso(current.LastSeenAt)}
}

// ---------- 安装实例详情 ----------

func (s *server) installationDetail(c *gin.Context) {
	installationID := strings.TrimSpace(c.Param("id"))
	if !installationIDPattern.MatchString(installationID) {
		problem(c, 422, "INVALID_INSTALLATION", "installationId is invalid")
		return
	}
	now := time.Now().UTC()
	tenant := tenantID(c)
	var rowID uint64
	var deviceClientID sql.NullInt64
	var applicationID, packageID, platform, version, build, runtime, locale, theme, osVersion, deviceClass, status string
	var otaRevision, runningRevision, brandingVersion sql.NullInt64
	var launchSource, runningUpdateID, sessionState, localizationVersion, revokedReason sql.NullString
	var firstSeen, lastActive time.Time
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,device_client_id,application_id,package_id,platform,app_version,build_number,runtime_version,ota_revision,launch_source,running_update_id,running_ota_revision,client_session_state,localization_version,branding_version,locale,theme,os_version,device_class,first_seen_at,last_active_at,status,revoked_reason FROM app_installations WHERE tenant_id=? AND installation_id=? LIMIT 1`, tenant, installationID).Scan(&rowID, &deviceClientID, &applicationID, &packageID, &platform, &version, &build, &runtime, &otaRevision, &launchSource, &runningUpdateID, &runningRevision, &sessionState, &localizationVersion, &brandingVersion, &locale, &theme, &osVersion, &deviceClass, &firstSeen, &lastActive, &status, &revokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "INSTALLATION_NOT_FOUND", "Installation not found")
		return
	}
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation")
		return
	}
	current, err := s.currentSessionOf(c, tenant, installationID, now)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation session")
		return
	}
	accounts, err := s.installationAccounts(c, tenant, installationID, current)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation accounts")
		return
	}
	siblings := []gin.H{}
	if deviceClientID.Valid {
		siblings, err = s.siblingInstallations(c, tenant, deviceClientID.Int64, installationID)
		if err != nil {
			problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load sibling installations")
			return
		}
	}
	pushTokens, err := s.installationPushTokens(c, tenant, installationID)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load push tokens")
		return
	}
	sessions, err := s.querySessions(c, tenant, "s.installation_id=?", installationID, now, 20)
	if err != nil {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to load installation sessions")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"installation":    gin.H{"installationId": installationID, "applicationId": applicationID, "packageId": packageID, "platform": platform, "appVersion": version, "buildNumber": build, "runtimeVersion": runtime, "availableOtaRevision": nullableInt64(otaRevision), "launchSource": nullableSQLString(launchSource), "runningUpdateId": nullableSQLString(runningUpdateID), "runningOtaRevision": nullableInt64(runningRevision), "clientSessionState": nullableSQLString(sessionState), "localizationVersion": nullableSQLString(localizationVersion), "brandingVersion": nullableInt64(brandingVersion), "locale": locale, "theme": theme, "osVersion": osVersion, "deviceClass": deviceClass, "firstSeenAt": iso(firstSeen), "lastActiveAt": iso(lastActive), "status": status, "revokedReason": nullableSQLString(revokedReason), "hasDeviceGroup": deviceClientID.Valid},
		"currentAccount":  currentSessionJSON(current),
		"activity":        installationActivity(current, lastActive, now),
		"sessionMismatch": nullableString(sessionMismatch(sessionState, current)),
		"accounts":        accounts,
		"siblings":        siblings,
		"pushTokens":      pushTokens,
		"sessions":        sessions,
	})
}

func (s *server) installationAccounts(c *gin.Context, tenant, installationID string, current *currentSession) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT r.user_id,u.address,u.status,r.first_login_at,r.last_login_at,r.login_count,r.last_connector FROM wallet_user_installation r JOIN wallet_user u ON u.id=r.user_id WHERE r.tenant_id=? AND r.installation_id=? ORDER BY r.last_login_at DESC`, tenant, installationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var userID uint64
		var address, status, connector string
		var first, last time.Time
		var count int
		if err := rows.Scan(&userID, &address, &status, &first, &last, &count, &connector); err != nil {
			return nil, err
		}
		items = append(items, gin.H{"userId": userID, "address": address, "status": status, "firstLoginAt": iso(first), "lastLoginAt": iso(last), "loginCount": count, "lastConnector": connector, "current": current != nil && current.UserID == userID})
	}
	return items, rows.Err()
}

// siblingInstallations 同一台设备（同 device_client_id）在本租户的其他安装实例；归并 ID 本身不返回。
func (s *server) siblingInstallations(c *gin.Context, tenant string, deviceClientID int64, exclude string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT installation_id,platform,app_version,build_number,launch_source,running_ota_revision,last_active_at,status FROM app_installations WHERE tenant_id=? AND device_client_id=? AND installation_id<>? ORDER BY last_active_at DESC`, tenant, deviceClientID, exclude)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, platform, version, build, status string
		var launchSource sql.NullString
		var revision sql.NullInt64
		var active time.Time
		if err := rows.Scan(&id, &platform, &version, &build, &launchSource, &revision, &active, &status); err != nil {
			return nil, err
		}
		items = append(items, gin.H{"installationId": id, "platform": platform, "appVersion": version, "buildNumber": build, "launchSource": nullableSQLString(launchSource), "runningOtaRevision": nullableInt64(revision), "lastActiveAt": iso(active), "status": status})
	}
	return items, rows.Err()
}

func (s *server) installationPushTokens(c *gin.Context, tenant, installationID string) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT provider,environment,permission_status,last_seen_at,invalid_at FROM app_push_tokens WHERE tenant_id=? AND installation_id=? ORDER BY last_seen_at DESC`, tenant, installationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var provider, environment, permission string
		var lastSeen time.Time
		var invalid sql.NullTime
		if err := rows.Scan(&provider, &environment, &permission, &lastSeen, &invalid); err != nil {
			return nil, err
		}
		items = append(items, gin.H{"provider": provider, "environment": environment, "permissionStatus": permission, "lastSeenAt": iso(lastSeen), "invalidAt": nullableOTAFieldTime(invalid)})
	}
	return items, rows.Err()
}

// querySessions 列出会话；where 是针对别名 s 的一个条件（单参数）。
func (s *server) querySessions(c *gin.Context, tenant, where string, arg any, now time.Time, limit int) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT s.id,s.user_id,u.address,s.installation_id,s.connector,s.chains,s.issued_at,s.expires_at,s.last_seen_at,s.revoked_at,s.ended_reason FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id WHERE s.tenant_id=? AND `+where+` ORDER BY s.issued_at DESC LIMIT ?`, tenant, arg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []gin.H{}
	for rows.Next() {
		var id, address, connector, chains string
		var userID uint64
		var installationID, endedReason sql.NullString
		var issued, expires, lastSeen time.Time
		var revoked sql.NullTime
		if err := rows.Scan(&id, &userID, &address, &installationID, &connector, &chains, &issued, &expires, &lastSeen, &revoked, &endedReason); err != nil {
			return nil, err
		}
		state := "active"
		switch {
		case revoked.Valid:
			state = "ended"
		case !expires.After(now):
			state = "expired"
		}
		items = append(items, gin.H{"sessionId": id, "userId": userID, "address": address, "installationId": nullableSQLString(installationID), "connector": connector, "chains": strings.Split(chains, ","), "issuedAt": iso(issued), "expiresAt": iso(expires), "lastSeenAt": iso(lastSeen), "revokedAt": nullableOTAFieldTime(revoked), "endedReason": nullableSQLString(endedReason), "state": state})
	}
	return items, rows.Err()
}

// ---------- 账号列表 / 详情 ----------

type walletUserListFilter struct {
	query       string
	status      string
	activeSince time.Time
	limit       int
	cursorAt    time.Time
	cursorID    uint64
	hasCursor   bool
}

func parseWalletUserListFilter(c *gin.Context, now time.Time) (walletUserListFilter, string) {
	f := walletUserListFilter{query: strings.ToLower(strings.TrimSpace(c.Query("q"))), status: strings.ToLower(strings.TrimSpace(c.Query("status"))), limit: 50}
	if f.query != "" && !strings.HasPrefix(f.query, "0x") {
		return f, "q must be an address prefix starting with 0x"
	}
	if f.status != "" && f.status != "active" && f.status != "blocked" {
		return f, "status must be active or blocked"
	}
	switch strings.TrimSpace(c.Query("activeWithin")) {
	case "":
	case "1d":
		f.activeSince = now.Add(-24 * time.Hour)
	case "7d":
		f.activeSince = now.Add(-7 * 24 * time.Hour)
	case "30d":
		f.activeSince = now.Add(-30 * 24 * time.Hour)
	default:
		return f, "activeWithin must be 1d, 7d or 30d"
	}
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > installationListMaxLimit {
			return f, "limit must be between 1 and 200"
		}
		f.limit = value
	}
	if raw := strings.TrimSpace(c.Query("cursor")); raw != "" {
		at, id, err := decodeInstallationCursor(raw)
		if err != nil {
			return f, "cursor is invalid"
		}
		f.cursorAt, f.cursorID, f.hasCursor = at, id, true
	}
	return f, ""
}

func (f walletUserListFilter) where(tenant string) (string, []any) {
	clauses := []string{"u.tenant_id=?"}
	args := []any{tenant}
	if f.query != "" {
		clauses = append(clauses, "u.address_key LIKE ?")
		args = append(args, f.query+"%")
	}
	if f.status != "" {
		clauses = append(clauses, "u.status=?")
		args = append(args, f.status)
	}
	if !f.activeSince.IsZero() {
		clauses = append(clauses, "u.last_login_at>=?")
		args = append(args, f.activeSince)
	}
	return strings.Join(clauses, " AND "), args
}

func (s *server) listWalletUsers(c *gin.Context) {
	now := time.Now().UTC()
	filter, invalid := parseWalletUserListFilter(c, now)
	if invalid != "" {
		problem(c, 422, "INVALID_WALLET_USER_FILTER", invalid)
		return
	}
	tenant := tenantID(c)
	where, args := filter.where(tenant)
	var total int
	if err := s.db.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM wallet_user u WHERE `+where, args...).Scan(&total); err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to count wallet users")
		return
	}
	pageWhere, pageArgs := where, append([]any{}, args...)
	if filter.hasCursor {
		pageWhere += " AND (u.last_login_at<? OR (u.last_login_at=? AND u.id<?))"
		pageArgs = append(pageArgs, filter.cursorAt, filter.cursorAt, filter.cursorID)
	}
	pageArgs = append([]any{now}, pageArgs...)
	pageArgs = append(pageArgs, filter.limit+1)
	// 最近活跃设备摘要（设计 §4.7）：该账号最近登录过的安装实例及其版本与心跳时间
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT u.id,u.address,u.status,u.first_seen_at,u.last_login_at,u.login_count,
		(SELECT COUNT(*) FROM wallet_user_installation r WHERE r.tenant_id=u.tenant_id AND r.user_id=u.id),
		(SELECT COUNT(DISTINCT s.installation_id) FROM wallet_session s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.id AND s.revoked_at IS NULL AND s.expires_at>? AND s.installation_id IS NOT NULL),
		latest.installation_id,latest.platform,latest.app_version,latest.build_number,latest.last_active_at
		FROM wallet_user u
		LEFT JOIN LATERAL (SELECT i.installation_id,i.platform,i.app_version,i.build_number,i.last_active_at FROM wallet_user_installation r JOIN app_installations i ON i.tenant_id=r.tenant_id AND i.installation_id=r.installation_id WHERE r.tenant_id=u.tenant_id AND r.user_id=u.id ORDER BY r.last_login_at DESC LIMIT 1) latest ON TRUE
		WHERE `+pageWhere+` ORDER BY u.last_login_at DESC, u.id DESC LIMIT ?`, pageArgs...)
	if err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to load wallet users")
		return
	}
	defer rows.Close()
	items := []gin.H{}
	var nextCursor any
	for rows.Next() {
		var id uint64
		var address, status string
		var first, last time.Time
		var loginCount, installations, activeInstallations int
		var latestID, latestPlatform, latestVersion, latestBuild sql.NullString
		var latestActive sql.NullTime
		if err := rows.Scan(&id, &address, &status, &first, &last, &loginCount, &installations, &activeInstallations, &latestID, &latestPlatform, &latestVersion, &latestBuild, &latestActive); err != nil {
			problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to read wallet users")
			return
		}
		if len(items) == filter.limit {
			nextCursor = items[len(items)-1]["cursor"]
			break
		}
		var lastInstallation any
		if latestID.Valid {
			lastInstallation = gin.H{"installationId": latestID.String, "platform": latestPlatform.String, "appVersion": latestVersion.String, "buildNumber": latestBuild.String, "lastActiveAt": nullableOTAFieldTime(latestActive)}
		}
		items = append(items, gin.H{"id": id, "address": address, "status": status, "firstSeenAt": iso(first), "lastLoginAt": iso(last), "loginCount": loginCount, "installationsCount": installations, "activeInstallationsCount": activeInstallations, "lastInstallation": lastInstallation, "cursor": encodeInstallationCursor(last, id)})
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to read wallet users")
		return
	}
	for _, item := range items {
		delete(item, "cursor")
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "nextCursor": nextCursor, "limit": filter.limit})
}

func parseWalletUserID(c *gin.Context) (uint64, bool) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id == 0 {
		problem(c, 422, "INVALID_WALLET_USER", "wallet user id is invalid")
		return 0, false
	}
	return id, true
}

func (s *server) walletUserDetail(c *gin.Context) {
	userID, ok := parseWalletUserID(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	tenant := tenantID(c)
	var address, status string
	var first, last time.Time
	var loginCount int
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT address,status,first_seen_at,last_login_at,login_count FROM wallet_user WHERE tenant_id=? AND id=?`, tenant, userID).Scan(&address, &status, &first, &last, &loginCount)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "WALLET_USER_NOT_FOUND", "Wallet user not found")
		return
	}
	if err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to load wallet user")
		return
	}
	devices, err := s.walletUserDevices(c, tenant, userID, now)
	if err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to load wallet user devices")
		return
	}
	sessions, err := s.querySessions(c, tenant, "s.user_id=?", userID, now, 50)
	if err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to load wallet user sessions")
		return
	}
	platformBlock := s.platformWalletBlocked(c, address) != ""
	// 邀请关系是这个账号的属性，扩展既有响应而不新开接口（设计 §4.4）
	referralView, err := s.referralOfWalletUser(c, tenant, userID)
	if err != nil {
		problem(c, 500, "WALLET_USER_QUERY_FAILED", "Unable to load wallet user")
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": gin.H{"id": userID, "address": address, "status": status, "firstSeenAt": iso(first), "lastLoginAt": iso(last), "loginCount": loginCount, "platformBlocked": platformBlock}, "devices": devices, "sessions": sessions, "referral": referralView})
}

// walletUserDevices 按设备归并分组返回该账号用过的安装实例；分组键只在本次响应内有意义（device-1、device-2…），
// 归并 ID 不返回给租户。没有归并信息的安装实例各自成组。
func (s *server) walletUserDevices(c *gin.Context, tenant string, userID uint64, now time.Time) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT i.device_client_id,i.installation_id,i.platform,i.app_version,i.build_number,i.launch_source,i.running_ota_revision,i.os_version,i.last_active_at,i.status,r.first_login_at,r.last_login_at,r.login_count,r.last_connector,
		(SELECT s.id FROM wallet_session s WHERE s.tenant_id=r.tenant_id AND s.user_id=r.user_id AND s.installation_id=r.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1)
		FROM wallet_user_installation r JOIN app_installations i ON i.tenant_id=r.tenant_id AND i.installation_id=r.installation_id
		WHERE r.tenant_id=? AND r.user_id=? ORDER BY i.device_client_id, r.last_login_at DESC`, now, tenant, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []gin.H{}
	index := map[int64]int{}
	for rows.Next() {
		var deviceClientID sql.NullInt64
		var installationID, platform, version, build, osVersion, status, connector string
		var launchSource, currentSessionID sql.NullString
		var revision sql.NullInt64
		var lastActive, firstLogin, lastLogin time.Time
		var loginCount int
		if err := rows.Scan(&deviceClientID, &installationID, &platform, &version, &build, &launchSource, &revision, &osVersion, &lastActive, &status, &firstLogin, &lastLogin, &loginCount, &connector, &currentSessionID); err != nil {
			return nil, err
		}
		activity := "signed_out"
		if currentSessionID.Valid {
			activity = "active"
			if now.Sub(lastActive) > activeDeviceWindow {
				activity = "session_active_device_idle"
			}
		}
		item := gin.H{"installationId": installationID, "platform": platform, "appVersion": version, "buildNumber": build, "launchSource": nullableSQLString(launchSource), "runningOtaRevision": nullableInt64(revision), "osVersion": osVersion, "lastActiveAt": iso(lastActive), "status": status, "firstLoginAt": iso(firstLogin), "lastLoginAt": iso(lastLogin), "loginCount": loginCount, "lastConnector": connector, "current": currentSessionID.Valid, "currentSessionId": nullableSQLString(currentSessionID), "activity": activity}
		if !deviceClientID.Valid {
			groups = append(groups, gin.H{"deviceGroup": fmt.Sprintf("device-%d", len(groups)+1), "grouped": false, "installations": []gin.H{item}})
			continue
		}
		position, exists := index[deviceClientID.Int64]
		if !exists {
			index[deviceClientID.Int64] = len(groups)
			groups = append(groups, gin.H{"deviceGroup": fmt.Sprintf("device-%d", len(groups)+1), "grouped": true, "installations": []gin.H{item}})
			continue
		}
		groups[position]["installations"] = append(groups[position]["installations"].([]gin.H), item)
	}
	return groups, rows.Err()
}

// ---------- 封禁 / 撤销会话 ----------

type adminActionBody struct {
	Reason  string `json:"reason"`
	Confirm bool   `json:"confirm"`
}

func decodeAdminAction(c *gin.Context) (adminActionBody, bool) {
	var body adminActionBody
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_ACTION", "Invalid action payload")
		return body, false
	}
	if !validateAdminAction(c, &body) {
		return body, false
	}
	return body, true
}

// validateAdminAction 是"confirm=true + reason >= 3 字符"这条规则的唯一实现。
// 带额外字段的管理端动作（如邀请补录）自己解码请求体，但必须走这里，
// 否则同一条规则会有第二份实现，改文案时只会改到一处。
func validateAdminAction(c *gin.Context, body *adminActionBody) bool {
	body.Reason = strings.TrimSpace(body.Reason)
	if !body.Confirm || len(body.Reason) < 3 {
		problem(c, 422, "INVALID_ACTION", "reason (at least 3 characters) and confirm=true are required")
		return false
	}
	return true
}

// blockWalletUser 租户级封禁 / 解封：封禁立即结束本租户该账号的有效会话（用户 2026-09-07 决定）。
func (s *server) blockWalletUser(block bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := parseWalletUserID(c)
		if !ok {
			return
		}
		body, ok := decodeAdminAction(c)
		if !ok {
			return
		}
		now := time.Now().UTC()
		tenant := tenantID(c)
		target, action := "active", "wallet_user_unblock"
		if block {
			target, action = "blocked", "wallet_user_block"
		}
		tx, err := s.db.BeginTx(c.Request.Context(), nil)
		if err != nil {
			problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to update wallet user")
			return
		}
		defer tx.Rollback()
		var address string
		if err := tx.QueryRowContext(c.Request.Context(), `SELECT address FROM wallet_user WHERE tenant_id=? AND id=? FOR UPDATE`, tenant, userID).Scan(&address); errors.Is(err, sql.ErrNoRows) {
			problem(c, 404, "WALLET_USER_NOT_FOUND", "Wallet user not found")
			return
		} else if err != nil {
			problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to update wallet user")
			return
		}
		if _, err := tx.ExecContext(c.Request.Context(), `UPDATE wallet_user SET status=?,updated_at=? WHERE tenant_id=? AND id=?`, target, now, tenant, userID); err != nil {
			problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to update wallet user")
			return
		}
		var ended int64
		if block {
			result, err := tx.ExecContext(c.Request.Context(), endSessionsSQL+`tenant_id=? AND user_id=?`, now, "blocked", tenant, userID)
			if err != nil {
				problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to end wallet user sessions")
				return
			}
			ended, _ = result.RowsAffected()
		}
		if err := insertAudit(c.Request.Context(), tx, newAudit(tenant, actor(c), action, "wallet-user", strconv.FormatUint(userID, 10), body.Reason, requestID(c), map[string]any{"address": address, "sessionsEnded": ended})); err != nil {
			problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to save audit")
			return
		}
		if err := tx.Commit(); err != nil {
			problem(c, 500, "WALLET_USER_UPDATE_FAILED", "Unable to update wallet user")
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": userID, "status": target, "sessionsEnded": ended, "updatedAt": iso(now)})
	}
}

func (s *server) revokeWalletSession(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Param("id"))
	if !strings.HasPrefix(sessionID, "wses_") || len(sessionID) > 80 {
		problem(c, 422, "INVALID_WALLET_SESSION", "session id is invalid")
		return
	}
	body, ok := decodeAdminAction(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	tenant := tenantID(c)
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "WALLET_SESSION_REVOKE_FAILED", "Unable to revoke session")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), endSessionsSQL+`tenant_id=? AND id=?`, now, "admin", tenant, sessionID)
	if err != nil {
		problem(c, 500, "WALLET_SESSION_REVOKE_FAILED", "Unable to revoke session")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 404, "WALLET_SESSION_NOT_FOUND", "Session not found or already ended")
		return
	}
	if err := insertAudit(c.Request.Context(), tx, newAudit(tenant, actor(c), "wallet_session_revoke", "wallet-session", sessionID, body.Reason, requestID(c), nil)); err != nil {
		problem(c, 500, "WALLET_SESSION_REVOKE_FAILED", "Unable to save audit")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, 500, "WALLET_SESSION_REVOKE_FAILED", "Unable to revoke session")
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessionId": sessionID, "revokedAt": iso(now), "endedReason": "admin"})
}

// platformWalletBlocked 平台级封禁检查（设计 §4.5）：命中返回错误码，未命中返回空。
// 查询失败按"不能确认未封禁"处理，返回 WALLET_BLOCK_CHECK_FAILED 让登录失败并可见。
// platformWalletBlocked 是登录路径上的平台级封禁检查，返回空串表示放行。
// 判据本身由 platformBlockedAddress 实现，这里只把它翻译成登录路径的错误码——
// 同一个判据不能有两份 SQL，否则改封禁语义时只会改到一处。
func (s *server) platformWalletBlocked(c *gin.Context, address string) string {
	blocked, err := s.platformBlockedAddress(c.Request.Context(), s.db, address)
	if err != nil {
		return "WALLET_BLOCK_CHECK_FAILED"
	}
	if blocked {
		return "WALLET_BLOCKED_PLATFORM"
	}
	return ""
}
