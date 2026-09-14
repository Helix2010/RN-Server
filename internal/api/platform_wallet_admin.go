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

// 设计 RN-App/docs/design/device-account-aggregation-2026-09-07.md §4.4、§4.5、§4.7（平台级）：
// 跨租户视图只对平台管理员开放，按完整地址或设备查询，每次查询写审计（租户 0）；
// 这里是唯一允许返回 device_client_id 的地方。平台级封禁对所有租户生效。

// normalizeWalletAddress 只接受完整的 0x 地址：平台级查询不做前缀匹配，避免批量枚举。
func normalizeWalletAddress(raw string) (address, key string, ok bool) {
	address = strings.TrimSpace(raw)
	if !addressPattern.MatchString(address) {
		return "", "", false
	}
	return address, strings.ToLower(address), true
}

// endSessionsByAddressSQL 结束某个地址在所有租户的有效会话（参数：now, reason, address_key）。
const endSessionsByAddressSQL = `UPDATE wallet_session s JOIN wallet_user u ON u.id=s.user_id AND u.tenant_id=s.tenant_id SET s.revoked_at=?,s.ended_reason=? WHERE u.address_key=? AND s.revoked_at IS NULL`

func (s *server) platformAudit(c *gin.Context, action, targetType, targetID, reason string, summary map[string]any) error {
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAudit(c.Request.Context(), tx, newAudit("0", actor(c), action, targetType, targetID, reason, requestID(c), summary)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) activePlatformBlock(c *gin.Context, key string) (gin.H, error) {
	var id uint64
	var reason, createdBy string
	var createdAt time.Time
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT id,reason,created_by,created_at FROM platform_wallet_block WHERE address_key=? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1`, key).Scan(&id, &reason, &createdBy, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return gin.H{"id": id, "reason": reason, "createdBy": createdBy, "createdAt": iso(createdAt)}, nil
}

// platformWalletLookup 某地址跨租户的全貌：各租户的账号状态、按设备聚合的安装实例与当前会话、平台级封禁。
func (s *server) platformWalletLookup(c *gin.Context) {
	address, key, ok := normalizeWalletAddress(c.Query("address"))
	if !ok {
		problem(c, 422, "INVALID_WALLET_ADDRESS", "address must be a full 0x-prefixed EVM address")
		return
	}
	now := time.Now().UTC()
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT u.id,u.tenant_id,t.slug,u.address,u.status,u.first_seen_at,u.last_login_at,u.login_count,
		(SELECT COUNT(*) FROM wallet_session s WHERE s.tenant_id=u.tenant_id AND s.user_id=u.id AND s.revoked_at IS NULL AND s.expires_at>?)
		FROM wallet_user u JOIN tenants t ON t.id=u.tenant_id WHERE u.address_key=? ORDER BY u.last_login_at DESC`, now, key)
	if err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to look up wallet")
		return
	}
	tenantsOut := []gin.H{}
	for rows.Next() {
		var userID, tenant uint64
		var slug, addr, status string
		var first, last time.Time
		var loginCount, activeSessions int
		if err := rows.Scan(&userID, &tenant, &slug, &addr, &status, &first, &last, &loginCount, &activeSessions); err != nil {
			rows.Close()
			problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to read wallet tenants")
			return
		}
		tenantsOut = append(tenantsOut, gin.H{"tenantId": tenant, "tenantSlug": slug, "userId": userID, "address": addr, "status": status, "firstSeenAt": iso(first), "lastLoginAt": iso(last), "loginCount": loginCount, "activeSessions": activeSessions})
	}
	rows.Close()
	devices, err := s.platformWalletDevices(c, key, now)
	if err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to read wallet devices")
		return
	}
	block, err := s.activePlatformBlock(c, key)
	if err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to read platform block")
		return
	}
	if err := s.platformAudit(c, "platform_wallet_lookup", "wallet-address", key, "platform wallet lookup", map[string]any{"tenants": len(tenantsOut), "devices": len(devices)}); err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to record lookup audit")
		return
	}
	c.JSON(http.StatusOK, gin.H{"address": address, "tenants": tenantsOut, "devices": devices, "platformBlock": block})
}

// platformWalletDevices 按 device_client_id 跨租户聚合该地址登录过的安装实例；没有归并信息的各自成组。
func (s *server) platformWalletDevices(c *gin.Context, key string, now time.Time) ([]gin.H, error) {
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT i.device_client_id,i.tenant_id,t.slug,i.installation_id,i.platform,i.app_version,i.build_number,i.launch_source,i.running_ota_revision,i.os_version,i.last_active_at,i.status,r.first_login_at,r.last_login_at,r.login_count,r.last_connector,
		(SELECT s.id FROM wallet_session s WHERE s.tenant_id=r.tenant_id AND s.user_id=r.user_id AND s.installation_id=r.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1)
		FROM wallet_user_installation r JOIN wallet_user u ON u.id=r.user_id AND u.tenant_id=r.tenant_id JOIN app_installations i ON i.tenant_id=r.tenant_id AND i.installation_id=r.installation_id JOIN tenants t ON t.id=r.tenant_id
		WHERE u.address_key=? ORDER BY i.device_client_id, r.last_login_at DESC`, now, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := []gin.H{}
	index := map[int64]int{}
	for rows.Next() {
		var deviceClientID sql.NullInt64
		var tenant uint64
		var slug, installationID, platform, version, build, osVersion, status, connector string
		var launchSource, currentSessionID sql.NullString
		var revision sql.NullInt64
		var lastActive, firstLogin, lastLogin time.Time
		var loginCount int
		if err := rows.Scan(&deviceClientID, &tenant, &slug, &installationID, &platform, &version, &build, &launchSource, &revision, &osVersion, &lastActive, &status, &firstLogin, &lastLogin, &loginCount, &connector, &currentSessionID); err != nil {
			return nil, err
		}
		activity := "signed_out"
		if currentSessionID.Valid {
			activity = "active"
			if now.Sub(lastActive) > activeDeviceWindow {
				activity = "session_active_device_idle"
			}
		}
		item := gin.H{"tenantId": tenant, "tenantSlug": slug, "installationId": installationID, "platform": platform, "appVersion": version, "buildNumber": build, "launchSource": nullableSQLString(launchSource), "runningOtaRevision": nullableInt64(revision), "osVersion": osVersion, "lastActiveAt": iso(lastActive), "status": status, "firstLoginAt": iso(firstLogin), "lastLoginAt": iso(lastLogin), "loginCount": loginCount, "lastConnector": connector, "current": currentSessionID.Valid, "activity": activity}
		if !deviceClientID.Valid {
			groups = append(groups, gin.H{"deviceGroup": fmt.Sprintf("device-%d", len(groups)+1), "deviceClientId": nil, "grouped": false, "installations": []gin.H{item}})
			continue
		}
		position, exists := index[deviceClientID.Int64]
		if !exists {
			index[deviceClientID.Int64] = len(groups)
			groups = append(groups, gin.H{"deviceGroup": fmt.Sprintf("device-%d", len(groups)+1), "deviceClientId": deviceClientID.Int64, "grouped": true, "installations": []gin.H{item}})
			continue
		}
		groups[position]["installations"] = append(groups[position]["installations"].([]gin.H), item)
	}
	return groups, rows.Err()
}

// platformDeviceLookup 一台设备（归并 ID）上所有租户的安装实例与当前账号。
func (s *server) platformDeviceLookup(c *gin.Context) {
	deviceClientID, err := strconv.ParseInt(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || deviceClientID <= 0 {
		problem(c, 422, "INVALID_DEVICE", "device id is invalid")
		return
	}
	now := time.Now().UTC()
	var platform string
	var firstSeen, lastSeen time.Time
	err = s.db.QueryRowContext(c.Request.Context(), `SELECT platform,first_seen_at,last_seen_at FROM device_clients WHERE id=?`, deviceClientID).Scan(&platform, &firstSeen, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "DEVICE_NOT_FOUND", "Device not found")
		return
	}
	if err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to load device")
		return
	}
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT i.tenant_id,t.slug,i.installation_id,i.platform,i.app_version,i.build_number,i.launch_source,i.running_ota_revision,i.os_version,i.last_active_at,i.status,
		(SELECT u.address FROM wallet_session s JOIN wallet_user u ON u.id=s.user_id WHERE s.tenant_id=i.tenant_id AND s.installation_id=i.installation_id AND s.revoked_at IS NULL AND s.expires_at>? ORDER BY s.issued_at DESC LIMIT 1),
		(SELECT COUNT(*) FROM wallet_user_installation r WHERE r.tenant_id=i.tenant_id AND r.installation_id=i.installation_id)
		FROM app_installations i JOIN tenants t ON t.id=i.tenant_id WHERE i.device_client_id=? ORDER BY i.last_active_at DESC`, now, deviceClientID)
	if err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to load device installations")
		return
	}
	defer rows.Close()
	installations := []gin.H{}
	for rows.Next() {
		var tenant uint64
		var slug, installationID, plat, version, build, osVersion, status string
		var launchSource, currentAddress sql.NullString
		var revision sql.NullInt64
		var lastActive time.Time
		var accounts int
		if err := rows.Scan(&tenant, &slug, &installationID, &plat, &version, &build, &launchSource, &revision, &osVersion, &lastActive, &status, &currentAddress, &accounts); err != nil {
			problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to read device installations")
			return
		}
		installations = append(installations, gin.H{"tenantId": tenant, "tenantSlug": slug, "installationId": installationID, "platform": plat, "appVersion": version, "buildNumber": build, "launchSource": nullableSQLString(launchSource), "runningOtaRevision": nullableInt64(revision), "osVersion": osVersion, "lastActiveAt": iso(lastActive), "status": status, "currentAddress": nullableSQLString(currentAddress), "accountsCount": accounts})
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to read device installations")
		return
	}
	if err := s.platformAudit(c, "platform_device_lookup", "device", strconv.FormatInt(deviceClientID, 10), "platform device lookup", map[string]any{"installations": len(installations)}); err != nil {
		problem(c, 500, "PLATFORM_LOOKUP_FAILED", "Unable to record lookup audit")
		return
	}
	c.JSON(http.StatusOK, gin.H{"device": gin.H{"deviceClientId": deviceClientID, "platform": platform, "firstSeenAt": iso(firstSeen), "lastSeenAt": iso(lastSeen)}, "installations": installations})
}

// listPlatformWalletBlocks GET /v1/admin/platform/wallet/blocks（设计 admin-list-pagination-2026-09-14 §4.5）。
func (s *server) listPlatformWalletBlocks(c *gin.Context) {
	where, page, invalid := parsePlatformBlockFilter(c)
	if invalid != "" {
		problem(c, 422, "INVALID_PLATFORM_BLOCK_FILTER", invalid)
		return
	}
	total, err := s.countListRows(c.Request.Context(), "platform_wallet_block", where)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_QUERY_FAILED", "Unable to load platform blocks")
		return
	}
	query := where.and(page.after)
	rows, err := s.db.QueryContext(c.Request.Context(), `SELECT id,address,reason,created_by,created_at,revoked_at,revoked_by,revoked_reason FROM platform_wallet_block WHERE `+query.sql()+` ORDER BY created_at DESC, id DESC LIMIT ?`, append(query.args, page.limit+1)...)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_QUERY_FAILED", "Unable to load platform blocks")
		return
	}
	defer rows.Close()
	items, cursors := []gin.H{}, []string{}
	for rows.Next() {
		var id uint64
		var address, reason, createdBy string
		var createdAt time.Time
		var revokedAt sql.NullTime
		var revokedBy, revokedReason sql.NullString
		if err := rows.Scan(&id, &address, &reason, &createdBy, &createdAt, &revokedAt, &revokedBy, &revokedReason); err != nil {
			problem(c, 500, "PLATFORM_BLOCK_QUERY_FAILED", "Unable to read platform blocks")
			return
		}
		items = append(items, gin.H{"id": id, "address": address, "reason": reason, "createdBy": createdBy, "createdAt": iso(createdAt), "revokedAt": nullableOTAFieldTime(revokedAt), "revokedBy": nullableSQLString(revokedBy), "revokedReason": nullableSQLString(revokedReason), "active": !revokedAt.Valid})
		cursors = append(cursors, encodeListCursor(createdAt, id))
	}
	if err := rows.Err(); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_QUERY_FAILED", "Unable to read platform blocks")
		return
	}
	items, next := finishListPage(items, cursors, page.limit)
	c.JSON(http.StatusOK, listResponse(items, total, next, page.limit))
}

func parsePlatformBlockFilter(c *gin.Context) (sqlWhere, listPage, string) {
	where := sqlWhere{}
	if raw := strings.TrimSpace(c.Query("address")); raw != "" {
		_, normalized, ok := normalizeWalletAddress(raw)
		if !ok {
			return where, listPage{}, "address must be a full 0x-prefixed EVM address"
		}
		where.add("address_key=?", normalized)
	}
	switch strings.TrimSpace(c.Query("status")) {
	case "":
	case "active":
		where.add("revoked_at IS NULL")
	case "revoked":
		where.add("revoked_at IS NOT NULL")
	default:
		return where, listPage{}, "status must be active or revoked"
	}
	page, invalid := parseListPage(c, sortKey{"created_at", cursorTime}, sortKey{"id", cursorUint})
	return where, page, invalid
}

// createPlatformWalletBlock 平台级封禁：写封禁记录并结束该地址在所有租户的有效会话；已有生效中的封禁返回 409。
func (s *server) createPlatformWalletBlock(c *gin.Context) {
	var body struct {
		Address string `json:"address"`
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_ACTION", "Invalid block payload")
		return
	}
	address, key, ok := normalizeWalletAddress(body.Address)
	body.Reason = strings.TrimSpace(body.Reason)
	if !ok || !body.Confirm || len(body.Reason) < 3 {
		problem(c, 422, "INVALID_ACTION", "address, reason (at least 3 characters) and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to create platform block")
		return
	}
	defer tx.Rollback()
	var existing int
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT COUNT(*) FROM platform_wallet_block WHERE address_key=? AND revoked_at IS NULL FOR UPDATE`, key).Scan(&existing); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to create platform block")
		return
	}
	if existing > 0 {
		problem(c, 409, "PLATFORM_BLOCK_EXISTS", "This address is already blocked at platform level")
		return
	}
	result, err := tx.ExecContext(c.Request.Context(), `INSERT INTO platform_wallet_block(address_key,address,reason,created_by,created_at) VALUES(?,?,?,?,?)`, key, address, body.Reason, actor(c), now)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to create platform block")
		return
	}
	id, _ := result.LastInsertId()
	ended, err := tx.ExecContext(c.Request.Context(), endSessionsByAddressSQL, now, "blocked", key)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to end sessions for the blocked wallet")
		return
	}
	sessionsEnded, _ := ended.RowsAffected()
	if err := insertAudit(c.Request.Context(), tx, newAudit("0", actor(c), "platform_wallet_block", "wallet-address", key, body.Reason, requestID(c), map[string]any{"blockId": id, "sessionsEnded": sessionsEnded})); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to save audit")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to create platform block")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "address": address, "sessionsEnded": sessionsEnded, "createdAt": iso(now)})
}

func (s *server) revokePlatformWalletBlock(c *gin.Context) {
	id, err := strconv.ParseUint(strings.TrimSpace(c.Param("id")), 10, 64)
	if err != nil || id == 0 {
		problem(c, 422, "INVALID_ACTION", "block id is invalid")
		return
	}
	body, ok := decodeAdminAction(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to revoke platform block")
		return
	}
	defer tx.Rollback()
	var key string
	if err := tx.QueryRowContext(c.Request.Context(), `SELECT address_key FROM platform_wallet_block WHERE id=? AND revoked_at IS NULL FOR UPDATE`, id).Scan(&key); errors.Is(err, sql.ErrNoRows) {
		problem(c, 404, "PLATFORM_BLOCK_NOT_FOUND", "Active platform block not found")
		return
	} else if err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to revoke platform block")
		return
	}
	if _, err := tx.ExecContext(c.Request.Context(), `UPDATE platform_wallet_block SET revoked_at=?,revoked_by=?,revoked_reason=? WHERE id=?`, now, actor(c), body.Reason, id); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to revoke platform block")
		return
	}
	if err := insertAudit(c.Request.Context(), tx, newAudit("0", actor(c), "platform_wallet_unblock", "wallet-address", key, body.Reason, requestID(c), map[string]any{"blockId": id})); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to save audit")
		return
	}
	if err := tx.Commit(); err != nil {
		problem(c, 500, "PLATFORM_BLOCK_FAILED", "Unable to revoke platform block")
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "revokedAt": iso(now)})
}
