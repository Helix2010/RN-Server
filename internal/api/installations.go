package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const installationCredentialTTL = 90 * 24 * time.Hour
const installationCredentialRotateBefore = 14 * 24 * time.Hour

// installationUpsertSQL is shared by register and heartbeat. Keep the column
// list, the VALUES placeholders and the argument list in saveInstallation in
// sync; TestInstallationUpsertPlaceholderCount guards the first two.
const installationCredentialLookupSQL = `SELECT credential_hash,credential_version,credential_expires_at,credential_revoked_at,application_id,platform,status FROM app_installations WHERE tenant_id=? AND application_id=? AND platform=? AND installation_id=? LIMIT 1`

const installationUpsertSQL = `INSERT INTO app_installations(tenant_id,device_client_id,installation_id,application_id,package_id,platform,distribution_channel,app_version,build_number,runtime_version,ota_channel,ota_revision,launch_source,running_update_id,running_ota_revision,client_session_state,device_integrity,localization_version,branding_version,locale,theme,os_version,device_class,first_seen_at,last_active_at,status,credential_hash,credential_version,credential_expires_at,credential_last_used_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?) ON DUPLICATE KEY UPDATE device_client_id=VALUES(device_client_id),package_id=VALUES(package_id),platform=VALUES(platform),distribution_channel=VALUES(distribution_channel),app_version=VALUES(app_version),build_number=VALUES(build_number),runtime_version=VALUES(runtime_version),ota_channel=VALUES(ota_channel),ota_revision=VALUES(ota_revision),launch_source=VALUES(launch_source),running_update_id=VALUES(running_update_id),running_ota_revision=VALUES(running_ota_revision),client_session_state=VALUES(client_session_state),device_integrity=VALUES(device_integrity),localization_version=VALUES(localization_version),branding_version=VALUES(branding_version),locale=VALUES(locale),theme=VALUES(theme),os_version=VALUES(os_version),device_class=VALUES(device_class),last_active_at=VALUES(last_active_at),credential_hash=COALESCE(credential_hash,VALUES(credential_hash)),credential_version=IF(credential_hash IS NULL,VALUES(credential_version),credential_version),credential_expires_at=COALESCE(credential_expires_at,VALUES(credential_expires_at)),credential_last_used_at=VALUES(credential_last_used_at),status=IF(credential_revoked_at IS NULL,'active',status),updated_at=VALUES(updated_at)`

var installationIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,80}$`)
var deviceSourceHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type installationHeartbeat struct {
	InstallationID   string `json:"installationId"`
	DeviceSourceHash string `json:"deviceSourceHash"`
	PackageID        string `json:"packageId"`
	OTAChannel       string `json:"otaChannel"`
	OTARevision      *int   `json:"otaRevision"`
	// 设备实际在跑什么（设计 §4.1）：launchSource 缺省表示旧版 App 未上报，服务端存 NULL
	LaunchSource    *string `json:"launchSource"`
	RunningUpdateID *string `json:"runningUpdateId"`
	// 客户端登录态，只用于与 wallet_session 对账，不参与任何判定
	SessionState *string `json:"sessionState"`
	// 设备完整性信号（安全评审 N31）。**自报**，不是安全控制：被攻破的客户端
	// 当然可以说自己没 root。它回答的是"我们的用户里有多少跑在 root 过的设备上"，
	// 此前这个问题完全没有答案。每一项都可以缺省，探不出来就是 null。
	DeviceIntegrity     *deviceIntegrityReport `json:"deviceIntegrity"`
	LocalizationVersion string                 `json:"localizationVersion"`
	BrandingVersion     *int                   `json:"brandingVersion"`
	Locale              string                 `json:"locale"`
	Theme               string                 `json:"theme"`
	OSVersion           string                 `json:"osVersion"`
	DeviceClass         string                 `json:"deviceClass"`
}

type installationCredentialRecord struct {
	Hash, ApplicationID, Platform, Status string
	Version                               int
	ExpiresAt                             time.Time
	RevokedAt                             sql.NullTime
}

func (s *server) registerInstallation(c *gin.Context) {
	body, ok := decodeInstallationBody(c)
	if !ok {
		return
	}
	platform, applicationID := strings.ToLower(c.GetHeader("x-platform")), text(c.GetHeader("x-application-id"), "unknown")
	if !oneOf(platform, "android", "ios") {
		problem(c, 422, "INVALID_INSTALLATION", "Platform is invalid")
		return
	}
	var existingDeviceKey, existingStatus sql.NullString
	var existingVersion int
	existingErr := s.db.QueryRowContext(c.Request.Context(), `SELECT d.device_key_hash,i.status,i.credential_version FROM app_installations i LEFT JOIN device_clients d ON d.id=i.device_client_id WHERE i.tenant_id=? AND i.application_id=? AND i.installation_id=? LIMIT 1`, tenantID(c), applicationID, body.InstallationID).Scan(&existingDeviceKey, &existingStatus, &existingVersion)
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		problem(c, 500, "INSTALLATION_QUERY_FAILED", "Unable to check installation")
		return
	}
	if existingErr == nil {
		if existingStatus.String == "revoked" {
			problem(c, 403, "INSTALLATION_REVOKED", "Installation has been revoked")
			return
		}
		if body.DeviceSourceHash == "" || !existingDeviceKey.Valid {
			problem(c, 409, "INSTALLATION_RECOVERY_UNAVAILABLE", "Installation credential cannot be recovered on this device")
			return
		}
		deviceKey, keyErr := s.deviceKeyHash(platform, body.DeviceSourceHash)
		if keyErr != nil || subtle.ConstantTimeCompare([]byte(existingDeviceKey.String), []byte(deviceKey)) != 1 {
			problem(c, 409, "INSTALLATION_IDENTITY_MISMATCH", "Installation identity does not match the registered device")
			return
		}
		credential, hash, rotateErr := newInstallationCredential()
		if rotateErr != nil {
			problem(c, 500, "INSTALLATION_CREDENTIAL_FAILED", "Unable to rotate installation credential")
			return
		}
		now, expires := time.Now().UTC(), time.Now().UTC().Add(installationCredentialTTL)
		result, updateErr := s.db.ExecContext(c.Request.Context(), `UPDATE app_installations SET credential_hash=?,credential_version=?,credential_expires_at=?,credential_last_used_at=?,credential_revoked_at=NULL,revoked_reason=NULL,status='active',updated_at=? WHERE tenant_id=? AND application_id=? AND installation_id=? AND status<>'revoked'`, hash, existingVersion+1, expires, now, now, tenantID(c), applicationID, body.InstallationID)
		if updateErr != nil {
			problem(c, 500, "INSTALLATION_CREDENTIAL_FAILED", "Unable to rotate installation credential")
			return
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			problem(c, 409, "INSTALLATION_CREDENTIAL_CONFLICT", "Installation changed; retry")
			return
		}
		c.JSON(http.StatusCreated, gin.H{"installationId": body.InstallationID, "installationCredential": credential, "credentialVersion": existingVersion + 1, "credentialExpiresAt": iso(expires), "heartbeatIntervalSeconds": 1800, "receivedAt": iso(now), "credentialRotated": true})
		return
	}
	credential, hash, err := newInstallationCredential()
	if err != nil {
		problem(c, 500, "INSTALLATION_CREDENTIAL_FAILED", "Unable to create installation credential")
		return
	}
	now, expires := time.Now().UTC(), time.Now().UTC().Add(installationCredentialTTL)
	if err := s.saveInstallation(c, body, hash, 1, expires, now); err != nil {
		slog.Error("installation register failed", "error", err, "requestId", requestID(c), "tenant", tenantID(c))
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to register installation")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"installationId": body.InstallationID, "installationCredential": credential, "credentialVersion": 1, "credentialExpiresAt": iso(expires), "heartbeatIntervalSeconds": 1800, "receivedAt": iso(now)})
}

func (s *server) installationHeartbeat(c *gin.Context) {
	body, ok := decodeInstallationBody(c)
	if !ok {
		return
	}
	record, valid := s.authenticateInstallation(c, body.InstallationID)
	if !valid {
		return
	}
	now := time.Now().UTC()
	if err := s.saveInstallation(c, body, record.Hash, record.Version, record.ExpiresAt, now); err != nil {
		slog.Error("installation heartbeat failed", "error", err, "requestId", requestID(c), "tenant", tenantID(c))
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to save installation heartbeat")
		return
	}
	response := gin.H{"installationId": body.InstallationID, "deviceGrouping": "available", "heartbeatIntervalSeconds": 1800, "receivedAt": iso(now), "credentialVersion": record.Version, "credentialExpiresAt": iso(record.ExpiresAt)}
	if time.Until(record.ExpiresAt) <= installationCredentialRotateBefore {
		credential, hash, rotateErr := newInstallationCredential()
		if rotateErr == nil {
			version, expires := record.Version+1, now.Add(installationCredentialTTL)
			result, updateErr := s.db.ExecContext(c.Request.Context(), `UPDATE app_installations SET credential_hash=?,credential_version=?,credential_expires_at=?,credential_last_used_at=?,updated_at=? WHERE tenant_id=? AND application_id=? AND installation_id=? AND credential_version=? AND credential_revoked_at IS NULL`, hash, version, expires, now, now, tenantID(c), record.ApplicationID, body.InstallationID, record.Version)
			if updateErr == nil {
				if affected, _ := result.RowsAffected(); affected == 1 {
					response["credentialRotated"], response["installationCredential"], response["credentialVersion"], response["credentialExpiresAt"] = true, credential, version, iso(expires)
				}
			}
		}
	}
	c.JSON(http.StatusOK, response)
}

func (s *server) revokeInstallation(c *gin.Context) {
	var body struct {
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_INSTALLATION", "Invalid installation payload")
		return
	}
	installationID := strings.TrimSpace(c.Param("id"))
	body.Reason = strings.TrimSpace(body.Reason)
	if !installationIDPattern.MatchString(installationID) || !body.Confirm || len(body.Reason) < 3 {
		problem(c, 422, "INVALID_INSTALLATION", "installationId, reason and confirm=true are required")
		return
	}
	now := time.Now().UTC()
	result, err := s.db.ExecContext(c.Request.Context(), `UPDATE app_installations SET status='revoked',credential_revoked_at=?,revoked_reason=?,updated_at=? WHERE tenant_id=? AND installation_id=? AND status<>'revoked'`, now, body.Reason, now, tenantID(c), installationID)
	if err != nil {
		problem(c, 500, "INSTALLATION_REVOKE_FAILED", "Unable to revoke installation")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, 404, "INSTALLATION_NOT_FOUND", "Installation not found")
		return
	}
	_, _ = s.db.ExecContext(c.Request.Context(), `UPDATE app_push_tokens SET invalid_at=?,updated_at=? WHERE tenant_id=? AND installation_id=? AND invalid_at IS NULL`, now, now, tenantID(c), installationID)
	// 撤销安装实例同时结束它上面的会话（设计 §4.2），App 下次校验会话得到 401 回到未登录态
	if _, err := s.db.ExecContext(c.Request.Context(), endSessionsSQL+`tenant_id=? AND installation_id=?`, now, "admin", tenantID(c), installationID); err != nil {
		problem(c, 500, "INSTALLATION_REVOKE_FAILED", "Installation revoked but its sessions could not be ended")
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true, "installationId": installationID, "revokedAt": iso(now)})
}

func (s *server) registerPushToken(c *gin.Context) {
	var body struct {
		InstallationID string `json:"installationId"`
		Provider       string `json:"provider"`
		Token          string `json:"token"`
		Environment    string `json:"environment"`
		Permission     string `json:"permissionStatus"`
	}
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_PUSH_TOKEN", "Invalid push token payload")
		return
	}
	body.Provider, body.Token = strings.ToLower(strings.TrimSpace(body.Provider)), strings.TrimSpace(body.Token)
	if !installationIDPattern.MatchString(body.InstallationID) || !oneOf(body.Provider, "fcm", "apns", "hms") || body.Token == "" || len(body.Token) > 512 {
		problem(c, 422, "INVALID_PUSH_TOKEN", "Push token is invalid")
		return
	}
	if _, valid := s.authenticateInstallation(c, body.InstallationID); !valid {
		return
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(c.Request.Context(), `INSERT INTO app_push_tokens(tenant_id,installation_id,platform,provider,token,environment,permission_status,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE environment=VALUES(environment),permission_status=VALUES(permission_status),last_seen_at=VALUES(last_seen_at),invalid_at=NULL,updated_at=VALUES(updated_at)`, tenantID(c), body.InstallationID, strings.ToLower(c.GetHeader("x-platform")), body.Provider, body.Token, text(body.Environment, "production"), text(body.Permission, "unknown"), now, now, now)
	if err != nil {
		problem(c, 500, "PUSH_TOKEN_SAVE_FAILED", "Unable to save push token")
		return
	}
	c.JSON(http.StatusOK, gin.H{"registered": true, "provider": body.Provider, "updatedAt": iso(now)})
}

func decodeInstallationBody(c *gin.Context) (installationHeartbeat, bool) {
	var body installationHeartbeat
	if decode(c, &body) != nil {
		problem(c, 400, "INVALID_INSTALLATION", "Invalid installation payload")
		return body, false
	}
	body.InstallationID, body.DeviceSourceHash, body.PackageID = strings.TrimSpace(body.InstallationID), strings.ToLower(strings.TrimSpace(body.DeviceSourceHash)), strings.TrimSpace(body.PackageID)
	if !installationIDPattern.MatchString(body.InstallationID) || body.PackageID == "" || len(body.PackageID) > 180 || (body.DeviceSourceHash != "" && !deviceSourceHashPattern.MatchString(body.DeviceSourceHash)) {
		problem(c, 422, "INVALID_INSTALLATION", "Installation identity is invalid")
		return body, false
	}
	if code, detail := normalizeRuntimeReport(&body); code != "" {
		problem(c, 422, code, detail)
		return body, false
	}
	return body, true
}

// normalizeRuntimeReport 校验心跳里"设备实际在跑什么"的字段并做规范化，返回失败码与说明（空表示通过）。
// 内置包不能带 update id，OTA 包必须带合法 update id，两者不符都是客户端 bug，直接 422 让它暴露。
func normalizeRuntimeReport(body *installationHeartbeat) (string, string) {
	runningID := ""
	if body.RunningUpdateID != nil {
		runningID = strings.ToLower(strings.TrimSpace(*body.RunningUpdateID))
	}
	if body.LaunchSource == nil {
		if runningID != "" {
			return "OTA_RUNNING_UPDATE_INVALID", "runningUpdateId requires launchSource"
		}
		body.RunningUpdateID = nil
	} else {
		source := strings.ToLower(strings.TrimSpace(*body.LaunchSource))
		switch source {
		case "embedded":
			if runningID != "" {
				return "OTA_RUNNING_UPDATE_INVALID", "Embedded launches must not report a running update id"
			}
			body.RunningUpdateID = nil
		case "ota":
			if !uuidPattern.MatchString(runningID) {
				return "OTA_RUNNING_UPDATE_INVALID", "OTA launches must report the running update id as a UUID"
			}
			body.RunningUpdateID = &runningID
		default:
			return "OTA_RUNNING_UPDATE_INVALID", "launchSource must be embedded or ota"
		}
		body.LaunchSource = &source
	}
	if body.SessionState != nil {
		state := strings.ToLower(strings.TrimSpace(*body.SessionState))
		if state != "signed_in" && state != "signed_out" {
			return "INVALID_INSTALLATION", "sessionState must be signed_in or signed_out"
		}
		body.SessionState = &state
	}
	return "", ""
}

func (s *server) saveInstallation(c *gin.Context, body installationHeartbeat, credentialHash string, credentialVersion int, credentialExpires, now time.Time) error {
	platform, applicationID := strings.ToLower(c.GetHeader("x-platform")), text(c.GetHeader("x-application-id"), "unknown")
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var deviceClientID any
	if body.DeviceSourceHash != "" && s.cfg.DeviceIdentityKey != "" {
		deviceKey, hashErr := s.deviceKeyHash(platform, body.DeviceSourceHash)
		if hashErr != nil {
			return hashErr
		}
		if _, err = tx.ExecContext(c.Request.Context(), `INSERT INTO device_clients(platform,device_key_hash,first_seen_at,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE last_seen_at=VALUES(last_seen_at),updated_at=VALUES(updated_at)`, platform, deviceKey, now, now, now, now); err != nil {
			return err
		}
		var id uint64
		if err = tx.QueryRowContext(c.Request.Context(), `SELECT id FROM device_clients WHERE platform=? AND device_key_hash=?`, platform, deviceKey).Scan(&id); err != nil {
			return err
		}
		deviceClientID = id
	}
	// 运行中的修订号由 update id 在本租户的 OTA 发布记录里解析；关联不上（回退、已删除、别的租户）存 NULL，
	// 管理端显示"未知更新"，不猜
	var runningRevision any
	if body.LaunchSource != nil && *body.LaunchSource == "ota" && body.RunningUpdateID != nil {
		var revision int
		switch lookupErr := tx.QueryRowContext(c.Request.Context(), `SELECT revision FROM ota_releases WHERE tenant_id=? AND update_id=? LIMIT 1`, tenantID(c), *body.RunningUpdateID).Scan(&revision); {
		case lookupErr == nil:
			runningRevision = revision
		case errors.Is(lookupErr, sql.ErrNoRows):
			runningRevision = nil
		default:
			return lookupErr
		}
	}
	_, err = tx.ExecContext(c.Request.Context(), installationUpsertSQL, tenantID(c), deviceClientID, body.InstallationID, applicationID, body.PackageID, platform, text(c.GetHeader("x-distribution-channel"), "development"), text(c.GetHeader("x-app-version"), "0"), text(c.GetHeader("x-build-number"), "0"), text(c.GetHeader("x-runtime-version"), "embedded"), body.OTAChannel, body.OTARevision, body.LaunchSource, body.RunningUpdateID, runningRevision, body.SessionState, encodeDeviceIntegrity(body.DeviceIntegrity), body.LocalizationVersion, body.BrandingVersion, body.Locale, body.Theme, body.OSVersion, body.DeviceClass, now, now, credentialHash, credentialVersion, credentialExpires, now, now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) authenticateInstallation(c *gin.Context, installationID string) (installationCredentialRecord, bool) {
	record, code := s.verifyInstallationCredential(c, installationID)
	switch code {
	case "":
		return record, true
	case "INSTALLATION_CREDENTIAL_REQUIRED":
		problem(c, 401, code, "Installation credential is required")
	default:
		problem(c, 401, code, "Installation credential is invalid, expired or revoked")
	}
	return record, false
}

// verifyInstallationCredential 校验 `Authorization: Installation <credential>`，返回失败码
// （空表示通过）。不直接写响应，给"可选携带安装身份"的接口（钱包登录）复用。
func (s *server) verifyInstallationCredential(c *gin.Context, installationID string) (installationCredentialRecord, string) {
	return s.verifyInstallationCredentialFor(c, tenantID(c), installationID)
}

// verifyInstallationCredentialFor 是同一套校验，但租户由调用方给出：bootstrap 不挂
// domainTenantScope（它自己按 Host 解析租户并对解析失败给 TENANT_NOT_FOUND），
// 上下文里没有 tenantId。
func (s *server) verifyInstallationCredentialFor(c *gin.Context, tenant, installationID string) (installationCredentialRecord, string) {
	var record installationCredentialRecord
	credential := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Installation "))
	if credential == "" || credential == strings.TrimSpace(c.GetHeader("Authorization")) {
		return record, "INSTALLATION_CREDENTIAL_REQUIRED"
	}
	// 安装记录的键是 (tenant, application_id, installation_id)：查询必须带上请求头里的
	// 应用身份和平台，否则同一 installation_id 下若有多条记录会随机取一条去比对，
	// 凭证明明有效也判失效
	err := s.db.QueryRowContext(c.Request.Context(), installationCredentialLookupSQL, tenant, text(c.GetHeader("x-application-id"), "unknown"), strings.ToLower(c.GetHeader("x-platform")), installationID).Scan(&record.Hash, &record.Version, &record.ExpiresAt, &record.RevokedAt, &record.ApplicationID, &record.Platform, &record.Status)
	if err != nil || record.RevokedAt.Valid || record.Status == "revoked" || record.ExpiresAt.Before(time.Now().UTC()) {
		return record, "INSTALLATION_CREDENTIAL_INVALID"
	}
	actual := sha256.Sum256([]byte(credential))
	expected, err := hex.DecodeString(record.Hash)
	if err != nil || len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
		return record, "INSTALLATION_CREDENTIAL_INVALID"
	}
	return record, ""
}

func newInstallationCredential() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	credential := "icred_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(credential))
	return credential, hex.EncodeToString(hash[:]), nil
}

func (s *server) deviceKeyHash(platform, sourceHash string) (string, error) {
	key, err := base64.RawStdEncoding.DecodeString(s.cfg.DeviceIdentityKey)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(s.cfg.DeviceIdentityKey)
	}
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid device identity key")
	}
	hash := hmac.New(sha256.New, key)
	_, _ = hash.Write([]byte(platform + ":" + sourceHash))
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func enqueuePushEvent(ctx context.Context, tx *sql.Tx, tenant, eventType string, payload map[string]any) error {
	raw, _ := json.Marshal(payload)
	now := time.Now().UTC()
	_, err := tx.ExecContext(ctx, `INSERT INTO app_push_outbox(id,tenant_id,event_type,payload,status,attempts,next_attempt_at,created_at,updated_at) VALUES(?,?,?,?,'pending',0,?,?,?)`, "push_"+randomID(16), tenant, eventType, raw, now, now, now)
	return err
}

// deviceIntegrityReport 是客户端自报的设备完整性信号（安全评审 N31）。
//
// 三态：true / false / 缺省。探针失败与"没有"必须分开——expo-device 的 root 检测
// 明确标着 experimental，把探不出来算成"干净"会让统计出来的数直接是假的。
type deviceIntegrityReport struct {
	Rooted     *bool `json:"rooted"`
	Emulator   *bool `json:"emulator"`
	SideLoaded *bool `json:"sideLoaded"`
	DevBundle  *bool `json:"devBundle"`
}

// encodeDeviceIntegrity 把信号存成 JSON；没上报就是 NULL，而不是一个全 false 的
// 对象——那会把"旧版 App 没上报"读成"这台设备干净"。
func encodeDeviceIntegrity(report *deviceIntegrityReport) any {
	if report == nil {
		return nil
	}
	if report.Rooted == nil && report.Emulator == nil && report.SideLoaded == nil && report.DevBundle == nil {
		return nil
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil
	}
	return raw
}

// rawJSONOrNil 把一列 JSON 原样透出去；空列就是 null。不解析再重编：那会把
// "探针没跑"和"探针说 false"在往返里悄悄抹平。
func rawJSONOrNil(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return json.RawMessage(raw)
}
