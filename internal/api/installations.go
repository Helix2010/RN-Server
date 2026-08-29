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
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const installationCredentialTTL = 90 * 24 * time.Hour
const installationCredentialRotateBefore = 14 * 24 * time.Hour

var installationIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,80}$`)
var deviceSourceHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type installationHeartbeat struct {
	InstallationID      string `json:"installationId"`
	DeviceSourceHash    string `json:"deviceSourceHash"`
	PackageID           string `json:"packageId"`
	OTAChannel          string `json:"otaChannel"`
	OTARevision         *int   `json:"otaRevision"`
	LocalizationVersion string `json:"localizationVersion"`
	BrandingVersion     *int   `json:"brandingVersion"`
	Locale              string `json:"locale"`
	Theme               string `json:"theme"`
	OSVersion           string `json:"osVersion"`
	DeviceClass         string `json:"deviceClass"`
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
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to save installation heartbeat")
		return
	}
	response := gin.H{"installationId": body.InstallationID, "heartbeatIntervalSeconds": 1800, "receivedAt": iso(now), "credentialVersion": record.Version, "credentialExpiresAt": iso(record.ExpiresAt)}
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
	return body, true
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
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_installations(tenant_id,device_client_id,installation_id,application_id,package_id,platform,distribution_channel,app_version,build_number,runtime_version,ota_channel,ota_revision,localization_version,branding_version,locale,theme,os_version,device_class,first_seen_at,last_active_at,status,credential_hash,credential_version,credential_expires_at,credential_last_used_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE device_client_id=VALUES(device_client_id),package_id=VALUES(package_id),platform=VALUES(platform),distribution_channel=VALUES(distribution_channel),app_version=VALUES(app_version),build_number=VALUES(build_number),runtime_version=VALUES(runtime_version),ota_channel=VALUES(ota_channel),ota_revision=VALUES(ota_revision),localization_version=VALUES(localization_version),branding_version=VALUES(branding_version),locale=VALUES(locale),theme=VALUES(theme),os_version=VALUES(os_version),device_class=VALUES(device_class),last_active_at=VALUES(last_active_at),credential_hash=COALESCE(credential_hash,VALUES(credential_hash)),credential_version=IF(credential_hash IS NULL,VALUES(credential_version),credential_version),credential_expires_at=COALESCE(credential_expires_at,VALUES(credential_expires_at)),credential_last_used_at=VALUES(credential_last_used_at),status=IF(credential_revoked_at IS NULL,'active',status),updated_at=VALUES(updated_at)`, tenantID(c), deviceClientID, body.InstallationID, applicationID, body.PackageID, platform, text(c.GetHeader("x-distribution-channel"), "development"), text(c.GetHeader("x-app-version"), "0"), text(c.GetHeader("x-build-number"), "0"), text(c.GetHeader("x-runtime-version"), "embedded"), body.OTAChannel, body.OTARevision, body.LocalizationVersion, body.BrandingVersion, body.Locale, body.Theme, body.OSVersion, body.DeviceClass, now, now, credentialHash, credentialVersion, credentialExpires, now, now, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *server) authenticateInstallation(c *gin.Context, installationID string) (installationCredentialRecord, bool) {
	var record installationCredentialRecord
	credential := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Installation "))
	if credential == "" {
		problem(c, 401, "INSTALLATION_CREDENTIAL_REQUIRED", "Installation credential is required")
		return record, false
	}
	err := s.db.QueryRowContext(c.Request.Context(), `SELECT credential_hash,credential_version,credential_expires_at,credential_revoked_at,application_id,platform,status FROM app_installations WHERE tenant_id=? AND installation_id=? LIMIT 1`, tenantID(c), installationID).Scan(&record.Hash, &record.Version, &record.ExpiresAt, &record.RevokedAt, &record.ApplicationID, &record.Platform, &record.Status)
	if err != nil || record.RevokedAt.Valid || record.Status == "revoked" || record.ExpiresAt.Before(time.Now().UTC()) || record.ApplicationID != text(c.GetHeader("x-application-id"), "unknown") || record.Platform != strings.ToLower(c.GetHeader("x-platform")) {
		problem(c, 401, "INSTALLATION_CREDENTIAL_INVALID", "Installation credential is invalid, expired or revoked")
		return record, false
	}
	actual := sha256.Sum256([]byte(credential))
	expected, err := hex.DecodeString(record.Hash)
	if err != nil || len(expected) != len(actual) || subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
		problem(c, 401, "INSTALLATION_CREDENTIAL_INVALID", "Installation credential is invalid, expired or revoked")
		return record, false
	}
	return record, true
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
