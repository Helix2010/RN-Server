package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

var installationIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,80}$`)
var deviceSourceHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type installationHeartbeat struct {
	InstallationID      string `json:"installationId"`
	DeviceSourceHash    string `json:"deviceSourceHash"`
	PackageID           string `json:"packageId"`
	OTAChannel          string `json:"otaChannel"`
	OTARevision         *int   `json:"otaRevision"`
	LocalizationVersion string `json:"localizationVersion"`
	Locale              string `json:"locale"`
	Theme               string `json:"theme"`
	OSVersion           string `json:"osVersion"`
	DeviceClass         string `json:"deviceClass"`
}

func (s *server) installationHeartbeat(c *gin.Context) {
	var body installationHeartbeat
	if decode(c, &body) != nil {
		problem(c, http.StatusBadRequest, "INVALID_INSTALLATION", "Invalid installation heartbeat")
		return
	}
	body.InstallationID = strings.TrimSpace(body.InstallationID)
	body.DeviceSourceHash = strings.ToLower(strings.TrimSpace(body.DeviceSourceHash))
	body.PackageID = strings.TrimSpace(body.PackageID)
	if !installationIDPattern.MatchString(body.InstallationID) || body.PackageID == "" || len(body.PackageID) > 180 || (body.DeviceSourceHash != "" && !deviceSourceHashPattern.MatchString(body.DeviceSourceHash)) {
		problem(c, http.StatusUnprocessableEntity, "INVALID_INSTALLATION", "Installation identity is invalid")
		return
	}
	platform := strings.ToLower(c.GetHeader("x-platform"))
	if !oneOf(platform, "android", "ios") {
		problem(c, http.StatusUnprocessableEntity, "INVALID_INSTALLATION", "Platform is invalid")
		return
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to save installation heartbeat")
		return
	}
	defer tx.Rollback()
	var deviceClientID any
	grouping := "disabled"
	if body.DeviceSourceHash != "" && s.cfg.DeviceIdentityKey != "" {
		deviceKey, hashErr := s.deviceKeyHash(platform, body.DeviceSourceHash)
		if hashErr != nil {
			problem(c, 503, "DEVICE_IDENTITY_UNAVAILABLE", "Device grouping is unavailable")
			return
		}
		_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO device_clients(platform,device_key_hash,first_seen_at,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE last_seen_at=VALUES(last_seen_at),updated_at=VALUES(updated_at)`, platform, deviceKey, now, now, now, now)
		if err == nil {
			var id uint64
			err = tx.QueryRowContext(c.Request.Context(), `SELECT id FROM device_clients WHERE platform=? AND device_key_hash=?`, platform, deviceKey).Scan(&id)
			deviceClientID, grouping = id, "available"
		}
	}
	if err != nil {
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to save device grouping")
		return
	}
	applicationID := text(c.GetHeader("x-application-id"), "unknown")
	_, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_installations(tenant_id,device_client_id,installation_id,application_id,package_id,platform,distribution_channel,app_version,build_number,runtime_version,ota_channel,ota_revision,localization_version,locale,theme,os_version,device_class,first_seen_at,last_active_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?) ON DUPLICATE KEY UPDATE device_client_id=VALUES(device_client_id),package_id=VALUES(package_id),platform=VALUES(platform),distribution_channel=VALUES(distribution_channel),app_version=VALUES(app_version),build_number=VALUES(build_number),runtime_version=VALUES(runtime_version),ota_channel=VALUES(ota_channel),ota_revision=VALUES(ota_revision),localization_version=VALUES(localization_version),locale=VALUES(locale),theme=VALUES(theme),os_version=VALUES(os_version),device_class=VALUES(device_class),last_active_at=VALUES(last_active_at),status='active',updated_at=VALUES(updated_at)`, tenantID(c), deviceClientID, body.InstallationID, applicationID, body.PackageID, platform, text(c.GetHeader("x-distribution-channel"), "development"), text(c.GetHeader("x-app-version"), "0"), text(c.GetHeader("x-build-number"), "0"), text(c.GetHeader("x-runtime-version"), "embedded"), body.OTAChannel, body.OTARevision, body.LocalizationVersion, body.Locale, body.Theme, body.OSVersion, body.DeviceClass, now, now, now, now)
	if err != nil || tx.Commit() != nil {
		problem(c, 500, "INSTALLATION_SAVE_FAILED", "Unable to save installation heartbeat")
		return
	}
	c.JSON(http.StatusOK, gin.H{"installationId": body.InstallationID, "deviceGrouping": grouping, "heartbeatIntervalSeconds": 1800, "receivedAt": iso(now)})
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
	var exists bool
	_ = s.db.QueryRowContext(c.Request.Context(), `SELECT EXISTS(SELECT 1 FROM app_installations WHERE tenant_id=? AND installation_id=?)`, tenantID(c), body.InstallationID).Scan(&exists)
	if !exists {
		problem(c, 409, "INSTALLATION_REQUIRED", "Register the installation before the push token")
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
