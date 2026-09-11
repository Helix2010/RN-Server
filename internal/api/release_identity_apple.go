package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// release.ios：租户 iOS 正式包身份（Apple Team ID + bundle id），存 app_configs，
// 只读租户自己那一行。结构刻意与 release.android 平行——两条发布链的身份来源要
// 长得一样才好核对，但字段本身没有交集，所以是两份记录而不是一份带平台字段的。
const releaseIOSIdentityConfigKey = "release.ios"

// appLinkPath 是通用链接里唯一被声明的路径，必须与 RN-App `app.config.ts` 的
// `APP_LINK_PATH` 保持一致。**不要**声明整个域名：那样每一个 API URL 都会试图
// 拉起应用，浏览器里点任何接口地址都会跳出 App。
const appLinkPath = "/app/wc"

var (
	// Apple Team ID 固定 10 位大写字母数字（开发者账号页面上的那一串）
	appleTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	// bundle id 是反向域名；Apple 允许字母、数字和连字符
	iosBundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

type iosReleaseIdentity struct {
	AppleTeamID string `json:"appleTeamId"`
	BundleID    string `json:"bundleId"`
}

type iosReleaseIdentityWrite struct {
	AppleTeamID     string `json:"appleTeamId"`
	BundleID        string `json:"bundleId"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

type iosReleaseIdentityRecord struct {
	Value     iosReleaseIdentity
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func normalizeIOSReleaseIdentity(v iosReleaseIdentity) iosReleaseIdentity {
	return iosReleaseIdentity{
		AppleTeamID: strings.ToUpper(strings.TrimSpace(v.AppleTeamID)),
		BundleID:    strings.TrimSpace(v.BundleID),
	}
}

func validateIOSReleaseIdentity(v iosReleaseIdentity) error {
	if !appleTeamIDPattern.MatchString(v.AppleTeamID) {
		return errors.New("appleTeamId must be the 10-character Apple Developer Team ID")
	}
	if len(v.BundleID) > 255 || !iosBundleIDPattern.MatchString(v.BundleID) {
		return errors.New("bundleId must be a valid reverse-DNS iOS bundle identifier")
	}
	return nil
}

func parseIOSReleaseIdentity(raw []byte) (iosReleaseIdentity, error) {
	var v iosReleaseIdentity
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("release.ios is not valid JSON: %w", err)
	}
	v = normalizeIOSReleaseIdentity(v)
	if err := validateIOSReleaseIdentity(v); err != nil {
		return v, err
	}
	return v, nil
}

func (s *server) iosReleaseIdentityRecord(ctx context.Context, tenant string) (*iosReleaseIdentityRecord, error) {
	var raw []byte
	var record iosReleaseIdentityRecord
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, releaseIOSIdentityConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Value, err = parseIOSReleaseIdentity(raw); err != nil {
		return nil, err
	}
	return &record, nil
}

func iosReleaseIdentityView(record *iosReleaseIdentityRecord) gin.H {
	if record == nil {
		return gin.H{"configured": false, "identity": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"identity":   gin.H{"appleTeamId": record.Value.AppleTeamID, "bundleId": record.Value.BundleID},
		"version":    record.Version,
		"updatedBy":  record.UpdatedBy,
		"updatedAt":  iso(record.UpdatedAt),
	}
}

func (s *server) getIOSReleaseIdentity(c *gin.Context) {
	record, err := s.iosReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, iosReleaseIdentityView(record))
}

func (s *server) updateIOSReleaseIdentity(c *gin.Context) {
	var body iosReleaseIdentityWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", "appleTeamId, bundleId, expectedVersion, reason and confirm=true are required")
		return
	}
	value := normalizeIOSReleaseIdentity(iosReleaseIdentity{AppleTeamID: body.AppleTeamID, BundleID: body.BundleID})
	if err := validateIOSReleaseIdentity(value); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", err.Error())
		return
	}
	current, err := s.iosReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}
	raw, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if current != nil {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), releaseIOSIdentityConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), releaseIOSIdentityConfigKey, raw, actor(c), now, tenantID(c), releaseIOSIdentityConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}
	previous := map[string]any{}
	if current != nil {
		previous = map[string]any{"appleTeamId": current.Value.AppleTeamID, "bundleId": current.Value.BundleID}
	}
	event := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseIOSIdentityConfigKey, body.Reason, requestID(c), map[string]any{"appleTeamId": value.AppleTeamID, "bundleId": value.BundleID, "previous": previous, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	c.JSON(http.StatusOK, iosReleaseIdentityView(&iosReleaseIdentityRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}))
}

// appleAppSiteAssociation 生成 iOS 通用链接的归属声明内容。
// `appIDs` + `components` 是 iOS 13 起的形状，`appID` + `paths` 留给更早的系统，
// 两者可以并存在同一条 detail 里，Apple 各取所需。
func appleAppSiteAssociation(identity iosReleaseIdentity) gin.H {
	appID := identity.AppleTeamID + "." + identity.BundleID
	return gin.H{
		"applinks": gin.H{
			"apps": []string{},
			"details": []gin.H{{
				"appID":  appID,
				"paths":  []string{appLinkPath},
				"appIDs": []string{appID},
				"components": []gin.H{{
					"/":       appLinkPath,
					"comment": "WalletConnect return leg",
				}},
			}},
		},
	}
}

// wellKnownAppleAppSiteAssociation 按租户域名提供 iOS 通用链接的归属声明
// （`/.well-known/apple-app-site-association`，安全评审 N13 的 iOS 一半）。
//
// 与 Android 的 assetlinks.json 同一套道理：自定义 scheme（`anyfun://`）谁都能
// 抢注，把回跳绑在租户自己的域名上才抢不走。没有登记 iOS 发布身份的租户返回
// 404——宁可让系统判定"未声明"，也不发一份猜出来的授权。
//
// 注意：这个文件**没有** `.json` 后缀（Apple 的硬性要求），但必须以
// `application/json` 送出，且不能重定向。
func (s *server) wellKnownAppleAppSiteAssociation(c *gin.Context) {
	record, err := s.iosReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if record == nil {
		problem(c, http.StatusNotFound, "RELEASE_IDENTITY_NOT_CONFIGURED", "This tenant has not registered an iOS release identity")
		return
	}
	// 与 assetlinks 同档：缓存一小时，换 Team ID / bundle id 后不至于长期发旧文件
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, appleAppSiteAssociation(record.Value))
}
