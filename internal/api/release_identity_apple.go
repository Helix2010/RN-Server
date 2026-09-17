package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// release.ios：租户 iOS 正式包身份（Apple Team ID + bundle id）与分发入口，存
// app_configs，只读租户自己那一行。结构刻意与 release.android 平行——两条发布链的
// 身份来源要长得一样才好核对，但字段本身没有交集，所以是两份记录而不是一份带平台
// 字段的。
//
// 分发入口（installUrl）也放在这里而不是单开一个键：它随身份一起被运营维护、
// 一起进同一条审计、一起被 bootstrap 读。凭据是另一回事，见 ios_asc.go。
// 设计 docs/design/ios-testflight-distribution-2026-09-17.md §4.5.1。
const releaseIOSIdentityConfigKey = "release.ios"

// appLinkPath 是通用链接里被声明的钱包回跳路径，必须与 RN-App `app.config.ts` 的
// `APP_LINK_PATH` 保持一致。**不要**声明整个域名：那样每一个 API URL 都会试图
// 拉起应用，浏览器里点任何接口地址都会跳出 App。
const appLinkPath = "/app/wc"

// appleInviteLinkPattern 是邀请链接在 AASA 里的形状。Android 侧两条路径都声明了
// （`app.config.ts` 的 `APP_LINK_PATH` + `INVITE_LINK_PATH`），iOS 少了这一条，
// 于是同一个邀请链接在 Android 上唤起 App、在 iOS 上只会打开落地页。
// referralInvitePath 带尾斜杠（前缀匹配的需要），AASA 这边要的是通配形态。
const appleInviteLinkPattern = referralInvitePath + "*"

// installUrl 的来源。同一个 URL 手填与同步来的长得一样，事后推不出来，所以存。
const (
	iosInstallURLSourceManual = "manual"
	iosInstallURLSourceSynced = "synced"
)

var (
	// Apple Team ID 固定 10 位大写字母数字（开发者账号页面上的那一串）
	appleTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	// bundle id 是反向域名；Apple 允许字母、数字和连字符
	iosBundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	// 安装入口只认 Apple 自己的两个域。这个值会被下发到 App 里、被落地页直接跳转，
	// 允许任意 host 等于给了一个"从控制台改一个字段就把全体 iOS 用户导去任意站点"
	// 的开关——而分发入口恰恰是用户最愿意点的那个按钮。
	iosInstallURLHosts = map[string]bool{"testflight.apple.com": true, "apps.apple.com": true}
)

type iosReleaseIdentity struct {
	AppleTeamID string `json:"appleTeamId"`
	BundleID    string `json:"bundleId"`
	// InstallURL 是 TestFlight 公开链接或 App Store 页面。空=没配，与历史行为一致。
	InstallURL string `json:"installUrl,omitempty"`
	// InstallURLSource：manual=人在控制台填的，synced=从 App Store Connect 同步来的
	InstallURLSource string `json:"installUrlSource,omitempty"`
	// BuildExpiresAt 是当前 TestFlight build 的过期时刻（上传 + 90 天）。
	// 模式 B 人工填，模式 A 由同步覆盖。RFC3339，空=不知道。
	BuildExpiresAt string `json:"buildExpiresAt,omitempty"`
}

type iosReleaseIdentityWrite struct {
	AppleTeamID     string `json:"appleTeamId"`
	BundleID        string `json:"bundleId"`
	InstallURL      string `json:"installUrl"`
	BuildExpiresAt  string `json:"buildExpiresAt"`
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
	normalized := iosReleaseIdentity{
		AppleTeamID:      strings.ToUpper(strings.TrimSpace(v.AppleTeamID)),
		BundleID:         strings.TrimSpace(v.BundleID),
		InstallURL:       strings.TrimSpace(v.InstallURL),
		InstallURLSource: strings.TrimSpace(v.InstallURLSource),
		BuildExpiresAt:   strings.TrimSpace(v.BuildExpiresAt),
	}
	// 没有链接就没有来源。留一个孤零零的 "synced" 会让界面显示"同步来的（空）"
	if normalized.InstallURL == "" {
		normalized.InstallURLSource = ""
	} else if normalized.InstallURLSource == "" {
		normalized.InstallURLSource = iosInstallURLSourceManual
	}
	if at, err := time.Parse(time.RFC3339, normalized.BuildExpiresAt); err == nil {
		normalized.BuildExpiresAt = at.UTC().Format(time.RFC3339)
	}
	return normalized
}

// validateIOSInstallURL 只允许 Apple 自己的分发入口，且必须带路径——
// `https://testflight.apple.com` 光秃秃一个域名对用户毫无意义。
func validateIOSInstallURL(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > 255 {
		return errors.New("installUrl must be at most 255 characters")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || !iosInstallURLHosts[strings.ToLower(parsed.Host)] ||
		strings.Trim(parsed.Path, "/") == "" {
		return errors.New("installUrl must be an https link under testflight.apple.com or apps.apple.com, including its path")
	}
	// `https://evil.com@testflight.apple.com/join/x` 真正会打开的确实是 Apple，但这个
	// 字符串会原样出现在管理端、二维码和 App 的更新按钮上，读起来像是去 evil.com。
	// 分发入口没有任何用得上 userinfo 的场景，直接拒掉。
	if parsed.User != nil {
		return errors.New("installUrl must not carry a user@ part")
	}
	return nil
}

func validateIOSReleaseIdentity(v iosReleaseIdentity) error {
	if !appleTeamIDPattern.MatchString(v.AppleTeamID) {
		return errors.New("appleTeamId must be the 10-character Apple Developer Team ID")
	}
	if len(v.BundleID) > 255 || !iosBundleIDPattern.MatchString(v.BundleID) {
		return errors.New("bundleId must be a valid reverse-DNS iOS bundle identifier")
	}
	if err := validateIOSInstallURL(v.InstallURL); err != nil {
		return err
	}
	if v.InstallURLSource != "" && v.InstallURLSource != iosInstallURLSourceManual && v.InstallURLSource != iosInstallURLSourceSynced {
		return errors.New("installUrlSource must be manual or synced")
	}
	if v.BuildExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, v.BuildExpiresAt); err != nil {
			return errors.New("buildExpiresAt must be an RFC3339 timestamp")
		}
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

// iosInstallURL 是 bootstrap 与公开落地页要的那一个字符串。
//
// 没配就是没配（record == nil），这条链路上"没有安装入口"是一个正常状态。但**读坏了
// 不是**：那会让所有 iOS 用户静默地拿不到更新按钮，而症状与"运营还没填"一模一样。
// 所以这两种情况在返回值上一样、在日志里不一样。
func (s *server) iosInstallURL(ctx context.Context, tenant string) string {
	record, err := s.iosReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		slog.Error("release.ios cannot be read; iOS clients get no install entry point",
			"tenant", tenant, "error", err)
		return ""
	}
	if record == nil {
		return ""
	}
	return record.Value.InstallURL
}

func iosReleaseIdentityValueView(v iosReleaseIdentity) gin.H {
	return gin.H{
		"appleTeamId":      v.AppleTeamID,
		"bundleId":         v.BundleID,
		"installUrl":       nullableString(v.InstallURL),
		"installUrlSource": nullableString(v.InstallURLSource),
		"buildExpiresAt":   nullableString(v.BuildExpiresAt),
	}
}

func iosReleaseIdentityView(record *iosReleaseIdentityRecord) gin.H {
	if record == nil {
		return gin.H{"configured": false, "identity": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"identity":   iosReleaseIdentityValueView(record.Value),
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
	// 人在控制台按了保存，来源就是 manual——哪怕填进去的字符串和上次同步来的一模一样。
	// 同步那条路径（syncIOSTestFlight）自己写 synced。
	value := normalizeIOSReleaseIdentity(iosReleaseIdentity{
		AppleTeamID: body.AppleTeamID, BundleID: body.BundleID,
		InstallURL: body.InstallURL, InstallURLSource: iosInstallURLSourceManual,
		BuildExpiresAt: body.BuildExpiresAt,
	})
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
	previous := map[string]any{}
	if current != nil {
		previous = map[string]any{"appleTeamId": current.Value.AppleTeamID, "bundleId": current.Value.BundleID, "installUrl": current.Value.InstallURL}
	}
	summary := map[string]any{
		"appleTeamId": value.AppleTeamID, "bundleId": value.BundleID,
		"installUrl": value.InstallURL, "previous": previous,
	}
	record, saveErr := s.writeIOSReleaseIdentity(c, value, currentVersion, body.Reason, summary)
	if saveErr != nil {
		return
	}
	c.JSON(http.StatusOK, iosReleaseIdentityView(record))
}

// writeIOSReleaseIdentity 把一份完整的身份写回去，并落一条审计。
// 手工保存与 TestFlight 同步共用它：两条路径写进库的形状必须一样。
// 出错时自己回过响应并返回非 nil，调用方直接 return。
func (s *server) writeIOSReleaseIdentity(c *gin.Context, value iosReleaseIdentity, currentVersion int, reason string, summary map[string]any) (*iosReleaseIdentityRecord, error) {
	raw, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return nil, err
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if currentVersion > 0 {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), releaseIOSIdentityConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), releaseIOSIdentityConfigKey, raw, actor(c), now, tenantID(c), releaseIOSIdentityConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return nil, err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return nil, errors.New("stale release identity")
	}
	summary["databaseVersion"] = newVersion
	event := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseIOSIdentityConfigKey, reason, requestID(c), summary)
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return nil, errors.New("release identity save failed")
	}
	return &iosReleaseIdentityRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}, nil
}

// appleAppSiteAssociation 生成 iOS 通用链接的归属声明内容。
// `appIDs` + `components` 是 iOS 13 起的形状，`appID` + `paths` 留给更早的系统，
// 两者可以并存在同一条 detail 里，Apple 各取所需。
//
// 两条路径：钱包回跳（WalletConnect）与邀请链接。两条都要声明——少声明一条的
// 症状是"同一个链接在 Android 上唤起 App、在 iOS 上打开网页"，而这在测试里很像
// "iOS 的深链没做"，不像"漏了一行配置"。
func appleAppSiteAssociation(identity iosReleaseIdentity) gin.H {
	appID := identity.AppleTeamID + "." + identity.BundleID
	return gin.H{
		"applinks": gin.H{
			"apps": []string{},
			"details": []gin.H{{
				"appID":  appID,
				"paths":  []string{appLinkPath, appleInviteLinkPattern},
				"appIDs": []string{appID},
				"components": []gin.H{
					{"/": appLinkPath, "comment": "WalletConnect return leg"},
					{"/": appleInviteLinkPattern, "comment": "Referral invite link"},
				},
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

// iosBuildIdentityProblem 回答"这个租户现在能不能出一个 iOS 包"，能就返回空串。
//
// 单独一条而不是并进 composeTenantManifest：那份清单是两个平台共用的，把 iOS 的
// 必填项加进去会让**Android** 的构建因为"没配 Apple Team ID"排不进队列。
//
// 检查放在排队那一刻（createBuildJob）与认领那一刻（claimBuildJob）各一次：前者让
// 运营当场看见缺什么，后者兜住"排队之后有人把配置删了"——队列是跨租户的，一条注定
// 失败的任务占着构建机，拖的是所有人。
func (s *server) iosBuildIdentityProblem(ctx context.Context, tenant string) string {
	record, err := s.iosReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		return "存着的 release.ios 配置读不出来：" + err.Error()
	}
	if record == nil {
		return "这个租户还没有登记 iOS 发布身份（Apple Team ID 与 bundle id）。到「iOS 打包与分发 → 应用身份」登记后再排队。"
	}
	if strings.TrimSpace(record.Value.AppleTeamID) == "" {
		return "iOS 发布身份缺 Apple Team ID：构建时要拿它做 DEVELOPMENT_TEAM，缺了 xcodebuild 签不了名。"
	}
	if strings.TrimSpace(record.Value.BundleID) == "" {
		return "iOS 发布身份缺 bundle id。"
	}
	return ""
}
