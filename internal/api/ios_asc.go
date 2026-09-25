package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/ascapi"
	"github.com/gin-gonic/gin"
)

// ios.asc：租户的 App Store Connect API Key（设计
// docs/design/ios-testflight-distribution-2026-09-17.md §4.6）。
//
// ## 为什么平台可以代管这把钥匙
//
// 服务端早就在按租户加密保管同类材料：OTA 签名私钥（ota.signing）、FCM 服务账号
// （push.fcm）。ASC Key 与 FCM 服务账号是同一类东西——第三方平台签发的、可吊销的
// 服务凭证，泄露后在对方后台点一下就作废。存法照抄 pushcreds，不需要新的信任模型。
//
// **真正的新增风险只有一条**：ASC Key 的权限范围比 FCM 服务账号大，它能动租户
// App Store 账号下的 App。缓解办法是让租户在 ASC 建 Key 时限制到本 App——2026-09-17
// 实测那把团队密钥能看到该团队全部 5 个 App。管理端的上传表单旁边要写明这件事。
//
// ## 两个键分开存
//
// release.ios 放身份与分发入口（全明文，运营天天看），ios.asc 放凭证。理由照搬
// pushcreds 的原话：轮换互不影响、审计一目了然、字段形状不同。
//
// ## 这把钥匙是可选的
//
// 不交 Key 的租户走模式 B：自己在 ASC 网页上建外部测试组、开公开链接，把那条
// https://testflight.apple.com/join/XXXXXXXX 填进 release.ios。扫码分发与 App 内
// 更新入口只需要那一个字符串，没有 Key 全都能跑。**模式 B 是默认路径，不是降级路径。**
const iosASCConfigKey = "ios.asc"

// iosASCBodyMax：.p8 约 250 字节，base64 之后不到 400。16 KiB 留足余量，同时不给
// 这个接口开一个更大的内存口子。
const iosASCBodyMax = 16 << 10

func iosASCAAD(tenant string) string { return "ios-asc:" + tenant }

// iosASC 是 ios.asc 的 config_value。
//
// 明文只放给人看的三项——issuerId 与 keyId 在 ASC 页面上本来就公开显示，appId 是
// 保存时验证顺带查到的（存下来省掉之后每次同步再查一次）。私钥整份加密。
type iosASC struct {
	IssuerID            string     `json:"issuerId"`
	KeyID               string     `json:"keyId"`
	AppID               string     `json:"appId"`
	PrivateKeyEncrypted string     `json:"privateKeyEncrypted"`
	VerifiedAt          *time.Time `json:"verifiedAt,omitempty"`
}

type iosASCRecord struct {
	Value     iosASC
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

// iosASCRecordFor 读一个租户的 ASC 凭证。**没有平台级回落**：每个租户一个 Apple
// 团队、一个 bundle id、一把 Key（设计 §4.3）。共用一把等于任何一个租户的运营都能
// 动别人的 App。
func (s *server) iosASCRecordFor(ctx context.Context, tenant string) (*iosASCRecord, error) {
	var raw []byte
	var record iosASCRecord
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`,
		tenant, iosASCConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return nil, err
	}
	return &record, nil
}

// ascClientFor 组一个这个租户的只读客户端。没装 Key 返回 nil（模式 B）。
func (s *server) ascClientFor(ctx context.Context, tenant string) (*ascapi.Client, *iosASCRecord, error) {
	record, err := s.iosASCRecordFor(ctx, tenant)
	if err != nil || record == nil {
		return nil, nil, err
	}
	if s.secrets == nil {
		return nil, record, errors.New("STORAGE_MASTER_KEY 不可用，解不开这个租户的 App Store Connect 密钥")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(record.Value.PrivateKeyEncrypted)
	if err != nil {
		return nil, record, errors.New("存着的 App Store Connect 密钥不是合法的 base64")
	}
	pemText, err := s.secrets.Decrypt(ciphertext, iosASCAAD(tenant))
	if err != nil {
		return nil, record, errors.New("存着的 App Store Connect 密钥解不开")
	}
	client := &ascapi.Client{
		Key:     ascapi.Key{IssuerID: record.Value.IssuerID, KeyID: record.Value.KeyID, PrivateKeyPEM: pemText},
		BaseURL: s.ascBaseURL,
	}
	return client, record, nil
}

func iosASCView(record *iosASCRecord) gin.H {
	if record == nil {
		// 没装 Key 不是错误，是模式 B
		return gin.H{"configured": false, "credentials": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"credentials": gin.H{
			"issuerId":   record.Value.IssuerID,
			"keyId":      record.Value.KeyID,
			"appId":      nullableString(record.Value.AppID),
			"verifiedAt": nullableTimePointer(record.Value.VerifiedAt),
		},
		"version":   record.Version,
		"updatedBy": record.UpdatedBy,
		"updatedAt": iso(record.UpdatedAt),
	}
}

func (s *server) getIOSASCCredentials(c *gin.Context) {
	record, err := s.iosASCRecordFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_CONFIG_INVALID", "Stored ios.asc configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, iosASCView(record))
}

type iosASCWrite struct {
	IssuerID string `json:"issuerId"`
	KeyID    string `json:"keyId"`
	// PrivateKey 接受 base64（控制台读文件之后传的形态）或原样 PEM
	PrivateKey      string `json:"privateKey"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// updateIOSASCCredentials 装或整把替换这个租户的 ASC Key。
//
// 保存即验证：立刻用它签一个 JWT 去查这个租户 bundle id 的 App 记录，必须恰好命中
// 一条才算保存成功。这条照抄 FCM 的规矩——本地解析只证明"格式对"，密钥在 Apple 后台
// 被吊销之后本地照样解析成功，直到第一次真同步才炸。它同时挡掉两类错配：Key 属于别
// 的团队，以及 ASC 上的 bundle id 与 release.ios 对不上。
func (s *server) updateIOSASCCredentials(c *gin.Context) {
	var body iosASCWrite
	if err := decodeLimited(c, &body, iosASCBodyMax); err != nil {
		if requestTooLarge(err) {
			problem(c, http.StatusRequestEntityTooLarge, "IOS_ASC_KEY_TOO_LARGE",
				"这份密钥太大了。正常的 .p8 不到 300 字节——确认传的不是别的文件")
			return
		}
		problem(c, http.StatusBadRequest, "INVALID_IOS_ASC", "issuerId、keyId、privateKey、expectedVersion、reason 和 confirm=true 都是必填")
		return
	}
	issuer := strings.TrimSpace(body.IssuerID)
	keyID := strings.TrimSpace(body.KeyID)
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 || issuer == "" || keyID == "" {
		problem(c, http.StatusBadRequest, "INVALID_IOS_ASC", "issuerId、keyId、privateKey、expectedVersion、reason 和 confirm=true 都是必填")
		return
	}
	pemText := strings.TrimSpace(string(decodePushCredentialPayload(body.PrivateKey)))
	if pemText == "" {
		problem(c, http.StatusBadRequest, "INVALID_IOS_ASC", "privateKey 是空的")
		return
	}
	if _, err := ascapi.ParsePrivateKey(pemText); err != nil {
		problem(c, http.StatusUnprocessableEntity, "INVALID_IOS_ASC", "这不是一把可用的 App Store Connect 密钥："+err.Error())
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "保存 App Store Connect 密钥之前必须先配置 STORAGE_MASTER_KEY")
		return
	}
	// 自助上传的租户不收：先查一次，免得白白拿 Key 去 Apple 核对；落库前在事务里加锁再查一次
	mode, err := s.iosDeliveryModeFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_DELIVERY_CONFIG_INVALID", "Stored "+iosDeliveryConfigKey+" configuration is invalid")
		return
	}
	if mode == iosDeliveryIPA {
		problem(c, http.StatusConflict, "IOS_DELIVERY_SELF_UPLOAD", iosASCSelfUploadDetail)
		return
	}
	// 没有 iOS 发布身份就没有可验证的 bundle id——先登记身份再装钥匙，顺序反过来
	// 的话"验证通过"证明不了这把钥匙属于这个租户
	identity, err := s.iosReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if identity == nil || strings.TrimSpace(identity.Value.BundleID) == "" {
		problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE",
			"先在「应用身份」登记 Apple Team ID 与 bundle id：保存密钥时要拿 bundle id 去 Apple 那边核对这把钥匙属不属于这个租户")
		return
	}
	client := ascapi.Client{
		Key:     ascapi.Key{IssuerID: issuer, KeyID: keyID, PrivateKeyPEM: pemText},
		BaseURL: s.ascBaseURL,
	}
	app, err := client.Verify(c.Request.Context(), identity.Value.BundleID)
	if err != nil {
		problem(c, http.StatusFailedDependency, "IOS_ASC_KEY_REJECTED", err.Error())
		return
	}

	current, err := s.iosASCRecordFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_CONFIG_INVALID", "Stored ios.asc configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_IOS_ASC", "App Store Connect 密钥已被改动，刷新后重试")
		return
	}
	ciphertext, err := s.secrets.Encrypt(pemText, iosASCAAD(tenantID(c)))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_SAVE_FAILED", "Unable to encrypt the App Store Connect key")
		return
	}
	now := time.Now().UTC()
	value := iosASC{
		IssuerID: issuer, KeyID: keyID, AppID: app.ID,
		PrivateKeyEncrypted: base64.RawStdEncoding.EncodeToString(ciphertext), VerifiedAt: &now,
	}
	stored, _ := json.Marshal(value)

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_SAVE_FAILED", "Unable to save the App Store Connect key")
		return
	}
	defer tx.Rollback()
	if mode, err := iosDeliveryModeLocked(c.Request.Context(), tx, tenantID(c)); err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_SAVE_FAILED", "Unable to save the App Store Connect key")
		return
	} else if mode == iosDeliveryIPA {
		problem(c, http.StatusConflict, "IOS_DELIVERY_SELF_UPLOAD", iosASCSelfUploadDetail)
		return
	}
	var result sql.Result
	newVersion := 1
	if currentVersion > 0 {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, actor(c), now, tenantID(c), iosASCConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(),
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), iosASCConfigKey, stored, actor(c), now, tenantID(c), iosASCConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_SAVE_FAILED", "Unable to save the App Store Connect key")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_IOS_ASC", "App Store Connect 密钥已被改动，刷新后重试")
		return
	}
	// 审计只记看得见的几项。私钥不进日志、不进审计、不经任何接口返回。
	event := newAudit(tenantID(c), actor(c), "ios_asc_credentials_update", "app-config", iosASCConfigKey, body.Reason, requestID(c),
		map[string]any{"issuerId": issuer, "keyId": keyID, "appId": app.ID, "appName": app.Name,
			"bundleId": app.BundleID, "verified": true, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_SAVE_FAILED", "Unable to save the App Store Connect key")
		return
	}
	c.JSON(http.StatusOK, iosASCView(&iosASCRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}))
}

// deleteIOSASCCredentials 退回模式 B。
func (s *server) deleteIOSASCCredentials(c *gin.Context) {
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_IOS_ASC", "reason 是必填的")
		return
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_DELETE_FAILED", "Unable to delete the App Store Connect key")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, tenantID(c), iosASCConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_DELETE_FAILED", "Unable to delete the App Store Connect key")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusNotFound, "IOS_ASC_NOT_FOUND", "这个租户没有装 App Store Connect 密钥")
		return
	}
	event := newAudit(tenantID(c), actor(c), "ios_asc_credentials_delete", "app-config", iosASCConfigKey, reason, requestID(c), map[string]any{})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_DELETE_FAILED", "Unable to delete the App Store Connect key")
		return
	}
	// 删掉本地那一份不等于这把钥匙作废：它在 Apple 那边还有效，还能被任何拿到 .p8
	// 的人使用。这句话必须出现在响应里，否则"删了"会被当成"吊销了"。
	c.JSON(http.StatusOK, gin.H{
		"configured": false,
		"reminder":   "平台这边已经删掉了。这把密钥在 Apple 那边仍然有效——要真正作废，去 App Store Connect → 用户和访问 → 集成 → 团队密钥里吊销它。",
	})
}

// ---- TestFlight 状态同步 ----

// syncIOSTestFlight 从 App Store Connect 拉一次状态，并把公开链接与当前 build 的过期
// 日回写进 release.ios。
//
// **只读 Apple 侧**：这里不建测试组、不开公开链接、不提审、不动测试员。那三件事永远
// 由人在 ASC 上点（设计 §4.6.6），理由是失败后果不对称——多开一个公开链接是把内测包
// 发给全世界，少开一个只是没人能装。
//
// 人工填过的链接不会被静默覆盖：那是一个人做过的决定，同步是一台机器的观察。
// 两者不一致时如实报出来，要以 Apple 那边为准就带 overrideManual=true 再来一次。
func (s *server) syncIOSTestFlight(c *gin.Context) {
	ctx := c.Request.Context()
	client, record, err := s.ascClientFor(ctx, tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "IOS_ASC_CONFIG_INVALID", err.Error())
		return
	}
	if client == nil || record == nil {
		problem(c, http.StatusConflict, "IOS_ASC_NOT_CONFIGURED",
			"这个租户没有装 App Store Connect 密钥（模式 B）。TestFlight 的公开链接与过期日在「分发入口」里人工维护。")
		return
	}
	identity, err := s.iosReleaseIdentityRecord(ctx, tenantID(c))
	if err != nil || identity == nil {
		problem(c, http.StatusConflict, "IOS_IDENTITY_INCOMPLETE", "这个租户还没有登记 iOS 发布身份")
		return
	}
	appID := strings.TrimSpace(record.Value.AppID)
	if appID == "" {
		app, findErr := client.FindApp(ctx, identity.Value.BundleID)
		if findErr != nil {
			problem(c, http.StatusFailedDependency, "IOS_ASC_SYNC_FAILED", findErr.Error())
			return
		}
		appID = app.ID
	}
	builds, err := client.LatestBuilds(ctx, appID, 10)
	if err != nil {
		problem(c, http.StatusFailedDependency, "IOS_ASC_SYNC_FAILED", err.Error())
		return
	}
	groups, err := client.BetaGroups(ctx, appID)
	if err != nil {
		problem(c, http.StatusFailedDependency, "IOS_ASC_SYNC_FAILED", err.Error())
		return
	}

	observed := observedTestFlight(builds, groups)
	value := identity.Value
	changes := map[string]any{}
	conflict := ""
	if observed.PublicLink != "" && observed.PublicLink != value.InstallURL {
		// 人工填过的不静默覆盖
		if value.InstallURLSource == iosInstallURLSourceManual && value.InstallURL != "" &&
			strings.TrimSpace(c.Query("overrideManual")) != "true" {
			conflict = "控制台里这条安装入口是人工填的，与 App Store Connect 上的公开链接不一致。" +
				"确认以 Apple 那边为准就带上 overrideManual=true 再同步一次。"
		} else {
			changes["installUrl"] = map[string]any{"from": value.InstallURL, "to": observed.PublicLink}
			value.InstallURL = observed.PublicLink
			value.InstallURLSource = iosInstallURLSourceSynced
		}
	}
	if observed.BuildExpiresAt != "" && observed.BuildExpiresAt != value.BuildExpiresAt {
		changes["buildExpiresAt"] = map[string]any{"from": value.BuildExpiresAt, "to": observed.BuildExpiresAt}
		value.BuildExpiresAt = observed.BuildExpiresAt
	}
	if len(changes) > 0 {
		value = normalizeIOSReleaseIdentity(value)
		if err := validateIOSReleaseIdentity(value); err != nil {
			// Apple 给回来的链接不在我们允许的域里：宁可不写，也不要存一个之后会被
			// 读取路径拒掉的值（parseIOSReleaseIdentity 会让整条记录读不出来）
			problem(c, http.StatusFailedDependency, "IOS_ASC_SYNC_FAILED",
				"App Store Connect 上的公开链接不是一个可接受的安装入口："+err.Error())
			return
		}
		if _, saveErr := s.writeIOSReleaseIdentity(c, value, identity.Version,
			"synced from App Store Connect",
			map[string]any{"source": "app-store-connect", "appId": appID, "changes": changes}); saveErr != nil {
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"appId":          appID,
		"builds":         testFlightBuildViews(builds),
		"groups":         testFlightGroupViews(groups),
		"installUrl":     nullableString(value.InstallURL),
		"buildExpiresAt": nullableString(value.BuildExpiresAt),
		"changed":        len(changes) > 0,
		"changes":        changes,
		"conflict":       nullableString(conflict),
	})
}

// testFlightObservation 是从 Apple 那边读到的、我们要落库的两件事。
type testFlightObservation struct {
	PublicLink     string
	BuildExpiresAt string
}

// observedTestFlight 从 build 与测试组里挑出"现在生效的那一份"。
//
// 公开链接只取**外部组**里开着的那一条：内部组没有公开链接，而多个外部组都开了链接
// 时取第一条并不比取最后一条更对——这种情况少见，出现了就让人去 ASC 上看清楚。
// 过期日取最新一个没过期的 build：那正是 §5 的 90 天时钟在算的东西。
func observedTestFlight(builds []ascapi.Build, groups []ascapi.BetaGroup) testFlightObservation {
	var observation testFlightObservation
	for _, group := range groups {
		if !group.IsInternal && group.PublicLinkEnabled && strings.TrimSpace(group.PublicLink) != "" {
			observation.PublicLink = strings.TrimSpace(group.PublicLink)
			break
		}
	}
	for _, build := range builds {
		if build.Expired || build.ExpirationDate == nil {
			continue
		}
		observation.BuildExpiresAt = build.ExpirationDate.UTC().Format(time.RFC3339)
		break
	}
	return observation
}

func testFlightBuildViews(builds []ascapi.Build) []gin.H {
	items := make([]gin.H, 0, len(builds))
	for _, build := range builds {
		items = append(items, gin.H{
			"id": build.ID, "version": build.Version, "processingState": build.ProcessingState,
			"expired": build.Expired, "expirationDate": nullableTimePointer(build.ExpirationDate),
			"uploadedDate": nullableTimePointer(build.UploadedDate),
		})
	}
	return items
}

func testFlightGroupViews(groups []ascapi.BetaGroup) []gin.H {
	items := make([]gin.H, 0, len(groups))
	for _, group := range groups {
		items = append(items, gin.H{
			"id": group.ID, "name": group.Name, "isInternal": group.IsInternal,
			"publicLinkEnabled": group.PublicLinkEnabled, "publicLink": nullableString(group.PublicLink),
			"publicLinkLimit": group.PublicLinkLimit,
		})
	}
	return items
}
