package api

// APNs 的管理端半边。路径、状态码、乐观锁、审计字段全部照 push_credentials.go
// 的 FCM 那一套来（设计 docs/design/push-apns-and-shared-app-identity-2026-09-18.md §2）。
//
// 只有两处结构性差异：
//
//   - topic 不存在 push.apns 里，取该租户 release.ios 的 bundleId。保存和验证
//     都要先拿到它，没配就直接拦下——没有 bundle id 时本来就没有能收推送的 App。
//   - 验证不是"换一次令牌"，是真发一条静默推送探活（pushcreds.VerifyAPNs）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/gin-gonic/gin"
)

// apnsCredentialBodyMax：.p8 约 250 字节，base64 之后还是几百字节。和 FCM 用
// 同一个上限，省得两个接口各有一套说法。
const apnsCredentialBodyMax = pushCredentialBodyMax

type apnsCredentialWrite struct {
	// AuthKeyP8 接受 base64（控制台读文件之后传的形态）或原样 PEM。
	AuthKeyP8 string `json:"authKeyP8"`
	TeamID    string `json:"teamId"`
	KeyID     string `json:"keyId"`
	// Environment 空 = production（设计 §2.4）。
	Environment     string `json:"environment"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

func (s *server) verifyAPNsCredential(ctx context.Context, value pushcreds.APNs, authKey []byte, bundleID string) error {
	if s.verifyAPNs == nil {
		return pushcreds.VerifyAPNs(ctx, value, authKey, bundleID)
	}
	return s.verifyAPNs(ctx, value, authKey, bundleID)
}

// apnsTopic 取该租户 release.ios 的 bundleId。
//
// 平台那一行（tenant 0）没有自己的 iOS 身份——它服务的是所有继承者。要验证它，
// 得借一个租户的 bundle id，而"借哪个"没有正确答案，所以平台层不验证，只校验
// 形状；不匹配由各租户自己那一侧发现（与 FCM 不比平台层项目同理）。
func (s *server) apnsTopic(ctx context.Context, tenant string) (string, error) {
	identity, err := s.iosReleaseIdentityRecord(ctx, tenant)
	if err != nil {
		return "", err
	}
	if identity == nil {
		return "", nil
	}
	return strings.TrimSpace(identity.Value.BundleID), nil
}

func (s *server) updatePushCredentialsAPNs(c *gin.Context) { s.writePushAPNs(c, tenantID(c)) }

// updatePlatformPushCredentialsAPNs 改的是平台默认那一行，所有没单独配的租户都继承它。
func (s *server) updatePlatformPushCredentialsAPNs(c *gin.Context) {
	s.writePushAPNs(c, pushcreds.PlatformTenant)
}

func (s *server) writePushAPNs(c *gin.Context, tenant string) {
	var body apnsCredentialWrite
	if err := decodeLimited(c, &body, apnsCredentialBodyMax); err != nil {
		if requestTooLarge(err) {
			problem(c, http.StatusRequestEntityTooLarge, "PUSH_CREDENTIAL_TOO_LARGE",
				"密钥文件太大了。一份 .p8 只有几百字节——确认传的不是别的文件")
			return
		}
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "authKeyP8, teamId, keyId, expectedVersion, reason 和 confirm=true 都是必填")
		return
	}
	teamID := strings.TrimSpace(body.TeamID)
	keyID := strings.TrimSpace(body.KeyID)
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 || teamID == "" || keyID == "" {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "authKeyP8, teamId, keyId, expectedVersion, reason 和 confirm=true 都是必填")
		return
	}
	environment, err := pushcreds.NormalizeAPNsEnvironment(body.Environment)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", err.Error())
		return
	}
	raw := decodePushCredentialPayload(body.AuthKeyP8)
	if len(raw) == 0 {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "authKeyP8 是空的")
		return
	}
	if err := pushcreds.ParseAPNsAuthKey(raw); err != nil {
		if errors.Is(err, pushcreds.ErrLooksLikeCertificate) {
			problem(c, http.StatusUnprocessableEntity, "PUSH_CREDENTIAL_IS_CERTIFICATE", err.Error())
			return
		}
		problem(c, http.StatusUnprocessableEntity, "INVALID_PUSH_CREDENTIAL", "这不是一份可用的 .p8 令牌密钥："+err.Error())
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "保存推送凭据之前必须先配置 STORAGE_MASTER_KEY")
		return
	}

	value := pushcreds.APNs{TeamID: teamID, KeyID: keyID, Environment: environment}

	// 真发一条探活再保存。和 FCM 一样不提供跳过开关（ADR-0017）。平台那一行
	// 没有自己的 bundle id，跳过这一步——见 apnsTopic 的说明。
	if tenant != pushcreds.PlatformTenant {
		topic, topicErr := s.apnsTopic(c.Request.Context(), tenant)
		if topicErr != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
			return
		}
		if topic == "" {
			problem(c, http.StatusPreconditionFailed, "IOS_BUNDLE_ID_REQUIRED",
				"这个租户还没有 iOS bundle id。APNs 的 topic 取自它，先到「iOS 打包与分发」配好应用身份")
			return
		}
		if err := s.verifyAPNsCredential(c.Request.Context(), value, raw, topic); err != nil {
			code := "APNS_CREDENTIAL_REJECTED"
			if errors.Is(err, pushcreds.ErrAPNsTopicDisallowed) {
				code = "APNS_TOPIC_DISALLOWED"
			}
			problem(c, http.StatusFailedDependency, code, err.Error())
			return
		}
	}

	current, err := pushcreds.LoadAPNs(c.Request.Context(), s.db, tenant)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIALS_QUERY_FAILED", "Unable to load push credentials")
		return
	}
	// 乐观锁只认**这个租户自己**那一行：继承来的版本号不是它的
	currentVersion := 0
	if err == nil && current.SourceTenant == tenant {
		currentVersion = current.Version
	}
	if currentVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_PUSH_CREDENTIAL", "推送凭据已被改动，刷新后重试")
		return
	}

	sealed, err := pushcreds.EncryptAPNsAuthKey(s.secrets, tenant, raw)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to encrypt the APNs auth key")
		return
	}
	now := time.Now().UTC()
	value.AuthKeyEncrypted = sealed
	if tenant != pushcreds.PlatformTenant {
		value.VerifiedAt = &now
	}
	stored, _ := json.Marshal(value)

	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to save push credentials")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if currentVersion > 0 {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, actor(c), now, tenant, pushcreds.APNsConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(),
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenant, pushcreds.APNsConfigKey, stored, actor(c), now, tenant, pushcreds.APNsConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to save push credentials")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_PUSH_CREDENTIAL", "推送凭据已被改动，刷新后重试")
		return
	}
	// 审计只记看得见的几项。.p8 不进日志、不进审计、不经任何接口返回。
	event := newAudit(tenant, actor(c), "push_credentials_update", "app-config", pushcreds.APNsConfigKey, body.Reason, requestID(c),
		map[string]any{"provider": "apns", "teamId": teamID, "keyIdHint": pushcreds.KeyHint(keyID),
			"environment": environment, "verified": tenant != pushcreds.PlatformTenant, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to save push credentials")
		return
	}
	c.JSON(http.StatusOK, s.pushCredentialsAfterWrite(c, tenant))
}

func (s *server) deletePushCredentialsAPNs(c *gin.Context) { s.removePushAPNs(c, tenantID(c)) }

// deletePlatformPushCredentialsAPNs 删的是所有继承者共用的那一行。
func (s *server) deletePlatformPushCredentialsAPNs(c *gin.Context) {
	s.removePushAPNs(c, pushcreds.PlatformTenant)
}

func (s *server) removePushAPNs(c *gin.Context, tenant string) {
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "reason 是必填的")
		return
	}
	inheritors := 0
	if tenant == pushcreds.PlatformTenant {
		inheritors = s.apnsCredentialInheritors(c.Request.Context())
		if inheritors > 0 && strings.TrimSpace(c.Query("confirm")) != "true" {
			problem(c, http.StatusConflict, "PUSH_CREDENTIAL_INHERITED",
				"有 "+strconv.Itoa(inheritors)+" 个租户正在继承平台默认的 APNs 凭据，删掉之后它们的 iOS 推送会立刻停。"+
					"确认要删就带上 confirm=true")
			return
		}
	}
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_DELETE_FAILED", "Unable to delete push credentials")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(c.Request.Context(), `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, pushcreds.APNsConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_DELETE_FAILED", "Unable to delete push credentials")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusNotFound, "PUSH_CREDENTIAL_NOT_FOUND", "这一层没有自己的 APNs 凭据")
		return
	}
	event := newAudit(tenant, actor(c), "push_credentials_delete", "app-config", pushcreds.APNsConfigKey, reason, requestID(c),
		map[string]any{"provider": "apns", "inheritorsAffected": inheritors})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_DELETE_FAILED", "Unable to delete push credentials")
		return
	}
	view := s.pushCredentialsAfterWrite(c, tenant)
	view["inheritorsAffected"] = inheritors
	c.JSON(http.StatusOK, view)
}

// apnsCredentialInheritors 数有多少个启用中的租户没有自己的 APNs 凭据。
func (s *server) apnsCredentialInheritors(ctx context.Context) int {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenants t WHERE t.deleted=0 AND t.status=1
		   AND NOT EXISTS (SELECT 1 FROM app_configs c WHERE c.tenant_id=t.id AND c.config_key=?)`,
		pushcreds.APNsConfigKey).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// testPushCredentialsAPNs 用生效的凭据再探活一次。
//
// 保存时的验证只能证明**当时**有效。.p8 在 Apple 后台被吊销之后服务端这边一点
// 动静都没有，所以要留一个随时能问的入口（与 FCM 的 test 同理）。
func (s *server) testPushCredentialsAPNs(c *gin.Context) {
	tenant := tenantID(c)
	record, err := pushcreds.LoadAPNs(c.Request.Context(), s.db, tenant)
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusPreconditionFailed, "APNS_NOT_CONFIGURED", "这个租户没有 APNs 凭据，平台默认也没有")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIALS_QUERY_FAILED", "Unable to load push credentials")
		return
	}
	// 继承来的是平台那一行：由平台管理员来测（见 testPushCredentialsFCM）
	if record.Inherited(tenant) && !isPlatformSession(c) {
		pushCredentialsInherited(c)
		return
	}
	authKey, err := record.AuthKey(s.secrets)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "APNS_CREDENTIAL_UNREADABLE", "已保存的 .p8 解不开："+err.Error())
		return
	}
	topic, err := s.apnsTopic(c.Request.Context(), tenant)
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.ios configuration is invalid")
		return
	}
	if topic == "" {
		problem(c, http.StatusPreconditionFailed, "IOS_BUNDLE_ID_REQUIRED",
			"这个租户还没有 iOS bundle id。APNs 的 topic 取自它，先到「iOS 打包与分发」配好应用身份")
		return
	}
	if err := s.verifyAPNsCredential(c.Request.Context(), record.Value, authKey, topic); err != nil {
		code := "APNS_CREDENTIAL_REJECTED"
		if errors.Is(err, pushcreds.ErrAPNsTopicDisallowed) {
			code = "APNS_TOPIC_DISALLOWED"
		}
		s.auditPushCredentialTest(c, "apns", record.Inherited(tenant), code)
		problem(c, http.StatusFailedDependency, code, err.Error())
		return
	}
	s.auditPushCredentialTest(c, "apns", record.Inherited(tenant), "")
	now := time.Now().UTC()
	record.Value.VerifiedAt = &now
	if stored, marshalErr := json.Marshal(record.Value); marshalErr == nil {
		_, _ = s.db.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, now, record.SourceTenant, pushcreds.APNsConfigKey, record.Version)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "provider": "apns", "teamId": record.Value.TeamID, "topic": topic,
		"environment": record.Value.Environment, "inherited": record.Inherited(tenant), "checkedAt": iso(now)})
}

// apnsCredentialView 是 pushCredentialsView 里的 apns 那一段。
//
// 带上 topic（该租户的 bundle id）和它配没配：凭据本身没问题、但 bundle id 还没
// 配时，界面要说得出"缺的是另一半"，而不是一个红叉。
func (s *server) apnsCredentialView(ctx context.Context, tenant string) gin.H {
	view := gin.H{"configured": false, "inherited": false, "version": 0}
	record, err := pushcreds.LoadAPNs(ctx, s.db, tenant)
	if err == nil {
		view = gin.H{
			"configured":   record.Value.AuthKeyEncrypted != "",
			"inherited":    record.Inherited(tenant),
			"sourceTenant": record.SourceTenant, "version": record.Version,
			"teamId":      record.Value.TeamID,
			"keyIdHint":   pushcreds.KeyHint(record.Value.KeyID),
			"environment": record.Value.Environment,
			"verifiedAt":  nullableTimePointer(record.Value.VerifiedAt),
			"updatedBy":   record.UpdatedBy, "updatedAt": nullableTime(record.UpdatedAt),
		}
	}
	// topic 不在这条记录里（设计 §2.2），每次现取。
	topic, topicErr := s.apnsTopic(ctx, tenant)
	if topicErr == nil {
		view["topic"] = nullableString(topic)
	} else {
		view["topic"] = nil
	}
	return view
}
