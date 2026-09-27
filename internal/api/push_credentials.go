package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/gin-gonic/gin"
)

// 推送凭据的服务端半边：服务账号私钥留在服务端，按租户存、用主密钥封。
//
// 另一半是编进 APK 的 google-services.json（build.android）。两者必须属于同一个
// Firebase 项目——对不上时构建成功、安装成功、token 注册成功，只有推送发不出去。
// 所以两边保存时互相校验，见 googleServicesProjectProblem 与 build_config.go。
//
// 设计见 docs/design/env-config-slimdown-2026-09-13.md §5，决策见 ADR-0017。

// pushCredentialBodyMax：服务账号 JSON 约 2.3 KB，base64 之后 3 KB 出头。64 KiB
// 留足余量，同时不给这个接口开一个更大的内存口子。
const pushCredentialBodyMax = 64 << 10

type pushCredentialWrite struct {
	// ServiceAccountJSON 接受 base64（控制台读文件之后传的形态）或原样 JSON。
	ServiceAccountJSON string `json:"serviceAccountJson"`
	ExpectedVersion    int    `json:"expectedVersion"`
	Reason             string `json:"reason"`
	Confirm            bool   `json:"confirm"`
}

func (s *server) verify(ctx context.Context, account pushcreds.ServiceAccount) error {
	if s.verifyFCM == nil {
		return pushcreds.Verify(ctx, account)
	}
	return s.verifyFCM(ctx, account)
}

func (s *server) getPushCredentials(c *gin.Context) {
	view, err := s.pushCredentialsView(c.Request.Context(), tenantID(c), isPlatformSession(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIALS_QUERY_FAILED", "Unable to load push credentials")
		return
	}
	c.JSON(http.StatusOK, view)
}

func (s *server) updatePushCredentialsFCM(c *gin.Context) { s.writePushFCM(c, tenantID(c)) }

// updatePlatformPushCredentialsFCM 改的是平台默认那一行，所有没单独配的租户都继承它。
func (s *server) updatePlatformPushCredentialsFCM(c *gin.Context) {
	s.writePushFCM(c, pushcreds.PlatformTenant)
}

func (s *server) writePushFCM(c *gin.Context, tenant string) {
	var body pushCredentialWrite
	if err := decodeLimited(c, &body, pushCredentialBodyMax); err != nil {
		if requestTooLarge(err) {
			problem(c, http.StatusRequestEntityTooLarge, "PUSH_CREDENTIAL_TOO_LARGE",
				"服务账号 JSON 太大了。正常的一份约 2 KB——确认传的不是别的文件")
			return
		}
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "serviceAccountJson, expectedVersion, reason 和 confirm=true 都是必填")
		return
	}
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "serviceAccountJson, expectedVersion, reason 和 confirm=true 都是必填")
		return
	}
	raw := decodePushCredentialPayload(body.ServiceAccountJSON)
	if len(raw) == 0 {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "serviceAccountJson 是空的")
		return
	}
	account, err := pushcreds.ParseServiceAccount(raw)
	if err != nil {
		if errors.Is(err, pushcreds.ErrLooksLikeGoogleServices) {
			problem(c, http.StatusUnprocessableEntity, "PUSH_CREDENTIAL_IS_GOOGLE_SERVICES", err.Error())
			return
		}
		problem(c, http.StatusUnprocessableEntity, "INVALID_PUSH_CREDENTIAL", "这不是一份可用的服务账号："+err.Error())
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusServiceUnavailable, "STORAGE_MASTER_KEY_REQUIRED", "保存推送凭据之前必须先配置 STORAGE_MASTER_KEY")
		return
	}

	// 与这个租户的 google-services.json 比项目。平台那一行不比：它服务的是所有
	// 继承者，拿任何一个租户的文件去卡它都不对；不匹配由各租户自己那一侧发现。
	if tenant != pushcreds.PlatformTenant {
		if detail := s.googleServicesProjectProblem(c.Request.Context(), tenant, account.ProjectID); detail != "" {
			problem(c, http.StatusUnprocessableEntity, "FCM_PROJECT_MISMATCH", detail)
			return
		}
	}

	// 换一次真令牌再保存。CredentialsFromJSON 只在本地解析、不联网，所以"能加载"
	// 证明不了这把钥匙还有效——密钥被吊销之后服务照样起得来，直到第一次真发推送
	// 才炸。不提供跳过开关：它存在的第一天就会有人在 Google 抽风时存进一把坏钥匙。
	if err := s.verify(c.Request.Context(), account); err != nil {
		problem(c, http.StatusFailedDependency, "FCM_CREDENTIAL_REJECTED", err.Error())
		return
	}

	current, err := pushcreds.LoadFCM(c.Request.Context(), s.db, tenant)
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

	sealed, err := pushcreds.Encrypt(s.secrets, tenant, raw)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to encrypt the service account")
		return
	}
	now := time.Now().UTC()
	value := pushcreds.FCM{
		ProjectID: account.ProjectID, ClientEmail: account.ClientEmail, PrivateKeyID: account.PrivateKeyID,
		ServiceAccountEncrypted: sealed, VerifiedAt: &now,
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
			stored, actor(c), now, tenant, pushcreds.FCMConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(),
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenant, pushcreds.FCMConfigKey, stored, actor(c), now, tenant, pushcreds.FCMConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to save push credentials")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_PUSH_CREDENTIAL", "推送凭据已被改动，刷新后重试")
		return
	}
	// 审计只记看得见的三项。私钥不进日志、不进审计、不经任何接口返回。
	event := newAudit(tenant, actor(c), "push_credentials_update", "app-config", pushcreds.FCMConfigKey, body.Reason, requestID(c),
		map[string]any{"provider": "fcm", "projectId": account.ProjectID, "clientEmail": account.ClientEmail,
			"privateKeyIdHint": pushcreds.KeyHint(account.PrivateKeyID), "verified": true, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_SAVE_FAILED", "Unable to save push credentials")
		return
	}
	view, _ := s.pushCredentialsView(c.Request.Context(), tenantID(c), isPlatformSession(c))
	c.JSON(http.StatusOK, view)
}

func (s *server) deletePushCredentialsFCM(c *gin.Context) { s.removePushFCM(c, tenantID(c)) }

// deletePlatformPushCredentialsFCM 删的是所有继承者共用的那一行。
func (s *server) deletePlatformPushCredentialsFCM(c *gin.Context) {
	s.removePushFCM(c, pushcreds.PlatformTenant)
}

func (s *server) removePushFCM(c *gin.Context, tenant string) {
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) < 3 {
		problem(c, http.StatusBadRequest, "INVALID_PUSH_CREDENTIAL", "reason 是必填的")
		return
	}
	// 删平台那一行不是"删一个配置"，是"关掉所有没单独配的租户的推送"。先数出
	// 有多少个租户正在继承它，没有明确确认就不动手。
	inheritors := 0
	if tenant == pushcreds.PlatformTenant {
		inheritors = s.pushCredentialInheritors(c.Request.Context())
		if inheritors > 0 && strings.TrimSpace(c.Query("confirm")) != "true" {
			problem(c, http.StatusConflict, "PUSH_CREDENTIAL_INHERITED",
				"有 "+strconv.Itoa(inheritors)+" 个租户正在继承平台默认的推送凭据，删掉之后它们的推送会立刻停。"+
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
	result, err := tx.ExecContext(c.Request.Context(), `DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, tenant, pushcreds.FCMConfigKey)
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_DELETE_FAILED", "Unable to delete push credentials")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusNotFound, "PUSH_CREDENTIAL_NOT_FOUND", "这一层没有自己的推送凭据")
		return
	}
	event := newAudit(tenant, actor(c), "push_credentials_delete", "app-config", pushcreds.FCMConfigKey, reason, requestID(c),
		map[string]any{"provider": "fcm", "inheritorsAffected": inheritors})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIAL_DELETE_FAILED", "Unable to delete push credentials")
		return
	}
	// 删完之后生效的是哪一个项目，要在响应里说清楚——租户那一层删掉会回落到
	// 平台默认，那通常不是"推送关掉了"的意思。
	view, _ := s.pushCredentialsView(c.Request.Context(), tenantID(c), isPlatformSession(c))
	view["inheritorsAffected"] = inheritors
	c.JSON(http.StatusOK, view)
}

// pushCredentialInheritors 数有多少个启用中的租户没有自己的推送凭据——也就是
// 正在吃平台默认那一行的。
func (s *server) pushCredentialInheritors(ctx context.Context) int {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenants t WHERE t.deleted=0 AND t.status=1
		   AND NOT EXISTS (SELECT 1 FROM app_configs c WHERE c.tenant_id=t.id AND c.config_key=?)`,
		pushcreds.FCMConfigKey).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

// testPushCredentialsFCM 用生效的凭据真换一次令牌。
//
// 保存时的验证只能证明**当时**有效。密钥在 Firebase 控制台被吊销之后，服务端这边
// 一点动静都没有，所以要留一个随时能问的入口。
func (s *server) testPushCredentialsFCM(c *gin.Context) {
	record, err := pushcreds.LoadFCM(c.Request.Context(), s.db, tenantID(c))
	if errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusPreconditionFailed, "FCM_NOT_CONFIGURED", "这个租户没有推送凭据，平台默认也没有")
		return
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "PUSH_CREDENTIALS_QUERY_FAILED", "Unable to load push credentials")
		return
	}
	// 继承来的是平台那一行：测试会改写它的 verifiedAt，由平台管理员来测（设计 tenant-console-accounts-and-sso §3.4）
	if record.Inherited(tenantID(c)) && !isPlatformSession(c) {
		pushCredentialsInherited(c)
		return
	}
	account, err := record.ServiceAccount(s.secrets)
	if err != nil {
		problem(c, http.StatusServiceUnavailable, "FCM_CREDENTIAL_UNREADABLE", "已保存的服务账号解不开："+err.Error())
		return
	}
	if err := s.verify(c.Request.Context(), account); err != nil {
		s.auditPushCredentialTest(c, "fcm", record.Inherited(tenantID(c)), "FCM_CREDENTIAL_REJECTED")
		problem(c, http.StatusFailedDependency, "FCM_CREDENTIAL_REJECTED", err.Error())
		return
	}
	s.auditPushCredentialTest(c, "fcm", record.Inherited(tenantID(c)), "")
	// 验过就刷一下 verifiedAt：界面上"上次验证于"是这条链路唯一的活性证据
	now := time.Now().UTC()
	record.Value.VerifiedAt = &now
	if stored, marshalErr := json.Marshal(record.Value); marshalErr == nil {
		_, _ = s.db.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			stored, now, record.SourceTenant, pushcreds.FCMConfigKey, record.Version)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "provider": "fcm", "projectId": account.ProjectID,
		"inherited": record.Inherited(tenantID(c)), "checkedAt": iso(now)})
}

// pushCredentialsInherited：租户会话不能测平台默认那一行。
func pushCredentialsInherited(c *gin.Context) {
	problem(c, http.StatusForbidden, "PUSH_CREDENTIALS_INHERITED",
		"这个租户用的是平台默认的推送凭据，由平台管理员维护与测试；要自己测，先给本租户单独配一份")
}

// auditPushCredentialTest 记一次推送凭据测试（原来不记，测试又会改写 verifiedAt）。problemCode 空 = 通过。
func (s *server) auditPushCredentialTest(c *gin.Context, provider string, inherited bool, problemCode string) {
	s.auditNow(newAudit(tenantID(c), actor(c), "push_credentials_test", "push-credentials", provider, "测试推送凭据", requestID(c),
		map[string]any{"provider": provider, "inherited": inherited, "ok": problemCode == "", "problem": nullableString(problemCode)}))
}

// hidePlatformPushRow：租户会话看继承来的平台那一行时，不给平台的服务账号、密钥提示与修改人
// （设计 tenant-console-accounts-and-sso §3.4）。项目 id、Team 留着：租户要拿它对自己的 google-services.json、bundle id。
func hidePlatformPushRow(view gin.H, keys ...string) {
	if view["inherited"] != true {
		return
	}
	for _, key := range append([]string{"sourceTenant", "updatedBy", "updatedAt"}, keys...) {
		delete(view, key)
	}
}

// pushCredentialsView 是三个 provider 的一次性视图。
//
// FCM 那一段额外带上 google-services.json 的项目与匹配结果：控制台不该自己再去
// 比一次，两处各比一次迟早会得出不同的答案。
func (s *server) pushCredentialsView(ctx context.Context, tenant string, showPlatformRow bool) (gin.H, error) {
	fcm := gin.H{"configured": false, "inherited": false, "version": 0}
	record, err := pushcreds.LoadFCM(ctx, s.db, tenant)
	switch {
	case err == nil:
		fcm = gin.H{
			"configured":   record.Value.ServiceAccountEncrypted != "",
			"inherited":    record.Inherited(tenant),
			"sourceTenant": record.SourceTenant, "version": record.Version,
			"projectId": record.Value.ProjectID, "clientEmail": record.Value.ClientEmail,
			"privateKeyIdHint": pushcreds.KeyHint(record.Value.PrivateKeyID),
			"verifiedAt":       nullableTimePointer(record.Value.VerifiedAt),
			"updatedBy":        record.UpdatedBy, "updatedAt": nullableTime(record.UpdatedAt),
		}
	case errors.Is(err, sql.ErrNoRows):
		// 没配。过渡期 env 里可能还留着一份，那条路只在派发时兜底，界面上不假装它配好了
	default:
		return nil, err
	}

	googleProject := s.storedGoogleServicesProjectID(ctx, tenant)
	fcm["googleServicesProjectId"] = nullableString(googleProject)
	// 三态：两边都配好了才有真假可言，缺一边就是 null——界面据此显示"待配置"
	// 而不是一个红叉
	if googleProject != "" && fcm["configured"] == true {
		fcm["projectMatches"] = googleProject == fcm["projectId"]
	} else {
		fcm["projectMatches"] = nil
	}

	// HMS 仍不进库：没有租户在用，而它的字段形状和前两家都不同，现在设计等于凭空猜。
	// 位置先占住，界面上画出来标"未接入"。
	apns := s.apnsCredentialView(ctx, tenant)
	if !showPlatformRow {
		hidePlatformPushRow(fcm, "clientEmail", "privateKeyIdHint")
		hidePlatformPushRow(apns, "keyIdHint")
	}
	return gin.H{"fcm": fcm,
		"apns": apns,
		"hms":  gin.H{"configured": false, "inherited": false, "version": 0}}, nil
}

// googleServicesProjectProblem 检查服务账号与这个租户的 google-services.json 是不是
// 同一个 Firebase 项目。空串表示没问题（含"还没传文件"）。
func (s *server) googleServicesProjectProblem(ctx context.Context, tenant, serviceAccountProject string) string {
	stored := s.storedGoogleServicesProjectID(ctx, tenant)
	if stored == "" || stored == serviceAccountProject {
		return ""
	}
	return "这把服务账号属于 Firebase 项目 " + serviceAccountProject + "，而本租户的 google-services.json 来自项目 " +
		stored + "。两者必须是同一个项目，否则设备能注册、推送发不出去（FCM 回 SENDER_ID_MISMATCH）。" +
		"要么换一份同项目的服务账号，要么在「打包与签名」页换掉 google-services.json"
}

// pushCredentialProjectProblem 是 googleServicesProjectProblem 的反方向：换
// google-services.json 时，看它和已生效的推送凭据是不是同一个项目。
//
// 继承来的凭据也算数，但报错要说清楚这一层——"服务端凭据是平台默认的项目 X"，
// 否则看的人会在自己的页面上找一份根本不在那儿的配置。
func (s *server) pushCredentialProjectProblem(ctx context.Context, tenant, fileProject string) string {
	if fileProject == "" {
		return ""
	}
	record, err := pushcreds.LoadFCM(ctx, s.db, tenant)
	if err != nil || record.Value.ProjectID == "" || record.Value.ProjectID == fileProject {
		return ""
	}
	where := "本租户的推送凭据"
	fix := "要么换一份属于项目 " + record.Value.ProjectID + " 的 google-services.json，要么在下方更新推送凭据"
	if record.Inherited(tenant) {
		where = "服务端推送凭据是平台默认的"
		fix = "要么换一份属于项目 " + record.Value.ProjectID + " 的 google-services.json，" +
			"要么给本租户单独配一份属于项目 " + fileProject + " 的服务账号"
	}
	return "这份 google-services.json 来自 Firebase 项目 " + fileProject + "，而" + where + "属于项目 " +
		record.Value.ProjectID + "。两者必须是同一个项目，否则设备能注册、推送发不出去。" + fix
}

func (s *server) storedGoogleServicesProjectID(ctx context.Context, tenant string) string {
	var raw []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE config_key=? AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`,
		buildConfigKey, tenant, tenant).Scan(&raw)
	if err != nil {
		return ""
	}
	var cfg buildConfig
	if json.Unmarshal(raw, &cfg) != nil {
		return ""
	}
	return googleServicesProjectIDFromBase64(cfg.GoogleServicesJSON)
}

// decodePushCredentialPayload 接受 base64（控制台读文件之后的形态）或原样 JSON。
// 原样 JSON 以 '{' 开头，不会被误判成 base64。
func decodePushCredentialPayload(value string) []byte {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded
	}
	return []byte(trimmed)
}

func nullableTimePointer(value *time.Time) any {
	if value == nil {
		return nil
	}
	return nullableTime(*value)
}
