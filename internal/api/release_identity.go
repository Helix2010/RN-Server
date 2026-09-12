package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/apkinspect"
	"github.com/Helix2010/RN-Server/internal/objectstore"
	"github.com/gin-gonic/gin"
)

// release.android：租户 Android 正式包身份（包名 + 签名证书 SHA-256），存 app_configs，
// 只读租户自己那一行——签名者 pin 不能从平台级（tenant 0）继承，没配就是没配。
const releaseAndroidIdentityConfigKey = "release.android"

// React Native 模板附带的公开 debug keystore 的证书指纹。任何人都持有这把密钥，
// 用它签出的安装包在任何环境、任何租户都不允许入库，也不允许被 pin。
//
// 值放在 internal/androidkeystore：打包代理那边有同一道闸，而两份各写各的字面量
// 已经出过一次事——代理那份填的是 debug key 的 SHA-1 补零凑到 64 位，于是那道闸
// 永远匹配不上。
const reactNativeDebugSignerSHA256 = androidkeystore.PublicDebugSignerSHA256

var (
	androidPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
	sha256HexPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type androidReleaseIdentity struct {
	PackageName  string `json:"packageName"`
	SignerSHA256 string `json:"signerSha256"`
}

type androidReleaseIdentityWrite struct {
	PackageName     string `json:"packageName"`
	SignerSHA256    string `json:"signerSha256"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

type androidReleaseIdentityRecord struct {
	Value     androidReleaseIdentity
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

func normalizeFingerprint(v string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(v), ":", ""))
}

func normalizeAndroidReleaseIdentity(v androidReleaseIdentity) androidReleaseIdentity {
	return androidReleaseIdentity{PackageName: strings.TrimSpace(v.PackageName), SignerSHA256: normalizeFingerprint(v.SignerSHA256)}
}

func validateAndroidReleaseIdentity(v androidReleaseIdentity) error {
	if len(v.PackageName) > 255 || !androidPackagePattern.MatchString(v.PackageName) {
		return errors.New("packageName must be a valid Android application id")
	}
	if !sha256HexPattern.MatchString(v.SignerSHA256) {
		return errors.New("signerSha256 must be the certificate SHA-256 as 64 lowercase hex characters")
	}
	if v.SignerSHA256 == reactNativeDebugSignerSHA256 {
		return errors.New("signerSha256 is the public React Native debug key and cannot be pinned")
	}
	return nil
}

func parseAndroidReleaseIdentity(raw []byte) (androidReleaseIdentity, error) {
	var v androidReleaseIdentity
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("release.android is not valid JSON: %w", err)
	}
	v = normalizeAndroidReleaseIdentity(v)
	if err := validateAndroidReleaseIdentity(v); err != nil {
		return v, err
	}
	return v, nil
}

// checkAndroidReleaseIdentity 决定一个已解析的 APK 能否入库；空码表示通过。
// 顺序：公开 debug 密钥 → 生产环境未 pin → 包名 → 签名者。
func checkAndroidReleaseIdentity(apk apkinspect.Metadata, pin *androidReleaseIdentity, production bool) (code, detail string) {
	signer := normalizeFingerprint(apk.SignerSHA256)
	if signer == reactNativeDebugSignerSHA256 {
		return "RELEASE_DEBUG_SIGNER", "APK is signed with the public React Native debug key"
	}
	if pin == nil {
		if production {
			return "RELEASE_SIGNER_UNPINNED", "Tenant has no release.android identity pin; set packageName and signerSha256 before uploading"
		}
		return "", ""
	}
	if apk.PackageName != pin.PackageName {
		return "RELEASE_PACKAGE_MISMATCH", "APK package name does not match the tenant Android package"
	}
	if signer != pin.SignerSHA256 {
		return "RELEASE_SIGNER_MISMATCH", "APK signer certificate does not match the tenant release signing key"
	}
	return "", ""
}

// normalizeEtag 统一 ETag 形态：objectstore.Stat 已去引号，这里再去一次以容纳手工写入或旧记录里带引号的值。
func normalizeEtag(v string) string { return strings.Trim(strings.TrimSpace(v), `"`) }

// objectIntegrityMismatch 比对下发前 Stat 到的对象大小/ETag 与入库值，返回不一致的维度；
// 空串表示一致。storedEtag 为空只允许出现在改动前入库、file_metadata 里没有 objectEtag 键的记录上
// （调用方已用 storedMetadataField 区分"键不存在"与"键存在但为空"，后者是 500 数据事故）。
// 分段上传对象的 ETag 形如 "<md5>-<n>"，同一对象再次 Stat 得到相同值，直接按字串比对即可。
func objectIntegrityMismatch(actual objectstore.ObjectInfo, storedSize int64, storedEtag string) string {
	if storedSize >= 0 && actual.Size != storedSize {
		return "size"
	}
	if storedEtag != "" && normalizeEtag(actual.ETag) != normalizeEtag(storedEtag) {
		return "etag"
	}
	return ""
}

// auditNow 给没有外层事务的路径（公开下载、入库前的拒绝）写审计；写失败只记日志，不改变主响应。
func (s *server) auditNow(event auditEvent) {
	if s.db == nil {
		// 只会出现在没有数据库的单测里；生产构造 server 时数据库是必填项
		slog.Error("audit write skipped: server has no database", "action", event.Action, "target", event.TargetID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("audit write failed", "action", event.Action, "target", event.TargetID, "error", err)
		return
	}
	if err := insertAudit(ctx, tx, event); err != nil {
		_ = tx.Rollback()
		slog.Error("audit write failed", "action", event.Action, "target", event.TargetID, "error", err)
		return
	}
	if err := tx.Commit(); err != nil {
		slog.Error("audit write failed", "action", event.Action, "target", event.TargetID, "error", err)
	}
}

func (s *server) androidReleaseIdentityRecord(ctx context.Context, tenant string) (*androidReleaseIdentityRecord, error) {
	var raw []byte
	var record androidReleaseIdentityRecord
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, releaseAndroidIdentityConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Value, err = parseAndroidReleaseIdentity(raw); err != nil {
		return nil, err
	}
	return &record, nil
}

func androidReleaseIdentityView(record *androidReleaseIdentityRecord) gin.H {
	if record == nil {
		return gin.H{"configured": false, "identity": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	return gin.H{
		"configured": true,
		"identity":   gin.H{"packageName": record.Value.PackageName, "signerSha256": record.Value.SignerSHA256},
		"version":    record.Version,
		"updatedBy":  record.UpdatedBy,
		"updatedAt":  iso(record.UpdatedAt),
	}
}

func (s *server) getAndroidReleaseIdentity(c *gin.Context) {
	record, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, androidReleaseIdentityView(record))
}

func (s *server) updateAndroidReleaseIdentity(c *gin.Context) {
	var body androidReleaseIdentityWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", "packageName, signerSha256, expectedVersion, reason and confirm=true are required")
		return
	}
	value := normalizeAndroidReleaseIdentity(androidReleaseIdentity{PackageName: body.PackageName, SignerSHA256: body.SignerSHA256})
	if err := validateAndroidReleaseIdentity(value); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", err.Error())
		return
	}
	current, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
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
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), releaseAndroidIdentityConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), releaseAndroidIdentityConfigKey, raw, actor(c), now, tenantID(c), releaseAndroidIdentityConfigKey)
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
		previous = map[string]any{"packageName": current.Value.PackageName, "signerSha256": current.Value.SignerSHA256}
	}
	event := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseAndroidIdentityConfigKey, body.Reason, requestID(c), map[string]any{"packageName": value.PackageName, "signerSha256": value.SignerSHA256, "previous": previous, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	}
	c.JSON(http.StatusOK, androidReleaseIdentityView(&androidReleaseIdentityRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}))
}

// storedMetadataField 读 file_metadata 里的字串字段，并区分三种情况：
//   - 键不存在（或整条记录没有元数据）：present=false，value=""，改动前入库的旧记录；
//   - 键存在且是非空字串：present=true；
//   - 有内容却不是合法 JSON、或键存在但为空 / 不是字串：数据事故，返回错误，调用方以 500 拒绝，
//     不当成"没记录"放行（入库路径从不写空值，空值只能是被改过）。
func storedMetadataField(raw []byte, key string) (value string, present bool, err error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "", false, nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return "", false, fmt.Errorf("file_metadata is not valid JSON: %w", err)
	}
	item, exists := metadata[key]
	if !exists {
		return "", false, nil
	}
	text, isString := item.(string)
	if !isString || strings.TrimSpace(text) == "" {
		return "", true, fmt.Errorf("file_metadata.%s is present but empty or not a string", key)
	}
	return strings.TrimSpace(text), true, nil
}

// storedMetadataString：只关心值的调用方（键不存在与合法值都直接用，损坏才报错）。
func storedMetadataString(raw []byte, key string) (string, error) {
	value, _, err := storedMetadataField(raw, key)
	return value, err
}

// verifyStoredObject 在下发前核对对象存储里的东西还是入库时校验过的那一个。
// 返回 Stat 错误（对象存储不可用，调用方 502）、或不一致的维度（"size" / "etag"，调用方拒绝并留痕）。
func verifyStoredObject(ctx context.Context, client objectstore.Client, key string, storedSize int64, storedEtag string) (objectstore.ObjectInfo, string, error) {
	info, err := client.Stat(ctx, key)
	if err != nil {
		return objectstore.ObjectInfo{}, "", err
	}
	return info, objectIntegrityMismatch(info, storedSize, storedEtag), nil
}

// objectChangeNotices 让"对象被改写"的 error 日志与审计每 (kind, tenant, id, mismatch) 在 TTL 内只写一次：
// 公开下载端点无认证，被替换的对象会被反复请求，每次都写审计会把 audit_events 灌满。请求本身照样拒绝。
type objectChangeNotices struct {
	ttl  time.Duration
	seen sync.Map
}

const objectChangeNoticeTTL = 10 * time.Minute

var objectChanges = &objectChangeNotices{ttl: objectChangeNoticeTTL}

// shouldNotify 第一次或上次通知已过 TTL 时返回 true。
func (n *objectChangeNotices) shouldNotify(key string, now time.Time) bool {
	for {
		previous, loaded := n.seen.LoadOrStore(key, now)
		if !loaded {
			return true
		}
		last, _ := previous.(time.Time)
		if now.Sub(last) < n.ttl {
			return false
		}
		if n.seen.CompareAndSwap(key, previous, now) {
			return true
		}
	}
}

// noteObjectChanged 记 error 日志并写审计（去重后），供公开下载与 OTA 资源下发路径共用。
func (s *server) noteObjectChanged(kind, tenant, id, mismatch, requestID string, actual objectstore.ObjectInfo, storedSize int64, storedEtag string, extra map[string]any) {
	if !objectChanges.shouldNotify(kind+":"+tenant+":"+id+":"+mismatch, time.Now()) {
		return
	}
	summary := map[string]any{"mismatch": mismatch, "storedSize": storedSize, "objectSize": actual.Size, "storedEtag": storedEtag, "objectEtag": actual.ETag}
	for k, v := range extra {
		summary[k] = v
	}
	slog.Error("stored object changed after verification", "kind", kind, "tenant", tenant, "id", id, "mismatch", mismatch, "storedSize", storedSize, "objectSize", actual.Size)
	actorID, action, targetType, reason := "system-release", "release_object_changed", "release", "Object storage content no longer matches the verified release"
	if kind == "ota" {
		actorID, action, targetType, reason = "system-ota", "ota_object_changed", "ota-release", "Object storage content no longer matches the verified OTA package"
	}
	s.auditNow(newAudit(tenant, actorID, action, targetType, id, reason, requestID, summary))
}

// wellKnownAssetLinks 按租户域名提供 Android App Links 的归属声明
// （`/.well-known/assetlinks.json`，安全评审 N13）。
//
// 自定义 scheme（`anyfun://`）谁都能在自己的 manifest 里声明，装了恶意应用的
// 机器上，外部钱包批准后的回跳可能被它接走。App Link 把链接绑在租户自己的
// 域名上：系统安装应用时来拉这个文件，只有文件里列出的包名 + 签名指纹才允许
// 接管该域名的链接，抢注不了。
//
// 内容直接由已登记的发布身份（`release.android` 的 packageName + signerSha256）
// 生成，不引入第二份真相源 —— 指纹改了、包名改了，这个文件自动跟着变。
// 没有登记 pin 的租户返回 404：宁可让系统判定"未声明"，也不能发一份猜出来的
// 授权，那等于把域名交给一个我们并不确认的应用。
func (s *server) wellKnownAssetLinks(c *gin.Context) {
	record, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
		return
	}
	if record == nil {
		problem(c, http.StatusNotFound, "RELEASE_IDENTITY_NOT_CONFIGURED", "This tenant has not registered an Android release identity")
		return
	}
	fingerprint, ok := colonFingerprint(record.Value.SignerSHA256)
	if !ok {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Registered signer fingerprint is not a SHA-256 digest")
		return
	}
	// Google 只接受这一种形状；缓存一小时，指纹轮换后不至于长期发旧文件
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, []gin.H{{
		"relation": []string{"delegate_permission/common.handle_all_urls"},
		"target": gin.H{
			"namespace":                "android_app",
			"package_name":             record.Value.PackageName,
			"sha256_cert_fingerprints": []string{fingerprint},
		},
	}})
}

// colonFingerprint 把入库的 64 位小写十六进制指纹转成 Google 要求的
// `AA:BB:…` 大写冒号分隔形式。长度或字符不对就返回 false，不猜。
func colonFingerprint(raw string) (string, bool) {
	normalized := normalizeFingerprint(raw)
	if len(normalized) != 64 {
		return "", false
	}
	parts := make([]string, 0, 32)
	for i := 0; i < len(normalized); i += 2 {
		pair := normalized[i : i+2]
		for _, ch := range pair {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return "", false
			}
		}
		parts = append(parts, strings.ToUpper(pair))
	}
	return strings.Join(parts, ":"), true
}
