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

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
	"github.com/gin-gonic/gin"
)

// Android 签名密钥（`app_configs` 的 `build.keystore`）。
//
// 这条路径与 OTA 签名密钥**刻意不同**：OTA 私钥是服务端自己要用来签 manifest 的，
// 所以它在服务端生成、用 storage master key 加密、服务端解得开。Android keystore
// 服务端运行时根本不用，而它泄露在 direct 分发下没有补救办法——所以服务端**不能**
// 有打开它的能力。
//
// 做法：运维在本机用自己的口令把 keystore 封成一个盒子（`cmd/build-keystore`），
// 上传的是盒子。服务端再用 storage master key 在外面包一层落库——外层挡住"只拿到
// 一份数据库备份"的人，内层挡住拿到服务器的人。打包机本地持有封装口令，取下来
// 自己开。
//
// 于是你要的集中管理都成立了：按租户隔离、管理端可配、新打包机只需要一个口令，
// 而后端仍然碰不到密钥。
const buildKeystoreConfigKey = "build.keystore"

type buildKeystoreRecord struct {
	// Sealed 是外层加密后的 base64。内层是运维口令封的盒子，服务端两层都不解内层。
	Sealed         string `json:"sealed"`
	KeyAlias       string `json:"keyAlias"`
	KeystoreSHA256 string `json:"keystoreSha256"`
}

func buildKeystoreAAD(tenant string) string { return "build-keystore:" + tenant }

func (s *server) buildKeystoreRecord(ctx context.Context, tenant string) (*buildKeystoreRecord, int, string, time.Time, error) {
	var raw []byte
	var version int
	var updatedBy string
	var updatedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, buildKeystoreConfigKey).Scan(&raw, &version, &updatedBy, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, "", time.Time{}, nil
	}
	if err != nil {
		return nil, 0, "", time.Time{}, err
	}
	var record buildKeystoreRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, version, updatedBy, updatedAt, err
	}
	return &record, version, updatedBy, updatedAt, nil
}

// sealedBuildKeystoreFor 剥掉外层，返回运维那层盒子的原文 JSON。只有代理通道用它。
func (s *server) sealedBuildKeystoreFor(ctx context.Context, tenant string) (json.RawMessage, string, error) {
	record, _, _, _, err := s.buildKeystoreRecord(ctx, tenant)
	if err != nil || record == nil {
		return nil, "", err
	}
	if s.secrets == nil {
		return nil, "", errors.New("storage master key is unavailable")
	}
	encrypted, err := base64.StdEncoding.DecodeString(record.Sealed)
	if err != nil {
		return nil, "", err
	}
	plaintext, err := s.secrets.Decrypt(encrypted, buildKeystoreAAD(tenant))
	if err != nil {
		return nil, "", err
	}
	return json.RawMessage(plaintext), record.KeyAlias, nil
}

func (s *server) getBuildKeystore(c *gin.Context) {
	record, version, updatedBy, updatedAt, err := s.buildKeystoreRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration is invalid")
		return
	}
	// 全平台已经封了密钥的租户数。封装口令是**整台打包机共用的一个**，所以第二个
	// 租户开始，这里不能再让人自己想一个——控制台要按这个数字说不同的话。
	sealedTenants, err := s.sealedKeystoreTenantCount(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Unable to count configured keystores")
		return
	}
	if record == nil {
		c.JSON(http.StatusOK, gin.H{"configured": false, "keyAlias": nil, "keystoreSha256": nil, "version": 0, "updatedBy": nil, "updatedAt": nil,
			"sealedTenantCount": sealedTenants, "check": keystoreCheckView(nil, 0)})
		return
	}
	check, err := s.keystoreCheckFor(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Unable to read the verification result")
		return
	}
	// 盒子本身**不经过管理端**。管理端要的是"这个租户配的是哪把密钥"，那由
	// keystore 的 sha256 回答；盒子只发给打包机。
	c.JSON(http.StatusOK, gin.H{
		"configured":     true,
		"keyAlias":       nullableString(record.KeyAlias),
		"keystoreSha256": nullableString(record.KeystoreSHA256),
		"version":        version,
		"updatedBy":      nullableString(updatedBy),
		"updatedAt":      nullableTime(updatedAt),
		// 打包机验过没有：pending / ok / failed。服务端自己验不了——它没有口令
		"check":             keystoreCheckView(check, version),
		"sealedTenantCount": sealedTenants,
	})
}

// saveBuildKeystore 收下一个离线封好的盒子。
//
// 可以顺带把发布身份的签名指纹一起写了：指纹本来就是这把 keystore 里那张证书的
// 摘要，`build-keystore seal` 算得出来。让人再跑一次 keytool 把 64 位十六进制抄
// 进另一个表单，抄错的表现是构建成功、产物却在入库那一步被 SIGNER_MISMATCH 拒。
// 两条写在一个事务里，不留"密钥换了、pin 还是旧的"这个中间态。
func (s *server) saveBuildKeystore(c *gin.Context) {
	var body struct {
		Sealed          buildkeystore.Sealed `json:"sealed"`
		KeyAlias        string               `json:"keyAlias"`
		KeystoreSHA256  string               `json:"keystoreSha256"`
		ExpectedVersion int                  `json:"expectedVersion"`
		Reason          string               `json:"reason"`
		Confirm         bool                 `json:"confirm"`
		// 下面三项一起出现或者一起不出现。带上就同时更新发布身份的指纹。
		SignerSHA256                   string `json:"signerSha256"`
		PackageName                    string `json:"packageName"`
		ReleaseIdentityExpectedVersion *int   `json:"releaseIdentityExpectedVersion"`
	}
	if err := decode(c, &body); err != nil {
		problem(c, http.StatusBadRequest, "MALFORMED_BUILD_KEYSTORE",
			"Request body was rejected: "+err.Error()+"。如果提到 unknown field，多半是浏览器里还开着旧版控制台，强制刷新一次。")
		return
	}
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "sealed, keyAlias, keystoreSha256, expectedVersion, reason and confirm=true are required")
		return
	}
	alias := strings.TrimSpace(body.KeyAlias)
	digest := strings.ToLower(strings.TrimSpace(body.KeystoreSHA256))
	if alias == "" || len(alias) > 120 || !isHex(digest, 64, 64) {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "keyAlias is required and keystoreSha256 must be a sha256 digest")
		return
	}
	// 服务端打不开盒子，但可以看它的形状对不对。一个格式不对的盒子在这里拦住，
	// 比在第一次构建时才发现便宜得多。
	if body.Sealed.Version == 0 || body.Sealed.KDF == "" || body.Sealed.Ciphertext == "" || body.Sealed.Salt == "" || body.Sealed.Nonce == "" {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "sealed must carry v, kdf, salt, nonce and ciphertext")
		return
	}
	if body.Sealed.KDF != "scrypt" || body.Sealed.N < 1<<16 || body.Sealed.R < 8 || body.Sealed.P < 1 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "sealed must use scrypt with at least N=65536, r=8, p=1")
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Storage master key is unavailable")
		return
	}

	// 要不要顺带写发布身份。三项要么都给、要么都不给——只给一半的请求多半是
	// 调用方拼错了，静默忽略会让人以为指纹已经更新了
	pinIdentity := strings.TrimSpace(body.SignerSHA256) != "" || strings.TrimSpace(body.PackageName) != "" || body.ReleaseIdentityExpectedVersion != nil
	var identity androidReleaseIdentity
	releaseVersion := 0
	if pinIdentity {
		if body.ReleaseIdentityExpectedVersion == nil || *body.ReleaseIdentityExpectedVersion < 0 {
			problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", "releaseIdentityExpectedVersion is required when packageName or signerSha256 is present")
			return
		}
		identity = normalizeAndroidReleaseIdentity(androidReleaseIdentity{PackageName: body.PackageName, SignerSHA256: body.SignerSHA256})
		if err := validateAndroidReleaseIdentity(identity); err != nil {
			problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", err.Error())
			return
		}
		current, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c))
		if err != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
			return
		}
		if current != nil {
			releaseVersion = current.Version
		}
		if releaseVersion != *body.ReleaseIdentityExpectedVersion {
			problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
			return
		}
	}

	sealedJSON, err := json.Marshal(body.Sealed)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "sealed is not serializable")
		return
	}
	encrypted, err := s.secrets.Encrypt(string(sealedJSON), buildKeystoreAAD(tenantID(c)))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to protect the sealed keystore")
		return
	}
	value, _ := json.Marshal(buildKeystoreRecord{
		Sealed:         base64.StdEncoding.EncodeToString(encrypted),
		KeyAlias:       alias,
		KeystoreSHA256: digest,
	})
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the sealed keystore")
		return
	}
	defer tx.Rollback()
	var current int
	err = tx.QueryRowContext(c.Request.Context(), `SELECT version FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenantID(c), buildKeystoreConfigKey).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the sealed keystore")
		return
	}
	if current != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	newVersion := current + 1
	if affected, err := upsertAppConfig(c, tx, buildKeystoreConfigKey, value, current, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the sealed keystore")
		return
	} else if affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	// 审计记别名与 keystore 指纹，绝不记盒子内容
	event := newAudit(tenantID(c), actor(c), "build_keystore_update", "app-config", buildKeystoreConfigKey, strings.TrimSpace(body.Reason), requestID(c),
		map[string]any{"keyAlias": alias, "keystoreSha256": digest, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the sealed keystore")
		return
	}

	// 回参与 GET 同形。管理端两处用的是同一个 schema，少两个键就会在解析响应时
	// 失败——服务端明明存好了，界面却报错，而错误信息说的是"字段类型不对"
	sealedTenants, err := s.sealedKeystoreTenantCount(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to count configured keystores")
		return
	}
	response := gin.H{
		"configured": true, "keyAlias": alias, "keystoreSha256": digest,
		"version": newVersion, "updatedBy": nullableString(actor(c)), "updatedAt": nullableTime(now),
		// 刚写进去的盒子必然还没验过：验它的是打包机，下一轮轮询才发生
		"check": keystoreCheckView(nil, newVersion), "sealedTenantCount": sealedTenants,
	}
	if pinIdentity {
		identityValue, _ := json.Marshal(identity)
		newReleaseVersion := releaseVersion + 1
		if affected, err := upsertAppConfig(c, tx, releaseAndroidIdentityConfigKey, identityValue, releaseVersion, now); err != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
			return
		} else if affected != 1 {
			problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
			return
		}
		identityEvent := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseAndroidIdentityConfigKey, strings.TrimSpace(body.Reason), requestID(c),
			map[string]any{"packageName": identity.PackageName, "signerSha256": identity.SignerSHA256, "source": "build_keystore_update", "databaseVersion": newReleaseVersion})
		if insertAudit(c.Request.Context(), tx, identityEvent) != nil {
			problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
			return
		}
		response["releaseIdentityVersion"] = newReleaseVersion
	}
	if tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the sealed keystore")
		return
	}
	c.JSON(http.StatusOK, response)
}
