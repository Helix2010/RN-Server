package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
	"github.com/gin-gonic/gin"
)

// 在服务端生成 Android 签名密钥。
//
// 这条路径和「上传一个封好的盒子」并存，不是取代它。为什么要有它：离线那条路
// 假设 keystore 已经存在，但整套系统里没有任何一个地方说 keystore 怎么来——新租户
// 第一次配就卡在这。而 keystore 里的证书指纹是发布身份要 pin 的那个值，让人跑一遍
// keytool 再把 64 位十六进制抄进表单，抄错的表现是构建成功、产物在入库那一步被拒。
//
// 安全上的差别要说清楚，不要含糊：**服务端仍然打不开任何已存的密钥**——盒子是用
// 管理员的封装口令封的，服务端没有那个口令。差别只在生成的**那一次**：明文私钥在
// 服务端进程的内存里存在过。今天那是"从来没有"。所以：
//
//   - 这条路径是可选的，离线封装那条完整保留，对服务端信任更低时走那条；
//   - 明文 keystore 只在这一次响应里返回，任何地方都不落盘、不写日志、不进审计；
//   - store 口令由服务端随机生成。它不需要任何人记住（打包机从盒子里读），但备份
//     下来的那份文件要用它才打得开，所以随响应返回一次。
//
// 生成的同时把包名和证书指纹写进发布身份，两件事在一个事务里。分两步做就会有
// "密钥换了、pin 还是旧的"这个中间态，而那个态下所有上传都会被判 SIGNER_MISMATCH。
func (s *server) generateBuildKeystore(c *gin.Context) {
	var body struct {
		PackageName                    string `json:"packageName"`
		CommonName                     string `json:"commonName"`
		Organization                   string `json:"organization"`
		Country                        string `json:"country"`
		KeyAlias                       string `json:"keyAlias"`
		KeySize                        int    `json:"keySize"`
		ValidityYears                  int    `json:"validityYears"`
		ExpectedVersion                int    `json:"expectedVersion"`
		ReleaseIdentityExpectedVersion int    `json:"releaseIdentityExpectedVersion"`
		Reason                         string `json:"reason"`
		Confirm                        bool   `json:"confirm"`
	}
	if err := decode(c, &body); err != nil {
		problem(c, http.StatusBadRequest, "MALFORMED_BUILD_KEYSTORE",
			"Request body was rejected: "+err.Error()+"。如果提到 unknown field，多半是浏览器里还开着旧版控制台，强制刷新一次。")
		return
	}
	if !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 || body.ReleaseIdentityExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_BUILD_KEYSTORE", "reason, confirm=true and both expected versions are required")
		return
	}
	// 加密给打包机登记的那把公钥。没登记就没法生成——而不是退回去问人要一个口令
	agentKey, err := s.buildAgentKey(c.Request.Context())
	if err != nil {
		problem(c, http.StatusInternalServerError, "AGENT_KEY_QUERY_FAILED", "Unable to read the registered build agent key")
		return
	}
	if agentKey == nil {
		problem(c, http.StatusFailedDependency, "NO_BUILD_AGENT_KEY",
			"打包机还没有登记公钥，密钥没有地方可以加密给。确认打包机上的 build-agent 在跑，它启动时会自己登记一次。")
		return
	}
	identity := normalizeAndroidReleaseIdentity(androidReleaseIdentity{PackageName: body.PackageName})
	if len(identity.PackageName) > 255 || !androidPackagePattern.MatchString(identity.PackageName) {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", "packageName must be a valid Android application id")
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Storage master key is unavailable")
		return
	}

	// 两个乐观锁都先对一遍再生成：生成一把 4096 位的密钥要几秒，让它跑完再发现
	// 版本过期，人只会重来一次
	keystoreRecord, keystoreVersion, _, _, err := s.buildKeystoreRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_CONFIG_INVALID", "Stored build.keystore configuration is invalid")
		return
	}
	if keystoreRecord == nil {
		keystoreVersion = 0
	}
	if keystoreVersion != body.ExpectedVersion {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	releaseRecord, err := s.androidReleaseIdentityRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_CONFIG_INVALID", "Stored release.android configuration is invalid")
		return
	}
	releaseVersion := 0
	if releaseRecord != nil {
		releaseVersion = releaseRecord.Version
	}
	if releaseVersion != body.ReleaseIdentityExpectedVersion {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}

	generated, err := androidkeystore.Generate(androidkeystore.Params{
		CommonName:    body.CommonName,
		Organization:  body.Organization,
		Country:       body.Country,
		KeyAlias:      strings.TrimSpace(body.KeyAlias),
		KeySize:       body.KeySize,
		ValidityYears: body.ValidityYears,
	})
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_KEYSTORE_PARAMETERS", err.Error())
		return
	}
	identity.SignerSHA256 = generated.SignerSHA256
	// 理论上生成不出 RN 那把公开 debug 密钥的指纹，但这道闸是发布身份的规则，
	// 不该因为"这次是我们自己生成的"就跳过
	if err := validateAndroidReleaseIdentity(identity); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_RELEASE_IDENTITY", err.Error())
		return
	}

	// 加密给打包机的公钥。服务端只有公钥，存下去之后它自己也打不开——这正是签名
	// 密钥可以放进数据库的那条论证，换成公钥之后一个字都不用改
	sealed, err := buildkeystore.SealTo(buildkeystore.Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString(generated.PKCS12),
		StorePassword:  generated.StorePassword,
		KeyAlias:       strings.TrimSpace(body.KeyAlias),
		// PKCS#12 里 key 和 store 用同一个口令。Java 允许它们不同，但那只会多一个
		// 能配错的地方，而没有任何人需要单独知道其中一个
		KeyPassword: generated.StorePassword,
	}, agentKey.Current)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to seal the generated keystore")
		return
	}
	sealedJSON, err := json.Marshal(sealed)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to serialize the sealed keystore")
		return
	}
	encrypted, err := s.secrets.Encrypt(string(sealedJSON), buildKeystoreAAD(tenantID(c)))
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to protect the sealed keystore")
		return
	}
	keystoreValue, _ := json.Marshal(buildKeystoreRecord{
		Sealed:         base64.StdEncoding.EncodeToString(encrypted),
		KeyAlias:       strings.TrimSpace(body.KeyAlias),
		KeystoreSHA256: generated.KeystoreSHA256,
	})
	identityValue, _ := json.Marshal(identity)

	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the generated keystore")
		return
	}
	defer tx.Rollback()

	newKeystoreVersion := keystoreVersion + 1
	if affected, err := upsertAppConfig(c, tx, buildKeystoreConfigKey, keystoreValue, keystoreVersion, now); err != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the generated keystore")
		return
	} else if affected != 1 {
		problem(c, http.StatusConflict, "STALE_BUILD_KEYSTORE", "Keystore changed; refresh and retry")
		return
	}
	newReleaseVersion := releaseVersion + 1
	if affected, err := upsertAppConfig(c, tx, releaseAndroidIdentityConfigKey, identityValue, releaseVersion, now); err != nil {
		problem(c, http.StatusInternalServerError, "RELEASE_IDENTITY_SAVE_FAILED", "Unable to save release identity")
		return
	} else if affected != 1 {
		problem(c, http.StatusConflict, "STALE_RELEASE_IDENTITY", "Release identity changed; refresh and retry")
		return
	}

	reason := strings.TrimSpace(body.Reason)
	// 审计里绝不出现 keystore 内容、store 口令或封装口令；记的是"配的是哪一把"
	keystoreAudit := newAudit(tenantID(c), actor(c), "build_keystore_generate", "app-config", buildKeystoreConfigKey, reason, requestID(c),
		map[string]any{
			"keyAlias": strings.TrimSpace(body.KeyAlias), "keystoreSha256": generated.KeystoreSHA256,
			"signerSha256": generated.SignerSHA256, "keySize": body.KeySize,
			"certificateNotAfter": generated.NotAfter.Format(time.RFC3339),
			"databaseVersion":     newKeystoreVersion,
		})
	previous := map[string]any{}
	if releaseRecord != nil {
		previous = map[string]any{"packageName": releaseRecord.Value.PackageName, "signerSha256": releaseRecord.Value.SignerSHA256}
	}
	identityAudit := newAudit(tenantID(c), actor(c), "release_identity_update", "app-config", releaseAndroidIdentityConfigKey, reason, requestID(c),
		map[string]any{
			"packageName": identity.PackageName, "signerSha256": identity.SignerSHA256,
			"source": "build_keystore_generate", "previous": previous, "databaseVersion": newReleaseVersion,
		})
	if insertAudit(c.Request.Context(), tx, keystoreAudit) != nil ||
		insertAudit(c.Request.Context(), tx, identityAudit) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "BUILD_KEYSTORE_SAVE_FAILED", "Unable to save the generated keystore")
		return
	}

	// keystoreBase64 与 storePassword 只在这一次出现。此后服务端手上只有封好的
	// 盒子，而它打不开——所以管理员现在不备份，以后就再也拿不到这个文件了。
	c.JSON(http.StatusOK, gin.H{
		"keystoreBase64":         base64.StdEncoding.EncodeToString(generated.PKCS12),
		"fileName":               strings.TrimSpace(body.KeyAlias) + ".p12",
		"storePassword":          generated.StorePassword,
		"keyAlias":               strings.TrimSpace(body.KeyAlias),
		"keystoreSha256":         generated.KeystoreSHA256,
		"signerSha256":           generated.SignerSHA256,
		"packageName":            identity.PackageName,
		"certificateNotAfter":    generated.NotAfter.Format(time.RFC3339),
		"version":                newKeystoreVersion,
		"releaseIdentityVersion": newReleaseVersion,
	})
}

// upsertAppConfig 写一行 app_configs 并带上乐观锁。expectedVersion 为 0 表示这一行
// 还不存在——INSERT 的 WHERE NOT EXISTS 挡住并发插入，返回 0 行让调用方报冲突。
func upsertAppConfig(c *gin.Context, tx *sql.Tx, key string, value []byte, expectedVersion int, now time.Time) (int64, error) {
	var result sql.Result
	var err error
	if expectedVersion == 0 {
		result, err = tx.ExecContext(c.Request.Context(),
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`,
			tenantID(c), key, value, actor(c), now, tenantID(c), key)
	} else {
		result, err = tx.ExecContext(c.Request.Context(),
			`UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`,
			value, actor(c), now, tenantID(c), key, expectedVersion)
	}
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, errors.New("cannot tell whether the write applied")
	}
	return affected, nil
}
