package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// OTA 代码签名（安全评审 N17 / N19，§13 阶段 0b-2）。
//
// OTA 此前只有**完整性**没有**真实性**：manifest 的 sha256 存在我们自己的数据库里，
// 能改数据库或能顶替这条响应的人，可以让客户端拿到一份它认为"完整"的恶意 bundle。
// 而 OTA 能改的是整个 JS 层——包括钱包签名前的确认界面。
//
// 这里补上真实性：服务端用每租户一把 RSA 私钥对**改写完成后的最终响应体**签名，
// 客户端用编译进包里的证书验签。expo-updates 的 `CodeSigningConfiguration` 在
// `allowUnsignedManifests=false`（默认）时，缺签名、签名不对、keyid 不符都会拒绝
// 并回落到内置 bundle。
//
// ## 协议事实（读 expo-updates 57.0.21 的源码确认，不是从文档抄的）
//
//   - 请求带 `expo-expect-signature`（RFC 8941 字典）表示这个客户端要验签。
//   - 响应的 `expo-signature` 也是 RFC 8941 字典：`sig="<base64>", keyid="…", alg="rsa-v1_5-sha256"`。
//   - 签的是 **body 的原始字节**，`Signature.getInstance("SHA256withRSA")`，即
//     PKCS#1 v1.5 + SHA-256（`CodeSigningConfiguration.kt:93-96`）。
//   - **plain 响应**：`expo-signature` 是 HTTP 响应头（`FileDownloader.kt:478`）。
//   - **multipart 响应**：它是 **part 的头**，manifest 与 directive 各自一份，
//     各签各的 part body（`FileDownloader.kt:556,570`）。
//   - 算法只认 `rsa-v1_5-sha256`（`CodeSigningAlgorithm.kt`）。
//
// ## 为什么签"最终字节"而不是入库时签一次
//
// 下发前这条响应还会被改写（`applyManifestStrategy` 用数据库里的生效策略覆盖
// manifest 里的值）。对入库时的原文签名，签的就不是客户端实际收到的东西——
// 中间那段改写会成为一个不被签名覆盖的缺口。

// ota.signing：每租户一把签名密钥，存 app_configs。私钥用 storage master key
// 加密后落库（与灰度令牌、品牌资源同一套认证加密），明文不出这个文件。
const otaSigningConfigKey = "ota.signing"

// expo-updates 只实现了这一个算法。
const otaSigningAlgorithm = "rsa-v1_5-sha256"

// keyid 的默认值，与 expo-updates 的 CODE_SIGNING_METADATA_DEFAULT_KEY_ID 一致。
const otaSigningDefaultKeyID = "main"

// RSA 密钥下限。1024 位今天已经不该用来保护"能改整个 JS 层"的能力。
const otaSigningMinBits = 2048

type otaSigningKey struct {
	KeyID string `json:"keyId"`
	// PrivateKey 是加密后的 PKCS#8 DER（base64）。任何时候都不出现在 API 响应里。
	PrivateKey string `json:"privateKey"`
	// Certificate 是客户端要编译进包里的那份证书（PEM），公开信息。
	Certificate string `json:"certificate"`
}

type otaSigningRecord struct {
	Value     otaSigningKey
	Version   int
	UpdatedBy string
	UpdatedAt time.Time
}

// otaSignatureHeader 拼 RFC 8941 字典。三个值都是 sf-string，必须带引号；
// base64 里的 `+` `/` `=` 在 sf-string 里合法，不需要转义，但 `"` 和 `\` 要。
func otaSignatureHeader(signature []byte, keyID string) string {
	escape := func(v string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v)
	}
	return fmt.Sprintf(`sig="%s", keyid="%s", alg="%s"`,
		escape(base64.StdEncoding.EncodeToString(signature)),
		escape(keyID),
		otaSigningAlgorithm,
	)
}

// clientExpectsOTASignature：客户端带了 expo-expect-signature 就是要验签。
// 不解析它的内容——里面只有 keyid/alg 的偏好，而我们只有一把密钥、一个算法，
// 解析出来也没有第二种可选项。带了头却给不出签名时，客户端自己会拒绝并回落到
// 内置 bundle，这正是我们要的 fail closed。
func clientExpectsOTASignature(header string) bool {
	return strings.TrimSpace(header) != ""
}

func parseOTASigningKey(raw []byte) (otaSigningKey, error) {
	var v otaSigningKey
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("ota.signing is not valid JSON: %w", err)
	}
	if strings.TrimSpace(v.KeyID) == "" || strings.TrimSpace(v.PrivateKey) == "" {
		return v, errors.New("ota.signing is missing keyId or privateKey")
	}
	return v, nil
}

func (s *server) otaSigningRecord(ctx context.Context, tenant string) (*otaSigningRecord, error) {
	var raw []byte
	var record otaSigningRecord
	err := s.db.QueryRowContext(ctx, `SELECT config_value,version,updated_by,updated_at FROM app_configs WHERE tenant_id=? AND config_key=? LIMIT 1`, tenant, otaSigningConfigKey).Scan(&raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Value, err = parseOTASigningKey(raw); err != nil {
		return nil, err
	}
	return &record, nil
}

// decodeOTASigningPrivateKey 解出可用于签名的私钥。
func (s *server) decodeOTASigningPrivateKey(tenant string, stored string) (*rsa.PrivateKey, error) {
	if s.secrets == nil {
		return nil, errors.New("storage master key is unavailable")
	}
	encrypted, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, fmt.Errorf("stored ota signing key is not base64: %w", err)
	}
	plaintext, err := s.secrets.Decrypt(encrypted, otaSigningAAD(tenant))
	if err != nil {
		return nil, fmt.Errorf("stored ota signing key cannot be decrypted: %w", err)
	}
	return parseRSAPrivateKeyPEM(plaintext)
}

func otaSigningAAD(tenant string) string { return "ota-signing:" + tenant }

// parseRSAPrivateKeyPEM 接受 PKCS#1（"RSA PRIVATE KEY"）与 PKCS#8（"PRIVATE KEY"）
// 两种 PEM：expo 的 codesigning 生成器给的是 PKCS#8，而 openssl 老参数给 PKCS#1，
// 两种都会被人贴进来。
func parseRSAPrivateKeyPEM(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(text)))
	if block == nil {
		return nil, errors.New("private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return validatedRSAKey(key)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key is neither PKCS#1 nor PKCS#8 RSA")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA; expo-updates only verifies rsa-v1_5-sha256")
	}
	return validatedRSAKey(key)
}

func validatedRSAKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key.N.BitLen() < otaSigningMinBits {
		return nil, fmt.Errorf("RSA key is %d bits; minimum is %d", key.N.BitLen(), otaSigningMinBits)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("RSA key is not internally consistent: %w", err)
	}
	return key, nil
}

// signOTABody 对最终响应体签名，返回可直接写进 expo-signature 的字符串。
func signOTABody(key *rsa.PrivateKey, keyID string, body []byte) (string, error) {
	digest := sha256.Sum256(body)
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return otaSignatureHeader(signature, keyID), nil
}

// otaSigner 是一次请求里用到的签名能力；nil 表示这个租户没配密钥。
type otaSigner struct {
	key   *rsa.PrivateKey
	keyID string
}

func (s *otaSigner) sign(body []byte) (string, error) {
	if s == nil {
		return "", nil
	}
	return signOTABody(s.key, s.keyID, body)
}

// otaSignerFor 取这个租户的签名器。没配密钥返回 (nil, nil)——调用方照常下发未签名
// 响应，要验签的客户端会自己拒绝并回落到内置 bundle。密钥配了但坏了返回错误：
// 那是配置事故，不能当成"没配"悄悄降级成不签名。
func (s *server) otaSignerFor(ctx context.Context, tenant string) (*otaSigner, error) {
	record, err := s.otaSigningRecord(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	}
	key, err := s.decodeOTASigningPrivateKey(tenant, record.Value.PrivateKey)
	if err != nil {
		return nil, err
	}
	keyID := strings.TrimSpace(record.Value.KeyID)
	if keyID == "" {
		keyID = otaSigningDefaultKeyID
	}
	return &otaSigner{key: key, keyID: keyID}, nil
}

type otaSigningWrite struct {
	KeyID           string `json:"keyId"`
	PrivateKeyPEM   string `json:"privateKeyPem"`
	CertificatePEM  string `json:"certificatePem"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// certificateFacts 把证书里对运维有用的公开事实读出来。有效期尤其重要：证书过期
// 之后 OTA 救不了自己（要验签的客户端会拒绝每一次更新），只能发原生新版，所以
// "还有多久过期"必须是界面上看得见的东西，而不是靠谁记得当初填了几年。
func certificateFacts(certificatePEM string) (subject string, notBefore, notAfter time.Time) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certificatePEM)))
	if block == nil {
		return "", time.Time{}, time.Time{}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, time.Time{}
	}
	return certificate.Subject.CommonName, certificate.NotBefore.UTC(), certificate.NotAfter.UTC()
}

// certificateFingerprint 给运维一个能和 App 里那份证书对照的值。
func certificateFingerprint(certificatePEM string) (string, bool) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certificatePEM)))
	if block == nil {
		return "", false
	}
	sum := sha256.Sum256(block.Bytes)
	return fmt.Sprintf("%x", sum), true
}

// otaSigningView 只暴露公开信息。私钥**永远**不出现在任何响应里——它写进来之后
// 就只有服务端解得开，管理端要换就整把换，不提供"读出来看看"。
func otaSigningView(record *otaSigningRecord) map[string]any {
	if record == nil {
		return map[string]any{"configured": false, "keyId": nil, "certificatePem": nil, "certificateSha256": nil, "certificateSubject": nil, "certificateNotBefore": nil, "certificateNotAfter": nil, "version": 0, "updatedBy": nil, "updatedAt": nil}
	}
	fingerprint, _ := certificateFingerprint(record.Value.Certificate)
	subject, notBefore, notAfter := certificateFacts(record.Value.Certificate)
	return map[string]any{
		"configured":           true,
		"keyId":                record.Value.KeyID,
		"certificatePem":       nullableString(record.Value.Certificate),
		"certificateSha256":    nullableString(fingerprint),
		"certificateSubject":   nullableString(subject),
		"certificateNotBefore": nullableTime(notBefore),
		"certificateNotAfter":  nullableTime(notAfter),
		"version":              record.Version,
		"updatedBy":            record.UpdatedBy,
		"updatedAt":            iso(record.UpdatedAt),
	}
}

func (s *server) getOTASigningKey(c *gin.Context) {
	record, err := s.otaSigningRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_CONFIG_INVALID", "Stored ota.signing configuration is invalid")
		return
	}
	c.JSON(http.StatusOK, otaSigningView(record))
}

// certificateMatchesKey 确认贴进来的证书和私钥是一对。不对上的话，服务端签得出来
// 而客户端一定验不过，表现是所有设备静默停在内置 bundle——最难查的那种故障。
func certificateMatchesKey(certificatePEM string, key *rsa.PrivateKey) error {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certificatePEM)))
	if block == nil {
		return errors.New("certificatePem is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("certificatePem is not a certificate: %w", err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !public.Equal(&key.PublicKey) {
		return errors.New("certificatePem does not match privateKeyPem: the client would reject every update")
	}
	return nil
}

func (s *server) updateOTASigningKey(c *gin.Context) {
	var body otaSigningWrite
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_OTA_SIGNING_KEY", "privateKeyPem, certificatePem, expectedVersion, reason and confirm=true are required")
		return
	}
	s.storeOTASigningKey(c, body.KeyID, body.PrivateKeyPEM, body.CertificatePEM, body.ExpectedVersion, body.Reason, "ota_signing_key_update")
}

// storeOTASigningKey 是「贴进来」与「服务端生成」共用的落库路径。两条入口写的是
// 同一条记录、同一套校验、同一条审计，差别只在私钥从哪来——分成两份实现的话，
// 迟早有一边漏掉配对校验或乐观锁。
func (s *server) storeOTASigningKey(c *gin.Context, rawKeyID, privateKeyPEM, certificatePEM string, expectedVersion int, reason, action string) {
	// 先校验请求本身，再看服务端有没有能力存。顺序反过来的话，一个明显不合法的
	// 私钥会收到 500「服务端问题」，调用方照着这个提示永远查不到自己贴错了东西。
	key, err := parseRSAPrivateKeyPEM(privateKeyPEM)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_OTA_SIGNING_KEY", err.Error())
		return
	}
	if err := certificateMatchesKey(certificatePEM, key); err != nil {
		problem(c, http.StatusBadRequest, "INVALID_OTA_SIGNING_KEY", err.Error())
		return
	}
	if s.secrets == nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_SAVE_FAILED", "Storage master key is unavailable")
		return
	}
	keyID := strings.TrimSpace(rawKeyID)
	if keyID == "" {
		keyID = otaSigningDefaultKeyID
	}
	encrypted, err := s.secrets.Encrypt(strings.TrimSpace(privateKeyPEM), otaSigningAAD(tenantID(c)))
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_SAVE_FAILED", "Unable to protect the signing key")
		return
	}
	value := otaSigningKey{
		KeyID:       keyID,
		PrivateKey:  base64.StdEncoding.EncodeToString(encrypted),
		Certificate: strings.TrimSpace(certificatePEM),
	}
	current, err := s.otaSigningRecord(c.Request.Context(), tenantID(c))
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_CONFIG_INVALID", "Stored ota.signing configuration is invalid")
		return
	}
	currentVersion := 0
	if current != nil {
		currentVersion = current.Version
	}
	if currentVersion != expectedVersion {
		problem(c, http.StatusConflict, "STALE_OTA_SIGNING_KEY", "Signing key changed; refresh and retry")
		return
	}
	raw, _ := json.Marshal(value)
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(c.Request.Context(), nil)
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	defer tx.Rollback()
	var result sql.Result
	newVersion := 1
	if current != nil {
		newVersion = currentVersion + 1
		result, err = tx.ExecContext(c.Request.Context(), `UPDATE app_configs SET config_value=?,version=version+1,updated_by=?,updated_at=? WHERE tenant_id=? AND config_key=? AND version=?`, raw, actor(c), now, tenantID(c), otaSigningConfigKey, currentVersion)
	} else {
		result, err = tx.ExecContext(c.Request.Context(), `INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) SELECT ?,?,?,1,?,? WHERE NOT EXISTS (SELECT 1 FROM app_configs WHERE tenant_id=? AND config_key=?)`, tenantID(c), otaSigningConfigKey, raw, actor(c), now, tenantID(c), otaSigningConfigKey)
	}
	if err != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		problem(c, http.StatusConflict, "STALE_OTA_SIGNING_KEY", "Signing key changed; refresh and retry")
		return
	}
	fingerprint, _ := certificateFingerprint(value.Certificate)
	// 审计里记指纹与 keyid，绝不记私钥
	event := newAudit(tenantID(c), actor(c), action, "app-config", otaSigningConfigKey, reason, requestID(c), map[string]any{"keyId": keyID, "certificateSha256": fingerprint, "databaseVersion": newVersion})
	if insertAudit(c.Request.Context(), tx, event) != nil || tx.Commit() != nil {
		problem(c, http.StatusInternalServerError, "OTA_SIGNING_SAVE_FAILED", "Unable to save the signing key")
		return
	}
	c.JSON(http.StatusOK, otaSigningView(&otaSigningRecord{Value: value, Version: newVersion, UpdatedBy: actor(c), UpdatedAt: now}))
}

// ---- 服务端生成密钥对 ----
//
// 为什么允许服务端生成：签每一份 manifest 时，服务端本来就必须把明文私钥解出来。
// 让它在这里诞生，暴露面没有变大，却省掉了运维机上的明文文件、跨机器搬运、以及
// 靠人记得 shred 的纪律——那条链路上的每一环都真实地出过错。
//
// 代价是没有离线备份：丢了这把密钥就只能发原生新版换证书。但主动轮换的代价本来
// 也正好是"发一个原生新版"，所以这里没有新增损失。Android keystore 不适用这条
// 推论：服务端运行时根本不用它，而它丢了没有任何补救。

// otaSigningKeyMaxBits 挡住"生成一把 32768 位密钥"这种把 CPU 焊死几分钟的请求。
const otaSigningKeyMaxBits = 8192

// otaSigningMaxYears：证书过期后 OTA 救不了自己，只能发原生新版，所以有效期要长；
// 但长到没有尽头就等于永远不会被换掉。
const otaSigningMaxYears = 30

type otaSigningGenerate struct {
	KeyID           string `json:"keyId"`
	CommonName      string `json:"commonName"`
	KeySize         int    `json:"keySize"`
	Years           int    `json:"years"`
	ExpectedVersion int    `json:"expectedVersion"`
	Reason          string `json:"reason"`
	Confirm         bool   `json:"confirm"`
}

// generateOTASigningMaterial 生成 expo-updates 真的会接受的那种叶证书。
//
// CertificateChain.kt 的判据是 `keyUsage[0] && extendedKeyUsage.contains(CODE_SIGNING_OID)`
// ——digitalSignature 与 code signing 两个扩展缺一不可，且它 `checkValidity()`，
// 所以 NotBefore 必须已经过去。少任何一项都在**运行时**被拒，症状是所有设备静默
// 停在内置 bundle，最难查的那种；因此这里写死，不做成可配置项。
func generateOTASigningMaterial(commonName string, bits int, now time.Time, years int) (string, string, error) {
	if bits < otaSigningMinBits || bits > otaSigningKeyMaxBits {
		return "", "", fmt.Errorf("keySize must be between %d and %d", otaSigningMinBits, otaSigningKeyMaxBits)
	}
	if years < 1 || years > otaSigningMaxYears {
		return "", "", fmt.Errorf("years must be between 1 and %d", otaSigningMaxYears)
	}
	if strings.TrimSpace(commonName) == "" {
		return "", "", errors.New("commonName is required")
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("unable to generate an RSA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("unable to draw a serial number: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	subjectKeyID := sha256.Sum256(publicKeyDER)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: strings.TrimSpace(commonName)},
		// 往前挪 5 分钟：客户端 checkValidity() 用的是设备时钟，刚签发就被判"还没生效"
		// 是一种只在部分设备上出现、而且完全静默的故障。
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.AddDate(years, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          subjectKeyID[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("unable to create the certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(keyPEM), string(certPEM), nil
}

// generateOTASigningKey 生成并直接落库。私钥**不出现在响应里**，和贴进来的那条路
// 一样：装进去之后只能整把换，读不回来。响应里给证书，那是要编进原生包的公开材料。
func (s *server) generateOTASigningKey(c *gin.Context) {
	var body otaSigningGenerate
	if decode(c, &body) != nil || !body.Confirm || len(strings.TrimSpace(body.Reason)) < 3 || body.ExpectedVersion < 0 {
		problem(c, http.StatusBadRequest, "INVALID_OTA_SIGNING_KEY", "expectedVersion, reason and confirm=true are required")
		return
	}
	if body.KeySize == 0 {
		body.KeySize = 4096
	}
	if body.Years == 0 {
		body.Years = 10
	}
	commonName := strings.TrimSpace(body.CommonName)
	if commonName == "" {
		commonName = tenantID(c) + " OTA"
	}
	privateKeyPEM, certificatePEM, err := generateOTASigningMaterial(commonName, body.KeySize, time.Now(), body.Years)
	if err != nil {
		problem(c, http.StatusBadRequest, "INVALID_OTA_SIGNING_KEY", err.Error())
		return
	}
	s.storeOTASigningKey(c, body.KeyID, privateKeyPEM, certificatePEM, body.ExpectedVersion, body.Reason, "ota_signing_key_generate")
}
