package pushcreds

// APNs 侧和 FCM 是同一套结构：按租户存、平台级回落、保存即验证、明文只留
// 非机密的标识项。形状故意照抄（设计 docs/design/push-apns-and-shared-app-identity-2026-09-18.md
// §2），因为 FCM 那套已经在生产上跑过一轮，另起一套只会让两边慢慢漂开。
//
// 与 FCM 的三点不同，都是 APNs 本身决定的：
//
//  1. topic（bundle id）**不存在这条记录里**，取该租户 release.ios 的 bundleId。
//     存两份必然漂移，而漂移的表现是推送静默失效（APNs 回 DeviceTokenNotForTopic，
//     和 FCM 的 SENDER_ID_MISMATCH 是同一类"哪儿都成功，只有推送发不出去"）。
//  2. 没有"换一次访问令牌"这种廉价探活，验证要真发一条（见 VerifyAPNs）。
//  3. 多一个 environment：production 与 sandbox 的 device token 互不通用。

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

// APNsEnvironmentProduction 是默认值。TestFlight 装的包走 production——它是
// App Store 分发的构建，不是 sandbox；只有 Xcode 直连真机调试出来的包才注册
// sandbox token。两边的 token 互不通用，拿 sandbox token 去 production 发会回
// BadDeviceToken，和"凭据坏了"表现一样，所以界面上必须把这一项说清楚。
const (
	APNsEnvironmentProduction = "production"
	APNsEnvironmentSandbox    = "sandbox"
)

// APNs 是 push.apns 的 config_value。
//
// teamId / keyId 明文：和 FCM 的 projectId / clientEmail 同理，它们在 Apple
// 开发者后台本来就公开显示，不是机密，而管理端要靠它们回答"现在用的是哪把钥匙"。
// .p8 私钥加密存——服务端每发一条推送都要用它签 JWT，必须能解开，这一点和
// FCM 服务账号同类（ADR-0017 已论证过为什么这不违反"密钥不进库"）。
type APNs struct {
	TeamID           string     `json:"teamId"`
	KeyID            string     `json:"keyId"`
	Environment      string     `json:"environment"`
	AuthKeyEncrypted string     `json:"authKeyEncrypted"`
	VerifiedAt       *time.Time `json:"verifiedAt,omitempty"`
}

// APNsRecord 与 Record 对称。SourceTenant 同样是**生效那一行**的租户：
// 派发器的客户端缓存和解密用的 AAD 都以它为准，不是请求方的租户。
type APNsRecord struct {
	Value        APNs
	SourceTenant string
	Version      int
	UpdatedBy    string
	UpdatedAt    time.Time
}

// Inherited 说明这一行是继承来的。界面上必须显眼：继承来的 Team ID 管不着
// 自己的 bundle id，一样发不出去（APNs 回 TopicDisallowed）。
func (r APNsRecord) Inherited(tenant string) bool {
	return r.SourceTenant != "" && r.SourceTenant != tenant
}

// LoadAPNs 读一个租户生效的 APNs 凭据：自己的优先，没有就用平台那一行。
// 语句与 LoadFCM 逐字对应。
func LoadAPNs(ctx context.Context, db *sql.DB, tenant string) (APNsRecord, error) {
	var record APNsRecord
	var raw []byte
	err := db.QueryRowContext(ctx,
		`SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs
		 WHERE config_key=? AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`,
		APNsConfigKey, tenant, tenant).
		Scan(&record.SourceTenant, &raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return record, fmt.Errorf("stored %s for tenant %s is not valid JSON: %w", APNsConfigKey, record.SourceTenant, err)
	}
	return record, nil
}

// AuthKey 解出这条记录里的 .p8。AAD 用的是**生效行**的租户。
func (r APNsRecord) AuthKey(box *secretbox.Box) ([]byte, error) {
	if r.Value.AuthKeyEncrypted == "" {
		return nil, errors.New("no APNs auth key is stored")
	}
	if box == nil {
		return nil, errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(r.Value.AuthKeyEncrypted)
	if err != nil {
		return nil, fmt.Errorf("stored APNs auth key is not valid base64: %w", err)
	}
	plaintext, err := box.Decrypt(ciphertext, AssociatedData(r.SourceTenant, APNsConfigKey, "authKey"))
	if err != nil {
		return nil, fmt.Errorf("stored APNs auth key cannot be decrypted: %w", err)
	}
	return []byte(plaintext), nil
}

// EncryptAPNsAuthKey 封存一份 .p8，返回 base64 密文。
func EncryptAPNsAuthKey(box *secretbox.Box, tenant string, raw []byte) (string, error) {
	if box == nil {
		return "", errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := box.Encrypt(string(raw), AssociatedData(tenant, APNsConfigKey, "authKey"))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// ErrLooksLikeCertificate：传上来的是 .p12 / .cer 证书，不是 .p8 令牌密钥。
//
// Apple 后台两种推送凭据并存（旧的证书、新的 token key），名字都叫"密钥"，
// 拿混很常见。这里挡住，否则会变成运行时一句看不懂的 JWT 签名失败。
var ErrLooksLikeCertificate = errors.New("这看起来是推送证书（.p12 / .cer），不是 .p8 令牌密钥。" +
	"到 Apple Developer → Keys → 新建一个勾了 Apple Push Notifications service (APNs) 的密钥下载")

// ParseAPNsAuthKey 校验形状：必须是 PKCS#8 里的一把 ECDSA P-256 私钥。
// 挡在这里的每一条，放过去都会变成运行时一句看不懂的签名错误。
func ParseAPNsAuthKey(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return errors.New("文件是空的")
	}
	if strings.Contains(trimmed, "BEGIN CERTIFICATE") {
		return ErrLooksLikeCertificate
	}
	block, _ := pem.Decode([]byte(trimmed))
	if block == nil {
		// .p12 是二进制的，PEM 解不出来
		if !strings.Contains(trimmed, "BEGIN") {
			return ErrLooksLikeCertificate
		}
		return errors.New("这不是一份 PEM 私钥")
	}
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		return fmt.Errorf("PEM 块是 %q，不是私钥", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("私钥解析失败：%w", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		return fmt.Errorf("APNs 令牌密钥必须是 ECDSA，这份是 %T", parsed)
	}
	return nil
}

// ErrAPNsCredentialRejected：Apple 拒绝了这把钥匙。
var ErrAPNsCredentialRejected = errors.New("Apple 拒绝了这把密钥")

// ErrAPNsTopicDisallowed：钥匙本身没问题，但它的 team 管不着这个 bundle id。
var ErrAPNsTopicDisallowed = errors.New("这把密钥所属的 Team 管不着这个 bundle id")

// apnsProbeToken 是一个明显无效的 device token（32 字节全 0）。
//
// 用它探活的依据：APNs **先验 provider token（我们的 JWT）、再验 device token**。
// 所以回 BadDeviceToken 恰恰证明鉴权那一关过了——这是 APNs 没有独立"验证凭据"
// 接口时唯一能走"和真正发送完全相同那条路"的办法（与 FCM 的 Verify 同一条原则：
// 不走真路的验证证明不了任何事）。
const apnsProbeToken = "0000000000000000000000000000000000000000000000000000000000000000"

// VerifyAPNs 真发一条静默推送去探活。bundleID 取该租户 release.ios 的 bundleId。
//
// 判读表（设计 §2.3）：
//
//	403 InvalidProviderToken / ExpiredProviderToken → 凭据坏
//	400 TopicDisallowed                            → 凭据与 bundle id 不匹配
//	400 BadDeviceToken / DeviceTokenNotForTopic     → 凭据好（只是收件人是假的）
//	其余                                            → 原文回显，不猜
func VerifyAPNs(ctx context.Context, value APNs, authKey []byte, bundleID string) error {
	if strings.TrimSpace(bundleID) == "" {
		return errors.New("这个租户还没有 iOS bundle id，先到「iOS 打包与分发」配好应用身份")
	}
	client, err := NewAPNsClient(value, authKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	response, err := client.PushWithContext(ctx, &apns2.Notification{
		DeviceToken: apnsProbeToken,
		Topic:       strings.TrimSpace(bundleID),
		Payload:     []byte(`{"aps":{"content-available":1}}`),
	})
	if err != nil {
		return fmt.Errorf("连不上 APNs：%w", err)
	}
	switch response.Reason {
	case apns2.ReasonBadDeviceToken, apns2.ReasonDeviceTokenNotForTopic:
		// 鉴权过了，收件人是我们编的——这就是"通过"
		return nil
	case apns2.ReasonInvalidProviderToken, apns2.ReasonExpiredProviderToken, apns2.ReasonMissingProviderToken:
		return fmt.Errorf("%w：%s（核对 Team ID、Key ID 与 .p8 是不是同一把）", ErrAPNsCredentialRejected, response.Reason)
	case apns2.ReasonTopicDisallowed:
		return fmt.Errorf("%w：%s", ErrAPNsTopicDisallowed, bundleID)
	}
	if response.Sent() {
		// 不该发生：全 0 的 token 不可能是真的。真发生了说明我们对 APNs 的
		// 判读有偏差，放过去比拦住危险，所以这里也算通过但留一条日志。
		slog.Warn("APNs accepted the probe token; verification logic may need review", "tenant_key", APNsConfigKey)
		return nil
	}
	return fmt.Errorf("%w：APNs %d %s", ErrAPNsCredentialRejected, response.StatusCode, response.Reason)
}

// NewAPNsClient 造一个 APNs 客户端。派发器按**生效行的租户**持有它。
func NewAPNsClient(value APNs, authKey []byte) (*apns2.Client, error) {
	key, err := token.AuthKeyFromBytes(authKey)
	if err != nil {
		return nil, fmt.Errorf("load APNs key: %w", err)
	}
	client := apns2.NewTokenClient(&token.Token{
		AuthKey: key,
		KeyID:   strings.TrimSpace(value.KeyID),
		TeamID:  strings.TrimSpace(value.TeamID),
	})
	if value.Environment == APNsEnvironmentSandbox {
		return client.Development(), nil
	}
	return client.Production(), nil
}

// NormalizeAPNsEnvironment 把空值收敛到 production（设计 §2.4）。
func NormalizeAPNsEnvironment(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", APNsEnvironmentProduction:
		return APNsEnvironmentProduction, nil
	case APNsEnvironmentSandbox:
		return APNsEnvironmentSandbox, nil
	}
	return "", fmt.Errorf("environment 必须是 %s 或 %s", APNsEnvironmentProduction, APNsEnvironmentSandbox)
}

// 密文不该出现在日志里，它的长度和存在与否才是有用的（与 FCM 同）。
func (a APNs) safeSummary() string {
	return fmt.Sprintf("push.apns{team=%s keyId=%s env=%s sealed=%s}",
		a.TeamID, KeyHint(a.KeyID), a.Environment, presence(a.AuthKeyEncrypted))
}

func (a APNs) String() string       { return a.safeSummary() }
func (a APNs) GoString() string     { return a.safeSummary() }
func (a APNs) LogValue() slog.Value { return slog.StringValue(a.safeSummary()) }

// AnyAPNsConfigured 说明库里有没有任何一行 APNs 凭据。只在启动时问一次，
// 用来决定要不要为"凭据还留在 env 里"打那条弃用警告（与 AnyConfigured 同）。
func AnyAPNsConfigured(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_configs WHERE config_key=?`, APNsConfigKey).Scan(&count)
	return count > 0, err
}
