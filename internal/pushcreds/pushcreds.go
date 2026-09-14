// Package pushcreds 是按租户存放的推送凭据。
//
// 为什么必须按租户：google-services.json 自 2026-09-13 起是按租户存的，而 FCM 的
// 设备注册 token 绑定它被签发时的 Firebase 项目。用项目 X 的服务账号去发一个属于
// 项目 A 的 token，v1 接口回 403 SENDER_ID_MISMATCH——构建成功、安装成功、token
// 注册成功，只有推送发不出去。env 里放不下 N 份服务账号，所以凭据必须和它服务的
// 租户放在一起，并且和那个租户的 google-services.json 对得上。
//
// 这个包被管理端（保存、读取、验证）和派发器（发送时解析）共用：记录形状、平台级
// 回落、解密和"真换一次令牌"的验证只有一份实现，两边不会漂开。
//
// 与 build.keystore 的区别要说清楚：签名密钥服务端**不需要也不能**解开（它加密给
// 打包机的公钥）；服务账号私钥服务端每发一条推送都要用它签 JWT，所以它和
// ota.signing 同类——服务端能解开，用 STORAGE_MASTER_KEY 封存。这一点推翻了
// ADR-0011「不写入数据库」那一句，由 ADR-0017 显式 supersede。
package pushcreds

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/internal/secretbox"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// FCMConfigKey 等三个键分开存：轮换互不影响，审计一目了然，而且三家的字段形状
// 完全不同，挤进一行 JSON 只会让每次改动都碰到另外两家。
const (
	FCMConfigKey  = "push.fcm"
	APNsConfigKey = "push.apns"
	HMSConfigKey  = "push.hms"
)

// FCMScope 是发推送所需的唯一 scope。保存时验证用的也是它——验证要和真正发送
// 走同一条路，否则"验证通过"证明不了任何事。
const FCMScope = "https://www.googleapis.com/auth/firebase.messaging"

// PlatformTenant 是平台级默认那一行。租户没有自己的凭据时继承它，这给了一条
// 零行为变化的迁移路径：把 env 里那份导进来，所有租户继续用同一个项目。
const PlatformTenant = "0"

// FCM 是 push.fcm 的 config_value。
//
// 明文只放给人看的三项——项目、账号、key id 在 Firebase 控制台上本来就公开显示，
// 不是机密，而管理端要靠它们回答"现在用的是哪把钥匙"。整份服务账号 JSON 加密存。
type FCM struct {
	ProjectID               string     `json:"projectId"`
	ClientEmail             string     `json:"clientEmail"`
	PrivateKeyID            string     `json:"privateKeyId"`
	ServiceAccountEncrypted string     `json:"serviceAccountEncrypted"`
	VerifiedAt              *time.Time `json:"verifiedAt,omitempty"`
}

// Record 是一次读取的结果。SourceTenant 是**生效那一行**的租户——它可能是平台
// 的 "0"，派发器的客户端缓存和解密用的 AAD 都必须以它为准，不是请求方的租户。
type Record struct {
	Value        FCM
	SourceTenant string
	Version      int
	UpdatedBy    string
	UpdatedAt    time.Time
}

// Inherited 说明这一行是继承来的。界面上必须显眼：继承来的项目对不上自己的
// google-services.json，一样发不出去。
func (r Record) Inherited(tenant string) bool {
	return r.SourceTenant != "" && r.SourceTenant != tenant
}

// ServiceAccount 是服务账号 JSON 里我们要看的那一部分。
type ServiceAccount struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// LoadFCM 读一个租户生效的 FCM 凭据：自己的优先，没有就用平台那一行。
func LoadFCM(ctx context.Context, db *sql.DB, tenant string) (Record, error) {
	var record Record
	var raw []byte
	err := db.QueryRowContext(ctx,
		`SELECT CAST(tenant_id AS CHAR),config_value,version,updated_by,updated_at FROM app_configs
		 WHERE config_key=? AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`,
		FCMConfigKey, tenant, tenant).
		Scan(&record.SourceTenant, &raw, &record.Version, &record.UpdatedBy, &record.UpdatedAt)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record.Value); err != nil {
		return record, fmt.Errorf("stored %s for tenant %s is not valid JSON: %w", FCMConfigKey, record.SourceTenant, err)
	}
	return record, nil
}

// AnyConfigured 说明库里有没有任何一行推送凭据。只在启动时问一次，用来决定
// 要不要为"凭据还留在 env 里"打那条弃用警告。
func AnyConfigured(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_configs WHERE config_key=?`, FCMConfigKey).Scan(&count)
	return count > 0, err
}

// AssociatedData 把密文绑在租户和字段上：一个租户的密文搬到另一个租户名下解不开。
func AssociatedData(tenant, configKey, field string) string {
	return tenant + ":" + configKey + ":" + field
}

// ServiceAccount 解出这条记录里的服务账号。AAD 用的是**生效行**的租户。
func (r Record) ServiceAccount(box *secretbox.Box) (ServiceAccount, error) {
	if r.Value.ServiceAccountEncrypted == "" {
		return ServiceAccount{}, errors.New("no service account is stored")
	}
	if box == nil {
		return ServiceAccount{}, errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(r.Value.ServiceAccountEncrypted)
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("stored service account is not valid base64: %w", err)
	}
	plaintext, err := box.Decrypt(ciphertext, AssociatedData(r.SourceTenant, FCMConfigKey, "serviceAccount"))
	if err != nil {
		return ServiceAccount{}, fmt.Errorf("stored service account cannot be decrypted: %w", err)
	}
	return ParseServiceAccount([]byte(plaintext))
}

// Encrypt 封存一份服务账号 JSON，返回 base64 密文。
func Encrypt(box *secretbox.Box, tenant string, raw []byte) (string, error) {
	if box == nil {
		return "", errors.New("STORAGE_MASTER_KEY is unavailable")
	}
	ciphertext, err := box.Encrypt(string(raw), AssociatedData(tenant, FCMConfigKey, "serviceAccount"))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// ErrLooksLikeGoogleServices：传上来的是 google-services.json，不是服务账号。
//
// 这两份文件都来自同一个 Firebase 项目、都叫 json、都从控制台下载，拿混是迟早
// 的事。build_config.go 那边已经拒绝反过来的情况（含 private_key 的），这里是
// 对称的另一半。
var ErrLooksLikeGoogleServices = errors.New("这看起来是 google-services.json（编进 APK 的那一半），不是服务账号私钥。" +
	"服务账号要到 Firebase 控制台 → 项目设置 → 服务账号 → 生成新的私钥下载")

// ParseServiceAccount 校验形状。挡在这里的每一条，放过去都会变成运行时一句
// 看不懂的 OAuth 错误。
func ParseServiceAccount(raw []byte) (ServiceAccount, error) {
	var account ServiceAccount
	if err := json.Unmarshal(raw, &account); err != nil {
		return account, fmt.Errorf("这不是合法的 JSON：%w", err)
	}
	if account.PrivateKey == "" {
		var probe struct {
			ProjectInfo map[string]any `json:"project_info"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.ProjectInfo != nil {
			return account, ErrLooksLikeGoogleServices
		}
		return account, errors.New("缺少 private_key")
	}
	if account.Type != "service_account" {
		return account, fmt.Errorf(`type 必须是 service_account，这份是 %q`, account.Type)
	}
	for field, value := range map[string]string{
		"project_id": account.ProjectID, "client_email": account.ClientEmail, "private_key_id": account.PrivateKeyID,
	} {
		if strings.TrimSpace(value) == "" {
			return account, errors.New("缺少 " + field)
		}
	}
	if !strings.Contains(account.PrivateKey, "PRIVATE KEY") {
		return account, errors.New("private_key 不像一份 PEM 私钥")
	}
	return account, nil
}

// Verify 真去换一次访问令牌。
//
// 这一步不能省。google.CredentialsFromJSON 只在本地解析 JSON，**不联网**：密钥
// 在 Firebase 控制台被吊销之后，服务照样能起来，日志一行错都没有，直到第一次真
// 发推送才炸。deploy/amos/rotate-fcm-key.sh 当初就是为这件事写的，现在它搬进了
// 服务端，走的是和真正发送完全相同的那条路——换不到令牌就不保存。
func Verify(ctx context.Context, account ServiceAccount) error {
	raw, err := json.Marshal(account)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: 15 * time.Second})
	credentials, err := google.CredentialsFromJSON(ctx, raw, FCMScope)
	if err != nil {
		return fmt.Errorf("这份服务账号无法加载：%w", err)
	}
	if _, err := credentials.TokenSource.Token(); err != nil {
		return fmt.Errorf("%w：%s", ErrTokenExchangeFailed, tokenExchangeHint(err))
	}
	return nil
}

// ErrTokenExchangeFailed：拿着这把钥匙换不到访问令牌。
var ErrTokenExchangeFailed = errors.New("Google 拒绝了这把密钥")

// tokenExchangeHint 把 Google 的原文带上，并对两种一眼看不出原因的加一句提示。
func tokenExchangeHint(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "invalid_grant"):
		// 服务端和 Google 的时钟差超过几十秒时就是这一句，而它读起来像"密钥不对"
		return message + "（invalid_grant 也可能是服务器时钟偏差，检查一下 timedatectl）"
	case strings.Contains(message, "invalid_client"):
		return message + "（服务账号可能已在 Firebase 控制台被删除或禁用）"
	}
	return message
}

// NewHTTPClient 造一个会自动带上访问令牌的客户端，令牌的缓存与刷新由 oauth2
// 自己管。派发器按租户持有它。
func NewHTTPClient(ctx context.Context, account ServiceAccount) (*http.Client, error) {
	raw, err := json.Marshal(account)
	if err != nil {
		return nil, err
	}
	credentials, err := google.CredentialsFromJSON(ctx, raw, FCMScope)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &oauth2.Transport{Source: credentials.TokenSource}, Timeout: 15 * time.Second}, nil
}

// KeyHint 是 private_key_id 的前 8 位。审计和界面上用它回答"现在用的是哪一把"，
// 而不用把 id 整个印出来。
func KeyHint(privateKeyID string) string {
	if len(privateKeyID) <= 8 {
		return privateKeyID
	}
	return privateKeyID[:8] + "…"
}

// ---- 打印时的机密防护 ----
//
// ServiceAccount 里装着 private_key：一次 `fmt.Errorf("...%v", account)` 或
// `slog.Error("...", "account", account)` 就够把发推送的能力整个交出去。和
// config.Config 一样用白名单——只列可以打印的三项，新加字段默认不出现。
//
// 注意 Verify / NewHTTPClient 里的 json.Marshal(account) **不受影响也不该受影响**：
// 那是把它交给 Google，不是打印。

func (a ServiceAccount) safeSummary() string {
	return fmt.Sprintf("serviceAccount{project=%s client=%s keyId=%s privateKey=%s}",
		a.ProjectID, a.ClientEmail, KeyHint(a.PrivateKeyID), presence(a.PrivateKey))
}

func (a ServiceAccount) String() string       { return a.safeSummary() }
func (a ServiceAccount) GoString() string     { return a.safeSummary() }
func (a ServiceAccount) LogValue() slog.Value { return slog.StringValue(a.safeSummary()) }

// FCM 的 config_value 也一样：密文不该出现在日志里，它的长度和存在与否才是有用的。
func (f FCM) safeSummary() string {
	return fmt.Sprintf("push.fcm{project=%s client=%s keyId=%s sealed=%s}",
		f.ProjectID, f.ClientEmail, KeyHint(f.PrivateKeyID), presence(f.ServiceAccountEncrypted))
}

func (f FCM) String() string       { return f.safeSummary() }
func (f FCM) GoString() string     { return f.safeSummary() }
func (f FCM) LogValue() slog.Value { return slog.StringValue(f.safeSummary()) }

func presence(value string) string {
	if value == "" {
		return "unset"
	}
	return fmt.Sprintf("<set,%d chars>", len(value))
}
