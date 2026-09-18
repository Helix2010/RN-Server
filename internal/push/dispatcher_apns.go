package push

// APNs 按租户取客户端与 topic。结构与 fcmSender / legacyEnvSender 一一对应
// （设计 docs/design/push-apns-and-shared-app-identity-2026-09-18.md §2.6）。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

// apnsSenderFor 取这个租户生效的 APNs 客户端。
//
// 每条事件查一次 app_configs（走主键索引），命中缓存且版本没变就直接用。
// 缓存键是**生效行**的租户：四个租户都继承平台那一行时只有一个客户端，
// 而不是四份相同的。
func (d *Dispatcher) apnsSender(ctx context.Context, tenant string) (*apns2.Client, error) {
	record, err := pushcreds.LoadAPNs(ctx, d.db, tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return d.legacyAPNsSender()
	}
	if err != nil {
		return nil, err
	}
	if record.Value.AuthKeyEncrypted == "" {
		return nil, credentialError{"APNS_NOT_CONFIGURED",
			"租户 " + record.SourceTenant + " 的 push.apns 里没有令牌密钥"}
	}
	d.apnsMu.Lock()
	cached, ok := d.apnsClients[record.SourceTenant]
	d.apnsMu.Unlock()
	if ok && cached.version == record.Version {
		return cached.client, nil
	}
	authKey, err := record.AuthKey(d.secrets)
	if err != nil {
		return nil, credentialError{"APNS_CREDENTIAL_UNREADABLE", err.Error()}
	}
	client, err := pushcreds.NewAPNsClient(record.Value, authKey)
	if err != nil {
		return nil, credentialError{"APNS_CREDENTIAL_UNREADABLE", err.Error()}
	}
	d.apnsMu.Lock()
	d.apnsClients[record.SourceTenant] = &apnsSender{version: record.Version, client: client}
	d.apnsMu.Unlock()
	return client, nil
}

// legacyAPNsSender 是过渡期的兜底：库里一行都没有、而 env 里还留着那几个键。
// 下一版删掉，见 New 里的那条警告。
func (d *Dispatcher) legacyAPNsSender() (*apns2.Client, error) {
	if d.cfg.APNsPrivateKey == "" {
		return nil, credentialError{"APNS_NOT_CONFIGURED",
			"这个租户没有 APNs 凭据，平台默认（tenant 0）也没有；到管理端配一份"}
	}
	const key = "env"
	d.apnsMu.Lock()
	cached, ok := d.apnsClients[key]
	d.apnsMu.Unlock()
	if ok {
		return cached.client, nil
	}
	client, err := pushcreds.NewAPNsClient(pushcreds.APNs{
		TeamID:      d.cfg.APNsTeamID,
		KeyID:       d.cfg.APNsKeyID,
		Environment: d.cfg.APNsEnvironment,
	}, decodeSecret(d.cfg.APNsPrivateKey))
	if err != nil {
		return nil, credentialError{"APNS_CREDENTIAL_UNREADABLE", "APNS_PRIVATE_KEY 解析失败：" + err.Error()}
	}
	d.apnsMu.Lock()
	d.apnsClients[key] = &apnsSender{version: 0, client: client}
	d.apnsMu.Unlock()
	return client, nil
}

// tenantBundleID 读该租户 release.ios 的 bundleId，只在设备没上报 package_id 时用。
//
// 直接查而不走 api 包：push 不依赖 api，而这里要的只是一个字符串。
// 读不到就返回空串，由调用方给出"两边都没有"的错误。
func (d *Dispatcher) tenantBundleID(ctx context.Context, tenant string) string {
	var raw []byte
	err := d.db.QueryRowContext(ctx,
		`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key='release.ios' LIMIT 1`, tenant).Scan(&raw)
	if err != nil {
		return ""
	}
	var value struct {
		BundleID string `json:"bundleId"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return strings.TrimSpace(value.BundleID)
}

// 保持 token 包被引用：New 里验形状用的就是它。
var _ = token.AuthKeyFromBytes
