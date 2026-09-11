package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 灰度发布（canary）：一条发布记录只对名单里的安装可见，与 active 平行、互不干涉。
// 设计与论证见 RN-App/docs/design/canary-release-allowlist-2026-09-11.md。
//
// 这里集中三件事，免得四条读路径各写一遍走样：
//  1. 可见性 SQL 片段（canaryVisibleSQL / canaryVisibleOTASQL）；
//  2. 把请求解析成"服务端认可的安装 ID"，认不出一律空串（fail-closed）；
//  3. OTA 用的短时灰度令牌——manifest 请求由原生侧在 JS 起来之前发出，带不了
//     Authorization，只能靠 bootstrap 预先下发、由 extra params 捎回来的令牌。

// canaryVisibleSQL 是全量包读路径共用的可见性条件：active，或者"灰度且我在名单里"。
// 两个占位符吃同一个安装 ID：第一处让空身份直接让整个灰度分支失效（老客户端、匿名
// 请求、凭证无效都落在这里），第二处做名单匹配。JSON_CONTAINS(NULL,…) 求值为 NULL，
// 所以名单为空的灰度行对谁都不可见——出错的方向永远是"少发"。
const canaryVisibleSQL = `(status='active' OR (status='canary' AND ?<>'' AND JSON_CONTAINS(canary_installations,JSON_QUOTE(?))))`

// canaryVisibleOTASQL 与上面同形，给 ota_releases 带表别名 o 的查询用。
const canaryVisibleOTASQL = `(o.status='active' OR (o.status='canary' AND ?<>'' AND JSON_CONTAINS(o.canary_installations,JSON_QUOTE(?))))`

// canaryTokenTTL 是灰度令牌的有效期。短到抓包拿去冒充也活不过一天，长到设备一天
// 开一次 App 就能续上；过期而没续上时设备静默回到 active，不报错。
const canaryTokenTTL = 24 * time.Hour

// canaryTokenAAD 把令牌绑死在租户上，与发布产物令牌同一套认证加密（不是签名：
// 客户端读不出里面的安装 ID，改一个字节就解不开）。
const canaryTokenAAD = "canary-audience:"

// canaryExtraParamKey 是 OTA manifest 请求里捎带令牌用的 Expo-Extra-Params 键。
// 必须全小写：expo-structured-headers 的 Utils.checkKey 只认 lcalpha/digit/_-.*，
// 键里出现大写字母会在拼 manifest 请求头时抛 IllegalArgumentException。
const canaryExtraParamKey = "canary-token"

// canaryAudienceLimit 是单条发布的名单上限，与设计里"JSON 列只撑到一两百台"的门槛一致。
// 超过这个量级要改成关联表，而不是把 JSON 列养大。
const canaryAudienceLimit = 200

type canaryAudienceToken struct {
	InstallationID string `json:"installationId"`
	TenantID       string `json:"tenantId"`
	ExpiresAt      int64  `json:"expiresAt"`
}

func (s *server) encodeCanaryToken(tenant, installationID string, now time.Time) (string, error) {
	if s.secrets == nil {
		return "", errors.New("storage master key is unavailable")
	}
	raw, err := json.Marshal(canaryAudienceToken{InstallationID: installationID, TenantID: tenant, ExpiresAt: now.Add(canaryTokenTTL).Unix()})
	if err != nil {
		return "", err
	}
	encrypted, err := s.secrets.Encrypt(string(raw), canaryTokenAAD+tenant)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encrypted), nil
}

// decodeCanaryToken 只在完全可信时返回安装 ID；解不开、租户不符、过期都返回空串，
// 调用方据此按匿名处理。
func (s *server) decodeCanaryToken(tenant, encoded string) string {
	if s.secrets == nil || strings.TrimSpace(encoded) == "" {
		return ""
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return ""
	}
	plaintext, err := s.secrets.Decrypt(encrypted, canaryTokenAAD+tenant)
	if err != nil {
		return ""
	}
	var value canaryAudienceToken
	if json.Unmarshal([]byte(plaintext), &value) != nil || value.TenantID != tenant || value.InstallationID == "" {
		return ""
	}
	if time.Now().UTC().Unix() > value.ExpiresAt {
		return ""
	}
	return value.InstallationID
}

// canaryAudienceID 解析"服务端认可的安装身份"：必须同时带 X-Installation-ID 和有效的
// Authorization: Installation <凭证>。裸的安装 ID 不算数——它会出现在日志与截图里，
// 改机工具也能伪造，见设计 §8.1。
//
// 任何一步不成立都返回空串，调用方继续按匿名往下走：bootstrap 是启动门禁，
// 配置必须照发，只是不给灰度。
func (s *server) canaryAudienceID(c *gin.Context, tenant string) string {
	installationID := strings.TrimSpace(c.GetHeader("x-installation-id"))
	if installationID == "" || tenant == "" {
		return ""
	}
	if _, code := s.verifyInstallationCredentialFor(c, tenant, installationID); code != "" {
		return ""
	}
	return installationID
}

// canaryAudienceFromExtraParams 取 OTA manifest 请求里的灰度令牌并还原安装 ID。
func (s *server) canaryAudienceFromExtraParams(c *gin.Context, tenant string) string {
	return s.decodeCanaryToken(tenant, structuredDictionaryString(c.GetHeader("Expo-Extra-Params"), canaryExtraParamKey))
}

// structuredDictionaryString 从 RFC 8941 结构化字典里取一个字符串成员的值，
// 形如 `canary-token="abc", other="x"`。expo 一律用 sf-string 序列化（StringItem），
// 但这里同时接受裸 token 形式，免得依赖对端的序列化细节。
// 解析不出来返回空串——上层会按匿名处理，没有需要区分的失败原因。
func structuredDictionaryString(header, key string) string {
	header = strings.TrimSpace(header)
	if header == "" || key == "" {
		return ""
	}
	for _, member := range splitStructuredMembers(header) {
		name, value, found := strings.Cut(member, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), key) {
			continue
		}
		value = strings.TrimSpace(value)
		// 参数（`key="v";p=1`）不属于值本身，切掉
		if !strings.HasPrefix(value, `"`) {
			if semicolon := strings.IndexByte(value, ';'); semicolon >= 0 {
				value = strings.TrimSpace(value[:semicolon])
			}
			return value
		}
		return unquoteStructuredString(value)
	}
	return ""
}

// splitStructuredMembers 按逗号切分字典成员，引号内的逗号不算分隔符。
func splitStructuredMembers(header string) []string {
	members := []string{}
	quoted, escaped, start := false, false, 0
	for i := 0; i < len(header); i++ {
		switch {
		case escaped:
			escaped = false
		case quoted && header[i] == '\\':
			escaped = true
		case header[i] == '"':
			quoted = !quoted
		case header[i] == ',' && !quoted:
			members = append(members, strings.TrimSpace(header[start:i]))
			start = i + 1
		}
	}
	return append(members, strings.TrimSpace(header[start:]))
}

// unquoteStructuredString 还原 sf-string：只有 `"` 和 `\` 会被转义。
// base64url 的字符集（A-Za-z0-9-_）里一个都没有，所以令牌走这条路不会有歧义。
func unquoteStructuredString(value string) string {
	if len(value) < 2 || !strings.HasPrefix(value, `"`) {
		return ""
	}
	var out strings.Builder
	for i := 1; i < len(value); i++ {
		switch value[i] {
		case '\\':
			if i+1 >= len(value) {
				return ""
			}
			i++
			if value[i] != '"' && value[i] != '\\' {
				return ""
			}
			out.WriteByte(value[i])
		case '"':
			if i != len(value)-1 {
				return ""
			}
			return out.String()
		default:
			out.WriteByte(value[i])
		}
	}
	return ""
}

// normalizeCanaryAudience 校验并规整管理端提交的名单：去空白、去重、保序。
// 返回的错误码直接给 problem() 用。
func normalizeCanaryAudience(raw []string) ([]string, string, string) {
	seen := map[string]bool{}
	audience := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if len(item) > 120 {
			return nil, "CANARY_AUDIENCE_INVALID", "Installation IDs must be at most 120 characters"
		}
		if seen[item] {
			continue
		}
		seen[item] = true
		audience = append(audience, item)
	}
	if len(audience) == 0 {
		return nil, "CANARY_AUDIENCE_REQUIRED", "A canary release must target at least one installation"
	}
	if len(audience) > canaryAudienceLimit {
		return nil, "CANARY_AUDIENCE_TOO_LARGE", "A canary audience is limited to 200 installations"
	}
	return audience, "", ""
}

// unknownCanaryInstallations 挑出这个租户下不存在的安装 ID。拼错一个字符的名单会
// 让灰度悄悄对那台设备失效，运营只会看到"发了但没收到"——不如入口就拒绝。
func (s *server) unknownCanaryInstallations(ctx context.Context, tenant, platform string, audience []string) ([]string, error) {
	if len(audience) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(audience)), ",")
	args := make([]any, 0, len(audience)+2)
	args = append(args, tenant, platform)
	for _, item := range audience {
		args = append(args, item)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT installation_id FROM app_installations WHERE tenant_id=? AND platform=? AND installation_id IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		known[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	unknown := []string{}
	for _, item := range audience {
		if !known[item] {
			unknown = append(unknown, item)
		}
	}
	return unknown, nil
}

// canaryAudienceOf 解析存储的名单列；NULL / 空 / 解析失败都当空名单。
func canaryAudienceOf(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var audience []string
	if json.Unmarshal(raw, &audience) != nil {
		return nil
	}
	return audience
}

// canaryAudienceDigest 给审计用：记设备数与内容哈希，不灌完整名单。
// 审计回答的是"谁在什么时候把范围改成了什么"，完整名单在发布记录上随时可查。
func canaryAudienceDigest(audience []string) map[string]any {
	sorted := append([]string(nil), audience...)
	sort.Strings(sorted)
	return map[string]any{"count": len(audience), "sha256": sha256Hex(strings.Join(sorted, "\n"))}
}

// canaryAudienceForStatus 只在灰度状态下把名单交出去：别的状态下这一列即使有残留值
// 也不代表"生效中的范围"，返回 nil 让管理端只能显示"没有"。
func canaryAudienceForStatus(status string, raw []byte) []string {
	if status != "canary" {
		return nil
	}
	audience := canaryAudienceOf(raw)
	if audience == nil {
		return []string{}
	}
	return audience
}
