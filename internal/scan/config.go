// Package scan 是扫链模块在 API 进程与 indexer 进程之间共享的模型：每条链的扫链
// 配置（存在 app_configs 的 tenant 0 行里）与运行状态（chain_scan_state 表）。
// 这里只放数据形状、校验和存取 SQL，不放扫链逻辑；api 包用它做管理接口，
// indexer 包用它驱动 worker。
package scan

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Helix2010/RN-Server/internal/secretbox"
)

const (
	// ConfigKeyPrefix 是 app_configs.config_key 的前缀：chain-scan.<chain>。
	ConfigKeyPrefix = "chain-scan."

	// NativeModeBlocks 逐块读全部交易：精确、双向、零延迟，每块一次请求。
	NativeModeBlocks NativeMode = "blocks"
	// NativeModeBalance 用 Multicall3 余额差触发：只记入账，归属可能延后。
	NativeModeBalance NativeMode = "balance"

	// 默认值只用于管理端新建配置时的预填，不是运行时兜底：配置行里缺字段就是非法。
	DefaultAddrChunk    = 1000
	DefaultNativeGapCap = 20000

	MaxEndpoints    = 8
	MaxLabelLength  = 80
	MaxURLLength    = 512
	MaxEndpointRPS  = 1000
	MaxConfirmation = 1000
	MaxPollSeconds  = 3600
)

// NativeMode 原生币索引模式。
type NativeMode string

// Endpoint 一个扫链端点。URL 可能带密钥，落库前必须用 secretbox 加密。
type Endpoint struct {
	URL   string `json:"url"`
	Label string `json:"label"`
	// RPS 每秒请求上限（令牌桶），追块时同样受限。
	RPS int `json:"rps"`
	// MaxLogSpan 端点级的 eth_getLogs 跨度覆盖；0 表示用链级值。
	MaxLogSpan int `json:"maxLogSpan,omitempty"`
}

// ChainConfig 一条链的扫链配置，对应 app_configs 里 chain-scan.<chain> 的 config_value。
type ChainConfig struct {
	Chain         string     `json:"-"`
	Enabled       bool       `json:"enabled"`
	Paused        bool       `json:"paused"`
	Endpoints     []Endpoint `json:"endpoints"`
	MaxLogSpan    int        `json:"maxLogSpan"`
	Confirmations int        `json:"confirmations"`
	PollSeconds   int        `json:"pollSeconds"`
	AddrChunk     int        `json:"addrChunk"`
	NativeMode    NativeMode `json:"nativeMode"`
	NativeGapCap  uint64     `json:"nativeGapCap"`
	StartBlock    uint64     `json:"startBlock"`
	// Version 是 app_configs.version，只读；indexer 用它判断配置是否变化。
	Version int `json:"-"`
}

// storedEndpoint 是落库形态：url 换成 secretbox 密文的 base64。
type storedEndpoint struct {
	URLEncrypted string `json:"urlEncrypted"`
	Label        string `json:"label"`
	RPS          int    `json:"rps"`
	MaxLogSpan   int    `json:"maxLogSpan,omitempty"`
}

type storedConfig struct {
	Enabled       bool             `json:"enabled"`
	Paused        bool             `json:"paused"`
	Endpoints     []storedEndpoint `json:"endpoints"`
	MaxLogSpan    int              `json:"maxLogSpan"`
	Confirmations int              `json:"confirmations"`
	PollSeconds   int              `json:"pollSeconds"`
	AddrChunk     int              `json:"addrChunk"`
	NativeMode    NativeMode       `json:"nativeMode"`
	NativeGapCap  uint64           `json:"nativeGapCap"`
	StartBlock    uint64           `json:"startBlock"`
}

// ConfigKey 返回某条链的 app_configs.config_key。
func ConfigKey(chain string) string { return ConfigKeyPrefix + chain }

// AssociatedData 是端点 URL 加密时绑定的关联数据：换链或换字段就解不开。
func AssociatedData(chain string) string { return "chain-scan:" + chain + ":endpoint" }

// ValidationError 是配置校验失败，管理端按 400 返回原文。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// Validate 做结构校验（不访问网络）：范围、数量、URL 形式。端点 eth_chainId 是否
// 相符由管理端保存前的体检负责。allowPlainHTTP 只在私网部署时打开。
func Validate(cfg ChainConfig, allowPlainHTTP bool) error {
	if strings.TrimSpace(cfg.Chain) == "" {
		return invalid("chain 不能为空")
	}
	if len(cfg.Endpoints) > MaxEndpoints {
		return invalid("端点最多 %d 个", MaxEndpoints)
	}
	if cfg.Enabled && len(cfg.Endpoints) == 0 {
		return invalid("启用扫链至少要配置一个端点")
	}
	seen := map[string]bool{}
	for index, endpoint := range cfg.Endpoints {
		if err := validateEndpoint(endpoint, allowPlainHTTP); err != nil {
			return invalid("端点 %d：%v", index+1, err)
		}
		if seen[endpoint.URL] {
			return invalid("端点 %d 与前面的端点重复", index+1)
		}
		seen[endpoint.URL] = true
	}
	if cfg.MaxLogSpan < 1 {
		return invalid("maxLogSpan 必须 ≥ 1（先跑端点体检取建议值）")
	}
	if cfg.Confirmations < 1 || cfg.Confirmations > MaxConfirmation {
		return invalid("confirmations 必须在 1～%d 之间", MaxConfirmation)
	}
	if cfg.PollSeconds < 1 || cfg.PollSeconds > MaxPollSeconds {
		return invalid("pollSeconds 必须在 1～%d 之间", MaxPollSeconds)
	}
	if cfg.AddrChunk < 1 || cfg.AddrChunk > 5000 {
		return invalid("addrChunk 必须在 1～5000 之间")
	}
	switch cfg.NativeMode {
	case NativeModeBlocks, NativeModeBalance:
	default:
		return invalid("nativeMode 只能是 blocks 或 balance")
	}
	if cfg.NativeMode == NativeModeBalance && cfg.NativeGapCap < 1 {
		return invalid("balance 模式下 nativeGapCap 必须 ≥ 1")
	}
	return nil
}

func validateEndpoint(endpoint Endpoint, allowPlainHTTP bool) error {
	raw := strings.TrimSpace(endpoint.URL)
	if raw == "" {
		return errors.New("url 不能为空")
	}
	if len(raw) > MaxURLLength {
		return fmt.Errorf("url 超过 %d 字符", MaxURLLength)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return errors.New("url 不是合法地址")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !allowPlainHTTP {
			return errors.New("只允许 https://（私网明文 http 需要 INDEXER_ALLOW_PLAIN_HTTP=true）")
		}
	default:
		return errors.New("url 必须以 https:// 开头")
	}
	if strings.TrimSpace(endpoint.Label) == "" {
		return errors.New("label 不能为空")
	}
	if len(endpoint.Label) > MaxLabelLength {
		return fmt.Errorf("label 超过 %d 字符", MaxLabelLength)
	}
	if endpoint.RPS < 1 || endpoint.RPS > MaxEndpointRPS {
		return fmt.Errorf("rps 必须在 1～%d 之间", MaxEndpointRPS)
	}
	if endpoint.MaxLogSpan < 0 {
		return errors.New("maxLogSpan 不能为负")
	}
	return nil
}

// Encode 把配置转成落库 JSON：端点 URL 用 box 加密。
func Encode(cfg ChainConfig, box *secretbox.Box) ([]byte, error) {
	if box == nil {
		return nil, errors.New("storage secret box is not configured")
	}
	stored := storedConfig{
		Enabled: cfg.Enabled, Paused: cfg.Paused, MaxLogSpan: cfg.MaxLogSpan,
		Confirmations: cfg.Confirmations, PollSeconds: cfg.PollSeconds, AddrChunk: cfg.AddrChunk,
		NativeMode: cfg.NativeMode, NativeGapCap: cfg.NativeGapCap, StartBlock: cfg.StartBlock,
		Endpoints: make([]storedEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, endpoint := range cfg.Endpoints {
		ciphertext, err := box.Encrypt(strings.TrimSpace(endpoint.URL), AssociatedData(cfg.Chain))
		if err != nil {
			return nil, err
		}
		stored.Endpoints = append(stored.Endpoints, storedEndpoint{
			URLEncrypted: base64.StdEncoding.EncodeToString(ciphertext),
			Label:        strings.TrimSpace(endpoint.Label),
			RPS:          endpoint.RPS,
			MaxLogSpan:   endpoint.MaxLogSpan,
		})
	}
	return json.Marshal(stored)
}

// Decode 把落库 JSON 解回配置：端点 URL 解密。任何字段缺失或解不开都是错误，
// 不用默认值补——配置行坏了就是事故，要在管理端修。
func Decode(chain string, raw []byte, version int, box *secretbox.Box) (ChainConfig, error) {
	if box == nil {
		return ChainConfig{}, errors.New("storage secret box is not configured")
	}
	var stored storedConfig
	if err := json.Unmarshal(raw, &stored); err != nil {
		return ChainConfig{}, fmt.Errorf("chain-scan.%s: malformed config json: %w", chain, err)
	}
	cfg := ChainConfig{
		Chain: chain, Enabled: stored.Enabled, Paused: stored.Paused, MaxLogSpan: stored.MaxLogSpan,
		Confirmations: stored.Confirmations, PollSeconds: stored.PollSeconds, AddrChunk: stored.AddrChunk,
		NativeMode: stored.NativeMode, NativeGapCap: stored.NativeGapCap, StartBlock: stored.StartBlock,
		Version: version, Endpoints: make([]Endpoint, 0, len(stored.Endpoints)),
	}
	for index, endpoint := range stored.Endpoints {
		ciphertext, err := base64.StdEncoding.DecodeString(endpoint.URLEncrypted)
		if err != nil {
			return ChainConfig{}, fmt.Errorf("chain-scan.%s: endpoint %d url is not base64", chain, index+1)
		}
		plain, err := box.Decrypt(ciphertext, AssociatedData(chain))
		if err != nil {
			return ChainConfig{}, fmt.Errorf("chain-scan.%s: endpoint %d: %w", chain, index+1, err)
		}
		cfg.Endpoints = append(cfg.Endpoints, Endpoint{URL: plain, Label: endpoint.Label, RPS: endpoint.RPS, MaxLogSpan: endpoint.MaxLogSpan})
	}
	// 落库的配置也过一遍结构校验：手工改库改坏了要在这里暴露，而不是让 worker 带病运行
	if err := Validate(cfg, true); err != nil {
		return ChainConfig{}, fmt.Errorf("chain-scan.%s: %w", chain, err)
	}
	return cfg, nil
}

// MaskURL 把端点 URL 里可能含密钥的部分遮掉，只留 scheme + host + 路径首段。
func MaskURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "…"
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	path := ""
	if len(segments) > 0 && segments[0] != "" {
		path = "/" + segments[0]
		if len(segments) > 1 {
			path += "/…"
		}
	}
	return parsed.Scheme + "://" + parsed.Host + path
}

// HasSecret 粗判 URL 是否带密钥：有 query、或路径里有 ≥ 16 位的十六进制 / base64 段。
func HasSecret(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if parsed.RawQuery != "" || parsed.User != nil {
		return true
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if len(segment) >= 16 && !strings.ContainsAny(segment, ".-") {
			return true
		}
	}
	return false
}
