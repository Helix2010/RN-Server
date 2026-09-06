// Package indexer 是扫链进程：按链轮询平台配置的端点，把目录内 ERC-20 转账与原生币
// 入账写进 wallet_transfer_index。设计见 RN-App/docs/design/wallet-receive-index-2026-09-06.md。
package indexer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

const (
	// rpcTimeout 单次请求上限；全区块与日志响应可能很大，给得比代币元数据读取宽。
	rpcTimeout = 30 * time.Second
	// rpcMaxResponse 单次响应上限：100 块 Monad 全交易约几 MB，8MB 够用且能挡住恶意端点。
	rpcMaxResponse = 8 << 20
	// coolingBase / coolingMax 端点冷却退避：30s × 2^n，上限 10 分钟。
	coolingBase = 30 * time.Second
	coolingMax  = 10 * time.Minute
	// failuresBeforeCooling 连续失败几次进入冷却。
	failuresBeforeCooling = 3
)

var (
	// errNoEndpoint 全部端点不可用：worker 进入 stalled。
	errNoEndpoint = errors.New("no healthy endpoint")
	// errSpanTooLarge 节点拒绝了区块跨度：调用方把跨度减半重试，不算端点失败。
	errSpanTooLarge = errors.New("block range rejected by endpoint")
	// spanPattern 各家节点对"跨度过大"的说法不一样（实测：-32614 / "Block range is too large" /
	// "limit exceeded" / "query returned more than"），按文案兜不住的用 code 兜。
	spanPattern = regexp.MustCompile(`(?i)block range|range is too large|limited to|too many (logs|results|blocks)|limit exceeded|returned more than|exceeds? .*limit`)
)

// rpcError JSON-RPC 层错误。
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message) }

// isSpanError 判断是否"跨度过大"：-32614 是 Base / Monad 的码，其余按文案。
func isSpanError(err error) bool {
	var typed *rpcError
	if errors.As(err, &typed) {
		return typed.Code == -32614 || spanPattern.MatchString(typed.Message)
	}
	return false
}

// endpoint 一个端点及其运行时健康度。
type endpoint struct {
	cfg    scan.Endpoint
	health scan.EndpointHealth
	bucket *tokenBucket
}

// Pool 一条链的端点池：按配置顺序选第一个健康端点，同一轮固定用它；失败计数、
// 冷却、chainId 核对、落后节点跳过、每端点限速都在这里。
type Pool struct {
	chain     string
	chainID   int64
	client    *http.Client
	now       func() time.Time
	mu        sync.Mutex
	endpoints []*endpoint
	// current 本轮固定使用的端点下标；-1 表示尚未选择。
	current int
}

// NewPool 构造端点池。chainID 来自平台链目录，每个端点首次使用前核对 eth_chainId。
func NewPool(chain string, chainID int64, endpoints []scan.Endpoint, client *http.Client, now func() time.Time) *Pool {
	if client == nil {
		client = &http.Client{}
	}
	if now == nil {
		now = time.Now
	}
	pool := &Pool{chain: chain, chainID: chainID, client: client, now: now, current: -1}
	for _, cfg := range endpoints {
		sum := sha256.Sum256([]byte(strings.TrimSpace(cfg.URL)))
		pool.endpoints = append(pool.endpoints, &endpoint{
			cfg:    cfg,
			health: scan.EndpointHealth{Label: cfg.Label, URLHash: hex.EncodeToString(sum[:]), Health: scan.HealthUnknown},
			bucket: newTokenBucket(cfg.RPS, now),
		})
	}
	return pool
}

// Health 返回端点健康度快照，按配置顺序。
func (p *Pool) Health() []scan.EndpointHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]scan.EndpointHealth, 0, len(p.endpoints))
	for _, item := range p.endpoints {
		out = append(out, item.health)
	}
	return out
}

// RestoreHealth 用落库的健康度初始化（重启后不用重新探所有端点）。
func (p *Pool) RestoreHealth(saved []scan.EndpointHealth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, item := range p.endpoints {
		for _, prior := range saved {
			if prior.URLHash == item.health.URLHash {
				item.health = prior
				item.health.Label = item.cfg.Label
				if item.health.Health == scan.HealthCooling && item.health.CoolingUntil != nil && !item.health.CoolingUntil.After(p.now()) {
					item.health.Health = scan.HealthUnknown
				}
			}
		}
	}
}

// BeginRound 为新一轮选端点：按顺序找第一个可用的（healthy，或冷却到期 / unknown 且探活通过）。
// minHead 是游标：端点链头低于它就是落后节点，本轮跳过。
func (p *Pool) BeginRound(ctx context.Context, minHead uint64) (uint64, error) {
	p.mu.Lock()
	candidates := make([]int, 0, len(p.endpoints))
	for index, item := range p.endpoints {
		switch item.health.Health {
		case scan.HealthMismatch:
			continue
		case scan.HealthCooling:
			if item.health.CoolingUntil != nil && item.health.CoolingUntil.After(p.now()) {
				continue
			}
		}
		candidates = append(candidates, index)
	}
	p.mu.Unlock()
	var lastErr error = errNoEndpoint
	for _, index := range candidates {
		head, err := p.probe(ctx, index)
		if err != nil {
			lastErr = err
			continue
		}
		if head < minHead {
			p.note(index, fmt.Errorf("endpoint head %d is behind cursor %d", head, minHead), false)
			lastErr = fmt.Errorf("endpoint %s is behind cursor", p.endpoints[index].cfg.Label)
			continue
		}
		p.mu.Lock()
		p.current = index
		p.mu.Unlock()
		return head, nil
	}
	p.mu.Lock()
	p.current = -1
	p.mu.Unlock()
	return 0, lastErr
}

// probe 探活：eth_chainId 必须等于目录，再取链头。chainId 不符永久剔除。
func (p *Pool) probe(ctx context.Context, index int) (uint64, error) {
	raw, err := p.callIndex(ctx, index, "eth_chainId", nil)
	if err != nil {
		p.note(index, err, true)
		return 0, err
	}
	got, err := hexQuantity(raw)
	if err != nil {
		p.note(index, err, true)
		return 0, err
	}
	if got.Cmp(big.NewInt(p.chainID)) != 0 {
		p.mu.Lock()
		item := p.endpoints[index]
		item.health.Health = scan.HealthMismatch
		item.health.LastError = fmt.Sprintf("endpoint reports chain %s, catalog says %d", got, p.chainID)
		p.mu.Unlock()
		return 0, fmt.Errorf("endpoint %s: %s", item.cfg.Label, item.health.LastError)
	}
	rawHead, err := p.callIndex(ctx, index, "eth_blockNumber", nil)
	if err != nil {
		p.note(index, err, true)
		return 0, err
	}
	head, err := hexUint64(rawHead)
	if err != nil {
		p.note(index, err, true)
		return 0, err
	}
	p.mu.Lock()
	item := p.endpoints[index]
	item.health.Health = scan.HealthHealthy
	item.health.ConsecutiveFailures = 0
	item.health.CoolingUntil = nil
	item.health.HeadBlock = head
	p.mu.Unlock()
	return head, nil
}

// Current 当前端点的 label（日志用）。
func (p *Pool) Current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current < 0 {
		return ""
	}
	return p.endpoints[p.current].cfg.Label
}

// SpanFor 当前端点生效的 eth_getLogs 跨度：端点级覆盖优先。
func (p *Pool) SpanFor(chainSpan int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current >= 0 && p.endpoints[p.current].cfg.MaxLogSpan > 0 {
		return p.endpoints[p.current].cfg.MaxLogSpan
	}
	return chainSpan
}

// Call 用本轮端点发一次请求。传输层 / 5xx 错误计入失败；跨度错误原样返回给调用方。
func (p *Pool) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	p.mu.Lock()
	index := p.current
	p.mu.Unlock()
	if index < 0 {
		return nil, errNoEndpoint
	}
	raw, err := p.callIndex(ctx, index, method, params)
	if err != nil {
		if isSpanError(err) {
			p.mu.Lock()
			p.endpoints[index].health.SpanRejected++
			p.mu.Unlock()
			return nil, errSpanTooLarge
		}
		var typed *rpcError
		if errors.As(err, &typed) {
			// 其它 JSON-RPC 层错误（参数、方法不支持）是确定性的，不算端点故障
			return nil, err
		}
		p.note(index, err, true)
		return nil, err
	}
	return raw, nil
}

// note 记一次失败；countFailure=false 只记错误文案（落后节点）不计数。
func (p *Pool) note(index int, err error, countFailure bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.endpoints[index]
	item.health.LastError = truncate(err.Error(), 512)
	if !countFailure {
		return
	}
	item.health.ConsecutiveFailures++
	if item.health.ConsecutiveFailures >= failuresBeforeCooling {
		exponent := item.health.ConsecutiveFailures - failuresBeforeCooling
		if exponent > 5 {
			exponent = 5
		}
		delay := coolingBase * time.Duration(1<<uint(exponent))
		if delay > coolingMax {
			delay = coolingMax
		}
		until := p.now().Add(delay)
		item.health.Health = scan.HealthCooling
		item.health.CoolingUntil = &until
		if p.current == index {
			p.current = -1
		}
	}
}

// callIndex 对指定端点发请求：限速等待 → HTTP → 解 JSON-RPC。
func (p *Pool) callIndex(ctx context.Context, index int, method string, params []any) (json.RawMessage, error) {
	item := p.endpoints[index]
	if err := item.bucket.wait(ctx); err != nil {
		return nil, err
	}
	if params == nil {
		params = []any{}
	}
	payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodPost, item.cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	started := p.now()
	response, err := p.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, rpcMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > rpcMaxResponse {
		return nil, fmt.Errorf("%s: response exceeds %d bytes", method, rpcMaxResponse)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	// 有些节点用 413 / 400 带 JSON-RPC error 体报跨度过大（实测 Monad、Base），先试着解
	if unmarshalErr := json.Unmarshal(body, &envelope); unmarshalErr == nil && envelope.Error != nil {
		return nil, envelope.Error
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", method, response.StatusCode)
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%s: malformed json-rpc response", method)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil, fmt.Errorf("%s: response has no result", method)
	}
	p.mu.Lock()
	item.health.LatencyMs = int(p.now().Sub(started) / time.Millisecond)
	okAt := p.now()
	item.health.LastOkAt = &okAt
	if item.health.Health == scan.HealthHealthy {
		item.health.ConsecutiveFailures = 0
	}
	p.mu.Unlock()
	return envelope.Result, nil
}

// tokenBucket 每端点限速：rps 个令牌 / 秒，桶容量 = rps。
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(rps int, now func() time.Time) *tokenBucket {
	if rps < 1 {
		rps = 1
	}
	return &tokenBucket{rate: float64(rps), tokens: float64(rps), last: now(), now: now}
}

func (b *tokenBucket) wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		current := b.now()
		b.tokens += current.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.rate {
			b.tokens = b.rate
		}
		b.last = current
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		missing := (1 - b.tokens) / b.rate
		b.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(missing * float64(time.Second))):
		}
	}
}

// ---- 解码工具 ----

func hexQuantity(raw json.RawMessage) (*big.Int, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("result is not a string")
	}
	return parseHexQuantity(value)
}

func parseHexQuantity(value string) (*big.Int, error) {
	if !strings.HasPrefix(value, "0x") || len(value) == 2 {
		return nil, errors.New("value is not a hex quantity")
	}
	number, ok := new(big.Int).SetString(value[2:], 16)
	if !ok {
		return nil, errors.New("value is not a hex quantity")
	}
	return number, nil
}

func hexUint64(raw json.RawMessage) (uint64, error) {
	number, err := hexQuantity(raw)
	if err != nil {
		return 0, err
	}
	if !number.IsUint64() {
		return 0, errors.New("quantity exceeds uint64")
	}
	return number.Uint64(), nil
}

func parseHexUint64(value string) (uint64, error) {
	number, err := parseHexQuantity(value)
	if err != nil {
		return 0, err
	}
	if !number.IsUint64() {
		return 0, errors.New("quantity exceeds uint64")
	}
	return number.Uint64(), nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
