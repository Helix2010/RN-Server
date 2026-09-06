package indexer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

// EndpointProbe 是管理端"端点体检"的结果：一个端点跑一遍，给出可用跨度与建议。
type EndpointProbe struct {
	Label          string  `json:"label"`
	OK             bool    `json:"ok"`
	Error          string  `json:"error,omitempty"`
	ChainID        int64   `json:"chainId,omitempty"`
	HeadBlock      uint64  `json:"headBlock,omitempty"`
	LatencyMs      int     `json:"latencyMs,omitempty"`
	BlockTimeMs    int     `json:"blockTimeMs,omitempty"`
	Multicall3     bool    `json:"multicall3"`
	MaxLogSpan     int     `json:"maxLogSpan"`
	FullBlockMs    int     `json:"fullBlockMs,omitempty"`
	FullBlockTxs   int     `json:"fullBlockTxs,omitempty"`
	SpanTried      []int   `json:"spanTried"`
	SuggestedMode  string  `json:"suggestedMode,omitempty"`
	SuggestedSpan  int     `json:"suggestedSpan,omitempty"`
	SuggestedConfs int     `json:"suggestedConfirmations,omitempty"`
	sampleSeconds  float64 // 内部：出块秒数
}

// probeSpans 体检尝试的 eth_getLogs 跨度，从小到大，取最后一个成功的。
var probeSpans = []int{100, 500, 1000, 2000, 5000, 10000}

// ProbeEndpoint 对一个端点做体检：chainId 核对、链头、出块时间、Multicall3、
// getLogs 可用跨度（带代币合约 address 过滤，与真实扫链一致）、全区块耗时。
func ProbeEndpoint(ctx context.Context, chainID int64, endpoint scan.Endpoint, tokenFilter []string, client *http.Client) EndpointProbe {
	result := EndpointProbe{Label: endpoint.Label, SpanTried: []int{}}
	pool := NewPool("probe", chainID, []scan.Endpoint{endpoint}, client, nil)
	started := time.Now()
	head, err := pool.BeginRound(ctx, 0)
	if err != nil {
		result.Error = err.Error()
		if health := pool.Health(); len(health) == 1 && health[0].Health == scan.HealthMismatch {
			result.Error = health[0].LastError
		}
		return result
	}
	result.ChainID = chainID
	result.HeadBlock = head
	result.LatencyMs = int(time.Since(started) / time.Millisecond)
	// 出块时间：head 与 head-100 的时间戳差
	if head > 100 {
		newer, errNew := probeHeader(ctx, pool, head)
		older, errOld := probeHeader(ctx, pool, head-100)
		if errNew == nil && errOld == nil && newer.Time.After(older.Time) {
			result.sampleSeconds = newer.Time.Sub(older.Time).Seconds() / 100
			result.BlockTimeMs = int(result.sampleSeconds * 1000)
		}
	}
	if raw, err := pool.Call(ctx, "eth_getCode", []any{multicall3, "latest"}); err == nil {
		var code string
		if json.Unmarshal(raw, &code) == nil && len(code) > 4 {
			result.Multicall3 = true
		}
	}
	for _, span := range probeSpans {
		if uint64(span) > head {
			break
		}
		result.SpanTried = append(result.SpanTried, span)
		filter := map[string]any{"fromBlock": hexBlock(head - uint64(span)), "toBlock": hexBlock(head - 1),
			"topics": []any{transferTopic, nil, []string{topicAddress("0x0000000000000000000000000000000000000001")}}}
		if len(tokenFilter) > 0 {
			filter["address"] = tokenFilter
		}
		if _, err := pool.Call(ctx, "eth_getLogs", []any{filter}); err != nil {
			if err == errSpanTooLarge {
				break
			}
			result.Error = "eth_getLogs: " + err.Error()
			return result
		}
		result.MaxLogSpan = span
	}
	if result.MaxLogSpan == 0 {
		result.Error = "endpoint rejects eth_getLogs even for 100 blocks"
		return result
	}
	blockStart := time.Now()
	if raw, err := pool.Call(ctx, "eth_getBlockByNumber", []any{hexBlock(head - 1), true}); err == nil {
		var block rpcBlock
		if json.Unmarshal(raw, &block) == nil {
			var txs []json.RawMessage
			_ = json.Unmarshal(block.Transactions, &txs)
			result.FullBlockTxs = len(txs)
		}
		result.FullBlockMs = int(time.Since(blockStart) / time.Millisecond)
	}
	result.OK = true
	result.SuggestedSpan = result.MaxLogSpan
	// 出块 ≥ 2s 且每天 ≤ 5 万块用 blocks 精确扫；更快的链用余额差
	if result.sampleSeconds >= 2 {
		result.SuggestedMode = string(scan.NativeModeBlocks)
	} else {
		result.SuggestedMode = string(scan.NativeModeBalance)
	}
	switch {
	case result.sampleSeconds >= 10:
		result.SuggestedConfs = 12
	case result.sampleSeconds >= 1:
		result.SuggestedConfs = 10
	default:
		result.SuggestedConfs = 5
	}
	return result
}

func probeHeader(ctx context.Context, pool *Pool, number uint64) (header, error) {
	raw, err := pool.Call(ctx, "eth_getBlockByNumber", []any{hexBlock(number), false})
	if err != nil {
		return header{}, err
	}
	var block rpcBlock
	if err := json.Unmarshal(raw, &block); err != nil || block.Hash == "" {
		return header{}, fmt.Errorf("block %d: malformed result", number)
	}
	return headerOf(block)
}
