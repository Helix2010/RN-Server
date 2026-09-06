package indexer

import (
	"context"
	"net/http"
	"testing"

	"github.com/Helix2010/RN-Server/internal/scan"
)

func TestProbeEndpointReportsSpanAndSuggestions(t *testing.T) {
	chain := newFakeChain(11155420)
	chain.maxSpan = 1000
	for number := uint64(1); number <= 12000; number++ {
		chain.mine(number)
	}
	server := chain.server()
	defer server.Close()
	result := ProbeEndpoint(context.Background(), 11155420, scan.Endpoint{URL: server.URL, Label: "fake", RPS: 1000}, []string{tokenUSDC}, http.DefaultClient)
	if !result.OK || result.MaxLogSpan != 1000 || result.HeadBlock != 12000 {
		t.Fatalf("result = %+v", result)
	}
	// 假链每块 2 秒 → blocks 模式、10 个确认
	if result.SuggestedMode != "blocks" || result.SuggestedConfs != 10 || result.BlockTimeMs != 2000 {
		t.Fatalf("suggestions = %+v", result)
	}
	if len(result.SpanTried) != 4 { // 100, 500, 1000, 2000(拒)
		t.Fatalf("span tried = %v", result.SpanTried)
	}
}

func TestProbeEndpointFlagsChainMismatch(t *testing.T) {
	chain := newFakeChain(1)
	chain.mine(1)
	server := chain.server()
	defer server.Close()
	result := ProbeEndpoint(context.Background(), 11155420, scan.Endpoint{URL: server.URL, Label: "wrong", RPS: 10}, nil, http.DefaultClient)
	if result.OK || result.Error == "" {
		t.Fatalf("result = %+v", result)
	}
}
