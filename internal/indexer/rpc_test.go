package indexer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/scan"
)

func TestPoolSkipsMismatchedChainAndPrefersHealthyEndpointInOrder(t *testing.T) {
	wrong := newFakeChain(1)
	wrong.mine(1)
	right := newFakeChain(11155420)
	right.mine(5)
	wrongServer, rightServer := wrong.server(), right.server()
	defer wrongServer.Close()
	defer rightServer.Close()
	pool := NewPool("op-sepolia", 11155420, []scan.Endpoint{{URL: wrongServer.URL, Label: "wrong", RPS: 100}, {URL: rightServer.URL, Label: "right", RPS: 100}}, http.DefaultClient, nil)
	head, err := pool.BeginRound(context.Background(), 0)
	if err != nil || head != 5 {
		t.Fatalf("head=%d err=%v", head, err)
	}
	health := pool.Health()
	if health[0].Health != scan.HealthMismatch || health[1].Health != scan.HealthHealthy {
		t.Fatalf("health = %+v", health)
	}
	if pool.Current() != "right" {
		t.Fatalf("current = %s", pool.Current())
	}
}

func TestPoolCoolsDownAfterConsecutiveFailuresAndRecovers(t *testing.T) {
	chain := newFakeChain(11155420)
	chain.mine(1)
	server := chain.server()
	defer server.Close()
	clock := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	pool := NewPool("op-sepolia", 11155420, []scan.Endpoint{{URL: server.URL, Label: "only", RPS: 100}}, http.DefaultClient, now)
	if _, err := pool.BeginRound(context.Background(), 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	chain.mu.Lock()
	chain.fail = true
	chain.mu.Unlock()
	for attempt := 0; attempt < failuresBeforeCooling; attempt++ {
		if _, err := pool.Call(context.Background(), "eth_blockNumber", nil); err == nil {
			t.Fatal("expected failure")
		}
	}
	health := pool.Health()[0]
	if health.Health != scan.HealthCooling || health.CoolingUntil == nil || !health.CoolingUntil.Equal(clock.Add(coolingBase)) {
		t.Fatalf("health = %+v", health)
	}
	if _, err := pool.BeginRound(context.Background(), 0); err == nil {
		t.Fatal("cooling endpoint must not be selected")
	}
	// 冷却到期 + 节点恢复 → 探活通过 → healthy
	clock = clock.Add(coolingBase + time.Second)
	chain.mu.Lock()
	chain.fail = false
	chain.mu.Unlock()
	if _, err := pool.BeginRound(context.Background(), 0); err != nil {
		t.Fatalf("begin after cooling: %v", err)
	}
	if health := pool.Health()[0]; health.Health != scan.HealthHealthy || health.ConsecutiveFailures != 0 {
		t.Fatalf("health after recovery = %+v", health)
	}
}

func TestPoolSkipsEndpointBehindCursor(t *testing.T) {
	behind := newFakeChain(11155420)
	behind.mine(3)
	ahead := newFakeChain(11155420)
	ahead.mine(50)
	behindServer, aheadServer := behind.server(), ahead.server()
	defer behindServer.Close()
	defer aheadServer.Close()
	pool := NewPool("op-sepolia", 11155420, []scan.Endpoint{{URL: behindServer.URL, Label: "behind", RPS: 100}, {URL: aheadServer.URL, Label: "ahead", RPS: 100}}, http.DefaultClient, nil)
	head, err := pool.BeginRound(context.Background(), 20)
	if err != nil || head != 50 || pool.Current() != "ahead" {
		t.Fatalf("head=%d current=%s err=%v", head, pool.Current(), err)
	}
	if health := pool.Health()[0]; health.ConsecutiveFailures != 0 || health.LastError == "" {
		t.Fatalf("behind endpoint must be noted without counting a failure: %+v", health)
	}
}

func TestPoolReportsSpanErrorsWithoutCountingFailure(t *testing.T) {
	chain := newFakeChain(11155420)
	chain.mine(100)
	chain.maxSpan = 10
	server := chain.server()
	defer server.Close()
	pool := NewPool("op-sepolia", 11155420, []scan.Endpoint{{URL: server.URL, Label: "only", RPS: 100}}, http.DefaultClient, nil)
	if _, err := pool.BeginRound(context.Background(), 0); err != nil {
		t.Fatalf("begin: %v", err)
	}
	_, err := pool.Call(context.Background(), "eth_getLogs", []any{map[string]any{"fromBlock": "0x1", "toBlock": "0x64", "topics": []any{}}})
	if err != errSpanTooLarge {
		t.Fatalf("err = %v", err)
	}
	if health := pool.Health()[0]; health.SpanRejected != 1 || health.ConsecutiveFailures != 0 || health.Health != scan.HealthHealthy {
		t.Fatalf("health = %+v", health)
	}
}

func TestIsSpanErrorMatchesKnownNodeMessages(t *testing.T) {
	cases := []rpcError{{Code: -32614, Message: "eth_getLogs is limited to a 100 block range"}, {Code: -32000, Message: "Block range is too large"}, {Code: -32005, Message: "limit exceeded"}, {Code: -32005, Message: "query returned more than 10000 results"}}
	for _, item := range cases {
		err := &item
		if !isSpanError(err) {
			t.Fatalf("%v not recognised as span error", err)
		}
	}
	if isSpanError(&rpcError{Code: -32601, Message: "method not found"}) {
		t.Fatal("method not found is not a span error")
	}
}

func TestTokenBucketWaitsForTokens(t *testing.T) {
	clock := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	bucket := newTokenBucket(2, func() time.Time { return clock })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for index := 0; index < 2; index++ {
		if err := bucket.wait(ctx); err != nil {
			t.Fatalf("token %d: %v", index, err)
		}
	}
	// 第三个令牌要等（时钟不动，只能等 ctx 超时）
	if err := bucket.wait(ctx); err == nil {
		t.Fatal("expected to block on an empty bucket")
	}
	clock = clock.Add(time.Second)
	if err := bucket.wait(context.Background()); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}
