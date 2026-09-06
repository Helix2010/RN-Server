package indexer

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/scan"
)

func TestTopicAddressRoundTrip(t *testing.T) {
	topic := topicAddress("0xAbCdEf0000000000000000000000000000000001")
	if len(topic) != 66 || !strings.HasPrefix(topic, "0x000000000000000000000000abcdef") {
		t.Fatalf("topic = %s", topic)
	}
	address, err := addressFromTopic(topic)
	if err != nil || address != "0xabcdef0000000000000000000000000000000001" {
		t.Fatalf("address=%s err=%v", address, err)
	}
	if _, err := addressFromTopic("0x" + strings.Repeat("ff", 32)); err == nil {
		t.Fatal("non-address topic must be rejected")
	}
}

func TestAggregate3EncodeDecodeRoundTrip(t *testing.T) {
	addresses := []string{alice, bob}
	data := encodeGetEthBalances(addresses)
	if !strings.HasPrefix(data, "0x"+selectorAggregate3) {
		t.Fatalf("selector missing: %s", data[:12])
	}
	// 头部：偏移 0x20、长度 2、两个元组偏移（64、64+6*32）
	payload := data[10:]
	if payload[:64] != word(0x20) || payload[64:128] != word(2) || payload[128:192] != word(64) || payload[192:256] != word(64+6*32) {
		t.Fatalf("head words wrong: %s", payload[:256])
	}
	decoded, err := decodeAggregate3Balances(encodeAggregate3Result([]string{word(1000), word(5)}), 2)
	if err != nil || decoded[0].Cmp(big.NewInt(1000)) != 0 || decoded[1].Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("decoded=%v err=%v", decoded, err)
	}
	if _, err := decodeAggregate3Balances(encodeAggregate3Result([]string{word(1)}), 2); err == nil {
		t.Fatal("count mismatch must be rejected")
	}
}

// TestAggregate3AgainstLiveMulticall3 打真实 OP Sepolia 节点核对 ABI 编码；只在
// INDEXER_LIVE_TEST=1 时跑（CI 没网也不该依赖公共节点）。
func TestAggregate3AgainstLiveMulticall3(t *testing.T) {
	if os.Getenv("INDEXER_LIVE_TEST") != "1" {
		t.Skip("set INDEXER_LIVE_TEST=1 to hit sepolia.optimism.io")
	}
	pool := NewPool("op-sepolia", 11155420, []scan.Endpoint{{URL: "https://sepolia.optimism.io", Label: "public", RPS: 2}}, http.DefaultClient, nil)
	head, err := pool.BeginRound(context.Background(), 0)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	addresses := []string{multicall3, "0x0000000000000000000000000000000000000001"}
	raw, err := pool.Call(context.Background(), "eth_call", []any{map[string]string{"to": multicall3, "data": encodeGetEthBalances(addresses)}, hexBlock(head - 5)})
	if err != nil {
		t.Fatalf("eth_call: %v", err)
	}
	var encoded string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		t.Fatalf("result: %v", err)
	}
	balances, err := decodeAggregate3Balances(encoded, len(addresses))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	single, err := pool.Call(context.Background(), "eth_getBalance", []any{addresses[1], hexBlock(head - 5)})
	if err != nil {
		t.Fatalf("eth_getBalance: %v", err)
	}
	expected, _ := hexQuantity(single)
	if balances[1].Cmp(expected) != 0 {
		t.Fatalf("multicall balance %s != eth_getBalance %s", balances[1], expected)
	}
	t.Logf("live check ok: head=%d balances=%v", head, balances)
}
