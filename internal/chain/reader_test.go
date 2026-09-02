package chain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNode 模拟一个 JSON-RPC 节点：按方法与 selector 返回预设值。
type fakeNode struct {
	chainID string
	code    string
	calls   map[string]string // selector → 十六进制返回值；缺失即 revert
	delay   time.Duration
	status  int
	rawBody string // 非空时原样返回，用来模拟坏响应
	hits    atomic.Int32
}

func (n *fakeNode) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n.hits.Add(1)
		if n.delay > 0 {
			time.Sleep(n.delay)
		}
		if n.status != 0 {
			w.WriteHeader(n.status)
			return
		}
		if n.rawBody != "" {
			_, _ = w.Write([]byte(n.rawBody))
			return
		}
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		reply := func(result any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
		}
		switch request.Method {
		case "eth_chainId":
			reply(n.chainID)
		case "eth_getCode":
			reply(n.code)
		case "eth_call":
			var call struct {
				Data string `json:"data"`
			}
			_ = json.Unmarshal(request.Params[0], &call)
			if result, ok := n.calls[call.Data]; ok {
				reply(result)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32000, "message": "execution reverted"}})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}
}

func abiString(value string) string {
	data := []byte(value)
	padded := make([]byte, ((len(data)+31)/32)*32)
	copy(padded, data)
	return "0x" + word(32) + word(len(data)) + hex.EncodeToString(padded)
}

func bytes32(value string) string {
	buf := make([]byte, 32)
	copy(buf, value)
	return "0x" + hex.EncodeToString(buf)
}

func word(value int) string { return fmt.Sprintf("%064x", value) }

func uintWord(value int) string { return "0x" + word(value) }

func usdcNode() *fakeNode {
	return &fakeNode{
		chainID: "0x1",
		code:    "0x6080604052",
		calls: map[string]string{
			selectorSymbol:   abiString("USDC"),
			selectorName:     abiString("USD Coin"),
			selectorDecimals: uintWord(6),
		},
	}
}

func readWith(t *testing.T, node *fakeNode, chainID int) (Metadata, error) {
	t.Helper()
	server := httptest.NewServer(node.handler())
	t.Cleanup(server.Close)
	reader := NewReader(server.Client())
	return reader.ReadToken(context.Background(), Network{ID: "test", ChainID: chainID, Endpoints: []string{server.URL}}, "0x0000000000000000000000000000000000000001")
}

func expectKind(t *testing.T, err error, want Kind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %v, got nil error", want)
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("expected *chain.Error, got %T: %v", err, err)
	}
	if typed.Kind != want {
		t.Fatalf("kind = %v, want %v (%v)", typed.Kind, want, err)
	}
}

func TestReadTokenDecodesAbiStrings(t *testing.T) {
	meta, err := readWith(t, usdcNode(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Symbol != "USDC" || meta.Name != "USD Coin" || meta.Decimals != 6 {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestReadTokenDecodesBytes32Symbols(t *testing.T) {
	// MKR 这类老合约把 symbol/name 存成 bytes32，按 ABI string 解会读到垃圾
	node := usdcNode()
	node.calls[selectorSymbol] = bytes32("MKR")
	node.calls[selectorName] = bytes32("Maker")
	node.calls[selectorDecimals] = uintWord(18)
	meta, err := readWith(t, node, 1)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Symbol != "MKR" || meta.Name != "Maker" || meta.Decimals != 18 {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestReadTokenRejectsAnEndpointOnTheWrongChain(t *testing.T) {
	node := usdcNode()
	node.chainID = "0x38"
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindChainMismatch)
	// 链不符是确定性结论，不该再去读代码和元数据
	if node.hits.Load() != 1 {
		t.Fatalf("expected exactly one call, got %d", node.hits.Load())
	}
}

func TestReadTokenRejectsAnExternallyOwnedAccount(t *testing.T) {
	node := usdcNode()
	node.code = "0x"
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindNotAContract)
}

func TestReadTokenRejectsOversizedResponses(t *testing.T) {
	node := usdcNode()
	// 一个合法 JSON 但远超 64KB 的返回：不能因为节点想撑爆内存就照单全收
	node.calls[selectorSymbol] = "0x" + strings.Repeat("00", MaxResponseBytes)
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindUnavailable)
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error should mention the size cap: %v", err)
	}
}

func TestReadTokenTimesOut(t *testing.T) {
	node := usdcNode()
	node.delay = 300 * time.Millisecond
	server := httptest.NewServer(node.handler())
	t.Cleanup(server.Close)
	reader := NewReader(server.Client())
	reader.CallTimeout = 30 * time.Millisecond
	started := time.Now()
	_, err := reader.ReadToken(context.Background(), Network{ID: "test", ChainID: 1, Endpoints: []string{server.URL}}, "0x0000000000000000000000000000000000000001")
	expectKind(t, err, KindUnavailable)
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("timeout must cut the call short, not wait for the node")
	}
}

func TestReadTokenRejectsDecimalsOutOfRange(t *testing.T) {
	node := usdcNode()
	node.calls[selectorDecimals] = uintWord(37)
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
	node.calls[selectorDecimals] = "0x" + strings.Repeat("ff", 32)
	_, err = readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
	node.calls[selectorDecimals] = uintWord(36)
	if meta, err := readWith(t, node, 1); err != nil || meta.Decimals != 36 {
		t.Fatalf("36 is the inclusive upper bound: %+v %v", meta, err)
	}
}

func TestReadTokenRejectsUnprintableSymbols(t *testing.T) {
	node := usdcNode()
	// 零宽字符是仿冒符号的常用手法
	node.calls[selectorSymbol] = abiString("USD​T")
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
	node.calls[selectorSymbol] = abiString("  USDT ")
	meta, err := readWith(t, node, 1)
	if err != nil || meta.Symbol != "USDT" {
		t.Fatalf("surrounding whitespace should be trimmed: %+v %v", meta, err)
	}
	node.calls[selectorSymbol] = abiString(strings.Repeat("A", MaxSymbolLength+1))
	_, err = readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
	node.calls[selectorSymbol] = abiString("")
	_, err = readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
}

func TestReadTokenTreatsARevertingSymbolAsInvalidMetadata(t *testing.T) {
	node := usdcNode()
	delete(node.calls, selectorSymbol)
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindMetadataInvalid)
}

func TestReadTokenToleratesAMissingName(t *testing.T) {
	// 没有 name() 的合约仍然可以是合法代币；名字留空由运营补
	node := usdcNode()
	delete(node.calls, selectorName)
	meta, err := readWith(t, node, 1)
	if err != nil || meta.Name != "" || meta.Symbol != "USDC" {
		t.Fatalf("meta = %+v err = %v", meta, err)
	}
}

func TestReadTokenFailsOverOnlyWhenTheNodeIsDown(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	t.Cleanup(down.Close)
	up := httptest.NewServer(usdcNode().handler())
	t.Cleanup(up.Close)
	reader := NewReader(nil)
	meta, err := reader.ReadToken(context.Background(), Network{ID: "test", ChainID: 1, Endpoints: []string{down.URL, up.URL}}, "0x0000000000000000000000000000000000000001")
	if err != nil || meta.Symbol != "USDC" {
		t.Fatalf("second endpoint should have answered: %+v %v", meta, err)
	}
	if _, err := reader.ReadToken(context.Background(), Network{ID: "test", ChainID: 1}, "0x01"); KindOf(err) != KindUnavailable {
		t.Fatalf("a network without endpoints must be unavailable, got %v", err)
	}
}

func TestReadTokenRejectsMalformedResponses(t *testing.T) {
	node := &fakeNode{rawBody: "<html>not json</html>"}
	_, err := readWith(t, node, 1)
	expectKind(t, err, KindUnavailable)
}

func TestDecodeTextRejectsTruncatedAbiStrings(t *testing.T) {
	// 只有一个偏移词、没有内容：不是 bytes32，而是被截断的 ABI string
	if _, err := decodeText(mustHex(word(32))); err == nil {
		t.Fatal("a dangling ABI head must not decode as bytes32")
	}
	if _, err := decodeText(mustHex(word(32) + word(1000))); err == nil {
		t.Fatal("a length past the end of the data must be rejected")
	}
	if _, err := decodeText([]byte{1, 2, 3}); err == nil {
		t.Fatal("odd lengths are not a known encoding")
	}
	if _, err := decodeText(nil); err == nil {
		t.Fatal("empty return data means the function does not exist")
	}
}

func TestSanitizeTextKeepsUnicodeLettersButNotSymbols(t *testing.T) {
	cases := map[string]bool{"泰达币": true, "Tether USD": true, "USD-C.v2 (PoS)": true, "🚀 Rocket": false, "tab\tbed": false, "nul\x00": false}
	for input, ok := range cases {
		_, err := SanitizeText(input, MaxNameLength)
		if (err == nil) != ok {
			t.Errorf("SanitizeText(%q) err=%v, want ok=%v", input, err, ok)
		}
	}
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
