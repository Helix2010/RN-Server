package api

import (
	"reflect"
	"testing"
)

func firstNetwork(wallet map[string]any, id string) map[string]any {
	for _, item := range wallet["networks"].([]any) {
		network := item.(map[string]any)
		if network["id"] == id {
			return network
		}
	}
	return nil
}

func TestNormalizeWalletDefaultsToEveryNetwork(t *testing.T) {
	wallet := normalizeWallet(nil)
	if wallet["walletConnectProjectId"] != "" {
		t.Fatalf("project id should default to empty, got %v", wallet["walletConnectProjectId"])
	}
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc", "eth", "base"}) {
		t.Fatalf("chains = %v", wallet["chains"])
	}
	bsc := firstNetwork(wallet, "bsc")
	if bsc["chainId"] != 56 {
		t.Fatalf("bsc chainId = %v", bsc["chainId"])
	}
	if bsc["explorerUrl"] != "https://bscscan.com" {
		t.Fatalf("bsc explorer = %v", bsc["explorerUrl"])
	}
	if len(bsc["rpcUrls"].([]any)) == 0 {
		t.Fatal("bsc should ship a default rpc endpoint")
	}
}

func TestNormalizeWalletKeepsOnlyEnabledChains(t *testing.T) {
	wallet := normalizeWallet(map[string]any{"chains": []any{"base", "nope"}})
	if !reflect.DeepEqual(wallet["chains"], []any{"base"}) {
		t.Fatalf("chains = %v", wallet["chains"])
	}
	if len(wallet["networks"].([]any)) != 1 {
		t.Fatalf("networks = %v", wallet["networks"])
	}
	if firstNetwork(wallet, "base")["chainId"] != 8453 {
		t.Fatal("base chainId should come from the platform catalog")
	}
}

func TestNormalizeWalletAppliesTenantEndpointOverrides(t *testing.T) {
	wallet := normalizeWallet(map[string]any{
		"networks": []any{
			map[string]any{
				"id":          "bsc",
				"rpcUrls":     []any{"https://rpc.tenant.example/bsc"},
				"explorerUrl": "https://explorer.tenant.example/",
			},
		},
	})
	// networks 里出现即视为启用，不必在 chains 里重复一遍
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc"}) {
		t.Fatalf("chains = %v", wallet["chains"])
	}
	bsc := firstNetwork(wallet, "bsc")
	if !reflect.DeepEqual(bsc["rpcUrls"], []any{"https://rpc.tenant.example/bsc"}) {
		t.Fatalf("rpcUrls = %v", bsc["rpcUrls"])
	}
	// 末尾斜杠会让拼出来的地址变成双斜杠
	if bsc["explorerUrl"] != "https://explorer.tenant.example" {
		t.Fatalf("explorerUrl = %v", bsc["explorerUrl"])
	}
	// 平台目录里的 chainId 不允许被租户改写
	if bsc["chainId"] != 56 {
		t.Fatalf("chainId = %v", bsc["chainId"])
	}
}

func TestNormalizeWalletRejectsCleartextEndpoints(t *testing.T) {
	wallet := normalizeWallet(map[string]any{
		"networks": []any{
			map[string]any{
				"id":          "eth",
				"rpcUrls":     []any{"http://rpc.tenant.example", "not a url", ""},
				"explorerUrl": "http://explorer.tenant.example",
			},
		},
	})
	eth := firstNetwork(wallet, "eth")
	// 明文 RPC 会泄露用户查询的每个地址和余额，必须回退到默认值
	if !reflect.DeepEqual(eth["rpcUrls"], []any{"https://ethereum-rpc.publicnode.com"}) {
		t.Fatalf("rpcUrls = %v", eth["rpcUrls"])
	}
	if eth["explorerUrl"] != "https://etherscan.io" {
		t.Fatalf("explorerUrl = %v", eth["explorerUrl"])
	}
}

func TestNormalizeWalletKeepsTheProjectID(t *testing.T) {
	wallet := normalizeWallet(map[string]any{
		"walletConnectProjectId": "  abc123  ",
	})
	if wallet["walletConnectProjectId"] != "abc123" {
		t.Fatalf("project id = %q", wallet["walletConnectProjectId"])
	}
}

func TestNormalizeWalletIgnoresGarbage(t *testing.T) {
	wallet := normalizeWallet(map[string]any{
		"chains":   "not-a-list",
		"networks": []any{"not-an-object", nil, map[string]any{"id": 42}},
	})
	// 配置坏掉时回退到全部支持的链，而不是返回空列表让 App 没链可用
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc", "eth", "base"}) {
		t.Fatalf("chains = %v", wallet["chains"])
	}
}
