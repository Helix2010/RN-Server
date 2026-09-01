package api

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
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

func TestWalletCatalogCoversEverySupportedNetwork(t *testing.T) {
	catalog := walletCatalog()
	if len(catalog) != len(supportedNetworks) {
		t.Fatalf("catalog should list every supported network, got %d", len(catalog))
	}
	first := catalog[0].(map[string]any)
	// 管理端要靠这几个字段渲染"平台默认"，缺一个就得自己抄一份链表
	for _, key := range []string{"id", "name", "chainId", "defaultRpcUrls", "defaultExplorerUrl"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("catalog entry missing %q: %v", key, first)
		}
	}
	if first["chainId"] != 56 {
		t.Fatalf("bsc chainId = %v", first["chainId"])
	}
}

func TestValidateWalletSectionAcceptsAConfiguredTenant(t *testing.T) {
	err := validateWalletSection(map[string]any{
		"walletConnectProjectId": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
		"chains":                 []any{"bsc", "base"},
		"networks": []any{
			map[string]any{
				"id":          "bsc",
				"chainId":     float64(56),
				"rpcUrls":     []any{"https://rpc.tenant.example/bsc"},
				"explorerUrl": "https://explorer.tenant.example",
			},
		},
	})
	if err != nil {
		t.Fatalf("valid section rejected: %v", err)
	}
}

func TestValidateWalletSectionRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{"不是对象", []any{"bsc"}, "wallet 必须是一个对象"},
		{"未知字段", map[string]any{"projectId": "x"}, "wallet.projectId 不是可配置项"},
		{"projectId 填了链接", map[string]any{"walletConnectProjectId": "https://cloud.reown.com/app/abc"}, "格式不对"},
		{"projectId 太短", map[string]any{"walletConnectProjectId": "abc"}, "格式不对"},
		{"一条链都不启用", map[string]any{"chains": []any{}}, "至少要启用一条链"},
		{"不支持的链", map[string]any{"chains": []any{"solana"}}, `不支持的链 "solana"`},
		{"改写 chainId", map[string]any{"networks": []any{map[string]any{"id": "bsc", "chainId": float64(1)}}}, "chainId 固定为 56"},
		{"明文 RPC", map[string]any{"networks": []any{map[string]any{"id": "eth", "rpcUrls": []any{"http://rpc.example"}}}}, "必须是 https://"},
		{"浏览器地址不是 URL", map[string]any{"networks": []any{map[string]any{"id": "eth", "explorerUrl": "etherscan.io"}}}, "区块浏览器地址必须是 https://"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := validateWalletSection(testCase.raw)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), testCase.want)
			}
		})
	}
}

func TestValidateWalletSectionAllowsClearingTheProjectID(t *testing.T) {
	// 清空 projectId 是合法操作：租户可以先关掉外部钱包入口
	if err := validateWalletSection(map[string]any{"walletConnectProjectId": "  "}); err != nil {
		t.Fatalf("empty project id rejected: %v", err)
	}
}

func TestStoredWalletSectionCarriesTheSavedValue(t *testing.T) {
	stored := []byte(`{"configVersion":"1","wallet":{"walletConnectProjectId":"abc123abc123abc1","chains":["bsc"]}}`)
	carried := object(storedWalletSection(stored))
	if carried == nil || carried["walletConnectProjectId"] != "abc123abc123abc1" {
		t.Fatalf("carried = %v", carried)
	}
	if storedWalletSection(nil) != nil {
		t.Fatal("no stored config should carry nothing")
	}
	if storedWalletSection([]byte(`{"configVersion":"1"}`)) != nil {
		t.Fatal("a config without a wallet section should carry nothing")
	}
	if storedWalletSection([]byte(`not json`)) != nil {
		t.Fatal("unparsable config should carry nothing")
	}
}

func TestConfigSummaryReportsWalletReadiness(t *testing.T) {
	summary := configSummary(map[string]any{
		"localization": map[string]any{},
		"theme":        map[string]any{},
		"features":     map[string]any{},
		"wallet":       normalizeWallet(map[string]any{"walletConnectProjectId": "a1b2c3d4e5f60718", "chains": []any{"bsc"}}),
	})
	wallet := summary["wallet"].(gin.H)
	if wallet["walletConnectConfigured"] != true {
		t.Fatalf("wallet summary = %v", wallet)
	}
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc"}) {
		t.Fatalf("chains = %v", wallet["chains"])
	}
	// 没填 projectId 时要如实报告未配置：管理端靠这个提示"外部钱包入口不可用"
	blank := configSummary(map[string]any{
		"localization": map[string]any{}, "theme": map[string]any{}, "features": map[string]any{},
		"wallet": normalizeWallet(nil),
	})
	if blank["wallet"].(gin.H)["walletConnectConfigured"] != false {
		t.Fatal("blank project id should report not configured")
	}
}
