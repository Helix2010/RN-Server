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
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc", "eth", "base", "monad"}) {
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
	// 写入时已校验过类型，这里只保证类型断言不会 panic；没有任何有效配置 = 未配置，
	// 走声明式默认（全部主网）
	if !reflect.DeepEqual(wallet["chains"], []any{"bsc", "eth", "base", "monad"}) {
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

func TestNormalizeWalletLeavesTestnetsOutOfTheDefaults(t *testing.T) {
	// 加一条测试链不该让所有还没配过钱包的租户突然多出一条测试网
	wallet := normalizeWallet(nil)
	for _, item := range wallet["chains"].([]any) {
		if item == "op-sepolia" {
			t.Fatal("测试链不能进默认启用列表")
		}
	}
	if firstNetwork(wallet, "op-sepolia") != nil {
		t.Fatal("测试链不能出现在默认下发的 networks 里")
	}
}

func TestNormalizeWalletEnablesATestnetWhenAsked(t *testing.T) {
	wallet := normalizeWallet(map[string]any{"chains": []any{"bsc", "op-sepolia"}})
	network := firstNetwork(wallet, "op-sepolia")
	if network == nil {
		t.Fatal("显式勾选后测试链必须能启用")
	}
	if network["chainId"] != 11155420 {
		t.Fatalf("op-sepolia chainId = %v", network["chainId"])
	}
	if network["testnet"] != true {
		t.Fatalf("下发给 App 的 networks 要带 testnet 标记，got %v", network["testnet"])
	}
	// 主网不能被误标成测试网
	if firstNetwork(wallet, "bsc")["testnet"] != false {
		t.Fatal("bsc 不是测试网")
	}
}

func TestWalletCatalogMarksTestnets(t *testing.T) {
	// 管理端靠这个标记在界面上警示运营
	for _, item := range walletCatalog() {
		entry := item.(map[string]any)
		if entry["id"] != "op-sepolia" {
			continue
		}
		if entry["testnet"] != true {
			t.Fatal("目录里的 op-sepolia 必须标为测试网")
		}
		if entry["chainId"] != 11155420 {
			t.Fatalf("chainId = %v", entry["chainId"])
		}
		return
	}
	t.Fatal("目录里找不到 op-sepolia")
}

func TestValidateWalletSectionAcceptsTheTestnet(t *testing.T) {
	if err := validateWalletSection(map[string]any{
		"chains":   []any{"op-sepolia"},
		"networks": []any{map[string]any{"id": "op-sepolia", "chainId": float64(11155420)}},
	}); err != nil {
		t.Fatalf("测试链应当是合法配置: %v", err)
	}
}

func TestSupportedNetworkIDsListsEveryChain(t *testing.T) {
	// 报错文案里的链清单必须跟着目录走，不能写死
	ids := supportedNetworkIDs()
	for _, want := range []string{"bsc", "eth", "base", "op-sepolia"} {
		if !strings.Contains(ids, want) {
			t.Fatalf("%q 不在报错清单里: %s", want, ids)
		}
	}
}

func TestNormalizeWalletDeliversNothingWhenEveryConfiguredChainIsUnknown(t *testing.T) {
	// 目录下线了一条链，而某租户只勾了它：这是要迁移租户配置的事故，运行时不替它
	// 换成别的链——下发空列表，App 如实呈现"没有链"
	wallet := normalizeWallet(map[string]any{"chains": []any{"nope"}})
	if !reflect.DeepEqual(wallet["chains"], []any{}) {
		t.Fatalf("chains = %v, want an empty list", wallet["chains"])
	}
	if !reflect.DeepEqual(wallet["networks"], []any{}) {
		t.Fatalf("networks = %v, want an empty list", wallet["networks"])
	}
}

func TestIsHTTPSURLMatchesWhatTheAppWillAccept(t *testing.T) {
	// 服务端放过而 App 的 URL 解析拒绝的值，会让该租户所有设备的 bootstrap 失效
	// 大小写的 scheme 两端都接受（url.Parse 会归一化）；首尾空白会被 trim 掉
	accept := []string{"https://rpc.example", "https://rpc.example/v1?key=abc", "https://rpc.example:8545/", "HTTPS://rpc.example", " https://rpc.example\n"}
	reject := []string{
		"https://not a url",
		"https:///",
		"https:",
		"https://user:pass@rpc.example",
		"https://rpc.\nexample",
		"http://rpc.example",
		"",
		"https://" + strings.Repeat("a", maxEndpointLength),
	}
	for _, value := range accept {
		if !isHTTPSURL(value) {
			t.Errorf("should accept %q", value)
		}
	}
	for _, value := range reject {
		if isHTTPSURL(value) {
			t.Errorf("should reject %q", value)
		}
	}
}

func TestHTTPSListDropsDuplicatesAndCredentials(t *testing.T) {
	urls := httpsList([]any{
		"https://a.example",
		"https://a.example",
		"https://user:pw@b.example",
		" https://c.example ",
	})
	if !reflect.DeepEqual(urls, []any{"https://a.example", "https://c.example"}) {
		t.Fatalf("urls = %v", urls)
	}
}

func TestValidateWalletSectionCapsTheEndpointList(t *testing.T) {
	many := []any{}
	for i := 0; i < maxEndpointsPerChain+1; i++ {
		many = append(many, "https://rpc.example/"+strings.Repeat("x", i+1))
	}
	err := validateWalletSection(map[string]any{
		"networks": []any{map[string]any{"id": "bsc", "rpcUrls": many}},
	})
	if err == nil || !strings.Contains(err.Error(), "最多配置") {
		t.Fatalf("expected the endpoint cap to be enforced, got %v", err)
	}
}

func TestValidConfigRequiresSemverInTheUpdatePolicy(t *testing.T) {
	base := func(policy map[string]any) map[string]any {
		return map[string]any{
			"configVersion": "1", "ttlSeconds": float64(300),
			"localization": map[string]any{}, "theme": map[string]any{}, "features": map[string]any{},
			"updatePolicy": policy, "support": map[string]any{},
		}
	}
	if !validConfig(base(map[string]any{"minSupportedVersion": "1.0.0", "latestVersion": "1.2.0"})) {
		t.Fatal("a semver policy should be valid")
	}
	// 非法版本号会让 compareVersion 当成 1.0.0，强制升级静默失效
	if validConfig(base(map[string]any{"minSupportedVersion": "abc", "latestVersion": "1.2.0"})) {
		t.Fatal("a garbage minimum version must be rejected")
	}
	if validConfig(base(map[string]any{"minSupportedVersion": "1.0.0", "latestVersion": ""})) {
		t.Fatal("an empty latest version must be rejected")
	}
}

func TestNormalizeWalletKeepsOnchainSendsOffUnlessTheTenantOptedIn(t *testing.T) {
	// 没配过端点的租户也会拿到平台默认端点，所以"有端点"不能当开关：
	// 转出是否真的上链必须是一个显式的、默认关的布尔
	if normalizeWallet(nil)["onchainSends"] != false {
		t.Fatal("onchainSends must default to false")
	}
	if normalizeWallet(map[string]any{"onchainSends": true})["onchainSends"] != true {
		t.Fatal("an explicit opt-in must be delivered")
	}
	if normalizeWallet(map[string]any{"onchainSends": "yes"})["onchainSends"] != false {
		t.Fatal("a non-boolean must not switch real sends on")
	}
	if err := validateWalletSection(map[string]any{"onchainSends": "yes"}); err == nil {
		t.Fatal("validation must reject a non-boolean onchainSends")
	}
	if err := validateWalletSection(map[string]any{"onchainSends": true}); err != nil {
		t.Fatalf("a boolean onchainSends must validate, got %v", err)
	}
}
