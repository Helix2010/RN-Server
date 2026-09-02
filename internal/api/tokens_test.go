package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/chain"
	"github.com/Helix2010/RN-Server/internal/store"
	"github.com/gin-gonic/gin"
)

// ---- 目录与配置视图 ----

func TestWalletCatalogCarriesTheNativeCurrency(t *testing.T) {
	want := map[string]string{"bsc": "BNB", "eth": "ETH", "base": "ETH", "op-sepolia": "ETH", "monad": "MON"}
	seen := map[string]bool{}
	for _, item := range walletCatalog() {
		entry := item.(map[string]any)
		id := entry["id"].(string)
		seen[id] = true
		// 原生币没有合约读不了链，管理端只能靠目录里这两项显示原生币行
		if entry["nativeSymbol"] != want[id] || entry["nativeDecimals"] != 18 {
			t.Errorf("%s native = %v/%v", id, entry["nativeSymbol"], entry["nativeDecimals"])
		}
	}
	if len(seen) != 5 {
		t.Fatalf("catalog = %v", seen)
	}
}

func TestChainTokenSeedNativeRowsMatchTheCatalog(t *testing.T) {
	// 预置的原生币行与链目录是同一件事的两份描述，必须一致
	for _, network := range supportedNetworks {
		found := false
		for _, row := range store.ChainTokenSeed {
			if row.Chain != network.ID || row.Address != nativeTokenAddress {
				continue
			}
			found = true
			if row.Symbol != network.NativeSymbol || row.Decimals != network.NativeDecimals {
				t.Errorf("%s: seed %s/%d, catalog %s/%d", network.ID, row.Symbol, row.Decimals, network.NativeSymbol, network.NativeDecimals)
			}
		}
		if !found {
			t.Errorf("%s has no native seed row", network.ID)
		}
	}
}

func TestValidateWalletSectionRejectsTokens(t *testing.T) {
	// tokens 不是通过配置 PATCH 写的，管理端把它带回来就是走错了路
	err := validateWalletSection(map[string]any{"tokens": []any{}})
	if err == nil || !strings.Contains(err.Error(), "wallet.tokens 不是可配置项") {
		t.Fatalf("err = %v", err)
	}
}

func TestNormalizeWalletNeverCarriesTokens(t *testing.T) {
	// 管理端的配置视图不带 tokens：就算库里的 wallet 段混进了 tokens 也要丢掉
	wallet := normalizeWallet(map[string]any{"chains": []any{"bsc"}, "tokens": []any{map[string]any{"symbol": "X"}}})
	if _, present := wallet["tokens"]; present {
		t.Fatal("config view must not carry tokens")
	}
}

// ---- 合并视图 ----

func seedRecord(id int64, tenant, chainID, address, symbol string, decimals, sortWeight int, enabled bool) tokenRecord {
	return tokenRecord{ID: id, TenantID: tenant, Chain: chainID, Address: address, Symbol: symbol, Name: symbol, Decimals: decimals, DisplayDecimals: 2, LogoColor: "#26A17B", SortWeight: sortWeight, Enabled: enabled, UpdatedAt: time.Unix(0, 0)}
}

const (
	bscUSDT = "0x55d398326f99059fF775485246999027B3197955"
	bscUSDC = "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"
)

func TestMergeTokenRecordsPrefersTenantRowsAndSorts(t *testing.T) {
	rows := []tokenRecord{
		seedRecord(1, "0", "bsc", "native", "BNB", 18, 1000, true),
		seedRecord(2, "0", "bsc", bscUSDT, "USDT", 18, 900, true),
		seedRecord(3, "0", "bsc", bscUSDC, "USDC", 18, 800, true),
		// 租户停用了 USDT：覆盖行地址大小写不同也要认出是同一个币
		seedRecord(10, "100000001", "bsc", strings.ToLower(bscUSDT), "USDT", 18, 900, false),
		// 租户自己的币，权重和 USDC 一样，按 symbol 排在它前面
		seedRecord(11, "100000001", "bsc", "0x0000000000000000000000000000000000000AAA", "CAKE", 18, 800, true),
		// 已软删除的行不参与合并
		{ID: 12, TenantID: "100000001", Chain: "bsc", Address: "0x0000000000000000000000000000000000000BBB", Symbol: "DEAD", Deleted: true},
	}
	// 全局行排在租户行后面也不能改变"租户行覆盖全局行"的结果
	rows = append(rows, seedRecord(4, "0", "bsc", "0x0000000000000000000000000000000000000AAA", "CAKE", 18, 1, true))
	merged := mergeTokenRecords(rows)
	got := []string{}
	for _, row := range merged {
		got = append(got, row.Symbol+"@"+row.scope())
	}
	want := []string{"BNB@global", "USDT@tenant", "CAKE@tenant", "USDC@global"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}
	if merged[1].ID != 10 || merged[1].Enabled {
		t.Fatalf("USDT should be the tenant override: %+v", merged[1])
	}
}

func TestBootstrapTokensFiltersAndShapes(t *testing.T) {
	merged := mergeTokenRecords([]tokenRecord{
		seedRecord(1, "0", "bsc", "native", "BNB", 18, 1000, true),
		seedRecord(2, "0", "bsc", bscUSDT, "USDT", 18, 900, true),
		seedRecord(3, "0", "bsc", bscUSDC, "USDC", 18, 800, false),
		seedRecord(4, "0", "eth", "native", "ETH", 18, 1000, true),
	})
	items := bootstrapTokens(merged, []any{"bsc", 42})
	if len(items) != 2 {
		t.Fatalf("items = %v", items)
	}
	first := items[0].(gin.H)
	keys := []string{}
	for key := range first {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if !reflect.DeepEqual(keys, []string{"address", "chain", "decimals", "displayDecimals", "logoColor", "name", "symbol"}) {
		t.Fatalf("bootstrap token keys = %v", keys)
	}
	// 读路径原样下发，不再截断
	if first["symbol"] != "BNB" || first["displayDecimals"] != 2 {
		t.Fatalf("first = %v", first)
	}
	if items[1].(gin.H)["symbol"] != "USDT" {
		t.Fatalf("second = %v", items[1])
	}
	if len(bootstrapTokens(merged, nil)) != 0 {
		t.Fatal("no enabled chains means no tokens")
	}
}

func TestTokenViewFollowsTheContract(t *testing.T) {
	view := tokenView(seedRecord(2, "0", "bsc", bscUSDT, "USDT", 18, 900, true))
	keys := []string{}
	for key := range view {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"address", "allowlisted", "chain", "decimals", "displayDecimals", "enabled", "id", "logoColor", "metadataSyncedAt", "name", "scope", "sortWeight", "symbol", "updatedAt"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("token keys = %v", keys)
	}
	if view["scope"] != "global" || view["allowlisted"] != true || view["metadataSyncedAt"] != nil {
		t.Fatalf("view = %v", view)
	}
	if _, present := view["verified"]; present {
		t.Fatal("verified must never come from the server")
	}
	tenant := tokenView(seedRecord(9, "100000001", "bsc", "0x0000000000000000000000000000000000000AAA", "CAKE", 18, 1, true))
	if tenant["scope"] != "tenant" || tenant["allowlisted"] != false {
		t.Fatalf("tenant view = %v", tenant)
	}
}

func TestTokenAllowlistMatchesTheAppTable(t *testing.T) {
	// 与 RN-App src/core/wallet/config/token-allowlist.ts 一致的五个地址（那边是小写）
	listed := map[string]string{
		"bsc":  "0x55d398326f99059ff775485246999027b3197955,0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
		"eth":  "0xdac17f958d2ee523a2206206994597c13d831ec7,0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		"base": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
	}
	count := 0
	for chainID, addresses := range listed {
		for _, address := range strings.Split(addresses, ",") {
			count++
			if !tokenAllowlisted(chainID, address) || !tokenAllowlisted(chainID, strings.ToUpper(address)) {
				t.Errorf("%s %s should be allowlisted regardless of case", chainID, address)
			}
		}
	}
	if count != len(allowlistedTokens) || count != 5 {
		t.Fatalf("allowlist has %d entries, test covers %d", len(allowlistedTokens), count)
	}
	if !tokenAllowlisted("op-sepolia", nativeTokenAddress) {
		t.Fatal("native coins are verified by the app without an address")
	}
	if tokenAllowlisted("eth", "0x55d398326f99059ff775485246999027b3197955") {
		t.Fatal("the allowlist is per chain: BSC USDT is not Ethereum USDT")
	}
}

// ---- 校验 ----

func TestNormalizeTokenAddress(t *testing.T) {
	if got, err := normalizeTokenAddress(" " + strings.ToLower(bscUSDT) + " "); err != nil || got != bscUSDT {
		t.Fatalf("lowercase should checksum: %q %v", got, err)
	}
	if got, err := normalizeTokenAddress("0x" + strings.ToUpper(bscUSDT[2:])); err != nil || got != bscUSDT {
		t.Fatalf("uppercase should checksum: %q %v", got, err)
	}
	if got, err := normalizeTokenAddress(bscUSDT); err != nil || got != bscUSDT {
		t.Fatalf("a valid checksum should pass through: %q %v", got, err)
	}
	// 混合大小写但校验和不对：抄错了大小写，不能静默"修正"
	wrong := strings.Replace(bscUSDT, "fF", "ff", 1)
	if _, err := normalizeTokenAddress(wrong); err == nil {
		t.Fatal("a wrong checksum must be rejected")
	}
	for _, bad := range []string{"native", "", "0x1234", bscUSDT + "0", "55d398326f99059fF775485246999027B3197955"} {
		if _, err := normalizeTokenAddress(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestCheckTokenPatchFieldsSeparatesReadOnlyFromUnknown(t *testing.T) {
	for _, name := range []string{"symbol", "decimals", "chain", "contractAddress", "address", "id", "scope"} {
		err := checkTokenPatchFields(map[string]json.RawMessage{name: []byte(`1`), "reason": []byte(`"x"`)})
		if err == nil || err.code != "TOKEN_FIELD_READONLY" || err.status != http.StatusBadRequest {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := checkTokenPatchFields(map[string]json.RawMessage{"colour": []byte(`"#fff"`)}); err == nil || err.code != "INVALID_TOKEN_REQUEST" {
		t.Fatalf("unknown field: %v", err)
	}
	if err := checkTokenPatchFields(map[string]json.RawMessage{"name": nil, "displayDecimals": nil, "logoColor": nil, "sortWeight": nil, "enabled": nil, "reason": nil, "expectedVersion": nil}); err != nil {
		t.Fatalf("editable fields rejected: %v", err)
	}
}

func TestApplyTokenPatchEnforcesBounds(t *testing.T) {
	row := seedRecord(2, "0", "eth", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6, 900, true)
	seven, three, name, color, weight, off := 7, 3, "  Tether USD ", "#26a17b", 5, false
	if _, err := applyTokenPatch(row, tokenPatch{DisplayDecimals: &seven}); err == nil {
		t.Fatal("displayDecimals above the on-chain decimals must be rejected")
	}
	updated, err := applyTokenPatch(row, tokenPatch{DisplayDecimals: &three, Name: &name, LogoColor: &color, SortWeight: &weight, Enabled: &off})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayDecimals != 3 || updated.Name != "Tether USD" || updated.LogoColor != "#26a17b" || updated.SortWeight != 5 || updated.Enabled {
		t.Fatalf("updated = %+v", updated)
	}
	// symbol/decimals 不在补丁里，必须原样保留
	if updated.Symbol != "USDT" || updated.Decimals != 6 {
		t.Fatalf("read-only facts changed: %+v", updated)
	}
	bad := "red"
	if _, err := applyTokenPatch(row, tokenPatch{LogoColor: &bad}); err == nil {
		t.Fatal("a non-hex colour must be rejected")
	}
	emoji := "🚀 Rocket"
	if _, err := applyTokenPatch(row, tokenPatch{Name: &emoji}); err == nil {
		t.Fatal("names follow the same character rules as on-chain text")
	}
}

func TestTokenChainProblemMapsEveryKind(t *testing.T) {
	cases := map[chain.Kind]struct {
		status int
		code   string
	}{
		chain.KindNotAContract:    {400, "TOKEN_NOT_A_CONTRACT"},
		chain.KindChainMismatch:   {400, "TOKEN_CHAIN_MISMATCH"},
		chain.KindMetadataInvalid: {400, "TOKEN_METADATA_INVALID"},
		chain.KindUnavailable:     {502, "TOKEN_CHAIN_UNAVAILABLE"},
	}
	for kind, want := range cases {
		got := tokenChainProblem(&chain.Error{Kind: kind, Err: errors.New("x")})
		if got.status != want.status || got.code != want.code {
			t.Errorf("%v → %d %s, want %d %s", kind, got.status, got.code, want.status, want.code)
		}
	}
	if got := tokenChainProblem(errors.New("dial tcp: refused")); got.code != "TOKEN_CHAIN_UNAVAILABLE" {
		t.Fatalf("plain errors are unavailability: %v", got)
	}
}

func TestReadsTokenChainMatchesOnlyTheChainReadingRoutes(t *testing.T) {
	yes := []string{"POST /v1/admin/tokens", "POST /v1/admin/tokens/preview", "POST /v1/admin/tokens/12/resync"}
	no := []string{"GET /v1/admin/tokens", "PATCH /v1/admin/tokens/12", "DELETE /v1/admin/tokens/12", "GET /v1/mobile/bootstrap"}
	for _, item := range yes {
		parts := strings.SplitN(item, " ", 2)
		if !readsTokenChain(httptest.NewRequest(parts[0], parts[1], nil)) {
			t.Errorf("%s must be exempt from the database timeout", item)
		}
	}
	for _, item := range no {
		parts := strings.SplitN(item, " ", 2)
		if readsTokenChain(httptest.NewRequest(parts[0], parts[1], nil)) {
			t.Errorf("%s must keep the database timeout", item)
		}
	}
}

// ---- handler 级：校验必须在碰数据库和链之前完成 ----

// neverRead 是一个一旦被调用就让测试失败的读链器。
type neverRead struct{ t *testing.T }

func (r neverRead) ReadToken(context.Context, chain.Network, string) (chain.Metadata, error) {
	r.t.Fatal("the chain must not be read before the request validates")
	return chain.Metadata{}, nil
}

func tokenTestContext(t *testing.T, method, path, body string, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Params = params
	c.Set("tenantId", "100000001")
	c.Set("actorId", "tester")
	c.Set("requestId", "req_test")
	return c, recorder
}

func problemCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not json: %s", recorder.Body.String())
	}
	code, _ := body["code"].(string)
	return code
}

func TestPatchTokenRejectsReadOnlyFieldsBeforeTouchingTheDatabase(t *testing.T) {
	// db 为 nil：任何数据库访问都会 panic，证明只读字段的拒绝发生在校验阶段
	s := &server{tokens: neverRead{t}}
	c, recorder := tokenTestContext(t, http.MethodPatch, "/v1/admin/tokens/12", `{"symbol":"USDX","reason":"改符号","expectedVersion":3}`, gin.Params{{Key: "id", Value: "12"}})
	s.patchToken(c)
	if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "TOKEN_FIELD_READONLY" {
		t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
	}
	c, recorder = tokenTestContext(t, http.MethodPatch, "/v1/admin/tokens/12", `{"name":"x","reason":"x","expectedVersion":3}`, gin.Params{{Key: "id", Value: "12"}})
	s.patchToken(c)
	if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_TOKEN_REQUEST" {
		t.Fatalf("short reason: status %d body %s", recorder.Code, recorder.Body.String())
	}
	c, recorder = tokenTestContext(t, http.MethodPatch, "/v1/admin/tokens/abc", `{}`, gin.Params{{Key: "id", Value: "abc"}})
	s.patchToken(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad id: status %d", recorder.Code)
	}
}

func TestCreateTokenValidatesBeforeReadingTheChain(t *testing.T) {
	s := &server{tokens: neverRead{t}}
	cases := []struct {
		name string
		body string
	}{
		{"unsupported chain", `{"chain":"solana","contractAddress":"` + bscUSDT + `","displayDecimals":2,"reason":"加币种","expectedVersion":0}`},
		{"missing displayDecimals", `{"chain":"bsc","contractAddress":"` + bscUSDT + `","reason":"加币种","expectedVersion":0}`},
		{"short reason", `{"chain":"bsc","contractAddress":"` + bscUSDT + `","displayDecimals":2,"reason":"x","expectedVersion":0}`},
		{"negative version", `{"chain":"bsc","contractAddress":"` + bscUSDT + `","displayDecimals":2,"reason":"加币种","expectedVersion":-1}`},
		{"bad checksum", `{"chain":"bsc","contractAddress":"` + strings.Replace(bscUSDT, "fF", "ff", 1) + `","displayDecimals":2,"reason":"加币种","expectedVersion":0}`},
		{"read-only field", `{"chain":"bsc","contractAddress":"` + bscUSDT + `","displayDecimals":2,"decimals":6,"reason":"加币种","expectedVersion":0}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			c, recorder := tokenTestContext(t, http.MethodPost, "/v1/admin/tokens", testCase.body, nil)
			s.createToken(c)
			if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_TOKEN_REQUEST" {
				t.Fatalf("status %d body %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestPreviewTokenValidatesBeforeReadingTheChain(t *testing.T) {
	s := &server{tokens: neverRead{t}}
	for _, body := range []string{
		`{"chain":"solana","contractAddress":"` + bscUSDT + `"}`,
		`{"chain":"bsc","contractAddress":"native"}`,
		`{"chain":"bsc","contractAddress":"` + bscUSDT + `","symbol":"USDT"}`,
	} {
		c, recorder := tokenTestContext(t, http.MethodPost, "/v1/admin/tokens/preview", body, nil)
		s.previewToken(c)
		if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_TOKEN_REQUEST" {
			t.Fatalf("%s: status %d body %s", body, recorder.Code, recorder.Body.String())
		}
	}
}

func TestResyncAndDeleteValidateTheirBodies(t *testing.T) {
	s := &server{tokens: neverRead{t}}
	c, recorder := tokenTestContext(t, http.MethodPost, "/v1/admin/tokens/12/resync", `{"reason":"重新读取"}`, gin.Params{{Key: "id", Value: "0"}})
	s.resyncToken(c)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("id 0: status %d", recorder.Code)
	}
	c, recorder = tokenTestContext(t, http.MethodPost, "/v1/admin/tokens/12/resync", `{"reason":"x","expectedVersion":1}`, gin.Params{{Key: "id", Value: "12"}})
	s.resyncToken(c)
	if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_TOKEN_REQUEST" {
		t.Fatalf("short reason: status %d body %s", recorder.Code, recorder.Body.String())
	}
	c, recorder = tokenTestContext(t, http.MethodDelete, "/v1/admin/tokens/12", `{"reason":"下线","expectedVersion":1,"confirm":true}`, gin.Params{{Key: "id", Value: "12"}})
	s.deleteToken(c)
	if recorder.Code != http.StatusBadRequest || problemCode(t, recorder) != "INVALID_TOKEN_REQUEST" {
		t.Fatalf("unknown field on delete: status %d body %s", recorder.Code, recorder.Body.String())
	}
}

func TestApplyTokenPatchRefusesDisablingTheNativeCoin(t *testing.T) {
	// 启用一条链即启用它的原生币：App 的手续费与原生币余额都按目录里这一条显示
	row := tokenRecord{Chain: "bsc", Address: nativeTokenAddress, Symbol: "BNB", Decimals: 18, DisplayDecimals: 4, LogoColor: "#F0B90B", Enabled: true}
	off := false
	if _, err := applyTokenPatch(row, tokenPatch{Enabled: &off}); err == nil {
		t.Fatal("disabling the native coin must be refused")
	}
	on := true
	if _, err := applyTokenPatch(row, tokenPatch{Enabled: &on}); err != nil {
		t.Fatalf("enabling the native coin must stay allowed: %v", err)
	}
}

func TestApplyTokenPatchRequiresALogoColor(t *testing.T) {
	// 头像底色直接落到 App 的背景色上，没有"没有颜色"的展示形态：新建时必填，改动时不能清空
	row := tokenRecord{Chain: "bsc", Address: "0x55d398326f99059fF775485246999027B3197955", Symbol: "USDT", Decimals: 18, DisplayDecimals: 2}
	if _, err := applyTokenPatch(row, tokenPatch{}); err == nil {
		t.Fatal("a token without a logo colour must be refused")
	}
	empty := ""
	row.LogoColor = "#26A17B"
	if _, err := applyTokenPatch(row, tokenPatch{LogoColor: &empty}); err == nil {
		t.Fatal("clearing the logo colour must be refused")
	}
	if updated, err := applyTokenPatch(row, tokenPatch{}); err != nil || updated.LogoColor != "#26A17B" {
		t.Fatalf("a patch that leaves the colour alone must pass: %v", err)
	}
}

func TestValidateDeliveredTokensRefusesCorruptRowsAndMissingNatives(t *testing.T) {
	good := []tokenRecord{
		seedRecord(1, "0", "bsc", "native", "BNB", 18, 1000, true),
		seedRecord(2, "0", "bsc", bscUSDT, "USDT", 18, 900, true),
	}
	if err := validateDeliveredTokens(good, []any{"bsc"}); err != nil {
		t.Fatalf("valid catalogue rejected: %v", err)
	}
	// 读路径不截断：展示精度越界就是事故，整份 bootstrap 失败
	bad := append([]tokenRecord{}, good...)
	bad[1].DisplayDecimals = 40
	if err := validateDeliveredTokens(bad, []any{"bsc"}); err == nil {
		t.Fatal("displayDecimals above decimals must be refused")
	}
	bad = append([]tokenRecord{}, good...)
	bad[1].LogoColor = ""
	if err := validateDeliveredTokens(bad, []any{"bsc"}); err == nil {
		t.Fatal("an empty logoColor must be refused")
	}
	// 启用的链必须有启用的原生币
	if err := validateDeliveredTokens(good, []any{"bsc", "eth"}); err == nil {
		t.Fatal("an enabled chain without a native token must be refused")
	}
	// 停用的坏行不影响下发
	disabled := append([]tokenRecord{}, good...)
	disabled[1].Enabled, disabled[1].DisplayDecimals = false, 40
	if err := validateDeliveredTokens(disabled, []any{"bsc"}); err != nil {
		t.Fatalf("a disabled row must not block delivery: %v", err)
	}
}
