package store

import (
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/siwe"
)

// appAllowlist 抄自 RN-App 的 src/core/wallet/config/token-allowlist.ts。
// 那份表是 App 里 verified 的唯一来源；服务端预置的地址与精度必须与它逐字相符，
// 否则 App 会把服务端下发的 USDT 当成"元数据不符"直接丢弃。
var appAllowlist = map[string]map[string]struct {
	symbol   string
	decimals int
}{
	"bsc": {
		"0x55d398326f99059ff775485246999027b3197955": {"USDT", 18},
		"0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": {"USDC", 18},
	},
	"eth": {
		"0xdac17f958d2ee523a2206206994597c13d831ec7": {"USDT", 6},
		"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {"USDC", 6},
	},
	"base": {
		"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": {"USDC", 6},
	},
	"op-sepolia": {},
}

func TestChainTokenSeedMatchesTheAppAllowlist(t *testing.T) {
	contracts := 0
	for _, row := range ChainTokenSeed {
		if row.Address == "native" {
			continue
		}
		contracts++
		entry, ok := appAllowlist[row.Chain][strings.ToLower(row.Address)]
		if !ok {
			t.Errorf("%s %s 不在 App 白名单里", row.Chain, row.Address)
			continue
		}
		if entry.symbol != row.Symbol || entry.decimals != row.Decimals {
			t.Errorf("%s %s: 服务端 %s/%d，App %s/%d", row.Chain, row.Address, row.Symbol, row.Decimals, entry.symbol, entry.decimals)
		}
	}
	total := 0
	for _, byAddress := range appAllowlist {
		total += len(byAddress)
	}
	if contracts != total || contracts != 5 {
		t.Fatalf("预置合约 %d 条，App 白名单 %d 条，两边都应是 5", contracts, total)
	}
}

func TestChainTokenSeedAddressesAreChecksummed(t *testing.T) {
	// 唯一键按字面比较，大小写不同的同一地址会绕过它；入库形式必须是 EIP-55
	for _, row := range ChainTokenSeed {
		if row.Address == "native" {
			continue
		}
		if got := siwe.ChecksumAddress(row.Address); got != row.Address {
			t.Errorf("%s %s 不是 EIP-55 形式，应为 %s", row.Chain, row.Address, got)
		}
	}
}

func TestChainTokenSeedShape(t *testing.T) {
	natives := map[string]int{}
	seen := map[string]bool{}
	for _, row := range ChainTokenSeed {
		key := row.Chain + "|" + row.Address
		if seen[key] {
			t.Errorf("重复的预置行 %s", key)
		}
		seen[key] = true
		if row.DisplayDecimals > row.Decimals {
			t.Errorf("%s %s 展示精度 %d 超过链上精度 %d", row.Chain, row.Symbol, row.DisplayDecimals, row.Decimals)
		}
		if row.Address == "native" {
			natives[row.Chain]++
			if row.DisplayDecimals != 4 {
				t.Errorf("原生币 %s 的展示精度应为 4", row.Chain)
			}
		} else if row.DisplayDecimals != 2 {
			t.Errorf("稳定币 %s/%s 的展示精度应为 2", row.Chain, row.Symbol)
		}
		if row.Chain == "op-sepolia" && row.Address != "native" {
			t.Errorf("测试链不预置代币: %s", row.Symbol)
		}
	}
	for _, chain := range []string{"bsc", "eth", "base", "op-sepolia"} {
		if natives[chain] != 1 {
			t.Errorf("链 %s 应恰好有一条原生币，实际 %d", chain, natives[chain])
		}
	}
}

func TestChainTokenCatalogMigrationIsRegistered(t *testing.T) {
	for _, item := range migrations {
		if item.version == 28 {
			if item.name != "chain_token_catalog" {
				t.Fatalf("migration 28 = %q", item.name)
			}
			return
		}
	}
	t.Fatal("migration 28 is missing")
}
