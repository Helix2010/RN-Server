package api

import (
	"strings"
	"testing"
)

// 平台级查询只接受完整地址：不做前缀匹配，避免跨租户批量枚举（设计 §4.11）
func TestNormalizeWalletAddressRequiresFullAddress(t *testing.T) {
	for _, raw := range []string{"", "0x98", "9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x9858EfFD232B4033E47d90003D41EC34EcaEda9", "0xZZ58EfFD232B4033E47d90003D41EC34EcaEda94"} {
		if _, _, ok := normalizeWalletAddress(raw); ok {
			t.Fatalf("%q must be rejected", raw)
		}
	}
	address, key, ok := normalizeWalletAddress("  0x9858EfFD232B4033E47d90003D41EC34EcaEda94 ")
	if !ok || address != "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" || key != "0x9858effd232b4033e47d90003d41ec34ecaeda94" {
		t.Fatalf("unexpected normalization: %q %q %v", address, key, ok)
	}
}

// 平台级封禁要结束该地址在所有租户的有效会话，但只动仍有效的行
func TestEndSessionsByAddressSQLScope(t *testing.T) {
	for _, fragment := range []string{"JOIN wallet_user u", "u.address_key=?", "s.revoked_at IS NULL", "ended_reason=?"} {
		if !strings.Contains(endSessionsByAddressSQL, fragment) {
			t.Fatalf("cross-tenant end sessions SQL missing %s", fragment)
		}
	}
	if strings.Contains(endSessionsByAddressSQL, "tenant_id=?") {
		t.Fatal("platform block must not be scoped to a single tenant")
	}
}
