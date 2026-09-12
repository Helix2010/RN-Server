package api

import "testing"

func TestAllowlistUnsetLetsEverythingThrough(t *testing.T) {
	list, err := parseIPAllowlist(nil)
	if err != nil || list != nil {
		t.Fatalf("empty config must mean no restriction: %v %v", list, err)
	}
	if !list.allows("203.0.113.9") {
		t.Fatal("a nil allowlist must allow")
	}
}

func TestAllowlistMatchesBareIPsAndCIDRs(t *testing.T) {
	list, err := parseIPAllowlist([]string{"127.0.0.1", "10.0.0.0/8", "::1"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, ok := range []string{"127.0.0.1", "10.4.5.6", "::1"} {
		if !list.allows(ok) {
			t.Fatalf("%s should be allowed", ok)
		}
	}
	for _, blocked := range []string{"127.0.0.2", "11.0.0.1", "203.0.113.9"} {
		if list.allows(blocked) {
			t.Fatalf("%s should be blocked", blocked)
		}
	}
}

// 宁可挡错也不放开：一个畸形地址不该成为绕过这条名单的方式
func TestAllowlistRejectsAnUnparseableAddress(t *testing.T) {
	list, _ := parseIPAllowlist([]string{"127.0.0.1"})
	if list.allows("not-an-ip") || list.allows("") {
		t.Fatal("an unparseable client address must not be allowed")
	}
}

func TestAllowlistRejectsNonsenseConfiguration(t *testing.T) {
	for _, bad := range [][]string{{"not-an-ip"}, {"10.0.0.0/99"}} {
		if _, err := parseIPAllowlist(bad); err == nil {
			t.Fatalf("%v should not parse", bad)
		}
	}
}

/*
 * 这条是整件事的关键：gin 默认信任所有代理，来源地址由 X-Forwarded-For 决定，
 * 也就是请求方自己说了算。那种情况下的 IP 白名单看起来像一道门，实际谁都能推开——
 * 比没有门更糟，因为它会让人以为这件事做完了。所以宁可不启动。
 */
func TestAllowlistWithoutTrustedProxiesIsRefusedAtStartup(t *testing.T) {
	if err := validateAdminIPConfiguration([]string{"10.0.0.1"}, nil); err == nil {
		t.Fatal("an allowlist without trusted proxies must be refused")
	}
	if err := validateAdminIPConfiguration([]string{"10.0.0.1"}, []string{"172.18.0.0/16"}); err != nil {
		t.Fatalf("a complete configuration must start: %v", err)
	}
	if err := validateAdminIPConfiguration(nil, nil); err != nil {
		t.Fatalf("no allowlist at all is still allowed: %v", err)
	}
}
