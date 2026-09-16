package ident

import (
	"strings"
	"testing"
)

func TestTenantSlug(t *testing.T) {
	for _, ok := range []string{"AnyFun", "anyfun", "predict-kim", "a", "a.b_c-d"} {
		if !ValidTenantSlug(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "-x", ".x", "a/b", "a b", "a\x1bb", "é", strings.Repeat("a", 101)} {
		if ValidTenantSlug(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPackageName(t *testing.T) {
	for _, ok := range []string{"com.anyfun.foundation", "a.b", "com.x_y.z9"} {
		if !ValidPackageName(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "com", "Com.anyfun", "com..x", "com.9x", ".com.x", "com.x.", "com.x\n", "com.x-y"} {
		if ValidPackageName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	long := "a." + strings.Repeat("b", MaxPackageNameLength)
	if ValidPackageName(long) {
		t.Error("accepted an over-long package name")
	}
}

func TestKeyAliasAndMachineName(t *testing.T) {
	if !ValidKeyAlias("anyfun-release") || ValidKeyAlias("my alias") || ValidKeyAlias("") || ValidKeyAlias(strings.Repeat("a", 65)) {
		t.Fatal("key alias rule is wrong")
	}
	if !ValidMachineName("amos-signer-a") || ValidMachineName("a") || ValidMachineName("Amos") || ValidMachineName("-amos") {
		t.Fatal("machine name rule is wrong")
	}
}

func TestServerID(t *testing.T) {
	if !ValidServerID("bld_AbC-d_09xyz") || !ValidServerIDWithPrefix("mch_abcdEFGH", "mch") {
		t.Fatal("valid ids rejected")
	}
	for _, bad := range []string{"", "bld_", "BLD_abcd", "bld abcd", "bld_ab\ncd", "bld_ab/cd"} {
		if ValidServerID(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
	if ValidServerIDWithPrefix("bld_abcdefgh", "mch") {
		t.Fatal("prefix not enforced")
	}
}

func TestRFC3339UTC(t *testing.T) {
	for _, ok := range []string{"2026-09-16T08:00:00Z", "2026-09-16T08:00:00.123Z"} {
		if !ValidRFC3339UTC(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "2026-09-16T08:00:00+08:00", "2026-09-16 08:00:00Z", "yesterdayZ"} {
		if ValidRFC3339UTC(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPrintableASCII(t *testing.T) {
	if !PrintableASCII("abc ~") || PrintableASCII("a\tb") || PrintableASCII("\x1b[2J") || PrintableASCII("é") {
		t.Fatal("printable ASCII rule is wrong")
	}
}
