package api

import (
	"strings"
	"testing"

	"github.com/Helix2010/authorization-go-sdk/cid"
)

// RN 对 userinfo 的额外要求（cid_login.go cidSubject）：SDK 只挡空白与控制字符。
func TestCIDSubject(t *testing.T) {
	const subject = "1c9670fc-87c8-4655-9366-d8eebbea7c74"
	got, err := cidSubject(&cid.User{Subject: strings.ToUpper(subject), Email: "a@example.com"})
	if err != nil || got != subject {
		t.Fatalf("subject = %q, err = %v", got, err)
	}
	// 账号 id 不是 uuid：拒绝，错误里不带对方给的值
	for _, weird := range []string{"admin", "10002", subject + "x", ""} {
		if _, err := cidSubject(&cid.User{Subject: weird, Email: "a@example.com"}); err == nil || (weird != "" && strings.Contains(err.Error(), weird)) {
			t.Errorf("subject %q: err = %v", weird, err)
		}
	}
	if _, err := cidSubject(nil); err == nil {
		t.Error("a nil user must be rejected")
	}
}

// 回调按统一账号的全部记录认人（设计 console-accounts-external-maintenance §4.1）。
func TestAccountForLogin(t *testing.T) {
	platform := &tenantAccount{ID: "1", Scope: scopePlatform, Status: accountActive}
	inA := &tenantAccount{ID: "2", Scope: scopeTenant, TenantID: "7", Status: accountActive}
	inB := &tenantAccount{ID: "3", Scope: scopeTenant, TenantID: "8", Status: accountActive}
	disabledInA := &tenantAccount{ID: "4", Scope: scopeTenant, TenantID: "7", Status: "disabled"}
	disabledPlatform := &tenantAccount{ID: "5", Scope: scopePlatform, Status: "disabled"}
	for _, tc := range []struct {
		name     string
		accounts []*tenantAccount
		tenant   string
		want     *tenantAccount
		refused  string
	}{
		{"没有记录", nil, "7", nil, "no_access"},
		{"只有别的租户的记录", []*tenantAccount{inB}, "7", nil, "no_access"},
		{"本租户的记录", []*tenantAccount{inA, inB}, "7", inA, ""},
		{"多个租户，按域名选", []*tenantAccount{inA, inB}, "8", inB, ""},
		// 平台管理员不操作租户：只有平台记录，在租户控制台上进不来（设计 service-and-console-split-2026-09-27 §4.1）
		{"平台记录在租户控制台上不认", []*tenantAccount{platform}, "8", nil, "no_access"},
		{"停用的平台记录在租户控制台上也是 no_access", []*tenantAccount{disabledPlatform}, "7", nil, "no_access"},
		{"平台记录加本租户记录", []*tenantAccount{platform, inA}, "7", nil, "identity_conflict"},
		{"平台记录加别的租户的记录也算冲突", []*tenantAccount{platform, inB}, "7", nil, "identity_conflict"},
		{"停用的平台记录加租户记录仍是冲突", []*tenantAccount{disabledPlatform, inA}, "7", nil, "identity_conflict"},
		{"本租户的记录停用了", []*tenantAccount{disabledInA}, "7", nil, "disabled"},
		// 平台控制台（tenant 为空，设计 service-and-console-split-2026-09-27 §4.2）：只认平台记录
		{"平台控制台：平台记录", []*tenantAccount{platform}, "", platform, ""},
		{"平台控制台：只有租户记录", []*tenantAccount{inA, inB}, "", nil, "no_access"},
		{"平台控制台：没有记录", nil, "", nil, "no_access"},
		{"平台控制台：平台记录加租户记录仍是冲突", []*tenantAccount{platform, inA}, "", nil, "identity_conflict"},
		{"平台控制台：平台记录停用了", []*tenantAccount{disabledPlatform}, "", nil, "disabled"},
	} {
		got, refused := accountForLogin(tc.accounts, tc.tenant)
		if got != tc.want || refused != tc.refused {
			t.Fatalf("%s: got %v %q, want %v %q", tc.name, got, refused, tc.want, tc.refused)
		}
	}
}
