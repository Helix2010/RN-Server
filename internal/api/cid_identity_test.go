package api

import (
	"strings"
	"testing"

	"github.com/Helix2010/authorization-go-sdk/cid"
)

// RN 对 userinfo 的额外要求（cid_login.go cidIdentity）：SDK 只挡空白与控制字符。
func TestCIDIdentity(t *testing.T) {
	const subject = "1c9670fc-87c8-4655-9366-d8eebbea7c74"
	user, err := cidIdentity(&cid.User{Subject: strings.ToUpper(subject), Email: " a@example.com "})
	if err != nil || user.Subject != subject || user.Email != "a@example.com" {
		t.Fatalf("user = %+v, err = %v", user, err)
	}
	// 账号 id 不是 uuid：拒绝，错误里不带对方给的值
	for _, weird := range []string{"admin", "10002", subject + "x", ""} {
		if _, err := cidIdentity(&cid.User{Subject: weird, Email: "a@example.com"}); err == nil || (weird != "" && strings.Contains(err.Error(), weird)) {
			t.Errorf("subject %q: err = %v", weird, err)
		}
	}
	if _, err := cidIdentity(nil); err == nil {
		t.Error("a nil user must be rejected")
	}
	// 邮箱只作显示与发信，过长就不要
	user, err = cidIdentity(&cid.User{Subject: subject, Email: strings.Repeat("a", 250) + "@example.com"})
	if err != nil || user.Email != "" {
		t.Fatalf("long email: user = %+v, err = %v", user, err)
	}
}
