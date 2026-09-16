package machinekey

import (
	"strings"
	"testing"
)

func TestEnrollmentCode(t *testing.T) {
	code, err := NewEnrollmentCode()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidEnrollmentCode(code) || len(code) != 47 || !strings.HasPrefix(code, "rne_") {
		t.Fatalf("generated code %q is not valid", code)
	}
	other, _ := NewEnrollmentCode()
	if other == code {
		t.Fatal("two generated codes are equal")
	}
	valid := "rne_" + strings.Repeat("A", 43)
	if !ValidEnrollmentCode(valid) {
		t.Fatal("all-zero code rejected")
	}
	for _, bad := range []string{
		"",
		"rne_",
		"rnm_" + strings.Repeat("A", 43),           // 机器令牌不是注册码
		"RNE_" + strings.Repeat("A", 43),           // 前缀区分大小写
		"rne_" + strings.Repeat("A", 42),           // 太短
		"rne_" + strings.Repeat("A", 44),           // 太长
		"rne_" + strings.Repeat("A", 42) + "=",     // 带填充
		"rne_" + strings.Repeat("A", 42) + "+",     // 不是 base64url
		"rne_" + strings.Repeat("A", 42) + "B",     // 非规范编码（末位多出的比特不为 0）
		" rne_" + strings.Repeat("A", 43),          // 空白
		"rne_" + strings.Repeat("A", 41) + "\nA",   // 换行
		"rne_" + strings.Repeat("A", 42) + "é"[:1], // 非 ASCII 字节
	} {
		if ValidEnrollmentCode(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
