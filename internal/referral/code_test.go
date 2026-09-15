package referral

import (
	"strings"
	"testing"
)

func TestAlphabetIsCrockford(t *testing.T) {
	if len(alphabet) != 32 {
		t.Fatalf("alphabet must hold 32 symbols, got %d", len(alphabet))
	}
	for _, excluded := range []rune{'I', 'L', 'O', 'U'} {
		if strings.ContainsRune(alphabet, excluded) {
			t.Fatalf("alphabet must not contain the ambiguous symbol %q", excluded)
		}
	}
	seen := map[rune]bool{}
	for _, r := range alphabet {
		if seen[r] {
			t.Fatalf("alphabet repeats %q", r)
		}
		seen[r] = true
	}
}

func TestGenerateStaysInsideAlphabet(t *testing.T) {
	for i := 0; i < 500; i++ {
		code, err := Generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(code) != codeLength {
			t.Fatalf("length = %d, want %d", len(code), codeLength)
		}
		for _, r := range code {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("generated %q contains %q which is outside the alphabet", code, r)
			}
		}
		// 生成的码必须能被归一化回它自己，否则用户抄下来再输入就对不上
		if normalized, ok := Normalize(code); !ok || normalized != code {
			t.Fatalf("generated %q does not round-trip through Normalize (got %q, ok=%v)", code, normalized, ok)
		}
	}
}

// 每一位都应该能取到字母表里的任意符号：如果生成用了有偏的取模，
// 靠前的符号会明显更常出现。500 * 8 = 4000 次抽取，32 个符号期望各 125 次。
func TestGenerateCoversAlphabet(t *testing.T) {
	counts := map[rune]int{}
	for i := 0; i < 500; i++ {
		code, err := Generate()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		for _, r := range code {
			counts[r]++
		}
	}
	for _, r := range alphabet {
		if counts[r] == 0 {
			t.Fatalf("symbol %q never appeared in 4000 draws", r)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "已是规范形态", in: "ABCD1234", want: "ABCD1234", ok: true},
		{name: "小写", in: "abcd1234", want: "ABCD1234", ok: true},
		{name: "分段连字符", in: "ABCD-1234", want: "ABCD1234", ok: true},
		{name: "前后空白与内部空格", in: "  AB CD 12 34 ", want: "ABCD1234", ok: true},
		{name: "下划线", in: "ABCD_1234", want: "ABCD1234", ok: true},
		{name: "全角字母数字", in: "ＡＢＣＤ１２３４", want: "ABCD1234", ok: true},
		{name: "全角空格", in: "ABCD　1234", want: "ABCD1234", ok: true},
		// Crockford 映射：去掉 I L O 的全部意义就在这里
		{name: "大写 I 映射成 1", in: "IBCD1234", want: "1BCD1234", ok: true},
		{name: "小写 l 映射成 1", in: "lBCD1234", want: "1BCD1234", ok: true},
		{name: "大写 O 映射成 0", in: "OBCD1234", want: "0BCD1234", ok: true},
		{name: "小写 o 映射成 0", in: "obcd1234", want: "0BCD1234", ok: true},
		// U 被 Crockford 排除，不映射，出现即输错
		{name: "U 不映射直接判非法", in: "UBCD1234", ok: false},
		{name: "太短", in: "ABCD123", ok: false},
		{name: "太长", in: "ABCD12345", ok: false},
		{name: "空串", in: "", ok: false},
		{name: "全是分隔符", in: "--------", ok: false},
		{name: "非字母数字被丢掉后不足长度", in: "AB@CD#12", want: "ABCD12", ok: false},
		{name: "中文", in: "邀请码邀请码邀请码", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Normalize(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Fatalf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// 归一化必须幂等：入库的是归一化结果，再归一化一次不能变。
func TestNormalizeIsIdempotent(t *testing.T) {
	for _, raw := range []string{"abcd-1234", "ＡＢＣＤ１２３４", "i l o 1 2 3 4 5"} {
		once, ok := Normalize(raw)
		if !ok {
			t.Fatalf("normalize(%q) rejected", raw)
		}
		twice, ok := Normalize(once)
		if !ok || twice != once {
			t.Fatalf("normalize is not idempotent for %q: %q then %q (ok=%v)", raw, once, twice, ok)
		}
	}
}

func TestFormat(t *testing.T) {
	if got := Format("ABCD1234"); got != "ABCD-1234" {
		t.Fatalf("Format = %q, want ABCD-1234", got)
	}
	// 长度不对就原样返回，不去猜怎么分段
	if got := Format("ABC"); got != "ABC" {
		t.Fatalf("Format of a malformed code must pass through, got %q", got)
	}
	// 分段形态必须能被归一化回原值
	back, ok := Normalize(Format("ABCD1234"))
	if !ok || back != "ABCD1234" {
		t.Fatalf("formatted code does not normalize back: %q ok=%v", back, ok)
	}
}
