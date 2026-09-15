// Package referral 放邀请码的字母表、生成与归一化。
//
// 迁移的回填（internal/store）与接口的注册、绑定（internal/api）都要用同一套规则，
// 所以它不能长在任何一边。归一化只有这一处实现：设计
// RN-App/docs/design/referral-graph-2026-09-15.md §4.2 要求各端提交原文、
// 服务端一处归一化，各端各自 trim 就是第二份真相。
package referral

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// Alphabet 是 Crockford Base32：0-9A-Z 去掉 I L O U。
// 去掉易混字符是为了让人能照着念、照着抄；U 被 Crockford 排除在字母表外，
// 所以归一化不把它映射成别的字符，出现即输错。
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeLength 邀请码长度。空间 32^8 = 1.0995e12，见设计 §3.3 的碰撞估算。
const CodeLength = 8

// Generate 取一个随机邀请码。
//
// 字母表恰好 32 个字符，256 % 32 == 0，所以按位取低 5 位是均匀的，不需要拒绝采样。
func Generate() (string, error) {
	buf := make([]byte, CodeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("referral: read random: %w", err)
	}
	out := make([]byte, CodeLength)
	for i, b := range buf {
		out[i] = Alphabet[b&0x1F]
	}
	return string(out), nil
}

// Normalize 把用户输入的原文归一化成入库形态，第二个返回值为 false 表示格式非法。
//
// 五步（设计 §4.2 / REFERRAL_SCHEMA.md）：
//  1. 全角转半角；
//  2. 去掉所有非字母数字字符（空格、连字符、下划线等，所以带横线的 ABCD-1234 也认）；
//  3. 转大写；
//  4. Crockford 易混字符映射 I L -> 1、O -> 0（去掉这两个字符的全部意义就在这一步，
//     没有它，照着念的人输 O 会拿到"码不存在"，而正确行为是解码成 0）；
//  5. 必须恰好 CodeLength 位且每一位都在字母表内。
//
// 调用方要把 false 映射成 REFERRAL_CODE_MALFORMED（422），与"码不存在"的
// REFERRAL_CODE_UNKNOWN（404）分开：前者是用户输错，后者是码无效，文案不同。
func Normalize(raw string) (string, bool) {
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		r = halfWidth(r)
		if !isASCIIAlphanumeric(r) {
			continue
		}
		r = upper(r)
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		b.WriteRune(r)
	}
	code := b.String()
	if len(code) != CodeLength {
		return "", false
	}
	if strings.ContainsFunc(code, func(r rune) bool { return !strings.ContainsRune(Alphabet, r) }) {
		return "", false
	}
	return code, true
}

// halfWidth 把全角 ASCII（U+FF01..U+FF5E）映射回半角；其余原样返回。
// 全角空格 U+3000 不用单独处理：它不是字母数字，下一步会被丢掉。
func halfWidth(r rune) rune {
	if r >= 0xFF01 && r <= 0xFF5E {
		return r - 0xFEE0
	}
	return r
}

func isASCIIAlphanumeric(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func upper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - ('a' - 'A')
	}
	return r
}

// Format 是展示用的分段形态 XXXX-XXXX，提高抄写正确率（设计 §5.1）。
// 存储、URL 与二维码内容一律用不分段的原值；Normalize 会去掉连字符，
// 所以用户把分段形态粘回输入框也认。
func Format(code string) string {
	if len(code) != CodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}
