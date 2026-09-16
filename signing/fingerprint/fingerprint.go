// Package fingerprint 是签名链路上所有指纹的唯一写法：完整 sha256，小写十六进制，
// 64 个字符。
//
// 不提供截短版本。旧代码里 16 个十六进制字符（64 比特）的"指纹"是给人看的，
// 但人会拿它去比对，而 64 比特不足以挡住有意构造的碰撞。
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Length 是指纹的字符数。
const Length = 64

// SHA256Hex 返回 b 的 sha256，小写十六进制。
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Valid 判断 s 是否恰好是 64 个小写十六进制字符。
func Valid(s string) bool {
	if len(s) != Length {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Normalize 接受 keytool 那种带冒号、大写的写法：去掉冒号、转小写后校验。
// 不去空白——调用方读一行输入时自己去掉行尾，这里多容忍一种写法就多一种
// "看起来一样其实不一样"的输入。
func Normalize(s string) (string, bool) {
	out := strings.ToLower(strings.ReplaceAll(s, ":", ""))
	if !Valid(out) {
		return "", false
	}
	return out, true
}
