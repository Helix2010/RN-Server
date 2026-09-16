package machinekey

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// EnrollmentCodePrefix 是一次性注册码的前缀。注册码 = "rne_" + 32 字节随机数的 base64url（无填充，
// 43 个字符）；服务端只存 sha256，60 分钟有效，用一次作废。安装命令把它交给 signer enroll /
// build-agent enroll，换回长期机器令牌。
const EnrollmentCodePrefix = "rne_"

const enrollmentCodeBytes = 32

// ValidEnrollmentCode 判断注册码格式：rne_ + 43 个 base64url 字符，且解码恰好 32 字节（规范编码）。
func ValidEnrollmentCode(s string) bool {
	body, ok := strings.CutPrefix(s, EnrollmentCodePrefix)
	if !ok || len(body) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	return err == nil && len(raw) == enrollmentCodeBytes
}

// NewEnrollmentCode 生成一个注册码（服务端用）。
func NewEnrollmentCode() (string, error) {
	raw := make([]byte, enrollmentCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return EnrollmentCodePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
