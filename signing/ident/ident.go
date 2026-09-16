// Package ident 集中放签名链路上各种标识符的格式规则。
//
// 服务端、签名闸、离线工具对同一个字段必须用同一条规则：一边放行、另一边拒收的
// 字段，报错会出现在离根因很远的地方（离线工具产出的文件在控制台上传时才被拒）。
// 规则都是白名单，不接受空白、控制字符与非 ASCII：这些字符串会被打印到运维的终端上，
// 也会被拼进文件名与日志。
package ident

import (
	"regexp"
	"strings"
	"time"
)

var (
	// 租户 slug 沿用服务端现有规则：线上 slug 是 AnyFun，所以允许大写（见 cb5188c）
	tenantSlugPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	// Android applicationId：只收小写。大写包名 Android 允许，但我们没有，也不打算有
	packageNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	keyAliasPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	machineNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,39}$`)
	// 服务端 id（任务 bld_…、机器 mch_…）：前缀 + base64url 随机串
	serverIDPattern = regexp.MustCompile(`^[a-z]{2,8}_[A-Za-z0-9_-]{4,64}$`)
)

// MaxPackageNameLength 是包名长度上限。Android 自己的上限更宽，这里只防超长输入。
const MaxPackageNameLength = 255

// ValidTenantSlug 判断租户 slug。
func ValidTenantSlug(s string) bool { return tenantSlugPattern.MatchString(s) }

// ValidPackageName 判断 Android 包名。
func ValidPackageName(s string) bool {
	return len(s) <= MaxPackageNameLength && packageNamePattern.MatchString(s)
}

// ValidKeyAlias 判断 keystore 别名。
func ValidKeyAlias(s string) bool { return keyAliasPattern.MatchString(s) }

// ValidMachineName 判断机器名（构建机、签名闸）。
func ValidMachineName(s string) bool { return machineNamePattern.MatchString(s) }

// ValidServerID 判断服务端生成的 id，例如 bld_xxx、mch_xxx。
func ValidServerID(s string) bool { return serverIDPattern.MatchString(s) }

// ValidServerIDWithPrefix 判断带指定前缀（不含下划线）的服务端 id。
func ValidServerIDWithPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix+"_") && serverIDPattern.MatchString(s)
}

// ValidRFC3339UTC 判断 RFC3339 的 UTC 时间（以 Z 结尾）。
func ValidRFC3339UTC(s string) bool {
	if len(s) > 40 || !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// PrintableASCII 判断 s 只含可打印 ASCII（0x20–0x7e）。给还没有更具体规则、
// 但要显示在终端上的字符串用。
func PrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
