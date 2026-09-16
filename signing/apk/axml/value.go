// Package axml 解析与生成 Android 二进制 XML（AndroidManifest.xml 编译后的格式）。
//
// 解析的输入来自不可信的构建产物，所以解析器按"与 Android 自己的解析方式不可能出现
// 分歧"来写：凡是 Android 会静默忽略、而我们会看见（或反过来）的构造一律拒绝，
// 例如属性名与资源 ID 不一致、属性没有按资源 ID 升序排列、原始字符串与类型化值
// 指向不同字符串、UTF-8 字符串的 UTF-16 长度声明与实际不符。这类分歧就是绕过：
// 签名闸看到 allowBackup=false，设备却看不到。
//
// 编码器用于测试夹具，也用于签名闸现场合成试签用的最小 APK。
package axml

import (
	"fmt"
	"strconv"
)

// AndroidNS 是 android: 前缀对应的命名空间。
const AndroidNS = "http://schemas.android.com/apk/res/android"

// Res_value 的数据类型（frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h）。
const (
	TypeNull             uint8 = 0x00
	TypeReference        uint8 = 0x01
	TypeAttribute        uint8 = 0x02
	TypeString           uint8 = 0x03
	TypeFloat            uint8 = 0x04
	TypeDimension        uint8 = 0x05
	TypeFraction         uint8 = 0x06
	TypeDynamicReference uint8 = 0x07
	TypeDynamicAttribute uint8 = 0x08
	TypeIntDec           uint8 = 0x10
	TypeIntHex           uint8 = 0x11
	TypeIntBoolean       uint8 = 0x12
	TypeIntColorARGB8    uint8 = 0x1c
	TypeIntColorRGB8     uint8 = 0x1d
	TypeIntColorARGB4    uint8 = 0x1e
	TypeIntColorRGB4     uint8 = 0x1f
)

// Value 是属性的类型化值。String 只在 Type == TypeString 时有意义。
type Value struct {
	Type   uint8
	Data   uint32
	String string
}

// Bool 返回布尔字面量。Android 的 TypedArray.getBoolean 以 data != 0 为真。
func (v Value) Bool() (bool, bool) {
	if v.Type != TypeIntBoolean {
		return false, false
	}
	return v.Data != 0, true
}

// Int 返回十进制或十六进制整数字面量（按 int32 符号扩展）。
func (v Value) Int() (int64, bool) {
	if v.Type != TypeIntDec && v.Type != TypeIntHex {
		return 0, false
	}
	return int64(int32(v.Data)), true
}

// Str 返回字符串字面量。
func (v Value) Str() (string, bool) {
	if v.Type != TypeString {
		return "", false
	}
	return v.String, true
}

func validType(t uint8) bool {
	return t <= TypeDynamicAttribute || (t >= TypeIntDec && t <= TypeIntBoolean) || (t >= TypeIntColorARGB8 && t <= TypeIntColorRGB4)
}

// Error 是结构性拒绝。Code 是稳定的错误码，Detail 可以安全地打印到终端。
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// 错误码。
const (
	CodeMalformed  = "AXML_MALFORMED"
	CodeStringPool = "AXML_STRING_POOL"
	// CodeStringBudget：字符串池解码总量超过 Limits.MaxStringBytes（重叠偏移放大）。
	CodeStringBudget = "AXML_STRING_POOL_BUDGET_EXCEEDED"
	// CodeStringControl：池里的字符串含 U+0000、TAB/LF/CR 以外的 C0、DEL 或 C1 控制字符。
	CodeStringControl             = "AXML_STRING_CONTROL_CHARACTER"
	CodeUnknownFrameworkAttribute = "AXML_UNKNOWN_FRAMEWORK_ATTRIBUTE"
	CodeAttributeIDMismatch       = "AXML_ATTRIBUTE_ID_MISMATCH"
	CodeNamespace                 = "AXML_NAMESPACE"
	CodeDuplicateAttribute        = "AXML_DUPLICATE_ATTRIBUTE"
	CodeAttributeOrder            = "AXML_ATTRIBUTE_ORDER"
	CodeRawValueMismatch          = "AXML_RAW_VALUE_MISMATCH"
)

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Quote 把不可信字符串变成可以安全打印的形式：截到 128 字节，非 ASCII 与控制字符转义。
func Quote(s string) string {
	const max = 128
	if len(s) > max {
		return strconv.QuoteToASCII(s[:max]) + "…"
	}
	return strconv.QuoteToASCII(s)
}
