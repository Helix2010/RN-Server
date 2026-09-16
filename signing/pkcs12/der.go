package pkcs12

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"unicode/utf16"
)

// ---- DER 编码 ----
//
// 编码侧不用 encoding/asn1 的结构体标签：RawValue 在 Marshal 时会忽略 explicit 等
// 参数，写出来的形状和结构体声明对不上，读代码的人很难看出。这里逐层手写 TLV，
// 每一层是什么一眼可见。

func tlv(tag byte, content []byte) []byte {
	n := len(content)
	out := make([]byte, 0, n+6)
	out = append(out, tag)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	case n <= 0xffff:
		out = append(out, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		out = append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func derSequence(parts ...[]byte) []byte { return tlv(0x30, bytes.Join(parts, nil)) }

// derSet 按 DER 的要求把 SET OF 的元素按编码排序。
func derSet(parts ...[]byte) []byte {
	sorted := append([][]byte(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	return tlv(0x31, bytes.Join(sorted, nil))
}

func derOctets(b []byte) []byte { return tlv(0x04, b) }

// derExplicit0 是 [0] EXPLICIT（构造型、上下文标签 0）。
func derExplicit0(inner []byte) []byte { return tlv(0xa0, inner) }

// derImplicit0Octets 是 [0] IMPLICIT OCTET STRING（原始型、上下文标签 0）。
func derImplicit0Octets(b []byte) []byte { return tlv(0x80, b) }

var derNull = []byte{0x05, 0x00}

func derOID(oid asn1.ObjectIdentifier) []byte {
	raw, err := asn1.Marshal(oid)
	if err != nil {
		// 只会用包内常量调用；常量写错是编程错误
		panic(fmt.Sprintf("pkcs12: invalid object identifier %v: %v", oid, err))
	}
	return raw
}

func derInt(n int) []byte {
	raw, err := asn1.Marshal(n)
	if err != nil {
		panic(fmt.Sprintf("pkcs12: cannot encode integer %d: %v", n, err))
	}
	return raw
}

// bmpString 编码 BMPString（UTF-16BE）内容字节。
func bmpString(s string) ([]byte, error) {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units))
	for _, u := range units {
		if u == 0 {
			return nil, errors.New("pkcs12: text must not contain NUL")
		}
		out = append(out, byte(u>>8), byte(u))
	}
	return out, nil
}

// macPassword 是 PKCS#12 MAC 那一层的口令编码：BMPString 后面跟两个 0 字节（RFC 7292 附录 B.1）。
func macPassword(password string) ([]byte, error) {
	encoded, err := bmpString(password)
	if err != nil {
		return nil, err
	}
	return append(encoded, 0, 0), nil
}

// ---- DER 解码 ----
//
// 解码侧只借用 encoding/asn1 读单个 TLV（它拒绝不定长与非最短长度编码），结构逐层手工
// 校验：每一层检查类别、标签、构造位、子元素个数，读完不许有剩余字节。

func parseElement(b []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return asn1.RawValue{}, nil, malformed("invalid DER element")
	}
	return v, rest, nil
}

// parseOnly 要求 b 恰好是一个元素。
func parseOnly(b []byte) (asn1.RawValue, error) {
	v, rest, err := parseElement(b)
	if err != nil {
		return v, err
	}
	if len(rest) != 0 {
		return v, malformed("trailing data after a DER element")
	}
	return v, nil
}

// children 解出构造型元素的全部子元素，最多 max 个。
func children(v asn1.RawValue, max int) ([]asn1.RawValue, error) {
	if !v.IsCompound {
		return nil, malformed("expected a constructed element")
	}
	var out []asn1.RawValue
	rest := v.Bytes
	for len(rest) > 0 {
		if len(out) == max {
			return nil, malformed("too many elements")
		}
		child, next, err := parseElement(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		rest = next
	}
	return out, nil
}

func isUniversal(v asn1.RawValue, tag int, compound bool) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag && v.IsCompound == compound
}

func isSequence(v asn1.RawValue) bool { return isUniversal(v, asn1.TagSequence, true) }

func isSet(v asn1.RawValue) bool { return isUniversal(v, asn1.TagSet, true) }

func isContext(v asn1.RawValue, tag int, compound bool) bool {
	return v.Class == asn1.ClassContextSpecific && v.Tag == tag && v.IsCompound == compound
}

func sequenceChildren(v asn1.RawValue, min, max int, what string) ([]asn1.RawValue, error) {
	if !isSequence(v) {
		return nil, malformed(what + " is not a SEQUENCE")
	}
	items, err := children(v, max)
	if err != nil {
		return nil, err
	}
	if len(items) < min {
		return nil, malformed(what + " has too few elements")
	}
	return items, nil
}

func parseOIDValue(v asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if !isUniversal(v, asn1.TagOID, false) {
		return nil, malformed("expected an OBJECT IDENTIFIER")
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(v.FullBytes, &oid)
	if err != nil || len(rest) != 0 {
		return nil, malformed("invalid OBJECT IDENTIFIER")
	}
	return oid, nil
}

func parseIntValue(v asn1.RawValue) (int, error) {
	if !isUniversal(v, asn1.TagInteger, false) {
		return 0, malformed("expected an INTEGER")
	}
	var n int
	rest, err := asn1.Unmarshal(v.FullBytes, &n)
	if err != nil || len(rest) != 0 {
		return 0, malformed("invalid INTEGER")
	}
	return n, nil
}

func parseOctetsValue(v asn1.RawValue) ([]byte, error) {
	if !isUniversal(v, asn1.TagOctetString, false) {
		return nil, malformed("expected a primitive OCTET STRING")
	}
	return v.Bytes, nil
}

// explicitInner 解出 [tag] EXPLICIT 包着的唯一元素。
func explicitInner(v asn1.RawValue, tag int) (asn1.RawValue, error) {
	if !isContext(v, tag, true) {
		return asn1.RawValue{}, malformed("expected an explicit context tag")
	}
	return parseOnly(v.Bytes)
}

// algorithm 是 AlgorithmIdentifier。params 为 nil 表示没有参数。
type algorithm struct {
	oid    asn1.ObjectIdentifier
	params *asn1.RawValue
}

func parseAlgorithm(v asn1.RawValue) (algorithm, error) {
	items, err := sequenceChildren(v, 1, 2, "AlgorithmIdentifier")
	if err != nil {
		return algorithm{}, err
	}
	oid, err := parseOIDValue(items[0])
	if err != nil {
		return algorithm{}, err
	}
	alg := algorithm{oid: oid}
	if len(items) == 2 {
		alg.params = &items[1]
	}
	return alg, nil
}

// paramsAbsentOrNull：散列与 HMAC 算法的参数只能省略或为 NULL。
func (a algorithm) paramsAbsentOrNull() bool {
	return a.params == nil || (isUniversal(*a.params, asn1.TagNull, false) && len(a.params.Bytes) == 0)
}

// decodeBMPString 解 BMPString 内容字节；拒绝奇数长度、NUL 与不成对的代理项。
func decodeBMPString(b []byte) (string, error) {
	if len(b)%2 != 0 || len(b) > 2*256 {
		return "", malformed("invalid BMPString")
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		if units[i] == 0 {
			return "", malformed("BMPString contains NUL")
		}
	}
	for i := 0; i < len(units); i++ {
		switch u := units[i]; {
		case u >= 0xd800 && u < 0xdc00:
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] >= 0xe000 {
				return "", malformed("BMPString has an unpaired surrogate")
			}
			i++
		case u >= 0xdc00 && u < 0xe000:
			return "", malformed("BMPString has an unpaired surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}
