package axml

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"unicode/utf16"
)

// Node 是要编码的元素。
type Node struct {
	Namespace string
	Name      string
	Attrs     []Attr
	Children  []*Node
}

// Attr 是要编码的属性。ResourceID 为 0 表示不进资源表。Raw 为 nil 时按 aapt2 的写法
// 生成原始值（字符串值原样、其它类型 -1）；设置它只为在测试里构造原始值与类型化值的分歧。
type Attr struct {
	Namespace  string
	Name       string
	ResourceID uint32
	Value      Value
	Raw        *string
}

// StringAttr 构造字符串属性。
func StringAttr(ns, name string, id uint32, s string) Attr {
	return Attr{Namespace: ns, Name: name, ResourceID: id, Value: Value{Type: TypeString, String: s}}
}

// IntAttr 构造十进制整数属性。
func IntAttr(ns, name string, id uint32, n int64) Attr {
	return Attr{Namespace: ns, Name: name, ResourceID: id, Value: Value{Type: TypeIntDec, Data: uint32(int32(n))}}
}

// BoolAttr 构造布尔属性。Android 的 true 是 0xffffffff。
func BoolAttr(ns, name string, id uint32, b bool) Attr {
	var data uint32
	if b {
		data = 0xffffffff
	}
	return Attr{Namespace: ns, Name: name, ResourceID: id, Value: Value{Type: TypeIntBoolean, Data: data}}
}

// AndroidAttr 构造 android: 命名空间下的框架属性。名字不在框架属性表里时 panic——
// 只给测试与签名闸合成试签包这类写死的调用用。
func AndroidAttr(name string, v Value) Attr {
	id, ok := FrameworkAttrID(name)
	if !ok {
		panic("axml: unknown framework attribute " + name)
	}
	return Attr{Namespace: AndroidNS, Name: name, ResourceID: id, Value: v}
}

// StringValue、IntValue、BoolValue 是构造 Value 的便捷函数。
func StringValue(s string) Value { return Value{Type: TypeString, String: s} }

// IntValue 构造十进制整数值。
func IntValue(n int64) Value { return Value{Type: TypeIntDec, Data: uint32(int32(n))} }

// BoolValue 构造布尔值。
func BoolValue(b bool) Value {
	if b {
		return Value{Type: TypeIntBoolean, Data: 0xffffffff}
	}
	return Value{Type: TypeIntBoolean}
}

type poolKey struct {
	s  string
	id uint32
}

type encoder struct {
	index   map[poolKey]uint32
	strings []string
	resIDs  []uint32
}

func (e *encoder) intern(s string, id uint32) uint32 {
	k := poolKey{s, id}
	if i, ok := e.index[k]; ok {
		return i
	}
	i := uint32(len(e.strings))
	e.index[k] = i
	e.strings = append(e.strings, s)
	return i
}

// Encode 把元素树编码成二进制 XML：UTF-8 字符串池，带资源 ID 的属性名排在池首并
// 对应资源表，属性按给定顺序写出（调用方负责按资源 ID 升序，测试可以故意打乱）。
func Encode(root *Node) ([]byte, error) {
	if root == nil {
		return nil, errors.New("axml: nil root")
	}
	e := &encoder{index: map[poolKey]uint32{}}
	// 第一遍：带资源 ID 的属性名进池首
	var namespaces []string
	nsSeen := map[string]bool{}
	var walkIDs func(n *Node) error
	walkIDs = func(n *Node) error {
		if n.Name == "" {
			return errors.New("axml: element with empty name")
		}
		for _, a := range n.Attrs {
			if a.Name == "" {
				return fmt.Errorf("axml: attribute with empty name on %s", n.Name)
			}
			if a.ResourceID != 0 {
				before := len(e.strings)
				e.intern(a.Name, a.ResourceID)
				if len(e.strings) > before {
					e.resIDs = append(e.resIDs, a.ResourceID)
				}
			}
			if a.Namespace != "" && !nsSeen[a.Namespace] {
				nsSeen[a.Namespace] = true
				namespaces = append(namespaces, a.Namespace)
			}
		}
		for _, c := range n.Children {
			if err := walkIDs(c); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walkIDs(root); err != nil {
		return nil, err
	}
	sort.Strings(namespaces)
	prefixes := make([]string, len(namespaces))
	other := 0
	for i, ns := range namespaces {
		if ns == AndroidNS {
			prefixes[i] = "android"
		} else {
			prefixes[i] = fmt.Sprintf("ns%d", other)
			other++
		}
	}

	var body []byte
	line := uint32(1)
	nodeHeader := func(typ uint16, size uint32) []byte {
		b := make([]byte, nodeHeaderSize)
		binary.LittleEndian.PutUint16(b, typ)
		binary.LittleEndian.PutUint16(b[2:], nodeHeaderSize)
		binary.LittleEndian.PutUint32(b[4:], size)
		binary.LittleEndian.PutUint32(b[8:], line)
		binary.LittleEndian.PutUint32(b[12:], noIndex)
		line++
		return b
	}
	for i, ns := range namespaces {
		b := nodeHeader(chunkStartNamespace, nodeHeaderSize+namespaceExtSize)
		b = binary.LittleEndian.AppendUint32(b, e.intern(prefixes[i], 0))
		b = binary.LittleEndian.AppendUint32(b, e.intern(ns, 0))
		body = append(body, b...)
	}
	var writeNode func(n *Node) error
	writeNode = func(n *Node) error {
		if len(n.Attrs) > 0xffff {
			return errors.New("axml: too many attributes")
		}
		size := uint32(nodeHeaderSize + attrExtSize + attributeSize*len(n.Attrs))
		b := nodeHeader(chunkStartElement, size)
		nameIndex := e.intern(n.Name, 0)
		b = binary.LittleEndian.AppendUint32(b, noIndex)
		b = binary.LittleEndian.AppendUint32(b, nameIndex)
		b = binary.LittleEndian.AppendUint16(b, attrExtSize)
		b = binary.LittleEndian.AppendUint16(b, attributeSize)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(n.Attrs)))
		b = append(b, 0, 0, 0, 0, 0, 0) // id/class/style index
		for _, a := range n.Attrs {
			ns := uint32(noIndex)
			if a.Namespace != "" {
				ns = e.intern(a.Namespace, 0)
			}
			name := e.intern(a.Name, a.ResourceID)
			data := a.Value.Data
			raw := uint32(noIndex)
			if a.Value.Type == TypeString {
				data = e.intern(a.Value.String, 0)
				raw = data
			}
			if a.Raw != nil {
				raw = e.intern(*a.Raw, 0)
			}
			b = binary.LittleEndian.AppendUint32(b, ns)
			b = binary.LittleEndian.AppendUint32(b, name)
			b = binary.LittleEndian.AppendUint32(b, raw)
			b = binary.LittleEndian.AppendUint16(b, 8)
			b = append(b, 0, a.Value.Type)
			b = binary.LittleEndian.AppendUint32(b, data)
		}
		body = append(body, b...)
		for _, c := range n.Children {
			if err := writeNode(c); err != nil {
				return err
			}
		}
		end := nodeHeader(chunkEndElement, nodeHeaderSize+endElementExtSize)
		end = binary.LittleEndian.AppendUint32(end, noIndex)
		end = binary.LittleEndian.AppendUint32(end, nameIndex)
		body = append(body, end...)
		return nil
	}
	if err := writeNode(root); err != nil {
		return nil, err
	}
	for i := len(namespaces) - 1; i >= 0; i-- {
		b := nodeHeader(chunkEndNamespace, nodeHeaderSize+namespaceExtSize)
		b = binary.LittleEndian.AppendUint32(b, e.intern(prefixes[i], 0))
		b = binary.LittleEndian.AppendUint32(b, e.intern(namespaces[i], 0))
		body = append(body, b...)
	}

	pool, err := e.stringPool()
	if err != nil {
		return nil, err
	}
	resMap := make([]byte, 8, 8+4*len(e.resIDs))
	binary.LittleEndian.PutUint16(resMap, chunkResourceMap)
	binary.LittleEndian.PutUint16(resMap[2:], 8)
	binary.LittleEndian.PutUint32(resMap[4:], uint32(8+4*len(e.resIDs)))
	for _, id := range e.resIDs {
		resMap = binary.LittleEndian.AppendUint32(resMap, id)
	}

	out := make([]byte, 8, 8+len(pool)+len(resMap)+len(body))
	binary.LittleEndian.PutUint16(out, chunkXML)
	binary.LittleEndian.PutUint16(out[2:], 8)
	out = append(out, pool...)
	out = append(out, resMap...)
	out = append(out, body...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

func (e *encoder) stringPool() ([]byte, error) {
	var data []byte
	offsets := make([]uint32, len(e.strings))
	for i, s := range e.strings {
		offsets[i] = uint32(len(data))
		u16 := len(utf16.Encode([]rune(s)))
		if u16 > 0x7fff || len(s) > 0x7fff {
			return nil, fmt.Errorf("axml: string %d is too long", i)
		}
		data = appendLength8(data, u16)
		data = appendLength8(data, len(s))
		data = append(data, s...)
		data = append(data, 0)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	headerAndOffsets := stringPoolHeaderSize + 4*len(e.strings)
	size := headerAndOffsets + len(data)
	b := make([]byte, stringPoolHeaderSize, size)
	binary.LittleEndian.PutUint16(b, chunkStringPool)
	binary.LittleEndian.PutUint16(b[2:], stringPoolHeaderSize)
	binary.LittleEndian.PutUint32(b[4:], uint32(size))
	binary.LittleEndian.PutUint32(b[8:], uint32(len(e.strings)))
	binary.LittleEndian.PutUint32(b[12:], 0)
	binary.LittleEndian.PutUint32(b[16:], utf8Flag)
	if len(e.strings) > 0 {
		binary.LittleEndian.PutUint32(b[20:], uint32(headerAndOffsets))
	}
	binary.LittleEndian.PutUint32(b[24:], 0)
	for _, o := range offsets {
		b = binary.LittleEndian.AppendUint32(b, o)
	}
	return append(b, data...), nil
}

func appendLength8(b []byte, n int) []byte {
	if n > 0x7f {
		return append(b, byte(0x80|n>>8), byte(n))
	}
	return append(b, byte(n))
}
