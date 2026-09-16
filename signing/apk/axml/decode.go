package axml

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// 块类型。
const (
	chunkStringPool     = 0x0001
	chunkXML            = 0x0003
	chunkStartNamespace = 0x0100
	chunkEndNamespace   = 0x0101
	chunkStartElement   = 0x0102
	chunkEndElement     = 0x0103
	chunkCDATA          = 0x0104
	chunkResourceMap    = 0x0180

	noIndex = 0xffffffff

	stringPoolHeaderSize = 28
	utf8Flag             = 0x100
	sortedFlag           = 0x1

	nodeHeaderSize    = 16
	attrExtSize       = 20
	attributeSize     = 20
	namespaceExtSize  = 8
	endElementExtSize = 8
)

// Limits 限制解析一个不可信文件时的资源消耗。
type Limits struct {
	MaxSize       int // 整个文件字节数
	MaxStrings    int // 字符串池条目数
	MaxElements   int // 元素总数
	MaxDepth      int // 元素嵌套深度
	MaxAttributes int // 单个元素的属性数
	// MaxStringBytes 是字符串池解码结果的总字节数（同一偏移只算一次）。不同偏移可以指向互相重叠的
	// 长串（例如一串长度头逐个递减、共用同一个结尾 NUL），逐个解码的总量随池大小平方增长；
	// 没有这个总量上限，几 MiB 的清单就能让检查进程分配几 GiB。
	MaxStringBytes int
}

// DefaultLimits 远大于真实清单（anyfun 1.3.16：34 KiB、213 个字符串、约 400 个元素）。
// MaxStringBytes 是 MaxSize 的 2 倍：不重叠的池解码后最多是文件大小的 1.5 倍（UTF-16 每单元最多 3 字节 UTF-8）。
func DefaultLimits() Limits {
	return Limits{MaxSize: 8 << 20, MaxStrings: 100000, MaxElements: 50000, MaxDepth: 64, MaxAttributes: 256, MaxStringBytes: 16 << 20}
}

// Document 是解析结果。
type Document struct {
	Root *Element
}

// Element 是一个元素。
type Element struct {
	Namespace string
	Name      string
	Attrs     []Attribute
	Children  []*Element
	Line      uint32
}

// Attribute 是一个属性。ResourceID 是 Android 实际用来识别它的资源 ID（没有为 0）。
type Attribute struct {
	Namespace  string
	Name       string
	ResourceID uint32
	Value      Value
}

// Attr 按资源 ID 查找属性。
func (e *Element) Attr(id uint32) (Attribute, bool) {
	for _, a := range e.Attrs {
		if a.ResourceID == id {
			return a, true
		}
	}
	return Attribute{}, false
}

// AttrByName 按命名空间与名字查找没有资源 ID 的属性（例如 <manifest package>）。
func (e *Element) AttrByName(namespace, name string) (Attribute, bool) {
	for _, a := range e.Attrs {
		if a.Namespace == namespace && a.Name == name {
			return a, true
		}
	}
	return Attribute{}, false
}

type decoder struct {
	data    []byte
	lim     Limits
	strings []string
	resIDs  []uint32
}

// Decode 严格解析二进制 XML。任何结构问题返回 *Error。
func Decode(data []byte, lim Limits) (*Document, error) {
	if len(data) > lim.MaxSize {
		return nil, errorf(CodeMalformed, "binary XML is %d bytes, over the %d byte limit", len(data), lim.MaxSize)
	}
	if len(data) < 8 {
		return nil, errorf(CodeMalformed, "binary XML is too short")
	}
	typ, headerSize, size := chunkHeader(data)
	if typ != chunkXML || headerSize != 8 || int(size) != len(data) || size%4 != 0 {
		return nil, errorf(CodeMalformed, "not a binary XML document (type 0x%04x, header %d, size %d, file %d)", typ, headerSize, size, len(data))
	}
	d := &decoder{data: data, lim: lim}
	return d.decode()
}

func chunkHeader(b []byte) (typ uint16, headerSize uint16, size uint32) {
	return binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:])
}

type frameKind int

const (
	frameNamespace frameKind = iota
	frameElement
)

type frame struct {
	kind      frameKind
	prefix    uint32
	uri       uint32
	nsIndex   uint32
	nameIndex uint32
	element   *Element
}

func (d *decoder) decode() (*Document, error) {
	off := 8
	seenPool := false
	seenMap := false
	seenNode := false
	rootClosed := false
	var root *Element
	var stack []frame
	elements := 0
	depth := 0
	// 在作用域里的命名空间 URI（字符串内容），用于校验属性命名空间是否声明过
	var scopes []string

	for off < len(d.data) {
		if len(d.data)-off < 8 {
			return nil, errorf(CodeMalformed, "truncated chunk header at offset %d", off)
		}
		typ, headerSize, size := chunkHeader(d.data[off:])
		if headerSize < 8 || uint32(headerSize) > size || uint64(size) > uint64(len(d.data)-off) || (size|uint32(headerSize))%4 != 0 {
			return nil, errorf(CodeMalformed, "chunk at offset %d has an invalid header (type 0x%04x, header %d, size %d)", off, typ, headerSize, size)
		}
		chunk := d.data[off : off+int(size)]
		switch typ {
		case chunkStringPool:
			if seenPool || seenMap || seenNode {
				return nil, errorf(CodeMalformed, "string pool must be the first and only one")
			}
			if err := d.parseStringPool(chunk); err != nil {
				return nil, err
			}
			seenPool = true
		case chunkResourceMap:
			if !seenPool || seenMap || seenNode {
				return nil, errorf(CodeMalformed, "resource map must directly follow the string pool and appear once")
			}
			if headerSize != 8 || (size-8)%4 != 0 {
				return nil, errorf(CodeMalformed, "resource map has an invalid size")
			}
			n := int(size-8) / 4
			d.resIDs = make([]uint32, n)
			for i := 0; i < n; i++ {
				d.resIDs[i] = binary.LittleEndian.Uint32(chunk[8+4*i:])
			}
			seenMap = true
		case chunkStartNamespace, chunkEndNamespace, chunkStartElement, chunkEndElement:
			if !seenPool {
				return nil, errorf(CodeMalformed, "node before the string pool")
			}
			seenNode = true
			if headerSize != nodeHeaderSize {
				return nil, errorf(CodeMalformed, "node at offset %d has header size %d, want 16", off, headerSize)
			}
			comment := binary.LittleEndian.Uint32(chunk[12:])
			if comment != noIndex && !d.validIndex(comment) {
				return nil, errorf(CodeMalformed, "node comment string index out of range")
			}
			line := binary.LittleEndian.Uint32(chunk[8:])
			ext := chunk[nodeHeaderSize:]
			switch typ {
			case chunkStartNamespace, chunkEndNamespace:
				if size != nodeHeaderSize+namespaceExtSize {
					return nil, errorf(CodeMalformed, "namespace node has size %d", size)
				}
				prefix := binary.LittleEndian.Uint32(ext)
				uri := binary.LittleEndian.Uint32(ext[4:])
				if (prefix != noIndex && !d.validIndex(prefix)) || !d.validIndex(uri) {
					return nil, errorf(CodeMalformed, "namespace node string index out of range")
				}
				if typ == chunkStartNamespace {
					if rootClosed {
						return nil, errorf(CodeMalformed, "namespace declared after the root element closed")
					}
					stack = append(stack, frame{kind: frameNamespace, prefix: prefix, uri: uri})
					scopes = append(scopes, d.strings[uri])
				} else {
					if len(stack) == 0 || stack[len(stack)-1].kind != frameNamespace ||
						stack[len(stack)-1].prefix != prefix || stack[len(stack)-1].uri != uri {
						return nil, errorf(CodeMalformed, "namespace end does not match the open namespace")
					}
					stack = stack[:len(stack)-1]
					scopes = scopes[:len(scopes)-1]
				}
			case chunkStartElement:
				if rootClosed {
					return nil, errorf(CodeMalformed, "more than one root element")
				}
				elements++
				if elements > d.lim.MaxElements {
					return nil, errorf(CodeMalformed, "more than %d elements", d.lim.MaxElements)
				}
				depth++
				if depth > d.lim.MaxDepth {
					return nil, errorf(CodeMalformed, "elements nested deeper than %d", d.lim.MaxDepth)
				}
				el, nsIndex, nameIndex, err := d.parseStartElement(chunk, ext, scopes)
				if err != nil {
					return nil, err
				}
				el.Line = line
				if root == nil {
					root = el
				} else {
					parent := d.openElement(stack)
					if parent == nil {
						return nil, errorf(CodeMalformed, "element outside the root element")
					}
					parent.Children = append(parent.Children, el)
				}
				stack = append(stack, frame{kind: frameElement, nsIndex: nsIndex, nameIndex: nameIndex, element: el})
			case chunkEndElement:
				if size != nodeHeaderSize+endElementExtSize {
					return nil, errorf(CodeMalformed, "end element node has size %d", size)
				}
				ns := binary.LittleEndian.Uint32(ext)
				name := binary.LittleEndian.Uint32(ext[4:])
				if len(stack) == 0 || stack[len(stack)-1].kind != frameElement {
					return nil, errorf(CodeMalformed, "end element without a matching start")
				}
				top := stack[len(stack)-1]
				if !d.sameString(ns, top.nsIndex) || !d.sameString(name, top.nameIndex) {
					return nil, errorf(CodeMalformed, "end element does not match the open element %s", Quote(top.element.Name))
				}
				stack = stack[:len(stack)-1]
				depth--
				if depth == 0 {
					rootClosed = true
				}
			}
		case chunkCDATA:
			return nil, errorf(CodeMalformed, "CDATA nodes are not allowed in a manifest")
		default:
			return nil, errorf(CodeMalformed, "unknown chunk type 0x%04x at offset %d", typ, off)
		}
		off += int(size)
	}
	if !seenPool {
		return nil, errorf(CodeMalformed, "no string pool")
	}
	if root == nil || !rootClosed {
		return nil, errorf(CodeMalformed, "no complete root element")
	}
	if len(stack) != 0 {
		return nil, errorf(CodeMalformed, "unbalanced namespaces or elements at end of document")
	}
	return &Document{Root: root}, nil
}

func (d *decoder) openElement(stack []frame) *Element {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].kind == frameElement {
			return stack[i].element
		}
	}
	return nil
}

func (d *decoder) validIndex(i uint32) bool { return uint64(i) < uint64(len(d.strings)) }

// sameString：两个索引相同，或都是 -1，或指向内容相同的字符串。
func (d *decoder) sameString(a, b uint32) bool {
	if a == b {
		return true
	}
	if a == noIndex || b == noIndex || !d.validIndex(a) || !d.validIndex(b) {
		return false
	}
	return d.strings[a] == d.strings[b]
}

func (d *decoder) parseStringPool(chunk []byte) error {
	_, headerSize, size := chunkHeader(chunk)
	if headerSize != stringPoolHeaderSize {
		return errorf(CodeStringPool, "string pool header size is %d, want 28", headerSize)
	}
	stringCount := binary.LittleEndian.Uint32(chunk[8:])
	styleCount := binary.LittleEndian.Uint32(chunk[12:])
	flags := binary.LittleEndian.Uint32(chunk[16:])
	stringsStart := binary.LittleEndian.Uint32(chunk[20:])
	stylesStart := binary.LittleEndian.Uint32(chunk[24:])
	if styleCount != 0 || stylesStart != 0 {
		return errorf(CodeStringPool, "styled strings are not allowed in a manifest")
	}
	if flags&^(utf8Flag|sortedFlag) != 0 {
		return errorf(CodeStringPool, "unknown string pool flags 0x%x", flags)
	}
	if uint64(stringCount) > uint64(d.lim.MaxStrings) {
		return errorf(CodeStringPool, "string pool has %d strings, over the %d limit", stringCount, d.lim.MaxStrings)
	}
	offsetsEnd := uint64(stringPoolHeaderSize) + 4*uint64(stringCount)
	if offsetsEnd > uint64(size) {
		return errorf(CodeStringPool, "string offsets overrun the pool")
	}
	if stringCount == 0 {
		if stringsStart != 0 && uint64(stringsStart) != offsetsEnd {
			return errorf(CodeStringPool, "empty string pool has a strings start")
		}
		d.strings = nil
		return nil
	}
	if uint64(stringsStart) < offsetsEnd || uint64(stringsStart) >= uint64(size) {
		return errorf(CodeStringPool, "strings start %d is outside the pool", stringsStart)
	}
	pool := chunk[stringsStart:size]
	utf8Pool := flags&utf8Flag != 0
	if !utf8Pool && len(pool)%2 != 0 {
		return errorf(CodeStringPool, "UTF-16 string data has odd length")
	}
	d.strings = make([]string, stringCount)
	// 同一偏移只解码一次，结果共享（Go 字符串共享底层字节）；解码总字节数有上限
	byOffset := make(map[uint32]string)
	budget := d.lim.MaxStringBytes
	for i := uint32(0); i < stringCount; i++ {
		offset := binary.LittleEndian.Uint32(chunk[stringPoolHeaderSize+4*i:])
		if uint64(offset) >= uint64(len(pool)) {
			return errorf(CodeStringPool, "string %d offset is outside the pool", i)
		}
		if s, ok := byOffset[offset]; ok {
			d.strings[i] = s
			continue
		}
		var (
			s   string
			err *Error
		)
		if utf8Pool {
			s, err = decodeUTF8String(pool[offset:], i, budget)
		} else {
			if offset%2 != 0 {
				return errorf(CodeStringPool, "string %d has an odd UTF-16 offset", i)
			}
			s, err = decodeUTF16String(pool[offset:], i, budget)
		}
		if err != nil {
			return err
		}
		budget -= len(s)
		byOffset[offset] = s
		d.strings[i] = s
	}
	return nil
}

// budgetError：解码到第 index 个字符串时总量超限。
func budgetError(index uint32) *Error {
	return errorf(CodeStringBudget, "decoding string %d exceeds the string pool budget; distinct offsets overlap into more text than a manifest can hold", index)
}

// allowedPoolRune：池里的字符串只允许 XML 1.0 能表达的字符，并排除 DEL 与 C1。
//
// aapt2 从 XML 源文件编出清单；XML 1.0 连字符引用都不能表达 U+0000 与 TAB/LF/CR 以外的 C0，
// 所以真实清单里不会有。U+0000 尤其要拒：aapt2 与 Android 的部分路径在 NUL 处截断，而这里读出整串，
// 同一个权限名或组件名两边看到的不一样。TAB/LF/CR 必须允许：expo-updates 的
// CODE_SIGNING_CERTIFICATE 是多行 PEM（anyfun 1.3.16 的清单里有 29 个 LF）。
// DEL 与 C1 与 ZIP 条目名规则一致一并拒绝（它们也是终端控制序列的来源）。
func allowedPoolRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return true
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return false
	}
	return true
}

// decodeUTF8String：先 UTF-16 长度，再 UTF-8 字节长度，各 1 或 2 字节，后面是字节和一个 NUL。
// budget 是剩余可解码字节数。
func decodeUTF8String(b []byte, index uint32, budget int) (string, *Error) {
	u16len, n, ok := decodeLength8(b)
	if !ok {
		return "", errorf(CodeStringPool, "string %d has a truncated length", index)
	}
	b = b[n:]
	u8len, n, ok := decodeLength8(b)
	if !ok {
		return "", errorf(CodeStringPool, "string %d has a truncated length", index)
	}
	b = b[n:]
	if u8len >= len(b) {
		return "", errorf(CodeStringPool, "string %d overruns the pool", index)
	}
	if u8len > budget {
		return "", budgetError(index)
	}
	raw := b[:u8len]
	if b[u8len] != 0 {
		return "", errorf(CodeStringPool, "string %d is not NUL-terminated", index)
	}
	if !utf8.Valid(raw) {
		return "", errorf(CodeStringPool, "string %d is not valid UTF-8", index)
	}
	actual := 0
	for _, r := range string(raw) {
		if !allowedPoolRune(r) {
			return "", errorf(CodeStringControl, "string %d contains control character U+%04X", index, r)
		}
		actual += utf16.RuneLen(r)
	}
	if actual != u16len {
		// Android 在这种情况下返回 null，我们却能读出字符串：分歧，拒绝
		return "", errorf(CodeStringPool, "string %d declares %d UTF-16 units but has %d", index, u16len, actual)
	}
	return string(raw), nil
}

func decodeLength8(b []byte) (length, consumed int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	length = int(b[0])
	if length&0x80 != 0 {
		if len(b) < 2 {
			return 0, 0, false
		}
		return (length&0x7f)<<8 | int(b[1]), 2, true
	}
	return length, 1, true
}

// decodeUTF16String：长度（1 或 2 个单元），后面是 UTF-16LE 单元和一个 NUL 单元。
// 第一遍只校验（代理对、控制字符）并算出 UTF-8 字节数，核对 budget 之后才分配，第二遍写出；
// 不分配中间的 []uint16 / []rune。
func decodeUTF16String(b []byte, index uint32, budget int) (string, *Error) {
	if len(b) < 2 {
		return "", errorf(CodeStringPool, "string %d has a truncated length", index)
	}
	length := int(binary.LittleEndian.Uint16(b))
	n := 2
	if length&0x8000 != 0 {
		if len(b) < 4 {
			return "", errorf(CodeStringPool, "string %d has a truncated length", index)
		}
		length = (length&0x7fff)<<16 | int(binary.LittleEndian.Uint16(b[2:]))
		n = 4
	}
	b = b[n:]
	if uint64(length)*2+2 > uint64(len(b)) {
		return "", errorf(CodeStringPool, "string %d overruns the pool", index)
	}
	if binary.LittleEndian.Uint16(b[2*length:]) != 0 {
		return "", errorf(CodeStringPool, "string %d is not NUL-terminated", index)
	}
	if length > budget { // 每个单元至少产出 1 字节
		return "", budgetError(index)
	}
	size := 0
	for i := 0; i < length; {
		r, consumed, err := utf16RuneAt(b, i, length, index)
		if err != nil {
			return "", err
		}
		i += consumed
		size += utf8.RuneLen(r)
	}
	if size > budget {
		return "", budgetError(index)
	}
	var out strings.Builder // Grow 一次、String 不再拷贝
	out.Grow(size)
	for i := 0; i < length; {
		r, consumed, _ := utf16RuneAt(b, i, length, index)
		i += consumed
		out.WriteRune(r)
	}
	return out.String(), nil
}

// utf16RuneAt 读第 i 个单元开始的一个字符，返回它占的单元数（1 或 2）。
func utf16RuneAt(b []byte, i, length int, index uint32) (rune, int, *Error) {
	u := rune(binary.LittleEndian.Uint16(b[2*i:]))
	r, consumed := u, 1
	switch {
	case u >= 0xd800 && u < 0xdc00:
		if i+1 >= length {
			return 0, 0, errorf(CodeStringPool, "string %d has an unpaired surrogate", index)
		}
		lo := rune(binary.LittleEndian.Uint16(b[2*(i+1):]))
		if lo < 0xdc00 || lo >= 0xe000 {
			return 0, 0, errorf(CodeStringPool, "string %d has an unpaired surrogate", index)
		}
		r, consumed = utf16.DecodeRune(u, lo), 2
	case u >= 0xdc00 && u < 0xe000:
		return 0, 0, errorf(CodeStringPool, "string %d has an unpaired surrogate", index)
	}
	if !allowedPoolRune(r) {
		return 0, 0, errorf(CodeStringControl, "string %d contains control character U+%04X", index, r)
	}
	return r, consumed, nil
}

func (d *decoder) parseStartElement(chunk, ext []byte, scopes []string) (*Element, uint32, uint32, error) {
	if len(ext) < attrExtSize {
		return nil, 0, 0, errorf(CodeMalformed, "start element node is truncated")
	}
	nsIndex := binary.LittleEndian.Uint32(ext)
	nameIndex := binary.LittleEndian.Uint32(ext[4:])
	attributeStart := binary.LittleEndian.Uint16(ext[8:])
	attrSize := binary.LittleEndian.Uint16(ext[10:])
	attributeCount := binary.LittleEndian.Uint16(ext[12:])
	idIndex := binary.LittleEndian.Uint16(ext[14:])
	classIndex := binary.LittleEndian.Uint16(ext[16:])
	styleIndex := binary.LittleEndian.Uint16(ext[18:])
	if nsIndex != noIndex {
		return nil, 0, 0, errorf(CodeMalformed, "elements must not have a namespace")
	}
	if !d.validIndex(nameIndex) {
		return nil, 0, 0, errorf(CodeMalformed, "element name string index out of range")
	}
	name := d.strings[nameIndex]
	if name == "" {
		return nil, 0, 0, errorf(CodeMalformed, "element has an empty name")
	}
	if attributeStart != attrExtSize || attrSize != attributeSize {
		return nil, 0, 0, errorf(CodeMalformed, "element %s has attributeStart %d / attributeSize %d, want 20 / 20", Quote(name), attributeStart, attrSize)
	}
	if int(attributeCount) > d.lim.MaxAttributes {
		return nil, 0, 0, errorf(CodeMalformed, "element %s has %d attributes, over the %d limit", Quote(name), attributeCount, d.lim.MaxAttributes)
	}
	if idIndex > attributeCount || classIndex > attributeCount || styleIndex > attributeCount {
		return nil, 0, 0, errorf(CodeMalformed, "element %s has an id/class/style index beyond its attributes", Quote(name))
	}
	if len(chunk) != nodeHeaderSize+attrExtSize+attributeSize*int(attributeCount) {
		return nil, 0, 0, errorf(CodeMalformed, "element %s node size does not match its attribute count", Quote(name))
	}
	el := &Element{Name: name, Attrs: make([]Attribute, 0, attributeCount)}
	var lastID uint32
	seenIDs := make(map[uint32]bool, attributeCount)
	type nsName struct{ ns, name string }
	seenNames := make(map[nsName]bool, attributeCount)
	for i := 0; i < int(attributeCount); i++ {
		a := ext[attrExtSize+attributeSize*i:]
		attrNS := binary.LittleEndian.Uint32(a)
		attrName := binary.LittleEndian.Uint32(a[4:])
		raw := binary.LittleEndian.Uint32(a[8:])
		valueSize := binary.LittleEndian.Uint16(a[12:])
		res0 := a[14]
		dataType := a[15]
		data := binary.LittleEndian.Uint32(a[16:])
		if !d.validIndex(attrName) || d.strings[attrName] == "" {
			return nil, 0, 0, errorf(CodeMalformed, "element %s has an attribute with an invalid name", Quote(name))
		}
		attr := Attribute{Name: d.strings[attrName]}
		if attrNS != noIndex {
			if !d.validIndex(attrNS) {
				return nil, 0, 0, errorf(CodeMalformed, "attribute %s namespace index out of range", Quote(attr.Name))
			}
			attr.Namespace = d.strings[attrNS]
			if !inScope(scopes, attr.Namespace) {
				return nil, 0, 0, errorf(CodeNamespace, "attribute %s uses an undeclared namespace %s", Quote(attr.Name), Quote(attr.Namespace))
			}
		}
		if valueSize != 8 || res0 != 0 {
			return nil, 0, 0, errorf(CodeMalformed, "attribute %s has a malformed value header", Quote(attr.Name))
		}
		if !validType(dataType) {
			return nil, 0, 0, errorf(CodeMalformed, "attribute %s has unknown value type 0x%02x", Quote(attr.Name), dataType)
		}
		attr.Value = Value{Type: dataType, Data: data}
		if dataType == TypeString {
			if !d.validIndex(data) {
				return nil, 0, 0, errorf(CodeMalformed, "attribute %s string value index out of range", Quote(attr.Name))
			}
			if raw != data {
				return nil, 0, 0, errorf(CodeRawValueMismatch, "attribute %s raw string differs from its typed string value", Quote(attr.Name))
			}
			attr.Value.String = d.strings[data]
		} else if raw != noIndex {
			return nil, 0, 0, errorf(CodeRawValueMismatch, "attribute %s carries a raw string next to a typed value", Quote(attr.Name))
		}

		if uint64(attrName) < uint64(len(d.resIDs)) {
			attr.ResourceID = d.resIDs[attrName]
		}
		if err := checkIdentity(attr); err != nil {
			return nil, 0, 0, err
		}
		if attr.ResourceID != 0 {
			if seenIDs[attr.ResourceID] {
				return nil, 0, 0, errorf(CodeDuplicateAttribute, "element %s has attribute id 0x%08x twice", Quote(name), attr.ResourceID)
			}
			seenIDs[attr.ResourceID] = true
			if attr.ResourceID <= lastID {
				return nil, 0, 0, errorf(CodeAttributeOrder, "element %s attribute %s is not in ascending resource id order", Quote(name), Quote(attr.Name))
			}
			lastID = attr.ResourceID
		}
		key := nsName{attr.Namespace, attr.Name}
		if seenNames[key] {
			return nil, 0, 0, errorf(CodeDuplicateAttribute, "element %s has attribute %s twice", Quote(name), Quote(attr.Name))
		}
		seenNames[key] = true
		el.Attrs = append(el.Attrs, attr)
	}
	return el, nsIndex, nameIndex, nil
}

func inScope(scopes []string, uri string) bool {
	for i := len(scopes) - 1; i >= 0; i-- {
		if scopes[i] == uri {
			return true
		}
	}
	return false
}

// checkIdentity 保证"名字"和"资源 ID"说的是同一个属性。Android 读清单属性时按资源 ID
// （不看命名空间和名字），我们也按 ID 读；这里挡住两者不一致的构造。
func checkIdentity(a Attribute) *Error {
	id := a.ResourceID
	switch pkg := id >> 24; {
	case id == 0:
		if a.Namespace == AndroidNS {
			if _, known := FrameworkAttrID(a.Name); known {
				return errorf(CodeAttributeIDMismatch, "android:%s has no resource id", Quote(a.Name))
			}
		}
		return nil
	case pkg == 0x01:
		want, known := FrameworkAttrName(id)
		if !known {
			return errorf(CodeUnknownFrameworkAttribute, "attribute %s has resource id 0x%08x, which is not a known framework attribute", Quote(a.Name), id)
		}
		if a.Namespace != AndroidNS {
			return errorf(CodeNamespace, "attribute %s has framework resource id 0x%08x outside the android namespace", Quote(a.Name), id)
		}
		if a.Name != want {
			return errorf(CodeAttributeIDMismatch, "attribute named %s carries the resource id of android:%s", Quote(a.Name), want)
		}
		return nil
	case pkg == 0x00:
		return errorf(CodeAttributeIDMismatch, "attribute %s has a dynamic resource id 0x%08x", Quote(a.Name), id)
	default:
		if a.Namespace == AndroidNS {
			return errorf(CodeAttributeIDMismatch, "android:%s has non-framework resource id 0x%08x", Quote(a.Name), id)
		}
		return nil
	}
}
