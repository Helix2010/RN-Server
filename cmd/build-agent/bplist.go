package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf16"
)

// 二进制 plist（`bplist00`）的只读解析器。
//
// 用在 `.ipa` 里的 `Info.plist` 上：Xcode 导出的那一份是二进制格式。控制进程要从包里读出
// bundle id、版本与 build 号，与任务行比对之后才交给上传账户——**不对这个文件调 plutil
// 或 unzip**（设计 ios-mac-builders-home-network-2026-09-18 §4.3 第 1 步）：它是执行进程
// 交上来的东西，而执行进程跑的是第三方代码。用解析器而不是子进程，最坏的结果是解析失败。
//
// 只实现读需要的那些类型。解析全程按不可信输入处理：每一处偏移都查边界，对象引用不允许
// 指向自己或往回指（防构造出来的环让解析器打转）。
type bplistParser struct {
	data       []byte
	offsets    []uint64
	refSize    int
	numObjects uint64
	// depth 限制嵌套层数：Info.plist 是几层的字典，深到 32 层只可能是构造出来的
	depth int
}

const bplistMaxDepth = 32

// parseBinaryPlist 解析一份二进制 plist，返回顶层对象。
func parseBinaryPlist(data []byte) (any, error) {
	const headerLen, trailerLen = 8, 32
	if len(data) < headerLen+trailerLen || string(data[:6]) != "bplist" {
		return nil, errors.New("not a binary plist")
	}
	trailer := data[len(data)-trailerLen:]
	offsetSize := int(trailer[6])
	refSize := int(trailer[7])
	numObjects := binary.BigEndian.Uint64(trailer[8:16])
	topObject := binary.BigEndian.Uint64(trailer[16:24])
	tableOffset := binary.BigEndian.Uint64(trailer[24:32])
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 {
		return nil, errors.New("binary plist has an unusable integer size")
	}
	// numObjects 直接决定一次分配的大小，先按文件长度封顶
	if numObjects == 0 || numObjects > uint64(len(data)) || topObject >= numObjects {
		return nil, errors.New("binary plist object count is out of range")
	}
	end := tableOffset + numObjects*uint64(offsetSize)
	if tableOffset < headerLen || end > uint64(len(data)-trailerLen) {
		return nil, errors.New("binary plist offset table is out of range")
	}
	p := &bplistParser{data: data, refSize: refSize, numObjects: numObjects}
	p.offsets = make([]uint64, numObjects)
	for i := uint64(0); i < numObjects; i++ {
		start := tableOffset + i*uint64(offsetSize)
		p.offsets[i] = beUint(data[start : start+uint64(offsetSize)])
		if p.offsets[i] >= tableOffset {
			return nil, errors.New("binary plist object offset points outside the object table")
		}
	}
	return p.object(topObject)
}

// beUint 读一个 1–8 字节的大端无符号整数。
func beUint(b []byte) uint64 {
	var out uint64
	for _, c := range b {
		out = out<<8 | uint64(c)
	}
	return out
}

func (p *bplistParser) object(ref uint64) (any, error) {
	if ref >= p.numObjects {
		return nil, errors.New("binary plist object reference is out of range")
	}
	if p.depth++; p.depth > bplistMaxDepth {
		return nil, errors.New("binary plist is nested too deeply")
	}
	defer func() { p.depth-- }()
	at := p.offsets[ref]
	if at >= uint64(len(p.data)) {
		return nil, errors.New("binary plist object offset is out of range")
	}
	marker := p.data[at]
	kind, info := marker>>4, uint64(marker&0x0f)
	body := at + 1
	// 低四位是 0xF 时，长度另有一个整数对象跟在后面
	countable := kind == 0x4 || kind == 0x5 || kind == 0x6 || kind == 0xa || kind == 0xc || kind == 0xd
	if countable && info == 0x0f {
		length, next, err := p.integerAt(body)
		if err != nil {
			return nil, err
		}
		info, body = length, next
	}
	switch kind {
	case 0x0:
		switch marker {
		case 0x00:
			return nil, nil
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		}
		return nil, fmt.Errorf("binary plist has an unsupported marker %#x", marker)
	case 0x1: // 整数：2^info 字节
		size := uint64(1) << info
		b, err := p.slice(body, size)
		if err != nil {
			return nil, err
		}
		if size == 8 {
			return int64(binary.BigEndian.Uint64(b)), nil
		}
		return int64(beUint(b)), nil
	case 0x2: // 浮点
		size := uint64(1) << info
		b, err := p.slice(body, size)
		if err != nil {
			return nil, err
		}
		switch size {
		case 4:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
		case 8:
			return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
		}
		return nil, errors.New("binary plist real has an unusable size")
	case 0x3: // 日期：2001-01-01 起的秒数
		b, err := p.slice(body, 8)
		if err != nil {
			return nil, err
		}
		seconds := math.Float64frombits(binary.BigEndian.Uint64(b))
		return time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(seconds * float64(time.Second))), nil
	case 0x4: // data
		b, err := p.slice(body, info)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), b...), nil
	case 0x5: // ASCII 字符串
		b, err := p.slice(body, info)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 0x6: // UTF-16BE 字符串
		b, err := p.slice(body, info*2)
		if err != nil {
			return nil, err
		}
		units := make([]uint16, info)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(b[i*2:])
		}
		return string(utf16.Decode(units)), nil
	case 0xa, 0xc: // 数组、集合
		refs, err := p.refs(body, info)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(refs))
		for _, r := range refs {
			value, err := p.object(r)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	case 0xd: // 字典：先 n 个键引用，再 n 个值引用
		keys, err := p.refs(body, info)
		if err != nil {
			return nil, err
		}
		values, err := p.refs(body+info*uint64(p.refSize), info)
		if err != nil {
			return nil, err
		}
		out := make(map[string]any, len(keys))
		for i, keyRef := range keys {
			key, err := p.object(keyRef)
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("binary plist dictionary key is not a string")
			}
			if out[name], err = p.object(values[i]); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("binary plist has an unsupported object type %#x", kind)
}

// integerAt 读一个紧跟在标记后面的整数对象（长度前缀用）。
func (p *bplistParser) integerAt(at uint64) (value, next uint64, err error) {
	if at >= uint64(len(p.data)) {
		return 0, 0, errors.New("binary plist length prefix is out of range")
	}
	marker := p.data[at]
	if marker>>4 != 0x1 {
		return 0, 0, errors.New("binary plist length prefix is not an integer")
	}
	size := uint64(1) << uint64(marker&0x0f)
	b, err := p.slice(at+1, size)
	if err != nil {
		return 0, 0, err
	}
	return beUint(b), at + 1 + size, nil
}

func (p *bplistParser) refs(at, count uint64) ([]uint64, error) {
	b, err := p.slice(at, count*uint64(p.refSize))
	if err != nil {
		return nil, err
	}
	out := make([]uint64, count)
	for i := uint64(0); i < count; i++ {
		out[i] = beUint(b[i*uint64(p.refSize) : (i+1)*uint64(p.refSize)])
	}
	return out, nil
}

// slice 取一段并查边界。长度相加要防溢出：count 来自文件里的数。
func (p *bplistParser) slice(at, count uint64) ([]byte, error) {
	if at > uint64(len(p.data)) || count > uint64(len(p.data)) || at+count > uint64(len(p.data)) {
		return nil, errors.New("binary plist value runs past the end of the file")
	}
	return p.data[at : at+count], nil
}
