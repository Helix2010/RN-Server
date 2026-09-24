package plist

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// XML plist 的最小解析器。用在描述文件（`.mobileprovision`）上：那是一个 CMS 签名块，
// 里面包着一份 XML plist。Mac 上的控制进程盘点描述文件时读它，服务端核对自助上传的 .ipa
// 里嵌着的那一份时也读它。
//
// **为什么不调 `security cms -D -i` / `plutil`**：这两个都要起子进程去解析一份文件，而
// 调用方（控制进程、服务端）持有令牌与密钥。对 `.ipa` 的规矩在设计 §4.3 第 1 步已经写死
// （不对文件调 unzip / plutil），两处用同一套做法比记住"哪一处可以例外"便宜。纯 Go 还有
// 一个好处：在 Linux 上也能跑，测试不需要一台 Mac。
//
// 只实现用得到的类型：dict、array、string、integer、real、true/false、date、data（按原始
// base64 字符串给出，调用方自己解）。遇到不认识的标签直接报错，不猜。
//
// ParseXML 解析一份 XML plist，顶层必须是字典。
func ParseXML(data []byte) (map[string]any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("plist has no root element: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local != "plist" {
			return nil, fmt.Errorf("plist root element is %q", start.Name.Local)
		}
		value, err := plistNext(decoder)
		if err != nil {
			return nil, err
		}
		dict, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("plist root value is not a dictionary")
		}
		return dict, nil
	}
}

// plistNext 读下一个值元素。到 </plist> 或其它结束标签时返回 io.EOF 之外的 nil 值。
func plistNext(decoder *xml.Decoder) (any, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch element := token.(type) {
		case xml.EndElement:
			return nil, io.EOF
		case xml.StartElement:
			return plistValue(decoder, element)
		}
	}
}

func plistValue(decoder *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "dict":
		out := map[string]any{}
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch element := token.(type) {
			case xml.EndElement:
				return out, nil
			case xml.StartElement:
				if element.Name.Local != "key" {
					return nil, fmt.Errorf("plist dictionary has a %q where a key was expected", element.Name.Local)
				}
				var key string
				if err := decoder.DecodeElement(&key, &element); err != nil {
					return nil, err
				}
				value, err := plistNext(decoder)
				if err != nil {
					return nil, fmt.Errorf("plist key %q has no value: %w", key, err)
				}
				out[key] = value
			}
		}
	case "array":
		out := []any{}
		for {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			switch element := token.(type) {
			case xml.EndElement:
				return out, nil
			case xml.StartElement:
				value, err := plistValue(decoder, element)
				if err != nil {
					return nil, err
				}
				out = append(out, value)
			}
		}
	case "true", "false":
		if err := decoder.Skip(); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	case "string", "data":
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return nil, err
		}
		return text, nil
	case "date":
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return nil, fmt.Errorf("plist date %q: %w", text, err)
		}
		return at.UTC(), nil
	case "integer":
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return nil, err
		}
		number, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("plist integer %q: %w", text, err)
		}
		return number, nil
	case "real":
		var text string
		if err := decoder.DecodeElement(&text, &start); err != nil {
			return nil, err
		}
		number, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("plist real %q: %w", text, err)
		}
		return number, nil
	}
	return nil, fmt.Errorf("plist has an unsupported element %q", start.Name.Local)
}

// String / Dict / Time / Bool 是取值的小工具：类型不对当作没有这个键。
// 读这些文件的代码不该因为一个字段类型变了就 panic。
func String(dict map[string]any, key string) string {
	value, _ := dict[key].(string)
	return value
}

func Dict(dict map[string]any, key string) map[string]any {
	value, _ := dict[key].(map[string]any)
	return value
}

func Time(dict map[string]any, key string) time.Time {
	value, _ := dict[key].(time.Time)
	return value
}

func Bool(dict map[string]any, key string) bool {
	value, _ := dict[key].(bool)
	return value
}

// Parse 认二进制与 XML 两种 plist，顶层必须是字典：Xcode 导出的 Info.plist 是二进制，
// 手工造的测试数据与描述文件里的那份是 XML。
func Parse(raw []byte) (map[string]any, error) {
	if bytes.HasPrefix(raw, []byte("bplist")) {
		value, err := ParseBinary(raw)
		if err != nil {
			return nil, err
		}
		fields, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("plist root value is not a dictionary")
		}
		return fields, nil
	}
	return ParseXML(raw)
}
