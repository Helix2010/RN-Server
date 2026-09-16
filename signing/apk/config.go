package apk

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// ExpoConfig 是内嵌 Expo 配置里与信任根相关的字段。字段缺失或类型不对时为 nil。
type ExpoConfig struct {
	Slug                   *string // slug
	Scheme                 *string // scheme
	AndroidPackage         *string // android.package
	Version                *string // version
	APIBaseURL             *string // extra.apiBaseUrl
	BootstrapSignerAddress *string // extra.bootstrapSignerAddress
	ApplicationID          *string // extra.applicationId
	DistributionChannel    *string // extra.distributionChannel
	UpdatesURL             *string // updates.url
	UpdatesEnabled         *bool   // updates.enabled
	AndroidVersionCode     *int64  // android.versionCode
}

const maxJSONDepth = 64

// parseStrictJSONObject 解析顶层必须是对象的 JSON：拒绝非法 UTF-8、任何层级的重复键、
// 尾随数据与过深嵌套。重复键必须拒：Go、JavaScript 取最后一个，Java 的 JSONObject 直接报错，
// 同一份文件在不同读者眼里不是同一个配置。
func parseStrictJSONObject(raw []byte, entry string) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid UTF-8", entry)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not a JSON object", entry)
	}
	obj, err := readObject(dec, entry, "", 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s has trailing data after the JSON object", entry)
	}
	return obj, nil
}

func readValue(dec *json.Decoder, entry, path string, depth int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth >= maxJSONDepth {
			return nil, errorf(CodeEmbeddedConfigInvalid, "%s nests deeper than %d levels", entry, maxJSONDepth)
		}
		switch v {
		case '{':
			return readObject(dec, entry, path, depth+1)
		case '[':
			var arr []any
			for dec.More() {
				item, err := readValue(dec, entry, path+"[]", depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, item)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
			}
			return arr, nil
		default:
			return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
		}
	default:
		return v, nil
	}
}

func readObject(dec *json.Decoder, entry, path string, depth int) (map[string]any, error) {
	obj := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
		}
		keyPath := key
		if path != "" {
			keyPath = path + "." + key
		}
		if _, dup := obj[key]; dup {
			return nil, errorf(CodeEmbeddedConfigDupKey, "%s has duplicate key %s", entry, quotePath(keyPath))
		}
		value, err := readValue(dec, entry, keyPath, depth)
		if err != nil {
			return nil, err
		}
		obj[key] = value
	}
	if end, err := dec.Token(); err != nil || end != json.Delim('}') {
		return nil, errorf(CodeEmbeddedConfigInvalid, "%s is not valid JSON", entry)
	}
	return obj, nil
}

func quotePath(p string) string {
	const max = 128
	if len(p) > max {
		p = p[:max]
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range p {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func lookup(obj map[string]any, path ...string) (any, bool) {
	var cur any = obj
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[key]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func stringAt(obj map[string]any, path ...string) *string {
	v, ok := lookup(obj, path...)
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func boolAt(obj map[string]any, path ...string) *bool {
	v, ok := lookup(obj, path...)
	if !ok {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

func intAt(obj map[string]any, path ...string) *int64 {
	v, ok := lookup(obj, path...)
	if !ok {
		return nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return nil
	}
	i, err := n.Int64()
	if err != nil {
		return nil
	}
	return &i
}

func expoConfigFrom(obj map[string]any) *ExpoConfig {
	return &ExpoConfig{
		Slug:                   stringAt(obj, "slug"),
		Scheme:                 stringAt(obj, "scheme"),
		AndroidPackage:         stringAt(obj, "android", "package"),
		Version:                stringAt(obj, "version"),
		APIBaseURL:             stringAt(obj, "extra", "apiBaseUrl"),
		BootstrapSignerAddress: stringAt(obj, "extra", "bootstrapSignerAddress"),
		ApplicationID:          stringAt(obj, "extra", "applicationId"),
		DistributionChannel:    stringAt(obj, "extra", "distributionChannel"),
		UpdatesURL:             stringAt(obj, "updates", "url"),
		UpdatesEnabled:         boolAt(obj, "updates", "enabled"),
		AndroidVersionCode:     intAt(obj, "android", "versionCode"),
	}
}

func fingerprintValue(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", errorf(CodeEmbeddedConfigInvalid, "%s is not valid UTF-8", FingerprintEntry)
	}
	return strings.TrimSpace(string(raw)), nil
}
