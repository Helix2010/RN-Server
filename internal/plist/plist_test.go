package plist

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// 这两个解析器读的是执行进程交上来的文件（.ipa 里的 Info.plist）与运维放上来的描述文件，
// 按不可信输入处理：读得对，也不能被构造出来的文件带着打转或读到界外。

// realBinaryInfoPlist 是 Python plistlib 产出的真二进制 plist（bplist00），
// 里面既有字符串、布尔、整数，也有嵌套字典与数组——Xcode 导出的 Info.plist 就是这个形状。
const realBinaryInfoPlist = "YnBsaXN0MDDZAQIDBAUGBwgJCg8QERITFBUWXENGQnVuZGxlRGVlcF8QEkNGQnVuZGxlSWRlbnRpZmllclxDRkJ1bmRsZU5hbWVfEBRDRkJ1bmRsZU51bWVyaWNUaGluZ18QGkNGQnVuZGxlU2hvcnRWZXJzaW9uU3RyaW5nXxAPQ0ZCdW5kbGVWZXJzaW9uXxASTFNSZXF1aXJlc0lQaG9uZU9TXxAWVUlMYXVuY2hTdG9yeWJvYXJkTmFtZV8QHFVJUmVxdWlyZWREZXZpY2VDYXBhYmlsaXRpZXPRCwxRYdENDlFiUWNfEBVjb20uYW55ZnVuLmZvdW5kYXRpb25WQW55RnVuECpVMS4zLjdSMzMJXFNwbGFzaFNjcmVlbqEXVWFybXY3AAgAGwAoAD0ASgBhAH4AkAClAL4A3QDgAOIA5QDnAOkBAQEIAQoBEAETARQBIQEjAAAAAAAAAgEAAAAAAAAAGAAAAAAAAAAAAAAAAAAAASk="

func TestBinaryPlistReadsWhatXcodeWrites(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(realBinaryInfoPlist)
	if err != nil {
		t.Fatal(err)
	}
	value, err := ParseBinary(raw)
	if err != nil {
		t.Fatalf("a real binary plist was refused: %v", err)
	}
	fields, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("the root is %T", value)
	}
	for key, want := range map[string]string{
		"CFBundleIdentifier":         "com.anyfun.foundation",
		"CFBundleShortVersionString": "1.3.7",
		"CFBundleVersion":            "33",
		"CFBundleName":               "AnyFun",
	} {
		if got := String(fields, key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
	if fields["LSRequiresIPhoneOS"] != true || fields["CFBundleNumericThing"] != int64(42) {
		t.Fatalf("booleans and integers did not survive: %#v", fields)
	}
	if nested := Dict(Dict(fields, "CFBundleDeep"), "a"); String(nested, "b") != "c" {
		t.Fatalf("nested dictionaries did not survive: %#v", fields["CFBundleDeep"])
	}
	if list, _ := fields["UIRequiredDeviceCapabilities"].([]any); len(list) != 1 || list[0] != "armv7" {
		t.Fatalf("arrays did not survive: %#v", fields["UIRequiredDeviceCapabilities"])
	}
}

// 构造出来的文件不能让解析器打转或读到界外：这个文件来自不可信的一侧。
func TestBinaryPlistRefusesMalformedInput(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(realBinaryInfoPlist)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":        {},
		"not a plist":  []byte("PK\x03\x04 this is a zip"),
		"truncated":    raw[:len(raw)/2],
		"header only":  []byte("bplist00"),
		"no trailer":   raw[:len(raw)-8],
		"bad trailer":  append(append([]byte{}, raw[:len(raw)-16]...), bytes.Repeat([]byte{0xff}, 16)...),
		"zero offsets": append(append([]byte{}, raw[:8]...), bytes.Repeat([]byte{0x00}, 40)...),
	}
	for name, data := range cases {
		if _, err := ParseBinary(data); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestParseReadsBothFormatsAndInsistsOnADictionary(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(realBinaryInfoPlist)
	if err != nil {
		t.Fatal(err)
	}
	if fields, err := Parse(raw); err != nil || String(fields, "CFBundleVersion") != "33" {
		t.Fatalf("binary: %v %v", fields, err)
	}
	xml := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>get-task-allow</key><false/><key>n</key><integer>7</integer></dict></plist>`)
	fields, err := Parse(xml)
	if err != nil || Bool(fields, "get-task-allow") || fields["n"] != int64(7) {
		t.Fatalf("xml: %v %v", fields, err)
	}
	if _, err := Parse([]byte(`<?xml version="1.0"?><plist version="1.0"><array><string>a</string></array></plist>`)); err == nil {
		t.Fatal("a plist whose root is not a dictionary was accepted")
	}
}
