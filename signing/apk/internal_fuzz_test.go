package apk

import (
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

// FuzzManifestExtraction 直接喂二进制 XML 给清单提取（FuzzParse 的变异大多被 CRC 挡在外面）。
func FuzzManifestExtraction(f *testing.F) {
	for _, n := range []*axml.Node{
		{Name: "manifest", Attrs: []axml.Attr{axml.StringAttr("", "package", 0, "com.example.app")}},
		{Name: "manifest", Attrs: []axml.Attr{axml.AndroidAttr("versionCode", axml.IntValue(1)), axml.StringAttr("", "package", 0, "a.b")},
			Children: []*axml.Node{{Name: "application", Attrs: []axml.Attr{axml.AndroidAttr("allowBackup", axml.BoolValue(false))},
				Children: []*axml.Node{{Name: "activity", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue(".A"))},
					Children: []*axml.Node{{Name: "intent-filter", Children: []*axml.Node{
						{Name: "data", Attrs: []axml.Attr{axml.AndroidAttr("scheme", axml.StringValue("https")), axml.AndroidAttr("host", axml.StringValue("x.example"))}},
					}}}}}}}},
	} {
		b, err := axml.Encode(n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := axml.Decode(data, axml.DefaultLimits())
		if err != nil {
			return
		}
		if _, err := extractManifest(doc); err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("non-*Error: %T", err)
			}
		}
	})
}

// FuzzStrictJSON：内嵌配置的 JSON 解析不能 panic；接受的输入必须是对象。
func FuzzStrictJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"extra":{"apiBaseUrl":"https://a.example"}}`, `{"a":[1,{"b":null}],"a2":true}`, `{"a":1,"a":2}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		obj, err := parseStrictJSONObject(data, AppConfigEntry)
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("non-*Error: %T", err)
			}
			return
		}
		if obj == nil {
			t.Fatal("nil object without error")
		}
		_ = expoConfigFrom(obj)
	})
}
