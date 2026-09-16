package axml

import "testing"

// FuzzDecode：任意输入都不能 panic、不能挂住；解析成功时必须有根元素。
func FuzzDecode(f *testing.F) {
	for _, n := range []*Node{
		sampleTree(),
		attrElement(AndroidAttr("allowBackup", BoolValue(false)), AndroidAttr("usesCleartextTraffic", BoolValue(false))),
		{Name: "manifest"},
	} {
		b, err := Encode(n)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := Decode(data, DefaultLimits())
		if err == nil && (doc == nil || doc.Root == nil) {
			t.Fatal("success without a root element")
		}
		if err != nil {
			if _, ok := err.(*Error); !ok {
				t.Fatalf("non-*Error error: %T %v", err, err)
			}
		}
	})
}
