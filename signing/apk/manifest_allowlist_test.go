package apk_test

import (
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

func withManifest(t *testing.T, mutate func(root, app *axml.Node)) []byte {
	t.Helper()
	spec := apktest.Default()
	root := apktest.ManifestNode(spec)
	var app *axml.Node
	for _, c := range root.Children {
		if c.Name == "application" {
			app = c
		}
	}
	mutate(root, app)
	manifest, err := axml.Encode(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := apktest.BuildWithManifest(spec, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// <key-sets>/<upgrade-key-set> 让设备接受由另一组密钥签名的升级：不管出现在哪里都拒签。
// <manifest>、<application> 的直接子元素走允许列表。
func TestManifestElementAllowList(t *testing.T) {
	name := func(v string) axml.Attr { return axml.AndroidAttr("name", axml.StringValue(v)) }
	keySets := func() *axml.Node {
		return &axml.Node{Name: "key-sets", Children: []*axml.Node{
			{Name: "key-set", Attrs: []axml.Attr{name("evil")}, Children: []*axml.Node{
				{Name: "public-key", Attrs: []axml.Attr{name("k"), axml.AndroidAttr("value", axml.StringValue("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"))}},
			}},
			{Name: "upgrade-key-set", Attrs: []axml.Attr{name("evil")}},
		}}
	}
	cases := map[string]func(root, app *axml.Node){
		"key-sets under manifest": func(root, _ *axml.Node) { root.Children = append(root.Children, keySets()) },
		"key-sets nested in application": func(_, app *axml.Node) {
			app.Children = append(app.Children, keySets())
		},
		"upgrade-key-set alone": func(root, _ *axml.Node) {
			root.Children = append(root.Children, &axml.Node{Name: "upgrade-key-set", Attrs: []axml.Attr{name("evil")}})
		},
		"instrumentation": func(root, _ *axml.Node) {
			root.Children = append(root.Children, &axml.Node{Name: "instrumentation", Attrs: []axml.Attr{name("com.evil.Instr")}})
		},
		"overlay": func(root, _ *axml.Node) { root.Children = append(root.Children, &axml.Node{Name: "overlay"}) },
		"profileable": func(_, app *axml.Node) {
			app.Children = append(app.Children, &axml.Node{Name: "profileable"})
		},
		"uses-static-library": func(_, app *axml.Node) {
			app.Children = append(app.Children, &axml.Node{Name: "uses-static-library", Attrs: []axml.Attr{name("com.evil.lib")}})
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			_, err := parse(withManifest(t, mutate))
			wantCode(t, err, apk.CodeManifestElementNotAllowed)
		})
	}
	// 允许列表里的常见元素照常通过
	ok := withManifest(t, func(root, app *axml.Node) {
		root.Children = append(root.Children, &axml.Node{Name: "uses-feature", Attrs: []axml.Attr{name("android.hardware.camera")}})
		app.Children = append(app.Children, &axml.Node{Name: "uses-native-library", Attrs: []axml.Attr{name("libOpenCL.so")}})
	})
	if _, err := parse(ok); err != nil {
		t.Fatalf("allowed elements rejected: %v", err)
	}
}
