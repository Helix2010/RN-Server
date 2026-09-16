package axml

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

func sampleTree() *Node {
	return &Node{
		Name: "manifest",
		Attrs: []Attr{
			AndroidAttr("versionCode", IntValue(46)),
			AndroidAttr("versionName", StringValue("1.3.16")),
			StringAttr("", "package", 0, "com.anyfun.foundation"),
			StringAttr("", "platformBuildVersionName", 0, "16"),
		},
		Children: []*Node{
			{Name: "uses-sdk", Attrs: []Attr{AndroidAttr("minSdkVersion", IntValue(24)), AndroidAttr("targetSdkVersion", IntValue(36))}},
			{Name: "uses-permission", Attrs: []Attr{AndroidAttr("name", StringValue("android.permission.INTERNET"))}},
			{Name: "application", Attrs: []Attr{
				AndroidAttr("name", StringValue("com.anyfun.foundation.MainApplication")),
				AndroidAttr("allowBackup", BoolValue(false)),
				AndroidAttr("supportsRtl", BoolValue(true)),
			}, Children: []*Node{
				{Name: "meta-data", Attrs: []Attr{
					AndroidAttr("name", StringValue("expo.modules.updates.EXPO_UPDATE_URL")),
					AndroidAttr("value", StringValue("https://api.anyfun.win/v1/ota/manifest")),
				}},
				{Name: "activity", Attrs: []Attr{
					{Namespace: AndroidNS, Name: "theme", ResourceID: 0x01010000, Value: Value{Type: TypeReference, Data: 0x7f12025a}},
					AndroidAttr("name", StringValue(".MainActivity")),
					AndroidAttr("exported", BoolValue(true)),
				}},
			}},
		},
	}
}

func encode(t *testing.T, n *Node) []byte {
	t.Helper()
	b, err := Encode(n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want *Error with code %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("got code %s (%s), want %s", e.Code, e.Detail, code)
	}
}

func TestFrameworkTable(t *testing.T) {
	for name, id := range map[string]uint32{
		"debuggable": 0x0101000f, "testOnly": 0x01010272, "usesCleartextTraffic": 0x010104ec,
		"networkSecurityConfig": 0x01010527, "sharedUserId": 0x0101000b, "versionCodeMajor": 0x01010576,
		"versionCode": 0x0101021b, "minSdkVersion": 0x0101020c, "allowBackup": 0x01010280, "name": 0x01010003,
		"value": 0x01010024, "scheme": 0x01010027, "host": 0x01010028, "protectionLevel": 0x01010009,
		"autoVerify": 0x010104ee, "advancedPrintOptionsActivity": 0x010103f1, "canTakeScreenshot": 0x0101060f,
	} {
		got, ok := FrameworkAttrID(name)
		if !ok || got != id {
			t.Errorf("FrameworkAttrID(%s) = 0x%08x, %v; want 0x%08x", name, got, ok, id)
		}
		if back, ok := FrameworkAttrName(id); !ok || back != name {
			t.Errorf("FrameworkAttrName(0x%08x) = %s", id, back)
		}
	}
	if len(frameworkNameByID) != 1579 {
		t.Fatalf("table has %d entries, want 1579 (android-36 public-final.xml)", len(frameworkNameByID))
	}
}

func TestRoundTrip(t *testing.T) {
	doc, err := Decode(encode(t, sampleTree()), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root
	if root.Name != "manifest" || len(root.Children) != 3 {
		t.Fatalf("root = %+v", root)
	}
	if a, ok := root.AttrByName("", "package"); !ok || a.Value.String != "com.anyfun.foundation" || a.ResourceID != 0 {
		t.Fatalf("package = %+v", a)
	}
	if a, ok := root.Attr(AttrVersionCode); !ok {
		t.Fatal("versionCode missing")
	} else if n, ok := a.Value.Int(); !ok || n != 46 || a.Namespace != AndroidNS || a.Name != "versionCode" {
		t.Fatalf("versionCode = %+v", a)
	}
	app := root.Children[2]
	if b, ok := app.Attrs[1].Value.Bool(); !ok || b {
		t.Fatalf("allowBackup = %+v", app.Attrs[1])
	}
	if v, ok := app.Children[0].Attrs[1].Value.Str(); !ok || v != "https://api.anyfun.win/v1/ota/manifest" {
		t.Fatalf("meta-data value = %+v", app.Children[0].Attrs[1])
	}
	theme := app.Children[1].Attrs[0]
	if theme.Value.Type != TypeReference || theme.Value.Data != 0x7f12025a {
		t.Fatalf("theme = %+v", theme)
	}
	if _, ok := theme.Value.Str(); ok {
		t.Fatal("a reference reported as a string")
	}
}

func TestValueAccessors(t *testing.T) {
	if n, ok := (Value{Type: TypeIntHex, Data: 0xffffffff}).Int(); !ok || n != -1 {
		t.Fatalf("hex -1 = %d %v", n, ok)
	}
	if _, ok := (Value{Type: TypeIntBoolean}).Int(); ok {
		t.Fatal("boolean read as int")
	}
	if b, ok := (Value{Type: TypeIntBoolean, Data: 1}).Bool(); !ok || !b {
		t.Fatal("non-zero boolean is true on Android")
	}
	if _, ok := (Value{Type: TypeString, String: "true"}).Bool(); ok {
		t.Fatal("string read as boolean")
	}
}

func attrElement(attrs ...Attr) *Node {
	return &Node{Name: "manifest", Children: []*Node{{Name: "application", Attrs: attrs}}}
}

func TestAttributeIdentityRules(t *testing.T) {
	raw := "46"
	other := "com.evil"
	cases := map[string]struct {
		node *Node
		code string
	}{
		"name carries another attribute's id": {attrElement(Attr{Namespace: AndroidNS, Name: "debuggable", ResourceID: AttrAllowBackup, Value: BoolValue(false)}), CodeAttributeIDMismatch},
		"innocent name carries debuggable id": {attrElement(Attr{Namespace: AndroidNS, Name: "label", ResourceID: AttrDebuggable, Value: BoolValue(true)}), CodeAttributeIDMismatch},
		"known android name without id":       {attrElement(Attr{Namespace: AndroidNS, Name: "debuggable", Value: BoolValue(true)}), CodeAttributeIDMismatch},
		"unknown framework id":                {attrElement(Attr{Namespace: AndroidNS, Name: "futureAttr", ResourceID: 0x0101ffff, Value: BoolValue(true)}), CodeUnknownFrameworkAttribute},
		"framework non-attr id":               {attrElement(Attr{Namespace: AndroidNS, Name: "debuggable", ResourceID: 0x01020000, Value: BoolValue(true)}), CodeUnknownFrameworkAttribute},
		"framework id in other namespace":     {attrElement(Attr{Namespace: "http://example.com/evil", Name: "debuggable", ResourceID: AttrDebuggable, Value: BoolValue(true)}), CodeNamespace},
		"framework id without namespace":      {attrElement(Attr{Name: "debuggable", ResourceID: AttrDebuggable, Value: BoolValue(true)}), CodeNamespace},
		"dynamic id":                          {attrElement(Attr{Name: "x", ResourceID: 0x00010003, Value: BoolValue(true)}), CodeAttributeIDMismatch},
		"android name with app id":            {attrElement(Attr{Namespace: AndroidNS, Name: "custom", ResourceID: 0x7f010001, Value: BoolValue(true)}), CodeAttributeIDMismatch},
		"duplicate id": {attrElement(
			AndroidAttr("allowBackup", BoolValue(false)),
			AndroidAttr("allowBackup", BoolValue(true)),
		), CodeDuplicateAttribute},
		"duplicate name": {&Node{Name: "manifest", Attrs: []Attr{
			StringAttr("", "package", 0, "com.good"),
			StringAttr("", "package", 0, "com.evil"),
		}}, CodeDuplicateAttribute},
		"descending ids": {attrElement(
			AndroidAttr("allowBackup", BoolValue(false)),
			AndroidAttr("debuggable", BoolValue(false)),
		), CodeAttributeOrder},
		"raw string differs": {&Node{Name: "manifest", Attrs: []Attr{
			{Name: "package", Value: StringValue("com.good"), Raw: &other},
		}}, CodeRawValueMismatch},
		"raw string on int": {&Node{Name: "manifest", Attrs: []Attr{
			{Namespace: AndroidNS, Name: "versionCode", ResourceID: AttrVersionCode, Value: IntValue(46), Raw: &raw},
		}}, CodeRawValueMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(encode(t, tc.node), DefaultLimits())
			wantCode(t, err, tc.code)
			if strings.ContainsAny(err.Error(), "\x00\x1b\n") {
				t.Fatalf("error detail is not terminal-safe: %q", err)
			}
		})
	}
	// 没有 ID、不在 android 命名空间、名字未知：Android 与我们都忽略，允许
	ok := &Node{Name: "manifest", Attrs: []Attr{StringAttr("", "data-generated", 0, "x"), AndroidAttr("versionCode", IntValue(1))}}
	if _, err := Decode(encode(t, ok), DefaultLimits()); err != nil {
		t.Fatalf("benign attributes rejected: %v", err)
	}
}

// chunk 描述顶层块的位置，测试用来改字节。
type chunk struct {
	typ        uint16
	off, size  int
	headerSize int
}

func topChunks(t *testing.T, data []byte) []chunk {
	t.Helper()
	var out []chunk
	for off := 8; off < len(data); {
		typ, hs, size := chunkHeader(data[off:])
		out = append(out, chunk{typ: typ, off: off, size: int(size), headerSize: int(hs)})
		off += int(size)
	}
	return out
}

func splice(data []byte, at int, insert []byte) []byte {
	out := append(append(append([]byte{}, data[:at]...), insert...), data[at:]...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

func TestStructuralRejections(t *testing.T) {
	good := encode(t, sampleTree())
	chunks := topChunks(t, good)
	pool := chunks[0]
	firstNode := chunks[2] // 0 pool, 1 resource map, 2 start namespace
	if pool.typ != chunkStringPool || chunks[1].typ != chunkResourceMap || firstNode.typ != chunkStartNamespace {
		t.Fatalf("unexpected layout: %+v", chunks[:3])
	}
	var rootStart chunk
	for _, c := range chunks {
		if c.typ == chunkStartElement {
			rootStart = c
			break
		}
	}
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte{}, good...)) }
	cdata := make([]byte, 28)
	binary.LittleEndian.PutUint16(cdata, chunkCDATA)
	binary.LittleEndian.PutUint16(cdata[2:], 16)
	binary.LittleEndian.PutUint32(cdata[4:], 28)
	binary.LittleEndian.PutUint32(cdata[12:], noIndex)
	unknown := append([]byte{}, cdata...)
	binary.LittleEndian.PutUint16(unknown, 0x0105)

	cases := map[string]struct {
		data []byte
		code string
	}{
		"not xml":         {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b, 0x0002); return b }), CodeMalformed},
		"root size short": {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-4)); return b }), CodeMalformed},
		"trailing bytes":  {append(append([]byte{}, good...), 0, 0, 0, 0), CodeMalformed},
		"truncated": {mutate(func(b []byte) []byte {
			b = b[:len(b)-8]
			binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
			return b
		}), CodeMalformed},
		"odd chunk size":    {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[pool.off+4:], uint32(pool.size+1)); return b }), CodeMalformed},
		"chunk overruns":    {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[pool.off+4:], uint32(len(b))); return b }), CodeMalformed},
		"header over size":  {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[firstNode.off+2:], 32); return b }), CodeMalformed},
		"cdata":             {splice(good, rootStart.off+rootStart.size, cdata), CodeMalformed},
		"unknown chunk":     {splice(good, rootStart.off+rootStart.size, unknown), CodeMalformed},
		"map before pool":   {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[pool.off:], chunkResourceMap); return b }), CodeMalformed},
		"second pool":       {splice(good, chunks[1].off, good[pool.off:pool.off+pool.size]), CodeMalformed},
		"attribute start":   {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rootStart.off+16+8:], 24); return b }), CodeMalformed},
		"id index":          {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rootStart.off+16+14:], 99); return b }), CodeMalformed},
		"element namespace": {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[rootStart.off+16:], 0); return b }), CodeMalformed},
		"value size":        {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rootStart.off+36+12:], 12); return b }), CodeMalformed},
		"value type":        {mutate(func(b []byte) []byte { b[rootStart.off+36+15] = 0x42; return b }), CodeMalformed},
		"node header size":  {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[rootStart.off+2:], 20); return b }), CodeMalformed},
		"style count":       {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[pool.off+12:], 1); return b }), CodeStringPool},
		"pool flags":        {mutate(func(b []byte) []byte { b[pool.off+18] = 0x80; return b }), CodeStringPool},
		"string count":      {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[pool.off+8:], 0x10000000); return b }), CodeStringPool},
		"string offset":     {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[pool.off+28:], 0xfff0); return b }), CodeStringPool},
		"utf16 length lies": {mutate(func(b []byte) []byte {
			start := int(binary.LittleEndian.Uint32(b[pool.off+20:]))
			b[pool.off+start]++ // 第一个字符串的 UTF-16 长度
			return b
		}), CodeStringPool},
		"missing nul": {mutate(func(b []byte) []byte {
			start := int(binary.LittleEndian.Uint32(b[pool.off+20:]))
			n := int(b[pool.off+start+1])
			b[pool.off+start+2+n] = 'x'
			return b
		}), CodeStringPool},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(tc.data, DefaultLimits())
			wantCode(t, err, tc.code)
		})
	}
}

func TestTreeShapeRejections(t *testing.T) {
	good := encode(t, sampleTree())
	chunks := topChunks(t, good)
	var endNS, endRoot chunk
	for _, c := range chunks {
		switch c.typ {
		case chunkEndNamespace:
			endNS = c
		case chunkEndElement:
			endRoot = c
		}
	}
	// 两个根：把整个根元素再抄一遍，放在根结束之后、命名空间结束之前
	var rootStart chunk
	for _, c := range chunks {
		if c.typ == chunkStartElement {
			rootStart = c
			break
		}
	}
	rootBytes := good[rootStart.off : endRoot.off+endRoot.size]
	twoRoots := splice(good, endNS.off, rootBytes)
	// 去掉根的结束
	noEnd := append(append([]byte{}, good[:endRoot.off]...), good[endRoot.off+endRoot.size:]...)
	binary.LittleEndian.PutUint32(noEnd[4:], uint32(len(noEnd)))
	// 去掉命名空间结束
	noNSEnd := append([]byte{}, good[:endNS.off]...)
	binary.LittleEndian.PutUint32(noNSEnd[4:], uint32(len(noNSEnd)))
	// 结束元素名字不对
	wrongEnd := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(wrongEnd[endRoot.off+20:], 0)
	for name, data := range map[string][]byte{"two roots": twoRoots, "unclosed root": noEnd, "unclosed namespace": noNSEnd, "mismatched end": wrongEnd} {
		if _, err := Decode(data, DefaultLimits()); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			wantCode(t, err, CodeMalformed)
		}
	}
}

// utf16Pool 把文档的字符串池改写成 UTF-16 编码，extra 可以追加原始的 UTF-16 码元。
func utf16Pool(t *testing.T, data []byte, patch func(units [][]uint16)) []byte {
	t.Helper()
	d := &decoder{data: data, lim: DefaultLimits()}
	chunks := topChunks(t, data)
	pool := chunks[0]
	if err := d.parseStringPool(data[pool.off : pool.off+pool.size]); err != nil {
		t.Fatal(err)
	}
	units := make([][]uint16, len(d.strings))
	for i, s := range d.strings {
		units[i] = utf16.Encode([]rune(s))
	}
	if patch != nil {
		patch(units)
	}
	var body []byte
	offsets := make([]uint32, len(units))
	for i, u := range units {
		offsets[i] = uint32(len(body))
		body = binary.LittleEndian.AppendUint16(body, uint16(len(u)))
		for _, c := range u {
			body = binary.LittleEndian.AppendUint16(body, c)
		}
		body = binary.LittleEndian.AppendUint16(body, 0)
	}
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	start := 28 + 4*len(units)
	newPool := make([]byte, 28)
	binary.LittleEndian.PutUint16(newPool, chunkStringPool)
	binary.LittleEndian.PutUint16(newPool[2:], 28)
	binary.LittleEndian.PutUint32(newPool[4:], uint32(start+len(body)))
	binary.LittleEndian.PutUint32(newPool[8:], uint32(len(units)))
	binary.LittleEndian.PutUint32(newPool[20:], uint32(start))
	for _, o := range offsets {
		newPool = binary.LittleEndian.AppendUint32(newPool, o)
	}
	newPool = append(newPool, body...)
	out := append(append(append([]byte{}, data[:pool.off]...), newPool...), data[pool.off+pool.size:]...)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	return out
}

func TestUTF16StringPool(t *testing.T) {
	good := encode(t, sampleTree())
	converted := utf16Pool(t, good, nil)
	doc, err := Decode(converted, DefaultLimits())
	if err != nil {
		t.Fatalf("UTF-16 pool rejected: %v", err)
	}
	if a, _ := doc.Root.AttrByName("", "package"); a.Value.String != "com.anyfun.foundation" {
		t.Fatalf("package = %+v", a)
	}
	broken := utf16Pool(t, good, func(units [][]uint16) {
		units[len(units)-1] = append(units[len(units)-1], 0xd800)
	})
	_, err = Decode(broken, DefaultLimits())
	wantCode(t, err, CodeStringPool)
}

func TestLimits(t *testing.T) {
	deep := &Node{Name: "manifest"}
	cur := deep
	for i := 0; i < 70; i++ {
		child := &Node{Name: "x"}
		cur.Children = []*Node{child}
		cur = child
	}
	_, err := Decode(encode(t, deep), DefaultLimits())
	wantCode(t, err, CodeMalformed)

	wide := &Node{Name: "manifest"}
	for i := 0; i < 10; i++ {
		wide.Children = append(wide.Children, &Node{Name: "x"})
	}
	lim := DefaultLimits()
	lim.MaxElements = 5
	_, err = Decode(encode(t, wide), lim)
	wantCode(t, err, CodeMalformed)

	many := &Node{Name: "manifest"}
	for i := 0; i < 300; i++ {
		many.Attrs = append(many.Attrs, StringAttr("", "a"+strings.Repeat("x", i), 0, "v"))
	}
	_, err = Decode(encode(t, many), DefaultLimits())
	wantCode(t, err, CodeMalformed)

	lim = DefaultLimits()
	lim.MaxStrings = 3
	_, err = Decode(encode(t, sampleTree()), lim)
	wantCode(t, err, CodeStringPool)

	lim = DefaultLimits()
	lim.MaxSize = 64
	_, err = Decode(encode(t, sampleTree()), lim)
	wantCode(t, err, CodeMalformed)
}

func TestQuoteIsTerminalSafe(t *testing.T) {
	q := Quote("a\x1b[2J‮" + strings.Repeat("z", 300))
	if strings.ContainsAny(q, "\x1b‮") || len(q) > 200 {
		t.Fatalf("Quote = %q", q)
	}
}
