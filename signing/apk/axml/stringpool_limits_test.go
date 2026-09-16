package axml

import (
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// buildUTF16Pool 造一个只有字符串池的文档：offsets 是 body 里的单元下标（×2 即字节偏移）。
func buildUTF16Pool(offsets []uint32, body []uint16) []byte {
	raw := make([]byte, 0, 2*len(body)+4)
	for _, u := range body {
		raw = binary.LittleEndian.AppendUint16(raw, u)
	}
	for len(raw)%4 != 0 {
		raw = append(raw, 0)
	}
	start := 28 + 4*len(offsets)
	pool := make([]byte, 28, start+len(raw))
	binary.LittleEndian.PutUint16(pool[0:], chunkStringPool)
	binary.LittleEndian.PutUint16(pool[2:], 28)
	binary.LittleEndian.PutUint32(pool[4:], uint32(start+len(raw)))
	binary.LittleEndian.PutUint32(pool[8:], uint32(len(offsets)))
	binary.LittleEndian.PutUint32(pool[20:], uint32(start))
	for _, o := range offsets {
		pool = binary.LittleEndian.AppendUint32(pool, 2*o)
	}
	pool = append(pool, raw...)
	doc := make([]byte, 8, 8+len(pool))
	binary.LittleEndian.PutUint16(doc[0:], chunkXML)
	binary.LittleEndian.PutUint16(doc[2:], 8)
	binary.LittleEndian.PutUint32(doc[4:], uint32(8+len(pool)))
	return append(doc, pool...)
}

// allocatedBy 返回 fn 期间的累计分配字节数（含已经回收的），比峰值更严格。
func allocatedBy(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// R2 回归：4000 个偏移都指向同一个 100 万单元的串。修复前每个索引各解一次并保留（2 MiB 的清单
// 峰值 4.4 GiB），现在同一偏移只解一次，所有索引共享同一份字节。
func TestAliasedOffsetsDecodeOnce(t *testing.T) {
	const units = 1 << 20
	const n = 4000
	body := make([]uint16, 0, units+3)
	body = append(body, uint16(0x8000|(units>>16)), uint16(units&0xffff))
	for i := 0; i < units; i++ {
		body = append(body, 'A')
	}
	body = append(body, 0)
	data := buildUTF16Pool(make([]uint32, n), body)

	d := &decoder{data: data, lim: DefaultLimits()}
	var err error
	allocated := allocatedBy(func() { err = d.parseStringPool(data[8:]) })
	if err != nil {
		t.Fatalf("aliased pool rejected: %v", err)
	}
	if len(d.strings) != n || len(d.strings[0]) != units {
		t.Fatalf("strings: %d, first %d bytes", len(d.strings), len(d.strings[0]))
	}
	first := unsafe.StringData(d.strings[0])
	for i, s := range d.strings {
		if unsafe.StringData(s) != first {
			t.Fatalf("string %d was decoded again instead of shared", i)
		}
	}
	if allocated > 4<<20 {
		t.Fatalf("decoding a %d KiB pool allocated %d MiB", len(data)>>10, allocated>>20)
	}
	t.Logf("pool %d KiB, allocated %.1f MiB", len(data)>>10, float64(allocated)/(1<<20))

	// 整条 Decode 路径同样有界（文档没有元素，最终报结构错误）
	allocated = allocatedBy(func() { _, err = Decode(data, DefaultLimits()) })
	if err == nil || allocated > 4<<20 {
		t.Fatalf("Decode: %v, allocated %d MiB", err, allocated>>20)
	}
}

// 不同偏移、互相重叠的串：长度头逐个递减、共用同一个结尾 NUL。按偏移去重挡不住，解码总量随池
// 大小平方增长（这个约 180 KiB 的池全部解码约 1.6 GiB），必须由总量上限拒绝。
func TestOverlappingOffsetsHitTheStringBudget(t *testing.T) {
	const end = 0x7fff // 共用的 NUL 所在单元
	const count = 0x7000
	body := make([]uint16, end+1)
	for k := 0; k < end; k++ {
		if k < count {
			body[k] = uint16(end - k - 1) // 下标 k 处的串长 end-k-1，结尾正好落在 body[end]
		} else {
			body[k] = 'A'
		}
	}
	offsets := make([]uint32, count)
	for k := range offsets {
		offsets[k] = uint32(k)
	}
	data := buildUTF16Pool(offsets, body)

	d := &decoder{data: data, lim: DefaultLimits()}
	var err error
	allocated := allocatedBy(func() { err = d.parseStringPool(data[8:]) })
	wantCode(t, err, CodeStringBudget)
	if allocated > 24<<20 {
		t.Fatalf("a %d KiB pool allocated %d MiB before being rejected", len(data)>>10, allocated>>20)
	}
	t.Logf("pool %d KiB rejected after allocating %.1f MiB", len(data)>>10, float64(allocated)/(1<<20))

	// 只取前几个偏移时照常解析：拒绝确实来自总量上限，而不是这些串本身不合法
	small := buildUTF16Pool(offsets[:8], body)
	d = &decoder{data: small, lim: DefaultLimits()}
	if err := d.parseStringPool(small[8:]); err != nil {
		t.Fatalf("the first overlapping strings are valid on their own: %v", err)
	}

	// UTF-8 池同样按总量计
	lim := DefaultLimits()
	lim.MaxStringBytes = 64
	many := &Node{Name: "manifest"}
	for i := 0; i < 10; i++ {
		many.Attrs = append(many.Attrs, StringAttr("", "a"+strings.Repeat("x", i), 0, strings.Repeat("v", 20)))
	}
	_, err = Decode(encode(t, many), lim)
	wantCode(t, err, CodeStringBudget)
}

// R2：池里的串内嵌 U+0000 时 aapt2/Android 的部分路径在 NUL 处截断，这里却读出整串——两边看到的
// 权限名、组件名不一样。UTF-8 与 UTF-16 两条路径都拒绝 U+0000、TAB/LF/CR 以外的 C0、DEL 与 C1。
func TestPoolStringsRejectControlCharacters(t *testing.T) {
	const permission = "android.permission.INTERNET"
	withValue := func(v string) *Node {
		n := sampleTree()
		n.Children[1].Attrs = []Attr{AndroidAttr("name", StringValue(v))}
		return n
	}
	for name, v := range map[string]string{
		"nul":          permission + "\x00.EVIL",
		"leading nul":  "\x00android.permission.CAMERA",
		"soh":          permission + "\x01",
		"escape":       permission + "\x1b[2J",
		"del":          permission + "\x7f",
		"c1 next line": permission + "\xc2\x85",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(encode(t, withValue(v)), DefaultLimits())
			wantCode(t, err, CodeStringControl)
			if strings.ContainsAny(err.Error(), "\x00\x01\x1b\x7f\xc2\x85") {
				t.Fatalf("error echoes the control character: %q", err)
			}
			utf16Doc := utf16Pool(t, encode(t, withValue(permission)), func(units [][]uint16) {
				for i, u := range units {
					if string(utf16.Decode(u)) == permission {
						units[i] = utf16.Encode([]rune(v))
					}
				}
			})
			_, err = Decode(utf16Doc, DefaultLimits())
			wantCode(t, err, CodeStringControl)
		})
	}
	// TAB、LF、CR 是 XML 能表达的空白；expo-updates 的多行 PEM 证书就在清单里
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\r\n\tAQAB\n-----END CERTIFICATE-----\n"
	doc, err := Decode(encode(t, withValue(pem)), DefaultLimits())
	if err != nil {
		t.Fatalf("multi-line PEM rejected: %v", err)
	}
	if a, ok := doc.Root.Children[1].Attr(0x01010003); !ok || a.Value.String != pem {
		t.Fatalf("PEM value = %+v", a)
	}
	if _, err := Decode(utf16Pool(t, encode(t, withValue(pem)), nil), DefaultLimits()); err != nil {
		t.Fatalf("multi-line PEM in a UTF-16 pool rejected: %v", err)
	}
}
