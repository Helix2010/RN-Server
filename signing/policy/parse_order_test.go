package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/provenance"
)

// countParses 把 parseFile 换成计数版本。
func countParses(t *testing.T) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	orig := parseFile
	parseFile = func(path string, lim apk.Limits) (*apk.Package, error) {
		n.Add(1)
		return orig(path, lim)
	}
	t.Cleanup(func() { parseFile = orig })
	return &n
}

// overlappingPoolManifest：字符串池里的串长度头逐个递减、共用同一个结尾 NUL（R2 的放大构造的
// 平方增长版本）。约 180 KiB，全部解码约 1.6 GiB。
func overlappingPoolManifest() []byte {
	const end, count = 0x7fff, 0x7000
	body := make([]byte, 0, 2*(end+2))
	for k := 0; k < end; k++ {
		u := uint16('A')
		if k < count {
			u = uint16(end - k - 1)
		}
		body = binary.LittleEndian.AppendUint16(body, u)
	}
	body = binary.LittleEndian.AppendUint16(body, 0)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	start := 28 + 4*count
	pool := make([]byte, 28, start+len(body))
	binary.LittleEndian.PutUint16(pool[0:], 0x0001)
	binary.LittleEndian.PutUint16(pool[2:], 28)
	binary.LittleEndian.PutUint32(pool[4:], uint32(start+len(body)))
	binary.LittleEndian.PutUint32(pool[8:], count)
	binary.LittleEndian.PutUint32(pool[20:], uint32(start))
	for k := 0; k < count; k++ {
		pool = binary.LittleEndian.AppendUint32(pool, uint32(2*k))
	}
	pool = append(pool, body...)
	doc := make([]byte, 8, 8+len(pool))
	binary.LittleEndian.PutUint16(doc[0:], 0x0003)
	binary.LittleEndian.PutUint16(doc[2:], 8)
	binary.LittleEndian.PutUint32(doc[4:], uint32(8+len(pool)))
	return append(doc, pool...)
}

func bombAPK(t *testing.T) []byte {
	t.Helper()
	raw, err := apktest.WriteZip([]apktest.File{{Name: "AndroidManifest.xml", Data: overlappingPoolManifest(), Deflate: true}}, apktest.ZipOptions{Align: true})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// 出处签名与未签名包摘要先于解析：服务端单独被攻破时塞过来的字节，解析器一个都碰不到。
func TestProvenanceIsCheckedBeforeParsing(t *testing.T) {
	parses := countParses(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for name, sc := range map[string]scenario{
		"malformed input":          {input: func(in *Input) { in.Version = 0 }},
		"builder not trusted":      {input: func(in *Input) { in.TrustedBuilders = nil }},
		"signed by another key":    {signWith: otherPriv},
		"statement does not match": {statement: func(s *provenance.Statement) { s.VersionCode = 47 }},
		"package replaced":         {replaceAPK: func(apktest.Spec) []byte { return bombAPK(t) }},
	} {
		before := parses.Load()
		if v := run(t, sc); v.OK {
			t.Fatalf("%s: accepted", name)
		}
		if parses.Load() != before {
			t.Errorf("%s: the package was parsed before the provenance was verified", name)
		}
	}
	before := parses.Load()
	if v := run(t, scenario{}); !v.OK || parses.Load() != before+1 {
		t.Fatalf("control: %+v, parses %d", v, parses.Load()-before)
	}
}

// R2 场景：没有任何出处的输入加一个解析炸弹。拒绝发生在解析之前，分配量只有读文件算摘要那点。
func TestParsingBombWithoutProvenanceIsNeverParsed(t *testing.T) {
	parses := countParses(t)
	path := filepath.Join(t.TempDir(), "evil.apk")
	if err := os.WriteFile(path, bombAPK(t), 0o600); err != nil {
		t.Fatal(err)
	}
	var v Verdict
	allocated := allocatedDuring(func() { v = EvaluateFile(Input{}, path, apk.DefaultLimits()) })
	if v.OK || v.Code != "POLICY_INPUT_INVALID" || parses.Load() != 0 {
		t.Fatalf("verdict %+v, parses %d", v, parses.Load())
	}
	if allocated > 4<<20 {
		t.Fatalf("allocated %d MiB before rejecting", allocated>>20)
	}
}

// 构建机本身签了这个炸弹（出处合法）：照常解析，但字符串池总量上限挡住，分配量有界。
func TestParsingBombWithValidProvenanceIsBounded(t *testing.T) {
	bomb := bombAPK(t)
	var v Verdict
	allocated := allocatedDuring(func() { v = run(t, scenario{rawAPK: bomb}) })
	if v.OK || v.Code != "AXML_STRING_POOL_BUDGET_EXCEEDED" {
		t.Fatalf("verdict %+v", v)
	}
	if allocated > 64<<20 {
		t.Fatalf("allocated %d MiB for a %d KiB package", allocated>>20, len(bomb)>>10)
	}
	t.Logf("%d KiB package rejected after allocating %.1f MiB", len(bomb)>>10, float64(allocated)/(1<<20))
}

func allocatedDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
