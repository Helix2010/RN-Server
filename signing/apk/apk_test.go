package apk_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/apk/axml"
)

func build(t *testing.T, s apktest.Spec) []byte {
	t.Helper()
	b, err := apktest.Build(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(data []byte) (*apk.Package, error) {
	return apk.Parse(bytes.NewReader(data), int64(len(data)), apk.DefaultLimits())
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *apk.Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want *apk.Error %s", err, code)
	}
	if e.Code != code {
		t.Fatalf("got %s (%s), want %s", e.Code, e.Detail, code)
	}
	if strings.ContainsAny(e.Detail, "\x00\x1b\r\n") {
		t.Fatalf("detail is not terminal-safe: %q", e.Detail)
	}
}

func TestDefaultPackage(t *testing.T) {
	data := build(t, apktest.Default())
	pkg, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if pkg.SHA256 != hex.EncodeToString(sum[:]) || pkg.Size != int64(len(data)) {
		t.Fatal("sha256/size wrong")
	}
	if pkg.SigningBlock || len(pkg.V1SignatureFiles) != 0 || pkg.MisalignedCount != 0 {
		t.Fatalf("signing/alignment facts wrong: %+v %v %v", pkg.SigningBlock, pkg.V1SignatureFiles, pkg.Misaligned)
	}
	m := pkg.Manifest
	if m.Package != "com.anyfun.foundation" || *m.VersionCode != 46 || *m.VersionName != "1.3.16" || *m.MinSDK != 24 || *m.TargetSDK != 36 {
		t.Fatalf("identity: %+v", m)
	}
	if m.VersionCodeMajor || m.SharedUserID {
		t.Fatal("unexpected versionCodeMajor/sharedUserId")
	}
	app := m.Application
	if app == nil || app.AllowBackup == nil || *app.AllowBackup || app.UsesCleartextTraffic != nil || app.Debuggable || app.TestOnly || app.NetworkSecurityConfig {
		t.Fatalf("application: %+v", app)
	}
	if len(m.UsesPermissions) != len(apktest.AnyfunPermissions)+1 || len(m.Permissions) != 1 || *m.Permissions[0].ProtectionLevel != 2 {
		t.Fatalf("permissions: %d uses, %+v", len(m.UsesPermissions), m.Permissions)
	}
	pem, _ := apktest.DefaultOTACertificate()
	meta := map[string]axml.Value{}
	for _, md := range app.MetaData {
		meta[md.Name] = md.Value
	}
	if v, _ := meta["expo.modules.updates.CODE_SIGNING_CERTIFICATE"].Str(); v != pem {
		t.Fatal("OTA certificate meta-data missing")
	}
	if b, ok := meta["expo.modules.updates.ENABLED"].Bool(); !ok || !b {
		t.Fatal("updates ENABLED meta-data wrong")
	}
	var hosts, schemes []string
	for _, f := range m.IntentFilters {
		if f.AutoVerify != nil && *f.AutoVerify {
			hosts = append(hosts, f.Hosts...)
		} else {
			schemes = append(schemes, f.Schemes...)
		}
	}
	if strings.Join(hosts, ",") != "api.anyfun.win" || strings.Join(schemes, ",") != "anyfun,exp+anyfun-app" {
		t.Fatalf("hosts %v schemes %v", hosts, schemes)
	}
	c := pkg.AppConfig
	if c == nil || *c.APIBaseURL != "https://api.anyfun.win" || *c.ApplicationID != "dex-mobile" || *c.DistributionChannel != "direct" ||
		*c.UpdatesURL != "https://api.anyfun.win/v1/ota/manifest" || !*c.UpdatesEnabled || *c.Slug != "anyfun-app" ||
		*c.Scheme != "anyfun" || *c.AndroidPackage != "com.anyfun.foundation" || *c.AndroidVersionCode != 46 || *c.Version != "1.3.16" ||
		!strings.EqualFold(*c.BootstrapSignerAddress, apktest.DefaultRoots().BootstrapSignerAddress) {
		t.Fatalf("app config: %+v", c)
	}
	if pkg.HasAppManifest || pkg.AppManifest != nil {
		t.Fatal("unexpected app.manifest")
	}
	if pkg.NativeFingerprint == nil || *pkg.NativeFingerprint != apktest.DefaultNativeFingerprint {
		t.Fatal("native fingerprint")
	}
}

// ---- 改字节用的布局信息 ----

type zipLayout struct {
	entries  map[string]apk.Entry
	cdRecord map[string]int // 中央目录记录在文件里的偏移
	cdOffset int
	eocd     int
}

func layoutOf(t *testing.T, data []byte) zipLayout {
	t.Helper()
	pkg, err := parse(data)
	if err != nil {
		t.Fatalf("layout of a package that does not parse: %v", err)
	}
	l := zipLayout{entries: map[string]apk.Entry{}, cdRecord: map[string]int{}, eocd: len(data) - 22}
	l.cdOffset = int(binary.LittleEndian.Uint32(data[l.eocd+16:]))
	for _, e := range pkg.Entries {
		l.entries[e.Name] = e
	}
	for pos := l.cdOffset; pos < l.eocd; {
		nameLen := int(binary.LittleEndian.Uint16(data[pos+28:]))
		extraLen := int(binary.LittleEndian.Uint16(data[pos+30:]))
		commentLen := int(binary.LittleEndian.Uint16(data[pos+32:]))
		l.cdRecord[string(data[pos+46:pos+46+nameLen])] = pos
		pos += 46 + nameLen + extraLen + commentLen
	}
	return l
}

func cloneBytes(b []byte) []byte { return append([]byte{}, b...) }

// both 在本地头与中央目录记录里同一个字段（本地偏移 localOff、中央偏移 cdOff）写同一个值。
func putBoth32(data []byte, l zipLayout, name string, localOff, cdOff int, v uint32) {
	binary.LittleEndian.PutUint32(data[int(l.entries[name].LocalHeaderOffset)+localOff:], v)
	binary.LittleEndian.PutUint32(data[l.cdRecord[name]+cdOff:], v)
}

func putBoth16(data []byte, l zipLayout, name string, localOff, cdOff int, v uint16) {
	binary.LittleEndian.PutUint16(data[int(l.entries[name].LocalHeaderOffset)+localOff:], v)
	binary.LittleEndian.PutUint16(data[l.cdRecord[name]+cdOff:], v)
}

// insertAt 在 at 处插入字节，并把 EOCD 的中央目录偏移、各记录的本地偏移按需平移。
func insertBeforeCD(data []byte, l zipLayout, insert []byte) []byte {
	out := append(append(cloneBytes(data[:l.cdOffset]), insert...), data[l.cdOffset:]...)
	binary.LittleEndian.PutUint32(out[len(out)-22+16:], uint32(l.cdOffset+len(insert)))
	return out
}

func TestZipStructureRejections(t *testing.T) {
	good := build(t, apktest.Default())
	l := layoutOf(t, good)
	const manifest = "AndroidManifest.xml"
	mutate := func(f func(b []byte) []byte) []byte { return f(cloneBytes(good)) }
	files := func(extra ...apktest.File) []byte {
		s := apktest.Default()
		s.ExtraEntries = extra
		return build(t, s)
	}
	withZipOpts := func(opts apktest.ZipOptions) []byte {
		manifestBytes, err := axml.Encode(apktest.ManifestNode(apktest.Default()))
		if err != nil {
			t.Fatal(err)
		}
		fs, err := apktest.Files(apktest.Default(), manifestBytes)
		if err != nil {
			t.Fatal(err)
		}
		opts.Align = true
		b, err := apktest.WriteZip(fs, opts)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	cases := map[string]struct {
		data []byte
		code string
	}{
		"not a zip":       {[]byte(strings.Repeat("x", 100)), apk.CodeZipNoEOCD},
		"truncated":       {good[:len(good)-1], apk.CodeZipNoEOCD},
		"tiny":            {[]byte("PK"), apk.CodeZipNoEOCD},
		"comment":         {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[l.eocd+20:], 3); return append(b, "abc"...) }), apk.CodeZipComment},
		"zip64 sentinel":  {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[l.eocd+10:], 0xffff); return b }), apk.CodeZip64Unsupported},
		"zip64 locator":   {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[l.eocd-20:], 0x07064b50); return b }), apk.CodeZip64Unsupported},
		"multi disk":      {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[l.eocd+4:], 1); return b }), apk.CodeZipMultiDisk},
		"entries on disk": {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint16(b[l.eocd+8:], 1); return b }), apk.CodeZipCDBounds},
		"cd size": {mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[l.eocd+12:], uint32(l.eocd-l.cdOffset-1))
			return b
		}), apk.CodeZipCDBounds},
		"cd signature": {mutate(func(b []byte) []byte { b[l.cdRecord["classes.dex"]] = 'X'; return b }), apk.CodeZipCDEntry},
		"cd entry count": {mutate(func(b []byte) []byte {
			v := binary.LittleEndian.Uint16(b[l.eocd+10:]) - 1
			binary.LittleEndian.PutUint16(b[l.eocd+8:], v)
			binary.LittleEndian.PutUint16(b[l.eocd+10:], v)
			return b
		}), apk.CodeZipCDBounds},
		"name dotdot":      {files(apktest.File{Name: "assets/../AndroidManifest.xml", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name backslash":   {files(apktest.File{Name: `assets\app.config`, Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name absolute":    {files(apktest.File{Name: "/AndroidManifest.xml", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name empty seg":   {files(apktest.File{Name: "assets//app.config", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name dot seg":     {files(apktest.File{Name: "./AndroidManifest.xml", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name directory":   {files(apktest.File{Name: "assets/", Data: nil}), apk.CodeZipNameInvalid},
		"name control":     {files(apktest.File{Name: "assets/\x1b[2Jevil", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"name not utf8":    {files(apktest.File{Name: "assets/\xff", Data: []byte("x")}), apk.CodeZipNameInvalid},
		"duplicate entry":  {withZipOpts(apktest.ZipOptions{DuplicateName: manifest}), apk.CodeZipDuplicateEntry},
		"encrypted":        {mutate(func(b []byte) []byte { putBoth16(b, l, manifest, 6, 8, 1); return b }), apk.CodeZipEncrypted},
		"strong encrypted": {mutate(func(b []byte) []byte { putBoth16(b, l, manifest, 6, 8, 1<<6); return b }), apk.CodeZipEncrypted},
		"method":           {mutate(func(b []byte) []byte { putBoth16(b, l, manifest, 8, 10, 12); return b }), apk.CodeZipMethodUnsupported},
		"stored sizes":     {mutate(func(b []byte) []byte { putBoth32(b, l, "resources.arsc", 22, 24, 1); return b }), apk.CodeZipMethodUnsupported},
		"local crc": {mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[l.entries[manifest].LocalHeaderOffset+14:], 1)
			return b
		}), apk.CodeZipLocalHeaderMismatch},
		"local flags": {mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[l.entries[manifest].LocalHeaderOffset+6:], 2)
			return b
		}), apk.CodeZipLocalHeaderMismatch},
		"local method": {mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[l.entries[manifest].LocalHeaderOffset+8:], 0)
			return b
		}), apk.CodeZipLocalHeaderMismatch},
		"local name":      {mutate(func(b []byte) []byte { b[l.entries[manifest].LocalHeaderOffset+30] = 'a'; return b }), apk.CodeZipLocalHeaderMismatch},
		"local signature": {mutate(func(b []byte) []byte { b[l.entries[manifest].LocalHeaderOffset] = 'Q'; return b }), apk.CodeZipLocalHeaderMismatch},
		"local offset":    {mutate(func(b []byte) []byte { binary.LittleEndian.PutUint32(b[l.cdRecord["classes.dex"]+42:], 1); return b }), apk.CodeZipLocalHeaderMismatch},
		"overlap": {mutate(func(b []byte) []byte {
			e := l.entries["classes.dex"]
			putBoth32(b, l, "classes.dex", 18, 20, uint32(e.CompressedSize+8))
			return b
		}), apk.CodeZipOverlap},
		"gap between entries": {mutate(func(b []byte) []byte {
			e := l.entries["classes.dex"]
			putBoth32(b, l, "classes.dex", 18, 20, uint32(e.CompressedSize-1))
			return b
		}), apk.CodeZipUnaccountedBytes},
		"prefix bytes": {func() []byte {
			b := append([]byte("MZ\x00\x00"), good...)
			l2 := layoutOf(t, good)
			for _, pos := range l2.cdRecord {
				off := binary.LittleEndian.Uint32(b[4+pos+42:])
				binary.LittleEndian.PutUint32(b[4+pos+42:], off+4)
			}
			binary.LittleEndian.PutUint32(b[len(b)-22+16:], uint32(l2.cdOffset+4))
			return b
		}(), apk.CodeZipUnaccountedBytes},
		"junk before cd": {insertBeforeCD(good, l, bytes.Repeat([]byte{0xab}, 40)), apk.CodeZipUnaccountedBytes},
		"bad signing block": {func() []byte {
			block := apktest.SigningBlock()
			binary.LittleEndian.PutUint64(block, binary.LittleEndian.Uint64(block)+1)
			return insertBeforeCD(good, l, block)
		}(), apk.CodeZipUnaccountedBytes},
		"manifest missing": {func() []byte {
			fs, _ := apktest.Files(apktest.Default(), nil)
			b, err := apktest.WriteZip(fs[1:], apktest.ZipOptions{Align: true})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}(), apk.CodeManifestMissing},
		"crc mismatch": {mutate(func(b []byte) []byte {
			putBoth32(b, l, manifest, 14, 16, l.entries[manifest].CRC32^1)
			return b
		}), apk.CodeZipEntryCorrupt},
		"inflates past declared size": {mutate(func(b []byte) []byte {
			putBoth32(b, l, manifest, 22, 24, uint32(l.entries[manifest].UncompressedSize-16))
			return b
		}), apk.CodeZipEntryCorrupt},
		"inflates short of declared size": {mutate(func(b []byte) []byte {
			putBoth32(b, l, manifest, 22, 24, uint32(l.entries[manifest].UncompressedSize+16))
			return b
		}), apk.CodeZipEntryCorrupt},
		"corrupt deflate stream": {mutate(func(b []byte) []byte {
			e := l.entries[manifest]
			for i := int64(0); i < 8 && i < e.CompressedSize; i++ {
				b[e.DataOffset+i] = 0xff
			}
			return b
		}), apk.CodeZipEntryCorrupt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(tc.data)
			wantCode(t, err, tc.code)
		})
	}
}

func TestZip64ExtraField(t *testing.T) {
	good := build(t, apktest.Default())
	l := layoutOf(t, good)
	pos := l.cdRecord["classes.dex"]
	nameLen := int(binary.LittleEndian.Uint16(good[pos+28:]))
	extra := []byte{0x01, 0x00, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8}
	at := pos + 46 + nameLen
	b := append(append(cloneBytes(good[:at]), extra...), good[at:]...)
	binary.LittleEndian.PutUint16(b[pos+30:], uint16(len(extra)))
	eocd := len(b) - 22
	binary.LittleEndian.PutUint32(b[eocd+12:], binary.LittleEndian.Uint32(b[eocd+12:])+uint32(len(extra)))
	_, err := parse(b)
	wantCode(t, err, apk.CodeZip64Unsupported)
}

func TestLimits(t *testing.T) {
	good := build(t, apktest.Default())
	lim := apk.DefaultLimits()
	lim.MaxFileSize = int64(len(good) - 1)
	_, err := apk.Parse(bytes.NewReader(good), int64(len(good)), lim)
	wantCode(t, err, apk.CodeZipTooLarge)

	lim = apk.DefaultLimits()
	lim.MaxEntries = 2
	_, err = apk.Parse(bytes.NewReader(good), int64(len(good)), lim)
	wantCode(t, err, apk.CodeZipTooManyEntries)

	lim = apk.DefaultLimits()
	lim.MaxManifestSize = 100
	_, err = apk.Parse(bytes.NewReader(good), int64(len(good)), lim)
	wantCode(t, err, apk.CodeZipEntryTooLarge)

	lim = apk.DefaultLimits()
	lim.MaxNameLength = 10
	_, err = apk.Parse(bytes.NewReader(good), int64(len(good)), lim)
	wantCode(t, err, apk.CodeZipNameInvalid)

	lim = apk.DefaultLimits()
	lim.MaxCentralDirectorySize = 10
	_, err = apk.Parse(bytes.NewReader(good), int64(len(good)), lim)
	wantCode(t, err, apk.CodeZipCDBounds)

	// 声明解压后 9 MiB 的清单：在解压之前就按声明大小拒绝，不会真的去解
	s := apktest.Default()
	huge := make([]byte, 9<<20)
	fs, err := apktest.Files(s, huge)
	if err != nil {
		t.Fatal(err)
	}
	bomb, err := apktest.WriteZip(fs, apktest.ZipOptions{Align: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(bomb) > 1<<20 {
		t.Fatalf("bomb fixture is %d bytes; expected a highly compressed entry", len(bomb))
	}
	_, err = parse(bomb)
	wantCode(t, err, apk.CodeZipEntryTooLarge)

	s = apktest.Default()
	s.NativeFingerprint = strings.Repeat("a", 2000)
	_, err = parse(build(t, s))
	wantCode(t, err, apk.CodeZipEntryTooLarge)
}

func TestSigningFacts(t *testing.T) {
	manifestBytes, err := axml.Encode(apktest.ManifestNode(apktest.Default()))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := apktest.Files(apktest.Default(), manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := apktest.WriteZip(fs, apktest.ZipOptions{Align: true, SigningBlock: true})
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !pkg.SigningBlock {
		t.Fatal("signing block not detected")
	}
	stripped, err := apktest.StripSigningBlock(signed)
	if err != nil {
		t.Fatal(err)
	}
	if pkg, err = parse(stripped); err != nil || pkg.SigningBlock {
		t.Fatalf("stripped: %v %v", err, pkg != nil && pkg.SigningBlock)
	}
	if _, err := apktest.StripSigningBlock(stripped); err == nil {
		t.Fatal("stripped a block that is not there")
	}

	s := apktest.Default()
	s.ExtraEntries = []apktest.File{
		{Name: "META-INF/CERT.SF", Data: []byte("x"), Deflate: true},
		{Name: "META-INF/CERT.rsa", Data: []byte("x"), Deflate: true},
		{Name: "META-INF/KEY.EC", Data: []byte("x")},
		{Name: "META-INF/SIG-release", Data: []byte("x")},
		{Name: "META-INF/MANIFEST.MF", Data: []byte("x")},
		{Name: "META-INF/services/X.SF", Data: []byte("x")},
	}
	pkg, err = parse(build(t, s))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(pkg.V1SignatureFiles)
	if strings.Join(pkg.V1SignatureFiles, ",") != "META-INF/CERT.SF,META-INF/CERT.rsa,META-INF/KEY.EC,META-INF/SIG-release" {
		t.Fatalf("v1 files = %v", pkg.V1SignatureFiles)
	}
}

func TestAlignment(t *testing.T) {
	manifestBytes, err := axml.Encode(apktest.ManifestNode(apktest.Default()))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := apktest.Files(apktest.Default(), manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"resources.arsc", "lib/arm64-v8a/libx.so"} {
		b, err := apktest.WriteZip(fs, apktest.ZipOptions{Align: true, Misalign: name})
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if pkg.MisalignedCount != 1 || pkg.Misaligned[0].Name != name {
			t.Fatalf("%s: misaligned = %+v", name, pkg.Misaligned)
		}
	}
	// .so 只按 4 字节对齐不够，要 16 KiB 页对齐：不对齐写包，调整前面一个 STORED 条目
	// 的长度，让 .so 的数据偏移恰好是 4 的倍数
	for filler := 0; filler < 4; filler++ {
		files := []apktest.File{
			{Name: "AndroidManifest.xml", Data: manifestBytes, Deflate: true},
			{Name: "filler.bin", Data: make([]byte, filler)},
			{Name: "lib/arm64-v8a/libx.so", Data: []byte("\x7fELF")},
		}
		b, err := apktest.WriteZip(files, apktest.ZipOptions{})
		if err != nil {
			t.Fatal(err)
		}
		pkg, err := parse(b)
		if err != nil {
			t.Fatal(err)
		}
		var so apk.Entry
		for _, e := range pkg.Entries {
			if e.Name == "lib/arm64-v8a/libx.so" {
				so = e
			}
		}
		if so.DataOffset%4 != 0 {
			continue
		}
		found := false
		for _, m := range pkg.Misaligned {
			if m.Name == so.Name && m.Alignment == 16384 {
				found = true
			}
		}
		if !found {
			t.Fatalf("a 4-aligned but not page-aligned .so was accepted: %+v", pkg.Misaligned)
		}
		return
	}
	t.Fatal("could not construct a 4-aligned .so")
}

func manifestPackage(t *testing.T, root *axml.Node) []byte {
	t.Helper()
	b, err := axml.Encode(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := apktest.BuildWithManifest(apktest.Default(), b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func findNode(root *axml.Node, name string) *axml.Node {
	if root.Name == name {
		return root
	}
	for _, c := range root.Children {
		if n := findNode(c, name); n != nil {
			return n
		}
	}
	return nil
}

func setAttr(n *axml.Node, id uint32, v axml.Value) {
	for i := range n.Attrs {
		if n.Attrs[i].ResourceID == id {
			n.Attrs[i].Value = v
			return
		}
	}
	panic("attribute not found")
}

func TestManifestRejections(t *testing.T) {
	ref := axml.Value{Type: axml.TypeReference, Data: 0x7f050001}
	cases := map[string]struct {
		mutate func(root *axml.Node) *axml.Node
		code   string
	}{
		"root not manifest": {func(r *axml.Node) *axml.Node { r.Name = "manifest2"; return r }, apk.CodeManifestStructure},
		"no package": {func(r *axml.Node) *axml.Node {
			var attrs []axml.Attr
			for _, a := range r.Attrs {
				if a.Name != "package" {
					attrs = append(attrs, a)
				}
			}
			r.Attrs = attrs
			return r
		}, apk.CodeManifestStructure},
		"package with id": {func(r *axml.Node) *axml.Node {
			for i := range r.Attrs {
				if r.Attrs[i].Name == "package" {
					r.Attrs[i].ResourceID = 0x7f010000
				}
			}
			apktestSort(r)
			return r
		}, apk.CodeManifestStructure},
		"two applications": {func(r *axml.Node) *axml.Node {
			r.Children = append(r.Children, &axml.Node{Name: "application"})
			return r
		}, apk.CodeManifestStructure},
		"two uses-sdk": {func(r *axml.Node) *axml.Node {
			r.Children = append(r.Children, &axml.Node{Name: "uses-sdk"})
			return r
		}, apk.CodeManifestStructure},
		"nested uses-permission": {func(r *axml.Node) *axml.Node {
			app := findNode(r, "application")
			app.Children = append(app.Children, &axml.Node{Name: "uses-permission", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("android.permission.RECORD_AUDIO"))}})
			return r
		}, apk.CodeManifestStructure},
		"nested application": {func(r *axml.Node) *axml.Node {
			q := findNode(r, "queries")
			q.Children = append(q.Children, &axml.Node{Name: "application"})
			return r
		}, apk.CodeManifestStructure},
		"permission without name": {func(r *axml.Node) *axml.Node {
			r.Children = append(r.Children, &axml.Node{Name: "uses-permission"})
			return r
		}, apk.CodeManifestStructure},
		"meta-data without name": {func(r *axml.Node) *axml.Node {
			app := findNode(r, "application")
			app.Children = append(app.Children, &axml.Node{Name: "meta-data", Attrs: []axml.Attr{axml.AndroidAttr("value", axml.StringValue("x"))}})
			return r
		}, apk.CodeManifestStructure},
		"duplicate meta-data": {func(r *axml.Node) *axml.Node {
			app := findNode(r, "application")
			app.Children = append(app.Children, &axml.Node{Name: "meta-data", Attrs: []axml.Attr{
				axml.AndroidAttr("name", axml.StringValue("expo.modules.updates.EXPO_UPDATE_URL")),
				axml.AndroidAttr("value", axml.StringValue("https://evil.example/v1/ota/manifest")),
			}})
			return r
		}, apk.CodeManifestStructure},
		"action without name": {func(r *axml.Node) *axml.Node {
			f := findNode(r, "intent-filter")
			f.Children = append(f.Children, &axml.Node{Name: "action"})
			return r
		}, apk.CodeManifestStructure},
		"allowBackup reference": {func(r *axml.Node) *axml.Node {
			setAttr(findNode(r, "application"), axml.AttrAllowBackup, ref)
			return r
		}, apk.CodeManifestAttributeType},
		"allowBackup string": {func(r *axml.Node) *axml.Node {
			setAttr(findNode(r, "application"), axml.AttrAllowBackup, axml.StringValue("false"))
			return r
		}, apk.CodeManifestAttributeType},
		"versionCode string": {func(r *axml.Node) *axml.Node {
			setAttr(r, axml.AttrVersionCode, axml.StringValue("46"))
			return r
		}, apk.CodeManifestAttributeType},
		"versionName reference": {func(r *axml.Node) *axml.Node {
			setAttr(r, axml.AttrVersionName, ref)
			return r
		}, apk.CodeManifestAttributeType},
		"minSdk codename": {func(r *axml.Node) *axml.Node {
			setAttr(findNode(r, "uses-sdk"), axml.AttrMinSDKVersion, axml.StringValue("Tiramisu"))
			return r
		}, apk.CodeManifestAttributeType},
		"package int": {func(r *axml.Node) *axml.Node {
			for i := range r.Attrs {
				if r.Attrs[i].Name == "package" {
					r.Attrs[i].Value = axml.IntValue(1)
				}
			}
			return r
		}, apk.CodeManifestAttributeType},
		"permission name reference": {func(r *axml.Node) *axml.Node {
			setAttr(findNode(r, "uses-permission"), axml.AttrName, ref)
			return r
		}, apk.CodeManifestAttributeType},
		"protectionLevel string": {func(r *axml.Node) *axml.Node {
			setAttr(findNode(r, "permission"), axml.AttrProtectionLevel, axml.StringValue("signature"))
			return r
		}, apk.CodeManifestAttributeType},
		"data host reference": {func(r *axml.Node) *axml.Node {
			var target *axml.Node
			var walk func(n *axml.Node)
			walk = func(n *axml.Node) {
				if n.Name == "data" {
					for _, a := range n.Attrs {
						if a.ResourceID == axml.AttrHost {
							target = n
						}
					}
				}
				for _, c := range n.Children {
					walk(c)
				}
			}
			walk(r)
			setAttr(target, axml.AttrHost, ref)
			return r
		}, apk.CodeManifestAttributeType},
		"autoVerify string": {func(r *axml.Node) *axml.Node {
			var target *axml.Node
			var walk func(n *axml.Node)
			walk = func(n *axml.Node) {
				if n.Name == "intent-filter" && len(n.Attrs) > 0 {
					target = n
				}
				for _, c := range n.Children {
					walk(c)
				}
			}
			walk(r)
			setAttr(target, axml.AttrAutoVerify, axml.StringValue("true"))
			return r
		}, apk.CodeManifestAttributeType},
		"attribute id mismatch passes through": {func(r *axml.Node) *axml.Node {
			app := findNode(r, "application")
			app.Attrs = append(app.Attrs, axml.Attr{Namespace: axml.AndroidNS, Name: "debuggable", ResourceID: 0x7f010001, Value: axml.BoolValue(true)})
			return r
		}, axml.CodeAttributeIDMismatch},
		"unsorted attributes pass through": {func(r *axml.Node) *axml.Node {
			app := findNode(r, "application")
			app.Attrs[0], app.Attrs[len(app.Attrs)-1] = app.Attrs[len(app.Attrs)-1], app.Attrs[0]
			return r
		}, axml.CodeAttributeOrder},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := tc.mutate(apktest.ManifestNode(apktest.Default()))
			_, err := parse(manifestPackage(t, root))
			wantCode(t, err, tc.code)
		})
	}

	// 非法清单字节本身：不是二进制 XML
	data, err := apktest.BuildWithManifest(apktest.Default(), []byte("<manifest/>"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = parse(data)
	wantCode(t, err, axml.CodeMalformed)
}

func apktestSort(n *axml.Node) {
	sort.SliceStable(n.Attrs, func(i, j int) bool {
		a, b := n.Attrs[i].ResourceID, n.Attrs[j].ResourceID
		if a>>24 != 0x01 {
			return false
		}
		if b>>24 != 0x01 {
			return true
		}
		return a < b
	})
}

func TestManifestFacts(t *testing.T) {
	s := apktest.Default()
	yes := true
	s.UsesCleartextTraffic = &yes
	s.AllowBackup = nil
	s.Debuggable, s.TestOnly, s.NetworkSecurityConfig, s.SharedUserID, s.VersionCodeMajor = true, true, true, true, true
	pkg, err := parse(build(t, s))
	if err != nil {
		t.Fatal(err)
	}
	m := pkg.Manifest
	a := m.Application
	if !m.VersionCodeMajor || !m.SharedUserID || !a.Debuggable || !a.TestOnly || !a.NetworkSecurityConfig ||
		a.AllowBackup != nil || a.UsesCleartextTraffic == nil || !*a.UsesCleartextTraffic {
		t.Fatalf("facts not reported: %+v %+v", m, a)
	}

	root := apktest.ManifestNode(apktest.Default())
	root.Children = append(root.Children,
		&axml.Node{Name: "uses-permission-sdk-23", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("android.permission.RECORD_AUDIO")), axml.AndroidAttr("maxSdkVersion", axml.IntValue(32))}},
		&axml.Node{Name: "permission-tree", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("com.anyfun.tree"))}},
		&axml.Node{Name: "permission-group", Attrs: []axml.Attr{axml.AndroidAttr("name", axml.StringValue("com.anyfun.group"))}},
	)
	pkg, err = parse(manifestPackage(t, root))
	if err != nil {
		t.Fatal(err)
	}
	last := pkg.Manifest.UsesPermissions[len(pkg.Manifest.UsesPermissions)-1]
	if last.Element != "uses-permission-sdk-23" || last.Name != "android.permission.RECORD_AUDIO" || *last.MaxSDK != 32 {
		t.Fatalf("sdk-23 permission: %+v", last)
	}
	if pkg.Manifest.PermissionTrees != 1 || pkg.Manifest.PermissionGroups != 1 {
		t.Fatal("permission tree/group counts")
	}
}

func TestEmbeddedConfig(t *testing.T) {
	withConfig := func(raw string) []byte {
		s := apktest.Default()
		s.AppConfigRaw = []byte(raw)
		return build(t, s)
	}
	cases := map[string]struct {
		raw  string
		code string
	}{
		"duplicate top key":    {`{"slug":"a","slug":"b"}`, apk.CodeEmbeddedConfigDupKey},
		"duplicate nested key": {`{"extra":{"apiBaseUrl":"https://api.anyfun.win","apiBaseUrl":"https://evil.example"}}`, apk.CodeEmbeddedConfigDupKey},
		"duplicate by escape":  {`{"extra":{"apiBaseUrl":"x","apiBaseUrl":"y"}}`, apk.CodeEmbeddedConfigDupKey},
		"duplicate in array":   {`{"plugins":[{"a":1,"a":2}]}`, apk.CodeEmbeddedConfigDupKey},
		"not json":             {`{"slug":`, apk.CodeEmbeddedConfigInvalid},
		"array":                {`["slug"]`, apk.CodeEmbeddedConfigInvalid},
		"trailing":             {`{"slug":"a"} {"slug":"b"}`, apk.CodeEmbeddedConfigInvalid},
		"invalid utf8":         {"{\"slug\":\"\xff\"}", apk.CodeEmbeddedConfigInvalid},
		"too deep":             {strings.Repeat(`{"a":`, 70) + `1` + strings.Repeat(`}`, 70), apk.CodeEmbeddedConfigInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(withConfig(tc.raw))
			wantCode(t, err, tc.code)
		})
	}

	pkg, err := parse(withConfig(`{"extra":{"apiBaseUrl":42,"applicationId":null},"updates":{"enabled":"true"},"android":{"versionCode":46.5}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := pkg.AppConfig
	if c.APIBaseURL != nil || c.ApplicationID != nil || c.UpdatesEnabled != nil || c.AndroidVersionCode != nil || c.Slug != nil {
		t.Fatalf("wrong-typed values must read as absent: %+v", c)
	}

	s := apktest.Default()
	s.AppConfig, s.AppConfigRaw = nil, nil
	s.NativeFingerprint = ""
	s.ExtraEntries = []apktest.File{
		{Name: "assets/app.manifest", Data: []byte(`{"id":"x","extra":{"expoClient":{"extra":{"apiBaseUrl":"https://evil.example"}}}}`), Deflate: true},
		{Name: "assets/fingerprint", Data: []byte("  abc123\n"), Deflate: true},
	}
	pkg, err = parse(build(t, s))
	if err != nil {
		t.Fatal(err)
	}
	if pkg.AppConfig != nil || !pkg.HasAppManifest || pkg.AppManifest == nil || *pkg.AppManifest.APIBaseURL != "https://evil.example" {
		t.Fatalf("app.manifest: %+v %+v", pkg.AppConfig, pkg.AppManifest)
	}
	if *pkg.NativeFingerprint != "abc123" {
		t.Fatalf("fingerprint not trimmed: %q", *pkg.NativeFingerprint)
	}

	s.ExtraEntries = []apktest.File{{Name: "assets/app.manifest", Data: []byte(`{"id":"x"}`)}}
	if pkg, err = parse(build(t, s)); err != nil || !pkg.HasAppManifest || pkg.AppManifest != nil {
		t.Fatalf("app.manifest without expoClient: %v", err)
	}
	s.ExtraEntries = []apktest.File{{Name: "assets/app.manifest", Data: []byte(`{"id":"x","id":"y"}`)}}
	_, err = parse(build(t, s))
	wantCode(t, err, apk.CodeEmbeddedConfigDupKey)
	s.ExtraEntries = []apktest.File{{Name: "assets/fingerprint", Data: []byte("\xfe\xff")}}
	_, err = parse(build(t, s))
	wantCode(t, err, apk.CodeEmbeddedConfigInvalid)
}

func TestParseFile(t *testing.T) {
	data := build(t, apktest.Default())
	dir := t.TempDir()
	path := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pkg, err := apk.ParseFile(path, apk.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if pkg.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256")
	}
	_, err = apk.ParseFile(dir, apk.DefaultLimits())
	wantCode(t, err, apk.CodeReadFailed)
	_, err = apk.ParseFile(filepath.Join(dir, "missing.apk"), apk.DefaultLimits())
	wantCode(t, err, apk.CodeReadFailed)
}

// 数据描述符：本地头里 CRC 与大小为 0，数据后面跟描述符，仍然可以解析；描述符不符则拒绝。
func TestDataDescriptor(t *testing.T) {
	manifestBytes, err := axml.Encode(apktest.ManifestNode(apktest.Default()))
	if err != nil {
		t.Fatal(err)
	}
	for _, withSignature := range []bool{true, false} {
		b, err := apktest.WriteZip([]apktest.File{{Name: "AndroidManifest.xml", Data: manifestBytes}}, apktest.ZipOptions{})
		if err != nil {
			t.Fatal(err)
		}
		cdOffset := int(binary.LittleEndian.Uint32(b[len(b)-22+16:]))
		crc := crc32.ChecksumIEEE(manifestBytes)
		desc := []byte{}
		if withSignature {
			desc = binary.LittleEndian.AppendUint32(desc, 0x08074b50)
		}
		desc = binary.LittleEndian.AppendUint32(desc, crc)
		desc = binary.LittleEndian.AppendUint32(desc, uint32(len(manifestBytes)))
		desc = binary.LittleEndian.AppendUint32(desc, uint32(len(manifestBytes)))
		out := append(append(cloneBytes(b[:cdOffset]), desc...), b[cdOffset:]...)
		// 标志位第 3 位，本地头 CRC/大小清零
		binary.LittleEndian.PutUint16(out[6:], 1<<3)
		binary.LittleEndian.PutUint32(out[14:], 0)
		binary.LittleEndian.PutUint32(out[18:], 0)
		binary.LittleEndian.PutUint32(out[22:], 0)
		newCD := cdOffset + len(desc)
		binary.LittleEndian.PutUint16(out[newCD+8:], 1<<3)
		binary.LittleEndian.PutUint32(out[len(out)-22+16:], uint32(newCD))
		if _, err := parse(out); err != nil {
			t.Fatalf("data descriptor (signature=%v) rejected: %v", withSignature, err)
		}
		bad := cloneBytes(out)
		binary.LittleEndian.PutUint32(bad[newCD-8:], uint32(len(manifestBytes)+1))
		if _, err := parse(bad); err == nil {
			t.Fatalf("mismatched data descriptor (signature=%v) accepted", withSignature)
		}
	}
}
