package api

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Helix2010/RN-Server/internal/apkinspect"
)

// 已签名 APK 夹具：测试里现场生成，不提交二进制。
//
// 服务端入库校验走的是真的 apkinspect（androidbinary 解析二进制 manifest、apkverifier 验
// APK Signature Scheme v2），所以这里要造一个它们都认的包：二进制 AndroidManifest.xml、
// 最小的 resources.arsc、内嵌 Expo 配置，再按 v2 规范插一个 APK Signing Block。
// 签名用 ECDSA P-256（算法 0x0201），证书是现场生成的自签证书；证书 DER 的 sha256
// 就是 apkinspect 报出来的签名者指纹。

type apkSigner struct {
	key         *ecdsa.PrivateKey
	certificate []byte
}

func (s apkSigner) sha256() string {
	sum := sha256.Sum256(s.certificate)
	return hex.EncodeToString(sum[:])
}

func newAPKSigner(t *testing.T) apkSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rn-signing-gate-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return apkSigner{key: key, certificate: der}
}

type apkSpec struct {
	PackageName   string
	VersionCode   int
	VersionName   string
	MinSDK        int
	ApplicationID string
	Fingerprint   string
}

// buildSignedAPK 造一个 v2 签名的 APK；signer 为 nil 时返回未签名的包。
func buildSignedAPK(t *testing.T, spec apkSpec, signer *apkSigner) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	add := func(name string, body []byte) {
		writer, err := archive.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	add("AndroidManifest.xml", binaryManifest(spec))
	add("resources.arsc", minimalResourceTable())
	add("assets/app.config", []byte(`{"runtimeVersion":"`+spec.VersionName+`","extra":{"applicationId":"`+spec.ApplicationID+`"}}`))
	if spec.Fingerprint != "" {
		add("assets/fingerprint", []byte(spec.Fingerprint))
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	unsigned := buffer.Bytes()
	if signer == nil {
		return unsigned
	}
	return signAPKv2(t, unsigned, *signer)
}

// ---- 二进制 XML ----

type axmlStrings struct {
	list  []string
	index map[string]uint32
}

func (p *axmlStrings) ref(value string) uint32 {
	if p.index == nil {
		p.index = map[string]uint32{}
	}
	if i, ok := p.index[value]; ok {
		return i
	}
	p.index[value] = uint32(len(p.list))
	p.list = append(p.list, value)
	return p.index[value]
}

func (p *axmlStrings) chunk() []byte {
	var data bytes.Buffer
	offsets := make([]uint32, 0, len(p.list))
	for _, value := range p.list {
		offsets = append(offsets, uint32(data.Len()))
		units := utf16.Encode([]rune(value))
		_ = binary.Write(&data, binary.LittleEndian, uint16(len(units)))
		_ = binary.Write(&data, binary.LittleEndian, units)
		_ = binary.Write(&data, binary.LittleEndian, uint16(0))
	}
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	headerSize := uint32(28)
	stringsStart := headerSize + 4*uint32(len(p.list))
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0x0001))
	_ = binary.Write(&out, binary.LittleEndian, uint16(headerSize))
	_ = binary.Write(&out, binary.LittleEndian, stringsStart+uint32(data.Len()))
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(p.list)))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // styles
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // flags：UTF-16
	_ = binary.Write(&out, binary.LittleEndian, stringsStart)
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	_ = binary.Write(&out, binary.LittleEndian, offsets)
	out.Write(data.Bytes())
	return out.Bytes()
}

type axmlAttr struct {
	namespace string
	name      string
	text      string
	intValue  int
	isInt     bool
}

func binaryManifest(spec apkSpec) []byte {
	const androidNS = "http://schemas.android.com/apk/res/android"
	const none = ^uint32(0)
	pool := &axmlStrings{}
	var body bytes.Buffer
	node := func(chunkType uint16, size uint32) {
		_ = binary.Write(&body, binary.LittleEndian, chunkType)
		_ = binary.Write(&body, binary.LittleEndian, uint16(16))
		_ = binary.Write(&body, binary.LittleEndian, size)
		_ = binary.Write(&body, binary.LittleEndian, uint32(1)) // line
		_ = binary.Write(&body, binary.LittleEndian, none)      // comment
	}
	// androidbinary 把前缀的字符串下标 0 当成"没有这个命名空间"，所以 URI 先进池子，前缀不落在 0 上
	uri := pool.ref(androidNS)
	prefix := pool.ref("android")
	node(0x0100, 24)
	_ = binary.Write(&body, binary.LittleEndian, prefix)
	_ = binary.Write(&body, binary.LittleEndian, uri)
	start := func(name string, attrs []axmlAttr) {
		node(0x0102, 16+20+20*uint32(len(attrs)))
		_ = binary.Write(&body, binary.LittleEndian, none)
		_ = binary.Write(&body, binary.LittleEndian, pool.ref(name))
		for _, v := range []uint16{20, 20, uint16(len(attrs)), 0, 0, 0} {
			_ = binary.Write(&body, binary.LittleEndian, v)
		}
		for _, attr := range attrs {
			ns := none
			if attr.namespace != "" {
				ns = pool.ref(attr.namespace)
			}
			_ = binary.Write(&body, binary.LittleEndian, ns)
			_ = binary.Write(&body, binary.LittleEndian, pool.ref(attr.name))
			if attr.isInt {
				_ = binary.Write(&body, binary.LittleEndian, none)
				_ = binary.Write(&body, binary.LittleEndian, []byte{8, 0, 0, 0x10})
				_ = binary.Write(&body, binary.LittleEndian, uint32(attr.intValue))
			} else {
				ref := pool.ref(attr.text)
				_ = binary.Write(&body, binary.LittleEndian, ref)
				_ = binary.Write(&body, binary.LittleEndian, []byte{8, 0, 0, 0x03})
				_ = binary.Write(&body, binary.LittleEndian, ref)
			}
		}
	}
	end := func(name string) {
		node(0x0103, 24)
		_ = binary.Write(&body, binary.LittleEndian, none)
		_ = binary.Write(&body, binary.LittleEndian, pool.ref(name))
	}
	start("manifest", []axmlAttr{
		{namespace: androidNS, name: "versionCode", intValue: spec.VersionCode, isInt: true},
		{namespace: androidNS, name: "versionName", text: spec.VersionName},
		{name: "package", text: spec.PackageName},
	})
	start("uses-sdk", []axmlAttr{
		{namespace: androidNS, name: "minSdkVersion", intValue: spec.MinSDK, isInt: true},
		{namespace: androidNS, name: "targetSdkVersion", intValue: 34, isInt: true},
	})
	end("uses-sdk")
	start("application", nil)
	end("application")
	end("manifest")
	node(0x0101, 24)
	_ = binary.Write(&body, binary.LittleEndian, prefix)
	_ = binary.Write(&body, binary.LittleEndian, uri)

	strings := pool.chunk()
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0x0003))
	_ = binary.Write(&out, binary.LittleEndian, uint16(8))
	_ = binary.Write(&out, binary.LittleEndian, uint32(8+len(strings)+body.Len()))
	out.Write(strings)
	out.Write(body.Bytes())
	return out.Bytes()
}

func minimalResourceTable() []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0x0002))
	_ = binary.Write(&out, binary.LittleEndian, uint16(12))
	_ = binary.Write(&out, binary.LittleEndian, uint32(12))
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))
	return out.Bytes()
}

// ---- APK Signature Scheme v2 ----

func lengthPrefixed(parts ...[]byte) []byte {
	var out bytes.Buffer
	for _, part := range parts {
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(part)))
		out.Write(part)
	}
	return out.Bytes()
}

func uint32LE(v uint32) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, v)
	return out
}

func signAPKv2(t *testing.T, unsigned []byte, signer apkSigner) []byte {
	t.Helper()
	eocd := bytes.LastIndex(unsigned, []byte{0x50, 0x4b, 0x05, 0x06})
	if eocd < 0 {
		t.Fatal("no end of central directory")
	}
	cdOffset := binary.LittleEndian.Uint32(unsigned[eocd+16:])
	entries, centralDirectory, end := unsigned[:cdOffset], unsigned[cdOffset:eocd], append([]byte(nil), unsigned[eocd:]...)

	// 摘要：三段内容按 1 MiB 切块，每块 sha256(0xa5 || len || chunk)，再 sha256(0x5a || count || 各块摘要)
	chunkDigests := [][]byte{}
	for _, section := range [][]byte{entries, centralDirectory, end} {
		for offset := 0; offset < len(section); offset += 1 << 20 {
			limit := offset + 1<<20
			if limit > len(section) {
				limit = len(section)
			}
			chunk := section[offset:limit]
			h := sha256.New()
			h.Write([]byte{0xa5})
			h.Write(uint32LE(uint32(len(chunk))))
			h.Write(chunk)
			chunkDigests = append(chunkDigests, h.Sum(nil))
		}
	}
	top := sha256.New()
	top.Write([]byte{0x5a})
	top.Write(uint32LE(uint32(len(chunkDigests))))
	for _, digest := range chunkDigests {
		top.Write(digest)
	}
	const algorithm = 0x0201 // ECDSA with SHA-256
	digests := lengthPrefixed(append(uint32LE(algorithm), lengthPrefixed(top.Sum(nil))...))
	signedData := append(append(lengthPrefixed(digests), lengthPrefixed(lengthPrefixed(signer.certificate))...), lengthPrefixed(nil)...)
	sum := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, signer.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&signer.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signatures := lengthPrefixed(append(uint32LE(algorithm), lengthPrefixed(signature)...))
	signerBlock := append(append(lengthPrefixed(signedData), lengthPrefixed(signatures)...), lengthPrefixed(publicKey)...)
	value := lengthPrefixed(lengthPrefixed(signerBlock))

	var pair bytes.Buffer
	_ = binary.Write(&pair, binary.LittleEndian, uint64(4+len(value)))
	_ = binary.Write(&pair, binary.LittleEndian, uint32(0x7109871a))
	pair.Write(value)
	blockSize := uint64(pair.Len() + 8 + 16)
	var block bytes.Buffer
	_ = binary.Write(&block, binary.LittleEndian, blockSize)
	block.Write(pair.Bytes())
	_ = binary.Write(&block, binary.LittleEndian, blockSize)
	block.WriteString("APK Sig Block 42")

	binary.LittleEndian.PutUint32(end[16:], cdOffset+uint32(block.Len()))
	var out bytes.Buffer
	out.Write(entries)
	out.Write(block.Bytes())
	out.Write(centralDirectory)
	out.Write(end)
	return out.Bytes()
}

// 夹具本身要被真的 apkinspect 接受，否则用它的入库测试什么都证明不了。
func TestAPKFixtureIsAcceptedByApkinspect(t *testing.T) {
	signer := newAPKSigner(t)
	spec := apkSpec{PackageName: "com.fixture.app", VersionCode: 42, VersionName: "1.4.2", MinSDK: 24, ApplicationID: "dex-mobile", Fingerprint: "abc123"}
	path := t.TempDir() + "/signed.apk"
	if err := os.WriteFile(path, buildSignedAPK(t, spec, &signer), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata, err := apkinspect.Inspect(path)
	if err != nil {
		t.Fatalf("apkinspect refused the fixture: %v", err)
	}
	if metadata.PackageName != spec.PackageName || metadata.VersionCode != 42 || metadata.VersionName != "1.4.2" || metadata.MinSDK != 24 {
		t.Fatalf("manifest fields: %+v", metadata)
	}
	if metadata.SignerSHA256 != signer.sha256() || metadata.SigningScheme != 2 {
		t.Fatalf("signer %s scheme %d, want %s v2", metadata.SignerSHA256, metadata.SigningScheme, signer.sha256())
	}
	if metadata.ApplicationID != "dex-mobile" || metadata.RuntimeVersion != "abc123" {
		t.Fatalf("embedded config: %+v", metadata)
	}
	unsignedPath := t.TempDir() + "/unsigned.apk"
	if err := os.WriteFile(unsignedPath, buildSignedAPK(t, spec, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := apkinspect.Inspect(unsignedPath); err == nil {
		t.Fatal("an unsigned fixture passed signature verification")
	}
}
