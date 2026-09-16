package pkcs12

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// 测试用的迭代次数：格式与默认值相同，只是快。
const testIterations = 1000

type keyPair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

var (
	pairsOnce sync.Once
	pairs     [2]keyPair
)

// testPairs 生成两对 2048 位 RSA 密钥与自签证书，整个包共用。
func testPairs(t testing.TB) [2]keyPair {
	t.Helper()
	pairsOnce.Do(func() {
		for i := range pairs {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			pairs[i] = keyPair{key: key, cert: selfSigned(key, fmt.Sprintf("pkcs12 test %d", i))}
		}
	})
	return pairs
}

func selfSigned(key *rsa.PrivateKey, cn string) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

func randomPassword(t testing.TB) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("pw-%x", b)
}

func sha256Mac() macHash { return macHash{sha256.New, sha256.Size, sha256.BlockSize} }

// fileWithBags 用任意 SafeBag 拼出 MAC 正确的文件。
func fileWithBags(t testing.TB, password string, bags ...[]byte) []byte {
	t.Helper()
	authSafe := derSequence(dataContentInfo(derSequence(bags...)))
	out, err := assemble(authSafe, password, testIterations, sha256Mac(), oidSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func attrs(t testing.TB, alias string, id []byte) []byte {
	t.Helper()
	a, err := bagAttributes(alias, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func shrouded(t testing.TB, p keyPair, password string, attributes []byte) []byte {
	t.Helper()
	bag, err := shroudedKeyBag(p.key, password, testIterations, attributes)
	if err != nil {
		t.Fatal(err)
	}
	return bag
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	data, err := Encode(p.key, p.cert, "anyfun-release", password)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Decode(data, password)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Alias != "anyfun-release" {
		t.Fatalf("entries: %v", entries)
	}
	if !p.key.Equal(entries[0].PrivateKey) {
		t.Fatal("private key did not round trip")
	}
	want := fingerprint.SHA256Hex(p.cert.Raw)
	if CertificateSHA256(entries[0]) != want {
		t.Fatal("certificate did not round trip")
	}
	if len(entries[0].Chain) != 1 || !entries[0].Chain[0].Equal(p.cert) {
		t.Fatal("chain of a self-signed certificate should be just the leaf")
	}
	found, err := FindKey(data, password, "anyfun-release")
	if err != nil || CertificateSHA256(found) != want {
		t.Fatalf("FindKey: %v", err)
	}
	if CertificateSHA256(KeyEntry{}) != "" {
		t.Fatal("empty entry should have no fingerprint")
	}
}

func TestWrongPasswordAndTampering(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	data, err := encode(p.key, p.cert, "k", password, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data, password+"x"); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := Decode(data, ""); err == nil {
		t.Fatal("empty password accepted")
	}

	// 改 MAC 摘要本身
	mac := extractMACDigest(t, data)
	i := bytes.Index(data, mac)
	if i < 0 {
		t.Fatal("MAC digest not found")
	}
	tampered := bytes.Clone(data)
	tampered[i] ^= 1
	if _, err := Decode(tampered, password); !errors.Is(err, ErrPassword) {
		t.Fatalf("tampered MAC: %v", err)
	}

	// 改证书里的一个字节（MAC 覆盖的内容）
	j := bytes.Index(data, p.cert.RawSubject)
	tampered = bytes.Clone(data)
	tampered[j+len(p.cert.RawSubject)-1] ^= 1
	if _, err := Decode(tampered, password); !errors.Is(err, ErrPassword) {
		t.Fatalf("tampered content: %v", err)
	}
}

// extractMACDigest 从 PFX 里取出 MacData 的摘要字节。
func extractMACDigest(t *testing.T, data []byte) []byte {
	t.Helper()
	pfx, err := parseOnly(data)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := children(pfx, 3)
	if err != nil {
		t.Fatal(err)
	}
	macData, _ := children(parts[2], 3)
	digestInfo, _ := children(macData[0], 2)
	return digestInfo[1].Bytes
}

// 私钥密文被改、但 MAC 重新算对（知道口令的人构造）：必须解密失败，不能返回垃圾私钥。
func TestTamperedEncryptedKeyWithValidMAC(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	// 不挂属性，bag 的最后若干字节就是 AES-CBC 密文
	bag := shrouded(t, p, password, nil)
	for _, offset := range []int{16, 64} {
		tampered := bytes.Clone(bag)
		tampered[len(tampered)-offset] ^= 0x80
		data := fileWithBags(t, password, certificateBag(p.cert.Raw, nil), tampered)
		if _, err := Decode(data, password); err == nil {
			t.Fatalf("offset %d: a tampered encrypted key decoded", offset)
		}
	}
}

func TestTwoKeyEntries(t *testing.T) {
	ps := testPairs(t)
	password := randomPassword(t)
	data := fileWithBags(t, password,
		certificateBag(ps[0].cert.Raw, attrs(t, "a", []byte("1"))), shrouded(t, ps[0], password, attrs(t, "a", []byte("1"))),
		certificateBag(ps[1].cert.Raw, attrs(t, "b", []byte("2"))), shrouded(t, ps[1], password, attrs(t, "b", []byte("2"))),
	)
	entries, err := Decode(data, password)
	if err != nil || len(entries) != 2 {
		t.Fatalf("Decode: %v %v", entries, err)
	}
	if _, err := FindKey(data, password, "a"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("FindKey on two entries: %v", err)
	}
	if _, err := SingleKey(data, password); err == nil {
		t.Fatal("SingleKey accepted two entries")
	}
}

func TestAliasMismatch(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	data, err := encode(p.key, p.cert, "anyfun-release", password, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FindKey(data, password, "other"); err == nil {
		t.Fatal("alias mismatch accepted")
	}
}

func TestKeyCertificatePairing(t *testing.T) {
	ps := testPairs(t)
	password := randomPassword(t)
	// localKeyId 指向一张不属于这把私钥的证书
	wrong := fileWithBags(t, password,
		certificateBag(ps[1].cert.Raw, attrs(t, "k", []byte("id"))),
		shrouded(t, ps[0], password, attrs(t, "k", []byte("id"))),
	)
	if _, err := Decode(wrong, password); err == nil {
		t.Fatal("mismatched certificate accepted")
	}
	// 没有证书
	noCert := fileWithBags(t, password, shrouded(t, ps[0], password, attrs(t, "k", []byte("id"))))
	if _, err := Decode(noCert, password); err == nil {
		t.Fatal("key without certificate accepted")
	}
	// 没有 localKeyId：按公钥配对；别名取证书上的
	byKey := fileWithBags(t, password,
		certificateBag(ps[1].cert.Raw, nil),
		certificateBag(ps[0].cert.Raw, attrs(t, "k", []byte("x"))),
		shrouded(t, ps[0], password, nil),
	)
	entry, err := SingleKey(byKey, password)
	if err != nil || entry.Alias != "k" || !entry.Certificate.Equal(ps[0].cert) {
		t.Fatalf("public-key pairing: %v %v", entry, err)
	}
	// 私钥与证书的 friendlyName 不同
	conflict := fileWithBags(t, password,
		certificateBag(ps[0].cert.Raw, attrs(t, "a", []byte("id"))),
		shrouded(t, ps[0], password, attrs(t, "b", []byte("id"))),
	)
	if _, err := Decode(conflict, password); err == nil {
		t.Fatal("conflicting friendlyNames accepted")
	}
}

func TestUnencryptedKeyBag(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	a := attrs(t, "plain", []byte("id"))
	data := fileWithBags(t, password,
		certificateBag(p.cert.Raw, a),
		derSequence(derOID(oidKeyBag), derExplicit0(pkcs8), a),
	)
	entry, err := FindKey(data, password, "plain")
	if err != nil || !p.key.Equal(entry.PrivateKey) {
		t.Fatalf("keyBag: %v", err)
	}
}

func TestEncryptedDataContentInfo(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	a := attrs(t, "k", []byte("id"))
	certContents := derSequence(certificateBag(p.cert.Raw, a))
	encrypted := encryptedContentInfo(t, certContents, password)
	authSafe := derSequence(encrypted, dataContentInfo(derSequence(shrouded(t, p, password, a))))
	data, err := assemble(authSafe, password, testIterations, sha256Mac(), oidSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FindKey(data, password, "k"); err != nil {
		t.Fatalf("encryptedData content info: %v", err)
	}
}

// encryptedContentInfo 用 PBES2 把 SafeContents 包成 encryptedData（keytool 对证书就是这么做的）。
func encryptedContentInfo(t testing.TB, safeContents []byte, password string) []byte {
	t.Helper()
	epki, err := encryptPBES2(safeContents, password, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := parseOnly(epki)
	items, _ := children(v, 2)
	eci := derSequence(derOID(oidData), items[0].FullBytes, derImplicit0Octets(items[1].Bytes))
	return derSequence(derOID(oidEncryptedData), derExplicit0(derSequence(derInt(0), eci)))
}

func TestLegacyEncryptionRejected(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	legacy := asn1OID(1, 2, 840, 113549, 1, 12, 1, 3) // pbeWithSHAAnd3-KeyTripleDES-CBC
	params := derSequence(derOctets([]byte("saltsalt")), derInt(2048))
	eci := derSequence(derOID(oidData), derSequence(derOID(legacy), params), derImplicit0Octets(make([]byte, 32)))
	encrypted := derSequence(derOID(oidEncryptedData), derExplicit0(derSequence(derInt(0), eci)))
	a := attrs(t, "k", []byte("id"))
	authSafe := derSequence(encrypted, dataContentInfo(derSequence(certificateBag(p.cert.Raw, a))))
	data, err := assemble(authSafe, password, testIterations, macHash{sha1.New, sha1.Size, sha1.BlockSize}, oidSHA1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data, password); !errors.Is(err, ErrLegacyEncryption) {
		t.Fatalf("legacy encryption: %v", err)
	}
	for _, oid := range [][]int{{1, 2, 840, 113549, 1, 5, 3}, {1, 2, 840, 113549, 3, 7}, {1, 2, 840, 113549, 1, 12, 1, 6}} {
		if !isLegacyEncryption(asn1OID(oid...)) {
			t.Errorf("%v not classified as legacy", oid)
		}
	}
	for _, oid := range [][]int{{1, 2, 840, 113549, 1, 5, 13}, {1, 2, 840, 113549, 1, 5, 12}, {2, 16, 840, 1, 101, 3, 4, 1, 42}} {
		if isLegacyEncryption(asn1OID(oid...)) {
			t.Errorf("%v classified as legacy", oid)
		}
	}
}

func asn1OID(parts ...int) []int { return parts }

func TestMACRequirementsAndLimits(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	a := attrs(t, "k", []byte("id"))
	authSafe := derSequence(dataContentInfo(derSequence(certificateBag(p.cert.Raw, a), shrouded(t, p, password, a))))

	noMAC := derSequence(derInt(3), dataContentInfo(authSafe))
	if _, err := Decode(noMAC, password); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("missing MAC: %v", err)
	}
	for _, iterations := range []int{0, maxIterations + 1} {
		macData := derSequence(
			derSequence(derSequence(derOID(oidSHA256), derNull), derOctets(make([]byte, 32))),
			derOctets([]byte("salt")), derInt(iterations))
		data := derSequence(derInt(3), dataContentInfo(authSafe), macData)
		if _, err := Decode(data, password); !errors.Is(err, ErrMalformed) {
			t.Errorf("iterations %d: %v", iterations, err)
		}
	}
	md5 := derSequence(
		derSequence(derSequence(derOID(asn1OID(1, 2, 840, 113549, 2, 5)), derNull), derOctets(make([]byte, 16))),
		derOctets([]byte("salt")), derInt(1))
	if _, err := Decode(derSequence(derInt(3), dataContentInfo(authSafe), md5), password); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("MD5 MAC: %v", err)
	}
	for _, h := range []struct {
		mh  macHash
		oid []int
	}{
		{macHash{sha1.New, sha1.Size, sha1.BlockSize}, oidSHA1},
		{sha256Mac(), oidSHA256},
	} {
		data, err := assemble(authSafe, password, 3, h.mh, h.oid)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := FindKey(data, password, "k"); err != nil {
			t.Fatalf("MAC %v: %v", h.oid, err)
		}
	}
	wrongVersion := bytes.Clone(fileWithBags(t, password, certificateBag(p.cert.Raw, a), shrouded(t, p, password, a)))
	// 版本号在 SEQUENCE 头之后的 INTEGER 里：把 3 改成 2
	idx := bytes.Index(wrongVersion, []byte{0x02, 0x01, 0x03})
	wrongVersion[idx+2] = 2
	if _, err := Decode(wrongVersion, password); !errors.Is(err, ErrMalformed) {
		t.Fatalf("version 2: %v", err)
	}
}

func TestGarbageAndTruncationDoNotPanic(t *testing.T) {
	p := testPairs(t)[0]
	password := randomPassword(t)
	data, err := encode(p.key, p.cert, "k", password, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(data); n += 7 {
		if _, err := Decode(data[:n], password); err == nil {
			t.Fatalf("truncated to %d bytes decoded", n)
		}
	}
	for _, garbage := range [][]byte{nil, {0x30}, {0x30, 0x80, 0, 0}, bytes.Repeat([]byte{0x30, 0x82}, 100), make([]byte, MaxInputSize+1)} {
		if _, err := Decode(garbage, password); err == nil {
			t.Fatal("garbage decoded")
		}
	}
	if _, err := Decode(append(bytes.Clone(data), 0), password); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

func TestEncodeRejectsBadInput(t *testing.T) {
	ps := testPairs(t)
	for name, fn := range map[string]func() error{
		"alias with space":     func() error { _, err := Encode(ps[0].key, ps[0].cert, "my alias", "pw"); return err },
		"empty alias":          func() error { _, err := Encode(ps[0].key, ps[0].cert, "", "pw"); return err },
		"empty password":       func() error { _, err := Encode(ps[0].key, ps[0].cert, "k", ""); return err },
		"NUL password":         func() error { _, err := encode(ps[0].key, ps[0].cert, "k", "a\x00b", 1); return err },
		"certificate mismatch": func() error { _, err := Encode(ps[0].key, ps[1].cert, "k", "pw"); return err },
		"nil key":              func() error { _, err := Encode(nil, ps[0].cert, "k", "pw"); return err },
	} {
		if fn() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyEntryNeverFormatsPrivateKey(t *testing.T) {
	p := testPairs(t)[0]
	entry := KeyEntry{Alias: "k", Certificate: p.cert, Chain: []*x509.Certificate{p.cert}, PrivateKey: p.key}
	secrets := []string{p.key.D.String(), p.key.D.Text(16), p.key.Primes[0].String(), p.key.Primes[0].Text(16)}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, entry), fmt.Sprintf(verb, &entry), fmt.Sprintf(verb, []KeyEntry{entry}),
			fmt.Sprintf(verb, struct{ E KeyEntry }{entry}))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("entry", "e", entry)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("entry", "e", &entry)
	outputs = append(outputs, buf.String())
	if raw, err := json.Marshal(entry); err == nil {
		t.Fatalf("json.Marshal succeeded: %.40s…", raw)
	}
	for _, out := range outputs {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Fatalf("formatted output leaks key material: %.80s…", out)
			}
		}
	}
	if !strings.Contains(entry.String(), fingerprint.SHA256Hex(p.cert.Raw)) {
		t.Fatal("fingerprint missing from the formatted entry")
	}
}

func TestDecodeBMPString(t *testing.T) {
	for _, bad := range [][]byte{{0x00}, {0x00, 0x00}, {0xd8, 0x00}, {0xdc, 0x00, 0x00, 0x41}} {
		if _, err := decodeBMPString(bad); err == nil {
			t.Errorf("%x accepted", bad)
		}
	}
	good, _ := bmpString("k😀")
	if s, err := decodeBMPString(good); err != nil || s != "k😀" {
		t.Fatalf("round trip: %q %v", s, err)
	}
}

// 一个文件的 KDF 总工作量有上限：密文可能来自不可信的一方，不能让它把签名闸拖上几个小时。
func TestKDFWorkBudget(t *testing.T) {
	var w workBudget
	if err := w.spend(maxIterations); err != nil {
		t.Fatalf("a single maximal KDF was refused: %v", err)
	}
	if err := w.spend(1); !errors.Is(err, ErrMalformed) {
		t.Fatalf("budget not enforced: %v", err)
	}
	for _, n := range []int{0, -1, maxIterations + 1} {
		var fresh workBudget
		if err := fresh.spend(n); !errors.Is(err, ErrMalformed) {
			t.Errorf("iterations %d accepted", n)
		}
	}

	p := testPairs(t)[0]
	password := randomPassword(t)
	bags := derSequence(shrouded(t, p, password, nil))
	almostSpent := workBudget{spent: maxTotalIterations - testIterations + 1}
	var keys []keyItem
	var certs []certItem
	count := 0
	if err := parseSafeContents(bags, password, &almostSpent, &keys, &certs, &count); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bag decryption past the budget: %v", err)
	}
	enough := workBudget{spent: maxTotalIterations - testIterations}
	if err := parseSafeContents(bags, password, &enough, &keys, &certs, &count); err != nil || len(keys) != 1 {
		t.Fatalf("bag decryption within the budget: %v", err)
	}
}
