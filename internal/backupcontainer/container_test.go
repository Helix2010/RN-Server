package backupcontainer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 3072 位够用而且比 4096 快得多；测试里生成密钥是最慢的一步
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, minRecipientBits)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func seal(t *testing.T, pub *rsa.PublicKey, layer Layer, payload []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	meta := Meta{Layer: layer, Seq: 42, InstanceID: "test-1"}
	if err := Seal(&out, pub, meta, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return out.Bytes()
}

func TestRoundTrip(t *testing.T) {
	key := testKey(t)
	// 覆盖三种长度：空、不对齐、正好对齐一个分组的整数倍（tar 的真实形状）
	for _, size := range []int{0, 1, 15, 16, 17, 512, 4096, 70000} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		sealed := seal(t, &key.PublicKey, LayerInner, payload)
		meta, got, err := Open(bytes.NewReader(sealed), key)
		if err != nil {
			t.Fatalf("size %d: open: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: payload round-trip mismatch", size)
		}
		if meta.Format != Format || meta.Alg != Alg || meta.Layer != LayerInner {
			t.Fatalf("size %d: meta not preserved: %+v", size, meta)
		}
		if meta.Seq != 42 || meta.InstanceID != "test-1" {
			t.Fatalf("size %d: seq/instanceId not preserved: %+v", size, meta)
		}
	}
}

// 封出来的长度必须和 SealedSize 说的一致——tar 头是照着它写的，对不上 tar 就是坏的
func TestSealedSizeMatchesReality(t *testing.T) {
	key := testKey(t)
	for _, size := range []int64{0, 1, 15, 16, 1000, 10240} {
		payload := make([]byte, size)
		sealed := seal(t, &key.PublicKey, LayerOuter, payload)
		members, err := readMembers(bytes.NewReader(sealed))
		if err != nil {
			t.Fatal(err)
		}
		if got := int64(len(members[payloadName])); got != SealedSize(size) {
			t.Fatalf("plaintext %d: SealedSize says %d, actual ciphertext %d", size, SealedSize(size), got)
		}
	}
}

// 每一层必须独立取 80 字节。复用一旦发生，外层的 key.bin（外层那个人能解）里就直接
// 躺着内层的 AES 密钥，两把锁塌成一把——而这个 bug 在往返测试下完全正常
func TestEachLayerDrawsItsOwnKeyMaterial(t *testing.T) {
	key := testKey(t)
	payload := []byte("same payload both times")
	a := seal(t, &key.PublicKey, LayerInner, payload)
	b := seal(t, &key.PublicKey, LayerOuter, payload)

	ma, err := readMembers(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	mb, err := readMembers(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ma[payloadName], mb[payloadName]) {
		t.Fatal("two layers produced identical ciphertext: key material or IV is being reused")
	}

	materialA, err := rsa.DecryptOAEP(newSHA256(), nil, key, ma[keyName], nil)
	if err != nil {
		t.Fatal(err)
	}
	materialB, err := rsa.DecryptOAEP(newSHA256(), nil, key, mb[keyName], nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(materialA, materialB) {
		t.Fatal("two layers share the same 80 bytes of key material")
	}
}

func TestTamperedPayloadIsRejectedBeforeDecrypting(t *testing.T) {
	key := testKey(t)
	sealed := seal(t, &key.PublicKey, LayerInner, bytes.Repeat([]byte("payload "), 500))
	members, err := readMembers(bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	members[payloadName][10] ^= 0x01
	if _, _, err := Open(bytes.NewReader(rebuild(t, members)), key); err == nil {
		t.Fatal("a flipped bit in payload.enc was accepted")
	} else if !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("expected an integrity failure, got: %v", err)
	}
}

// v5 的 MAC 只覆盖 payload.enc，于是 layer / recipient / seq / alg 可以随便改而
// MAC 照样通过：改 recipient 能骗持有人「这个包不是给我的」，改 alg 是将来 format 2
// 出现时现成的降级通道
func TestTamperedMetaIsRejected(t *testing.T) {
	key := testKey(t)
	sealed := seal(t, &key.PublicKey, LayerInner, []byte("payload"))
	members, err := readMembers(bytes.NewReader(sealed))
	if err != nil {
		t.Fatal(err)
	}
	var meta Meta
	if err := json.Unmarshal(members[metaName], &meta); err != nil {
		t.Fatal(err)
	}
	meta.Layer = LayerOuter
	meta.Seq = 1
	meta.Recipient = strings.Repeat("0", 64)
	forged, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	members[metaName] = forged
	if _, _, err := Open(bytes.NewReader(rebuild(t, members)), key); err == nil {
		t.Fatal("a rewritten meta.json was accepted")
	}
}

func TestWrongKeyCannotOpen(t *testing.T) {
	mine, theirs := testKey(t), testKey(t)
	sealed := seal(t, &mine.PublicKey, LayerInner, []byte("secret"))
	if _, _, err := Open(bytes.NewReader(sealed), theirs); err == nil {
		t.Fatal("a layer sealed to one key was opened with another")
	}
}

func TestRecipientKeyTooSmall(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	err = Seal(&bytes.Buffer{}, &small.PublicKey, Meta{Layer: LayerInner}, bytes.NewReader(nil), 0)
	if err == nil || !strings.Contains(err.Error(), "2048 bits") {
		t.Fatalf("expected a key-size refusal, got: %v", err)
	}
}

// 说好的长度和实际读到的对不上时必须报错。tar 头已经写下去了，这个包是坏的,
// 不能让它安静地上传成功
func TestPayloadSizeMismatchFails(t *testing.T) {
	key := testKey(t)
	err := Seal(&bytes.Buffer{}, &key.PublicKey, Meta{Layer: LayerInner}, bytes.NewReader([]byte("five!")), 99)
	if err == nil || !strings.Contains(err.Error(), "expected 99") {
		t.Fatalf("expected a size mismatch, got: %v", err)
	}
}

// 指纹的定义必须和恢复端那条命令算出来的一模一样：
//
//	openssl rsa -in k.key -pubout -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
//
// 对不上的话，持有人核对指纹这个环节——整套方案里唯一防「填错、填串」的人工检查
// ——永远对不上，大家很快就会学会忽略它
func TestFingerprintMatchesOpenSSL(t *testing.T) {
	openssl := lookOpenSSL(t)
	key := testKey(t)
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "k.pub")
	writePEM(t, pubPath, "PUBLIC KEY", mustMarshalPKIX(t, &key.PublicKey))

	der := run(t, openssl, dir, "rsa", "-pubin", "-in", pubPath, "-pubout", "-outform", "DER")
	derPath := filepath.Join(dir, "k.der")
	if err := os.WriteFile(derPath, der, 0o600); err != nil {
		t.Fatal(err)
	}
	out := string(run(t, openssl, dir, "dgst", "-sha256", "-r", derPath))
	want := strings.Fields(out)[0]

	got, err := Fingerprint(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint mismatch:\n  ours:    %s\n  openssl: %s", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("fingerprint is %d chars, the spec says 64", len(got))
	}
}

// 这条是整个包里最重要的一条测试。
//
// 灾难当天唯一走的路径是 openssl，不是这个包。Go 封 Go 解的往返测试**发现不了**
// 漏写 PKCS#7 填充——它只在 openssl 那条路上炸，而且不是干净地炸：openssl 报
// bad decrypt、退出码 1，但已经写出了一个少 16 字节的文件，tar 照样能读。
//
// 这里逐字跑 README-FIRST.txt 里给持有人的那几条命令。它们变了，这条测试就得变，
// 而那正是我们想要的：那几条命令是产品的一部分。
func TestOpenSSLCanOpenWhatWeSeal(t *testing.T) {
	openssl := lookOpenSSL(t)
	key := testKey(t)
	dir := t.TempDir()

	keyPath := filepath.Join(dir, "recovery.key")
	writePEM(t, keyPath, "PRIVATE KEY", mustMarshalPKCS8(t, key))

	// 513 字节：既不是 16 的倍数，又跨越了多个 64 KiB 以外的边界情况；
	// 另外单独测一次 4096（16 的整数倍，PKCS#7 必须补满一整个分组）
	for _, size := range []int{513, 4096} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		sealed := seal(t, &key.PublicKey, LayerOuter, payload)
		pkgPath := filepath.Join(dir, "layer.rnbk")
		if err := os.WriteFile(pkgPath, sealed, 0o600); err != nil {
			t.Fatal(err)
		}

		work := filepath.Join(dir, "work")
		if err := os.MkdirAll(work, 0o700); err != nil {
			t.Fatal(err)
		}
		run(t, "tar", dir, "xf", pkgPath, "-C", work)

		// 1) 拆信封。显式写 rsa_mgf1_md 而不是靠默认：默认确实跟随 rsa_oaep_md，
		//    但那是隐式约定，而这条命令要在若干年后的未知 openssl 版本上跑
		run(t, openssl, work, "pkeyutl", "-decrypt", "-inkey", keyPath,
			"-pkeyopt", "rsa_padding_mode:oaep",
			"-pkeyopt", "rsa_oaep_md:sha256",
			"-pkeyopt", "rsa_mgf1_md:sha256",
			"-in", filepath.Join(work, keyName), "-out", filepath.Join(work, "k.bin"))

		material, err := os.ReadFile(filepath.Join(work, "k.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if len(material) != keyMaterialSize {
			t.Fatalf("openssl unwrapped %d bytes, the spec says %d", len(material), keyMaterialSize)
		}
		encHex := hexOf(material[:aesKeySize])
		macHex := hexOf(material[aesKeySize : aesKeySize+macKeySize])
		ivHex := hexOf(material[aesKeySize+macKeySize:])

		// 2) 先验 MAC，覆盖 meta.json ‖ key.bin ‖ payload.enc
		joined := filepath.Join(work, "joined.bin")
		concat(t, joined, filepath.Join(work, metaName), filepath.Join(work, keyName), filepath.Join(work, payloadName))
		calc := run(t, openssl, work, "dgst", "-sha256", "-mac", "HMAC", "-macopt", "hexkey:"+macHex, "-binary", joined)
		want, err := os.ReadFile(filepath.Join(work, macName))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(calc, want) {
			t.Fatal("openssl computed a different HMAC: the MAC covers a different byte range than the spec says")
		}

		// 3) 解密。不带 -nopad——生产端加了 PKCS#7，漏了这一步就在这里炸
		plainPath := filepath.Join(work, "plain.bin")
		run(t, openssl, work, "enc", "-d", "-aes-256-cbc", "-K", encHex, "-iv", ivHex,
			"-in", filepath.Join(work, payloadName), "-out", plainPath)

		got, err := os.ReadFile(plainPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: openssl decrypted %d bytes, expected %d — check PKCS#7 padding", size, len(got), len(payload))
		}
		if err := os.RemoveAll(work); err != nil {
			t.Fatal(err)
		}
	}
}
