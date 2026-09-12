// Package androidkeystore 生成 Android 打包用的签名 keystore。
//
// 为什么要自己拼 PKCS#12，而不是拿一个现成的库：Gradle 的 signingConfig 要
// storeFile + keyAlias 两个东西对得上，而 keystore 里的"别名"是 PKCS#12 的
// friendlyName 属性。现成的 Go 编码库（go-pkcs12、x/crypto/pkcs12）都不写这个
// 属性，Java 读到没有 friendlyName 的条目就按序号编号——别名会变成 "1"。
// 一个别名叫 "1" 的 keystore 能用，但运维用 keytool 打开时看到的东西和控制台上
// 写的对不上，而这条链路上"两处说法不一致"正是最贵的那类错。
//
// 输出的格式与 keytool 一致：私钥用 PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC）
// 加密，证书明文（它本来就是公开材料），整体一个 SHA-256 的 MAC。JDK 9 以上直接
// 读；AGP 不设 storeType，走的就是 Java 的默认类型 pkcs12。
package androidkeystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"unicode/utf16"
)

// 迭代次数。这把 keystore 一辈子只被打开几次（每次构建一次），所以可以取得比
// 库的默认值（2048）高得多——它挡的是"盒子被人拿到之后离线爆破 store 口令"。
const kdfIterations = 210_000

const saltLength = 16

var (
	oidDataContentType         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCertBag                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidPKCS8ShroudedKeyBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertTypeX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidPBES2                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHmacWithSHA256          = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA256                  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

type pfxPdu struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []pkcs12Attribute `asn1:"set,optional"`
}

type pkcs12Attribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm     pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KDF              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        pkix.AlgorithmIdentifier
}

// bmpString 把别名编成 PKCS#12 要的 BMPString（UTF-16BE）。
// Android 的别名实际上都是 ASCII，但编码要按规矩来，否则 Java 读出来是乱码。
func bmpString(value string) ([]byte, error) {
	units := utf16.Encode([]rune(value))
	out := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		// 代理对本身是合法的 UTF-16，但 0x0000 会被当成结束符
		if unit == 0 {
			return nil, errors.New("alias must not contain a NUL character")
		}
		out = append(out, byte(unit>>8), byte(unit))
	}
	return out, nil
}

// bmpStringZeroTerminated 是 PKCS#12 口令的编码：BMPString 后面再跟两个 0 字节。
// 只有 MAC 那一层用它；PBES2 那一层按 RFC 8018 用 UTF-8（Java 和 OpenSSL 都这样）。
func bmpStringZeroTerminated(value string) ([]byte, error) {
	encoded, err := bmpString(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, 0, 0), nil
}

// pkcs12KDF 是 RFC 7292 附录 B.2 那个专用的派生函数。只有 MAC 用得到它；
// 私钥那一层用的是 PBKDF2。
//
// id: 1=加密密钥 2=IV 3=MAC 密钥。u/v 是散列的输出长度与分组长度（SHA-256 是 32/64）。
func pkcs12KDF(salt, password []byte, iterations, id, size int) []byte {
	const u, v = sha256.Size, sha256.BlockSize

	fill := func(pattern []byte) []byte {
		if len(pattern) == 0 {
			return nil
		}
		out := make([]byte, ((len(pattern)+v-1)/v)*v)
		for i := range out {
			out[i] = pattern[i%len(pattern)]
		}
		return out
	}

	diversifier := make([]byte, v)
	for i := range diversifier {
		diversifier[i] = byte(id)
	}
	expanded := append(fill(salt), fill(password)...)

	var out []byte
	for len(out) < size {
		digest := sha256.Sum256(append(append([]byte{}, diversifier...), expanded...))
		for i := 1; i < iterations; i++ {
			digest = sha256.Sum256(digest[:])
		}
		out = append(out, digest[:]...)
		if len(out) >= size {
			break
		}
		// B.2 步骤 6：把 A 铺满 v 字节得到 B，再把 I 的每个 v 字节块加上 B+1
		b := fill(digest[:])[:v]
		for j := 0; j < len(expanded); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(expanded[j+k]) + int(b[k]) + carry
				expanded[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// pbkdf2SHA256 是 RFC 8018 的 PBKDF2。写在这里而不是引 x/crypto/pbkdf2，是因为
// 这几行比一条依赖便宜，而且这个文件已经在处理同一层的其它原语了。
func pbkdf2SHA256(password, salt []byte, iterations, size int) []byte {
	var out []byte
	for block := 1; len(out) < size; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		result := append([]byte{}, u...)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range result {
				result[j] ^= u[j]
			}
		}
		out = append(out, result...)
	}
	return out[:size]
}

// encryptPKCS8 把 PKCS#8 私钥封成 EncryptedPrivateKeyInfo（PBES2）。
func encryptPKCS8(random io.Reader, pkcs8, password []byte) (encryptedPrivateKeyInfo, error) {
	var out encryptedPrivateKeyInfo
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return out, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return out, err
	}
	block, err := aes.NewCipher(pbkdf2SHA256(password, salt, kdfIterations, 32))
	if err != nil {
		return out, err
	}
	// PKCS#7 填充。CBC 要求整块，而少填一个字节的表现是 Java 那边一句
	// "given final block not properly padded"，看不出是谁写坏的
	padding := aes.BlockSize - len(pkcs8)%aes.BlockSize
	padded := append(append([]byte{}, pkcs8...), make([]byte, padding)...)
	for i := len(pkcs8); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt: salt, Iterations: kdfIterations, KeyLength: 32,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHmacWithSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return out, err
	}
	ivParams, err := asn1.Marshal(iv)
	if err != nil {
		return out, err
	}
	scheme, err := asn1.Marshal(pbes2Params{
		KDF:              pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivParams}},
	})
	if err != nil {
		return out, err
	}
	return encryptedPrivateKeyInfo{
		Algorithm:     pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: scheme}},
		EncryptedData: ciphertext,
	}, nil
}

// attributes 造出 friendlyName + localKeyId 这一对。两个 bag 上要挂同一对：
// Java 靠 localKeyId 把证书和私钥认成一条条目，靠 friendlyName 得到别名。
func attributes(alias string, keyID []byte) ([]pkcs12Attribute, error) {
	name, err := bmpString(alias)
	if err != nil {
		return nil, err
	}
	nameValue, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30 /* BMPString */, Bytes: name})
	if err != nil {
		return nil, err
	}
	idValue, err := asn1.Marshal(keyID)
	if err != nil {
		return nil, err
	}
	set := func(inner []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: inner}
	}
	return []pkcs12Attribute{
		{ID: oidFriendlyName, Value: set(nameValue)},
		{ID: oidLocalKeyID, Value: set(idValue)},
	}, nil
}

// explicit 造一个 [0] EXPLICIT 的包装，bagValue 用的就是这个形状。
func explicit(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

// encodePKCS12 把一张证书和它的私钥打成一个 keystore 文件。
func encodePKCS12(random io.Reader, key any, certificate *x509.Certificate, alias, password string) ([]byte, error) {
	bagAttributes, err := func() ([]pkcs12Attribute, error) {
		fingerprint := sha1.Sum(certificate.Raw)
		return attributes(alias, fingerprint[:])
	}()
	if err != nil {
		return nil, err
	}

	certValue, err := asn1.Marshal(certBag{ID: oidCertTypeX509Certificate, Data: certificate.Raw})
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	// PBES2 的口令按 UTF-8，不是 BMPString——RFC 8018 这么建议，Java 和 OpenSSL
	// 也都这么实现。只有下面的 MAC 走 PKCS#12 自己那套 BMPString 编码。
	shrouded, err := encryptPKCS8(random, pkcs8, []byte(password))
	if err != nil {
		return nil, err
	}
	keyValue, err := asn1.Marshal(shrouded)
	if err != nil {
		return nil, err
	}

	bags := []safeBag{
		{ID: oidCertBag, Value: explicit(certValue), Attributes: bagAttributes},
		{ID: oidPKCS8ShroudedKeyBag, Value: explicit(keyValue), Attributes: bagAttributes},
	}
	safeContents, err := asn1.Marshal(bags)
	if err != nil {
		return nil, err
	}
	// 证书这一格不加密：它是公开材料，而每多一种加密形态就多一处可能读不出来。
	// 私钥在自己的 bag 里已经是 PBES2 加密的。
	inner := contentInfo{ContentType: oidDataContentType}
	if inner.Content.Bytes, err = asn1.Marshal(safeContents); err != nil {
		return nil, err
	}
	inner.Content.Class, inner.Content.Tag, inner.Content.IsCompound = asn1.ClassContextSpecific, 0, true

	authenticatedSafe, err := asn1.Marshal([]contentInfo{inner})
	if err != nil {
		return nil, err
	}

	macPassword, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, err
	}
	macSalt := make([]byte, saltLength)
	if _, err := io.ReadFull(random, macSalt); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, pkcs12KDF(macSalt, macPassword, kdfIterations, 3, sha256.Size))
	mac.Write(authenticatedSafe)

	pfx := pfxPdu{
		Version: 3,
		AuthSafe: contentInfo{
			ContentType: oidDataContentType,
		},
		MacData: macData{
			Mac: digestInfo{
				Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
				Digest:    mac.Sum(nil),
			},
			MacSalt:    macSalt,
			Iterations: kdfIterations,
		},
	}
	if pfx.AuthSafe.Content.Bytes, err = asn1.Marshal(authenticatedSafe); err != nil {
		return nil, err
	}
	pfx.AuthSafe.Content.Class, pfx.AuthSafe.Content.Tag, pfx.AuthSafe.Content.IsCompound = asn1.ClassContextSpecific, 0, true
	return asn1.Marshal(pfx)
}

// randomReader 让测试能塞一个确定的随机源进来。
var randomReader io.Reader = rand.Reader
