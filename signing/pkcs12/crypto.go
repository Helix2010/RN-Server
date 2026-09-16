package pkcs12

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"
)

var (
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEncryptedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidCRLBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	oidSecretBag           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidCertTypeX509        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidPBES2               = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidSHA1                = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidPKCS12PBEPrefix     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1} // pbeWithSHAAnd*（RC4/3DES/RC2）
	oidPBES1Prefix         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5}     // pbeWithMD2/MD5/SHA1AndDES/RC2
	oidDESEDE3CBC          = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidDESCBC              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidRC2CBC              = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 2}
	oidPBMAC1              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	pkcs5NonLegacy         = []asn1.ObjectIdentifier{oidPBKDF2, oidPBES2, oidPBMAC1}
)

const (
	// defaultIterations 同时用于私钥的 PBKDF2 与 MAC 的 PKCS#12 KDF。这把 keystore 一辈子
	// 只被打开有限几次，可以取得比库默认值高得多，挡"拿到文件离线爆破口令"。
	defaultIterations = 210_000
	maxIterations     = 10_000_000

	saltSize    = 16
	maxSaltSize = 1024
)

// maxTotalIterations 限制一个文件里所有 KDF 迭代次数之和。密文可能来自不可信的一方
// （谁都能加密给签名闸的公钥，也就知道口令、算得出 MAC）：不设总量，256 个 bag
// 各要一千万次迭代就能让签名闸算上几个小时。keytool 的文件约 3 万次，我们的 42 万次。
// 是变量只为了让模糊测试调低它，生产代码不改。
var maxTotalIterations = 10_000_000

// macHash 描述 MAC 用的散列：u 是输出长度，v 是分组长度（PKCS#12 KDF 的参数）。
type macHash struct {
	newHash func() hash.Hash
	u, v    int
}

func macHashFor(oid asn1.ObjectIdentifier) (macHash, bool) {
	switch {
	case oid.Equal(oidSHA1):
		return macHash{sha1.New, sha1.Size, sha1.BlockSize}, true
	case oid.Equal(oidSHA256):
		return macHash{sha256.New, sha256.Size, sha256.BlockSize}, true
	case oid.Equal(oidSHA384):
		return macHash{sha512.New384, sha512.Size384, sha512.BlockSize}, true
	case oid.Equal(oidSHA512):
		return macHash{sha512.New, sha512.Size, sha512.BlockSize}, true
	}
	return macHash{}, false
}

func prfFor(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidHMACWithSHA1):
		return sha1.New, true
	case oid.Equal(oidHMACWithSHA224):
		return sha256.New224, true
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New, true
	case oid.Equal(oidHMACWithSHA384):
		return sha512.New384, true
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New, true
	}
	return nil, false
}

func aesKeySizeFor(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, true
	case oid.Equal(oidAES192CBC):
		return 24, true
	case oid.Equal(oidAES256CBC):
		return 32, true
	}
	return 0, false
}

func hasPrefix(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) <= len(prefix) {
		return false
	}
	return oid[:len(prefix)].Equal(prefix)
}

// isLegacyEncryption：RFC 7292 的 pbeWithSHAAnd*、PBES1，以及 PBES2 里套 DES/3DES/RC2。
func isLegacyEncryption(oid asn1.ObjectIdentifier) bool {
	if hasPrefix(oid, oidPKCS12PBEPrefix) {
		return true
	}
	if hasPrefix(oid, oidPBES1Prefix) && len(oid) == len(oidPBES1Prefix)+1 {
		for _, sibling := range pkcs5NonLegacy {
			if oid.Equal(sibling) {
				return false
			}
		}
		return true
	}
	return oid.Equal(oidDESEDE3CBC) || oid.Equal(oidDESCBC) || oid.Equal(oidRC2CBC)
}

// pkcs12KDF 是 RFC 7292 附录 B.2 的派生函数，只用于 MAC（id=3）。
func pkcs12KDF(h macHash, salt, password []byte, iterations, id, size int) []byte {
	fill := func(pattern []byte) []byte {
		if len(pattern) == 0 {
			return nil
		}
		out := make([]byte, ((len(pattern)+h.v-1)/h.v)*h.v)
		for i := range out {
			out[i] = pattern[i%len(pattern)]
		}
		return out
	}
	diversifier := make([]byte, h.v)
	for i := range diversifier {
		diversifier[i] = byte(id)
	}
	input := append(fill(salt), fill(password)...)
	defer wipe(input)

	digest := h.newHash()
	var out []byte
	for len(out) < size {
		digest.Reset()
		digest.Write(diversifier)
		digest.Write(input)
		a := digest.Sum(nil)
		for i := 1; i < iterations; i++ {
			digest.Reset()
			digest.Write(a)
			a = digest.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= size {
			break
		}
		// 步骤 6：B = A 铺满 v 字节；I 的每个 v 字节块 += B + 1（mod 2^(8v)）
		b := fill(a)[:h.v]
		for j := 0; j < len(input); j += h.v {
			carry := 1
			for k := h.v - 1; k >= 0; k-- {
				sum := int(input[j+k]) + int(b[k]) + carry
				input[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// encryptPBES2 用 PBKDF2-HMAC-SHA256 + AES-256-CBC 加密，返回 EncryptedPrivateKeyInfo 的
// DER：SEQUENCE { AlgorithmIdentifier(PBES2), OCTET STRING }。
func encryptPBES2(plaintext []byte, password string, iterations int) ([]byte, error) {
	salt := make([]byte, saltSize)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	defer wipe(padded)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	kdfParams := derSequence(derOctets(salt), derInt(iterations), derInt(32), derSequence(derOID(oidHMACWithSHA256), derNull))
	scheme := derSequence(
		derSequence(derOID(oidPBKDF2), kdfParams),
		derSequence(derOID(oidAES256CBC), derOctets(iv)),
	)
	return derSequence(derSequence(derOID(oidPBES2), scheme), derOctets(ciphertext)), nil
}

// workBudget 记录一个文件已经花掉的 KDF 迭代次数。
type workBudget struct{ spent int }

func (w *workBudget) spend(iterations int) error {
	if iterations < 1 || iterations > maxIterations {
		return malformed("KDF iteration count is out of range")
	}
	if w.spent += iterations; w.spent > maxTotalIterations {
		return malformed("the file asks for more key-derivation work than allowed")
	}
	return nil
}

// decrypt 按 AlgorithmIdentifier 解密。只支持 PBES2 + PBKDF2 + AES-CBC。
func decrypt(alg algorithm, ciphertext []byte, password string, work *workBudget) ([]byte, error) {
	if !alg.oid.Equal(oidPBES2) {
		if isLegacyEncryption(alg.oid) {
			return nil, ErrLegacyEncryption
		}
		return nil, fmt.Errorf("%w: encryption algorithm %s is not supported (only PBES2 with AES-CBC)", ErrUnsupported, alg.oid)
	}
	if alg.params == nil {
		return nil, malformed("PBES2 parameters are missing")
	}
	parts, err := sequenceChildren(*alg.params, 2, 2, "PBES2 parameters")
	if err != nil {
		return nil, err
	}
	kdf, err := parseAlgorithm(parts[0])
	if err != nil {
		return nil, err
	}
	scheme, err := parseAlgorithm(parts[1])
	if err != nil {
		return nil, err
	}
	if !kdf.oid.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("%w: key derivation %s is not supported (only PBKDF2)", ErrUnsupported, kdf.oid)
	}
	keySize, ok := aesKeySizeFor(scheme.oid)
	if !ok {
		if isLegacyEncryption(scheme.oid) {
			return nil, ErrLegacyEncryption
		}
		return nil, fmt.Errorf("%w: cipher %s is not supported (only AES-CBC)", ErrUnsupported, scheme.oid)
	}
	if scheme.params == nil {
		return nil, malformed("AES-CBC IV is missing")
	}
	iv, err := parseOctetsValue(*scheme.params)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, malformed("AES-CBC IV must be 16 bytes")
	}
	if kdf.params == nil {
		return nil, malformed("PBKDF2 parameters are missing")
	}
	kdfParts, err := sequenceChildren(*kdf.params, 2, 4, "PBKDF2 parameters")
	if err != nil {
		return nil, err
	}
	if !isUniversal(kdfParts[0], asn1.TagOctetString, false) {
		return nil, fmt.Errorf("%w: PBKDF2 salt must be specified inline", ErrUnsupported)
	}
	salt := kdfParts[0].Bytes
	if len(salt) == 0 || len(salt) > maxSaltSize {
		return nil, malformed("PBKDF2 salt size is out of range")
	}
	iterations, err := parseIntValue(kdfParts[1])
	if err != nil {
		return nil, err
	}
	prf := sha1.New // RFC 8018 的默认值
	rest := kdfParts[2:]
	if len(rest) > 0 && isUniversal(rest[0], asn1.TagInteger, false) {
		keyLength, err := parseIntValue(rest[0])
		if err != nil {
			return nil, err
		}
		if keyLength != keySize {
			return nil, malformed("PBKDF2 key length does not match the cipher")
		}
		rest = rest[1:]
	}
	if len(rest) > 0 {
		prfAlg, err := parseAlgorithm(rest[0])
		if err != nil {
			return nil, err
		}
		fn, ok := prfFor(prfAlg.oid)
		if !ok || !prfAlg.paramsAbsentOrNull() {
			return nil, fmt.Errorf("%w: PBKDF2 PRF %s is not supported", ErrUnsupported, prfAlg.oid)
		}
		prf = fn
		rest = rest[1:]
	}
	if len(rest) != 0 {
		return nil, malformed("unexpected PBKDF2 parameters")
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, malformed("ciphertext length is not a multiple of the AES block size")
	}
	if err := work.spend(iterations); err != nil {
		return nil, err
	}
	// PBES2 的口令按 UTF-8 字节（RFC 8018 的建议，JDK 与 OpenSSL 都这么实现）；只有 MAC
	// 那一层用 BMPString。
	key, err := pbkdf2.Key(prf, password, salt, iterations, keySize)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	n := int(plain[len(plain)-1])
	if n < 1 || n > aes.BlockSize {
		wipe(plain)
		return nil, ErrPassword
	}
	for _, b := range plain[len(plain)-n:] {
		if int(b) != n {
			wipe(plain)
			return nil, ErrPassword
		}
	}
	return plain[:len(plain)-n], nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
