// Package pkcs12 读写 Android 签名用的 PKCS#12 keystore，只依赖标准库。
//
// # 为什么自己实现编码，而不是在生成时调用 keytool
//
//   - 离线机器不需要装 JDK：离线区的机器越干净越好，多一套运行时就多一份要审的东西；
//   - 私钥由 Go 的 crypto/rand 生成，口令从头到尾只在本进程内存里，不经过子进程的
//     参数、环境变量或管道——`ps`、审计日志、shell 历史都看不到；
//   - 这套布局（证书 bag 与私钥 bag 各挂 friendlyName + localKeyId，私钥 PBES2 加密，
//     整体 SHA-256 MAC）已经在 internal/androidkeystore 里用 keytool 验证过；本包的
//     测试在机器上有 keytool / openssl 时再逐次验证它们都读得懂我们的输出。
//
// 现成的 Go 编码库（x/crypto/pkcs12、go-pkcs12）不写 friendlyName，Java 读到没有
// friendlyName 的条目会把别名编成 "1"，而签名闸按密文里的别名找条目；它们也不在
// "只依赖标准库"的范围内。
//
// # 输出格式
//
// 与 JDK 12+ 的 keytool 一致：私钥 PBES2（PBKDF2-HMAC-SHA256 + AES-256-CBC），证书明文
// （公开材料），MAC 为 HMAC-SHA256 + PKCS#12 KDF，两处迭代次数都是 210000。
//
// # 解码范围
//
// 只收 PBES2 + PBKDF2 + AES-CBC 的加密与 SHA-1/SHA-2 的 MAC，覆盖 JDK 12+ keytool
// 与 OpenSSL 3 的默认输出。RC2/RC4/3DES 等老算法直接报 ErrLegacyEncryption，让人用
// AES 重新导出，而不是为它们多写一套分组密码。没有 MAC 的文件拒收：解密前先认证。
package pkcs12

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

// MaxInputSize 是 Decode 接受的文件大小上限。
const MaxInputSize = 256 << 10

const (
	maxContentInfos = 32
	maxBags         = 256
	maxLocalKeyID   = 256
	maxChainLength  = 10
)

var (
	// ErrPassword：MAC 不对或解密后填充不对。口令错与文件被改在这里不区分。
	ErrPassword = errors.New("pkcs12: wrong password, or the file has been modified")
	// ErrLegacyEncryption：文件用的是 RC2/RC4/3DES/PBES1 这类老算法。
	ErrLegacyEncryption = errors.New("pkcs12: the file uses legacy PKCS#12 encryption (RC2/RC4/3DES/PBES1); re-export it with AES " +
		"(the default of OpenSSL 3 `openssl pkcs12 -export` and of keytool from JDK 12 or later)")
	// ErrUnsupported：结构合法，但用了本包不支持的算法或 bag 类型。
	ErrUnsupported = errors.New("pkcs12: unsupported content")
	// ErrMalformed：不是合法的 PKCS#12 文件。
	ErrMalformed = errors.New("pkcs12: malformed file")
)

func malformed(detail string) error { return fmt.Errorf("%w: %s", ErrMalformed, detail) }

// KeyEntry 是 keystore 里的一个私钥条目。
//
// 它装着私钥：String / GoString / Format / LogValue 只输出别名与证书指纹。
type KeyEntry struct {
	Alias       string
	Certificate *x509.Certificate // 与私钥配对的叶子证书
	// Chain 以叶子证书开头，其后是在文件里按 subject/issuer 名字找到的上级证书（未验签，
	// 只作展示）。
	Chain      []*x509.Certificate
	PrivateKey crypto.PrivateKey
}

// CertificateSHA256 返回叶子证书 DER 的 sha256；没有证书时返回空串。
func CertificateSHA256(e KeyEntry) string {
	if e.Certificate == nil {
		return ""
	}
	return fingerprint.SHA256Hex(e.Certificate.Raw)
}

func (e KeyEntry) String() string {
	return fmt.Sprintf("pkcs12.KeyEntry{alias=%q certificateSha256=%q privateKey=[redacted]}", e.Alias, CertificateSHA256(e))
}

// GoString 覆盖 %#v。
func (e KeyEntry) GoString() string { return e.String() }

// Format 覆盖所有格式化动词。
func (e KeyEntry) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.String()) }

// LogValue 覆盖 slog。
func (e KeyEntry) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alias", e.Alias), slog.String("certificateSha256", CertificateSHA256(e)))
}

// MarshalJSON 拒绝序列化私钥条目。
func (e KeyEntry) MarshalJSON() ([]byte, error) {
	return nil, errors.New("pkcs12: refusing to JSON-encode a private key entry")
}

// ---- 编码 ----

// Encode 把 RSA 私钥与它的证书打成只含一个条目的 PKCS#12 文件。
func Encode(key *rsa.PrivateKey, cert *x509.Certificate, alias, password string) ([]byte, error) {
	return encode(key, cert, alias, password, defaultIterations)
}

func encode(key *rsa.PrivateKey, cert *x509.Certificate, alias, password string, iterations int) ([]byte, error) {
	if key == nil || cert == nil {
		return nil, errors.New("pkcs12: key and certificate are required")
	}
	if !ident.ValidKeyAlias(alias) {
		return nil, errors.New("pkcs12: alias must match ^[A-Za-z0-9._-]{1,64}$")
	}
	if password == "" {
		return nil, errors.New("pkcs12: password must not be empty")
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("pkcs12: the certificate does not belong to the private key")
	}
	localKeyID := sha1.Sum(cert.Raw)
	attributes, err := bagAttributes(alias, localKeyID[:])
	if err != nil {
		return nil, err
	}
	keyBag, err := shroudedKeyBag(key, password, iterations, attributes)
	if err != nil {
		return nil, err
	}
	safeContents := derSequence(certificateBag(cert.Raw, attributes), keyBag)
	authSafe := derSequence(dataContentInfo(safeContents))
	return assemble(authSafe, password, iterations, macHash{sha256.New, sha256.Size, sha256.BlockSize}, oidSHA256)
}

// bagAttributes 造 friendlyName + localKeyId。两个 bag 挂同一对：Java 靠 localKeyId 把
// 证书与私钥认成一个条目，靠 friendlyName 得到别名。
func bagAttributes(alias string, localKeyID []byte) ([]byte, error) {
	name, err := bmpString(alias)
	if err != nil {
		return nil, err
	}
	friendly := derSequence(derOID(oidFriendlyName), derSet(tlv(0x1e, name)))
	keyID := derSequence(derOID(oidLocalKeyID), derSet(derOctets(localKeyID)))
	return derSet(friendly, keyID), nil
}

func certificateBag(certDER, attributes []byte) []byte {
	value := derSequence(derOID(oidCertTypeX509), derExplicit0(derOctets(certDER)))
	return derSequence(derOID(oidCertBag), derExplicit0(value), attributes)
}

func shroudedKeyBag(key crypto.PrivateKey, password string, iterations int, attributes []byte) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer wipe(pkcs8)
	encrypted, err := encryptPBES2(pkcs8, password, iterations)
	if err != nil {
		return nil, err
	}
	return derSequence(derOID(oidPKCS8ShroudedKeyBag), derExplicit0(encrypted), attributes), nil
}

func dataContentInfo(content []byte) []byte {
	return derSequence(derOID(oidData), derExplicit0(derOctets(content)))
}

// assemble 算 MAC 并拼出 PFX。authSafe 是 AuthenticatedSafe（SEQUENCE OF ContentInfo）的 DER。
func assemble(authSafe []byte, password string, iterations int, h macHash, digestOID asn1.ObjectIdentifier) ([]byte, error) {
	pw, err := macPassword(password)
	if err != nil {
		return nil, err
	}
	defer wipe(pw)
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := pkcs12KDF(h, salt, pw, iterations, 3, h.u)
	defer wipe(key)
	mac := hmac.New(h.newHash, key)
	mac.Write(authSafe)
	macData := derSequence(
		derSequence(derSequence(derOID(digestOID), derNull), derOctets(mac.Sum(nil))),
		derOctets(salt),
		derInt(iterations),
	)
	return derSequence(derInt(3), dataContentInfo(authSafe), macData), nil
}

// ---- 解码 ----

type keyItem struct {
	key          crypto.PrivateKey
	friendlyName string
	localKeyID   []byte
}

type certItem struct {
	cert         *x509.Certificate
	friendlyName string
	localKeyID   []byte
}

// Decode 认证并解出文件里的全部私钥条目。每个私钥都必须配上一张公钥一致的证书。
func Decode(data []byte, password string) ([]KeyEntry, error) {
	if len(data) == 0 || len(data) > MaxInputSize {
		return nil, malformed("the file must be between 1 byte and 256 KiB")
	}
	if password == "" {
		return nil, errors.New("pkcs12: password must not be empty")
	}
	pfx, err := parseOnly(data)
	if err != nil {
		return nil, err
	}
	parts, err := sequenceChildren(pfx, 2, 3, "PFX")
	if err != nil {
		return nil, err
	}
	version, err := parseIntValue(parts[0])
	if err != nil || version != 3 {
		return nil, malformed("PFX version must be 3")
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: the file has no integrity MAC; refusing to trust its contents", ErrUnsupported)
	}
	authSafe, err := parseAuthSafe(parts[1])
	if err != nil {
		return nil, err
	}
	var work workBudget
	if err := verifyMAC(parts[2], authSafe, password, &work); err != nil {
		return nil, err
	}

	infoList, err := parseOnly(authSafe)
	if err != nil {
		return nil, err
	}
	infos, err := sequenceChildren(infoList, 1, maxContentInfos, "AuthenticatedSafe")
	if err != nil {
		return nil, err
	}
	var keys []keyItem
	var certs []certItem
	bagCount := 0
	for _, info := range infos {
		contentType, content, err := parseContentInfo(info)
		if err != nil {
			return nil, err
		}
		var safeContents []byte
		switch {
		case contentType.Equal(oidData):
			safeContents, err = parseOctetsValue(content)
			if err != nil {
				return nil, err
			}
		case contentType.Equal(oidEncryptedData):
			safeContents, err = decryptEncryptedData(content, password, &work)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: content type %s", ErrUnsupported, contentType)
		}
		if err := parseSafeContents(safeContents, password, &work, &keys, &certs, &bagCount); err != nil {
			return nil, err
		}
	}
	return buildEntries(keys, certs)
}

// SingleKey 要求文件里恰好一个私钥条目并返回它。
func SingleKey(data []byte, password string) (KeyEntry, error) {
	entries, err := Decode(data, password)
	if err != nil {
		return KeyEntry{}, err
	}
	if len(entries) != 1 {
		return KeyEntry{}, fmt.Errorf("pkcs12: expected exactly one private key entry, found %d", len(entries))
	}
	return entries[0], nil
}

// FindKey 要求文件里恰好一个私钥条目，且别名等于 alias，叶子证书公钥与私钥一致。
func FindKey(data []byte, password, alias string) (KeyEntry, error) {
	entry, err := SingleKey(data, password)
	if err != nil {
		return KeyEntry{}, err
	}
	if entry.Alias != alias {
		return KeyEntry{}, fmt.Errorf("pkcs12: the private key entry is named %q, expected %q", entry.Alias, alias)
	}
	return entry, nil
}

// parseAuthSafe：ContentInfo{data, [0] OCTET STRING}，返回 OCTET STRING 的内容（MAC 覆盖的字节）。
func parseAuthSafe(v asn1.RawValue) ([]byte, error) {
	contentType, content, err := parseContentInfo(v)
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidData) {
		return nil, fmt.Errorf("%w: authSafe content type %s (public-key integrity mode is not supported)", ErrUnsupported, contentType)
	}
	return parseOctetsValue(content)
}

func parseContentInfo(v asn1.RawValue) (asn1.ObjectIdentifier, asn1.RawValue, error) {
	items, err := sequenceChildren(v, 2, 2, "ContentInfo")
	if err != nil {
		return nil, asn1.RawValue{}, err
	}
	contentType, err := parseOIDValue(items[0])
	if err != nil {
		return nil, asn1.RawValue{}, err
	}
	content, err := explicitInner(items[1], 0)
	if err != nil {
		return nil, asn1.RawValue{}, err
	}
	return contentType, content, nil
}

func verifyMAC(v asn1.RawValue, content []byte, password string, work *workBudget) error {
	items, err := sequenceChildren(v, 2, 3, "MacData")
	if err != nil {
		return err
	}
	digestInfo, err := sequenceChildren(items[0], 2, 2, "DigestInfo")
	if err != nil {
		return err
	}
	alg, err := parseAlgorithm(digestInfo[0])
	if err != nil {
		return err
	}
	h, ok := macHashFor(alg.oid)
	if !ok {
		return fmt.Errorf("%w: MAC digest %s (only SHA-1 and SHA-2 HMAC are supported)", ErrUnsupported, alg.oid)
	}
	if !alg.paramsAbsentOrNull() {
		return malformed("MAC digest parameters must be absent or NULL")
	}
	expected, err := parseOctetsValue(digestInfo[1])
	if err != nil {
		return err
	}
	if len(expected) != h.u {
		return malformed("MAC digest has the wrong length")
	}
	salt, err := parseOctetsValue(items[1])
	if err != nil {
		return err
	}
	if len(salt) == 0 || len(salt) > maxSaltSize {
		return malformed("MAC salt size is out of range")
	}
	iterations := 1
	if len(items) == 3 {
		if iterations, err = parseIntValue(items[2]); err != nil {
			return err
		}
	}
	if err := work.spend(iterations); err != nil {
		return err
	}
	pw, err := macPassword(password)
	if err != nil {
		return errors.New("pkcs12: password must not contain NUL")
	}
	defer wipe(pw)
	key := pkcs12KDF(h, salt, pw, iterations, 3, h.u)
	defer wipe(key)
	mac := hmac.New(h.newHash, key)
	mac.Write(content)
	if !hmac.Equal(mac.Sum(nil), expected) {
		return ErrPassword
	}
	return nil
}

// decryptEncryptedData：EncryptedData ::= SEQUENCE { version, EncryptedContentInfo, [1] unprotectedAttrs OPTIONAL }
func decryptEncryptedData(v asn1.RawValue, password string, work *workBudget) ([]byte, error) {
	items, err := sequenceChildren(v, 2, 3, "EncryptedData")
	if err != nil {
		return nil, err
	}
	version, err := parseIntValue(items[0])
	if err != nil || (version != 0 && version != 2) {
		return nil, malformed("EncryptedData version must be 0 or 2")
	}
	if len(items) == 3 && !isContext(items[2], 1, true) {
		return nil, malformed("unexpected element after EncryptedContentInfo")
	}
	eci, err := sequenceChildren(items[1], 3, 3, "EncryptedContentInfo")
	if err != nil {
		return nil, err
	}
	contentType, err := parseOIDValue(eci[0])
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidData) {
		return nil, fmt.Errorf("%w: encrypted content type %s", ErrUnsupported, contentType)
	}
	alg, err := parseAlgorithm(eci[1])
	if err != nil {
		return nil, err
	}
	if !isContext(eci[2], 0, false) {
		return nil, malformed("encryptedContent must be a primitive [0] OCTET STRING")
	}
	return decrypt(alg, eci[2].Bytes, password, work)
}

func parseSafeContents(data []byte, password string, work *workBudget, keys *[]keyItem, certs *[]certItem, bagCount *int) error {
	list, err := parseOnly(data)
	if err != nil {
		return err
	}
	bags, err := sequenceChildren(list, 0, maxBags, "SafeContents")
	if err != nil {
		return err
	}
	for _, bag := range bags {
		*bagCount++
		if *bagCount > maxBags {
			return malformed("too many bags")
		}
		items, err := sequenceChildren(bag, 2, 3, "SafeBag")
		if err != nil {
			return err
		}
		bagID, err := parseOIDValue(items[0])
		if err != nil {
			return err
		}
		value, err := explicitInner(items[1], 0)
		if err != nil {
			return err
		}
		var friendlyName string
		var localKeyID []byte
		if len(items) == 3 {
			if friendlyName, localKeyID, err = parseAttributes(items[2]); err != nil {
				return err
			}
		}
		switch {
		case bagID.Equal(oidPKCS8ShroudedKeyBag):
			key, err := parseShroudedKey(value, password, work)
			if err != nil {
				return err
			}
			*keys = append(*keys, keyItem{key: key, friendlyName: friendlyName, localKeyID: localKeyID})
		case bagID.Equal(oidKeyBag):
			if !isSequence(value) {
				return malformed("keyBag is not a PrivateKeyInfo")
			}
			key, err := x509.ParsePKCS8PrivateKey(value.FullBytes)
			if err != nil {
				return malformed("keyBag does not contain a PKCS#8 private key")
			}
			*keys = append(*keys, keyItem{key: key, friendlyName: friendlyName, localKeyID: localKeyID})
		case bagID.Equal(oidCertBag):
			cert, err := parseCertBag(value)
			if err != nil {
				return err
			}
			*certs = append(*certs, certItem{cert: cert, friendlyName: friendlyName, localKeyID: localKeyID})
		case bagID.Equal(oidSecretBag), bagID.Equal(oidCRLBag):
			// 与签名无关，忽略
		case bagID.Equal(oidSafeContentsBag):
			return fmt.Errorf("%w: nested safeContentsBag", ErrUnsupported)
		default:
			return fmt.Errorf("%w: bag type %s", ErrUnsupported, bagID)
		}
	}
	return nil
}

func parseShroudedKey(v asn1.RawValue, password string, work *workBudget) (crypto.PrivateKey, error) {
	items, err := sequenceChildren(v, 2, 2, "EncryptedPrivateKeyInfo")
	if err != nil {
		return nil, err
	}
	alg, err := parseAlgorithm(items[0])
	if err != nil {
		return nil, err
	}
	ciphertext, err := parseOctetsValue(items[1])
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(alg, ciphertext, password, work)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, malformed("the decrypted key is not a PKCS#8 private key")
	}
	return key, nil
}

func parseCertBag(v asn1.RawValue) (*x509.Certificate, error) {
	items, err := sequenceChildren(v, 2, 2, "CertBag")
	if err != nil {
		return nil, err
	}
	certType, err := parseOIDValue(items[0])
	if err != nil {
		return nil, err
	}
	if !certType.Equal(oidCertTypeX509) {
		return nil, fmt.Errorf("%w: certificate type %s", ErrUnsupported, certType)
	}
	inner, err := explicitInner(items[1], 0)
	if err != nil {
		return nil, err
	}
	der, err := parseOctetsValue(inner)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, malformed("certBag does not contain a valid X.509 certificate")
	}
	return cert, nil
}

// parseAttributes 读 friendlyName 与 localKeyId，其余属性忽略。同一属性出现两次或
// 一个属性有多个值都拒绝。
func parseAttributes(v asn1.RawValue) (string, []byte, error) {
	if !isSet(v) {
		return "", nil, malformed("bag attributes must be a SET")
	}
	attrs, err := children(v, 16)
	if err != nil {
		return "", nil, err
	}
	var friendlyName string
	var localKeyID []byte
	seenName, seenID := false, false
	for _, attr := range attrs {
		items, err := sequenceChildren(attr, 2, 2, "attribute")
		if err != nil {
			return "", nil, err
		}
		id, err := parseOIDValue(items[0])
		if err != nil {
			return "", nil, err
		}
		if !isSet(items[1]) {
			return "", nil, malformed("attribute values must be a SET")
		}
		values, err := children(items[1], 16)
		if err != nil {
			return "", nil, err
		}
		switch {
		case id.Equal(oidFriendlyName):
			if seenName || len(values) != 1 || !isUniversal(values[0], asn1.TagBMPString, false) {
				return "", nil, malformed("friendlyName must be a single BMPString")
			}
			if friendlyName, err = decodeBMPString(values[0].Bytes); err != nil {
				return "", nil, err
			}
			seenName = true
		case id.Equal(oidLocalKeyID):
			if seenID || len(values) != 1 || !isUniversal(values[0], asn1.TagOctetString, false) ||
				len(values[0].Bytes) == 0 || len(values[0].Bytes) > maxLocalKeyID {
				return "", nil, malformed("localKeyId must be a single non-empty OCTET STRING")
			}
			localKeyID = values[0].Bytes
			seenID = true
		}
	}
	return friendlyName, localKeyID, nil
}

func publicKeysEqual(a crypto.PublicKey, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

func publicOf(key crypto.PrivateKey) (crypto.PublicKey, bool) {
	signer, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, false
	}
	return signer.Public(), true
}

func buildEntries(keys []keyItem, certs []certItem) ([]KeyEntry, error) {
	entries := make([]KeyEntry, 0, len(keys))
	aliases := map[string]bool{}
	for _, k := range keys {
		pub, ok := publicOf(k.key)
		if !ok {
			return nil, fmt.Errorf("%w: private key type %T", ErrUnsupported, k.key)
		}
		var leaf *certItem
		if len(k.localKeyID) > 0 {
			for i := range certs {
				if bytes.Equal(certs[i].localKeyID, k.localKeyID) {
					if leaf != nil {
						return nil, malformed("more than one certificate carries the same localKeyId")
					}
					leaf = &certs[i]
				}
			}
			if leaf != nil && !publicKeysEqual(leaf.cert.PublicKey, pub) {
				return nil, malformed("the certificate with the matching localKeyId does not belong to the private key")
			}
		}
		if leaf == nil {
			for i := range certs {
				if publicKeysEqual(certs[i].cert.PublicKey, pub) {
					if leaf != nil {
						return nil, malformed("more than one certificate matches the private key")
					}
					leaf = &certs[i]
				}
			}
		}
		if leaf == nil {
			return nil, malformed("a private key entry has no certificate")
		}
		alias := k.friendlyName
		if alias == "" {
			alias = leaf.friendlyName
		} else if leaf.friendlyName != "" && leaf.friendlyName != alias {
			return nil, malformed("the private key and its certificate carry different friendlyNames")
		}
		if alias != "" {
			if aliases[alias] {
				return nil, malformed("two private key entries share an alias")
			}
			aliases[alias] = true
		}
		entries = append(entries, KeyEntry{
			Alias:       alias,
			Certificate: leaf.cert,
			Chain:       buildChain(leaf.cert, certs),
			PrivateKey:  k.key,
		})
	}
	return entries, nil
}

func buildChain(leaf *x509.Certificate, certs []certItem) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	current := leaf
	for len(chain) < maxChainLength && !bytes.Equal(current.RawIssuer, current.RawSubject) {
		var next *x509.Certificate
		for _, c := range certs {
			if bytes.Equal(c.cert.RawSubject, current.RawIssuer) && !inChain(chain, c.cert) {
				next = c.cert
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		current = next
	}
	return chain
}

func inChain(chain []*x509.Certificate, cert *x509.Certificate) bool {
	for _, c := range chain {
		if bytes.Equal(c.Raw, cert.Raw) {
			return true
		}
	}
	return false
}
