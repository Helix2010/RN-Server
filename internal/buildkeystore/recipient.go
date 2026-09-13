package buildkeystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// 加密给**打包机的公钥**，而不是用人敲的口令封。
//
// v1（scrypt + 口令）的问题不在密码学上，在人这一侧：打包机上只有一个
// BUILD_KEYSTORE_PASSPHRASE，全租户共用，于是控制台上那个「封装口令」输入框实际
// 是在问操作者要一个**保护所有租户密钥的平台秘密**。租户不可能知道它；知道了更糟
// ——拿到数据库快照就能开别人的盒子。而即使是平台运维，那也是一串 64 字符的东西，
// 要手抄进表单，抄错的表现是存下去一切正常、构建必然失败。2026-09-12 到 09-13
// 连着错了三次。
//
// v2 把人从这条路径上拿掉：打包机启动时生成一对 X25519 密钥，私钥永不离开那台机器，
// 公钥登记到服务端。服务端拿到明文 bundle 时直接加密给那个公钥——它自己只有公钥，
// 照样打不开，原来的安全论证一个字都不用改；而没有任何人需要输入任何口令。
//
// 构造是匿名发送方的 sealed box：临时密钥 + X25519 + HKDF-SHA256 + AES-256-GCM。
// 临时公钥进 AAD 与 KDF 的 info，所以换不掉；接收方公钥也进去，防止把同一条密文
// 重放给另一台打包机时还能解。
const (
	formatV2      = 2
	recipientAlg  = "x25519-hkdf-sha256-aes256gcm"
	recipientInfo = "rn-build-keystore/v2"
)

// Recipient 是打包机的公钥。32 字节的 X25519 公钥，不是秘密。
type Recipient struct {
	PublicKey string `json:"publicKey"` // base64
}

// Fingerprint 给人看的指纹：公钥的 sha256 前 16 个十六进制字符。
//
// 控制台上要显示它，因为"服务端现在把密钥加密给哪一台机器"是一件必须能被肉眼核对
// 的事——公钥被换掉意味着以后所有密钥都加密给了别人。
func (r Recipient) Fingerprint() string {
	raw, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])[:16]
}

func (r Recipient) key() (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("build agent public key is not base64: %w", err)
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// NewAgentKey 生成打包机自己的那对密钥。只有打包机会调它。
func NewAgentKey() (private []byte, recipient Recipient, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, Recipient{}, err
	}
	return key.Bytes(), Recipient{PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}, nil
}

// RecipientFor 从私钥算回公钥，用来登记和自检。
func RecipientFor(private []byte) (Recipient, error) {
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return Recipient{}, err
	}
	return Recipient{PublicKey: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}, nil
}

func derivedKey(shared, ephemeral, recipientPub []byte) ([]byte, error) {
	info := append([]byte(recipientInfo), ephemeral...)
	info = append(info, recipientPub...)
	out := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, info), out); err != nil {
		return nil, err
	}
	return out, nil
}

// SealTo 把 bundle 加密给打包机的公钥。服务端和 CLI 都用它。
func SealTo(bundle Bundle, recipient Recipient) (Sealed, error) {
	var out Sealed
	pub, err := recipient.key()
	if err != nil {
		return out, err
	}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return out, err
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return out, err
	}
	key, err := derivedKey(shared, ephemeral.PublicKey().Bytes(), pub.Bytes())
	if err != nil {
		return out, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return out, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	// 临时公钥进 AAD：换掉它就解不开，而它同时也是 KDF 的输入
	sealed := aead.Seal(nil, nonce, plaintext, ephemeral.PublicKey().Bytes())
	out = Sealed{
		Version:            formatV2,
		Algorithm:          recipientAlg,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		RecipientKeyID:     recipient.Fingerprint(),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:         base64.StdEncoding.EncodeToString(sealed),
	}
	// 封完立刻解一次。封出来打不开的盒子要等到第一次构建才暴露，而那时候明文
	// keystore 多半已经不在了
	if _, err := OpenWith(out, nil); err != nil && !errors.Is(err, errNeedPrivateKey) {
		return Sealed{}, fmt.Errorf("sealed box failed its own sanity check: %w", err)
	}
	return out, nil
}

var errNeedPrivateKey = errors.New("this box is addressed to the build machine; only it can open it")

// OpenWith 用打包机的私钥解开 v2 的盒子。private 为 nil 时只做结构校验。
func OpenWith(sealed Sealed, private []byte) (Bundle, error) {
	var bundle Bundle
	if sealed.Version != formatV2 || sealed.Algorithm != recipientAlg {
		return bundle, fmt.Errorf("unsupported sealed keystore format %d/%s", sealed.Version, sealed.Algorithm)
	}
	ephemeralRaw, err := base64.StdEncoding.DecodeString(sealed.EphemeralPublicKey)
	if err != nil {
		return bundle, errors.New("the sealed keystore has no usable ephemeral key")
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return bundle, errors.New("the sealed keystore has no usable nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return bundle, errors.New("the sealed keystore has no usable ciphertext")
	}
	if len(private) == 0 {
		if len(ephemeralRaw) != 32 || len(nonce) == 0 || len(ciphertext) == 0 {
			return bundle, errors.New("the sealed keystore is malformed")
		}
		return bundle, errNeedPrivateKey
	}
	priv, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return bundle, errors.New("this machine's build agent key is unusable")
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralRaw)
	if err != nil {
		return bundle, errors.New("the sealed keystore has no usable ephemeral key")
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		return bundle, err
	}
	key, err := derivedKey(shared, ephemeralRaw, priv.PublicKey().Bytes())
	if err != nil {
		return bundle, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return bundle, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return bundle, err
	}
	if len(nonce) != aead.NonceSize() {
		return bundle, errors.New("the sealed keystore has a nonce of the wrong size")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, ephemeralRaw)
	if err != nil {
		// 唯一可能的原因是这个盒子不是加密给这台机器的
		return bundle, errors.New("this box was encrypted for a different build machine's key")
	}
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return bundle, errors.New("the sealed keystore does not contain a keystore bundle")
	}
	return bundle, nil
}
