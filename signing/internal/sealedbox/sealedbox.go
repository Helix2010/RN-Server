// Package sealedbox 是"加密给一个 X25519 公钥"的信封，匿名发送方。
//
//	临时 X25519 密钥 → ECDH → HKDF-SHA256(info = label ‖ 临时公钥 ‖ 收件人公钥)
//	→ AES-256-GCM，附加数据 = label ‖ "\n" ‖ purpose ‖ "\n" ‖ 收件人指纹
//
// 临时公钥与收件人公钥都进 KDF：换掉临时公钥解不开，把一个信封改投给另一个收件人也解不开。
// 收件人指纹再进附加数据，改那一行同样解不开。
//
// **label 与 purpose 是域分隔**：两套材料（Android 的签名密钥、iOS 的签名材料）用不同的
// 取值，于是同一把私钥即便被同时授予两种身份，一种的密文也绝不会被当成另一种解开——不是
// 靠调用方记得检查，是解密这一步就失败。
//
// 这个包只做信封，不认识里面装的是什么：载荷由调用方序列化、调用方校验。
package sealedbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

const (
	// KeySize 是 X25519 公私钥的字节数。
	KeySize = 32
	// NonceSize 是 AES-GCM 的 nonce 字节数。
	NonceSize = 12
	// TagSize 是 AES-GCM 的认证标签字节数。
	TagSize = 16
)

// ErrDecrypt：解不开。**不分是哪一步坏的**——密钥不对、密文被改过、附加数据不符，
// 对外都是同一句话，免得错误信息本身变成一个可以试探的口子。
var ErrDecrypt = errors.New("sealedbox: cannot decrypt")

// ErrNotAddressedToThisKey：这个信封是给别人的。与 ErrDecrypt 分开，因为它指向的是
// 运维动作（收件人配错了），而不是"有人在改密文"。
var ErrNotAddressedToThisKey = errors.New("sealedbox: this box is addressed to another key")

// Sealed 是信封的四个字段，都是 base64（标准字母表，带 padding）。
// 外层结构（版本、算法名、JSON 标签）由调用方自己定——两套材料的线格式各自演进。
type Sealed struct {
	RecipientSHA256    string
	EphemeralPublicKey string
	Nonce              string
	Ciphertext         string
}

// Seal 封一份，临时密钥与 nonce 都现取随机。
func Seal(label, purpose string, payload, recipientPub []byte) (Sealed, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Sealed{}, err
	}
	return SealWith(label, purpose, payload, recipientPub, ephemeral, nonce)
}

// SealWith 指定临时密钥与 nonce。只给测试与固定向量用：生产里这两样必须是随机的，
// 重复用同一对 (密钥, nonce) 封两份不同的内容会把 GCM 的认证一起毁掉。
func SealWith(label, purpose string, payload, recipientPub []byte, ephemeral *ecdh.PrivateKey, nonce []byte) (Sealed, error) {
	if len(recipientPub) != KeySize {
		return Sealed{}, errors.New("sealedbox: recipient public key must be 32 bytes")
	}
	if len(nonce) != NonceSize {
		return Sealed{}, errors.New("sealedbox: nonce must be 12 bytes")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return Sealed{}, fmt.Errorf("sealedbox: recipient public key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Sealed{}, fmt.Errorf("sealedbox: key agreement: %w", err)
	}
	defer Wipe(shared)
	epk := ephemeral.PublicKey().Bytes()
	aead, err := newAEAD(label, shared, epk, recipientPub)
	if err != nil {
		return Sealed{}, err
	}
	recipientSHA := fingerprint.SHA256Hex(recipientPub)
	ct := aead.Seal(nil, nonce, payload, additionalData(label, purpose, recipientSHA))
	return Sealed{
		RecipientSHA256:    recipientSHA,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(epk),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:         base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open 解一份，回载荷。调用方负责 wipe 它。
func Open(s Sealed, label, purpose string, priv *ecdh.PrivateKey) ([]byte, error) {
	ownPub := priv.PublicKey().Bytes()
	ownSHA := fingerprint.SHA256Hex(ownPub)
	if s.RecipientSHA256 != ownSHA {
		return nil, ErrNotAddressedToThisKey
	}
	epk, err := DecodeFixed(s.EphemeralPublicKey, KeySize)
	if err != nil {
		return nil, ErrDecrypt
	}
	nonce, err := DecodeFixed(s.Nonce, NonceSize)
	if err != nil {
		return nil, ErrDecrypt
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(s.Ciphertext)
	if err != nil || len(ct) < TagSize {
		return nil, ErrDecrypt
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return nil, ErrDecrypt
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		// 低阶点：只可能是构造出来的密文
		return nil, ErrDecrypt
	}
	defer Wipe(shared)
	aead, err := newAEAD(label, shared, epk, ownPub)
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, nonce, ct, additionalData(label, purpose, ownSHA))
	if err != nil {
		return nil, ErrDecrypt
	}
	return payload, nil
}

// PrivateKey 把 32 字节私钥变成 ecdh 的类型。
func PrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	if len(raw) != KeySize {
		return nil, errors.New("sealedbox: private key must be 32 bytes")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// NewKey 生成一把新的 X25519 私钥。
func NewKey() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }

// additionalData：label、purpose、收件人指纹三样都进认证数据。
func additionalData(label, purpose, recipientSHA string) []byte {
	return []byte(label + "\n" + purpose + "\n" + recipientSHA)
}

// newAEAD：共享秘密经 HKDF 导出 AES-256 的密钥。info 里不加分隔符——两段都是定长的
// 32 字节公钥，接在定长的 label 后面不存在歧义。
func newAEAD(label string, shared, epk, recipientPub []byte) (cipher.AEAD, error) {
	var info strings.Builder
	info.WriteString(label)
	info.Write(epk)
	info.Write(recipientPub)
	key, err := hkdf.Key(sha256.New, shared, nil, info.String(), 32)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DecodeFixed 解一段定长的标准 base64。
func DecodeFixed(s string, size int) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, errors.New("wrong length")
	}
	return raw, nil
}

// Wipe 把一段字节抹零。
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
