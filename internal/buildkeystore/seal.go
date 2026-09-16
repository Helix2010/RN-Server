// Package buildkeystore 封装/解封 Android 签名密钥包。
//
// 为什么需要它：把 keystore 放进应用数据库，最直接的做法是用 STORAGE_MASTER_KEY
// 加密——但那把主密钥就在 wallet 后端进程里，等于后端多了一个它不需要的能力，
// 而 keystore 泄露在 direct 分发下没有补救办法（Android 用「包名 + 签名证书」
// 认身份，对方能签一个同签名的 APK 在用户设备上原地覆盖安装，数据目录连钱包一起
// 留着，补救只能换包名让每个用户手动卸载重装）。
//
// 所以这里多一层：运维在本机用自己的口令把 keystore 封成一个盒子，服务端只存这个
// 盒子、没有钥匙；打包机本地持有口令，取下来自己开。数据库因此可以集中保管、按
// 租户隔离，而服务端读到的永远只是密文。
//
// 口令弱不弱决定了这层的强度，所以 KDF 用 scrypt 而不是一轮哈希：拿到数据库的人
// 只能离线爆破，scrypt 的内存开销让这件事贵得多。
package buildkeystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// scrypt 参数：N=2^16 约 64 MB 内存、单次约 0.1 秒。构建机每次构建才解一次，
// 这个代价可以忽略；而对离线爆破来说它是按尝试次数乘上去的。
const (
	scryptN      = 1 << 16
	scryptR      = 8
	scryptP      = 1
	keyLength    = 32
	saltLength   = 16
	formatV1     = 1
	MinPassphase = 12
)

// Bundle 是被封进盒子里的东西。一个口令解开全部——打包机因此不需要为每个租户
// 单独持有 keystore 口令与别名。
type Bundle struct {
	KeystoreBase64 string `json:"keystoreBase64"`
	StorePassword  string `json:"storePassword"`
	KeyAlias       string `json:"keyAlias"`
	KeyPassword    string `json:"keyPassword"`
}

// Sealed 是可以安全存进数据库、经过服务端的那个盒子。
//
// 两种格式共存：v1 是口令封的（scrypt 那几个字段），v2 是加密给打包机公钥的
// （alg/epk/kid）。v1 只读不写——已经存在的盒子照样能开，新写的一律 v2，理由见
// recipient.go。
type Sealed struct {
	Version int    `json:"v"`
	KDF     string `json:"kdf,omitempty"`
	N       int    `json:"n,omitempty"`
	R       int    `json:"r,omitempty"`
	P       int    `json:"p,omitempty"`
	Salt    string `json:"salt,omitempty"`
	// v2 专有
	Algorithm          string `json:"alg,omitempty"`
	EphemeralPublicKey string `json:"epk,omitempty"`
	RecipientKeyID     string `json:"kid,omitempty"`

	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func derive(passphrase string, salt []byte, n, r, p int) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, n, r, p, keyLength)
}

// Seal 用口令把 bundle 封起来。
func Seal(bundle Bundle, passphrase string) (Sealed, error) {
	var out Sealed
	if len([]rune(passphrase)) < MinPassphase {
		return out, fmt.Errorf("passphrase must be at least %d characters: it is the only thing standing between a database dump and the signing key", MinPassphase)
	}
	if bundle.KeystoreBase64 == "" || bundle.KeyAlias == "" {
		return out, errors.New("keystore and key alias are required")
	}
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return out, err
	}
	key, err := derive(passphrase, salt, scryptN, scryptR, scryptP)
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return out, err
	}
	plaintext, err := json.Marshal(bundle)
	if err != nil {
		return out, err
	}
	return Sealed{
		Version: formatV1, KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)),
	}, nil
}

// Open 用口令打开盒子。口令不对时返回的是同一个错误，不区分"口令错"与"内容坏"——
// 区分它们只会给爆破者一个免费的预言机。
func Open(sealed Sealed, passphrase string) (Bundle, error) {
	var bundle Bundle
	if sealed.Version != formatV1 || sealed.KDF != "scrypt" {
		return bundle, fmt.Errorf("unsupported sealed keystore format %d/%s", sealed.Version, sealed.KDF)
	}
	// 参数是随盒子一起存的，不能照单全收：一个被改成 N=2 的盒子会让爆破变廉价
	if sealed.N < scryptN || sealed.R < scryptR || sealed.P < scryptP {
		return bundle, errors.New("sealed keystore uses weaker KDF parameters than we accept")
	}
	salt, err := base64.StdEncoding.DecodeString(sealed.Salt)
	if err != nil || len(salt) < saltLength {
		return bundle, errors.New("sealed keystore is malformed")
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return bundle, errors.New("sealed keystore is malformed")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return bundle, errors.New("sealed keystore is malformed")
	}
	key, err := derive(passphrase, salt, sealed.N, sealed.R, sealed.P)
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
		return bundle, errors.New("sealed keystore is malformed")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return bundle, errors.New("cannot open the sealed keystore: wrong passphrase or damaged content")
	}
	if err := json.Unmarshal(plaintext, &bundle); err != nil {
		return bundle, errors.New("cannot open the sealed keystore: wrong passphrase or damaged content")
	}
	return bundle, nil
}

// ValidateShape 检查一个盒子的**形状**对不对。服务端打不开它，但可以看它长得像不像。
//
// 两种格式都要认：v1 是口令封的（scrypt + salt），v2 是加密给打包机公钥的
// （alg + epk）。只认 v1 的后果不是「少支持一种格式」——今天 CLI 产出的全是 v2，
// 所以那等于**手上有明文 .p12 也装不回去**，而「把密钥装回一个新库」正是
// 灾难恢复里绕不过去的一步。
//
// 在这里拦住一个形状不对的盒子，比在第一次构建时才发现便宜得多。
func (s Sealed) ValidateShape() error {
	if s.Ciphertext == "" || s.Nonce == "" {
		return fmt.Errorf("sealed must carry nonce and ciphertext")
	}
	switch s.Version {
	case formatV1:
		if s.KDF != "scrypt" || s.Salt == "" {
			return fmt.Errorf("a v1 sealed keystore must use scrypt and carry a salt")
		}
		if s.N < 1<<16 || s.R < 8 || s.P < 1 {
			return fmt.Errorf("a v1 sealed keystore must use scrypt with at least N=65536, r=8, p=1")
		}
		return nil
	case formatV2:
		if s.Algorithm == "" || s.EphemeralPublicKey == "" {
			return fmt.Errorf("a v2 sealed keystore must carry alg and epk")
		}
		return nil
	default:
		return fmt.Errorf("unsupported sealed keystore format %d", s.Version)
	}
}
