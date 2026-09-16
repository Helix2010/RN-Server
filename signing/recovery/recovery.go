// Package recovery 是离线恢复密钥：整个平台一把（或几把）X25519 密钥，签名闸生成租户签名密钥时
// 除了加密给本机信任的签名闸，还加密给本机信任的恢复公钥。签名闸全部丢失时，拿离线 U 盘里的
// 恢复私钥与口令，用离线工具 build-keystore recover 解开服务端导出的密文，得到 .p12 原件。
//
// 两个文件：
//
//   - recovery-public.json（PublicFormat）：公钥与完整 sha256，公开信息。平台管理员在控制台登记，
//     签名闸按运维从密码管理器粘贴的 sha256 核对后写进本机记录。
//   - recovery-private.key（PrivateFormat）：32 字节 X25519 私钥，用口令加密。
//     scrypt（N=2^17, r=8, p=1）从口令派生 32 字节 → AES-256-GCM，
//     附加数据 = "rn-recovery-private/v1\n" + x25519PublicKeySha256。解开后再核对公钥 sha256。
//
// 恢复公钥作为 keystorebox v3 的收件人时，Box.RecipientSHA256 = x25519PublicKeySha256，
// 加密与解密用 keystorebox.Seal / keystorebox.Open（同一实现）。
package recovery

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

const (
	// PublicFormat 是公钥文件的格式标识。
	PublicFormat = "rn-recovery-public/v1"
	// PrivateFormat 是私钥文件的格式标识，也是附加数据的前缀。
	PrivateFormat = "rn-recovery-private/v1"
	// KDFAlgorithm 是私钥文件 kdf.alg 唯一允许的值。
	KDFAlgorithm = "scrypt"

	// ScryptN、ScryptR、ScryptP 是生成私钥文件时用的参数（约 128 MiB 内存）。
	ScryptN = 1 << 17
	ScryptR = 8
	ScryptP = 1
	// MinScryptN、MaxScryptN 是读私钥文件时接受的 N 范围（2 的幂）。下限只为测试提速留出余地，
	// 离线工具生成时固定用 ScryptN。
	MinScryptN = 1 << 14
	MaxScryptN = 1 << 20

	// MaxFileSize 是两种文件读入的上限。
	MaxFileSize = 16 << 10
	// MinPassphraseLength、MaxPassphraseLength 是口令的字节数范围。
	MinPassphraseLength = 12
	MaxPassphraseLength = 1024

	keySize   = 32
	saltSize  = 16
	nonceSize = 12
	gcmTag    = 16
)

var (
	// ErrWrongPassphrase：口令不对，或者私钥文件被改过（认证解密失败，两者不区分）。
	ErrWrongPassphrase = errors.New("recovery: the passphrase is wrong or the private key file was modified")
	// ErrInvalidFile：文件不是合法的恢复公钥或私钥文件。
	ErrInvalidFile = errors.New("recovery: not a valid recovery key file")
)

// PublicFile 是 recovery-public.json。JSON 字段名是跨组件契约，不能改。
type PublicFile struct {
	Format                string `json:"format"`
	Name                  string `json:"name"`
	X25519PublicKey       string `json:"x25519PublicKey"`       // base64 std，32 字节
	X25519PublicKeySHA256 string `json:"x25519PublicKeySha256"` // sha256(原始 32 字节)
	CreatedAt             string `json:"createdAt"`             // RFC3339 UTC
}

// KDF 是私钥文件的口令派生参数。
type KDF struct {
	Alg  string `json:"alg"`
	Salt string `json:"salt"` // base64 std，16 字节
	N    int    `json:"n"`
	R    int    `json:"r"`
	P    int    `json:"p"`
}

// PrivateFile 是 recovery-private.key。ciphertext 是加密后的 32 字节 X25519 私钥。
type PrivateFile struct {
	Format                string `json:"format"`
	Name                  string `json:"name"`
	X25519PublicKeySHA256 string `json:"x25519PublicKeySha256"`
	KDF                   KDF    `json:"kdf"`
	Nonce                 string `json:"nonce"`      // base64 std，12 字节
	Ciphertext            string `json:"ciphertext"` // base64 std，32 + 16 字节
}

// ValidName 判断恢复密钥名（与机器名同一条规则：^[a-z0-9][a-z0-9-]{1,39}$）。
func ValidName(s string) bool { return ident.ValidMachineName(s) }

// NewPublic 为一把 X25519 公钥生成公钥文件内容。
func NewPublic(name string, x25519Pub []byte, createdAt time.Time) (PublicFile, error) {
	p := PublicFile{
		Format:                PublicFormat,
		Name:                  name,
		X25519PublicKey:       base64.StdEncoding.EncodeToString(x25519Pub),
		X25519PublicKeySHA256: fingerprint.SHA256Hex(x25519Pub),
		CreatedAt:             createdAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := p.Validate(); err != nil {
		return PublicFile{}, err
	}
	return p, nil
}

// Validate 检查公钥文件每个字段，并核对 sha256 与公钥一致。
func (p PublicFile) Validate() error {
	switch {
	case p.Format != PublicFormat:
		return fmt.Errorf("%w: format must be %s", ErrInvalidFile, PublicFormat)
	case !ValidName(p.Name):
		return fmt.Errorf("%w: name must match ^[a-z0-9][a-z0-9-]{1,39}$", ErrInvalidFile)
	case !fingerprint.Valid(p.X25519PublicKeySHA256):
		return fmt.Errorf("%w: x25519PublicKeySha256 must be 64 lowercase hex characters", ErrInvalidFile)
	case !ident.ValidRFC3339UTC(p.CreatedAt):
		return fmt.Errorf("%w: createdAt must be an RFC3339 UTC timestamp", ErrInvalidFile)
	}
	pub, err := DecodePublicKey(p.X25519PublicKey)
	if err != nil {
		return err
	}
	if fingerprint.SHA256Hex(pub) != p.X25519PublicKeySHA256 {
		return fmt.Errorf("%w: x25519PublicKeySha256 does not match x25519PublicKey", ErrInvalidFile)
	}
	return nil
}

// PublicKey 返回 32 字节公钥（Validate 通过之后调用）。
func (p PublicFile) PublicKey() ([]byte, error) { return DecodePublicKey(p.X25519PublicKey) }

// DecodePublicKey 解码 base64 std 的 32 字节 X25519 公钥。服务端存的恢复公钥、签名闸从服务端取回的
// 公钥都用它解码，再与 sha256 核对。
func DecodePublicKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) != keySize {
		return nil, fmt.Errorf("%w: x25519PublicKey must be base64 of 32 bytes", ErrInvalidFile)
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("%w: x25519PublicKey is not an X25519 public key", ErrInvalidFile)
	}
	return raw, nil
}

// ParsePublic 严格解析公钥文件：未知字段、尾随数据、超长都拒绝，并校验 sha256 与公钥一致。
func ParsePublic(raw []byte) (PublicFile, error) {
	var p PublicFile
	if err := strictUnmarshal(raw, &p); err != nil {
		return PublicFile{}, err
	}
	if err := p.Validate(); err != nil {
		return PublicFile{}, err
	}
	return p, nil
}

// Generate 生成一把恢复密钥，返回公钥文件与用口令加密的私钥文件。n 是 scrypt 的 N，生产固定传 ScryptN。
func Generate(name string, passphrase []byte, createdAt time.Time, n int) (PublicFile, PrivateFile, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PublicFile{}, PrivateFile{}, err
	}
	pub, err := NewPublic(name, priv.PublicKey().Bytes(), createdAt)
	if err != nil {
		return PublicFile{}, PrivateFile{}, err
	}
	sealed, err := SealPrivate(name, priv, passphrase, n)
	if err != nil {
		return PublicFile{}, PrivateFile{}, err
	}
	return pub, sealed, nil
}

// ValidatePassphrase 检查口令：12–1024 字节 UTF-8，不含控制字符。错误信息不含口令内容。
func ValidatePassphrase(passphrase []byte) error {
	if len(passphrase) < MinPassphraseLength || len(passphrase) > MaxPassphraseLength || !utf8.Valid(passphrase) {
		return fmt.Errorf("recovery: the passphrase must be %d-%d bytes of UTF-8", MinPassphraseLength, MaxPassphraseLength)
	}
	for _, r := range string(passphrase) {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return errors.New("recovery: the passphrase must not contain control characters")
		}
	}
	return nil
}

// SealPrivate 用口令加密 X25519 私钥。n 是 scrypt 的 N（2 的幂，MinScryptN–MaxScryptN）。
func SealPrivate(name string, priv *ecdh.PrivateKey, passphrase []byte, n int) (PrivateFile, error) {
	if priv == nil || priv.Curve() != ecdh.X25519() {
		return PrivateFile{}, errors.New("recovery: expected an X25519 private key")
	}
	if !ValidName(name) {
		return PrivateFile{}, errors.New("recovery: name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return PrivateFile{}, err
	}
	if !validN(n) {
		return PrivateFile{}, fmt.Errorf("recovery: scrypt N must be a power of two between %d and %d", MinScryptN, MaxScryptN)
	}
	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return PrivateFile{}, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return PrivateFile{}, err
	}
	pubSHA := fingerprint.SHA256Hex(priv.PublicKey().Bytes())
	aead, err := passphraseAEAD(passphrase, salt, n, ScryptR, ScryptP)
	if err != nil {
		return PrivateFile{}, err
	}
	plain := priv.Bytes()
	defer wipe(plain)
	ct := aead.Seal(nil, nonce, plain, privateAAD(pubSHA))
	f := PrivateFile{
		Format:                PrivateFormat,
		Name:                  name,
		X25519PublicKeySHA256: pubSHA,
		KDF:                   KDF{Alg: KDFAlgorithm, Salt: base64.StdEncoding.EncodeToString(salt), N: n, R: ScryptR, P: ScryptP},
		Nonce:                 base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:            base64.StdEncoding.EncodeToString(ct),
	}
	if err := f.Validate(); err != nil {
		return PrivateFile{}, fmt.Errorf("recovery: the sealed private key failed its own shape check: %w", err)
	}
	return f, nil
}

// Validate 检查私钥文件的形状（不解密）。
func (f PrivateFile) Validate() error {
	switch {
	case f.Format != PrivateFormat:
		return fmt.Errorf("%w: format must be %s", ErrInvalidFile, PrivateFormat)
	case !ValidName(f.Name):
		return fmt.Errorf("%w: name must match ^[a-z0-9][a-z0-9-]{1,39}$", ErrInvalidFile)
	case !fingerprint.Valid(f.X25519PublicKeySHA256):
		return fmt.Errorf("%w: x25519PublicKeySha256 must be 64 lowercase hex characters", ErrInvalidFile)
	case f.KDF.Alg != KDFAlgorithm:
		return fmt.Errorf("%w: kdf.alg must be %s", ErrInvalidFile, KDFAlgorithm)
	case !validN(f.KDF.N) || f.KDF.R != ScryptR || f.KDF.P != ScryptP:
		return fmt.Errorf("%w: kdf parameters must be n = a power of two between %d and %d, r = %d, p = %d", ErrInvalidFile, MinScryptN, MaxScryptN, ScryptR, ScryptP)
	}
	if _, err := decodeFixed(f.KDF.Salt, saltSize); err != nil {
		return fmt.Errorf("%w: kdf.salt must be base64 of %d bytes", ErrInvalidFile, saltSize)
	}
	if _, err := decodeFixed(f.Nonce, nonceSize); err != nil {
		return fmt.Errorf("%w: nonce must be base64 of %d bytes", ErrInvalidFile, nonceSize)
	}
	if _, err := decodeFixed(f.Ciphertext, keySize+gcmTag); err != nil {
		return fmt.Errorf("%w: ciphertext must be base64 of %d bytes", ErrInvalidFile, keySize+gcmTag)
	}
	return nil
}

// ParsePrivate 严格解析私钥文件（不解密）。
func ParsePrivate(raw []byte) (PrivateFile, error) {
	var f PrivateFile
	if err := strictUnmarshal(raw, &f); err != nil {
		return PrivateFile{}, err
	}
	if err := f.Validate(); err != nil {
		return PrivateFile{}, err
	}
	return f, nil
}

// Open 用口令解开私钥，并核对它的公钥 sha256 与文件里记的一致。
func (f PrivateFile) Open(passphrase []byte) (*ecdh.PrivateKey, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if len(passphrase) == 0 || len(passphrase) > MaxPassphraseLength {
		return nil, ErrWrongPassphrase
	}
	salt, _ := decodeFixed(f.KDF.Salt, saltSize)
	nonce, _ := decodeFixed(f.Nonce, nonceSize)
	ct, _ := decodeFixed(f.Ciphertext, keySize+gcmTag)
	aead, err := passphraseAEAD(passphrase, salt, f.KDF.N, f.KDF.R, f.KDF.P)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, privateAAD(f.X25519PublicKeySHA256))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer wipe(plain)
	priv, err := ecdh.X25519().NewPrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("%w: the decrypted private key is malformed", ErrInvalidFile)
	}
	if fingerprint.SHA256Hex(priv.PublicKey().Bytes()) != f.X25519PublicKeySHA256 {
		return nil, fmt.Errorf("%w: the decrypted private key does not belong to x25519PublicKeySha256", ErrInvalidFile)
	}
	return priv, nil
}

// Encode 把公钥文件或私钥文件写成缩进 JSON（带结尾换行）。
func Encode(v any) ([]byte, error) {
	switch v.(type) {
	case PublicFile, PrivateFile:
	default:
		return nil, errors.New("recovery: Encode only accepts PublicFile or PrivateFile")
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func passphraseAEAD(passphrase, salt []byte, n, r, p int) (cipher.AEAD, error) {
	key, err := scrypt.Key(passphrase, salt, n, r, p, keySize)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func privateAAD(pubSHA string) []byte { return []byte(PrivateFormat + "\n" + pubSHA) }

func validN(n int) bool { return n >= MinScryptN && n <= MaxScryptN && n&(n-1) == 0 }

func decodeFixed(s string, size int) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != size {
		return nil, errors.New("wrong length")
	}
	return raw, nil
}

func strictUnmarshal(raw []byte, v any) error {
	if len(raw) > MaxFileSize {
		return fmt.Errorf("%w: larger than %d bytes", ErrInvalidFile, MaxFileSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data after the JSON object", ErrInvalidFile)
	}
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
