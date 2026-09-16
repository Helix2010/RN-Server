// Package keystorebox 是 Android 签名密钥的 v3 密文格式。
//
// 离线工具把密钥原件加密给离线 pin 文件里的每一台签名闸（每台一个 Box），服务端
// 只存密文，只有持有对应 X25519 私钥的签名闸解得开。构造是匿名发送方的 sealed box：
//
//	临时 X25519 密钥 → ECDH → HKDF-SHA256(info = "rn-build-keystore/v3" || epk || recipientPub)
//	→ AES-256-GCM，附加数据 = "rn-build-keystore/v3\n" + Purpose + "\n" + RecipientSHA256
//
// 临时公钥与收件人公钥都进 KDF：换掉 epk 解不开，把一个 Box 改投给另一台签名闸
// 也解不开。收件人指纹再进 AEAD 附加数据，改 recipientSha256 同样解不开。
//
// 明文里绑定了租户、包名、证书指纹、别名与全部收件人：签名闸解开后逐项与本机
// 确认值比对，服务端给的同名字段只作对照。
package keystorebox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

const (
	// Purpose 写在明文与附加数据里，防止同一把 X25519 私钥解开的别的密文被当成签名密钥。
	Purpose = "android-release-keystore"
	// UploadFormat 是离线工具产出、控制台上传的文件格式。
	UploadFormat = "rn-android-keystore-upload/v3"
	// Algorithm 是 Box.Algorithm 唯一允许的值。
	Algorithm = "x25519-hkdf-sha256-aes256gcm"
	// Version 是 Box.Version 唯一允许的值。
	Version = 3

	kdfLabel = "rn-build-keystore/v3"

	// MaxBoxes 限制一份上传里的收件人数量。一主一备，留足余量。
	MaxBoxes = 16
	// MaxP12Size 是 PKCS#12 原件解码后的上限。RSA 4096 的 keystore 约 5 KiB。
	MaxP12Size = 64 << 10
	// MaxPasswordLength 是口令字节数上限。
	MaxPasswordLength = 1024
	// maxCiphertextSize 是密文解码后的上限：明文 JSON 里 base64 的 p12 加其余字段。
	maxCiphertextSize = 128<<10 + aesGCMTagSize
	aesGCMTagSize     = 16
	gcmNonceSize      = 12
	x25519KeySize     = 32
)

var (
	// ErrNotAddressedToThisKey：Box 的收件人指纹不是这把私钥对应的公钥。
	ErrNotAddressedToThisKey = errors.New("keystorebox: the box is addressed to a different recipient key")
	// ErrDecrypt：认证解密失败。密文、附加数据、临时公钥任一被改都落在这里；
	// 不区分原因，区分只会给篡改者一个预言机。
	ErrDecrypt = errors.New("keystorebox: authenticated decryption failed")
	// ErrInvalidPlaintext：解开了，但明文不是合法的签名密钥记录。
	ErrInvalidPlaintext = errors.New("keystorebox: decrypted content is not a valid keystore record")
)

// Box 是加密给一台签名闸的密文。JSON 字段名是跨组件契约，不能改。
type Box struct {
	Version            int    `json:"v"`
	Algorithm          string `json:"alg"`
	RecipientSHA256    string `json:"recipientSha256"` // 收件人 X25519 公钥 sha256
	EphemeralPublicKey string `json:"epk"`             // base64 std
	Nonce              string `json:"nonce"`           // base64 std
	Ciphertext         string `json:"ct"`              // base64 std
}

// Plaintext 是 Box 解开后的内容。它装着私钥与口令：
//
//   - 实现了 String / GoString / Format / LogValue，只输出白名单里的非机密字段，
//     新加的字段默认不出现；
//   - MarshalJSON 直接报错，挡住"把它 json.Marshal 进日志"这种写法。封装时用的是
//     包内的另一个类型。
type Plaintext struct {
	Purpose           string   `json:"purpose"`
	TenantSlug        string   `json:"tenantSlug"`
	PackageName       string   `json:"packageName"`
	CertificateSHA256 string   `json:"certificateSha256"`
	KeyAlias          string   `json:"keyAlias"`
	Recipients        []string `json:"recipients"` // 排序后的收件人 sha256
	CreatedAt         string   `json:"createdAt"`  // RFC3339 UTC
	P12Base64         string   `json:"p12Base64"`
	StorePassword     string   `json:"storePassword"`
	KeyPassword       string   `json:"keyPassword"`
	// Generation 只在签名闸生成的密钥里有（离线工具产出的没有，JSON 与之前逐字节相同）。
	Generation *Generation `json:"generation,omitempty"`
}

// Generation 是生成者（主签名闸）为这把密钥在本机写下的确认参数。它在密文里：Box 的密文被生成签名
// 覆盖（签名覆盖整个 Upload），所以服务端改不了、也换不了。别的签名闸自动接受这把密钥时按它核对：
// 首次信任的信任根摘要必须等于 TrustRootsDigest（服务端不能给备签名闸另一套信任根），本机当前有效的
// 证书必须等于 SupersedesCertificateSHA256（服务端不能把一次更早的生成重放回来）。
type Generation struct {
	// TrustRootsDigest 是生成者确认的信任根摘要（trustroots.Digest）
	TrustRootsDigest string `json:"trustRootsDigest"`
	// MinSDK、TargetSDK、FirstSignMaxVersionCode 是生成者确认的下限与首签上限
	MinSDK                  int64 `json:"minSdk"`
	TargetSDK               int64 `json:"targetSdk"`
	FirstSignMaxVersionCode int64 `json:"firstSignMaxVersionCode"`
	// SupersedesCertificateSHA256 是生成时生成者本机对这个包名有效确认的证书；首次生成为空串
	SupersedesCertificateSHA256 string `json:"supersedesCertificateSha256"`
}

// Validate 检查生成参数的格式（取值下限由签名闸本机记录再校验）。
func (g Generation) Validate() error {
	switch {
	case !fingerprint.Valid(g.TrustRootsDigest):
		return errors.New("generation.trustRootsDigest must be 64 lowercase hex characters")
	case g.MinSDK < 1 || g.MinSDK > 1000 || g.TargetSDK < g.MinSDK || g.TargetSDK > 1000:
		return errors.New("generation.minSdk and targetSdk are out of range")
	case g.FirstSignMaxVersionCode < 1 || g.FirstSignMaxVersionCode > 2100000000:
		return errors.New("generation.firstSignMaxVersionCode is out of range")
	case g.SupersedesCertificateSHA256 != "" && !fingerprint.Valid(g.SupersedesCertificateSHA256):
		return errors.New("generation.supersedesCertificateSha256 must be empty or 64 lowercase hex characters")
	}
	return nil
}

// wirePlaintext 与 Plaintext 字段完全相同，只用于封装与解封时的 JSON 编解码。
type wirePlaintext struct {
	Purpose           string      `json:"purpose"`
	TenantSlug        string      `json:"tenantSlug"`
	PackageName       string      `json:"packageName"`
	CertificateSHA256 string      `json:"certificateSha256"`
	KeyAlias          string      `json:"keyAlias"`
	Recipients        []string    `json:"recipients"`
	CreatedAt         string      `json:"createdAt"`
	P12Base64         string      `json:"p12Base64"`
	StorePassword     string      `json:"storePassword"`
	KeyPassword       string      `json:"keyPassword"`
	Generation        *Generation `json:"generation,omitempty"`
}

// Upload 是离线工具产出、控制台上传的文件。
type Upload struct {
	Format            string `json:"format"`
	TenantSlug        string `json:"tenantSlug"`
	PackageName       string `json:"packageName"`
	KeyAlias          string `json:"keyAlias"`
	CertificateSHA256 string `json:"certificateSha256"`
	CreatedAt         string `json:"createdAt"`
	Boxes             []Box  `json:"boxes"`
}

// ---- 机密结构体的格式化白名单 ----

func (p Plaintext) String() string {
	generation := "none"
	if g := p.Generation; g != nil {
		generation = fmt.Sprintf("{trustRootsDigest=%q minSdk=%d targetSdk=%d firstSignMaxVersionCode=%d supersedesCertificateSha256=%q}",
			g.TrustRootsDigest, g.MinSDK, g.TargetSDK, g.FirstSignMaxVersionCode, g.SupersedesCertificateSHA256)
	}
	return fmt.Sprintf("keystorebox.Plaintext{purpose=%q tenantSlug=%q packageName=%q certificateSha256=%q keyAlias=%q recipients=%q createdAt=%q generation=%s p12=[redacted] storePassword=[redacted] keyPassword=[redacted]}",
		p.Purpose, p.TenantSlug, p.PackageName, p.CertificateSHA256, p.KeyAlias, p.Recipients, p.CreatedAt, generation)
}

// GoString 覆盖 %#v。
func (p Plaintext) GoString() string { return p.String() }

// Format 覆盖所有动词（%d、%x 这类不经过 String 的也包括在内）。
func (p Plaintext) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// LogValue 覆盖 slog。
func (p Plaintext) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("purpose", p.Purpose),
		slog.String("tenantSlug", p.TenantSlug),
		slog.String("packageName", p.PackageName),
		slog.String("certificateSha256", p.CertificateSHA256),
		slog.String("keyAlias", p.KeyAlias),
		slog.Any("recipients", p.Recipients),
		slog.String("createdAt", p.CreatedAt),
		slog.Bool("generated", p.Generation != nil),
	)
}

// MarshalJSON 拒绝序列化：明文只该出现在 Box 里。
func (p Plaintext) MarshalJSON() ([]byte, error) {
	return nil, errors.New("keystorebox: refusing to JSON-encode a keystore plaintext")
}

// P12 解码原件字节。调用方用完应尽快丢弃。
func (p Plaintext) P12() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(p.P12Base64)
	if err != nil || len(raw) == 0 || len(raw) > MaxP12Size {
		return nil, ErrInvalidPlaintext
	}
	return raw, nil
}

// ---- 校验 ----

// Validate 检查明文每个字段的格式。错误信息不含机密字段的内容。
func (p Plaintext) Validate() error {
	switch {
	case p.Purpose != Purpose:
		return errors.New("purpose is not " + Purpose)
	case !ident.ValidTenantSlug(p.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case !ident.ValidPackageName(p.PackageName):
		return errors.New("packageName is malformed")
	case !fingerprint.Valid(p.CertificateSHA256):
		return errors.New("certificateSha256 must be 64 lowercase hex characters")
	case !ident.ValidKeyAlias(p.KeyAlias):
		return errors.New("keyAlias is malformed")
	case !ident.ValidRFC3339UTC(p.CreatedAt):
		return errors.New("createdAt must be an RFC3339 UTC timestamp")
	}
	if err := validateRecipients(p.Recipients); err != nil {
		return err
	}
	if _, err := p.P12(); err != nil {
		return errors.New("p12Base64 must be non-empty standard base64 of at most 64 KiB")
	}
	if err := validatePassword(p.StorePassword); err != nil {
		return fmt.Errorf("storePassword %w", err)
	}
	if err := validatePassword(p.KeyPassword); err != nil {
		return fmt.Errorf("keyPassword %w", err)
	}
	if p.Generation != nil {
		if err := p.Generation.Validate(); err != nil {
			return err
		}
		if p.Generation.SupersedesCertificateSHA256 == p.CertificateSHA256 {
			return errors.New("generation.supersedesCertificateSha256 must differ from certificateSha256")
		}
	}
	return nil
}

func validateRecipients(recipients []string) error {
	if len(recipients) == 0 || len(recipients) > MaxBoxes {
		return fmt.Errorf("recipients must list 1-%d fingerprints", MaxBoxes)
	}
	for i, r := range recipients {
		if !fingerprint.Valid(r) {
			return errors.New("recipients must be 64 lowercase hex characters each")
		}
		// 严格递增：既是"排序后"，也排除了重复
		if i > 0 && recipients[i-1] >= r {
			return errors.New("recipients must be sorted and unique")
		}
	}
	return nil
}

// validatePassword：apksigner 的 file: 只读第一行，所以不允许换行；其余控制字符
// 一并拒绝，免得出现在口令文件里的东西和人以为的不一样。
func validatePassword(s string) error {
	if len(s) == 0 || len(s) > MaxPasswordLength || !utf8.ValidString(s) {
		return errors.New("must be 1-1024 bytes of UTF-8")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// ValidateShape 检查 Box 的形状，不解密。
func (b Box) ValidateShape() error {
	if b.Version != Version {
		return fmt.Errorf("box version must be %d", Version)
	}
	if b.Algorithm != Algorithm {
		return errors.New("box alg must be " + Algorithm)
	}
	if !fingerprint.Valid(b.RecipientSHA256) {
		return errors.New("box recipientSha256 must be 64 lowercase hex characters")
	}
	if _, err := decodeFixed(b.EphemeralPublicKey, x25519KeySize); err != nil {
		return errors.New("box epk must be base64 of 32 bytes")
	}
	if _, err := decodeFixed(b.Nonce, gcmNonceSize); err != nil {
		return errors.New("box nonce must be base64 of 12 bytes")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(b.Ciphertext)
	if err != nil || len(ct) <= aesGCMTagSize || len(ct) > maxCiphertextSize {
		return errors.New("box ct must be base64 of a non-empty ciphertext of at most 128 KiB")
	}
	return nil
}

// ValidateShape 检查上传文件的形状：格式、字段、boxes 非空且收件人不重复、每个 box
// 形状合法。不解密（服务端也解不开）。
func (u Upload) ValidateShape() error {
	switch {
	case u.Format != UploadFormat:
		return errors.New("format must be " + UploadFormat)
	case !ident.ValidTenantSlug(u.TenantSlug):
		return errors.New("tenantSlug is malformed")
	case !ident.ValidPackageName(u.PackageName):
		return errors.New("packageName is malformed")
	case !ident.ValidKeyAlias(u.KeyAlias):
		return errors.New("keyAlias is malformed")
	case !fingerprint.Valid(u.CertificateSHA256):
		return errors.New("certificateSha256 must be 64 lowercase hex characters")
	case !ident.ValidRFC3339UTC(u.CreatedAt):
		return errors.New("createdAt must be an RFC3339 UTC timestamp")
	case len(u.Boxes) == 0:
		return errors.New("boxes must not be empty")
	case len(u.Boxes) > MaxBoxes:
		return fmt.Errorf("boxes must list at most %d recipients", MaxBoxes)
	}
	seen := make(map[string]bool, len(u.Boxes))
	for i, box := range u.Boxes {
		if err := box.ValidateShape(); err != nil {
			return fmt.Errorf("boxes[%d]: %w", i, err)
		}
		if seen[box.RecipientSHA256] {
			return fmt.Errorf("boxes[%d]: recipientSha256 appears more than once", i)
		}
		seen[box.RecipientSHA256] = true
	}
	return nil
}

// ---- 加密与解密 ----

// Seal 把明文加密给一台签名闸。p.Recipients 必须已经包含这台签名闸的指纹。
func Seal(p Plaintext, recipientX25519Pub []byte) (Box, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Box{}, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Box{}, err
	}
	return sealWith(p, recipientX25519Pub, ephemeral, nonce)
}

func sealWith(p Plaintext, recipientX25519Pub []byte, ephemeral *ecdh.PrivateKey, nonce []byte) (Box, error) {
	if len(recipientX25519Pub) != x25519KeySize {
		return Box{}, errors.New("keystorebox: recipient public key must be 32 bytes")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recipientX25519Pub)
	if err != nil {
		return Box{}, fmt.Errorf("keystorebox: recipient public key: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Box{}, fmt.Errorf("keystorebox: plaintext: %w", err)
	}
	recipientSHA := fingerprint.SHA256Hex(recipientX25519Pub)
	if !contains(p.Recipients, recipientSHA) {
		return Box{}, errors.New("keystorebox: the recipient is not listed in the plaintext recipients")
	}
	plain, err := json.Marshal(wirePlaintext(p))
	if err != nil {
		return Box{}, err
	}
	defer wipe(plain)
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Box{}, fmt.Errorf("keystorebox: key agreement: %w", err)
	}
	defer wipe(shared)
	epk := ephemeral.PublicKey().Bytes()
	aead, err := newAEAD(shared, epk, recipientX25519Pub)
	if err != nil {
		return Box{}, err
	}
	ct := aead.Seal(nil, nonce, plain, additionalData(recipientSHA))
	box := Box{
		Version:            Version,
		Algorithm:          Algorithm,
		RecipientSHA256:    recipientSHA,
		EphemeralPublicKey: base64.StdEncoding.EncodeToString(epk),
		Nonce:              base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:         base64.StdEncoding.EncodeToString(ct),
	}
	if err := box.ValidateShape(); err != nil {
		return Box{}, fmt.Errorf("keystorebox: sealed box failed its own shape check: %w", err)
	}
	return box, nil
}

// Open 用本机 X25519 私钥解开 Box，校验 purpose、各字段格式，以及收件人列表里有自己。
func Open(b Box, x25519Private []byte) (Plaintext, error) {
	if len(x25519Private) != x25519KeySize {
		return Plaintext{}, errors.New("keystorebox: private key must be 32 bytes")
	}
	priv, err := ecdh.X25519().NewPrivateKey(x25519Private)
	if err != nil {
		return Plaintext{}, fmt.Errorf("keystorebox: private key: %w", err)
	}
	if err := b.ValidateShape(); err != nil {
		return Plaintext{}, fmt.Errorf("keystorebox: %w", err)
	}
	ownPub := priv.PublicKey().Bytes()
	ownSHA := fingerprint.SHA256Hex(ownPub)
	if b.RecipientSHA256 != ownSHA {
		return Plaintext{}, ErrNotAddressedToThisKey
	}
	return open(b, priv, additionalData(b.RecipientSHA256))
}

func open(b Box, priv *ecdh.PrivateKey, aad []byte) (Plaintext, error) {
	ownPub := priv.PublicKey().Bytes()
	ownSHA := fingerprint.SHA256Hex(ownPub)
	epk, _ := decodeFixed(b.EphemeralPublicKey, x25519KeySize)
	nonce, _ := decodeFixed(b.Nonce, gcmNonceSize)
	ct, _ := base64.StdEncoding.Strict().DecodeString(b.Ciphertext)
	ephemeral, err := ecdh.X25519().NewPublicKey(epk)
	if err != nil {
		return Plaintext{}, ErrDecrypt
	}
	shared, err := priv.ECDH(ephemeral)
	if err != nil {
		// 低阶点：只可能是构造出来的密文
		return Plaintext{}, ErrDecrypt
	}
	defer wipe(shared)
	aead, err := newAEAD(shared, epk, ownPub)
	if err != nil {
		return Plaintext{}, err
	}
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return Plaintext{}, ErrDecrypt
	}
	defer wipe(plain)
	var wire wirePlaintext
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Plaintext{}, ErrInvalidPlaintext
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Plaintext{}, ErrInvalidPlaintext
	}
	out := Plaintext(wire)
	if err := out.Validate(); err != nil {
		return Plaintext{}, fmt.Errorf("%w: %v", ErrInvalidPlaintext, err)
	}
	if !contains(out.Recipients, ownSHA) {
		return Plaintext{}, fmt.Errorf("%w: this machine is not listed among the recipients", ErrInvalidPlaintext)
	}
	return out, nil
}

// RecipientSHA256 返回 X25519 公钥的指纹（pin 文件与 Box 用的那个值）。
func RecipientSHA256(x25519Pub []byte) string { return fingerprint.SHA256Hex(x25519Pub) }

func newAEAD(shared, epk, recipientPub []byte) (cipher.AEAD, error) {
	var info strings.Builder
	info.WriteString(kdfLabel)
	info.Write(epk)
	info.Write(recipientPub)
	key, err := hkdf.Key(sha256.New, shared, nil, info.String(), 32)
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

func additionalData(recipientSHA string) []byte {
	return []byte(kdfLabel + "\n" + Purpose + "\n" + recipientSHA)
}

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

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// wipe 尽力清掉内存里的中间值。Go 的字符串清不掉，这只覆盖字节切片。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
