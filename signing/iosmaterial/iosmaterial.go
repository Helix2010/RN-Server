// Package iosmaterial 是 iOS 签名材料的密文格式（设计
// docs/design/ios-signing-material-distribution-2026-09-19.md）。
//
// 材料在**离线机器或管理员的浏览器**里加密给平台公钥，服务端只存、只转发密文——它没有
// 任何一把私钥，读不懂。Mac 上由对应的角色账户解开：证书与描述文件归 _rnbuilder，
// 上传 Key 归 _rnuploader，各用各的私钥，一把解不开另一把的东西。
//
// 信封用 internal/sealedbox（与 Android 签名密钥同一套构造），标签与用途不同，所以两套
// 材料之间是**域分隔**的：同一把私钥即便被同时授予两种身份，一种的密文也绝不会被当成另一
// 种解开——不是靠调用方记得检查，是解密这一步就失败。
//
// Box 外层那几个字段（kind、teamId、bundleId、machineId）是给**服务端路由**用的明文提示，
// 它们可以被篡改。真正作数的是密文里那一份：Mac 解开之后按自己的判据逐项核对，外层只作对照。
package iosmaterial

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/internal/sealedbox"
)

const (
	// Label 是这套材料的 KDF 标签。与 Android 那套不同，换不得。
	Label = "rn-ios-material/v1"
	// Algorithm 是 Box.Algorithm 唯一允许的值。
	Algorithm = "x25519-hkdf-sha256-aes256gcm"
	// Version 是 Box.Version 唯一允许的值。
	Version = 1

	// KindCertificate 是 Apple Distribution 证书（.p12 + 口令），每个 Team 一份、全机共用。
	KindCertificate = "certificate"
	// KindProfile 是 App Store 描述文件，每个 (Team, bundle id) 一份。
	KindProfile = "profile"
	// KindUploadKey 是 App Store Connect 上传 Key（.p8 + issuerId/keyId），
	// 每 (机器, Team) 一份——设计 §4.3：每台 Mac 一把，丢了能单独吊销。
	KindUploadKey = "upload-key"

	// 用途按角色分，进 AEAD 的附加数据。证书与描述文件是构建账户的，上传 Key 是上传账户的：
	// 拿到构建账户那把私钥的人解不开上传 Key，反之亦然
	PurposeBuilder  = "ios-builder-material"
	PurposeUploader = "ios-uploader-material"

	// MaxP12Size：一张证书加私钥，RSA 2048 的实际不到 4 KiB
	MaxP12Size = 64 << 10
	// MaxProfileSize：真实的描述文件几 KB
	MaxProfileSize = 256 << 10
	// MaxP8Size：ASC 的 .p8 是一段 EC 私钥，几百字节
	MaxP8Size = 8 << 10
	// MaxPasswordLength 是 .p12 口令的字节数上限
	MaxPasswordLength = 1024
	// MaxBoxSize 是 ParseBox 接受的文件大小上限
	MaxBoxSize = 2 << 20
)

var (
	// ErrNotAddressedToThisKey：这份材料不是给这把私钥的。
	ErrNotAddressedToThisKey = errors.New("iosmaterial: this material is addressed to a different key")
	// ErrDecrypt：解不开。密钥不对、密文被改、用途不符都落在这里，不分家。
	ErrDecrypt = errors.New("iosmaterial: authenticated decryption failed")
	// ErrInvalidMaterial：解开了，但里面不是一份合法的材料。
	ErrInvalidMaterial = errors.New("iosmaterial: decrypted content is not a valid material record")

	teamIDPattern    = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	bundleIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	machineIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	keyIDPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	issuerIDPattern  = regexp.MustCompile(`^[0-9a-f-]{16,64}$`)
)

// Material 是一份材料的明文。**它装着私钥与口令**：
//
//   - String / GoString / Format / LogValue 只输出白名单里的非机密字段，新加的字段默认不出现；
//   - MarshalJSON 直接报错，挡住"把它 json.Marshal 进日志"这种写法。封装时用的是包内的另一个类型。
type Material struct {
	Purpose string `json:"purpose"`
	Kind    string `json:"kind"`
	TeamID  string `json:"teamId"`
	// BundleID 只有描述文件有
	BundleID string `json:"bundleId,omitempty"`
	// MachineID 只有上传 Key 有
	MachineID string `json:"machineId,omitempty"`
	// RecipientSHA256 是收件人公钥指纹。附加数据里已经绑了一次，明文里再写一份是为了
	// 解开之后还能自证"这份确实是发给我的"，而不必回头信任外层
	RecipientSHA256 string `json:"recipientSha256"`
	CreatedAt       string `json:"createdAt"`

	// 证书
	P12Base64   string `json:"p12Base64,omitempty"`
	P12Password string `json:"p12Password,omitempty"`
	// 描述文件
	ProfileBase64 string `json:"profileBase64,omitempty"`
	// 上传 Key
	IssuerID string `json:"issuerId,omitempty"`
	KeyID    string `json:"keyId,omitempty"`
	P8Base64 string `json:"p8Base64,omitempty"`
}

// wireMaterial 是包内用来序列化的同构类型：Material 自己的 MarshalJSON 是报错的。
type wireMaterial Material

// Box 是服务端存的那一份。外层字段是给服务端路由用的明文提示，可被篡改；作数的是密文里那一份。
type Box struct {
	Version            int    `json:"v"`
	Algorithm          string `json:"alg"`
	Purpose            string `json:"purpose"`
	Kind               string `json:"kind"`
	TeamID             string `json:"teamId"`
	BundleID           string `json:"bundleId,omitempty"`
	MachineID          string `json:"machineId,omitempty"`
	RecipientSHA256    string `json:"recipientSha256"`
	EphemeralPublicKey string `json:"epk"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ct"`
	CreatedAt          string `json:"createdAt"`
}

// PurposeFor 回这个种类该用哪个用途（也就是哪把角色密钥）。
func PurposeFor(kind string) (string, error) {
	switch kind {
	case KindCertificate, KindProfile:
		return PurposeBuilder, nil
	case KindUploadKey:
		return PurposeUploader, nil
	}
	return "", fmt.Errorf("iosmaterial: unknown kind %q", firstRunes(kind, 32))
}

// Validate 查明文的形状。每一项都要有，因为这份东西会被拿去改钥匙串与磁盘。
func (m Material) Validate() error {
	want, err := PurposeFor(m.Kind)
	if err != nil {
		return err
	}
	switch {
	case m.Purpose != want:
		return fmt.Errorf("purpose %q does not match kind %q", firstRunes(m.Purpose, 32), m.Kind)
	case !teamIDPattern.MatchString(m.TeamID):
		return fmt.Errorf("teamId %q is not a 10 character Apple Team ID", firstRunes(m.TeamID, 32))
	case !fingerprint.Valid(m.RecipientSHA256):
		return errors.New("recipientSha256 is not a sha256")
	case !validTime(m.CreatedAt):
		return errors.New("createdAt is not an RFC3339 timestamp")
	}
	switch m.Kind {
	case KindCertificate:
		if err := requireOnly(m, "P12Base64", "P12Password"); err != nil {
			return err
		}
		if err := sizedBase64(m.P12Base64, MaxP12Size, "p12Base64"); err != nil {
			return err
		}
		if m.P12Password == "" || len(m.P12Password) > MaxPasswordLength || !utf8.ValidString(m.P12Password) {
			return errors.New("p12Password is empty, too long, or not UTF-8")
		}
	case KindProfile:
		if err := requireOnly(m, "ProfileBase64"); err != nil {
			return err
		}
		if !bundleIDPattern.MatchString(m.BundleID) {
			return fmt.Errorf("bundleId %q is malformed", firstRunes(m.BundleID, 64))
		}
		if err := sizedBase64(m.ProfileBase64, MaxProfileSize, "profileBase64"); err != nil {
			return err
		}
	case KindUploadKey:
		if err := requireOnly(m, "IssuerID", "KeyID", "P8Base64"); err != nil {
			return err
		}
		switch {
		case !machineIDPattern.MatchString(m.MachineID):
			return fmt.Errorf("machineId %q is malformed", firstRunes(m.MachineID, 64))
		case !issuerIDPattern.MatchString(m.IssuerID):
			return fmt.Errorf("issuerId %q is malformed", firstRunes(m.IssuerID, 64))
		case !keyIDPattern.MatchString(m.KeyID):
			return fmt.Errorf("keyId %q is malformed", firstRunes(m.KeyID, 32))
		}
		if err := sizedBase64(m.P8Base64, MaxP8Size, "p8Base64"); err != nil {
			return err
		}
	}
	return nil
}

// requireOnly 保证这个种类**只带**它该带的机密字段。多带一个的后果不是多几个字节：
// 一份"证书"里塞着 p8，落地那一步会照着 kind 走，而多出来的那份材料谁都没核对过。
func requireOnly(m Material, allowed ...string) error {
	present := map[string]bool{}
	for name, value := range map[string]string{
		"P12Base64": m.P12Base64, "P12Password": m.P12Password,
		"ProfileBase64": m.ProfileBase64,
		"IssuerID":      m.IssuerID, "KeyID": m.KeyID, "P8Base64": m.P8Base64,
	} {
		if value != "" {
			present[name] = true
		}
	}
	for _, name := range allowed {
		if !present[name] {
			return fmt.Errorf("%s is required for kind %s", name, m.Kind)
		}
		delete(present, name)
	}
	for name := range present {
		return fmt.Errorf("%s does not belong in a %s record", name, m.Kind)
	}
	// bundleId 与 machineId 也各有归属
	if m.Kind != KindProfile && m.BundleID != "" {
		return fmt.Errorf("bundleId does not belong in a %s record", m.Kind)
	}
	if m.Kind != KindUploadKey && m.MachineID != "" {
		return fmt.Errorf("machineId does not belong in a %s record", m.Kind)
	}
	return nil
}

func sizedBase64(s string, max int, name string) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	switch {
	case err != nil:
		return fmt.Errorf("%s is not canonical base64", name)
	case len(raw) == 0:
		return fmt.Errorf("%s is empty", name)
	case len(raw) > max:
		return fmt.Errorf("%s is %d bytes, over the %d byte limit", name, len(raw), max)
	}
	return nil
}

func validTime(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// Seal 把一份材料加密给收件人公钥。
func Seal(m Material, recipientPub []byte) (Box, error) {
	if len(recipientPub) != sealedbox.KeySize {
		return Box{}, errors.New("iosmaterial: recipient public key must be 32 bytes")
	}
	m.RecipientSHA256 = fingerprint.SHA256Hex(recipientPub)
	if m.Purpose == "" {
		purpose, err := PurposeFor(m.Kind)
		if err != nil {
			return Box{}, err
		}
		m.Purpose = purpose
	}
	if m.CreatedAt == "" {
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := m.Validate(); err != nil {
		return Box{}, fmt.Errorf("iosmaterial: %w", err)
	}
	plain, err := json.Marshal(wireMaterial(m))
	if err != nil {
		return Box{}, err
	}
	defer sealedbox.Wipe(plain)
	sealed, err := sealedbox.Seal(Label, m.Purpose, plain, recipientPub)
	if err != nil {
		return Box{}, fmt.Errorf("iosmaterial: %w", err)
	}
	box := Box{
		Version: Version, Algorithm: Algorithm,
		Purpose: m.Purpose, Kind: m.Kind, TeamID: m.TeamID,
		BundleID: m.BundleID, MachineID: m.MachineID,
		RecipientSHA256:    sealed.RecipientSHA256,
		EphemeralPublicKey: sealed.EphemeralPublicKey,
		Nonce:              sealed.Nonce,
		Ciphertext:         sealed.Ciphertext,
		CreatedAt:          m.CreatedAt,
	}
	if err := box.ValidateShape(); err != nil {
		return Box{}, fmt.Errorf("iosmaterial: sealed box failed its own shape check: %w", err)
	}
	return box, nil
}

// Open 用私钥解一份。外层字段一个都不采信：核对完全按解出来的那一份。
func Open(b Box, x25519Private []byte) (Material, error) {
	priv, err := sealedbox.PrivateKey(x25519Private)
	if err != nil {
		return Material{}, fmt.Errorf("iosmaterial: %w", err)
	}
	if err := b.ValidateShape(); err != nil {
		return Material{}, fmt.Errorf("iosmaterial: %w", err)
	}
	plain, err := sealedbox.Open(sealedbox.Sealed{
		RecipientSHA256:    b.RecipientSHA256,
		EphemeralPublicKey: b.EphemeralPublicKey,
		Nonce:              b.Nonce,
		Ciphertext:         b.Ciphertext,
	}, Label, b.Purpose, priv)
	switch {
	case errors.Is(err, sealedbox.ErrNotAddressedToThisKey):
		return Material{}, ErrNotAddressedToThisKey
	case err != nil:
		return Material{}, ErrDecrypt
	}
	defer sealedbox.Wipe(plain)

	var wire wireMaterial
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Material{}, ErrInvalidMaterial
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Material{}, ErrInvalidMaterial
	}
	out := Material(wire)
	if err := out.Validate(); err != nil {
		return Material{}, fmt.Errorf("%w: %v", ErrInvalidMaterial, err)
	}
	// 自证收件人：外层那一行可以被改，密文里这一行改不了
	if out.RecipientSHA256 != fingerprint.SHA256Hex(priv.PublicKey().Bytes()) {
		return Material{}, fmt.Errorf("%w: the record names another recipient", ErrInvalidMaterial)
	}
	// 外层与内层必须一致。外层是服务端拿来路由与显示的，改得动；内层改不动。两者不符
	// 只有两种可能：服务端的索引与内容对不上，或者有人动过手脚——都该当场停住，而不是
	// "反正我只信内层"然后把一份与索引不符的材料装到机器上。
	for _, pair := range []struct{ name, outer, inner string }{
		{"kind", b.Kind, out.Kind},
		{"teamId", b.TeamID, out.TeamID},
		{"bundleId", b.BundleID, out.BundleID},
		{"machineId", b.MachineID, out.MachineID},
	} {
		if pair.outer != pair.inner {
			return Material{}, fmt.Errorf("%w: the box says %s=%q but the sealed record says %q",
				ErrInvalidMaterial, pair.name, firstRunes(pair.outer, 64), firstRunes(pair.inner, 64))
		}
	}
	return out, nil
}

// ValidateShape 只查形状，不碰密码学。
func (b Box) ValidateShape() error {
	if b.Version != Version {
		return fmt.Errorf("version %d is not %d", b.Version, Version)
	}
	if b.Algorithm != Algorithm {
		return fmt.Errorf("algorithm %q is not %q", firstRunes(b.Algorithm, 64), Algorithm)
	}
	want, err := PurposeFor(b.Kind)
	if err != nil {
		return err
	}
	if b.Purpose != want {
		return fmt.Errorf("purpose %q does not match kind %q", firstRunes(b.Purpose, 32), b.Kind)
	}
	if !teamIDPattern.MatchString(b.TeamID) {
		return fmt.Errorf("teamId %q is not a 10 character Apple Team ID", firstRunes(b.TeamID, 32))
	}
	if !fingerprint.Valid(b.RecipientSHA256) {
		return errors.New("recipientSha256 is not a sha256")
	}
	if _, err := sealedbox.DecodeFixed(b.EphemeralPublicKey, sealedbox.KeySize); err != nil {
		return errors.New("epk is not a 32 byte base64 value")
	}
	if _, err := sealedbox.DecodeFixed(b.Nonce, sealedbox.NonceSize); err != nil {
		return errors.New("nonce is not a 12 byte base64 value")
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(b.Ciphertext)
	switch {
	case err != nil:
		return errors.New("ct is not canonical base64")
	case len(ct) <= sealedbox.TagSize:
		return errors.New("ct is too short to hold anything")
	case len(ct) > MaxBoxSize:
		return errors.New("ct is over the size limit")
	}
	if !validTime(b.CreatedAt) {
		return errors.New("createdAt is not an RFC3339 timestamp")
	}
	return nil
}

// ParseBox 读一份上传上来的密文。
func ParseBox(raw []byte) (Box, error) {
	if len(raw) > MaxBoxSize {
		return Box{}, errors.New("iosmaterial: the file is over the size limit")
	}
	var box Box
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&box); err != nil {
		return Box{}, fmt.Errorf("iosmaterial: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Box{}, errors.New("iosmaterial: trailing content after the box")
	}
	if err := box.ValidateShape(); err != nil {
		return Box{}, fmt.Errorf("iosmaterial: %w", err)
	}
	return box, nil
}

// ---- 机密结构体的格式化白名单 ----

func (m Material) String() string {
	parts := []string{"kind=" + m.Kind, "team=" + m.TeamID}
	if m.BundleID != "" {
		parts = append(parts, "bundle="+m.BundleID)
	}
	if m.MachineID != "" {
		parts = append(parts, "machine="+m.MachineID)
	}
	if m.KeyID != "" {
		parts = append(parts, "keyId="+m.KeyID)
	}
	return "iosmaterial.Material{" + strings.Join(parts, " ") + " …}"
}

func (m Material) GoString() string { return m.String() }

func (m Material) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, m.String()) }

func (m Material) LogValue() slog.Value { return slog.StringValue(m.String()) }

// MarshalJSON 报错：这个类型不该被 json.Marshal 出去。包内序列化用 wireMaterial。
func (m Material) MarshalJSON() ([]byte, error) {
	return nil, errors.New("iosmaterial: Material must not be marshalled; it holds a private key and a password")
}

func firstRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	out := []rune(s)[:n]
	return string(out) + "…"
}
