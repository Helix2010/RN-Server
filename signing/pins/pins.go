// Package pins 是离线 pin 文件：离线工具只把签名密钥加密给这里列出的签名闸。
//
// pin 文件是收件人的唯一依据。服务端登记了哪些签名闸、控制台接受了哪些公钥，都不会
// 让离线工具多加密一份。文件里每一项的公钥与指纹由运维从签名闸上的 `signer show-key`
// 抄来，加载时逐项核对指纹与公钥一致。
package pins

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

// Format 是 pin 文件的格式标识。
const Format = "rn-signer-pins/v1"

// MaxSigners 与 keystorebox.MaxBoxes 一致。
const MaxSigners = 16

// MaxFileSize 是 pin 文件的大小上限。
const MaxFileSize = 64 << 10

// Roles 是 pin 文件里签名闸的角色（只作标注，签名闸以本机记录为准）。
const (
	RolePrimary = "primary"
	RoleStandby = "standby"
)

// File 是 pin 文件。
type File struct {
	Format  string   `json:"format"`
	Signers []Signer `json:"signers"`
}

// Signer 是一台签名闸。
type Signer struct {
	Name                   string `json:"name"`
	Role                   string `json:"role"`
	X25519PublicKey        string `json:"x25519PublicKey"`
	X25519PublicKeySHA256  string `json:"x25519PublicKeySha256"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
}

// PublicKey 解码 X25519 公钥（Parse/Validate 之后调用才保证成功）。
func (s Signer) PublicKey() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s.X25519PublicKey)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("x25519PublicKey must be base64 of 32 bytes")
	}
	if _, err := ecdh.X25519().NewPublicKey(raw); err != nil {
		return nil, errors.New("x25519PublicKey is not a valid X25519 public key")
	}
	return raw, nil
}

// Validate 检查单项：名字、角色、公钥与指纹一致。
func (s Signer) Validate() error {
	if !ident.ValidMachineName(s.Name) {
		return errors.New("name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	}
	if s.Role != RolePrimary && s.Role != RoleStandby {
		return errors.New("role must be primary or standby")
	}
	raw, err := s.PublicKey()
	if err != nil {
		return err
	}
	if !fingerprint.Valid(s.X25519PublicKeySHA256) {
		return errors.New("x25519PublicKeySha256 must be 64 lowercase hex characters")
	}
	if fingerprint.SHA256Hex(raw) != s.X25519PublicKeySHA256 {
		return errors.New("x25519PublicKeySha256 does not match x25519PublicKey: the key or the fingerprint was copied wrong")
	}
	if !fingerprint.Valid(s.Ed25519PublicKeySHA256) {
		return errors.New("ed25519PublicKeySha256 must be 64 lowercase hex characters")
	}
	return nil
}

// Validate 检查整份文件：格式、至少一台、名字与公钥不重复、至多一台 primary。
func (f File) Validate() error {
	if f.Format != Format {
		return errors.New("format must be " + Format)
	}
	if len(f.Signers) == 0 || len(f.Signers) > MaxSigners {
		return fmt.Errorf("signers must list 1-%d signing gates", MaxSigners)
	}
	names := map[string]bool{}
	keys := map[string]bool{}
	edKeys := map[string]bool{}
	primaries := 0
	for i, s := range f.Signers {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("signers[%d]: %w", i, err)
		}
		if names[s.Name] {
			return fmt.Errorf("signers[%d]: name %s appears more than once", i, s.Name)
		}
		if keys[s.X25519PublicKeySHA256] {
			return fmt.Errorf("signers[%d]: the same X25519 public key appears more than once", i)
		}
		if edKeys[s.Ed25519PublicKeySHA256] {
			return fmt.Errorf("signers[%d]: the same Ed25519 public key appears more than once", i)
		}
		names[s.Name], keys[s.X25519PublicKeySHA256], edKeys[s.Ed25519PublicKeySHA256] = true, true, true
		if s.Role == RolePrimary {
			primaries++
		}
	}
	if primaries > 1 {
		return errors.New("at most one signer may be marked primary")
	}
	return nil
}

// Parse 严格解析并校验 pin 文件（未知字段、尾随数据都拒绝）。
func Parse(raw []byte) (File, error) {
	if len(raw) > MaxFileSize {
		return File{}, errors.New("pin file is larger than 64 KiB")
	}
	var f File
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return File{}, fmt.Errorf("pin file is not valid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return File{}, errors.New("pin file has trailing data after the JSON object")
	}
	if err := f.Validate(); err != nil {
		return File{}, fmt.Errorf("pin file: %w", err)
	}
	return f, nil
}

// RecipientSHA256s 返回排序后的全部收件人指纹（keystorebox.Plaintext.Recipients 的值）。
func (f File) RecipientSHA256s() []string {
	out := make([]string, 0, len(f.Signers))
	for _, s := range f.Signers {
		out = append(out, s.X25519PublicKeySHA256)
	}
	sort.Strings(out)
	return out
}

// Entry 生成一台签名闸的 pin 项（signer show-key 打印的那段）。
func Entry(name, role string, x25519Pub, ed25519Pub []byte) (Signer, error) {
	s := Signer{
		Name:                   name,
		Role:                   role,
		X25519PublicKey:        base64.StdEncoding.EncodeToString(x25519Pub),
		X25519PublicKeySHA256:  fingerprint.SHA256Hex(x25519Pub),
		Ed25519PublicKeySHA256: fingerprint.SHA256Hex(ed25519Pub),
	}
	if len(ed25519Pub) != 32 {
		return Signer{}, errors.New("ed25519 public key must be 32 bytes")
	}
	if err := s.Validate(); err != nil {
		return Signer{}, err
	}
	return s, nil
}
