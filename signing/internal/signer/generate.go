package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/releasekey"
)

// 生成的密钥参数：与离线工具 build-keystore create 一致。
const (
	generatedKeyBits      = 4096
	generatedValidityYear = 30
)

// generateReleaseKey 生成 RSA 密钥、证书与 PKCS#12。测试替换成预先生成的密钥池提速。
var generateReleaseKey = releasekey.Generate

// GenerateParams 是生成一把租户签名密钥需要的输入。收件人由调用方按本机记录定好（本机、
// 本机信任的签名闸、本机信任的恢复公钥），这里不做任何信任判断。
type GenerateParams struct {
	RequestID   string
	TenantSlug  string
	PackageName string
	KeyAlias    string
	// Recipients 是收件人的 X25519 公钥（每把 32 字节，不能重复）
	Recipients [][]byte
	// Generator 是生成者（主签名闸）的 Ed25519 私钥，给生成签名用
	Generator ed25519.PrivateKey
	// KeyBits 为 0 时用 4096；测试用 2048 提速
	KeyBits int
	Now     time.Time
	// Binding 是生成者本机为这把密钥写下的确认参数，写进每个 Box 的明文（被生成签名覆盖）。
	// 签名闸生成时必填；别的签名闸没有它就不自动接受。
	Binding *keystorebox.Generation
}

// GeneratedKeystore 是生成结果。明文原件与口令只在 GenerateKeystore 里存在，返回的只有密文与签名。
type GeneratedKeystore struct {
	Upload            keystorebox.Upload
	Signature         string // base64 std，Ed25519 签 keystorebox.GenerationMessage
	CertificateSHA256 string
}

// GenerateKeystore 生成 RSA 密钥、自签证书与 PKCS#12（releasekey.Generate，当场读回核对），
// 加密给每个收件人，组成 Upload 并签生成签名。
func GenerateKeystore(p GenerateParams) (GeneratedKeystore, error) {
	switch {
	case !keystorebox.ValidGenerationRequestID(p.RequestID):
		return GeneratedKeystore{}, errors.New("generation request id is malformed")
	case !ident.ValidTenantSlug(p.TenantSlug):
		return GeneratedKeystore{}, errors.New("tenant slug is malformed")
	case !ident.ValidPackageName(p.PackageName):
		return GeneratedKeystore{}, errors.New("package name is malformed")
	case !ident.ValidKeyAlias(p.KeyAlias):
		return GeneratedKeystore{}, errors.New("key alias is malformed")
	case len(p.Generator) != ed25519.PrivateKeySize:
		return GeneratedKeystore{}, errors.New("generator key must be an Ed25519 private key")
	case len(p.Recipients) == 0 || len(p.Recipients) > keystorebox.MaxBoxes:
		return GeneratedKeystore{}, fmt.Errorf("expected 1-%d recipients", keystorebox.MaxBoxes)
	}
	shas := make([]string, 0, len(p.Recipients))
	seen := map[string]bool{}
	for _, pub := range p.Recipients {
		sha := fingerprint.SHA256Hex(pub)
		if len(pub) != 32 || seen[sha] {
			return GeneratedKeystore{}, errors.New("recipients must be distinct 32-byte X25519 public keys")
		}
		seen[sha] = true
		shas = append(shas, sha)
	}
	sort.Strings(shas)
	bits := p.KeyBits
	if bits == 0 {
		bits = generatedKeyBits
	}
	generated, err := generateReleaseKey(releasekey.Params{
		Alias: p.KeyAlias, CommonName: p.TenantSlug + " Android Release", KeyBits: bits, ValidityYears: generatedValidityYear,
	})
	if err != nil {
		return GeneratedKeystore{}, fmt.Errorf("generate the signing key: %w", err)
	}
	createdAt := p.Now.UTC().Truncate(time.Second).Format(time.RFC3339)
	plain := keystorebox.Plaintext{
		Purpose:           keystorebox.Purpose,
		TenantSlug:        p.TenantSlug,
		PackageName:       p.PackageName,
		CertificateSHA256: generated.CertificateSHA256,
		KeyAlias:          p.KeyAlias,
		Recipients:        shas,
		CreatedAt:         createdAt,
		P12Base64:         base64.StdEncoding.EncodeToString(generated.PKCS12),
		StorePassword:     generated.Password,
		KeyPassword:       generated.Password,
		Generation:        p.Binding,
	}
	boxes := make([]keystorebox.Box, 0, len(p.Recipients))
	for _, pub := range p.Recipients {
		box, err := keystorebox.Seal(plain, pub)
		if err != nil {
			return GeneratedKeystore{}, fmt.Errorf("encrypt the signing key: %w", err)
		}
		boxes = append(boxes, box)
	}
	upload := keystorebox.Upload{
		Format:            keystorebox.UploadFormat,
		TenantSlug:        p.TenantSlug,
		PackageName:       p.PackageName,
		KeyAlias:          p.KeyAlias,
		CertificateSHA256: generated.CertificateSHA256,
		CreatedAt:         createdAt,
		Boxes:             boxes,
	}
	signature, err := keystorebox.SignGeneration(p.Generator, p.RequestID, upload)
	if err != nil {
		return GeneratedKeystore{}, err
	}
	return GeneratedKeystore{Upload: upload, Signature: signature, CertificateSHA256: generated.CertificateSHA256}, nil
}
