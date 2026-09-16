// Package releasekey 在离线机器上生成一把新的 Android 发布签名密钥：RSA 私钥 + 自签证书
// + PKCS#12 原件 + 随机口令。
//
// 生成的那一刻是明文私钥唯一出现在离线区之外的风险点之前的最后一站：调用方
// （build-keystore create）只把原件写进 0700 目录里的 0600 文件，只把密文交给控制台。
package releasekey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
)

const (
	minValidityYears = 25
	maxValidityYears = 60
	// 口令取 256 比特熵，十六进制写出：只含 [0-9a-f]，放进口令文件、交给 apksigner 的
	// file: 都不会有转义问题。
	passwordBytes = 32
)

// Params 是生成一把密钥需要人决定的东西。
type Params struct {
	Alias        string
	CommonName   string
	Organization string
	// KeyBits 只允许 2048 或 4096。离线工具固定用 4096，2048 只给测试提速。
	KeyBits int
	// ValidityYears：证书过期之后这把密钥再也签不出能覆盖安装的更新包，所以下限定得很长。
	ValidityYears int
}

// Result 是生成的结果。它装着原件与口令：String / GoString / Format / LogValue 只输出
// 证书指纹与到期时间，MarshalJSON 直接报错。
type Result struct {
	PKCS12            []byte
	Password          string
	CertificateSHA256 string
	Certificate       *x509.Certificate
	NotAfter          time.Time
}

func (r Result) String() string {
	return fmt.Sprintf("releasekey.Result{certificateSha256=%q notAfter=%s pkcs12=[redacted] password=[redacted]}",
		r.CertificateSHA256, r.NotAfter.UTC().Format(time.RFC3339))
}

// GoString 覆盖 %#v。
func (r Result) GoString() string { return r.String() }

// Format 覆盖所有格式化动词。
func (r Result) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.String()) }

// LogValue 覆盖 slog。
func (r Result) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("certificateSha256", r.CertificateSHA256),
		slog.Time("notAfter", r.NotAfter),
	)
}

// MarshalJSON 拒绝序列化。
func (r Result) MarshalJSON() ([]byte, error) {
	return nil, errors.New("releasekey: refusing to JSON-encode a generated signing key")
}

func (p Params) validate() error {
	if !ident.ValidKeyAlias(p.Alias) {
		return errors.New("alias must match ^[A-Za-z0-9._-]{1,64}$")
	}
	if err := validateName(p.CommonName, true); err != nil {
		return fmt.Errorf("commonName %w", err)
	}
	if err := validateName(p.Organization, false); err != nil {
		return fmt.Errorf("organization %w", err)
	}
	if p.KeyBits != 2048 && p.KeyBits != 4096 {
		return errors.New("key size must be 2048 or 4096 bits")
	}
	if p.ValidityYears < minValidityYears || p.ValidityYears > maxValidityYears {
		return fmt.Errorf("validity must be %d-%d years: once the certificate expires this key can no longer sign an update that installs over the existing app",
			minValidityYears, maxValidityYears)
	}
	return nil
}

// validateName：证书主体里的名字会出现在 apksigner、keytool 的输出里，不收控制字符。
func validateName(s string, required bool) error {
	if strings.TrimSpace(s) != s {
		return errors.New("must not have leading or trailing spaces")
	}
	if s == "" {
		if required {
			return errors.New("is required")
		}
		return nil
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > 64 {
		return errors.New("must be at most 64 characters of UTF-8")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// Generate 生成密钥、证书与 PKCS#12 原件，并当场用解码器读回核对。
func Generate(p Params) (Result, error) {
	if err := p.validate(); err != nil {
		return Result{}, fmt.Errorf("releasekey: %w", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, p.KeyBits)
	if err != nil {
		return Result{}, err
	}
	// 序列号随机取 128 比特：自签证书没有签发机构保证唯一，固定值会让两把不同的密钥
	// 在 apksigner 的输出里长得一样
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Result{}, err
	}
	serial.Add(serial, big.NewInt(1))
	subject := pkix.Name{CommonName: p.CommonName}
	if p.Organization != "" {
		subject.Organization = []string{p.Organization}
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		// 往回退一小时：签名闸与离线机器的时钟不一定一致
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.AddDate(p.ValidityYears, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return Result{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Result{}, err
	}
	raw := make([]byte, passwordBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return Result{}, err
	}
	password := hex.EncodeToString(raw)
	for i := range raw {
		raw[i] = 0
	}
	p12, err := pkcs12.Encode(key, cert, p.Alias, password)
	if err != nil {
		return Result{}, err
	}
	// 读回核对：原件打不开要现在发现，而不是等到签名闸第一次签名
	entry, err := pkcs12.FindKey(p12, password, p.Alias)
	if err != nil {
		return Result{}, fmt.Errorf("releasekey: the generated keystore failed its own read-back check: %w", err)
	}
	certSHA := fingerprint.SHA256Hex(cert.Raw)
	if pkcs12.CertificateSHA256(entry) != certSHA || !key.Equal(entry.PrivateKey) {
		return Result{}, errors.New("releasekey: the generated keystore reads back a different key or certificate")
	}
	return Result{
		PKCS12:            p12,
		Password:          password,
		CertificateSHA256: certSHA,
		Certificate:       cert,
		NotAfter:          cert.NotAfter,
	}, nil
}
