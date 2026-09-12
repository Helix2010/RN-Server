package androidkeystore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// AliasPattern 限制别名的字符集。它会被原样交给 Gradle 当 ANDROID_RELEASE_KEY_ALIAS，
// 空格和引号在那里会变成很难看懂的构建失败。
var AliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Params 是生成一把签名密钥需要人决定的全部东西。
//
// 证书里的这几项 Android 一个都不校验——它是自签名的，没有任何一方会去验证书主体。
// 它们只出现在 `apksigner verify --print-certs` 和 keytool 的输出里，是给人看的
// "这是谁的密钥"。所以只留必须的，不照抄 keytool 那一整套 dname 字段。
type Params struct {
	// CommonName 通常写 App 名。空的时候调用方应该先填好，这里不猜。
	CommonName   string
	Organization string
	// Country 是两位的 ISO 3166-1 代码，可以留空。
	Country string
	// KeyAlias 是 Gradle 那边的 keyAlias。
	KeyAlias string
	// KeySize 只允许 2048 或 4096。
	KeySize int
	// ValidityYears：证书过期之后这把密钥再也签不出能被系统接受的更新包。
	// direct 分发没有商店替我们提醒，所以下限定得比"够用"更长。
	ValidityYears int
}

// Result 是生成出来的东西。PKCS12 是明文的 keystore 文件，只在生成的那一次出现；
// 调用方要么把它封进盒子，要么交给人备份，不该留在任何地方。
type Result struct {
	PKCS12 []byte
	// StorePassword 由这里随机生成。它不需要任何人记住——打包机从盒子里读它——
	// 但备份下来的那份 keystore 文件要用它才能打开，所以调用方要展示一次。
	StorePassword string
	// SignerSHA256 是证书 DER 的 SHA-256，也就是 apksigner --print-certs 和
	// keytool -list -v 打出来的那一行。发布身份要 pin 的就是它。
	SignerSHA256 string
	// KeystoreSHA256 是 keystore 文件本身的摘要，用来认"配的是哪一个文件"。
	KeystoreSHA256 string
	Certificate    *x509.Certificate
	NotAfter       time.Time
}

const (
	minValidityYears = 25
	maxValidityYears = 60
	// 口令长度按 128 bit 熵取。它是随机生成的，不用考虑好不好记。
	storePasswordBytes = 16
)

func (p Params) validate() error {
	if strings.TrimSpace(p.CommonName) == "" || len([]rune(p.CommonName)) > 64 {
		return errors.New("commonName must be 1-64 characters")
	}
	if len([]rune(p.Organization)) > 64 {
		return errors.New("organization must be at most 64 characters")
	}
	if country := strings.TrimSpace(p.Country); country != "" && len(country) != 2 {
		return errors.New("country must be a two-letter ISO 3166-1 code")
	}
	if !AliasPattern.MatchString(p.KeyAlias) {
		return errors.New("keyAlias must be 1-64 characters of letters, digits, dot, dash or underscore")
	}
	if p.KeySize != 2048 && p.KeySize != 4096 {
		return errors.New("keySize must be 2048 or 4096")
	}
	if p.ValidityYears < minValidityYears || p.ValidityYears > maxValidityYears {
		return fmt.Errorf("validityYears must be between %d and %d: once the certificate expires this key can no longer sign an upgrade that installs over the existing app", minValidityYears, maxValidityYears)
	}
	return nil
}

// Generate 造一把新的签名密钥：RSA 密钥对 + 一张自签名证书 + 一个 PKCS#12 文件。
//
// 用 RSA 不用 EC：APK Signature Scheme v2/v3 两者都支持，但 v1（JAR 签名）在很老的
// 设备上只认 RSA/DSA，而 minSdk 往下兼容的成本为零。
func Generate(params Params) (Result, error) {
	var out Result
	if err := params.validate(); err != nil {
		return out, err
	}
	key, err := rsa.GenerateKey(randomReader, params.KeySize)
	if err != nil {
		return out, err
	}
	// 序列号随机取。自签名证书没有签发机构去保证唯一，但 apksigner 会把它打出来，
	// 固定成 1 会让两把不同的密钥在日志里长得一样
	serial, err := rand.Int(randomReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return out, err
	}
	subject := pkix.Name{CommonName: strings.TrimSpace(params.CommonName)}
	if organization := strings.TrimSpace(params.Organization); organization != "" {
		subject.Organization = []string{organization}
	}
	if country := strings.TrimSpace(params.Country); country != "" {
		subject.Country = []string{strings.ToUpper(country)}
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		Issuer:       subject,
		// 往回退一小时：打包机和这台机器的时钟不一定完全一致，而"证书还没生效"
		// 的表现是构建到签名那一步才失败
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(params.ValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(randomReader, template, template, &key.PublicKey, key)
	if err != nil {
		return out, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return out, err
	}

	password := make([]byte, storePasswordBytes)
	if _, err := randomReader.Read(password); err != nil {
		return out, err
	}
	storePassword := hex.EncodeToString(password)

	keystore, err := encodePKCS12(randomReader, key, certificate, params.KeyAlias, storePassword)
	if err != nil {
		return out, err
	}
	signer := sha256.Sum256(certificate.Raw)
	file := sha256.Sum256(keystore)
	return Result{
		PKCS12:         keystore,
		StorePassword:  storePassword,
		SignerSHA256:   hex.EncodeToString(signer[:]),
		KeystoreSHA256: hex.EncodeToString(file[:]),
		Certificate:    certificate,
		NotAfter:       certificate.NotAfter,
	}, nil
}

// CertificateSHA256 从一个 PKCS#12 keystore 里读出证书指纹。
//
// 离线封装那条路径用它：`build-keystore seal` 拿到的是一个已经存在的 keystore，
// 指纹本来就能从里面算出来，不该再让人跑一次 keytool 把 64 位十六进制抄一遍——
// 抄错的表现是构建成功、产物在入库那一步被拒。
//
// 只认 PKCS#12。老的 JKS 格式解不开，调用方要能接受"算不出来"。
func CertificateSHA256(keystore []byte, password string) (string, error) {
	certificate, err := parsePKCS12Certificate(keystore, password)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:]), nil
}

// PublicDebugSignerSHA256 是 React Native / Android SDK 模板自带的 debug.keystore
// 那张证书的 SHA-256。
//
// 它的私钥在每一台装了 RN 的机器上，所以谁都能用它签一个同包名的 APK 在用户设备上
// 原地覆盖安装，数据目录连钱包一起留着。拿它当发布身份等于把自校验关掉，还留下一行
// "已经校验过了"的假象。
//
// 重新求证：
//
//	keytool -list -v -keystore <RN-App>/android/app/debug.keystore -storepass android
//
// 打出来的 SHA256 行去掉冒号、转小写就是这个值。**不要**用同一段输出里的 SHA1——
// 2026-09-12 之前 cmd/build-agent 里那份常量就是把 SHA-1 补零凑到 64 位得来的，
// 于是那道闸永远匹配不上，是一条恒假的断言。
const PublicDebugSignerSHA256 = "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
