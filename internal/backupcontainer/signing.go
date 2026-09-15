package backupcontainer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

// 备份包的真实性锚点（设计 §4.3）。
//
// 容器本身**只有保密性，没有真实性**：RSA-OAEP 用的是公钥，而公钥不是秘密（指纹
// 还印在控制台上）。任何拿到桶写权限的人都能从零封一个 MAC 校验通过、两层都解得开
// 的包，里面放他写的 recover.sh——而那个脚本恢复时必然以 root 跑，在平台最脆弱的
// 那一天、由两位持有人亲手执行。
//
// 所以打包机对每一份内层密文出一个 Ed25519 签名。**必须由打包机签，不能由服务端签**：
// 服务端被攻破是本方案自己列出的威胁，服务端签的东西挡不住服务端。
//
// 选 Ed25519 是因为 `openssl pkeyutl -verify` 在 OpenSSL ≥ 1.1.1 上直接支持它，
// 恢复端不需要装任何东西——这和容器格式选 tar+openssl 是同一条理由。

// SigningKeySeedSize 是私钥种子的字节数
const SigningKeySeedSize = ed25519.SeedSize

// EncodeSigningPublicKey 把 Ed25519 公钥编成 base64 的 DER SubjectPublicKeyInfo。
//
// 存 DER 而不是 32 字节裸公钥，是为了恢复端能一步转成 PEM 喂给 openssl：
//
//	base64 -d < pub.b64 | openssl pkey -pubin -inform DER -out pub.pem
//
// 裸公钥要自己拼 SPKI 头，那是灾难当天最不该出现的一步手工操作。
func EncodeSigningPublicKey(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encode signing public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParseSigningPublicKey 是 EncodeSigningPublicKey 的逆操作。
func ParseSigningPublicKey(encoded string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("signing public key is not valid base64: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("signing public key is not a DER SubjectPublicKeyInfo: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected an Ed25519 public key, got %T", parsed)
	}
	return pub, nil
}

// SignPayload 对一份内层密文签名。签的是**密文**不是明文：验签的人手上只有密文，
// 而且必须在解密之前就能判断这个包该不该信。
func SignPayload(key ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(key, payload)
}

// VerifyPayload 验一份内层密文的签名。
func VerifyPayload(pub ed25519.PublicKey, payload, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("signing public key has the wrong length")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, expected %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, payload, signature) {
		return errors.New("signature does not match: this payload was not produced by the registered build machine")
	}
	return nil
}

// SigningFingerprint 是备份签名公钥的指纹，和恢复公钥用**同一个定义**：
// DER SPKI 的 SHA-256，小写 hex，64 字符。
//
// 三个持有人各自在纸上抄这一行（§2.2）。它是两台机器都没了之后，唯一还能回答
// 「这个包是不是我们那台机器产出的」的东西——数据库里的登记那时也没了。
func SigningFingerprint(pub ed25519.PublicKey) (string, error) {
	return Fingerprint(pub)
}

// 编译期确认 ed25519.PrivateKey 满足 crypto.Signer：将来有人想换成硬件密钥时，
// 这一行会告诉他接口是什么
var _ crypto.Signer = ed25519.PrivateKey(nil)
