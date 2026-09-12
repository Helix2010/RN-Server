package androidkeystore

import (
	"crypto/x509"
	"errors"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// parsePKCS12Certificate 从 keystore 里取出签名用的那张证书。
//
// 用 sslmate 那个 fork 而不是 x/crypto/pkcs12：后者只解得开 RC2/3DES 那套老加密，
// 而 JDK 9 之后 keytool 默认输出的是 PBES2（AES-256）。只支持一半会变成
// "有的 keystore 能自动填指纹、有的不能"，那比统一不支持更难解释。
//
// 解不开是正常结果，不是故障：JKS（keytool 的老格式）根本不是 PKCS#12。调用方
// 要能接受"算不出来，让人自己填"。
func parsePKCS12Certificate(keystore []byte, password string) (*x509.Certificate, error) {
	_, certificate, _, err := pkcs12.DecodeChain(keystore, password)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, errors.New("the keystore has no signing certificate")
	}
	return certificate, nil
}
