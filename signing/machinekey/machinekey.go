// Package machinekey 是机器换公钥时的身份证明。
//
// 已经 active 的机器（构建机或签名闸）要换公钥，必须用**当前**的 Ed25519 私钥对
// RotationMessage 签名。偷到机器令牌的人没有私钥，换不掉公钥，也就不能让已有的
// 密文全部作废或把出处签名换成自己的。私钥丢了按新机器处理。
package machinekey

import (
	"crypto/ed25519"
	"errors"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

const rotationPrefix = "rn-machine-key-rotation/v1\n"

// RotationMessage 返回要签名的字节：
//
//	"rn-machine-key-rotation/v1\n" + machineID + "\n" + newPrimaryKeySHA256 + "\n" + newEd25519KeySHA256
//
// newEd25519SHA256 对构建机是空串（构建机的主公钥本身就是 Ed25519）。
func RotationMessage(machineID, newKeySHA256, newEd25519SHA256 string) []byte {
	return []byte(rotationPrefix + machineID + "\n" + newKeySHA256 + "\n" + newEd25519SHA256)
}

// SignRotation 用当前私钥为新公钥签名。
func SignRotation(current ed25519.PrivateKey, machineID, newKeySHA256, newEd25519SHA256 string) ([]byte, error) {
	if len(current) != ed25519.PrivateKeySize {
		return nil, errors.New("machinekey: private key must be 64 bytes")
	}
	if err := validate(machineID, newKeySHA256, newEd25519SHA256); err != nil {
		return nil, err
	}
	return ed25519.Sign(current, RotationMessage(machineID, newKeySHA256, newEd25519SHA256)), nil
}

// VerifyRotation 用当前登记的公钥验证换钥签名。长度不对一律返回 false，不会 panic。
func VerifyRotation(current ed25519.PublicKey, machineID, newKeySHA256, newEd25519SHA256 string, signature []byte) bool {
	if len(current) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	if validate(machineID, newKeySHA256, newEd25519SHA256) != nil {
		return false
	}
	return ed25519.Verify(current, RotationMessage(machineID, newKeySHA256, newEd25519SHA256), signature)
}

// validate 挡住含换行的 id（否则 "a\nb" 与字段拼接能构造出歧义）与格式不对的指纹。
func validate(machineID, newKeySHA256, newEd25519SHA256 string) error {
	if machineID == "" || len(machineID) > 64 {
		return errors.New("machinekey: machine id is malformed")
	}
	for i := 0; i < len(machineID); i++ {
		if machineID[i] <= 0x20 || machineID[i] > 0x7e {
			return errors.New("machinekey: machine id is malformed")
		}
	}
	if !fingerprint.Valid(newKeySHA256) {
		return errors.New("machinekey: new key sha256 must be 64 lowercase hex characters")
	}
	if newEd25519SHA256 != "" && !fingerprint.Valid(newEd25519SHA256) {
		return errors.New("machinekey: new ed25519 key sha256 must be empty or 64 lowercase hex characters")
	}
	return nil
}
