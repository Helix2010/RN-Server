package keystorebox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// 签名闸生成的密钥：主签名闸在本机生成租户签名密钥、加密成 Upload 之后，用本机 Ed25519
// （记录签名那把）签 GenerationMessage。服务端用路由主签名闸登记的 Ed25519 公钥验证后才落库；
// 备签名闸拿到新密文时，只接受本机信任的签名闸签过的生成。
//
// 同证书重新封装（reseal）：主签名闸把本机已确认的同一把密钥重新加密给新的收件人（后加的签名闸），用同一把 Ed25519
// 签 ResealMessage。前缀与生成签名不同，两种签名不能互相冒充。
const (
	// GenerationPrefix 是生成签名输入的前缀。
	GenerationPrefix = "rn-keystore-generation/v1\n"
	// ResealPrefix 是重新封装签名输入的前缀。
	ResealPrefix = "rn-keystore-reseal/v1\n"
	// ResealIDPrefix 是重新封装 id 的前缀（rsl_ + 22 位 base64url，即 16 个随机字节）。
	ResealIDPrefix = "rsl_"
	// MaxUploadSize 是 ParseUpload 接受的上传文件大小上限（16 个 Box，每个至多约 172 KiB 的 base64）。
	MaxUploadSize = 4 << 20
)

// generationRequestIDPattern：请求 id 会拼进 URL 路径与签名输入，只收 base64url 字符。
var generationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// resealIDPattern：rsl_ 加 22 位 base64url。它也满足 generationRequestIDPattern（服务端把它记在同一个字段里）。
var resealIDPattern = regexp.MustCompile(`^rsl_[A-Za-z0-9_-]{22}$`)

// ErrGenerationSignature：生成签名格式不对或验证不通过。
var ErrGenerationSignature = errors.New("keystorebox: the keystore generation signature does not verify")

// ErrResealSignature：重新封装签名格式不对或验证不通过。
var ErrResealSignature = errors.New("keystorebox: the keystore reseal signature does not verify")

// ValidGenerationRequestID 判断生成请求 id：^[A-Za-z0-9_-]{1,128}$。
func ValidGenerationRequestID(s string) bool { return generationRequestIDPattern.MatchString(s) }

// ValidResealID 判断重新封装 id：^rsl_[A-Za-z0-9_-]{22}$。
func ValidResealID(s string) bool { return resealIDPattern.MatchString(s) }

// UploadDigest 是 Upload 的规范化摘要：sha256(json.Marshal(u))，小写十六进制。
//
// 规范化就是 json.Marshal 这个结构体本身（字段顺序由结构体固定，Boxes 保持原顺序），不做
// 额外的空白处理。服务端必须对解码后的结构体重新 Marshal 再算，不能对收到的原始字节算。
// 形状不合格的 Upload 没有摘要。
func UploadDigest(u Upload) (string, error) {
	if err := u.ValidateShape(); err != nil {
		return "", fmt.Errorf("keystorebox: upload: %w", err)
	}
	raw, err := json.Marshal(u)
	if err != nil {
		return "", err
	}
	return fingerprint.SHA256Hex(raw), nil
}

// GenerationMessage 返回生成签名的输入：
//
//	"rn-keystore-generation/v1\n" + requestID + "\n" + UploadDigest(u)
func GenerationMessage(requestID string, u Upload) ([]byte, error) {
	if !ValidGenerationRequestID(requestID) {
		return nil, errors.New("keystorebox: generation request id must match ^[A-Za-z0-9_-]{1,128}$")
	}
	digest, err := UploadDigest(u)
	if err != nil {
		return nil, err
	}
	return []byte(GenerationPrefix + requestID + "\n" + digest), nil
}

// SignGeneration 用生成者（主签名闸）的 Ed25519 私钥签名，返回 base64 std。
func SignGeneration(priv ed25519.PrivateKey, requestID string, u Upload) (string, error) {
	msg, err := GenerationMessage(requestID, u)
	if err != nil {
		return "", err
	}
	return sign(priv, msg)
}

// VerifyGeneration 用生成者登记的 Ed25519 公钥验证生成签名（base64 std）。任何格式问题都返回
// ErrGenerationSignature（包装），不会 panic。
func VerifyGeneration(pub ed25519.PublicKey, requestID string, u Upload, signature string) error {
	msg, err := GenerationMessage(requestID, u)
	return verify(ErrGenerationSignature, pub, msg, err, signature)
}

// ResealMessage 返回重新封装签名的输入：
//
//	"rn-keystore-reseal/v1\n" + resealID + "\n" + UploadDigest(u)
func ResealMessage(resealID string, u Upload) ([]byte, error) {
	if !ValidResealID(resealID) {
		return nil, errors.New("keystorebox: reseal id must match ^rsl_[A-Za-z0-9_-]{22}$")
	}
	digest, err := UploadDigest(u)
	if err != nil {
		return nil, err
	}
	return []byte(ResealPrefix + resealID + "\n" + digest), nil
}

// SignReseal 用重新封装者（主签名闸）的 Ed25519 私钥签名，返回 base64 std。
func SignReseal(priv ed25519.PrivateKey, resealID string, u Upload) (string, error) {
	msg, err := ResealMessage(resealID, u)
	if err != nil {
		return "", err
	}
	return sign(priv, msg)
}

// VerifyReseal 用重新封装者的 Ed25519 公钥验证重新封装签名（base64 std）。任何格式问题都返回
// ErrResealSignature（包装），不会 panic。
func VerifyReseal(pub ed25519.PublicKey, resealID string, u Upload, signature string) error {
	msg, err := ResealMessage(resealID, u)
	return verify(ErrResealSignature, pub, msg, err, signature)
}

func sign(priv ed25519.PrivateKey, msg []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("keystorebox: ed25519 private key must be 64 bytes")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// verify：msgErr 是拼签名输入时的错误（id 或上传文件不合格）。
func verify(sentinel error, pub ed25519.PublicKey, msg []byte, msgErr error, signature string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: the signer public key is not 32 bytes", sentinel)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the signature is not base64 of 64 bytes", sentinel)
	}
	if msgErr != nil {
		return fmt.Errorf("%w: %v", sentinel, msgErr)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return sentinel
	}
	return nil
}

// ParseUpload 严格解析上传文件（或控制台导出的密文文件）：未知字段、尾随数据、超长都拒绝，
// 再做 ValidateShape。
func ParseUpload(raw []byte) (Upload, error) {
	if len(raw) > MaxUploadSize {
		return Upload{}, fmt.Errorf("keystorebox: upload is larger than %d bytes", MaxUploadSize)
	}
	var u Upload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&u); err != nil {
		return Upload{}, fmt.Errorf("keystorebox: upload is not the expected JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Upload{}, errors.New("keystorebox: trailing data after the upload JSON")
	}
	if err := u.ValidateShape(); err != nil {
		return Upload{}, fmt.Errorf("keystorebox: upload: %w", err)
	}
	return u, nil
}

// BoxFor 返回 Upload 里发给 recipientSHA256 的那个 Box。
func (u Upload) BoxFor(recipientSHA256 string) (Box, bool) {
	for _, b := range u.Boxes {
		if b.RecipientSHA256 == recipientSHA256 {
			return b, true
		}
	}
	return Box{}, false
}
