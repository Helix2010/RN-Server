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
const (
	// GenerationPrefix 是生成签名输入的前缀。
	GenerationPrefix = "rn-keystore-generation/v1\n"
	// MaxUploadSize 是 ParseUpload 接受的上传文件大小上限（16 个 Box，每个至多约 172 KiB 的 base64）。
	MaxUploadSize = 4 << 20
)

// generationRequestIDPattern：请求 id 会拼进 URL 路径与签名输入，只收 base64url 字符。
var generationRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ErrGenerationSignature：生成签名格式不对或验证不通过。
var ErrGenerationSignature = errors.New("keystorebox: the keystore generation signature does not verify")

// ValidGenerationRequestID 判断生成请求 id：^[A-Za-z0-9_-]{1,128}$。
func ValidGenerationRequestID(s string) bool { return generationRequestIDPattern.MatchString(s) }

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
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("keystorebox: ed25519 private key must be 64 bytes")
	}
	msg, err := GenerationMessage(requestID, u)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// VerifyGeneration 用生成者登记的 Ed25519 公钥验证生成签名（base64 std）。任何格式问题都返回
// ErrGenerationSignature（包装），不会 panic。
func VerifyGeneration(pub ed25519.PublicKey, requestID string, u Upload, signature string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: the generator public key is not 32 bytes", ErrGenerationSignature)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: the signature is not base64 of 64 bytes", ErrGenerationSignature)
	}
	msg, err := GenerationMessage(requestID, u)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGenerationSignature, err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrGenerationSignature
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
