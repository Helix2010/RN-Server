// Package bundlesig 是安装包清单的离线签名：平台管理员在离线机器上用发布密钥签
// manifest.json，Mac 上的升级程序验完签名才肯换二进制。
//
// 为什么需要它（设计 docs/design/ios-mac-builders-home-network-2026-09-18.md §5.6）：
// 自升级是整个方案里**唯一一条"服务端能往 Mac 上放可执行代码"的路**，而每台 Mac 上放着
// 全部租户的签名材料。只校验 sha256 没有意义——sha256 是服务端给的，服务端被攻破它就跟着
// 被换掉。所以清单要由一把**服务端手里没有**的私钥签过。
//
// 签名覆盖三件事，少一件都有一条绕过去的路：
//
//   - 提交：签的是"这一版程序"，不是"某个文件的摘要"；
//   - 单调序号：攻破服务端的人不能把机器降回一个有已知漏洞、但当初确实被签过的旧版本。
//     要回滚就用**更高的序号**再签一份指向旧提交的清单——回滚因此是一次显式的、有签名的
//     动作，而不是数据库里改一个值；
//   - 清单摘要：清单里是每个归档与每个文件的 sha256，签了它就等于签了那些文件。
package bundlesig

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Format 是签名文件的格式标识，也进被签的字节里：换了格式的旧签名不能被当成新格式用。
const Format = "rn-machine-bundles-signature/v1"

// FileName 是签名文件在安装包目录里的名字，与 manifest.json 并排。
const FileName = "manifest.sig"

// MaxSize 是签名文件的大小上限。它是一份几百字节的 JSON；读它的一侧（Mac 上的升级程序）
// 对服务端给的东西按不可信处理。
const MaxSize = 8 << 10

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Signature 是 manifest.sig 的内容。
type Signature struct {
	Format string `json:"format"`
	// Commit 是这份清单描述的那一版程序
	Commit string `json:"commit"`
	// Sequence 每签一次加一。Mac 记住自己见过的最高值，低于它的一律拒
	Sequence int64 `json:"sequence"`
	// ManifestSHA256 是 manifest.json 的字节摘要
	ManifestSHA256 string `json:"manifestSha256"`
	// PublicKeySHA256 让人在装机时能核对"这是哪一把发布密钥"（与密码管理器里记的那个比）
	PublicKeySHA256 string `json:"publicKeySha256"`
	SignedAt        string `json:"signedAt"`
	// Signature 是对 signedBytes 的 Ed25519 签名，base64
	Signature string `json:"signature"`
}

// signedBytes 是真正被签的那串字节。每个字段一行、带格式标识与字段名：**不签 JSON**——
// JSON 的字段顺序、空白与转义有多种写法，签它等于把"同一份内容的不同写法"也算进签名里。
func (s Signature) signedBytes() []byte {
	return []byte(strings.Join([]string{
		Format,
		"commit=" + s.Commit,
		"sequence=" + strconv.FormatInt(s.Sequence, 10),
		"manifestSha256=" + s.ManifestSHA256,
		"",
	}, "\n"))
}

// PublicKeySHA256 是一把公钥的指纹，装机时按它核对。
func PublicKeySHA256(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// ManifestSHA256 是清单字节的摘要。
func ManifestSHA256(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:])
}

// Sign 签一份清单。commit 必须是完整的提交 sha——带 -dirty 的清单签不了，那正是要挡住的：
// 一个"工作区不干净"的构建不该被放到任何一台 Mac 上。
func Sign(private ed25519.PrivateKey, manifest []byte, commit string, sequence int64, at time.Time) (Signature, error) {
	if len(private) != ed25519.PrivateKeySize {
		return Signature{}, errors.New("release key is not an ed25519 private key")
	}
	if !commitPattern.MatchString(commit) {
		return Signature{}, fmt.Errorf("commit %q is not a full commit sha (a -dirty build cannot be signed)", commit)
	}
	if sequence < 1 {
		return Signature{}, errors.New("sequence must be a positive number")
	}
	public, _ := private.Public().(ed25519.PublicKey)
	signature := Signature{
		Format: Format, Commit: commit, Sequence: sequence,
		ManifestSHA256:  ManifestSHA256(manifest),
		PublicKeySHA256: PublicKeySHA256(public),
		SignedAt:        at.UTC().Format(time.RFC3339),
	}
	signature.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, signature.signedBytes()))
	return signature, nil
}

// Parse 解析一份签名文件，只做形状检查，不验签。
func Parse(raw []byte) (Signature, error) {
	var signature Signature
	if len(raw) > MaxSize {
		return signature, fmt.Errorf("%s is larger than %d bytes", FileName, MaxSize)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signature); err != nil {
		return signature, fmt.Errorf("%s is malformed: %w", FileName, err)
	}
	switch {
	case signature.Format != Format:
		return signature, fmt.Errorf("%s has format %q, expected %q", FileName, signature.Format, Format)
	case !commitPattern.MatchString(signature.Commit):
		return signature, errors.New("the signature names no usable commit")
	case signature.Sequence < 1:
		return signature, errors.New("the signature has no usable sequence number")
	case !digestPattern.MatchString(signature.ManifestSHA256):
		return signature, errors.New("the signature has no usable manifest digest")
	case !digestPattern.MatchString(signature.PublicKeySHA256):
		return signature, errors.New("the signature has no usable public key digest")
	}
	return signature, nil
}

// Verify 用这把公钥验一份清单。
//
// 三件事一起查，顺序不重要但都不能少：签名对不对、清单是不是被签的那一份、公钥是不是
// 本机 pin 的那一把。最后一条看起来多余（验签本来就用这把公钥），但它让**错拿了另一把
// 合法密钥签的清单**报出来的是"这不是这台机器信的那把密钥"，而不是"签名不对"。
func Verify(public ed25519.PublicKey, manifest []byte, signature Signature) error {
	if len(public) != ed25519.PublicKeySize {
		return errors.New("the pinned release key is not an ed25519 public key")
	}
	if signature.PublicKeySHA256 != PublicKeySHA256(public) {
		return fmt.Errorf("the manifest was signed by another release key (%s), not the one this machine pins",
			signature.PublicKeySHA256)
	}
	if got := ManifestSHA256(manifest); got != signature.ManifestSHA256 {
		return fmt.Errorf("the manifest does not match its signature (%s, signed %s)", got, signature.ManifestSHA256)
	}
	raw, err := base64.StdEncoding.DecodeString(signature.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return errors.New("the signature is not an ed25519 signature")
	}
	if !ed25519.Verify(public, signature.signedBytes(), raw) {
		return errors.New("the manifest signature does not verify against the pinned release key")
	}
	return nil
}

// ParsePublicKey 读一份公钥文件（base64，允许尾部换行）。
func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("the release public key is not base64: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the release public key is %d bytes, expected %d", len(decoded), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

// ParsePrivateKey 读一份私钥文件（base64）。它只在离线机器上被读。
func ParsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("the release private key is not base64: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the release private key is %d bytes, expected %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}
