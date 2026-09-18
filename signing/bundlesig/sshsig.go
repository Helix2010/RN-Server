package bundlesig

// 这个文件是 OpenSSH 的 sshsig 线格式（PROTOCOL.sshsig）的编解码，**只有序列化，没有曲线
// 运算**——签名与验签仍然走标准库的 crypto/ed25519。
//
// 为什么用这个格式而不是裸 ed25519 签名：Mac 装机脚本要在**下载安装包之前**验这份签名，
// 那时机器上除了脚本自己没有任何可信的东西。用 sshsig 的话，验签那一步就是系统自带的
//
//	ssh-keygen -Y verify -f <allowed_signers> -I release-key -n rn-machine-bundles -s <sig>
//
// 脚本里因此一行密码学都不用写。换成别的格式就得在 shell 里自带一个 ed25519 实现，而那段
// 代码没人能一眼看懂——这条链子的第一环靠的正是"运维能读完他要跑的东西"。
//
// 换格式没有动密钥：私钥文件、公钥字节、指纹口径（sha256(公钥 32 字节)）全都没变。

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Namespace 把这些签名与"同一把密钥在别处签的东西"隔开。它必须由验签一侧**写死**，
// 不能从签名文件里读：能自己填 namespace 的验签方等于没有 namespace。
const Namespace = "rn-machine-bundles"

// keyAlgo 是唯一允许的算法。发布密钥是 ed25519，别的一律不认。
const keyAlgo = "ssh-ed25519"

const (
	sshsigMagic   = "SSHSIG"
	sshsigVersion = 1
	sshsigHash    = "sha512"
	armorBegin    = "-----BEGIN SSH SIGNATURE-----"
	armorEnd      = "-----END SSH SIGNATURE-----"
	armorWidth    = 70
)

// sshString 是 SSH 线格式里的 string：4 字节大端长度 + 字节。
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// readSSHString 从 b 里取一个 string，返回它与剩下的部分。
func readSSHString(b []byte) (value, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errors.New("truncated ssh string")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errors.New("ssh string runs past the end of the buffer")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// sshPublicKeyBlob 是 ed25519 公钥的 SSH 线格式：string "ssh-ed25519" + string 32 字节。
func sshPublicKeyBlob(public ed25519.PublicKey) []byte {
	return append(sshString([]byte(keyAlgo)), sshString(public)...)
}

// SSHPublicKeyLine 是写进 release-key.pub 的那一行，与 allowed_signers 里的公钥同格式。
func SSHPublicKeyLine(public ed25519.PublicKey, comment string) string {
	line := keyAlgo + " " + base64.StdEncoding.EncodeToString(sshPublicKeyBlob(public))
	if comment != "" {
		line += " " + comment
	}
	return line
}

// parseSSHPublicKeyBlob 解 SSH 线格式的公钥，要求整个 blob 被恰好用完：多出来的字节说明
// 这不是一把干净的 ed25519 公钥，宁可拒了。
func parseSSHPublicKeyBlob(blob []byte) (ed25519.PublicKey, error) {
	algo, rest, err := readSSHString(blob)
	if err != nil {
		return nil, fmt.Errorf("the release public key is malformed: %w", err)
	}
	if string(algo) != keyAlgo {
		return nil, fmt.Errorf("the release public key is %q, expected %s", string(algo), keyAlgo)
	}
	key, rest, err := readSSHString(rest)
	if err != nil {
		return nil, fmt.Errorf("the release public key is malformed: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the release public key is %d bytes, expected %d", len(key), ed25519.PublicKeySize)
	}
	if len(rest) != 0 {
		return nil, errors.New("the release public key has trailing bytes")
	}
	return ed25519.PublicKey(key), nil
}

// sshsigSignedData 是真正被签的字节：magic + namespace + 保留字段 + 哈希算法 + H(消息)。
// namespace 进签名，所以换个用途的同一把密钥签出来的东西在这里验不过。
func sshsigSignedData(namespace string, message []byte) []byte {
	sum := sha512.Sum512(message)
	out := []byte(sshsigMagic)
	out = append(out, sshString([]byte(namespace))...)
	out = append(out, sshString(nil)...)
	out = append(out, sshString([]byte(sshsigHash))...)
	return append(out, sshString(sum[:])...)
}

// armor 按 OpenSSH 的写法把 blob 包起来：70 列一行。
func armor(blob []byte) string {
	encoded := base64.StdEncoding.EncodeToString(blob)
	var out strings.Builder
	out.WriteString(armorBegin)
	out.WriteByte('\n')
	for len(encoded) > armorWidth {
		out.WriteString(encoded[:armorWidth])
		out.WriteByte('\n')
		encoded = encoded[armorWidth:]
	}
	out.WriteString(encoded)
	out.WriteByte('\n')
	out.WriteString(armorEnd)
	out.WriteByte('\n')
	return out.String()
}

// dearmor 把装甲块解回 blob。行宽不做要求（OpenSSH 自己也只按 base64 解）。
func dearmor(text string) ([]byte, error) {
	trimmed := strings.TrimSpace(text)
	if !strings.HasPrefix(trimmed, armorBegin) || !strings.HasSuffix(trimmed, armorEnd) {
		return nil, errors.New("the signature is not an armoured SSH signature")
	}
	body := strings.TrimSuffix(strings.TrimPrefix(trimmed, armorBegin), armorEnd)
	var packed strings.Builder
	for _, field := range strings.Fields(body) {
		packed.WriteString(field)
	}
	blob, err := base64.StdEncoding.DecodeString(packed.String())
	if err != nil {
		return nil, errors.New("the signature body is not base64")
	}
	return blob, nil
}

// signSSHSig 用发布私钥签一段消息，产出与 ssh-keygen -Y sign 逐字节可互换的装甲块。
func signSSHSig(private ed25519.PrivateKey, namespace string, message []byte) string {
	public, _ := private.Public().(ed25519.PublicKey)
	raw := ed25519.Sign(private, sshsigSignedData(namespace, message))
	signature := append(sshString([]byte(keyAlgo)), sshString(raw)...)

	blob := []byte(sshsigMagic)
	blob = binary.BigEndian.AppendUint32(blob, sshsigVersion)
	blob = append(blob, sshString(sshPublicKeyBlob(public))...)
	blob = append(blob, sshString([]byte(namespace))...)
	blob = append(blob, sshString(nil)...)
	blob = append(blob, sshString([]byte(sshsigHash))...)
	blob = append(blob, sshString(signature)...)
	return armor(blob)
}

// verifySSHSig 验一个装甲块。
//
// 五件事都要对上，少一件就有一条绕过去的路：版本、装甲块里自报的公钥与 pin 的那把是同一
// 把、namespace 是本项目的、哈希算法是 sha512、签名本身。其中"自报的公钥"那一条尤其不能
// 省——装甲块里带着公钥，只按它验等于让签名自己决定谁签的。
func verifySSHSig(public ed25519.PublicKey, namespace string, message []byte, armored string) error {
	blob, err := dearmor(armored)
	if err != nil {
		return err
	}
	if len(blob) < len(sshsigMagic)+4 || string(blob[:len(sshsigMagic)]) != sshsigMagic {
		return errors.New("the signature has no SSHSIG preamble")
	}
	rest := blob[len(sshsigMagic):]
	if version := binary.BigEndian.Uint32(rest); version != sshsigVersion {
		return fmt.Errorf("the signature is SSHSIG version %d, expected %d", version, sshsigVersion)
	}
	rest = rest[4:]

	keyBlob, rest, err := readSSHString(rest)
	if err != nil {
		return errors.New("the signature is malformed")
	}
	signer, err := parseSSHPublicKeyBlob(keyBlob)
	if err != nil {
		return fmt.Errorf("the signature carries an unusable public key: %w", err)
	}
	if !signer.Equal(public) {
		return errors.New("the signature was made by another release key, not the one this machine pins")
	}
	gotNamespace, rest, err := readSSHString(rest)
	if err != nil {
		return errors.New("the signature is malformed")
	}
	if string(gotNamespace) != namespace {
		return fmt.Errorf("the signature was made for namespace %q, not %q", string(gotNamespace), namespace)
	}
	if _, rest, err = readSSHString(rest); err != nil { // 保留字段，内容不管
		return errors.New("the signature is malformed")
	}
	hash, rest, err := readSSHString(rest)
	if err != nil {
		return errors.New("the signature is malformed")
	}
	if string(hash) != sshsigHash {
		return fmt.Errorf("the signature hashes with %q, expected %s", string(hash), sshsigHash)
	}
	inner, rest, err := readSSHString(rest)
	if err != nil {
		return errors.New("the signature is malformed")
	}
	if len(rest) != 0 {
		return errors.New("the signature has trailing bytes")
	}
	algo, inner, err := readSSHString(inner)
	if err != nil || string(algo) != keyAlgo {
		return fmt.Errorf("the signature algorithm is not %s", keyAlgo)
	}
	raw, inner, err := readSSHString(inner)
	if err != nil || len(inner) != 0 || len(raw) != ed25519.SignatureSize {
		return errors.New("the signature is not an ed25519 signature")
	}
	if !ed25519.Verify(public, sshsigSignedData(namespace, message), raw) {
		return errors.New("the manifest signature does not verify against the pinned release key")
	}
	return nil
}

// SignerIdentity 是 allowed_signers 里的标识，与 ssh-keygen -Y verify -I 的参数一致。
const SignerIdentity = "release-key"

// AllowedSignersLine 是装机脚本喂给 ssh-keygen -Y verify 的那一行。标识写死成常量：
// 这份名单是脚本当场拿验过指纹的公钥现生成的，只有一个签名人。
func AllowedSignersLine(public ed25519.PublicKey) string {
	return SignerIdentity + " " + SSHPublicKeyLine(public, "")
}
