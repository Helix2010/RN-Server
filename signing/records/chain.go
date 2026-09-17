// Package records 是签名闸的本机记录：两个只追加的 JSONL 文件。
//
//   - trust.jsonl：本机角色、受信构建机、受信签名闸、受信恢复公钥、按 (包名, 证书指纹) 确认过的
//     租户与信任根。由运维在本机执行 signer confirm / trust-builder / trust-peer / trust-recovery /
//     promote 写入；另外两处自动写入：signer enroll 在全新的记录里写初始角色（一律是备）与恢复公钥，
//     签名闸对本机或本机信任的签名闸生成的密钥写自动确认（mode 非空）。
//     新增的记录类型只追加，旧记录（手工流程写的）原样可读。
//   - signed.jsonl：签名的两段式记录（预留 → 完成）、运维释放（abandon）、提升备用时
//     导入的主签名闸记录与人工基线。
//
// 服务端写不到这两个文件，这是它们存在的意义：服务端被攻破时，签名闸仍然按这里的
// 记录决定签给谁、用哪把密钥、包里指向哪个服务端、版本号能不能签。
//
// 每一行：
//
//	{"body":{"v":1,"file":"signed","seq":3,"prev":"<上一行的 sha256>","at":"…","type":"reserve","data":{…}},"sig":"<base64>"}
//
// sig 是本机 Ed25519 私钥对 "rn-signer-record/v1\n" || body 原始字节的签名；prev 是上一行
// 完整字节（不含换行）的 sha256，第一行（genesis）是 64 个 0。genesis 行记下本机公钥。
// 写入后 fsync；启动时从头校验整条链与每行签名，任何一处不对就拒绝启动。
//
// 行必须是规范形式（body 重新序列化后逐字节相同），所以同一条记录只有一种写法，
// 行哈希不存在可塑性。
package records

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
)

const (
	// TrustFileName 与 SignedFileName 是状态目录里的文件名。
	TrustFileName  = "trust.jsonl"
	SignedFileName = "signed.jsonl"

	kindTrust  = "trust"
	kindSigned = "signed"

	recordVersion   = 1
	signaturePrefix = "rn-signer-record/v1\n"
	zeroHash        = "0000000000000000000000000000000000000000000000000000000000000000"

	// MaxFileSize 与 MaxLineSize 限制读入内存的量。一次签名两行、每行几百字节，
	// 256 MiB 足够几十万次签名。
	MaxFileSize = 256 << 20
	MaxLineSize = 64 << 10

	typeGenesis = "genesis"
)

var (
	// ErrCorrupt：记录文件不完整、断链、签名不对或内容不合法。签名闸遇到它必须停下。
	ErrCorrupt = errors.New("records: local record file failed verification")
	// ErrTornTail：最后一行没写完（崩溃或断电）。需要运维查看后处理，签名闸不自动修。
	ErrTornTail = errors.New("records: the last line of a record file is incomplete")
)

type body struct {
	V    int             `json:"v"`
	File string          `json:"file"`
	Seq  uint64          `json:"seq"`
	Prev string          `json:"prev"`
	At   string          `json:"at"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type line struct {
	Body json.RawMessage `json:"body"`
	Sig  string          `json:"sig"`
}

// Genesis 是每个文件的第一行，记下写这个文件的签名闸。
type Genesis struct {
	MachineName            string `json:"machineName"`
	Ed25519PublicKey       string `json:"ed25519PublicKey"`
	Ed25519PublicKeySHA256 string `json:"ed25519PublicKeySha256"`
	X25519PublicKeySHA256  string `json:"x25519PublicKeySha256"`
}

func (g Genesis) validate() (ed25519.PublicKey, error) {
	if !ident.ValidMachineName(g.MachineName) {
		return nil, errors.New("genesis machineName is malformed")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(g.Ed25519PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("genesis ed25519PublicKey is malformed")
	}
	if fingerprint.SHA256Hex(raw) != g.Ed25519PublicKeySHA256 {
		return nil, errors.New("genesis ed25519PublicKeySha256 does not match the key")
	}
	if !fingerprint.Valid(g.X25519PublicKeySHA256) {
		return nil, errors.New("genesis x25519PublicKeySha256 is malformed")
	}
	return ed25519.PublicKey(raw), nil
}

// entry 是校验通过的一行。
type entry struct {
	Seq  uint64
	At   string
	Type string
	Data json.RawMessage
	Hash string
}

// verifier 逐行校验一个文件的内容。
type verifier struct {
	kind    string
	pinned  func(Genesis) error // 校验 genesis 是否属于预期的签名闸
	pub     ed25519.PublicKey
	genesis Genesis
	seq     uint64
	tail    string
}

func newVerifier(kind string, pinned func(Genesis) error) *verifier {
	return &verifier{kind: kind, pinned: pinned, tail: zeroHash}
}

// feed 校验 data（必须由完整的行组成）并逐行回调。返回消费的字节数。
func (v *verifier) feed(data []byte, apply func(entry) error) error {
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		return ErrTornTail
	}
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		raw := data[:i]
		data = data[i+1:]
		e, err := v.verifyLine(raw)
		if err != nil {
			return fmt.Errorf("%w: %s line %d: %v", ErrCorrupt, v.kind, v.seq, err)
		}
		if err := apply(e); err != nil {
			return fmt.Errorf("%w: %s line %d: %v", ErrCorrupt, v.kind, e.Seq, err)
		}
	}
	return nil
}

func (v *verifier) verifyLine(raw []byte) (entry, error) {
	if len(raw) == 0 || len(raw) > MaxLineSize {
		return entry{}, errors.New("empty or over-long line")
	}
	var l line
	if err := strictUnmarshal(raw, &l); err != nil {
		return entry{}, fmt.Errorf("not a record line: %v", err)
	}
	var b body
	if err := strictUnmarshal(l.Body, &b); err != nil {
		return entry{}, fmt.Errorf("record body: %v", err)
	}
	canonicalBody, err := json.Marshal(b)
	if err != nil || !bytes.Equal(canonicalBody, l.Body) {
		return entry{}, errors.New("record body is not in canonical form")
	}
	if !bytes.Equal(assembleLine(l.Body, l.Sig), raw) {
		return entry{}, errors.New("record line is not in canonical form")
	}
	switch {
	case b.V != recordVersion:
		return entry{}, fmt.Errorf("unsupported record version %d", b.V)
	case b.File != v.kind:
		return entry{}, fmt.Errorf("record belongs to %q, not %q", b.File, v.kind)
	case b.Seq != v.seq:
		return entry{}, fmt.Errorf("sequence %d where %d was expected", b.Seq, v.seq)
	case b.Prev != v.tail:
		return entry{}, errors.New("hash chain is broken (prev does not match the previous line)")
	case !ident.ValidRFC3339UTC(b.At):
		return entry{}, errors.New("timestamp is malformed")
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(l.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return entry{}, errors.New("signature is malformed")
	}
	if b.Seq == 0 {
		if b.Type != typeGenesis {
			return entry{}, errors.New("first line is not a genesis record")
		}
		var g Genesis
		if err := strictUnmarshal(b.Data, &g); err != nil {
			return entry{}, fmt.Errorf("genesis: %v", err)
		}
		pub, err := g.validate()
		if err != nil {
			return entry{}, err
		}
		if err := v.pinned(g); err != nil {
			return entry{}, err
		}
		v.pub, v.genesis = pub, g
	} else if b.Type == typeGenesis {
		return entry{}, errors.New("genesis record after the first line")
	}
	if !ed25519.Verify(v.pub, signingInput(l.Body), sig) {
		return entry{}, errors.New("signature does not verify")
	}
	hash := lineHash(raw)
	v.seq++
	v.tail = hash
	return entry{Seq: b.Seq, At: b.At, Type: b.Type, Data: b.Data, Hash: hash}, nil
}

// encodeLine 生成下一行（不含换行）。
func encodeLine(kind string, seq uint64, prev string, at time.Time, typ string, data any, priv ed25519.PrivateKey) ([]byte, error) {
	rawData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	b := body{V: recordVersion, File: kind, Seq: seq, Prev: prev, At: formatTime(at), Type: typ, Data: rawData}
	rawBody, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signingInput(rawBody))
	out := assembleLine(rawBody, base64.StdEncoding.EncodeToString(sig))
	if len(out) > MaxLineSize {
		return nil, errors.New("records: record line would exceed the size limit")
	}
	return out, nil
}

func assembleLine(rawBody []byte, sig string) []byte {
	var buf bytes.Buffer
	buf.WriteString(`{"body":`)
	buf.Write(rawBody)
	buf.WriteString(`,"sig":`)
	quoted, _ := json.Marshal(sig)
	buf.Write(quoted)
	buf.WriteString(`}`)
	return buf.Bytes()
}

func signingInput(rawBody []byte) []byte {
	return append([]byte(signaturePrefix), rawBody...)
}

func lineHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// strictUnmarshal：未知字段、尾随数据、重复顶层对象都拒绝。
func strictUnmarshal(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// readRange 读 [from, to) 的字节。
func readRange(f *os.File, from, to int64) ([]byte, error) {
	if to < from {
		return nil, fmt.Errorf("%w: the file shrank (was %d bytes, now %d)", ErrCorrupt, from, to)
	}
	if to > MaxFileSize {
		return nil, fmt.Errorf("%w: the file is larger than %d bytes", ErrCorrupt, MaxFileSize)
	}
	buf := make([]byte, to-from)
	if _, err := f.ReadAt(buf, from); err != nil && !(errors.Is(err, io.EOF) && len(buf) == 0) {
		return nil, err
	}
	return buf, nil
}

// validText 是运维输入的说明文字（原因、备注）：UTF-8、无控制字符、有长度上限。
func validText(s string, max int) bool {
	if strings.TrimSpace(s) == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return false
		}
	}
	return true
}
