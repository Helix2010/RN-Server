// Package backupbundle 把打包机产出的内层密文和服务端自己那部分组装成三组备份包
// （设计 platform-backup-recovery-2026-09-15 §4.1、§4.5）。
//
// 门限是 2-of-3：三个人两两配对成三组，每组一个包，包里套两层锁——外层封给这一组
// 的一个人，内层封给另一个。任意两个人凑齐就能开，一个人单独什么都读不到。
//
// 这个包**不碰数据库、不碰对象存储、不碰网络**。它是整条链路上最值得测透的一段：
// 组装错了的后果要到灾难当天才暴露，而那时没有第二次机会。
package backupbundle

import (
	"archive/tar"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// InnerPart 是一份已经封好的内层密文，连同它的签名和产出它的那一方报上来的清单。
type InnerPart struct {
	// Slot 是这份密文封给了哪个槽位
	Slot string
	// Sealed 是内层容器的完整字节（backupcontainer.Seal 的产物）
	Sealed []byte
	// Signature 是打包机对 Sealed 的 Ed25519 签名。服务端不验也验不了别人的，
	// 但它必须原样放进包里——恢复的人靠它判断这个包是不是我们那台机器产出的
	Signature []byte
}

// FileEntry 是恢复说明里「这个文件放到哪、什么权限、属主是谁」那一行。
// 内层清单原样上来（打包机侧），服务端自己那部分由服务端填。
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Target string `json:"target"`
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
}

// Tenant 进外层 manifest 和 RECOVERY.md 的租户清单。
type Tenant struct {
	Slug         string `json:"slug"`
	Domain       string `json:"domain"`
	HasKeystore  bool   `json:"hasKeystore"`
	SignerSHA256 string `json:"signerSha256,omitempty"`
}

// Recipient 是一个槽位上的恢复公钥。
type Recipient struct {
	Slot        string         `json:"slot"`
	Fingerprint string         `json:"fingerprint"`
	Key         *rsa.PublicKey `json:"-"`
	// Holder 是「由谁保管」，运维在控制台上填的那一行。印进 README-FIRST.txt，
	// 让拿到包的人知道该去找谁
	Holder string `json:"holder,omitempty"`
}

// Input 是组装一次备份需要的全部东西。
type Input struct {
	Seq        uint64
	InstanceID string
	CreatedAt  time.Time

	// Recipients 按槽位顺序，三把齐全（没有降级模式，§2.1）
	Recipients []Recipient

	// AgentInner 是打包机封好的两份内层密文，按槽位索引
	AgentInner map[string]InnerPart
	// ServerFiles 是服务端那部分的明文内容：路径 → 内容。
	// 它会被封成 server.rnbk，同样一份封两次（给 A 和给 B）
	ServerFiles map[string][]byte
	// ServerManifest 描述 ServerFiles 每个文件该放到哪
	ServerManifest []FileEntry
	// AgentManifest 是打包机报上来的内层清单，进 RECOVERY.md
	AgentManifest []FileEntry

	Tenants                  []Tenant
	ServerVersion            string
	AgentVersion             string
	SchemaVersion            int
	AgentKeyFingerprint      string
	BackupSigningFingerprint string
	// BackupSigningPublicKey 是备份签名公钥的 DER SubjectPublicKeyInfo。
	//
	// 它要跟着包走：灾难当天控制台多半也起不来，从库里取公钥这条路是断的。
	// 放在包里安全的前提是**锚点在纸上不在包里**——recover.sh 把持有人抄的那
	// 64 位指纹当参数收进来，先比指纹再验签。攻击者能换掉包里的公钥和 README
	// 上印的指纹，换不掉三个人纸上的那一行。
	BackupSigningPublicKey []byte
}

// Package 是产出的一组包。
type Package struct {
	Pair string
	// ObjectKey 由调用方按 InstanceID/Seq/Pair 拼；这里只给出建议的后缀
	SHA256 string
	Size   int64
	// ReadmeFirst 是并排放在桶里的那份不加密说明（§5.1）
	ReadmeFirst string
}

// Sink 给每一组包一个写入位置。服务端实现成临时文件，测试实现成内存缓冲。
//
// 用回调而不是返回 [][]byte：三个包各几十 MB，全堆在内存里是没必要的，
// 而且流式写下去正好对上「先算长度再开始写」那条约束。
type Sink interface {
	// Writer 返回写这一组包的位置。调用方负责 Close。
	Writer(pair string) (io.WriteCloser, error)
}

// outerManifest 是外层 manifest.json（§4.5）。
type outerManifest struct {
	Format                   int         `json:"format"`
	Seq                      uint64      `json:"seq"`
	Pair                     string      `json:"pair"`
	InstanceID               string      `json:"instanceId"`
	CreatedAt                string      `json:"createdAt"`
	ServerVersion            string      `json:"serverVersion"`
	AgentVersion             string      `json:"agentVersion"`
	SchemaVersion            int         `json:"schemaVersion"`
	AgentKeyFingerprint      string      `json:"agentKeyFingerprint"`
	BackupSigningFingerprint string      `json:"backupSigningFingerprint"`
	Tenants                  []Tenant    `json:"tenants"`
	Recipients               []Recipient `json:"recipients"`
	// Files 覆盖外层成员（manifest.json 自身除外）。
	// **inner.rnbk / inner.rnbk.sig / server.rnbk 必须在内**——不覆盖的话，
	// 攻击者可以把一个旧备份的 inner.rnbk 塞进新包、manifest 原样不动、重封外层，
	// 两层 MAC 全绿、两把私钥都用上了，恢复出来的却是轮换前的旧密钥，或者
	// agent-key 和库里的盒子对不上、全部租户的签名密钥永久打不开
	Files []FileEntry `json:"files"`
}

// innerManifest 是内层自己那份清单。
//
// 分层是有理由的：**机密文件的哈希不得出现在外层**。系统生成的 keystore 口令是
// 128 位随机值爆不动，但上传通道收的是管理员自带 .p12 的口令，可以是人选的弱口令
// ——它的 sha256 一旦出现在只需要一把钥匙就能读到的外层，就是一次离线爆破。
type innerManifest struct {
	Format    int         `json:"format"`
	Side      string      `json:"side"`
	CreatedAt string      `json:"createdAt"`
	Files     []FileEntry `json:"files"`
}

const (
	nameManifest   = "manifest.json"
	nameRecovery   = "RECOVERY.md"
	nameRecoverSh  = "recover.sh"
	nameInner      = "inner.rnbk"
	nameInnerSig   = "inner.rnbk.sig"
	nameServer     = "server.rnbk"
	nameSigningKey = "signing.der"
)

// Assemble 产出三组包，写进 sink。
func Assemble(in Input, sink Sink) ([]Package, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	byslot := map[string]Recipient{}
	for _, r := range in.Recipients {
		byslot[r.Slot] = r
	}

	// 服务端那部分也封给**内层**那个槽位，不是只封给开外层的人。
	// 否则只拿到外层那把私钥就能读到 rn-foundation.env 里的 STORAGE_MASTER_KEY，
	// 这一组的两把锁就只剩一把
	serverInner := map[string][]byte{}
	for _, slot := range backupcontainer.InnerSlots() {
		recipient, ok := byslot[slot]
		if !ok {
			return nil, fmt.Errorf("backupbundle: no recovery key configured for slot %s", slot)
		}
		sealed, err := sealServerPart(in, recipient)
		if err != nil {
			return nil, err
		}
		serverInner[slot] = sealed
	}

	out := make([]Package, 0, len(backupcontainer.Pairs()))
	for _, pair := range backupcontainer.Pairs() {
		inner, ok := in.AgentInner[pair.Inner]
		if !ok {
			return nil, fmt.Errorf("backupbundle: the build agent did not report an inner payload for slot %s", pair.Inner)
		}
		outerRecipient, ok := byslot[pair.Outer]
		if !ok {
			return nil, fmt.Errorf("backupbundle: no recovery key configured for slot %s", pair.Outer)
		}

		payload, err := buildOuterPayload(in, pair, inner, serverInner[pair.Inner])
		if err != nil {
			return nil, err
		}

		writer, err := sink.Writer(pair.Name)
		if err != nil {
			return nil, fmt.Errorf("backupbundle: open sink for %s: %w", pair.Name, err)
		}
		digest := sha256.New()
		counter := &countingWriter{}
		meta := backupcontainer.Meta{
			Layer:      backupcontainer.LayerOuter,
			Seq:        in.Seq,
			InstanceID: in.InstanceID,
			CreatedAt:  in.CreatedAt.UTC().Format(time.RFC3339),
		}
		sealErr := backupcontainer.Seal(io.MultiWriter(writer, digest, counter), outerRecipient.Key,
			meta, bytes.NewReader(payload), int64(len(payload)))
		closeErr := writer.Close()
		if sealErr != nil {
			return nil, fmt.Errorf("backupbundle: seal %s: %w", pair.Name, sealErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("backupbundle: finish %s: %w", pair.Name, closeErr)
		}
		sum := hex.EncodeToString(digest.Sum(nil))
		out = append(out, Package{
			Pair:        pair.Name,
			SHA256:      sum,
			Size:        counter.n,
			ReadmeFirst: renderReadmeFirst(in, pair, byslot, sum),
		})
	}
	return out, nil
}

func (in Input) validate() error {
	if in.Seq == 0 {
		return fmt.Errorf("backupbundle: seq is required")
	}
	if in.InstanceID == "" {
		return fmt.Errorf("backupbundle: instanceId is required")
	}
	if len(in.Recipients) != backupcontainer.SlotCount {
		return fmt.Errorf("backupbundle: the threshold is 2-of-%d and there is no reduced mode; got %d recovery keys",
			backupcontainer.SlotCount, len(in.Recipients))
	}
	seen := map[string]bool{}
	for _, r := range in.Recipients {
		if r.Key == nil {
			return fmt.Errorf("backupbundle: slot %s has no key", r.Slot)
		}
		if seen[r.Fingerprint] {
			return fmt.Errorf("backupbundle: two slots share fingerprint %s; one person could open a package alone",
				r.Fingerprint)
		}
		seen[r.Fingerprint] = true
	}
	// 没有公钥，包里的签名就只是一串没人能验的字节，而验签是两个真实性锚点之一
	if len(in.BackupSigningPublicKey) == 0 {
		return fmt.Errorf("backupbundle: the backup signing public key is missing; " +
			"without it nobody can verify the signature that comes with this package")
	}
	for _, slot := range backupcontainer.InnerSlots() {
		part, ok := in.AgentInner[slot]
		if !ok || len(part.Sealed) == 0 {
			return fmt.Errorf("backupbundle: the build agent did not report an inner payload for slot %s", slot)
		}
		if len(part.Signature) == 0 {
			return fmt.Errorf("backupbundle: the inner payload for slot %s has no signature; "+
				"without it nobody can tell whether this package came from our build machine", slot)
		}
	}
	if len(in.Tenants) == 0 {
		return fmt.Errorf("backupbundle: no tenants; a backup with nothing in it is not worth keeping")
	}
	return nil
}

func sealServerPart(in Input, recipient Recipient) ([]byte, error) {
	manifest := innerManifest{
		Format:    backupcontainer.Format,
		Side:      "server",
		CreatedAt: in.CreatedAt.UTC().Format(time.RFC3339),
		Files:     in.ServerManifest,
	}
	files := map[string][]byte{}
	for path, body := range in.ServerFiles {
		files[path] = body
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	files[nameManifest] = encoded

	plain, err := TarFiles(files)
	if err != nil {
		return nil, fmt.Errorf("backupbundle: pack the server part: %w", err)
	}
	var sealed bytes.Buffer
	meta := backupcontainer.Meta{
		Layer:      backupcontainer.LayerInner,
		Seq:        in.Seq,
		InstanceID: in.InstanceID,
		CreatedAt:  in.CreatedAt.UTC().Format(time.RFC3339),
	}
	if err := backupcontainer.Seal(&sealed, recipient.Key, meta, bytes.NewReader(plain), int64(len(plain))); err != nil {
		return nil, fmt.Errorf("backupbundle: seal the server part for slot %s: %w", recipient.Slot, err)
	}
	return sealed.Bytes(), nil
}

func buildOuterPayload(in Input, pair backupcontainer.Pair, inner InnerPart, serverPart []byte) ([]byte, error) {
	members := map[string][]byte{
		nameInner:      inner.Sealed,
		nameInnerSig:   inner.Signature,
		nameServer:     serverPart,
		nameSigningKey: in.BackupSigningPublicKey,
	}
	// files[] 覆盖除 manifest.json 自身之外的每一个外层成员，
	// 三个密文成员一个都不能漏——这一条是防拼接的
	files := []FileEntry{}
	for _, name := range []string{nameInner, nameInnerSig, nameServer, nameSigningKey} {
		files = append(files, FileEntry{
			Path:   name,
			Size:   int64(len(members[name])),
			SHA256: sha256Hex(members[name]),
		})
	}

	recovery := renderRecoveryMarkdown(in, pair)
	// 这四个成员的摘要要印进脚本里，脚本才能自己核对解包解全了没有。
	// 必须在这里取：下面两行一加，files 里就多了 recover.sh 自己
	digests := map[string]string{}
	for _, f := range files {
		digests[f.Path] = f.SHA256
	}
	script := renderRecoverScript(in, pair, digests)
	members[nameRecovery] = []byte(recovery)
	members[nameRecoverSh] = []byte(script)
	files = append(files,
		FileEntry{Path: nameRecovery, Size: int64(len(recovery)), SHA256: sha256Hex([]byte(recovery))},
		FileEntry{Path: nameRecoverSh, Size: int64(len(script)), SHA256: sha256Hex([]byte(script))})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	manifest := outerManifest{
		Format:                   backupcontainer.Format,
		Seq:                      in.Seq,
		Pair:                     pair.Name,
		InstanceID:               in.InstanceID,
		CreatedAt:                in.CreatedAt.UTC().Format(time.RFC3339),
		ServerVersion:            in.ServerVersion,
		AgentVersion:             in.AgentVersion,
		SchemaVersion:            in.SchemaVersion,
		AgentKeyFingerprint:      in.AgentKeyFingerprint,
		BackupSigningFingerprint: in.BackupSigningFingerprint,
		Tenants:                  in.Tenants,
		Recipients:               in.Recipients,
		Files:                    files,
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	members[nameManifest] = encoded
	return TarFiles(members)
}

// TarFiles 按名字排序打一个 tar。排序是为了**同样的输入产出同样的字节**——
// 没有它，两次备份的差异里会混进 map 遍历顺序，而「包体相对上次有没有异常跌落」
// 那条自检就没法用了。
//
// 导出是因为内层（打包机封的）和外层（服务端封的）必须是同一种布局：
// 恢复脚本对两层用的是同一条 `tar xf`，各写各的迟早会漂。
func TarFiles(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, name := range names {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)),
			Typeflag: tar.TypeReg, Format: tar.FormatPAX,
			// 时间戳固定成零值，同样是为了可复现
			ModTime: time.Unix(0, 0).UTC(),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	return len(p), nil
}
