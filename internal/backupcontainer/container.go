// Package backupcontainer 实现平台备份包的容器格式（设计 platform-backup-recovery-2026-09-15 §4.6）。
//
// 一层就是一个 tar，四个成员：
//
//	meta.json      明文元数据
//	key.bin        RSA-OAEP(公钥, 80 字节密钥材料)
//	payload.enc    AES-256-CBC + PKCS#7
//	payload.mac    HMAC-SHA256(meta.json ‖ key.bin ‖ payload.enc)
//
// 之所以是这四个文件而不是某种自定义二进制格式：**灾难当天唯一走的那条路径是
// `tar` + `openssl`**。恢复的人手上只有一台干净机器和两把私钥，不会有我们的代码。
//
// 几条容易写错、写错了又只在灾难当天才暴露的规矩，都在这里用代码钉死：
//
//   - **PKCS#7 填充**。tar 长度永远是 512 的倍数、也就永远是 16 的倍数，`openssl enc`
//     默认加 PKCS#7 而 crypto/cipher 不加。漏了填充，Go 封 Go 解的往返测试照样绿，
//     只有 openssl 那条路会炸——而且不是干净地炸：openssl 报 bad decrypt、退出码 1，
//     但已经写出了一个少 16 字节的文件，`tar xf` 还能读。所以有 TestOpenSSLCanOpen。
//   - **MAC 覆盖 meta.json ‖ key.bin ‖ payload.enc**，顺序固定。只覆盖密文的话，
//     layer / recipient / seq 可以随便改而 MAC 照样通过。
//   - **每一层独立取 80 字节**。跨层复用会让外层的 key.bin（外层那个人能解）里直接
//     躺着内层的 AES 密钥，两把锁当场塌成一把——而往返测试百分百通过。
//   - **不压缩**。内层 tar 里的租户 slug 由服务端下发，和 agent-key、口令在同一个流
//     里，而服务端看得到密文大小。压缩 = 一个现成的 BREACH 式预言机。
//
// MAC 只能证明「没损坏、没被拼接」，**不能证明「没被替换」**：RSA-OAEP 用的是公钥，
// 而公钥不是秘密，任何人都能从零封一个 MAC 通过的包。真实性靠外面那两个锚点——
// 对象 sha256 落库 + 打包机对内层的 Ed25519 签名（§4.3）。
package backupcontainer

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// Format 是容器格式版本号，进 meta.json，也进 MAC 覆盖范围
	Format = 1
	// Alg 是算法串，写进 meta.json 供恢复端核对。它在 MAC 覆盖范围内，
	// 所以将来出现 format 2 时不会成为降级通道
	Alg = "RSA-OAEP-SHA256+AES-256-CBC-PKCS7+HMAC-SHA256"

	// keyMaterialSize 是封进信封的那串字节：32 AES + 32 HMAC + 16 IV。
	// 三样一起封是为了省掉一次 KDF——恢复端不需要 `openssl kdf`，老版本
	// openssl 根本没有那个子命令。80 字节由 crypto/rand 一次取出，均匀独立，
	// Encrypt-then-MAC 要的就是两把独立均匀的键，这里加 KDF 不增加安全性。
	keyMaterialSize = 80
	aesKeySize      = 32
	macKeySize      = 32
	ivSize          = aes.BlockSize

	// minRecipientBits 是收件人公钥的下限。RSA-OAEP-SHA256 在 3072 位下能封
	// 318 字节，80 字节远在范围内
	minRecipientBits = 3072

	metaName    = "meta.json"
	keyName     = "key.bin"
	payloadName = "payload.enc"
	macName     = "payload.mac"
)

// Layer 说明这一层是外层还是内层。它进 meta.json 且在 MAC 覆盖范围内：
// 不带的话，同一个包里封给同一个人、文件名格式都一样的两个内层可以直接对调。
type Layer string

const (
	LayerOuter Layer = "outer"
	LayerInner Layer = "inner"
)

// Meta 是 meta.json 的内容。它是明文的——恢复的人要先看一眼这个包是不是给自己的，
// 才知道该不该去拿私钥。但它在 MAC 覆盖范围内，所以改不了。
type Meta struct {
	Format     int    `json:"format"`
	Layer      Layer  `json:"layer"`
	Seq        uint64 `json:"seq"`
	InstanceID string `json:"instanceId"`
	Alg        string `json:"alg"`
	// Recipient 是收件人公钥的指纹，定义见 Fingerprint
	Recipient string `json:"recipient"`
	CreatedAt string `json:"createdAt"`
}

// Fingerprint 是本方案里 RSA / Ed25519 公钥指纹的唯一定义：
// **DER 编码的 SubjectPublicKeyInfo 的 SHA-256，小写 hex，64 字符，无分隔符。**
//
// 写死它是因为同一把公钥有三种自然写法（DER SPKI / DER PKCS#1 / 直接哈希 PEM
// 文件），三个完全不同的值。而持有人核对指纹是整套方案里唯一那个防「填错、填串」
// 的人工环节，定义含糊等于这个环节永远对不上、或者对上了但对的是别的东西。
//
// 注意**不要**和 buildkeystore.Recipient.Fingerprint() 混——那个算的是打包机
// X25519 公钥的 sha256 截断到 16 字符，是另一把钥匙、另一套算法。
func Fingerprint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SealedSize 返回封完之后 payload.enc 会有多长。
//
// 它存在是因为 tar 头必须先写成员长度，不能边写边算。没有这个函数，实现会撞墙然后
// 退化成「整包进内存」——而备份包有几十 MB，那正是要避免的。CBC+PKCS#7 的密文长度
// 是确定的，所以流式完全可行，只是必须先算好。
func SealedSize(plaintextSize int64) int64 {
	return (plaintextSize/aes.BlockSize + 1) * aes.BlockSize
}

// Seal 把 payload 封成一层，写到 w。
//
// payloadSize 必须是准确值：它决定 tar 头里的长度，写少了 tar 是坏的，写多了同理。
// 调用方拿不准就先落盘再 Stat，不要猜。
func Seal(w io.Writer, recipient *rsa.PublicKey, meta Meta, payload io.Reader, payloadSize int64) error {
	if recipient == nil {
		return errors.New("backupcontainer: recipient is required")
	}
	if bits := recipient.N.BitLen(); bits < minRecipientBits {
		return fmt.Errorf("backupcontainer: recipient key is %d bits, need at least %d", bits, minRecipientBits)
	}
	if payloadSize < 0 {
		return errors.New("backupcontainer: payload size cannot be negative")
	}

	// 每一层独立取一次。绝不复用、绝不从别处传进来——这是 2-of-3 塌成 1-of-1
	// 的唯一静默路径，而它在任何往返测试下都表现正常
	material := make([]byte, keyMaterialSize)
	if _, err := rand.Read(material); err != nil {
		return fmt.Errorf("backupcontainer: draw key material: %w", err)
	}
	aesKey := material[:aesKeySize]
	macKey := material[aesKeySize : aesKeySize+macKeySize]
	iv := material[aesKeySize+macKeySize:]

	fingerprint, err := Fingerprint(recipient)
	if err != nil {
		return err
	}
	meta.Format = Format
	meta.Alg = Alg
	meta.Recipient = fingerprint
	if meta.CreatedAt == "" {
		meta.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("backupcontainer: encode meta: %w", err)
	}

	// MGF1 跟随 OAEP 的 hash：Go 的 EncryptOAEP 两处用同一个 hash，恢复端那条
	// openssl 命令里也显式写了 rsa_mgf1_md:sha256，两边对得上
	envelope, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipient, material, nil)
	if err != nil {
		return fmt.Errorf("backupcontainer: seal key material: %w", err)
	}

	mac := hmac.New(sha256.New, macKey)
	// 顺序就是规范的一部分：恢复端跑的是 `cat meta.json key.bin payload.enc | openssl dgst`
	mac.Write(metaBytes)
	mac.Write(envelope)

	tw := tar.NewWriter(w)
	if err := writeMember(tw, metaName, int64(len(metaBytes)), bytes.NewReader(metaBytes)); err != nil {
		return err
	}
	if err := writeMember(tw, keyName, int64(len(envelope)), bytes.NewReader(envelope)); err != nil {
		return err
	}

	cipherSize := SealedSize(payloadSize)
	if err := writeHeader(tw, payloadName, cipherSize); err != nil {
		return err
	}
	written, err := encryptStream(io.MultiWriter(tw, mac), aesKey, iv, payload, payloadSize)
	if err != nil {
		return err
	}
	if written != cipherSize {
		// 走到这里说明 payloadSize 和实际读到的字节数对不上。tar 头已经写下去了，
		// 这个包是坏的——必须报错，不能让一个长度错误的包安静地上传成功
		return fmt.Errorf("backupcontainer: payload size mismatch: header says %d, wrote %d", cipherSize, written)
	}

	sum := mac.Sum(nil)
	if err := writeMember(tw, macName, int64(len(sum)), bytes.NewReader(sum)); err != nil {
		return err
	}
	return tw.Close()
}

func writeHeader(tw *tar.Writer, name string, size int64) error {
	// 权限给 0600：这一层本身是密文，但解出来之后 umask 松的机器上会是 world-readable。
	// tar 里带上 0600，`tar xf` 就不会把它放宽
	return tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o600,
		Size:     size,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatPAX,
	})
}

func writeMember(tw *tar.Writer, name string, size int64, body io.Reader) error {
	if err := writeHeader(tw, name, size); err != nil {
		return err
	}
	_, err := io.Copy(tw, body)
	return err
}

// encryptStream 流式做 CBC，最后一块补 PKCS#7。返回写出的密文字节数。
func encryptStream(dst io.Writer, key, iv []byte, src io.Reader, plaintextSize int64) (int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, fmt.Errorf("backupcontainer: aes: %w", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	out := make([]byte, chunk)
	var written, read int64
	// tail 攒不满一个分组的余数，和最后的填充一起处理
	tail := make([]byte, 0, aes.BlockSize)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			read += int64(n)
			data := append(tail, buf[:n]...)
			full := len(data) - len(data)%aes.BlockSize
			if full > 0 {
				mode.CryptBlocks(out[:full], data[:full])
				if _, err := dst.Write(out[:full]); err != nil {
					return written, err
				}
				written += int64(full)
			}
			tail = append(tail[:0], data[full:]...)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return written, fmt.Errorf("backupcontainer: read payload: %w", readErr)
		}
	}
	if read != plaintextSize {
		return written, fmt.Errorf("backupcontainer: payload is %d bytes, expected %d", read, plaintextSize)
	}

	// PKCS#7：明文正好对齐时也要补满一整个分组，不能不补。openssl 解密时
	// 无条件剥最后一个分组，少补了就会把真实数据剥掉
	pad := aes.BlockSize - len(tail)
	block7 := append(tail, bytes.Repeat([]byte{byte(pad)}, pad)...)
	last := make([]byte, aes.BlockSize)
	mode.CryptBlocks(last, block7)
	if _, err := dst.Write(last); err != nil {
		return written, err
	}
	return written + aes.BlockSize, nil
}

// Open 解开一层。**只给测试和离线恢复工具用**——服务端从头到尾都开不了自己产出的包。
//
// 整包进内存是有意的：这条路径只在测试和一次性的恢复工具里走，而换来的是
// 「先验完 MAC 再碰解密」这件事在代码上一目了然。
func Open(r io.Reader, key *rsa.PrivateKey) (Meta, []byte, error) {
	members, err := readMembers(r)
	if err != nil {
		return Meta{}, nil, err
	}
	metaBytes, ok := members[metaName]
	if !ok {
		return Meta{}, nil, errors.New("backupcontainer: meta.json is missing")
	}
	envelope, ok := members[keyName]
	if !ok {
		return Meta{}, nil, errors.New("backupcontainer: key.bin is missing")
	}
	ciphertext, ok := members[payloadName]
	if !ok {
		return Meta{}, nil, errors.New("backupcontainer: payload.enc is missing")
	}
	want, ok := members[macName]
	if !ok {
		return Meta{}, nil, errors.New("backupcontainer: payload.mac is missing")
	}

	var meta Meta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return Meta{}, nil, fmt.Errorf("backupcontainer: decode meta: %w", err)
	}

	material, err := rsa.DecryptOAEP(sha256.New(), nil, key, envelope, nil)
	if err != nil {
		// 这一层不是封给这把私钥的，或者包坏了。两种情况对操作者是同一句话：
		// 换一组包试试（2-of-3 的三组里总有一组是你们这两个人的）
		return Meta{}, nil, fmt.Errorf("backupcontainer: this layer is not sealed to that key: %w", err)
	}
	if len(material) != keyMaterialSize {
		return Meta{}, nil, fmt.Errorf("backupcontainer: key material is %d bytes, expected %d", len(material), keyMaterialSize)
	}
	aesKey := material[:aesKeySize]
	macKey := material[aesKeySize : aesKeySize+macKeySize]
	iv := material[aesKeySize+macKeySize:]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(metaBytes)
	mac.Write(envelope)
	mac.Write(ciphertext)
	// 先验 MAC 再解密，顺序不能反：CBC 没有完整性，密文被改一位会解出
	// 「大部分正确、中间一段是垃圾」的内容，而那是会被照着执行的恢复步骤
	if subtle.ConstantTimeCompare(mac.Sum(nil), want) != 1 {
		return Meta{}, nil, errors.New("backupcontainer: integrity check failed; this layer is damaged or was spliced")
	}

	plaintext, err := decrypt(aesKey, iv, ciphertext)
	if err != nil {
		return Meta{}, nil, err
	}
	return meta, plaintext, nil
}

func decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("backupcontainer: ciphertext is %d bytes, not a whole number of blocks", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backupcontainer: aes: %w", err)
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)

	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) {
		return nil, errors.New("backupcontainer: bad PKCS#7 padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("backupcontainer: bad PKCS#7 padding")
		}
	}
	return out[:len(out)-pad], nil
}

func readMembers(r io.Reader) (map[string][]byte, error) {
	members := map[string][]byte{}
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return members, nil
		}
		if err != nil {
			return nil, fmt.Errorf("backupcontainer: read container: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("backupcontainer: read %s: %w", header.Name, err)
		}
		members[header.Name] = body
	}
}
