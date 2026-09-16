package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
	"github.com/Helix2010/RN-Server/signing/recovery"
)

// 恢复密钥文件名。
const (
	recoveryPrivateFile = "recovery-private.key"
	recoveryPublicFile  = "recovery-public.json"
)

// scryptN 是生成恢复私钥文件用的 scrypt N。测试改小提速，生产固定 recovery.ScryptN。
var scryptN = recovery.ScryptN

// errNotTTY：口令只从交互终端读。
var errNotTTY = errors.New("口令只能在交互终端里输入（标准输入不是终端）；不要用管道、重定向或脚本传口令")

// passphraseSource 读一次不回显的口令。
type passphraseSource interface {
	ReadPassphrase(prompt string) ([]byte, error)
	Close() error
}

// openPassphraseSource 打开口令输入。测试替换成脚本化的输入。
var openPassphraseSource = func() (passphraseSource, error) { return openTTYPassphrase(os.Stdin) }

// ---- recovery-key create ----

func recoveryKey(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	set := flag.NewFlagSet("recovery-key create", flag.ContinueOnError)
	out := set.String("out", "", "输出目录（不存在就新建 0700）")
	name := set.String("name", "", "恢复密钥名，例如 platform-recovery-2026")
	if err := parseFlags(set, args[1:], stderr); err != nil {
		return report(stderr, err)
	}
	if *out == "" || *name == "" {
		return report(stderr, usageError{msg: "缺少必填参数 --out、--name"})
	}
	if !recovery.ValidName(*name) {
		return report(stderr, errors.New("--name 必须匹配 ^[a-z0-9][a-z0-9-]{1,39}$"))
	}
	privatePath := filepath.Join(*out, recoveryPrivateFile)
	publicPath := filepath.Join(*out, recoveryPublicFile)
	createdDir, err := prepareOutDir(*out, privatePath, publicPath)
	if err != nil {
		return report(stderr, err)
	}
	cleanup := func() {
		if createdDir {
			_ = os.RemoveAll(*out)
		}
	}

	source, err := openPassphraseSource()
	if err != nil {
		cleanup()
		return report(stderr, err)
	}
	passphrase, err := readNewPassphrase(source)
	_ = source.Close()
	if err != nil {
		cleanup()
		return report(stderr, err)
	}
	defer wipe(passphrase)

	pub, priv, err := recovery.Generate(*name, passphrase, now(), scryptN)
	if err != nil {
		cleanup()
		return report(stderr, fmt.Errorf("生成恢复密钥失败: %v", err))
	}
	// 写之前读回核对：口令确实解得开、公钥对得上
	if key, err := priv.Open(passphrase); err != nil || fingerprint.SHA256Hex(key.PublicKey().Bytes()) != pub.X25519PublicKeySHA256 {
		cleanup()
		return report(stderr, errors.New("生成的恢复私钥没有通过读回核对，什么都没写"))
	}
	privRaw, err := recovery.Encode(priv)
	if err != nil {
		cleanup()
		return report(stderr, err)
	}
	pubRaw, err := recovery.Encode(pub)
	if err != nil {
		cleanup()
		return report(stderr, err)
	}
	if err := writeExclusiveMode(privatePath, privRaw, 0o600); err != nil {
		cleanup()
		return report(stderr, fmt.Errorf("写 %s 失败: %v", privatePath, err))
	}
	if err := writeExclusiveMode(publicPath, pubRaw, 0o644); err != nil {
		_ = os.Remove(privatePath)
		cleanup()
		return report(stderr, fmt.Errorf("写 %s 失败: %v", publicPath, err))
	}
	if err := syncDir(*out); err != nil {
		return report(stderr, fmt.Errorf("落盘 %s 失败: %v", *out, err))
	}
	fmt.Fprintf(stdout, `
================ 恢复密钥已生成 ================
名字:                %s
恢复公钥 SHA-256:    %s

  私钥文件（口令加密，0600）: %s
  公钥文件:                   %s

接下来:
  1. 把上面的「恢复公钥 SHA-256」完整记进密码管理器，和口令放在一起。口令不会显示在屏幕上。
  2. 把 %s 拷进两个离线 U 盘（与 STORAGE_MASTER_KEY 的加密包放在一起），核对后擦除这台机器上的副本。
  3. 在控制台「平台维护 → 签名闸恢复密钥」粘贴 %s 的内容。
  4. 新装签名闸的安装命令带 --recovery-sha256 <上面的 SHA-256>（从密码管理器粘贴，不取控制台显示的值）；
     已经在运行的签名闸在本机执行 signer trust-recovery 并粘贴它。
`, pub.Name, pub.X25519PublicKeySHA256, privatePath, publicPath, recoveryPrivateFile, recoveryPublicFile)
	return 0
}

// prepareOutDir：目录不存在就新建 0700（返回 true，失败时由调用方整个删掉）；已存在就必须是目录，
// 且两个输出文件都不存在。
func prepareOutDir(dir string, files ...string) (bool, error) {
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil {
			return false, fmt.Errorf("创建 %s 失败: %v", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return false, fmt.Errorf("设置 %s 权限失败: %v", dir, err)
		}
		return true, nil
	case err != nil:
		return false, fmt.Errorf("检查 %s 失败: %v", dir, err)
	case !info.IsDir():
		return false, fmt.Errorf("%s 不是目录", dir)
	}
	for _, f := range files {
		if _, err := os.Lstat(f); err == nil {
			return false, fmt.Errorf("%s 已经存在。不覆盖已有的恢复密钥", f)
		}
	}
	return false, nil
}

func readNewPassphrase(source passphraseSource) ([]byte, error) {
	first, err := source.ReadPassphrase(fmt.Sprintf("为恢复私钥设一个口令（%d–%d 字节，输入不回显）: ", recovery.MinPassphraseLength, recovery.MaxPassphraseLength))
	if err != nil {
		return nil, err
	}
	if err := recovery.ValidatePassphrase(first); err != nil {
		wipe(first)
		return nil, err
	}
	second, err := source.ReadPassphrase("再输入一遍: ")
	if err != nil {
		wipe(first)
		return nil, err
	}
	defer wipe(second)
	if !bytes.Equal(first, second) {
		wipe(first)
		return nil, errors.New("两次输入的口令不一致，什么都没写")
	}
	return first, nil
}

// ---- recover ----

func recoverKeystore(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("recover", flag.ContinueOnError)
	keyPath := set.String("recovery-key", "", "恢复私钥文件 recovery-private.key")
	uploadPath := set.String("upload", "", "控制台导出的密文文件")
	outDir := set.String("out-dir", "", "原件目录，必须不存在")
	if err := parseFlags(set, args, stderr); err != nil {
		return report(stderr, err)
	}
	if *keyPath == "" || *uploadPath == "" || *outDir == "" {
		return report(stderr, usageError{msg: "缺少必填参数 --recovery-key、--upload、--out-dir"})
	}
	keyRaw, err := readLimited(*keyPath, recovery.MaxFileSize)
	if err != nil {
		return report(stderr, fmt.Errorf("读恢复私钥文件失败: %v", err))
	}
	privFile, err := recovery.ParsePrivate(keyRaw)
	if err != nil {
		return report(stderr, fmt.Errorf("恢复私钥文件不合格: %v", err))
	}
	uploadRaw, err := readLimited(*uploadPath, keystorebox.MaxUploadSize)
	if err != nil {
		return report(stderr, fmt.Errorf("读密文文件失败: %v", err))
	}
	upload, err := keystorebox.ParseUpload(uploadRaw)
	if err != nil {
		return report(stderr, fmt.Errorf("密文文件不合格: %v", err))
	}
	box, ok := upload.BoxFor(privFile.X25519PublicKeySHA256)
	if !ok {
		var recipients []string
		for _, b := range upload.Boxes {
			recipients = append(recipients, b.RecipientSHA256)
		}
		return report(stderr, fmt.Errorf("这份密文没有加密给恢复密钥 %s（%s）。密文的收件人: %s",
			privFile.Name, privFile.X25519PublicKeySHA256, strings.Join(recipients, ", ")))
	}
	if _, err := os.Lstat(*outDir); err == nil {
		return report(stderr, fmt.Errorf("%s 已经存在。原件目录必须是新的", *outDir))
	} else if !errors.Is(err, os.ErrNotExist) {
		return report(stderr, fmt.Errorf("检查 %s 失败: %v", *outDir, err))
	}

	source, err := openPassphraseSource()
	if err != nil {
		return report(stderr, err)
	}
	passphrase, err := source.ReadPassphrase(fmt.Sprintf("恢复密钥 %s 的口令（输入不回显）: ", privFile.Name))
	_ = source.Close()
	if err != nil {
		return report(stderr, err)
	}
	key, err := privFile.Open(passphrase)
	wipe(passphrase)
	switch {
	case errors.Is(err, recovery.ErrWrongPassphrase):
		return report(stderr, errors.New("解不开恢复私钥：口令不对，或者私钥文件被改过"))
	case err != nil:
		return report(stderr, err)
	}
	keyBytes := key.Bytes()
	plain, err := keystorebox.Open(box, keyBytes)
	wipe(keyBytes)
	if err != nil {
		return report(stderr, fmt.Errorf("解不开发给恢复密钥的那份密文: %v", err))
	}
	if plain.TenantSlug != upload.TenantSlug || plain.PackageName != upload.PackageName || plain.KeyAlias != upload.KeyAlias ||
		plain.CertificateSHA256 != upload.CertificateSHA256 || plain.CreatedAt != upload.CreatedAt {
		return report(stderr, errors.New("密文里绑定的租户、包名、别名、证书或时间与密文文件的外层字段不一致，不导出"))
	}
	if plain.StorePassword != plain.KeyPassword {
		return report(stderr, errors.New("原件的仓库口令与私钥口令不同，PKCS#12 不支持，不导出"))
	}
	p12, err := plain.P12()
	if err != nil {
		return report(stderr, errors.New("解开的内容里没有可用的 PKCS#12 原件"))
	}
	entry, err := pkcs12.FindKey(p12, plain.StorePassword, plain.KeyAlias)
	if err != nil {
		return report(stderr, fmt.Errorf("解开的 PKCS#12 原件用它的口令与别名打不开: %v", err))
	}
	certSHA := pkcs12.CertificateSHA256(entry)
	if certSHA != upload.CertificateSHA256 {
		return report(stderr, fmt.Errorf("原件里的证书 SHA-256 是 %s，与密文文件记录的 %s 不一致，不导出", certSHA, upload.CertificateSHA256))
	}
	if !ident.ValidKeyAlias(entry.Alias) {
		return report(stderr, errors.New("原件里的别名不合格"))
	}

	if err := os.Mkdir(*outDir, 0o700); err != nil {
		return report(stderr, fmt.Errorf("创建原件目录失败: %v", err))
	}
	if err := os.Chmod(*outDir, 0o700); err != nil {
		_ = os.RemoveAll(*outDir)
		return report(stderr, fmt.Errorf("设置原件目录权限失败: %v", err))
	}
	files := struct{ p12, password, cert string }{
		p12:      filepath.Join(*outDir, plain.KeyAlias+".p12"),
		password: filepath.Join(*outDir, plain.KeyAlias+".password"),
		cert:     filepath.Join(*outDir, "certificate.pem"),
	}
	for _, w := range []struct {
		path string
		data []byte
	}{
		{files.p12, p12},
		{files.password, []byte(plain.StorePassword + "\n")},
		{files.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entry.Certificate.Raw})},
	} {
		if err := writeExclusive(w.path, w.data); err != nil {
			_ = os.RemoveAll(*outDir)
			return report(stderr, fmt.Errorf("写 %s 失败，已删除不完整的原件目录: %v", w.path, err))
		}
	}
	if err := syncDir(*outDir); err != nil {
		return report(stderr, fmt.Errorf("落盘 %s 失败: %v", *outDir, err))
	}
	fmt.Fprintf(stdout, `
================ 已从恢复密钥解出原件 ================
租户:          %s
包名:          %s
别名:          %s
证书 SHA-256:  %s （与密文文件一致）
生成时间:      %s
密文收件人:    %d 个

产出（目录 0700，文件 0600）:
  原件:          %s
  口令文件:      %s （口令不会显示在屏幕上）
  证书:          %s

接下来:
  1. 核对上面的证书 SHA-256 与密码管理器里记的一致。
  2. 用 build-keystore seal --pins <新的 pin 文件> --p12 %s --password-file %s --tenant %s --package %s
     重新加密给新的签名闸，在控制台「导入已有密钥（高级）」上传，并在每台签名闸上 signer confirm。
  3. 用完按「原件与配置机密的保管」处理本目录，擦除这台机器上的明文副本。
`, plain.TenantSlug, plain.PackageName, plain.KeyAlias, certSHA, plain.CreatedAt, len(plain.Recipients),
		files.p12, files.password, files.cert, files.p12, files.password, plain.TenantSlug, plain.PackageName)
	return 0
}

// writeExclusiveMode 新建文件（已存在就失败），写完 fsync。
func writeExclusiveMode(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
