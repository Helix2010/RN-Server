// build-keystore 是签名密钥的离线工具，只在不联网的离线机器上运行。
//
//	build-keystore create --pins <pin 文件> --tenant <slug> --package <包名> --alias <别名> [--out-dir <目录>]
//	build-keystore seal   --pins <pin 文件> --p12 <原件> --password-file <口令文件> --tenant <slug> --package <包名> [--alias <别名>] [--out <文件>]
//	build-keystore recovery-key create --out <目录> --name <名>
//	build-keystore recover --recovery-key <恢复私钥文件> --upload <导出的密文文件> --out-dir <目录>
//
// recovery-key create 生成整个平台的离线恢复密钥（全平台只做一次）；recover 用恢复私钥解开控制台
// 导出的密文文件，得到 .p12 原件与口令文件（签名闸全部丢失时用）。两者的口令只从交互终端不回显地读。
//
// create 生成一把新密钥（RSA 4096 + 自签证书 + PKCS#12），seal 为已有原件重新加密（新增或
// 更换签名闸时用）。两者都**只**加密给 pin 文件里的签名闸：服务端登记了谁、控制台接受了谁，
// 都不会让这个工具多加密一份。
//
// 口令只写进 0600 的口令文件，从不打印到屏幕；工具不联网，不输出任何带管理接口凭据的命令。
package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/pins"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
	"github.com/Helix2010/RN-Server/signing/releasekey"
)

// keyBits 是新密钥的 RSA 位数。测试改成 2048 提速，生产固定 4096。
var keyBits = 4096

// now 可在测试里替换。
var now = time.Now

const (
	validityYears = 30
	// 口令文件：口令最长 1024 字节，再加一个换行
	maxPasswordFileSize = keystorebox.MaxPasswordLength + 1
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usageText = `用法:
  build-keystore create --pins <pin 文件> --tenant <slug> --package <包名> --alias <别名>
                        [--out-dir <目录>] [--common-name <证书 CN>] [--org <证书 O>]
  build-keystore seal   --pins <pin 文件> --p12 <原件> --password-file <口令文件>
                        --tenant <slug> --package <包名> [--alias <别名>] [--out <上传文件>]
  build-keystore recovery-key create --out <目录> --name <恢复密钥名>
  build-keystore recover --recovery-key <recovery-private.key> --upload <导出的密文文件> --out-dir <目录>
                         --expect-certificate-sha256 <已发布 App 的证书 SHA-256，不取控制台>

只在离线机器上运行。create/seal 的收件人只来自 pin 文件；口令只写进 0600 的文件，不打印。
recovery-key create 与 recover 的口令只从交互终端输入（不回显），标准输入不是终端时拒绝。`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "create":
		return create(args[1:], stdout, stderr)
	case "seal":
		return seal(args[1:], stdout, stderr)
	case "recovery-key":
		return recoveryKey(args[1:], stdout, stderr)
	case "recover":
		return recoverKeystore(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, usageText)
		return 2
	}
}

// usageError 表示参数用法不对（退出码 2）。
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func report(stderr io.Writer, err error) int {
	var usage usageError
	if errors.As(err, &usage) {
		fmt.Fprintln(stderr, "错误: "+usage.msg)
		fmt.Fprintln(stderr, usageText)
		return 2
	}
	fmt.Fprintln(stderr, "错误: "+err.Error())
	return 1
}

func parseFlags(set *flag.FlagSet, args []string, stderr io.Writer) error {
	set.SetOutput(stderr)
	if err := set.Parse(args); err != nil {
		return usageError{msg: "参数无法解析"}
	}
	if set.NArg() != 0 {
		return usageError{msg: "多余的参数: " + strings.Join(set.Args(), " ")}
	}
	return nil
}

func required(values map[string]string) error {
	var missing []string
	for _, name := range []string{"pins", "p12", "password-file", "tenant", "package", "alias"} {
		if v, ok := values[name]; ok && v == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return usageError{msg: "缺少必填参数 " + strings.Join(missing, "、")}
	}
	return nil
}

func validateIdentity(tenant, pkg string) error {
	if !ident.ValidTenantSlug(tenant) {
		return errors.New("--tenant 必须匹配 ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
	}
	if !ident.ValidPackageName(pkg) {
		return errors.New("--package 必须是小写的反向域名包名，例如 com.example.wallet")
	}
	return nil
}

// ---- create ----

func create(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("create", flag.ContinueOnError)
	pinPath := set.String("pins", "", "离线 pin 文件（签名闸公钥的唯一来源）")
	tenant := set.String("tenant", "", "租户 slug")
	pkg := set.String("package", "", "Android 包名")
	alias := set.String("alias", "", "keystore 别名")
	outDir := set.String("out-dir", "", "原件目录，必须不存在；默认 ./<tenant>-<alias>-<UTC 时间>")
	commonName := set.String("common-name", "", "证书 CN，默认 \"<tenant> Android Release\"")
	org := set.String("org", "", "证书 O，可留空")
	if err := parseFlags(set, args, stderr); err != nil {
		return report(stderr, err)
	}
	if err := required(map[string]string{"pins": *pinPath, "tenant": *tenant, "package": *pkg, "alias": *alias}); err != nil {
		return report(stderr, err)
	}
	if err := validateIdentity(*tenant, *pkg); err != nil {
		return report(stderr, err)
	}
	if !ident.ValidKeyAlias(*alias) {
		return report(stderr, errors.New("--alias 必须匹配 ^[A-Za-z0-9._-]{1,64}$"))
	}
	pinFile, err := loadPins(*pinPath)
	if err != nil {
		return report(stderr, err)
	}
	createdAt := now().UTC()
	dir := *outDir
	if dir == "" {
		dir = fmt.Sprintf("%s-%s-%s", *tenant, *alias, createdAt.Format("20060102T150405Z"))
	}
	if _, err := os.Lstat(dir); err == nil {
		return report(stderr, fmt.Errorf("%s 已经存在。原件目录必须是新的，免得覆盖或混进一把正在使用的密钥", dir))
	} else if !errors.Is(err, os.ErrNotExist) {
		return report(stderr, fmt.Errorf("检查 %s 失败: %v", dir, err))
	}
	cn := *commonName
	if cn == "" {
		cn = *tenant + " Android Release"
	}

	// 先在内存里把所有东西做完、校验完，再落盘：中途失败不会留下半套原件
	generated, err := releasekey.Generate(releasekey.Params{
		Alias: *alias, CommonName: cn, Organization: *org, KeyBits: keyBits, ValidityYears: validityYears,
	})
	if err != nil {
		return report(stderr, fmt.Errorf("生成密钥失败: %v", err))
	}
	upload, err := sealUpload(pinFile, keystorebox.Plaintext{
		Purpose:           keystorebox.Purpose,
		TenantSlug:        *tenant,
		PackageName:       *pkg,
		CertificateSHA256: generated.CertificateSHA256,
		KeyAlias:          *alias,
		CreatedAt:         createdAt.Truncate(time.Second).Format(time.RFC3339),
		P12Base64:         base64.StdEncoding.EncodeToString(generated.PKCS12),
		StorePassword:     generated.Password,
		KeyPassword:       generated.Password,
	})
	if err != nil {
		return report(stderr, err)
	}
	uploadJSON, err := encodeUpload(upload)
	if err != nil {
		return report(stderr, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generated.Certificate.Raw})

	if err := os.Mkdir(dir, 0o700); err != nil {
		return report(stderr, fmt.Errorf("创建原件目录失败: %v", err))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return report(stderr, fmt.Errorf("设置原件目录权限失败: %v", err))
	}
	files := struct{ p12, password, cert, upload string }{
		p12:      filepath.Join(dir, *alias+".p12"),
		password: filepath.Join(dir, *alias+".password"),
		cert:     filepath.Join(dir, "certificate.pem"),
		upload:   filepath.Join(dir, "keystore-upload.json"),
	}
	writes := []struct {
		path string
		data []byte
	}{
		{files.p12, generated.PKCS12},
		{files.password, []byte(generated.Password + "\n")},
		{files.cert, certPEM},
		{files.upload, uploadJSON},
	}
	for _, w := range writes {
		if err := writeExclusive(w.path, w.data); err != nil {
			// 这个目录是本次新建的，里面还没有任何东西被上传或备份，整个删掉
			_ = os.RemoveAll(dir)
			return report(stderr, fmt.Errorf("写 %s 失败，已删除不完整的原件目录: %v", w.path, err))
		}
	}
	if err := syncDir(dir); err != nil {
		return report(stderr, fmt.Errorf("落盘 %s 失败: %v", dir, err))
	}

	fmt.Fprintf(stdout, `
================ 生成完成 ================
租户:          %s
包名:          %s
别名:          %s
证书 SHA-256:  %s
证书有效期至:  %s

`, *tenant, *pkg, *alias, generated.CertificateSHA256, generated.NotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))
	printRecipients(stdout, pinFile)
	fmt.Fprintf(stdout, `
产出（目录 0700，文件 0600）:
  原件:          %s
  口令文件:      %s （口令不会显示在屏幕上）
  证书:          %s
  上传文件:      %s

接下来:
  1. 把上面的「证书 SHA-256」完整记进密码管理器。在签名闸上执行 signer confirm 时，要粘贴的就是它。
  2. 在控制台「Android 打包与签名 → 签名密钥」上传 %s，同时登记包名 %s 与证书 SHA-256。
  3. 分别登上 pin 文件里的每一台签名闸，执行 signer confirm --tenant %s。
  4. 按「原件与配置机密的保管」把本目录（原件、口令文件、证书）与 pin 文件打进加密包，
     放进两个离线 U 盘；核对无误后擦除这台机器上的明文副本。
`, files.p12, files.password, files.cert, files.upload, filepath.Base(files.upload), *pkg, *tenant)
	return 0
}

// ---- seal ----

func seal(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("seal", flag.ContinueOnError)
	pinPath := set.String("pins", "", "离线 pin 文件（签名闸公钥的唯一来源）")
	p12Path := set.String("p12", "", "PKCS#12 原件")
	passwordPath := set.String("password-file", "", "口令文件（第一行是口令）")
	tenant := set.String("tenant", "", "租户 slug（v3 密文绑定租户）")
	pkg := set.String("package", "", "Android 包名（v3 密文绑定包名）")
	alias := set.String("alias", "", "keystore 别名；给了就必须与原件里的一致")
	out := set.String("out", "", "上传文件路径，必须不存在；默认 ./<tenant>-keystore-upload-<UTC 时间>.json")
	if err := parseFlags(set, args, stderr); err != nil {
		return report(stderr, err)
	}
	if err := required(map[string]string{"pins": *pinPath, "p12": *p12Path, "password-file": *passwordPath, "tenant": *tenant, "package": *pkg}); err != nil {
		return report(stderr, err)
	}
	if err := validateIdentity(*tenant, *pkg); err != nil {
		return report(stderr, err)
	}
	if *alias != "" && !ident.ValidKeyAlias(*alias) {
		return report(stderr, errors.New("--alias 必须匹配 ^[A-Za-z0-9._-]{1,64}$"))
	}
	pinFile, err := loadPins(*pinPath)
	if err != nil {
		return report(stderr, err)
	}
	p12, err := readLimited(*p12Path, keystorebox.MaxP12Size)
	if err != nil {
		return report(stderr, fmt.Errorf("读原件失败: %v", err))
	}
	password, err := readPasswordFile(*passwordPath)
	if err != nil {
		return report(stderr, err)
	}
	entry, err := pkcs12.SingleKey(p12, password)
	switch {
	case errors.Is(err, pkcs12.ErrPassword):
		return report(stderr, errors.New("打不开原件：口令不对，或者原件被改过"))
	case errors.Is(err, pkcs12.ErrLegacyEncryption):
		return report(stderr, errors.New("原件用的是老式加密（RC2/3DES 等），请用 OpenSSL 3 或 JDK 12 以上的 keytool 以 AES 重新导出"))
	case err != nil:
		return report(stderr, fmt.Errorf("读不出原件: %v", err))
	}
	if !ident.ValidKeyAlias(entry.Alias) {
		return report(stderr, errors.New("原件里的别名不符合 ^[A-Za-z0-9._-]{1,64}$，签名闸无法按它找到条目；请用合规的别名重新导出"))
	}
	if *alias != "" && entry.Alias != *alias {
		return report(stderr, fmt.Errorf("原件里的别名是 %s，与 --alias %s 不一致", entry.Alias, *alias))
	}
	certSHA := pkcs12.CertificateSHA256(entry)
	createdAt := now().UTC()
	upload, err := sealUpload(pinFile, keystorebox.Plaintext{
		Purpose:           keystorebox.Purpose,
		TenantSlug:        *tenant,
		PackageName:       *pkg,
		CertificateSHA256: certSHA,
		KeyAlias:          entry.Alias,
		CreatedAt:         createdAt.Truncate(time.Second).Format(time.RFC3339),
		P12Base64:         base64.StdEncoding.EncodeToString(p12),
		StorePassword:     password,
		KeyPassword:       password,
	})
	if err != nil {
		return report(stderr, err)
	}
	uploadJSON, err := encodeUpload(upload)
	if err != nil {
		return report(stderr, err)
	}
	outPath := *out
	if outPath == "" {
		outPath = fmt.Sprintf("%s-keystore-upload-%s.json", *tenant, createdAt.Format("20060102T150405Z"))
	}
	if err := writeExclusive(outPath, uploadJSON); err != nil {
		return report(stderr, fmt.Errorf("写上传文件失败: %v", err))
	}
	if err := syncDir(filepath.Dir(outPath)); err != nil {
		return report(stderr, fmt.Errorf("落盘 %s 失败: %v", outPath, err))
	}
	fmt.Fprintf(stdout, `
================ 加密完成 ================
租户:          %s
包名:          %s
别名:          %s
证书 SHA-256:  %s

`, *tenant, *pkg, entry.Alias, certSHA)
	printRecipients(stdout, pinFile)
	fmt.Fprintf(stdout, `
上传文件:      %s （0600）

接下来:
  1. 核对上面的证书 SHA-256 与密码管理器里的离线记录一致。
  2. 在控制台「Android 打包与签名 → 签名密钥」上传这个文件，同时登记包名与证书 SHA-256。
  3. 新加入的签名闸上执行 signer confirm --tenant %s。
`, outPath, *tenant)
	return 0
}

// ---- 公用 ----

func loadPins(path string) (pins.File, error) {
	raw, err := readLimited(path, pins.MaxFileSize)
	if err != nil {
		return pins.File{}, fmt.Errorf("读 pin 文件失败: %v", err)
	}
	f, err := pins.Parse(raw)
	if err != nil {
		return pins.File{}, fmt.Errorf("pin 文件不合格: %v", err)
	}
	return f, nil
}

// sealUpload 为 pin 文件里的每一台签名闸各封一个 Box（顺序与 pin 文件一致），组成上传文件。
func sealUpload(pinFile pins.File, plaintext keystorebox.Plaintext) (keystorebox.Upload, error) {
	plaintext.Recipients = pinFile.RecipientSHA256s()
	boxes := make([]keystorebox.Box, 0, len(pinFile.Signers))
	for _, signer := range pinFile.Signers {
		pub, err := signer.PublicKey()
		if err != nil {
			return keystorebox.Upload{}, fmt.Errorf("pin 文件里 %s 的公钥不可用: %v", signer.Name, err)
		}
		box, err := keystorebox.Seal(plaintext, pub)
		if err != nil {
			return keystorebox.Upload{}, fmt.Errorf("加密给 %s 失败: %v", signer.Name, err)
		}
		boxes = append(boxes, box)
	}
	upload := keystorebox.Upload{
		Format:            keystorebox.UploadFormat,
		TenantSlug:        plaintext.TenantSlug,
		PackageName:       plaintext.PackageName,
		KeyAlias:          plaintext.KeyAlias,
		CertificateSHA256: plaintext.CertificateSHA256,
		CreatedAt:         plaintext.CreatedAt,
		Boxes:             boxes,
	}
	if err := upload.ValidateShape(); err != nil {
		return keystorebox.Upload{}, fmt.Errorf("上传文件没有通过格式自检: %v", err)
	}
	return upload, nil
}

func encodeUpload(upload keystorebox.Upload) ([]byte, error) {
	raw, err := json.MarshalIndent(upload, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func printRecipients(w io.Writer, pinFile pins.File) {
	fmt.Fprintln(w, "收件人（只来自 pin 文件）:")
	for _, s := range pinFile.Signers {
		fmt.Fprintf(w, "  %s（%s）\n    X25519 公钥 SHA-256:  %s\n    Ed25519 公钥 SHA-256: %s\n",
			s.Name, s.Role, s.X25519PublicKeySHA256, s.Ed25519PublicKeySHA256)
	}
}

// readLimited 读一个普通文件，超过 max 字节就拒绝。
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s 不是普通文件", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s 超过 %d 字节", path, max)
	}
	return raw, nil
}

// readPasswordFile 读口令文件：去掉一个结尾换行，其余字符规则与 v3 明文一致。错误信息不含口令内容。
func readPasswordFile(path string) (string, error) {
	raw, err := readLimited(path, maxPasswordFileSize+1)
	if err != nil {
		return "", fmt.Errorf("读口令文件失败: %v", err)
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	if len(raw) > maxPasswordFileSize {
		return "", errors.New("口令文件太大：口令最长 1024 字节")
	}
	text := string(raw)
	switch {
	case strings.HasSuffix(text, "\r\n"):
		text = strings.TrimSuffix(text, "\r\n")
	case strings.HasSuffix(text, "\n"):
		text = strings.TrimSuffix(text, "\n")
	}
	if text == "" || len(text) > keystorebox.MaxPasswordLength || !utf8.ValidString(text) {
		return "", errors.New("口令文件的内容必须是 1-1024 字节的 UTF-8 口令（可带一个结尾换行）")
	}
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return "", errors.New("口令文件里有控制字符或多行内容：只允许一行口令")
		}
	}
	return text, nil
}

// writeExclusive 新建文件（已存在就失败），0600，写完 fsync。
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
