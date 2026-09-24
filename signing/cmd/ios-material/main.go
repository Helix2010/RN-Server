// ios-material 是 iOS 签名材料的离线工具（设计
// docs/design/ios-signing-material-distribution-2026-09-19.md）。
//
//	ios-material keygen  --out <目录>
//	ios-material encrypt --pub <公钥文件> --team <TEAMID> --out <密文> \
//	                     --kind certificate --p12 <文件>            （口令走标准输入）
//	                     --kind profile     --profile <文件> --bundle <bundle id>
//	                     --kind upload-key  --p8 <文件> --issuer <id> --key-id <id>
//	ios-material verify  --key <私钥文件> --in <密文>
//
// 它跑在**离线机器**上。私钥在这里生成、从这里进密码管理器，**不经过服务端**——服务端只
// 转发它读不懂的密文，这是整套设计的前提。
//
// 机密不进命令行：`.p12` 的口令只从标准输入读（`ps` 能看到别人的命令行，shell 历史也留）。
// 这个程序任何一条输出都不含私钥与口令。
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/internal/sealedbox"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const usage = `用法:
  ios-material keygen  --out <目录>
  ios-material encrypt --pub <公钥文件> --team <TEAMID> --kind <种类> --out <密文文件> ...
  ios-material verify  --key <私钥文件> --in <密文文件>

种类与它要的东西:
  certificate  --p12 <文件>                             口令从标准输入读
  profile      --profile <文件> --bundle <bundle id>
  upload-key   --p8 <文件> --issuer <id> --key-id <id>
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin)) }

func run(args []string, stdout, stderr io.Writer, stdin io.Reader) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = keygen(args[1:], stdout)
	case "encrypt":
		err = encrypt(args[1:], stdout, stdin)
	case "verify":
		err = verify(args[1:], stdout)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "ios-material:", err)
		return 1
	}
	return 0
}

// keygen 生成两把角色密钥。**分两把**是因为合成一把的话，拿到构建账户就同时拿到了上传
// 能力——那正是 Mac 上三个账户分开要挡的事（设计 §4.1）。
func keygen(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := set.String("out", "", "写到哪个目录")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out 是必填的")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	for _, role := range []string{"builder", "uploader"} {
		key, err := sealedbox.NewKey()
		if err != nil {
			return err
		}
		private := filepath.Join(*out, role+".x25519")
		if _, err := os.Stat(private); err == nil {
			return fmt.Errorf("%s 已经存在，不覆盖——覆盖等于把已经发出去的材料全部作废", private)
		}
		body := base64.StdEncoding.EncodeToString(key.Bytes()) + "\n"
		if err := os.WriteFile(private, []byte(body), 0o600); err != nil {
			return err
		}
		sealedbox.Wipe([]byte(body))
		pub := key.PublicKey().Bytes()
		if err := os.WriteFile(private+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n  私钥   %s（0600，立刻进密码管理器）\n  公钥   %s\n  指纹   %s\n",
			role, private, base64.StdEncoding.EncodeToString(pub), fingerprint.SHA256Hex(pub))
	}
	fmt.Fprint(stdout, `
下一步：
  1. 两个 .pub 的内容登记到控制台（平台维护 → Apple 证书与密钥 → 平台加密公钥）；
  2. 两个私钥进密码管理器，装机时用 --material-key-builder / --material-key-uploader 放到 Mac 上；
  3. 这台机器上的私钥文件在确认密码管理器里有了之后再删。
     **私钥一个字节都不要经过服务端。**
`)
	return nil
}

func encrypt(args []string, stdout io.Writer, stdin io.Reader) error {
	set := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	pubPath := set.String("pub", "", "收件人公钥文件（keygen 产出的 .pub）")
	team := set.String("team", "", "Apple Team ID")
	kind := set.String("kind", "", "certificate | profile | upload-key")
	outPath := set.String("out", "", "密文写到哪")
	p12 := set.String("p12", "", "证书 .p12")
	profilePath := set.String("profile", "", "描述文件 .mobileprovision")
	bundle := set.String("bundle", "", "bundle id（描述文件）")
	p8 := set.String("p8", "", "上传 Key .p8")
	issuer := set.String("issuer", "", "ASC issuer id（上传 Key）")
	keyID := set.String("key-id", "", "ASC key id（上传 Key）")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *pubPath == "" || *team == "" || *kind == "" || *outPath == "" {
		return errors.New("--pub、--team、--kind、--out 都是必填的")
	}
	pub, err := readKey(*pubPath)
	if err != nil {
		return err
	}
	material := iosmaterial.Material{Kind: *kind, TeamID: *team, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	switch *kind {
	case iosmaterial.KindCertificate:
		if material.P12Base64, err = readBase64(*p12); err != nil {
			return err
		}
		password, err := io.ReadAll(io.LimitReader(stdin, iosmaterial.MaxPasswordLength+1))
		if err != nil {
			return err
		}
		material.P12Password = strings.TrimRight(string(password), "\r\n")
		if material.P12Password == "" {
			return errors.New(".p12 的口令从标准输入读，现在是空的：用 `… | ios-material encrypt …` 或 `< 口令文件`")
		}
	case iosmaterial.KindProfile:
		material.BundleID = *bundle
		if material.ProfileBase64, err = readBase64(*profilePath); err != nil {
			return err
		}
	case iosmaterial.KindUploadKey:
		material.IssuerID, material.KeyID = *issuer, *keyID
		if material.P8Base64, err = readBase64(*p8); err != nil {
			return err
		}
	default:
		return fmt.Errorf("--kind 只能是 certificate、profile 或 upload-key，不是 %q", *kind)
	}
	box, err := iosmaterial.Seal(material, pub)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(box, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "已加密 %s → %s\n  收件人指纹 %s\n  这份密文可以交给控制台上传；服务端解不开它。\n",
		*kind, *outPath, box.RecipientSHA256)
	return nil
}

// verify 用私钥解一份，只打印非机密字段。加密完自己验一遍，比"传上去之后机器说解不开"早得多。
func verify(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("verify", flag.ContinueOnError)
	keyPath := set.String("key", "", "私钥文件")
	in := set.String("in", "", "密文文件")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" {
		return errors.New("--key 与 --in 都是必填的")
	}
	private, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	defer sealedbox.Wipe(private)
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	box, err := iosmaterial.ParseBox(raw)
	if err != nil {
		return err
	}
	material, err := iosmaterial.Open(box, private)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "解开了：%s\n  封装时间 %s\n", material, box.CreatedAt)
	return nil
}

// readKey 读一行 base64 的 32 字节密钥。
func readKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s 不是一行 base64：%w", path, err)
	}
	if len(key) != sealedbox.KeySize {
		return nil, fmt.Errorf("%s 解出来是 %d 字节，X25519 的密钥是 %d 字节", path, len(key), sealedbox.KeySize)
	}
	return key, nil
}

func readBase64(path string) (string, error) {
	if path == "" {
		return "", errors.New("这个种类要一个文件，但没给")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("%s 是空文件", path)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
