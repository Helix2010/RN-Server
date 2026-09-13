// build-keystore 处理 Android 签名密钥的**离线**那条路：在一台服务端够不着的机器上
// 生成或封装密钥，产出一份可以直接 PUT 给管理接口的请求体。
//
//	build-keystore create --package com.example.wallet --alias example --name "Example Wallet"
//	build-keystore seal --keystore ./release.keystore --alias example --package com.example.wallet
//
// create 是新租户走的路：这台机器上还没有 keystore，它生成一把、算出证书指纹、
// 封好盒子，一步到位。seal 是已经有 keystore 时用的。
//
// 口令从环境变量读，或者交互式输入；keystore 口令与 key 口令同理。它们都被封进
// 盒子里，所以打包机只需要一个封装口令，不需要为每个租户各存一份。
//
// 控制台上也有同样两条路（「Android 打包与签名」页）。那条更省事，代价是生成的
// 那一刻明文私钥在服务端进程内存里存在过。这个命令行工具是给"不接受那一点"的
// 场景准备的：整个过程服务端只见得到封好的盒子。
//
// 为什么不直接把 keystore 交给服务端加密：那样加密用的是 STORAGE_MASTER_KEY，
// 而它就在 wallet 后端进程里——等于后端多了一个它不需要的能力，而 keystore 泄露
// 在 direct 分发下没有补救办法。
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

var packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "create":
		create(os.Args[2:])
	case "seal":
		seal(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  build-keystore create --package <applicationId> --alias <alias> --name <证书里的名字>
                        --agent-key <打包机公钥 base64>
                        [--org <组织>] [--country <两位国家码>] [--key-size 2048|4096]
                        [--years 30] [--out-keystore <file>] [--out <file>]
  build-keystore seal   --keystore <file> --alias <alias> --agent-key <打包机公钥 base64>
                        [--package <applicationId>] [--out <file>]
                        [--expected-version N] [--release-identity-version N]`)
	os.Exit(2)
}

// create 生成一把新的签名密钥并当场封好。
//
// 明文 keystore 会写到本机磁盘上：**这是唯一一份**。服务端只拿到封好的盒子，它
// 打不开；封装口令丢了就只能重新生成一把，而那意味着已经装出去的用户升不上去。
func create(args []string) {
	set := flag.NewFlagSet("create", flag.ExitOnError)
	pkg := set.String("package", "", "Android 包名（applicationId），会一并登记为发布身份")
	alias := set.String("alias", "", "签名用的 key alias")
	name := set.String("name", "", "证书里的名字（CN），一般写 App 名")
	org := set.String("org", "", "证书里的组织名（O），可留空")
	country := set.String("country", "", "两位国家码（C），可留空")
	keySize := set.Int("key-size", 2048, "RSA 密钥长度：2048 或 4096")
	years := set.Int("years", 30, "证书有效期（年）")
	outKeystore := set.String("out-keystore", "", "明文 keystore 的输出路径，默认 <alias>.p12")
	agentKey := set.String("agent-key", "", "打包机的 X25519 公钥（base64），在控制台「平台维护 → 打包机公钥」上")
	out := set.String("out", "build-keystore.json", "输出的请求体路径")
	expectedVersion := set.Int("expected-version", 0, "乐观锁：线上 build.keystore 当前版本号，首次上传填 0")
	releaseVersion := set.Int("release-identity-version", 0, "乐观锁：线上 release.android 当前版本号，首次填 0")
	_ = set.Parse(args)

	requirePackage(*pkg)
	if strings.TrimSpace(*alias) == "" || strings.TrimSpace(*name) == "" {
		fail("--alias 与 --name 必填")
	}
	keystorePath := strings.TrimSpace(*outKeystore)
	if keystorePath == "" {
		keystorePath = strings.TrimSpace(*alias) + ".p12"
	}
	if _, err := os.Stat(keystorePath); err == nil {
		// 覆盖掉一把已经在用的 keystore，等于让所有装着旧版的设备再也升不上去
		fail(keystorePath + " 已经存在。换个 --out-keystore，或者先确认那把密钥不再需要")
	}

	generated, err := androidkeystore.Generate(androidkeystore.Params{
		CommonName:    strings.TrimSpace(*name),
		Organization:  strings.TrimSpace(*org),
		Country:       strings.TrimSpace(*country),
		KeyAlias:      strings.TrimSpace(*alias),
		KeySize:       *keySize,
		ValidityYears: *years,
	})
	if err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(keystorePath, generated.PKCS12, 0o600); err != nil {
		fail("写不出 keystore: " + err.Error())
	}
	// 加密给打包机的公钥，没有口令。公钥不是秘密，控制台「平台维护 → 打包机公钥」上有
	recipient := buildkeystore.Recipient{PublicKey: strings.TrimSpace(*agentKey)}
	if recipient.Fingerprint() == "" {
		fail("--agent-key 必填，而且要是打包机那把 X25519 公钥的 base64。\n" +
			"在控制台「平台维护 → 打包机公钥」上能看到它和它的指纹。")
	}
	sealed, err := buildkeystore.SealTo(buildkeystore.Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString(generated.PKCS12),
		StorePassword:  generated.StorePassword,
		KeyAlias:       strings.TrimSpace(*alias),
		KeyPassword:    generated.StorePassword,
	}, recipient)
	if err != nil {
		fail("加密给打包机公钥失败: " + err.Error())
	}

	writeBody(*out, map[string]any{
		"sealed":                         sealed,
		"keyAlias":                       strings.TrimSpace(*alias),
		"keystoreSha256":                 generated.KeystoreSHA256,
		"expectedVersion":                *expectedVersion,
		"packageName":                    strings.TrimSpace(*pkg),
		"signerSha256":                   generated.SignerSHA256,
		"releaseIdentityExpectedVersion": *releaseVersion,
		"reason":                         "create and upload android signing keystore",
		"confirm":                        true,
	})

	fmt.Printf(`
================ 生成完成 ================
keystore:        %s （0600，**这是唯一一份，请立刻备份**）
store 口令:      %s
alias:           %s
包名:            %s
证书指纹 SHA256: %s
证书有效期至:    %s
keystore SHA256: %s
请求体:          %s （0600）

"证书指纹"就是发布身份要登记的那个值——请求体里已经带上，不用再手工抄。

接下来：

  curl -sS -X PUT https://<租户域名>/v1/admin/build-keystore \
    -H "content-type: application/json" -H "x-admin-key: $ADMIN_API_KEY" \
    --data-binary @%s
  shred -u %s

把 %s 和上面那个 store 口令一起存进密码管理器，然后设好打包机的
BUILD_KEYSTORE_PASSPHRASE。服务端存的是盒子，它没有钥匙。
`, keystorePath, generated.StorePassword, strings.TrimSpace(*alias), strings.TrimSpace(*pkg),
		generated.SignerSHA256, generated.NotAfter.Format("2006-01-02"), generated.KeystoreSHA256,
		*out, *out, *out, keystorePath)
}

// seal 封装一把已经存在的 keystore。
func seal(args []string) {
	set := flag.NewFlagSet("seal", flag.ExitOnError)
	keystorePath := set.String("keystore", "", "keystore 文件路径")
	alias := set.String("alias", "", "签名用的 key alias")
	pkg := set.String("package", "", "Android 包名。带上就把证书指纹一并登记为发布身份")
	out := set.String("out", "build-keystore.json", "输出的请求体路径")
	agentKey := set.String("agent-key", "", "打包机的 X25519 公钥（base64），在控制台「平台维护 → 打包机公钥」上")
	expectedVersion := set.Int("expected-version", 0, "乐观锁：线上 build.keystore 当前版本号，首次上传填 0")
	releaseVersion := set.Int("release-identity-version", 0, "乐观锁：线上 release.android 当前版本号，首次填 0")
	_ = set.Parse(args)

	if strings.TrimSpace(*keystorePath) == "" || strings.TrimSpace(*alias) == "" {
		fail("--keystore 与 --alias 必填")
	}
	if strings.TrimSpace(*pkg) != "" {
		requirePackage(*pkg)
	}
	raw, err := os.ReadFile(*keystorePath)
	if err != nil {
		fail("读不到 keystore: " + err.Error())
	}

	storePassword := secret("ANDROID_RELEASE_KEYSTORE_PASSWORD", "keystore 口令")
	keyPassword := secret("ANDROID_RELEASE_KEY_PASSWORD", "key 口令（与 keystore 口令相同就直接回车）")
	if keyPassword == "" {
		keyPassword = storePassword
	}
	// 加密给打包机的公钥，不再问任何封装口令。公钥不是秘密，从平台维护页面抄过来
	// （或者 GET /v1/admin/platform/build-agent/public-key）。
	recipient := buildkeystore.Recipient{PublicKey: strings.TrimSpace(*agentKey)}
	if recipient.Fingerprint() == "" {
		fail("--agent-key 必填，而且要是打包机那把 X25519 公钥的 base64。\n" +
			"在控制台「平台维护 → 打包机公钥」上能看到它和它的指纹。")
	}
	sealed, err := buildkeystore.SealTo(buildkeystore.Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString(raw),
		StorePassword:  storePassword,
		KeyAlias:       strings.TrimSpace(*alias),
		KeyPassword:    keyPassword,
	}, recipient)
	if err != nil {
		fail("加密给打包机公钥失败: " + err.Error())
	}

	digest := sha256.Sum256(raw)
	body := map[string]any{
		"sealed":          sealed,
		"keyAlias":        strings.TrimSpace(*alias),
		"keystoreSha256":  hex.EncodeToString(digest[:]),
		"expectedVersion": *expectedVersion,
		"reason":          "upload sealed android signing keystore",
		"confirm":         true,
	}

	// 证书指纹本来就在这个文件里，不该让人再跑一次 keytool 把 64 位十六进制抄一遍。
	// 抄错的表现是构建成功、产物却在入库那一步被 RELEASE_SIGNER_MISMATCH 拒。
	signer, signerErr := androidkeystore.CertificateSHA256(raw, storePassword)
	switch {
	case signerErr != nil:
		fmt.Fprintf(os.Stderr, "\n注意: 读不出证书指纹（%v）。老的 JKS 格式解不开——请在控制台\n"+
			"「Android 打包与签名」里手工登记，指纹取自 keytool -list -v 的 SHA-256 行。\n", signerErr)
	case strings.TrimSpace(*pkg) == "":
		fmt.Fprintf(os.Stderr, "\n注意: 没给 --package，所以没有把发布身份一起写进请求体。\n"+
			"这把 keystore 的证书指纹是 %s。\n", signer)
	default:
		body["packageName"] = strings.TrimSpace(*pkg)
		body["signerSha256"] = signer
		body["releaseIdentityExpectedVersion"] = *releaseVersion
	}
	writeBody(*out, body)

	fmt.Printf(`
================ 封装完成 ================
keystore:        %s
alias:           %s
keystore SHA256: %s
证书指纹 SHA256: %s
请求体:          %s （0600）

接下来：

  curl -sS -X PUT https://<租户域名>/v1/admin/build-keystore \
    -H "content-type: application/json" -H "x-admin-key: $ADMIN_API_KEY" \
    --data-binary @%s
  shred -u %s

这个盒子是**加密给打包机那把公钥**的，没有任何口令。服务端只有公钥，它打不开；
换了打包机（或者打包机换了私钥）之后要用新公钥重新封一次——原始 keystore 仍在你
手上，所以这不是不可恢复的。
`, *keystorePath, strings.TrimSpace(*alias), hex.EncodeToString(digest[:]),
		orDash(signer), *out, *out, *out)
}

func writeBody(path string, body map[string]any) {
	encoded, _ := json.MarshalIndent(body, "", "  ")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		fail("写不出请求体: " + err.Error())
	}
}

func requirePackage(value string) {
	if !packagePattern.MatchString(strings.TrimSpace(value)) {
		fail("--package 必须是反向域名形式的 applicationId，例如 com.example.wallet")
	}
}

func orDash(value string) string {
	if value == "" {
		return "—（这个格式读不出来，请手工登记）"
	}
	return value
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "错误: "+message)
	os.Exit(1)
}

// secret 优先取环境变量；没有就从标准输入读一行。
//
// 不引第三方的"无回显读取"：那条依赖会把整个模块的 Go 版本要求往上顶，而生产
// 镜像固定在一个较老的 Go 上——2026-09-11 就因为这个让服务端镜像构建直接失败。
// 交互式使用时自己关回显即可：
//
//	read -rs -p "passphrase: " BUILD_KEYSTORE_PASSPHRASE && export BUILD_KEYSTORE_PASSPHRASE
func secret(envKey, prompt string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	fmt.Fprintf(os.Stderr, "%s（从标准输入读；想不回显就先 read -rs 存进 %s）: ", prompt, envKey)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fail("读不到输入: " + err.Error())
	}
	return strings.TrimSpace(line)
}
