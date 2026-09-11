// build-keystore 把一台机器上的 Android 签名密钥封成一个**服务端打不开**的盒子，
// 输出一份可以直接 PUT 给管理接口的请求体。
//
//	build-keystore seal --keystore ./anyfun-release.keystore --alias anyfun \
//	  --out ./build-keystore.json
//
// 口令从 BUILD_KEYSTORE_PASSPHRASE 读，或者交互式输入；keystore 口令与 key 口令
// 同理。它们都被封进盒子里，所以打包机只需要一个口令，不需要为每个租户各存一份。
//
// 为什么不直接把 keystore 交给服务端加密：那样加密用的是 STORAGE_MASTER_KEY，
// 而它就在 wallet 后端进程里——等于后端多了一个它不需要的能力，而 keystore 泄露
// 在 direct 分发下没有补救办法。
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "seal" {
		fmt.Fprintln(os.Stderr, "用法: build-keystore seal --keystore <file> --alias <alias> [--out <file>]")
		os.Exit(2)
	}
	set := flag.NewFlagSet("seal", flag.ExitOnError)
	keystorePath := set.String("keystore", "", "keystore 文件路径")
	alias := set.String("alias", "", "签名用的 key alias")
	out := set.String("out", "build-keystore.json", "输出的请求体路径")
	expectedVersion := set.Int("expected-version", 0, "乐观锁：线上当前版本号，首次上传填 0")
	_ = set.Parse(os.Args[2:])

	if strings.TrimSpace(*keystorePath) == "" || strings.TrimSpace(*alias) == "" {
		fmt.Fprintln(os.Stderr, "错误: --keystore 与 --alias 必填")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*keystorePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 读不到 keystore: %v\n", err)
		os.Exit(1)
	}

	storePassword := secret("ANDROID_RELEASE_KEYSTORE_PASSWORD", "keystore 口令")
	keyPassword := secret("ANDROID_RELEASE_KEY_PASSWORD", "key 口令（与 keystore 口令相同就直接回车）")
	if keyPassword == "" {
		keyPassword = storePassword
	}
	passphrase := secret("BUILD_KEYSTORE_PASSPHRASE", "封装口令（打包机上要用同一个）")

	sealed, err := buildkeystore.Seal(buildkeystore.Bundle{
		KeystoreBase64: base64.StdEncoding.EncodeToString(raw),
		StorePassword:  storePassword,
		KeyAlias:       strings.TrimSpace(*alias),
		KeyPassword:    keyPassword,
	}, passphrase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	// 开箱自检：封完立刻用同一个口令开一次。这一步失败说明盒子根本打不开，
	// 而那要等到第一次构建时才会暴露
	if _, err := buildkeystore.Open(sealed, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 刚封好的盒子打不开，不要上传: %v\n", err)
		os.Exit(1)
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
	encoded, _ := json.MarshalIndent(body, "", "  ")
	if err := os.WriteFile(*out, append(encoded, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "错误: 写不出请求体: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(`
================ 封装完成 ================
keystore:        %s
alias:           %s
keystore SHA256: %s
请求体:          %s （0600）

接下来：

  curl -sS -X PUT https://<租户域名>/v1/admin/build-keystore \
    -H "content-type: application/json" -H "x-admin-key: $ADMIN_API_KEY" \
    --data-binary @%s
  shred -u %s

打包机上设同一个封装口令：BUILD_KEYSTORE_PASSPHRASE。

服务端存的是这个盒子，它没有钥匙，打不开。丢了封装口令就只能重新封一次——
原始 keystore 仍在你手上，所以这不是不可恢复的。
`, *keystorePath, *alias, hex.EncodeToString(digest[:]), *out, *out, *out)
}

// secret 优先取环境变量；没有就从终端读，不回显。
func secret(envKey, prompt string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	raw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 读不到输入: %v\n", err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(raw))
}
