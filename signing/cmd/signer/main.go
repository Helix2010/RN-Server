// signer 是 Android 签名闸：一主一备，只给确认过的东西签名。
//
// 子命令与流程见 signing/internal/signer 与 deploy/signer/README.md。
package main

import (
	"os"

	"github.com/Helix2010/RN-Server/signing/internal/signer"
)

func main() {
	os.Exit(signer.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}
