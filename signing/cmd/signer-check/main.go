// signer-check 是签名闸的检查进程：对不可信的未签名 APK 做全部解析与签名前检查。
//
// 它不持有、也不读取任何机密：不读环境变量里的配置，不联网，不碰签名闸的状态目录。
// 从 stdin 读"策略输入 JSON 一行 + APK 字节"，把 APK 写进自己的临时目录，跑
// signing/apk 与 signing/policy，向 stdout 写一行结论 JSON 后退出。
//
// 生产上由 systemd socket 激活（rn-signer-a-check.socket，Accept=yes），每个连接一个
// DynamicUser、PrivateNetwork 的进程，stdin/stdout 就是那条连接；本地测试由签名闸
// 主进程以子进程方式启动（SIGNER_CHECK_EXEC）。进程崩溃只会让主进程拿不到结论，
// 主进程按临时错误上报。
package main

import (
	"os"

	"github.com/Helix2010/RN-Server/signing/internal/checkwire"
)

func main() {
	os.Exit(checkwire.Serve(os.Stdin, os.Stdout, os.Stderr))
}
