// Package androidkeystore 放 Android 签名证书相关、服务端与构建机共用的常量。
//
// 服务端生成签名密钥（原 Generate 与自写的 PKCS#12 编码）随签名闸方案删除（ADR-0019）：
// 签名密钥只由离线工具生成并加密给签名闸，服务端与构建机都不再接触 keystore 本身。
package androidkeystore

// PublicDebugSignerSHA256 是 React Native / Android SDK 模板自带的 debug.keystore
// 那张证书的 SHA-256。
//
// 它的私钥在每一台装了 RN 的机器上，所以谁都能用它签一个同包名的 APK 在用户设备上
// 原地覆盖安装，数据目录连钱包一起留着。拿它当发布身份等于把自校验关掉，还留下一行
// "已经校验过了"的假象。
//
// 重新求证：
//
//	keytool -list -v -keystore <RN-App>/android/app/debug.keystore -storepass android
//
// 打出来的 SHA256 行去掉冒号、转小写就是这个值。**不要**用同一段输出里的 SHA1——
// 2026-09-12 之前 cmd/build-agent 里那份常量就是把 SHA-1 补零凑到 64 位得来的，
// 于是那道闸永远匹配不上，是一条恒假的断言。
const PublicDebugSignerSHA256 = "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
