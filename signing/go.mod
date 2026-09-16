// 签名闸、检查进程与离线工具的独立 module。
//
// 只允许依赖标准库（和 golang.org/x/crypto，目前用不到）：这里的代码持有或处理
// 签名密钥，每多一个依赖就多一份要审的供应链。服务端经根模块的 replace 引用
// 共享格式包（fingerprint、keystorebox、provenance、trustroots、machinekey、pins）。
module github.com/Helix2010/RN-Server/signing

go 1.24.0
