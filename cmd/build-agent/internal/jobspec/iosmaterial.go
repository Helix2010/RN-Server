package jobspec

// iOS 签名材料的取法（设计 ios-mac-builders-home-network-2026-09-18 §4.2、§5.4）。
//
// 签名区 /var/rn-build-signing 是 _rnbuilder 0700：证书、钥匙串口令、描述文件都归执行
// 账户。控制进程（_rnbuildagent）连那个目录都 stat 不了——这是设计要的，第三方构建代码
// 与本机令牌各在一边。
//
// 可同一份设计（§5.4）又要控制进程盘点"这台机器现在能签哪些 (Team, bundle id)"，并随每次
// 认领报上去。两件事都对，缺的是中间那一段：**由执行账户把原文取出来交给控制进程**。
// build-runner 本来就是控制进程唯一能以执行账户启动的程序（sudoers 里只有它），所以这件
// 事挂在它身上，不必为它再开一条 sudo 规则，也不必放宽签名区的权限。
//
// 这里只搬**原文**，不搬结论：谁能签、哪份过期了、少了什么，仍旧全由控制进程判断。
// 把判断也挪过去等于让"这台机器报上去的能力"由跑第三方代码的那个账户说了算。
const (
	// IOSKeychainFileName 与 IOSProfilesDirName 是装机脚本铺出来的固定布局（§4.2）
	IOSKeychainFileName = "rn-signing.keychain-db"
	IOSProfilesDirName  = "profiles"
	// IOSProfileSuffix 是描述文件的扩展名
	IOSProfileSuffix = ".mobileprovision"
	// IOSProfileMaxBytes 是单份描述文件的上限。真实的是几 KB；这里留足余量，
	// 只为挡住"有人往那个目录里放了个几百 MB 的文件"把认领循环拖死
	IOSProfileMaxBytes = 256 << 10
	// IOSProfileMaxCount 是一次盘点最多读多少份。租户数是两位数，这里同样只挡意外
	IOSProfileMaxCount = 200
)

// IOSMaterial 是 `build-runner ios-inventory` 回给控制进程的东西：两条 security 命令的
// 标准输出，以及 profiles/ 下每份描述文件的原文。
type IOSMaterial struct {
	// Identities 是 `security find-identity -v -p codesigning <钥匙串>` 的标准输出
	Identities string `json:"identities"`
	// IdentitiesError 非空表示那条命令没跑成。它是致命的：读不出钥匙串里有哪些身份，
	// 这一轮盘点什么都不该报
	IdentitiesError string `json:"identitiesError,omitempty"`
	// Certificates 是 `security find-certificate -a -p <钥匙串>` 的标准输出，用来算到期日
	Certificates string `json:"certificates"`
	// CertificatesError 非空只影响"还剩几天到期"的提醒，不影响能不能签
	CertificatesError string `json:"certificatesError,omitempty"`
	// Profiles 是 "<TEAMID>/<文件名>" -> 文件原文（JSON 里是 base64）
	Profiles map[string][]byte `json:"profiles,omitempty"`
	// Problems 是取材料时"看见了但读不了"的东西，原样并进盘点结果
	Problems []string `json:"problems,omitempty"`
}
