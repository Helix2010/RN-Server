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

import (
	"regexp"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

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
	// IOSTenantsDirName 是按租户落盘的那一层（设计 ios-tenant-owned-signing-material-2026-09-25 §4.1）：
	// profiles/tenants/<租户>/<TEAM>/<bundle>.mobileprovision、上传区的 tenants/<租户>/<TEAM>/。
	// 多这一层是因为租户 id 是纯数字，也匹配 Team ID 的正则，直接放第一层会和旧布局混在一起
	IOSTenantsDirName = "tenants"
	// IOSTenantCertificatesFileName 是签名目录下的本机证书索引：{"<租户>/<TEAM>":"<SHA-1>"}。
	// 同一张证书在钥匙串里只存一份身份，谁在用它记在这里；构建时按它把签名身份钉死
	IOSTenantCertificatesFileName = "tenant-certificates.json"
)

// certificateSHA1Pattern 是 `security find-identity` 打印的身份指纹形状
var certificateSHA1Pattern = regexp.MustCompile(`^[0-9A-F]{40}$`)

// ValidTenantID 判断服务端给的租户 id 能不能拿去拼路径。一律用服务端给的 id，不用 slug 或
// 仓库目录名：那两个要么租户自己能改，要么会与别的租户撞（设计 §4.1）
func ValidTenantID(s string) bool { return iosmaterial.ValidTenantID(s) }

// ValidCertificateSHA1 判断一个证书指纹是不是 40 位大写十六进制。
func ValidCertificateSHA1(s string) bool { return certificateSHA1Pattern.MatchString(s) }

// TenantCertificateKey 是证书索引里的键。
func TenantCertificateKey(tenant, team string) string { return tenant + "/" + team }

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
	// TenantProfiles 是按租户落盘的描述文件："<租户>/<TEAMID>/<文件名>" -> 原文
	TenantProfiles map[string][]byte `json:"tenantProfiles,omitempty"`
	// TenantCertificates 是证书索引的原样内容（"<租户>/<TEAMID>" -> SHA-1）
	TenantCertificates map[string]string `json:"tenantCertificates,omitempty"`
}
