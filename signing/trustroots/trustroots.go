// Package trustroots 是编进安装包的信任根：App 连哪个服务端、信哪张 OTA 证书、
// 用谁的地址验 bootstrap 配置、认领哪些 App Links 域名与自定义 scheme。
//
// 签名闸在本机确认这些值（`signer confirm`），只给包内信任根与确认值逐项一致的包签名。
// 服务端合成 tenant.json 时用同一套规则算出摘要，用来判断"租户改了信任根之后主签名闸
// 是否已经重新确认"。两边必须用这里的 Normalize 与 Digest，不能各写一份。
package trustroots

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

const digestPrefix = "rn-trust-roots/v1\n"

// OTAManifestPath 是 updates.url 相对 apiBaseUrl 的路径（RN-App app.config.ts）。
const OTAManifestPath = "/v1/ota/manifest"

// MaxAppLinksHosts 是 App Links host 数量上限。
const MaxAppLinksHosts = 16

// DistributionChannels 是 RN-App app.config.ts 里 distributionChannel 的全部取值。
var DistributionChannels = []string{"development", "staging", "store", "direct", "mdm"}

var (
	// 与服务端 tenant_manifest.go 的 schemePattern 一致
	schemePattern        = regexp.MustCompile(`^[a-z][a-z0-9.+-]{1,31}$`)
	applicationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,119}$`)
	addressPattern       = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	hostLabelPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Roots 是包内信任根。JSON 字段名是跨组件契约，字段顺序决定摘要。
type Roots struct {
	APIBaseURL             string   `json:"apiBaseUrl"`             // 原样，https://…，无尾斜杠
	OTACertificateSHA256   string   `json:"otaCertificateSha256"`   // 内嵌 OTA 证书 DER 的 sha256
	BootstrapSignerAddress string   `json:"bootstrapSignerAddress"` // 0x + 40 hex，比对与摘要用小写
	AppLinksHosts          []string `json:"appLinksHosts"`          // 排序、去重、小写
	Scheme                 string   `json:"scheme"`
	DistributionChannel    string   `json:"distributionChannel"`
	ApplicationID          string   `json:"applicationId"`
}

// Normalize 严格校验并规范化。含控制字符、非 ASCII 的值一律报错；错误信息不回显原值，
// 因为这些值可能来自不可信的一方，而错误会被打印到运维终端上。
func (r Roots) Normalize() (Roots, error) {
	var out Roots
	if err := ValidateAPIBaseURL(r.APIBaseURL); err != nil {
		return Roots{}, err
	}
	out.APIBaseURL = r.APIBaseURL

	cert, ok := fingerprint.Normalize(r.OTACertificateSHA256)
	if !ok {
		return Roots{}, errors.New("otaCertificateSha256 must be a 64-character hex sha256")
	}
	out.OTACertificateSHA256 = cert

	address, err := NormalizeAddress(r.BootstrapSignerAddress)
	if err != nil {
		return Roots{}, err
	}
	out.BootstrapSignerAddress = address

	hosts, err := NormalizeHosts(r.AppLinksHosts)
	if err != nil {
		return Roots{}, err
	}
	out.AppLinksHosts = hosts

	if !schemePattern.MatchString(r.Scheme) {
		return Roots{}, errors.New("scheme must be 2-32 lowercase letters, digits, . + - starting with a letter")
	}
	if r.Scheme == "http" || r.Scheme == "https" {
		return Roots{}, errors.New("scheme must be a custom scheme, not http or https")
	}
	out.Scheme = r.Scheme

	if !validChannel(r.DistributionChannel) {
		return Roots{}, errors.New("distributionChannel must be one of " + strings.Join(DistributionChannels, ", "))
	}
	out.DistributionChannel = r.DistributionChannel

	if !applicationIDPattern.MatchString(r.ApplicationID) {
		return Roots{}, errors.New("applicationId must match ^[a-z0-9][a-z0-9_-]{1,119}$")
	}
	out.ApplicationID = r.ApplicationID
	return out, nil
}

// Digest = sha256("rn-trust-roots/v1\n" || json.Marshal(Normalize(r)))，小写十六进制。
func Digest(r Roots) (string, error) {
	normalized, err := r.Normalize()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(digestPrefix), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// Equal 比较两份已经规范化的信任根。
func Equal(a, b Roots) bool {
	if a.APIBaseURL != b.APIBaseURL || a.OTACertificateSHA256 != b.OTACertificateSHA256 ||
		a.BootstrapSignerAddress != b.BootstrapSignerAddress || a.Scheme != b.Scheme ||
		a.DistributionChannel != b.DistributionChannel || a.ApplicationID != b.ApplicationID ||
		len(a.AppLinksHosts) != len(b.AppLinksHosts) {
		return false
	}
	for i := range a.AppLinksHosts {
		if a.AppLinksHosts[i] != b.AppLinksHosts[i] {
			return false
		}
	}
	return true
}

// ValidateAPIBaseURL：https 源（scheme + host + 可选端口），无路径、无查询、无尾斜杠，
// host 必须是小写的 DNS 名（不收 IP、不收 localhost）。"原样"比较，所以这里不做任何改写。
func ValidateAPIBaseURL(raw string) error {
	const problem = "apiBaseUrl must be an https origin like https://api.example.com (lowercase host, optional port, no path or trailing slash)"
	if raw == "" || len(raw) > 262 || !printableASCII(raw) || !strings.HasPrefix(raw, "https://") {
		return errors.New(problem)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Path != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" {
		return errors.New(problem)
	}
	if "https://"+u.Host != raw {
		return errors.New(problem)
	}
	host := u.Hostname()
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return errors.New(problem)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New(problem)
	}
	if err := validateDNSName(host); err != nil {
		return errors.New(problem)
	}
	return nil
}

// OTAManifestURL 是由 apiBaseUrl 派生的 updates.url。
func OTAManifestURL(apiBaseURL string) string { return apiBaseURL + OTAManifestPath }

// AppLinksHostFor 按 RN-App 的规则（new URL(apiBaseUrl).host）派生 App Links host，
// 含端口（如果有）。
func AppLinksHostFor(apiBaseURL string) (string, error) {
	if err := ValidateAPIBaseURL(apiBaseURL); err != nil {
		return "", err
	}
	return strings.TrimPrefix(apiBaseURL, "https://"), nil
}

// NormalizeAddress 校验 0x + 40 位十六进制并转小写。
func NormalizeAddress(raw string) (string, error) {
	if !addressPattern.MatchString(raw) {
		return "", errors.New("bootstrapSignerAddress must be 0x followed by 40 hex characters")
	}
	return strings.ToLower(raw), nil
}

// NormalizeHosts 校验每个 host 并排序、去重、转小写。至少一个。
func NormalizeHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 || len(hosts) > MaxAppLinksHosts {
		return nil, fmt.Errorf("appLinksHosts must list 1-%d hosts", MaxAppLinksHosts)
	}
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		if !printableASCII(h) {
			return nil, errors.New("appLinksHosts must be DNS names with an optional port")
		}
		lower := strings.ToLower(h)
		if err := validateHostPort(lower); err != nil {
			return nil, err
		}
		set[lower] = true
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}

func validateHostPort(hostport string) error {
	const problem = "appLinksHosts must be DNS names with an optional port"
	host := hostport
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host = hostport[:i]
		port := hostport[i+1:]
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return errors.New(problem)
		}
	}
	if err := validateDNSName(host); err != nil {
		return errors.New(problem)
	}
	return nil
}

// validateDNSName：至少两段、每段合法、全小写，不是 IP，不是 localhost。
func validateDNSName(host string) error {
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("not a public DNS name")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("not a public DNS name")
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return errors.New("not a public DNS name")
		}
	}
	// 顶级域不能全是数字，否则 1.2.3.4 的变体（如 1.2.3.04）会混过 ParseIP
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return errors.New("not a public DNS name")
	}
	return nil
}

func validChannel(c string) bool {
	for _, v := range DistributionChannels {
		if c == v {
			return true
		}
	}
	return false
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
