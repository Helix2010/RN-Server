package trustroots

import (
	"strings"
	"testing"
)

func anyfun() Roots {
	return Roots{
		APIBaseURL:             "https://api.anyfun.win",
		OTACertificateSHA256:   strings.Repeat("ab", 32),
		BootstrapSignerAddress: "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17",
		AppLinksHosts:          []string{"api.anyfun.win"},
		Scheme:                 "anyfun",
		DistributionChannel:    "direct",
		ApplicationID:          "dex-mobile",
	}
}

// 金标摘要由 Python 按约定 3.4 独立算出：
// sha256("rn-trust-roots/v1\n" + json.dumps(normalized, separators=(",",":")))
func TestDigestGolden(t *testing.T) {
	got, err := Digest(anyfun())
	if err != nil {
		t.Fatal(err)
	}
	const want = "471e44434a0d66443c727a9b0802bbca4843a54f845340bea066555e6d177a2c"
	if got != want {
		t.Fatalf("Digest = %s, want %s", got, want)
	}
}

func TestNormalizeCanonicalizes(t *testing.T) {
	r := anyfun()
	r.AppLinksHosts = []string{"B.example.com", "api.anyfun.win", "b.example.com"}
	r.OTACertificateSHA256 = strings.ToUpper(r.OTACertificateSHA256)
	n, err := r.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(n.AppLinksHosts, ",") != "api.anyfun.win,b.example.com" {
		t.Fatalf("hosts = %v", n.AppLinksHosts)
	}
	if n.BootstrapSignerAddress != strings.ToLower(anyfun().BootstrapSignerAddress) || n.OTACertificateSHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("not lowercased: %+v", n)
	}
	// 规范化后的等价写法摘要相同，改任何一项摘要都变
	base, _ := Digest(anyfun())
	same := anyfun()
	same.BootstrapSignerAddress = strings.ToLower(same.BootstrapSignerAddress)
	same.AppLinksHosts = []string{"API.ANYFUN.WIN", "api.anyfun.win"}
	if d, _ := Digest(same); d != base {
		t.Fatal("equivalent roots produced a different digest")
	}
	for name, mutate := range map[string]func(*Roots){
		"api":     func(r *Roots) { r.APIBaseURL = "https://api2.anyfun.win" },
		"ota":     func(r *Roots) { r.OTACertificateSHA256 = strings.Repeat("cd", 32) },
		"address": func(r *Roots) { r.BootstrapSignerAddress = "0x" + strings.Repeat("1", 40) },
		"hosts":   func(r *Roots) { r.AppLinksHosts = []string{"api.anyfun.win", "evil.example.com"} },
		"scheme":  func(r *Roots) { r.Scheme = "anyfun2" },
		"channel": func(r *Roots) { r.DistributionChannel = "store" },
		"appId":   func(r *Roots) { r.ApplicationID = "dex-mobile2" },
	} {
		r := anyfun()
		mutate(&r)
		d, err := Digest(r)
		if err != nil || d == base {
			t.Errorf("%s: digest unchanged or error %v", name, err)
		}
		n1, _ := anyfun().Normalize()
		n2, _ := r.Normalize()
		if Equal(n1, n2) {
			t.Errorf("%s: Equal reports equal", name)
		}
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := map[string]func(*Roots){
		"http":                func(r *Roots) { r.APIBaseURL = "http://api.anyfun.win" },
		"trailing slash":      func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win/" },
		"path":                func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win/v1" },
		"query":               func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win?x=1" },
		"fragment":            func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win#x" },
		"userinfo":            func(r *Roots) { r.APIBaseURL = "https://user@api.anyfun.win" },
		"uppercase host":      func(r *Roots) { r.APIBaseURL = "https://API.anyfun.win" },
		"ip":                  func(r *Roots) { r.APIBaseURL = "https://127.0.0.1" },
		"ipv6":                func(r *Roots) { r.APIBaseURL = "https://[::1]" },
		"localhost":           func(r *Roots) { r.APIBaseURL = "https://localhost" },
		"bad port":            func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win:0" },
		"empty port":          func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win:" },
		"leading zero port":   func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win:0443" },
		"explicit 443":        func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win:443" },
		"host with 443":       func(r *Roots) { r.AppLinksHosts = []string{"api.anyfun.win:443"} },
		"escape sequence":     func(r *Roots) { r.APIBaseURL = "https://api.anyfun.win\x1b[2J" },
		"non-ascii host":      func(r *Roots) { r.APIBaseURL = "https://аpi.anyfun.win" }, // 西里尔字母 а
		"space":               func(r *Roots) { r.APIBaseURL = " https://api.anyfun.win" },
		"numeric tld":         func(r *Roots) { r.APIBaseURL = "https://1.2.3.04" },
		"ota short":           func(r *Roots) { r.OTACertificateSHA256 = "abcd" },
		"address short":       func(r *Roots) { r.BootstrapSignerAddress = "0x1234" },
		"address missing 0x":  func(r *Roots) { r.BootstrapSignerAddress = strings.Repeat("a", 42) },
		"address empty":       func(r *Roots) { r.BootstrapSignerAddress = "" },
		"no hosts":            func(r *Roots) { r.AppLinksHosts = nil },
		"wildcard host":       func(r *Roots) { r.AppLinksHosts = []string{"*.anyfun.win"} },
		"host with path":      func(r *Roots) { r.AppLinksHosts = []string{"api.anyfun.win/app"} },
		"host with control":   func(r *Roots) { r.AppLinksHosts = []string{"api.anyfun.win\n"} },
		"too many hosts":      func(r *Roots) { r.AppLinksHosts = make([]string, MaxAppLinksHosts+1) },
		"scheme https":        func(r *Roots) { r.Scheme = "https" },
		"scheme uppercase":    func(r *Roots) { r.Scheme = "AnyFun" },
		"scheme single char":  func(r *Roots) { r.Scheme = "a" },
		"channel unknown":     func(r *Roots) { r.DistributionChannel = "sideload" },
		"application id":      func(r *Roots) { r.ApplicationID = "Dex Mobile" },
		"application id long": func(r *Roots) { r.ApplicationID = strings.Repeat("a", 121) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := anyfun()
			mutate(&r)
			_, err := r.Normalize()
			if err == nil {
				t.Fatal("accepted")
			}
			// 错误信息不回显原值（可能含终端控制字符）
			if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), "аpi") {
				t.Fatalf("error echoes the raw value: %q", err)
			}
			if _, err := Digest(r); err == nil {
				t.Fatal("Digest accepted invalid roots")
			}
		})
	}
}

func TestDerivedValues(t *testing.T) {
	if OTAManifestURL("https://api.anyfun.win") != "https://api.anyfun.win/v1/ota/manifest" {
		t.Fatal("OTA manifest URL")
	}
	host, err := AppLinksHostFor("https://api.anyfun.win:8443")
	if err != nil || host != "api.anyfun.win:8443" {
		t.Fatalf("AppLinksHostFor = %q, %v", host, err)
	}
	if _, err := AppLinksHostFor("https://api.anyfun.win/"); err == nil {
		t.Fatal("accepted a trailing slash")
	}
	// 显式默认端口拒绝，而不是改写：否则 AppLinksHostFor 会得出 "api.anyfun.win:443"，
	// 而 RN-App（WHATWG URL）得出 "api.anyfun.win"
	if _, err := AppLinksHostFor("https://api.anyfun.win:443"); err == nil {
		t.Fatal("accepted an explicit default port")
	}
	withPort := anyfun()
	withPort.APIBaseURL = "https://api.anyfun.win:8443"
	withPort.AppLinksHosts = []string{"api.anyfun.win:8443"}
	if _, err := withPort.Normalize(); err != nil {
		t.Fatalf("port rejected: %v", err)
	}
}
