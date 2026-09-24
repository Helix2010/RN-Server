package machinesetup

// 两条系统级设置是 2026-09-23 在 mac-01 上一路查出来、先手工补上的（实现文档「mac-01 上手工
// 做的两条系统级设置」）：
//
//  1. LaunchDaemon 会话里 Security 框架只读**系统域**的钥匙串搜索列表，用户域设了也没用，
//     Xcode 因此找不到签名证书；
//  2. 签名钥匙串里的 WWDR G3 中间证书信任评估不用，要装进系统钥匙串，否则每次都靠联网现取。
//
// 这里把两个函数单独拉出来跑，/usr/bin/security 换成桩：系统域列表存在一个文件里，
// 系统钥匙串里有没有那张证书用一个标记文件表示。

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type signingRig struct {
	dir, bundle, searchList, certMarker, calls string
}

func newSigningRig(t *testing.T, initialSearchList string) signingRig {
	t.Helper()
	dir := t.TempDir()
	rig := signingRig{
		dir:        dir,
		bundle:     filepath.Join(dir, "bundle"),
		searchList: filepath.Join(dir, "system-search-list"),
		certMarker: filepath.Join(dir, "wwdr-installed"),
		calls:      filepath.Join(dir, "security.calls"),
	}
	for _, sub := range []string{"bin", "bundle"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, rig.searchList, initialSearchList, 0o644)

	body := string(InstallMacOSScript)
	const security = "/usr/bin/security"
	if !strings.Contains(body, security) {
		t.Fatalf("install-macos.sh no longer calls %s; this test swaps it for a stub", security)
	}
	body = strings.ReplaceAll(body, security, filepath.Join(dir, "bin/security"))
	body = strings.Replace(body, "\nmain \"$@\"\nexit\n", "\n", 1)
	write(t, filepath.Join(dir, "lib.sh"), body, 0o700)

	// security 的桩：只实现这两个函数用到的三种调用，照真 security 的输出格式
	// （列表每行缩进四格、带引号；证书已在时 add-certificates 报 already exists 并非零退出）。
	write(t, filepath.Join(dir, "bin/security"), `#!/bin/bash
printf '%s\n' "$*" >>"`+rig.calls+`"
case "$1 $2 $3" in
  "list-keychains -d system")
    if [ "$#" -eq 3 ]; then
      while IFS= read -r k; do [ -n "$k" ] && printf '    "%s"\n' "$k"; done <"`+rig.searchList+`"
      exit 0
    fi
    [ "$4" = -s ] || { echo "stub security: unexpected args: $*" >&2; exit 64; }
    shift 4
    printf '%s\n' "$@" >"`+rig.searchList+`"
    exit 0 ;;
esac
if [ "$1" = add-certificates ] && [ "$2" = -k ]; then
  if [ -e "`+rig.certMarker+`" ]; then
    echo "security: SecCertificateAddToKeychain: The specified item already exists in the keychain." >&2
    exit 48
  fi
  : >"`+rig.certMarker+`"
  exit 0
fi
echo "stub security: unexpected args: $*" >&2
exit 64
`, 0o755)
	return rig
}

func (r signingRig) putCert(t *testing.T, content string) {
	t.Helper()
	write(t, filepath.Join(r.bundle, "AppleWWDRCAG3.cer"), content, 0o644)
}

// run 调一个函数。WWDR_G3_SHA256 是 readonly，测试里要换成桩证书的摘要，
// 所以在 source 之前把那一行改掉。
func (r signingRig) run(t *testing.T, certSHA256, call string) (string, bool) {
	t.Helper()
	lib := filepath.Join(r.dir, "lib.sh")
	raw, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "readonly WWDR_G3_SHA256=dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f"
	if !strings.Contains(string(raw), pinned) {
		t.Fatal("install-macos.sh no longer pins the WWDR G3 digest this test expects")
	}
	patched := strings.Replace(string(raw), pinned, "readonly WWDR_G3_SHA256="+certSHA256, 1)
	write(t, filepath.Join(r.dir, "lib-test.sh"), patched, 0o700)
	out, err := runBash(t, `set -u
. "`+r.dir+`/lib-test.sh"
BUNDLE="`+r.bundle+`"
`+call+"\n")
	return out, err == nil
}

func (r signingRig) list(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(r.searchList)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestMacInstallPutsTheSigningKeychainOnTheSystemSearchList(t *testing.T) {
	rig := newSigningRig(t, "/Library/Keychains/System.keychain\n")
	call := "ensure_system_keychain_search_list /var/rn-build-signing/rn-signing.keychain-db"
	out, ok := rig.run(t, digest("x"), call)
	if !ok {
		t.Fatalf("failed:\n%s", out)
	}
	want := []string{"/Library/Keychains/System.keychain", "/var/rn-build-signing/rn-signing.keychain-db"}
	if got := rig.list(t); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("system search list = %v, want %v (existing entries kept, signing keychain appended)", got, want)
	}

	// 第二趟：security 回读的是解析过符号链接的 /private/var/…，也要认出来，不能再加一遍
	write(t, rig.searchList, "/Library/Keychains/System.keychain\n/private/var/rn-build-signing/rn-signing.keychain-db\n", 0o644)
	if out, ok := rig.run(t, digest("x"), call); !ok || !strings.Contains(out, "已在系统域") {
		t.Fatalf("second run should be a no-op:\n%s", out)
	}
	if got := rig.list(t); len(got) != 2 {
		t.Fatalf("the second run changed the list: %v", got)
	}
}

func TestMacInstallKeepsOtherSystemKeychains(t *testing.T) {
	rig := newSigningRig(t, "/Library/Keychains/System.keychain\n/Library/Keychains/Other.keychain\n")
	if out, ok := rig.run(t, digest("x"), "ensure_system_keychain_search_list /var/rn-build-signing/rn-signing.keychain-db"); !ok {
		t.Fatalf("failed:\n%s", out)
	}
	want := "/Library/Keychains/System.keychain /Library/Keychains/Other.keychain /var/rn-build-signing/rn-signing.keychain-db"
	if got := strings.Join(rig.list(t), " "); got != want {
		t.Fatalf("system search list = %s, want %s", got, want)
	}
}

func TestMacInstallFallsBackToTheSystemKeychainOnAnEmptyList(t *testing.T) {
	rig := newSigningRig(t, "")
	if out, ok := rig.run(t, digest("x"), "ensure_system_keychain_search_list /var/rn-build-signing/rn-signing.keychain-db"); !ok {
		t.Fatalf("failed:\n%s", out)
	}
	want := "/Library/Keychains/System.keychain /var/rn-build-signing/rn-signing.keychain-db"
	if got := strings.Join(rig.list(t), " "); got != want {
		t.Fatalf("system search list = %s, want %s", got, want)
	}
}

func TestMacInstallAddsTheWWDRIntermediateOnceAndToleratesARerun(t *testing.T) {
	rig := newSigningRig(t, "")
	rig.putCert(t, "stub certificate")
	out, ok := rig.run(t, digest("stub certificate"), "ensure_wwdr_intermediate")
	if !ok {
		t.Fatalf("failed:\n%s", out)
	}
	if _, err := os.Stat(rig.certMarker); err != nil {
		t.Fatal("the certificate was not added to the system keychain")
	}
	calls, _ := os.ReadFile(rig.calls)
	if !strings.Contains(string(calls), "add-certificates -k /Library/Keychains/System.keychain "+rig.bundle+"/AppleWWDRCAG3.cer") {
		t.Fatalf("expected an add into the system keychain, calls:\n%s", calls)
	}
	// 再跑一次：security 说 already exists，这不是失败
	if out, ok := rig.run(t, digest("stub certificate"), "ensure_wwdr_intermediate"); !ok || !strings.Contains(out, "已在系统钥匙串") {
		t.Fatalf("a rerun must treat 'already exists' as done:\n%s", out)
	}
}

func TestMacInstallRefusesAWWDRCertificateWithTheWrongDigest(t *testing.T) {
	rig := newSigningRig(t, "")
	rig.putCert(t, "not the certificate we pinned")
	out, ok := rig.run(t, digest("stub certificate"), "ensure_wwdr_intermediate")
	if ok {
		t.Fatalf("a certificate with the wrong digest was accepted:\n%s", out)
	}
	if _, err := os.Stat(rig.certMarker); err == nil {
		t.Fatal("the wrong certificate was added anyway")
	}
}

// 旧安装包里没有这张证书：告诉人怎么手工补，但不拦住装机（机器照样能用，只是验证书要联网）。
func TestMacInstallExplainsAMissingWWDRCertificate(t *testing.T) {
	rig := newSigningRig(t, "")
	out, ok := rig.run(t, digest("x"), "ensure_wwdr_intermediate")
	if !ok || !strings.Contains(out, "security add-certificates") {
		t.Fatalf("a bundle without the certificate should warn with the manual fix and carry on:\n%s", out)
	}
}

// 仓库里放的就是钉死的那一张：换证书时两处要一起改。
func TestBundledWWDRCertificateMatchesThePinnedDigest(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/build-agent-macos/AppleWWDRCAG3.cer")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); !strings.Contains(string(InstallMacOSScript), "readonly WWDR_G3_SHA256="+got) {
		t.Fatalf("deploy/build-agent-macos/AppleWWDRCAG3.cer has sha256 %s, which install-macos.sh does not pin", got)
	}
}
