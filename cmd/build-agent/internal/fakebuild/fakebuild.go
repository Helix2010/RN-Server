// Package fakebuild 给构建机的测试造一套假的 pnpm / node：它们不构建任何东西，只按
// RN-App 脚本的约定产出文件，并把自己收到的环境记下来，供测试断言"子进程只拿到白名单"。
//
// 只给测试用。
package fakebuild

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// NativeFingerprint 是假 `pnpm exec fingerprint .` 打印的哈希。
const NativeFingerprint = "0123456789abcdef0123456789abcdef01234567"

// 假 .ipa 里 Info.plist 写的身份。与 harness 的 claimBody 一致：控制进程会自己读一遍包，
// 对不上就不交付，也不上传。
const (
	IPABundleID     = "com.anyfun.foundation"
	IPAShortVersion = "1.3.7"
	IPABuildNumber  = "33"
)

// XcodeVersion 是假 xcodebuild 打印的版本。
const XcodeVersion = "Xcode 16.2"

// IPAWithIdentity 造一个形状正确的 .ipa：一个 zip，里面是 Payload/<App>.app/Info.plist。
// 控制进程用 archive/zip + 自带的 plist 解析器读它，所以这里必须是真的 zip。
func IPAWithIdentity(t *testing.T, bundleID, shortVersion, buildNumber string) []byte {
	t.Helper()
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	entry, err := archive.Create("Payload/AnyFun.app/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>` + bundleID + `</string>
	<key>CFBundleShortVersionString</key><string>` + shortVersion + `</string>
	<key>CFBundleVersion</key><string>` + buildNumber + `</string>
</dict>
</plist>`
	if _, err := entry.Write([]byte(plist)); err != nil {
		t.Fatal(err)
	}
	// App 里的扩展也有一份 Info.plist，而它的 bundle id 是 `<主 id>.<后缀>`：
	// 放一份进来，守住"只认恰好三段路径"那条规则
	extension, err := archive.Create("Payload/AnyFun.app/PlugIns/Share.appex/Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extension.Write([]byte(strings.Replace(plist, bundleID, bundleID+".share", 1))); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// CertificatePEM 是一张形状正确的假证书（正文三行以上、每行 64 字符）。
var CertificatePEM = "-----BEGIN CERTIFICATE-----\n" +
	"MIIBszCCAVmgAwIBAgIUQ2VydGlmaWNhdGVGb3JUZXN0aW5nT25seTAKBggqhkjO\n" +
	"PQQDAjAUMRIwEAYDVQQDDAlybi10ZXN0LWNhMB4XDTI2MDkxNjAwMDAwMFoXDTM2\n" +
	"MDkxNjAwMDAwMFowFDESMBAGA1UEAwwJcm4tdGVzdC1jYTBZMBMGByqGSM49AgEG\n" +
	"-----END CERTIFICATE-----\n"

// Tools 是一套假工具。
type Tools struct {
	Bin string
	// Record 下每一步子进程的环境：<Record>/<step>.env
	Record string
	// Sleep 存在时，假 pnpm install 睡文件里写的秒数（空文件是 120 秒，用来测中止）
	Sleep string
	// Linger 存在时，假 pnpm install 留下一个握着标准输出的后台进程（睡 1800 秒），PID 写进 <Record>/linger.pid
	Linger string
	// APK、OTA 与 IPA 是假产物的内容
	APK []byte
	OTA []byte
	IPA []byte
}

// Install 在 dir 下造出 bin/pnpm、bin/node 与记录目录。
func Install(t *testing.T, dir string) Tools {
	t.Helper()
	tools := Tools{
		Bin:    filepath.Join(dir, "bin"),
		Record: filepath.Join(dir, "record"),
		Sleep:  filepath.Join(dir, "sleep-on-install"),
		Linger: filepath.Join(dir, "linger-on-install"),
		APK:    APKWithCertificate(t, CertificatePEM),
		OTA:    []byte("PK\x05\x06" + strings.Repeat("\x00", 18)),
		// .ipa 是真的 zip：控制进程会打开它读 Info.plist，核对身份之后才交给上传账户
		IPA: IPAWithIdentity(t, IPABundleID, IPAShortVersion, IPABuildNumber),
	}
	for _, d := range []string{tools.Bin, tools.Record} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	apkFixture := filepath.Join(dir, "fixture.apk")
	otaFixture := filepath.Join(dir, "fixture-ota.zip")
	ipaFixture := filepath.Join(dir, "fixture.ipa")
	if err := os.WriteFile(apkFixture, tools.APK, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otaFixture, tools.OTA, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipaFixture, tools.IPA, 0o644); err != nil {
		t.Fatal(err)
	}
	pnpm := fmt.Sprintf(`#!/bin/sh
set -eu
record() { env > %[1]q/"$1".env; id -u > %[1]q/"$1".uid; }
case "$1" in
install)
  record install
  if [ -e %[2]q ]; then seconds=$(cat %[2]q); sleep "${seconds:-120}"; fi
  if [ -e %[6]q ]; then sleep 1800 & echo $! > %[1]q/linger.pid; fi
  mkdir -p node_modules
  ;;
exec)
  record fingerprint
  echo "progress on stderr" >&2
  printf '{"hash":"%[3]s","sources":[]}\n'
  ;;
android:release)
  record android-release
  version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "tenants/$2/tenant.json")
  code=$(sed -n 's/.*"androidVersionCode": *\([0-9]*\).*/\1/p' "tenants/$2/tenant.json")
  mkdir -p artifacts
  cp %[4]q "artifacts/$2-$version-build$code-release-unsigned.apk"
  echo "Android unsigned release APK written"
  ;;
ios:release)
  record ios-release
  shift
  slug="$1"; shift
  # 执行进程不再传 --upload（它没有任何 App Store Connect Key）；--signing-dir 是手工签名
  # 要用的描述文件目录
  signing=""; profiles=""; certificate=""
  while [ $# -gt 0 ]; do
    if [ "$1" = "--signing-dir" ]; then signing="$2"; fi
    if [ "$1" = "--profiles-dir" ]; then profiles="$2"; fi
    if [ "$1" = "--signing-certificate" ]; then certificate="$2"; fi
    if [ "$1" = "--upload" ]; then echo "fake pnpm: ios:release must not be given --upload" >&2; exit 4; fi
    shift
  done
  echo "$signing" > %[1]q/ios-signing-dir.txt
  echo "$profiles" > %[1]q/ios-profiles-dir.txt
  echo "$certificate" > %[1]q/ios-signing-certificate.txt
  version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "tenants/$slug/tenant.json")
  build=$(sed -n 's/.*"iosBuildNumber": *"\([^"]*\)".*/\1/p' "tenants/$slug/tenant.json")
  mkdir -p artifacts
  cp %[7]q "artifacts/$slug-$version-build$build.ipa"
  echo "iOS release IPA written"
  ;;
ota:build)
  record ota-build
  out=""
  while [ $# -gt 0 ]; do
    if [ "$1" = "--output-zip" ]; then out="$2"; fi
    shift
  done
  git rev-parse HEAD > %[1]q/ota-commit.txt
  cp %[5]q "$out"
  ;;
*)
  echo "fake pnpm: unexpected $*" >&2
  exit 3
  ;;
esac
`, tools.Record, tools.Sleep, NativeFingerprint, apkFixture, otaFixture, tools.Linger, ipaFixture)
	node := fmt.Sprintf(`#!/bin/sh
set -eu
env > %[1]q/sbom.env
apk=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
  --apk) apk="$2"; shift ;;
  --out) out="$2"; shift ;;
  esac
  shift
done
sum=$(sha256sum "$apk" | cut -d' ' -f1)
name=$(basename "$apk")
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"type":"application","hashes":[{"alg":"SHA-256","content":"%%s"}]},"properties":[{"name":"rn-app:artifact","value":"%%s"},{"name":"rn-app:artifact-signing","value":"unsigned"}]},"components":[]}\n' "$sum" "$name" > "$out"
`, tools.Record)
	// security：只把收到的命令记下来，不碰任何钥匙串。真机上这一步要真跑
	security := fmt.Sprintf(`#!/bin/sh
set -eu
cat > %[1]q/security.stdin
printf '%%s\n' "$*" > %[1]q/security.args
`, tools.Record)
	xcodebuild := fmt.Sprintf(`#!/bin/sh
set -eu
echo "%s"
echo "Build version 16C5032a"
`, XcodeVersion)
	for name, body := range map[string]string{"pnpm": pnpm, "node": node, "security": security, "xcodebuild": xcodebuild} {
		if err := os.WriteFile(filepath.Join(tools.Bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return tools
}

// PATH 返回假工具在前、系统工具在后的 PATH。
func (tools Tools) PATH() string { return tools.Bin + ":/usr/bin:/bin" }

// RecordedEnv 读回某一步记下的环境，去掉 sh 自己加的变量，按行排序。
func (tools Tools) RecordedEnv(t *testing.T, step string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tools.Record, step+".env"))
	if err != nil {
		t.Fatalf("step %s recorded no environment: %v", step, err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		key, _, _ := strings.Cut(line, "=")
		switch key {
		case "PWD", "SHLVL", "_", "OLDPWD":
			continue
		}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

// APKWithCertificate 造一个只含 AndroidManifest 占位与证书正文的 zip。
func APKWithCertificate(t *testing.T, certificatePEM string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	entry, err := w.Create("assets/ota-certificate.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(certificatePEM)); err != nil {
		t.Fatal(err)
	}
	manifest, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.Write([]byte("placeholder")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Git 在 dir 里跑 git，失败即 Fatal。
func Git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := gitCommand(dir, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// SourceRepo 造一个 RN-App 形状的最小仓库（build-sbom.mjs、四张图标），克隆成镜像裸库，
// 返回裸库路径与 main 的提交。
func SourceRepo(t *testing.T, root, tenantDirectory string) (bare, commit string) {
	t.Helper()
	source := filepath.Join(root, "source")
	bare = filepath.Join(root, "rn-app.git")
	files := map[string]string{
		"package.json":            `{"name":"fake-rn-app"}`,
		"scripts/build-sbom.mjs":  "// fake",
		"scripts/build-ota.mjs":   "// fake",
		"tenants/.keep":           "",
		"assets/tenants/.keep":    "",
		"gradle/placeholder.txt":  "x",
		"android-icon-readme.txt": "icons live under assets/tenants/<dir>/",
	}
	for _, icon := range []string{"icon.png", "android-icon-foreground.png", "android-icon-background.png", "android-icon-monochrome.png"} {
		files["assets/tenants/"+tenantDirectory+"/"+icon] = "png"
	}
	for name, content := range files {
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	Git(t, source, "init", "-q", "-b", "main")
	Git(t, source, "add", ".")
	Git(t, source, "commit", "-qm", "first")
	Git(t, root, "clone", "-q", "--mirror", source, bare)
	commit = Git(t, bare, "rev-parse", "refs/heads/main")
	return bare, commit
}
