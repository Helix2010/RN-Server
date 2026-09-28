package main

// 按租户落盘的材料：租户自己交，这台 Mac 是最后一道关（设计 ios-tenant-owned-signing-material-2026-09-25 §4.2）。
//
// 钥匙串用一个 Go 写的假 security 模拟：临时钥匙串、签名钥匙串、find-identity、导入、删身份。
// 真 security 只有 Mac 上有，而这里要盯的是核对的判断与引用计数，那在哪儿都该是对的。

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const (
	tenantA = "1000000001"
	tenantB = "1000000002"
)

var testNow = time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)

// testCA 是测试里的「WWDR」：现生成的根，签出几张假的分发证书。
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: testNow.AddDate(-1, 0, 0), NotAfter: testNow.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key}
}

type leafOptions struct {
	commonName string
	team       string
	notAfter   time.Time
}

// leaf 签一张分发证书。带一个 Apple 的 critical 私有扩展：真证书就有，Go 的 Verify 不剥掉它会拒。
func (ca testCA) leaf(t *testing.T, serial int64, options leafOptions) []byte {
	t.Helper()
	if options.commonName == "" {
		options.commonName = "Apple Distribution: Test Co (" + testTeam + ")"
	}
	if options.team == "" {
		options.team = testTeam
	}
	if options.notAfter.IsZero() {
		options.notAfter = testNow.AddDate(1, 0, 0)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: options.commonName, OrganizationalUnit: []string{options.team}},
		NotBefore:    testNow.AddDate(0, -1, 0), NotAfter: options.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 4}, Critical: true, Value: []byte{0x05, 0x00},
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func derSHA1(der []byte) string {
	digest := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}

// fakeSecurity 是一台 Mac 上的钥匙串。「.p12」在测试里就是证书 DER：导入即把它放进那个钥匙串。
type fakeSecurity struct {
	keychains map[string][][]byte
	// invalid 里的 SHA-1 在 find-identity -v 里不出现（过期、吊销、链不到 WWDR）
	invalid map[string]bool
	// importFails 非空时每次 import 都以这句话失败（口令不对之类）
	importFails string
	calls       []string
	stdin       []string
}

var findIdentityPattern = regexp.MustCompile(`find-identity (-v )?-p codesigning (\S+)`)

func installFakeSecurity(t *testing.T) *fakeSecurity {
	t.Helper()
	fake := &fakeSecurity{keychains: map[string][][]byte{}, invalid: map[string]bool{}}
	restoreRun, restoreNow, restoreAnchors := securityRun, runnerNow, trustAnchors
	securityRun = fake.run
	runnerNow = func() time.Time { return testNow }
	t.Cleanup(func() { securityRun, runnerNow, trustAnchors = restoreRun, restoreNow, restoreAnchors })
	return fake
}

func (f *fakeSecurity) run(_ context.Context, stdin string, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	f.stdin = append(f.stdin, stdin)
	switch args[0] {
	case "-i":
		var out strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(stdin), "\n") {
			fields := strings.Fields(line)
			switch {
			case len(fields) == 0:
			case fields[0] == "create-keychain":
				f.keychains[fields[len(fields)-1]] = nil
			case fields[0] == "find-identity":
				match := findIdentityPattern.FindStringSubmatch(line)
				for i, der := range f.keychains[match[2]] {
					if match[1] != "" && f.invalid[derSHA1(der)] {
						continue
					}
					cert, _ := x509.ParseCertificate(der)
					fmt.Fprintf(&out, "  %d) %s \"%s\"\n", i+1, derSHA1(der), cert.Subject.CommonName)
				}
			}
		}
		return out.String(), nil
	case "import":
		if f.importFails != "" {
			return "", fmt.Errorf("exit status 1: %s", f.importFails)
		}
		der, err := os.ReadFile(args[1])
		if err != nil {
			return "", err
		}
		keychain := args[3]
		for _, held := range f.keychains[keychain] {
			if bytes.Equal(held, der) {
				return "", fmt.Errorf("exit status 1: The specified item already exists in the keychain.")
			}
		}
		f.keychains[keychain] = append(f.keychains[keychain], der)
		return "", nil
	case "find-certificate":
		var out bytes.Buffer
		for _, der := range f.keychains[args[len(args)-1]] {
			_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		return out.String(), nil
	case "delete-keychain":
		delete(f.keychains, args[1])
		return "", nil
	case "delete-identity":
		keychain, want := args[len(args)-1], args[2]
		kept := [][]byte{}
		found := false
		for _, der := range f.keychains[keychain] {
			if derSHA1(der) == want {
				found = true
				continue
			}
			kept = append(kept, der)
		}
		f.keychains[keychain] = kept
		if !found {
			return "", fmt.Errorf("exit status 44: The specified item could not be found in the keychain.")
		}
		return "", nil
	}
	return "", fmt.Errorf("the fake security does not know %q", args[0])
}

// mainHashes 是签名钥匙串里的身份。
func (f *fakeSecurity) mainHashes(dir string) []string {
	out := []string{}
	for _, der := range f.keychains[filepath.Join(dir, jobspec.IOSKeychainFileName)] {
		out = append(out, derSHA1(der))
	}
	sort.Strings(out)
	return out
}

func (f *fakeSecurity) importsInto(keychain string) int {
	count := 0
	for _, call := range f.calls {
		if strings.HasPrefix(call, "import ") && strings.Contains(call, " -k "+keychain+" ") {
			count++
		}
	}
	return count
}

// tenantFixture 是一个签名区加上一个装着 WWDR 假根的信任锚。
func tenantFixture(t *testing.T) (dir string, pub []byte, fake *fakeSecurity, ca testCA) {
	t.Helper()
	dir, pub = materialFixture(t)
	fake = installFakeSecurity(t)
	fake.keychains[filepath.Join(dir, jobspec.IOSKeychainFileName)] = nil
	ca = newTestCA(t, "Test WWDR G3")
	trustAnchors = func() ([]*x509.Certificate, error) { return []*x509.Certificate{ca.cert}, nil }
	return dir, pub, fake, ca
}

func tenantCertificate(tenant string, der []byte) iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindCertificate, TenantID: tenant, TeamID: testTeam,
		P12Base64: base64.StdEncoding.EncodeToString(der), P12Password: "tenant chosen password",
	}
}

func installAs(t *testing.T, dir, box string, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"install-ios-material", "--signing-dir", dir}, extra...)
	return runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box), args...)
}

func readIndex(t *testing.T, dir string) map[string]string {
	t.Helper()
	index, err := readTenantCertificates(dir)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

// 两个租户交同一张证书：只导入一次、两个租户都记进索引；临时钥匙串与落盘的 .p12 都不留下。
func TestTenantCertificateIsCheckedAndImportedOnce(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	der := ca.leaf(t, 2, leafOptions{})
	for _, tenant := range []string{tenantA, tenantB} {
		code, out := installAs(t, dir, sealed(t, tenantCertificate(tenant, der), pub), "--tenant", tenant)
		if code != 0 {
			t.Fatalf("tenant %s: exit %d: %s", tenant, code, out)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil || result["certificateSha1"] != derSHA1(der) {
			t.Fatalf("the result does not name the identity: %s", out)
		}
	}
	main := filepath.Join(dir, jobspec.IOSKeychainFileName)
	if got := fake.importsInto(main); got != 1 {
		t.Fatalf("the same certificate was imported %d times into the signing keychain", got)
	}
	index := readIndex(t, dir)
	if index[tenantA+"/"+testTeam] != derSHA1(der) || index[tenantB+"/"+testTeam] != derSHA1(der) {
		t.Fatalf("index %v", index)
	}
	for keychain := range fake.keychains {
		if keychain != main {
			t.Errorf("a scratch keychain was left behind: %s", keychain)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".p12") || strings.HasPrefix(entry.Name(), ".verify-") {
			t.Errorf("left on disk: %s", entry.Name())
		}
	}
	info, err := os.Stat(filepath.Join(dir, jobspec.IOSTenantCertificatesFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the index must be 0600: %v %v", info, err)
	}
	// 口令只走标准输入，不进命令行
	for _, call := range fake.calls {
		if strings.Contains(call, "keychain-password") {
			t.Errorf("the keychain password reached a command line: %s", call)
		}
	}
}

// 不合格的一律不装：签名钥匙串、索引都不动，原因带着 rejected: 前缀交给控制进程。
func TestTenantCertificateRefusals(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	other := newTestCA(t, "Someone else's CA")
	cases := map[string]struct {
		material iosmaterial.Material
		flags    []string
		invalid  bool
		want     string
	}{
		"another team":     {tenantCertificate(tenantA, ca.leaf(t, 3, leafOptions{team: "ZZ99YY88XX"})), nil, false, "belongs to Team ZZ99YY88XX"},
		"development cert": {tenantCertificate(tenantA, ca.leaf(t, 4, leafOptions{commonName: "Apple Development: Someone (J4JDFC8LCC)"})), nil, false, "not an Apple Distribution certificate"},
		"expired":          {tenantCertificate(tenantA, ca.leaf(t, 5, leafOptions{notAfter: testNow.AddDate(0, 0, -1)})), nil, false, "expired"},
		"another chain":    {tenantCertificate(tenantA, other.leaf(t, 6, leafOptions{})), nil, false, "does not chain"},
		"macOS says no":    {tenantCertificate(tenantA, ca.leaf(t, 7, leafOptions{})), nil, true, "no valid code-signing identity"},
		"tenant mismatch":  {tenantCertificate(tenantB, ca.leaf(t, 8, leafOptions{})), nil, false, "belongs to tenant " + tenantB},
		"v1 without legacy": {func() iosmaterial.Material {
			m := tenantCertificate("", ca.leaf(t, 9, leafOptions{}))
			return m
		}(), nil, false, "version 1"},
	}
	for name, c := range cases {
		if c.invalid {
			der, _ := base64.StdEncoding.DecodeString(c.material.P12Base64)
			fake.invalid[derSHA1(der)] = true
		}
		args := append([]string{"--tenant", tenantA}, c.flags...)
		code, out := installAs(t, dir, sealed(t, c.material, pub), args...)
		if code != exitFailed {
			t.Errorf("%s: exit %d: %s", name, code, out)
			continue
		}
		if !strings.Contains(out, errorPrefix+rejectedPrefix) || !strings.Contains(out, c.want) {
			t.Errorf("%s: the refusal does not say why, or is not marked rejected: %s", name, out)
		}
	}
	if held := fake.mainHashes(dir); len(held) != 0 {
		t.Fatalf("a refused certificate reached the signing keychain: %v", held)
	}
	if index := readIndex(t, dir); len(index) != 0 {
		t.Fatalf("a refused certificate reached the index: %v", index)
	}
	for keychain := range fake.keychains {
		if keychain != filepath.Join(dir, jobspec.IOSKeychainFileName) {
			t.Errorf("a scratch keychain was left behind after a refusal: %s", keychain)
		}
	}
}

// 口令不对之类的导入失败，报出来的原因里不能带着口令。
func TestTenantCertificateImportFailureDoesNotEchoThePassword(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	material := tenantCertificate(tenantA, ca.leaf(t, 2, leafOptions{}))
	fake.importFails = "MAC verification failed during PKCS12 import (wrong password?) tenant chosen password"
	code, out := installAs(t, dir, sealed(t, material, pub), "--tenant", tenantA)
	if code == 0 || !strings.Contains(out, rejectedPrefix) {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "tenant chosen password") {
		t.Fatalf("the .p12 password reached the output: %s", out)
	}
}

// 迁移过来的 v1 只在清单标了 legacy 时才收；带租户的 v2 不能落进旧布局。
func TestLegacyAndTenantMaterialStayInTheirOwnLayout(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	der := ca.leaf(t, 2, leafOptions{})
	legacy := sealed(t, tenantCertificate("", der), pub)
	if code, out := installAs(t, dir, legacy, "--tenant", tenantA, "--legacy"); code != 0 {
		t.Fatalf("a legacy slot's v1 certificate was refused: %s", out)
	}
	if readIndex(t, dir)[tenantA+"/"+testTeam] != derSHA1(der) {
		t.Fatal("the legacy certificate was not indexed for the tenant")
	}
	if code, out := installAs(t, dir, sealed(t, tenantCertificate(tenantB, der), pub)); code != exitUsage || !strings.Contains(out, "--tenant") {
		t.Fatalf("a tenant's material was accepted into the per-team layout: %d %s", code, out)
	}
	if code, out := installAs(t, dir, legacy, "--legacy"); code != exitUsage {
		t.Fatalf("--legacy without --tenant was accepted: %d %s", code, out)
	}
	if code, _ := installAs(t, dir, legacy, "--tenant", "../1"); code != exitUsage {
		t.Fatal("a tenant id that is a path was accepted")
	}
	_ = fake
}

// 换证书：旧的那张没有租户再用就从钥匙串撤掉；别的租户还在用就留着。
func TestReplacingACertificateCountsReferences(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	first, second := ca.leaf(t, 2, leafOptions{}), ca.leaf(t, 3, leafOptions{})
	for _, step := range []struct {
		tenant string
		der    []byte
	}{{tenantA, first}, {tenantB, first}, {tenantA, second}} {
		if code, out := installAs(t, dir, sealed(t, tenantCertificate(step.tenant, step.der), pub), "--tenant", step.tenant); code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
	}
	held := fake.mainHashes(dir)
	if strings.Join(held, ",") != strings.Join(sortedStrings(derSHA1(first), derSHA1(second)), ",") {
		t.Fatalf("the first certificate is still used by tenant B and must stay: %v", held)
	}
	if code, out := installAs(t, dir, sealed(t, tenantCertificate(tenantB, second), pub), "--tenant", tenantB); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if held := fake.mainHashes(dir); strings.Join(held, ",") != derSHA1(second) {
		t.Fatalf("nobody uses the first certificate any more; it must leave the keychain: %v", held)
	}
}

func sortedStrings(values ...string) []string {
	sort.Strings(values)
	return values
}

// tenantProfileBytes 造一份描述文件：DeveloperCertificates 里放给定的证书。
func tenantProfileBytes(team, bundle string, expires time.Time, certificates [][]byte, extra string) []byte {
	var data strings.Builder
	for _, der := range certificates {
		data.WriteString("<data>" + base64.StdEncoding.EncodeToString(der) + "</data>")
	}
	return []byte("\x30\x82cms<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>" +
		"<key>ExpirationDate</key><date>" + expires.UTC().Format(time.RFC3339) + "</date>" +
		"<key>TeamIdentifier</key><array><string>" + team + "</string></array>" +
		"<key>DeveloperCertificates</key><array>" + data.String() + "</array>" +
		"<key>Entitlements</key><dict><key>application-identifier</key><string>" + team + "." + bundle + "</string></dict>" +
		extra + "</dict></plist>\x00sig")
}

func tenantProfile(tenant string, body []byte) iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TenantID: tenant, TeamID: testTeam, BundleID: "com.anyfun.foundation",
		ProfileBase64: base64.StdEncoding.EncodeToString(body),
	}
}

func TestTenantProfileIsCheckedAgainstTheTenantsCertificate(t *testing.T) {
	dir, pub, _, ca := tenantFixture(t)
	der := ca.leaf(t, 2, leafOptions{})
	expires := testNow.AddDate(0, 6, 0)
	good := tenantProfileBytes(testTeam, "com.anyfun.foundation", expires, [][]byte{der}, "")

	// 证书还没装：不算不合格（没有 rejected: 前缀），下一轮再试
	code, out := installAs(t, dir, sealed(t, tenantProfile(tenantA, good), pub), "--tenant", tenantA)
	if code == 0 || strings.Contains(out, rejectedPrefix) || !strings.Contains(out, "not installed on this machine yet") {
		t.Fatalf("a profile that arrived before its certificate: %d %s", code, out)
	}
	if code, out := installAs(t, dir, sealed(t, tenantCertificate(tenantA, der), pub), "--tenant", tenantA); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if code, out := installAs(t, dir, sealed(t, tenantProfile(tenantA, good), pub), "--tenant", tenantA); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	path := filepath.Join(dir, jobspec.IOSProfilesDirName, jobspec.IOSTenantsDirName, tenantA, testTeam, "com.anyfun.foundation"+jobspec.IOSProfileSuffix)
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, good) {
		t.Fatalf("the profile is not in the tenant's directory: %v", err)
	}

	for name, c := range map[string]struct {
		body []byte
		want string
	}{
		"another certificate": {tenantProfileBytes(testTeam, "com.anyfun.foundation", expires, [][]byte{ca.leaf(t, 9, leafOptions{})}, ""), "does not include the tenant's certificate"},
		"another bundle":      {tenantProfileBytes(testTeam, "com.anyfun.other", expires, [][]byte{der}, ""), "is for J4JDFC8LCC.com.anyfun.other"},
		"expired":             {tenantProfileBytes(testTeam, "com.anyfun.foundation", testNow.AddDate(0, 0, -1), [][]byte{der}, ""), "expired"},
		"ad hoc":              {tenantProfileBytes(testTeam, "com.anyfun.foundation", expires, [][]byte{der}, "<key>ProvisionedDevices</key><array><string>00008030</string></array>"), "lists devices"},
		"enterprise":          {tenantProfileBytes(testTeam, "com.anyfun.foundation", expires, [][]byte{der}, "<key>ProvisionsAllDevices</key><true/>"), "enterprise"},
		"not a profile":       {[]byte("hello"), "not a provisioning profile"},
	} {
		code, out := installAs(t, dir, sealed(t, tenantProfile(tenantA, c.body), pub), "--tenant", tenantA)
		if code == 0 || !strings.Contains(out, rejectedPrefix) || !strings.Contains(out, c.want) {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
	// 没通过的那几份一份都没替换掉已经装好的
	if got, _ := os.ReadFile(path); !bytes.Equal(got, good) {
		t.Fatal("a refused profile replaced the installed one")
	}
}

// 墓碑：撤描述文件删文件；撤证书删索引项，钥匙串里的身份没人用了才删。
func TestRemoveTenantMaterial(t *testing.T) {
	dir, pub, fake, ca := tenantFixture(t)
	der := ca.leaf(t, 2, leafOptions{})
	for _, tenant := range []string{tenantA, tenantB} {
		if code, out := installAs(t, dir, sealed(t, tenantCertificate(tenant, der), pub), "--tenant", tenant); code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
	}
	profile := tenantProfileBytes(testTeam, "com.anyfun.foundation", testNow.AddDate(0, 6, 0), [][]byte{der}, "")
	if code, out := installAs(t, dir, sealed(t, tenantProfile(tenantA, profile), pub), "--tenant", tenantA); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	remove := func(args ...string) (int, string) {
		return runRunner(t, func(string) string { return "" }, append([]string{"remove-ios-material", "--signing-dir", dir}, args...)...)
	}
	if code, out := remove("--tenant", tenantA, "--kind", "profile", "--team", testTeam, "--scope", "com.anyfun.foundation"); code != 0 || !strings.Contains(out, `"existed":true`) {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(tenantProfileDir(dir, tenantA, testTeam), "com.anyfun.foundation"+jobspec.IOSProfileSuffix)); !os.IsNotExist(err) {
		t.Fatalf("the profile is still there: %v", err)
	}
	if code, out := remove("--tenant", tenantA, "--kind", "certificate", "--team", testTeam); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if held := fake.mainHashes(dir); len(held) != 1 {
		t.Fatalf("tenant B still uses the certificate; it must stay in the keychain: %v", held)
	}
	if code, out := remove("--tenant", tenantB, "--kind", "certificate", "--team", testTeam); code != 0 || !strings.Contains(out, "identityDeleted") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if held := fake.mainHashes(dir); len(held) != 0 {
		t.Fatalf("nobody uses the certificate any more: %v", held)
	}
	if index := readIndex(t, dir); len(index) != 0 {
		t.Fatalf("index %v", index)
	}
	// 再撤一次：本来就没有算成功
	if code, out := remove("--tenant", tenantB, "--kind", "certificate", "--team", testTeam); code != 0 || !strings.Contains(out, `"existed":false`) {
		t.Fatalf("exit %d: %s", code, out)
	}

	// 旧布局：只撤描述文件；旧布局导进钥匙串的身份不动；上传 Key 不归这个账户
	legacyProfile := filepath.Join(dir, jobspec.IOSProfilesDirName, testTeam, "com.anyfun.foundation"+jobspec.IOSProfileSuffix)
	if err := os.MkdirAll(filepath.Dir(legacyProfile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyProfile, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := remove("--kind", "profile", "--team", testTeam, "--scope", "com.anyfun.foundation"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(legacyProfile); !os.IsNotExist(err) {
		t.Fatal("the per-team profile is still there")
	}
	for name, args := range map[string][]string{
		"legacy certificate": {"--kind", "certificate", "--team", testTeam},
		"upload key":         {"--tenant", tenantA, "--kind", "upload-key", "--team", testTeam},
		"scope escape":       {"--tenant", tenantA, "--kind", "profile", "--team", testTeam, "--scope", "../../x"},
		"bad team":           {"--tenant", tenantA, "--kind", "certificate", "--team", "../x"},
	} {
		if code, _ := remove(args...); code != exitUsage {
			t.Errorf("%s was accepted", name)
		}
	}
}

// 盘点把按租户的描述文件与证书索引原样带回去。
func TestIOSInventoryHandsBackTheTenantLayout(t *testing.T) {
	dir, pub, _, ca := tenantFixture(t)
	der := ca.leaf(t, 2, leafOptions{})
	if code, out := installAs(t, dir, sealed(t, tenantCertificate(tenantA, der), pub), "--tenant", tenantA); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	profile := tenantProfileBytes(testTeam, "com.anyfun.foundation", testNow.AddDate(0, 6, 0), [][]byte{der}, "")
	if code, out := installAs(t, dir, sealed(t, tenantProfile(tenantA, profile), pub), "--tenant", tenantA); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	code, out := runRunner(t, func(string) string { return "" }, "ios-inventory", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	material := decodeMaterial(t, out)
	if got := material.TenantProfiles[tenantA+"/"+testTeam+"/com.anyfun.foundation"+jobspec.IOSProfileSuffix]; !bytes.Equal(got, profile) {
		t.Fatalf("the tenant's profile did not come back: %v", material.TenantProfiles)
	}
	if material.TenantCertificates[tenantA+"/"+testTeam] != derSHA1(der) {
		t.Fatalf("index %v", material.TenantCertificates)
	}
	// 旧布局那一侧不把 tenants/ 当成一个 Team
	for name := range material.Profiles {
		if strings.HasPrefix(name, jobspec.IOSTenantsDirName+"/") {
			t.Errorf("the tenant layout leaked into the per-team profiles: %s", name)
		}
	}
}

// 坏掉的索引不能当成空的：那样撤证书会按错的引用计数删掉别人的身份。
func TestABrokenIndexStopsTheInstall(t *testing.T) {
	dir, pub, _, ca := tenantFixture(t)
	if err := os.WriteFile(filepath.Join(dir, jobspec.IOSTenantCertificatesFileName), []byte(`{"../x/J4JDFC8LCC":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out := installAs(t, dir, sealed(t, tenantCertificate(tenantA, ca.leaf(t, 2, leafOptions{})), pub), "--tenant", tenantA)
	if code == 0 || !strings.Contains(out, "not <tenant>/<TEAM>") {
		t.Fatalf("a broken index was trusted: %d %s", code, out)
	}
}

// 内嵌的 WWDR 与安装包里那一份字节相同，摘要与装机脚本钉的一致。
func TestEmbeddedWWDRIsTheOneTheInstallerPins(t *testing.T) {
	onDisk, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "build-agent-macos", "AppleWWDRCAG3.cer"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, wwdrG3DER) {
		t.Fatal("the embedded AppleWWDRCAG3.cer differs from deploy/build-agent-macos/AppleWWDRCAG3.cer")
	}
	digest := sha256.Sum256(wwdrG3DER)
	if hex.EncodeToString(digest[:]) != "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f" {
		t.Fatal("the embedded WWDR G3 is not the one install-macos.sh pins")
	}
	anchors, err := trustAnchors()
	if err != nil || len(anchors) != 1 || !strings.Contains(anchors[0].Subject.CommonName, "Worldwide Developer Relations") {
		t.Fatalf("anchors %v %v", anchors, err)
	}
}
