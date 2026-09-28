package main

// 按租户落盘的签名材料（设计 ios-tenant-owned-signing-material-2026-09-25 §4.1、§4.2、§12.5）。
//
// 以前材料只来自平台管理员，这台机器只查格式就装。现在任何一个租户账号都能交材料，而这台 Mac
// 是最后一道关：解开之后、落地之前核对内容，不合格就不装，原因随盘点报回控制台。
//
//   - 证书：先导进一个临时钥匙串，让 macOS 自己说「私钥与证书配对、链得到 WWDR、没过期」，
//     再用 Go 核对 Team、类型与链；合格才按 SHA-1 幂等地导进签名钥匙串，并记进本机索引。
//     不在 Go 里解 .p12：运维手册要求 legacy（RC2/3DES）导出，而 signing/pkcs12 只收 AES。
//   - 描述文件：Team、application-identifier、App Store 类型、没过期、包含本租户那张证书。
//     不验 CMS 签名：伪造一份最多让这个租户自己的构建失败，它只落在这个租户的目录下。
//
// 同一张证书在钥匙串里只存一份身份；谁在用它记在 tenant-certificates.json，撤的时候按引用计数。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/internal/ipa"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// wwdrG3DER 是 Apple WWDR G3 中间证书，与 deploy/build-agent-macos/AppleWWDRCAG3.cer 字节相同
// （有用例盯着）。分发证书的链要以它为锚点验过。内嵌而不是读安装包里那份：装机之后安装包目录
// 不一定还在，而程序本身在已验签的清单里。
//
//go:embed AppleWWDRCAG3.cer
var wwdrG3DER []byte

// trustAnchors 是核对分发证书时认的根。测试换成现生成的假根。
var trustAnchors = func() ([]*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(wwdrG3DER)
	if err != nil {
		return nil, fmt.Errorf("the embedded Apple WWDR G3 certificate cannot be parsed: %w", err)
	}
	return []*x509.Certificate{certificate}, nil
}

// runnerNow 是核对到期用的时钟。测试换掉它。
var runnerNow = time.Now

// rejectedPrefix 标出「材料本身不合格」：控制进程认出这个前缀，同一版不再反复试，直到清单上出现
// 新版本（§12.2）。其它失败（钥匙串一时打不开、security 超时）不带它，下一轮照常再试。
const rejectedPrefix = "rejected: "

type rejected struct{ err error }

func (r rejected) Error() string { return rejectedPrefix + r.err.Error() }

func rejectf(format string, args ...any) error { return rejected{fmt.Errorf(format, args...)} }

var (
	appleTeamPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	bundlePattern    = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
	// identityLinePattern 是 `security find-identity` 的一行："  1) <SHA-1> "Apple Distribution: …""
	identityLinePattern = regexp.MustCompile(`(?m)^\s*\d+\)\s+([0-9A-F]{40})\s+"`)
	// scratchPasswordAlphabet：临时钥匙串的口令会拼进 `security -i` 的一行命令，只用不需要引号的字符
	scratchPasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// distributionPrefixes：Apple Distribution 是现行类型，iPhone Distribution 是 2021 年之前签发的旧类型
var distributionPrefixes = []string{"Apple Distribution:", "iPhone Distribution:"}

// appleExtensionPrefix：Apple 在开发者证书里放的私有扩展（标成 critical）。Go 不认识它们，
// 不剥掉的话 Verify 一律报 UnhandledCriticalExtension
const appleExtensionPrefix = "1.2.840.113635.100.6."

// installTenantMaterial 核对一份属于某个租户的材料，合格才落地。
func installTenantMaterial(ctx context.Context, out io.Writer, dir, tenant string, legacy bool, version int, material iosmaterial.Material) error {
	switch {
	case version == iosmaterial.VersionTenant && material.TenantID != tenant:
		// 清单说这一格属于 tenant，材料自己说属于别人：租户交了一份声称是别人的材料，或者服务端把
		// A 的材料挪给了 B——两种都不能装
		return rejectf("this material belongs to tenant %s, not to tenant %s", material.TenantID, tenant)
	case version == iosmaterial.VersionLegacy && !legacy:
		return rejectf("this is a version 1 material with no tenant in it; only a slot the server marks legacy " +
			"(copied from the per-team store) may hold one — upload it again from the console")
	}
	result := map[string]any{
		"installed": true, "kind": material.Kind, "tenantId": tenant,
		"teamId": material.TeamID, "bundleId": material.BundleID,
	}
	switch material.Kind {
	case iosmaterial.KindCertificate:
		sha1, warning, err := installTenantCertificate(ctx, dir, tenant, material)
		if err != nil {
			return err
		}
		result["certificateSha1"] = sha1
		if warning != "" {
			result["warning"] = warning
		}
	case iosmaterial.KindProfile:
		if err := installTenantProfile(dir, tenant, material); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s is not installed by the build user", material.Kind)
	}
	return json.NewEncoder(out).Encode(result)
}

// installTenantCertificate 核对证书，按 SHA-1 幂等地导进签名钥匙串，记进索引。回 SHA-1 与一句
// 不致命的提醒（换下来的旧身份没撤掉）。
func installTenantCertificate(ctx context.Context, dir, tenant string, material iosmaterial.Material) (string, string, error) {
	sha1, err := verifyCertificate(ctx, dir, material)
	if err != nil {
		return "", "", err
	}
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	if _, err := os.Stat(keychain); err != nil {
		return "", "", fmt.Errorf("no signing keychain at %s: %w", keychain, err)
	}
	held, err := keychainHashes(ctx, keychain)
	if err != nil {
		return "", "", err
	}
	// 同一张证书两个租户各交一次、或者同一个租户重传：钥匙串里已经有这个身份，只写索引。
	// 再导一次，security import 会以 already exists 失败（设计 §11 评审第一条）
	if !held[sha1] {
		if err := importCertificate(ctx, dir, material); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return "", "", err
		}
		if held, err = keychainHashes(ctx, keychain); err != nil {
			return "", "", err
		}
		if !held[sha1] {
			return "", "", fmt.Errorf("the certificate was imported but identity %s is not in the signing keychain", sha1)
		}
	}
	index, err := readTenantCertificates(dir)
	if err != nil {
		return "", "", err
	}
	key := jobspec.TenantCertificateKey(tenant, material.TeamID)
	previous := index[key]
	index[key] = sha1
	if err := writeTenantCertificates(dir, index); err != nil {
		return "", "", err
	}
	// 换了证书：旧的那张没有任何租户再用就撤掉。撤不掉不让这次安装失败——新证书已经就位、构建按
	// SHA-1 钉的是新的；旧身份多留一会儿只是占着，下一次换或删时还会再试
	if previous != "" && previous != sha1 && !referenced(index, previous) {
		if err := deleteIdentity(ctx, dir, previous); err != nil {
			return sha1, "the replaced identity " + previous + " is still in the keychain: " + oneLine(err.Error()), nil
		}
	}
	return sha1, "", nil
}

// verifyCertificate 在临时钥匙串里核对一份 .p12，回身份的 SHA-1。
//
// 为什么走临时钥匙串：能被 `find-identity -v` 列出来，就说明私钥与证书配对，而且 macOS 认为它
// 有效——链到系统钥匙串里的 WWDR G3、没过期、没吊销。这与真正导入走的是同一套解析，Go 里不必
// 再写一套 RC2/3DES（设计 §10）。之后再用 Go 核对 macOS 不管的那几项：Team、证书类型、锚点。
func verifyCertificate(ctx context.Context, dir string, material iosmaterial.Material) (string, error) {
	p12, err := base64.StdEncoding.Strict().DecodeString(material.P12Base64)
	if err != nil {
		return "", rejectf("the certificate in this material is not base64")
	}
	defer wipe(p12)
	password, err := scratchPassword()
	if err != nil {
		return "", err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	scratch := filepath.Join(dir, ".verify-"+hex.EncodeToString(suffix)+".keychain-db")
	if err := runSecurityScript(ctx, password,
		"create-keychain -p "+password+" "+scratch,
		"unlock-keychain -p "+password+" "+scratch,
		"set-keychain-settings "+scratch,
	); err != nil {
		return "", fmt.Errorf("cannot create a scratch keychain to check the certificate: %w", err)
	}
	defer func() {
		// 删不掉也不能留着：里面是这个租户的私钥
		_, _ = securityRun(context.WithoutCancel(ctx), "", "delete-keychain", scratch)
		_ = os.Remove(scratch)
	}()
	p12Path, err := writeScratch(dir, ".verify-*.p12", p12)
	if err != nil {
		return "", err
	}
	defer os.Remove(p12Path)
	if _, err := securityRun(ctx, "", "import", p12Path, "-k", scratch, "-f", "pkcs12", "-P", material.P12Password); err != nil {
		return "", rejected{fmt.Errorf("macOS cannot import this .p12 (a wrong password, not a PKCS#12 file, "+
			"or exported without -legacy): %w", scrubbed(err, password, material.P12Password))}
	}
	// 搜索列表只改这一个进程的，与盘点同一个写法（iosinventory.go）：-v 的信任评估按搜索列表找链，
	// 而这个账户的家目录写不进去
	listing, err := securityRun(ctx, "list-keychains -s "+scratch+"\nfind-identity -v -p codesigning "+scratch+"\n", "-i")
	if err != nil {
		return "", fmt.Errorf("cannot list the identities in the scratch keychain: %w", scrubbed(err, password))
	}
	hashes := parseIdentityHashes(listing)
	switch {
	case len(hashes) == 0:
		return "", rejectf("this .p12 holds no valid code-signing identity: the private key is missing, " +
			"the certificate expired or was revoked, or it does not chain to Apple WWDR G3")
	case len(hashes) > 1:
		return "", rejectf("this .p12 holds %d identities; upload exactly one distribution certificate with its private key", len(hashes))
	}
	pems, err := securityRun(ctx, "", "find-certificate", "-a", "-p", scratch)
	if err != nil {
		return "", fmt.Errorf("cannot read the certificates in the scratch keychain: %w", err)
	}
	certificate := certificateWithSHA1(pems, hashes[0])
	if certificate == nil {
		return "", fmt.Errorf("identity %s is listed but its certificate is not in the scratch keychain", hashes[0])
	}
	anchors, err := trustAnchors()
	if err != nil {
		return "", err
	}
	if err := checkDistributionCertificate(certificate, material.TeamID, runnerNow(), anchors); err != nil {
		return "", rejected{err}
	}
	return hashes[0], nil
}

// checkDistributionCertificate 核对 macOS 不替我们管的几项：属于这个 Team、是分发证书、在有效期内、
// 以 WWDR G3 为锚点验得过链。
func checkDistributionCertificate(certificate *x509.Certificate, team string, now time.Time, anchors []*x509.Certificate) error {
	name := certificate.Subject.CommonName
	distribution := false
	for _, prefix := range distributionPrefixes {
		distribution = distribution || strings.HasPrefix(name, prefix)
	}
	switch {
	case !distribution:
		return fmt.Errorf("the certificate is %q, not an Apple Distribution certificate", firstRunes(name, 80))
	case !containsString(certificate.Subject.OrganizationalUnit, team):
		return fmt.Errorf("the certificate belongs to Team %s, not to %s", strings.Join(certificate.Subject.OrganizationalUnit, ","), team)
	case now.Before(certificate.NotBefore):
		return fmt.Errorf("the certificate is not valid before %s", certificate.NotBefore.UTC().Format(time.RFC3339))
	case !now.Before(certificate.NotAfter):
		return fmt.Errorf("the certificate expired on %s", certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}
	leaf := *certificate
	leaf.UnhandledCriticalExtensions = nil
	for _, oid := range certificate.UnhandledCriticalExtensions {
		if !strings.HasPrefix(oid.String(), appleExtensionPrefix) {
			leaf.UnhandledCriticalExtensions = append(leaf.UnhandledCriticalExtensions, oid)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return fmt.Errorf("the certificate does not chain to Apple WWDR G3: %w", err)
	}
	return nil
}

// installTenantProfile 核对描述文件，合格才放进这个租户的目录。
func installTenantProfile(dir, tenant string, material iosmaterial.Material) error {
	body, err := base64.StdEncoding.Strict().DecodeString(material.ProfileBase64)
	if err != nil {
		return rejectf("the profile in this material is not base64")
	}
	profile, err := ipa.ParseProfile(body)
	if err != nil {
		return rejectf("this is not a provisioning profile: %v", err)
	}
	now := runnerNow()
	want := material.TeamID + "." + material.BundleID
	switch {
	case !containsString(profile.TeamIdentifiers, material.TeamID):
		return rejectf("the profile's TeamIdentifier is %s, not %s", strings.Join(profile.TeamIdentifiers, ","), material.TeamID)
	case profile.TeamID+"."+profile.BundleID != want:
		return rejectf("the profile is for %s.%s, not %s", profile.TeamID, profile.BundleID, want)
	case profile.HasDevices:
		return rejectf("the profile lists devices: it is a development or Ad Hoc profile, not an App Store one")
	case profile.ProvisionsAllDevices:
		return rejectf("the profile provisions all devices: it is an enterprise profile, not an App Store one")
	case profile.GetTaskAllow:
		return rejectf("the profile allows debugging (get-task-allow): it is a development profile, not an App Store one")
	case profile.ExpiresAt.IsZero():
		return rejectf("the profile has no ExpirationDate")
	case !profile.ExpiresAt.After(now):
		return rejectf("the profile expired on %s", profile.ExpiresAt.UTC().Format(time.RFC3339))
	}
	index, err := readTenantCertificates(dir)
	if err != nil {
		return err
	}
	certificate := index[jobspec.TenantCertificateKey(tenant, material.TeamID)]
	if certificate == "" {
		// 不算不合格：证书可能下一轮就到（控制进程先装证书再装描述文件，但证书那一格也可能刚核对不过）
		return fmt.Errorf("the tenant's certificate for Team %s is not installed on this machine yet; the profile is checked against it", material.TeamID)
	}
	if !containsString(profile.DeveloperCertificateSHA1s, certificate) {
		return rejectf("the profile does not include the tenant's certificate %s; regenerate it with that certificate selected", certificate)
	}
	return writeProfile(tenantProfileDir(dir, tenant, material.TeamID), material)
}

// removeIOSMaterial 撤掉本机的一格（墓碑，§4.1）。tenant 为空只撤旧布局的描述文件：旧布局装进
// 钥匙串的身份不动（它们可能与某个租户的是同一张），旧布局的上传 Key 由上传账户撤。
func removeIOSMaterial(ctx context.Context, out io.Writer, who identity, dir, tenant, kind, team, scope string) error {
	if err := checkSigningDir(who, dir); err != nil {
		return usageError{err}
	}
	switch {
	case tenant != "" && !jobspec.ValidTenantID(tenant):
		return usagef("--tenant must be the tenant id the server gave (digits only), got %q", tenant)
	case !appleTeamPattern.MatchString(team):
		return usagef("--team must be a 10-character Apple Team ID")
	case kind == iosmaterial.KindProfile && !bundlePattern.MatchString(scope):
		return usagef("--scope must be the profile's bundle id")
	case kind == iosmaterial.KindCertificate && scope != "":
		return usagef("a certificate has no --scope")
	case kind == iosmaterial.KindCertificate && tenant == "":
		return usagef("certificates installed by the per-team layout are left in the keychain")
	case kind != iosmaterial.KindProfile && kind != iosmaterial.KindCertificate:
		return usagef("--kind must be certificate or profile; upload keys belong to the upload account")
	}
	result := map[string]any{"removed": true}
	if kind == iosmaterial.KindProfile {
		teamDir := filepath.Join(dir, jobspec.IOSProfilesDirName, team)
		if tenant != "" {
			teamDir = tenantProfileDir(dir, tenant, team)
		}
		existed, err := removeFile(filepath.Join(teamDir, scope+jobspec.IOSProfileSuffix))
		if err != nil {
			return err
		}
		result["existed"] = existed
		return json.NewEncoder(out).Encode(result)
	}
	index, err := readTenantCertificates(dir)
	if err != nil {
		return err
	}
	key := jobspec.TenantCertificateKey(tenant, team)
	sha1, existed := index[key]
	result["existed"] = existed
	if existed {
		delete(index, key)
		if err := writeTenantCertificates(dir, index); err != nil {
			return err
		}
		// 身份按引用计数：同一张证书别的租户还在用就留着
		if !referenced(index, sha1) {
			if err := deleteIdentity(ctx, dir, sha1); err != nil {
				return fmt.Errorf("the index entry is gone but identity %s is still in the keychain: %w", sha1, err)
			}
			result["identityDeleted"] = sha1
		}
	}
	return json.NewEncoder(out).Encode(result)
}

// deleteIdentity 从签名钥匙串里删掉一个身份（证书加私钥）。本来就没有算成功。
func deleteIdentity(ctx context.Context, dir, sha1 string) error {
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	password, err := readKeychainPassword(filepath.Join(dir, iosKeychainPasswordName))
	if err != nil {
		return err
	}
	if err := runSecurityScript(ctx, password,
		"unlock-keychain -p "+password+" "+keychain,
		"set-keychain-settings "+keychain,
	); err != nil {
		return fmt.Errorf("cannot unlock the signing keychain: %w", err)
	}
	if _, err := securityRun(ctx, "", "delete-identity", "-Z", sha1, keychain); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "could not be found") {
		return fmt.Errorf("security delete-identity: %w", err)
	}
	held, err := keychainHashes(ctx, keychain)
	if err != nil {
		return err
	}
	if held[sha1] {
		return fmt.Errorf("identity %s is still in the signing keychain after delete-identity", sha1)
	}
	return nil
}

// keychainHashes 是签名钥匙串里全部身份的 SHA-1（有效的与无效的都算：问的是「在不在」）。
func keychainHashes(ctx context.Context, keychain string) (map[string]bool, error) {
	listing, err := securityRun(ctx, "list-keychains -s "+keychain+"\nfind-identity -p codesigning "+keychain+"\n", "-i")
	if err != nil {
		return nil, fmt.Errorf("cannot list the identities in the signing keychain: %w", err)
	}
	out := map[string]bool{}
	for _, sha1 := range parseIdentityHashes(listing) {
		out[sha1] = true
	}
	return out, nil
}

// parseIdentityHashes 从 find-identity 的输出里按出现顺序取出不重复的 SHA-1。
func parseIdentityHashes(listing string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, match := range identityLinePattern.FindAllStringSubmatch(listing, -1) {
		if !seen[match[1]] {
			seen[match[1]] = true
			out = append(out, match[1])
		}
	}
	return out
}

// certificateWithSHA1 在一串 PEM 里找 DER 的 SHA-1 等于 want 的那张证书。
func certificateWithSHA1(pems, want string) *x509.Certificate {
	rest := []byte(pems)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		digest := sha1.Sum(block.Bytes)
		if strings.ToUpper(hex.EncodeToString(digest[:])) != want {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return certificate
	}
}

// ---- 本机证书索引 ----

func tenantProfileDir(dir, tenant, team string) string {
	return filepath.Join(dir, jobspec.IOSProfilesDirName, jobspec.IOSTenantsDirName, tenant, team)
}

// readTenantCertificates 读索引。没有就是空的；读不懂就报错——拿着一份坏索引，构建会钉错身份、
// 撤证书会按错的引用计数删身份，都比停下来更糟。
func readTenantCertificates(dir string) (map[string]string, error) {
	path := filepath.Join(dir, jobspec.IOSTenantCertificatesFileName)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1<<20))
	if err != nil {
		return nil, err
	}
	index := map[string]string{}
	if err := json.Unmarshal(raw, &index); err != nil {
		return nil, fmt.Errorf("%s is not a certificate index: %w", path, err)
	}
	for key, sha1 := range index {
		tenant, team, ok := strings.Cut(key, "/")
		if !ok || !jobspec.ValidTenantID(tenant) || !appleTeamPattern.MatchString(team) || !jobspec.ValidCertificateSHA1(sha1) {
			return nil, fmt.Errorf("%s has an entry that is not <tenant>/<TEAM> -> SHA-1: %q", path, firstRunes(key, 40))
		}
	}
	return index, nil
}

// writeTenantCertificates 原子地写索引，0600。
func writeTenantCertificates(dir string, index map[string]string) error {
	raw, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, jobspec.IOSTenantCertificatesFileName)
	tmp, err := writeScratch(dir, ".certificates-*", append(raw, '\n'))
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// referenced：索引里还有没有哪个租户在用这张证书。
func referenced(index map[string]string, sha1 string) bool {
	for _, value := range index {
		if value == sha1 {
			return true
		}
	}
	return false
}

// readTenantProfiles 读 profiles/tenants/<租户>/<TEAMID>/*.mobileprovision 的原文，键是
// "<租户>/<TEAMID>/<文件名>"。目录名只收形状对的：盘点把它们当成租户 id 与 Team 往上报。
func readTenantProfiles(root string, into map[string][]byte, count *int) []string {
	var problems []string
	tenants, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			problems = append(problems, "cannot read "+root+": "+err.Error())
		}
		return problems
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i].Name() < tenants[j].Name() })
	for _, tenant := range tenants {
		if !tenant.IsDir() || !jobspec.ValidTenantID(tenant.Name()) {
			continue
		}
		teams, err := os.ReadDir(filepath.Join(root, tenant.Name()))
		if err != nil {
			problems = append(problems, "cannot read "+filepath.Join(root, tenant.Name())+": "+err.Error())
			continue
		}
		for _, team := range teams {
			if !team.IsDir() || !appleTeamPattern.MatchString(team.Name()) {
				continue
			}
			dir := filepath.Join(root, tenant.Name(), team.Name())
			files, err := os.ReadDir(dir)
			if err != nil {
				problems = append(problems, "cannot read "+dir+": "+err.Error())
				continue
			}
			for _, file := range files {
				if file.IsDir() || !strings.HasSuffix(file.Name(), jobspec.IOSProfileSuffix) {
					continue
				}
				if *count >= jobspec.IOSProfileMaxCount {
					return append(problems, "more than "+fmt.Sprint(jobspec.IOSProfileMaxCount)+" profiles; the rest were not read")
				}
				path := filepath.Join(dir, file.Name())
				raw, err := readCapped(path)
				if err != nil {
					problems = append(problems, "cannot read "+path+": "+err.Error())
					continue
				}
				into[tenant.Name()+"/"+team.Name()+"/"+file.Name()] = raw
				*count++
			}
		}
	}
	return problems
}

// removeFile 删一个文件（是链接就删链接本身），回它原来在不在。
func removeFile(path string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return true, err
	}
	return true, nil
}

// scratchPassword 生成临时钥匙串的口令：32 个字母数字，拼得进 `security -i` 的一行命令。
func scratchPassword() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var out bytes.Buffer
	for _, b := range raw {
		out.WriteByte(scratchPasswordAlphabet[int(b)%len(scratchPasswordAlphabet)])
	}
	return out.String(), nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func firstRunes(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
