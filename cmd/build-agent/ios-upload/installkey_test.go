package main

// --install-key：上传 Key 的密文由**上传账户**解开。这一把是那些签名材料唯一缺的出口，
// 所以它既不在控制进程手里，也不在执行进程手里。

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

func uploadFixture(t *testing.T) (dir string, pub []byte) {
	t.Helper()
	dir = t.TempDir()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, materialKeyFileName),
		[]byte(base64.StdEncoding.EncodeToString(key.Bytes())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, key.PublicKey().Bytes()
}

func sealedKey(t *testing.T, material iosmaterial.Material, pub []byte) string {
	t.Helper()
	box, err := iosmaterial.Seal(material, pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestInstallKeyLandsWhereTheUploaderLooks(t *testing.T) {
	dir, pub := uploadFixture(t)
	p8 := testPrivateKeyPEM(t)
	box := sealedKey(t, iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString(p8),
	}, pub)

	var out, errBuf bytes.Buffer
	if code := run([]string{"--install-key", "--keys", dir}, strings.NewReader(box), &out, &errBuf); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errBuf.String())
	}
	teamDir := filepath.Join(dir, "J4JDFC8LCC")
	// 读的那一侧（readKey）按这两个名字找
	meta, err := os.ReadFile(filepath.Join(teamDir, "key.json"))
	if err != nil {
		t.Fatalf("key.json: %v", err)
	}
	if !strings.Contains(string(meta), "8WQNTAY7MP") {
		t.Errorf("key.json: %s", meta)
	}
	keyPath := filepath.Join(teamDir, "AuthKey_8WQNTAY7MP.p8")
	got, err := os.ReadFile(keyPath)
	if err != nil || string(got) != string(p8) {
		t.Fatalf("the .p8 came back changed: %q %v", got, err)
	}
	for _, path := range []string{keyPath, filepath.Join(teamDir, "key.json")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v (%v); these are 0600", path, info.Mode().Perm(), err)
		}
	}
	// 装完就能被读它的那一条路读出来——两个文件名与格式必须与 readKey 对得上
	if _, err := readKey(teamDir); err != nil {
		t.Errorf("the uploader cannot read what install-key just wrote: %v", err)
	}
}

func TestInstallKeyRefusesOtherKinds(t *testing.T) {
	dir, pub := uploadFixture(t)
	box := sealedKey(t, iosmaterial.Material{
		Kind: iosmaterial.KindCertificate, TeamID: "J4JDFC8LCC",
		P12Base64:   base64.StdEncoding.EncodeToString([]byte("pkcs12")),
		P12Password: "x",
	}, pub)
	var out, errBuf bytes.Buffer
	if code := run([]string{"--install-key", "--keys", dir}, strings.NewReader(box), &out, &errBuf); code == 0 {
		t.Fatal("the upload account installed a certificate")
	}
	if !strings.Contains(errBuf.String(), "upload account") {
		t.Errorf("the refusal does not say why: %s", errBuf.String())
	}
}

func TestInstallKeyNeedsItsOwnPrivateKey(t *testing.T) {
	dir, pub := uploadFixture(t)
	box := sealedKey(t, iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString(testPrivateKeyPEM(t)),
	}, pub)
	if err := os.Chmod(filepath.Join(dir, materialKeyFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"--install-key", "--keys", dir}, strings.NewReader(box), &out, &errBuf); code == 0 {
		t.Fatal("a world-readable material key was accepted")
	}
	if !strings.Contains(errBuf.String(), "0600") {
		t.Errorf("the refusal does not say what is wrong: %s", errBuf.String())
	}
}

// testPrivateKeyPEM 造一把真的 P-256 私钥：install-key 落盘之前会解一次，假的过不去，
// 而那一条检查正是为了不把一把用不了的 Key 装上去。
func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// 一把解不开的 .p8 要在**安装**这一步就被拒。放过去的话，发现它要等到第一次真去传包——
// 那时候构建已经跑完两小时，而报错指向的是上传，不是这次安装。
func TestInstallKeyRefusesAnUnusableP8(t *testing.T) {
	dir, pub := uploadFixture(t)
	box := sealedKey(t, iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nnope\n")),
	}, pub)
	var out, errBuf bytes.Buffer
	if code := run([]string{"--install-key", "--keys", dir}, strings.NewReader(box), &out, &errBuf); code == 0 {
		t.Fatal("an unusable .p8 was installed")
	}
	// 而且不该在盘上留下半份材料
	if _, err := os.Stat(filepath.Join(dir, "J4JDFC8LCC", "AuthKey_8WQNTAY7MP.p8")); err == nil {
		t.Error("the unusable key was written anyway")
	}
}

// 与 build-runner 那一条同一件事：上传账户这把的指纹也要与控制台登记的值一字不差。
// 两个账户各有一把，装机时正是靠这两个值分辨"哪把放错了位置"。
func TestMaterialKeyFingerprintIsTheValueTheConsoleRegisters(t *testing.T) {
	dir, pub := uploadFixture(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"--material-key-fingerprint", "--keys", dir}, strings.NewReader(""), &out, &errBuf); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errBuf.String())
	}
	want := sha256.Sum256(pub)
	if strings.TrimSpace(out.String()) != hex.EncodeToString(want[:]) {
		t.Fatalf("fingerprint %q, the console registers %s", strings.TrimSpace(out.String()), hex.EncodeToString(want[:]))
	}
}

// --list-keys 只说"哪些 Team 装好了"，不吐任何密钥内容——控制进程要的就只有这个。
func TestListKeysNamesTheTeamsAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	for _, team := range []string{"J4JDFC8LCC", "AB12CD34EF"} {
		if err := os.MkdirAll(filepath.Join(dir, team), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// key.json 是 installKey 最后写的那个文件，它在才算这一格完整
	if err := os.WriteFile(filepath.Join(dir, "J4JDFC8LCC", "key.json"),
		[]byte(`{"issuerId":"3223da1d-14c5-46fc-80a1-41ecfb6e3c67","keyId":"8WQNTAY7MP"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "J4JDFC8LCC", "AuthKey_8WQNTAY7MP.p8"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 不是 Team ID 的目录不算
	if err := os.MkdirAll(filepath.Join(dir, "not-a-team"), 0o700); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := listKeys(&out, dir); err != nil {
		t.Fatalf("--list-keys failed: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"teams":["J4JDFC8LCC"],"tenants":{}}` {
		t.Errorf("--list-keys said %s", got)
	}
	for _, leak := range []string{"secret", "8WQNTAY7MP", "3223da1d"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("--list-keys leaked %q to the control process: %s", leak, out.String())
		}
	}
}

// --remove-key 只删 <keys>/<TEAMID> 这一格，不跟符号链接；本来就没有算成功。
func TestRemoveKeyDeletesOnlyThatTeam(t *testing.T) {
	keys := t.TempDir()
	for _, team := range []string{"J4JDFC8LCC", "ZZ99YY88XX"} {
		if err := os.MkdirAll(filepath.Join(keys, team), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keys, team, "key.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--remove-key", "--team", "J4JDFC8LCC", "--keys", keys}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"removed":true`) || !strings.Contains(stdout.String(), `"existed":true`) {
		t.Fatalf("output: %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(keys, "J4JDFC8LCC")); !os.IsNotExist(err) {
		t.Fatalf("the key directory is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(keys, "ZZ99YY88XX", "key.json")); err != nil {
		t.Fatalf("another team's key was touched: %v", err)
	}
	// 已经没有了：照样成功
	stdout.Reset()
	if code := run([]string{"--remove-key", "--team", "J4JDFC8LCC", "--keys", keys}, nil, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"existed":false`) {
		t.Fatalf("removing an absent key: exit %d, %s %s", code, stdout.String(), stderr.String())
	}
	// 一格是链接：删链接本身，不顺着删到别处
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(keys, "AB12CD34EF")); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--remove-key", "--team", "AB12CD34EF", "--keys", keys}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("removal followed a symlink out of the key directory: %v", err)
	}
	// Team ID 形状不对：拼路径之前就拒
	if code := run([]string{"--remove-key", "--team", "../etc", "--keys", keys}, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("a malformed team was accepted: exit %d", code)
	}
}

func tenantUploadKey(t *testing.T, tenant string) iosmaterial.Material {
	t.Helper()
	return iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TenantID: tenant, TeamID: "J4JDFC8LCC",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString(testPrivateKeyPEM(t)),
	}
}

// 按租户落盘：Key 放进 tenants/<租户>/<TEAM>/；材料里写的租户必须与清单给的一致；迁移过来的 v1 要
// 带 --legacy；带租户的 Key 不能落进旧布局（设计 ios-tenant-owned-signing-material-2026-09-25 §4.3）。
func TestInstallKeyForATenant(t *testing.T) {
	dir, pub := uploadFixture(t)
	install := func(box string, args ...string) (int, string) {
		var out, errBuf bytes.Buffer
		code := run(append([]string{"--install-key", "--keys", dir}, args...), strings.NewReader(box), &out, &errBuf)
		return code, out.String() + errBuf.String()
	}
	if code, out := install(sealedKey(t, tenantUploadKey(t, "1000000001"), pub), "--tenant", "1000000001"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	teamDir := filepath.Join(dir, tenantsDirName, "1000000001", "J4JDFC8LCC")
	if _, err := readKey(teamDir); err != nil {
		t.Fatalf("the tenant's key is not where the uploader looks: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "J4JDFC8LCC")); !os.IsNotExist(err) {
		t.Fatal("a tenant's key also landed in the per-team layout")
	}
	for name, c := range map[string]struct {
		box  string
		args []string
		want string
	}{
		"another tenant's key":    {sealedKey(t, tenantUploadKey(t, "1000000002"), pub), []string{"--tenant", "1000000001"}, rejectedPrefix},
		"v1 without --legacy":     {sealedKey(t, tenantUploadKey(t, ""), pub), []string{"--tenant", "1000000001"}, rejectedPrefix},
		"tenant key, no tenant":   {sealedKey(t, tenantUploadKey(t, "1000000001"), pub), nil, "--tenant"},
		"tenant that is a path":   {sealedKey(t, tenantUploadKey(t, "1000000001"), pub), []string{"--tenant", "../1"}, "digits only"},
		"--legacy without tenant": {sealedKey(t, tenantUploadKey(t, ""), pub), []string{"--legacy"}, "--legacy"},
	} {
		if code, out := install(c.box, c.args...); code == 0 || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d: %s", name, code, out)
		}
	}
	if code, out := install(sealedKey(t, tenantUploadKey(t, ""), pub), "--tenant", "1000000002", "--legacy"); code != 0 {
		t.Fatalf("a legacy slot's v1 key was refused: %s", out)
	}

	var out bytes.Buffer
	if err := listKeys(&out, dir); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"teams":[],"tenants":{"1000000001":["J4JDFC8LCC"],"1000000002":["J4JDFC8LCC"]}}` {
		t.Fatalf("--list-keys said %s", got)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"--remove-key", "--tenant", "1000000001", "--team", "J4JDFC8LCC", "--keys", dir}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if _, err := os.Stat(teamDir); !os.IsNotExist(err) {
		t.Fatal("the tenant's key is still there")
	}
	if _, err := readKey(filepath.Join(dir, tenantsDirName, "1000000002", "J4JDFC8LCC")); err != nil {
		t.Fatalf("another tenant's key on the same team was touched: %v", err)
	}
}
