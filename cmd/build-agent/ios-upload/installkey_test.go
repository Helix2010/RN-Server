package main

// --install-key：上传 Key 的密文由**上传账户**解开。这一把是那些签名材料唯一缺的出口，
// 所以它既不在控制进程手里，也不在执行进程手里。

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC", MachineID: "mch_x",
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
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC", MachineID: "mch_x",
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
		Kind: iosmaterial.KindUploadKey, TeamID: "J4JDFC8LCC", MachineID: "mch_x",
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
