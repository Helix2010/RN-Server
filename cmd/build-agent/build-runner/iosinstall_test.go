package main

// install-ios-material：控制台传下来的密文，由执行账户解开、装到这台机器上。
//
// 控制进程搬的是密文、解不开；私钥只在这个账户名下。这一组盯的就是那条界线两边各自的
// 行为：密钥不在或者别人读得到就不干活；解开之后按种类落地；不是这个账户的活不接。

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const testTeam = "J4JDFC8LCC"

// materialFixture 备一个签名区：私钥、钥匙串占位、钥匙串口令。
func materialFixture(t *testing.T) (dir string, pub []byte) {
	t.Helper()
	dir = signingDir(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(materialKeyFileName, []byte(base64.StdEncoding.EncodeToString(key.Bytes())+"\n"), 0o600)
	write(jobspec.IOSKeychainFileName, []byte("pretend keychain"), 0o600)
	write("rn-signing.password", []byte("keychain-password\n"), 0o600)
	return dir, key.PublicKey().Bytes()
}

func sealed(t *testing.T, material iosmaterial.Material, pub []byte) string {
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

func TestInstallProfileLandsWhereTheInventoryLooks(t *testing.T) {
	dir, pub := materialFixture(t)
	body := []byte("pretend this is a mobileprovision")
	box := sealed(t, iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TeamID: testTeam, BundleID: "com.anyfun.foundation",
		ProfileBase64: base64.StdEncoding.EncodeToString(body),
	}, pub)

	code, out := runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	path := filepath.Join(dir, jobspec.IOSProfilesDirName, testTeam,
		"com.anyfun.foundation"+jobspec.IOSProfileSuffix)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the profile is not where the inventory looks for it: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("the profile came back changed: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v %v; a profile is written 0600", info.Mode().Perm(), err)
	}
	// 临时文件不留在原地：盘点会把它当成一份坏描述文件报出来
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".profile-") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
}

// 证书要做两件事：导进钥匙串，再 set-key-partition-list。少了第二条，codesign 第一次用
// 会弹 UI 授权，而这台机器没有图形会话——构建卡到超时，日志上看不出原因。
func TestInstallCertificateAlsoSetsThePartitionList(t *testing.T) {
	dir, pub := materialFixture(t)
	var calls []string
	restore := securityCommand
	securityCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		calls = append(calls, strings.Join(args, " "))
		return exec.CommandContext(ctx, "/bin/true")
	}
	t.Cleanup(func() { securityCommand = restore })

	box := sealed(t, iosmaterial.Material{
		Kind: iosmaterial.KindCertificate, TeamID: testTeam,
		P12Base64:   base64.StdEncoding.EncodeToString([]byte("pkcs12")),
		P12Password: "the p12 password",
	}, pub)
	code, out := runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if len(calls) != 2 {
		t.Fatalf("security was called %d times: %v", len(calls), calls)
	}
	if !strings.HasPrefix(calls[0], "import ") || !strings.Contains(calls[0], "-T /usr/bin/codesign") {
		t.Errorf("import call: %s", calls[0])
	}
	if !strings.HasPrefix(calls[1], "set-key-partition-list ") ||
		!strings.Contains(calls[1], "apple-tool:,apple:") {
		t.Errorf("partition call: %s", calls[1])
	}
	// .p12 不留在盘上
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".import-") {
			t.Errorf("the decrypted .p12 was left on disk: %s", entry.Name())
		}
	}
}

func TestInstallRefusesWhatIsNotItsJob(t *testing.T) {
	dir, pub := materialFixture(t)
	box := sealed(t, iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: testTeam, MachineID: "mch_x",
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString([]byte("p8")),
	}, pub)
	code, out := runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code == 0 {
		t.Fatalf("the build user installed an upload key: %s", out)
	}
	if !strings.Contains(out, "upload") {
		t.Errorf("the refusal does not say why: %s", out)
	}
}

// 私钥不在、或者别人也读得到，都不该继续——后者意味着它已经不是这个账户独有的了。
func TestInstallNeedsItsOwnPrivateKey(t *testing.T) {
	dir, pub := materialFixture(t)
	box := sealed(t, iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TeamID: testTeam, BundleID: "com.anyfun.foundation",
		ProfileBase64: base64.StdEncoding.EncodeToString([]byte("x")),
	}, pub)
	keyPath := filepath.Join(dir, materialKeyFileName)

	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code == 0 || !strings.Contains(out, "0600") {
		t.Fatalf("a world-readable material key was accepted: %d %s", code, out)
	}

	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	code, out = runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code == 0 || !strings.Contains(out, "--material-key-builder") {
		t.Fatalf("a missing material key does not point at how to fix it: %d %s", code, out)
	}
}

// 别人的密文解不开，而且错误里不该带出任何内容。
func TestInstallRefusesMaterialForAnotherKey(t *testing.T) {
	dir, _ := materialFixture(t)
	stranger, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	box := sealed(t, iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TeamID: testTeam, BundleID: "com.anyfun.foundation",
		ProfileBase64: base64.StdEncoding.EncodeToString([]byte("secret-profile-bytes")),
	}, stranger.PublicKey().Bytes())
	code, out := runRunnerWithInput(t, func(string) string { return "" }, strings.NewReader(box),
		"install-ios-material", "--signing-dir", dir)
	if code == 0 {
		t.Fatalf("material for another key was installed: %s", out)
	}
	if strings.Contains(out, "secret-profile-bytes") {
		t.Errorf("the error leaked the payload: %s", out)
	}
}
