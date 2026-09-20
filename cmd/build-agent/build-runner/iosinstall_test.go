package main

// install-ios-material：控制台传下来的密文，由执行账户解开、装到这台机器上。
//
// 控制进程搬的是密文、解不开；私钥只在这个账户名下。这一组盯的就是那条界线两边各自的
// 行为：密钥不在或者别人读得到就不干活；解开之后按种类落地；不是这个账户的活不接。

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

// 证书要做三件事，顺序不能换：先解锁钥匙串，再导进去，最后 set-key-partition-list。
//
// 少了解锁，守护进程往锁着的钥匙串里 import 只会换来 "User interaction is not allowed."
// （2026-09-20 真机）；少了最后一条，codesign 第一次用会弹 UI 授权，而这台机器没有图形
// 会话——构建卡到超时，日志上看不出原因。
func TestInstallCertificateUnlocksImportsThenSetsThePartitionList(t *testing.T) {
	dir, pub := materialFixture(t)
	record := filepath.Join(t.TempDir(), "security-stdin")
	var calls []string
	restore := securityCommand
	securityCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		calls = append(calls, strings.Join(args, " "))
		// 口令现在走标准输入，所以假的 security 要把收到的东西留下来
		return exec.CommandContext(ctx, "/bin/sh", "-c", "cat >> "+record)
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
	if len(calls) != 3 {
		t.Fatalf("security was called %d times: %v", len(calls), calls)
	}
	if calls[0] != "-i" || calls[2] != "-i" {
		t.Errorf("the two calls that carry the keychain password must read it from stdin: %v", calls)
	}
	if !strings.HasPrefix(calls[1], "import ") || !strings.Contains(calls[1], "-T /usr/bin/codesign") {
		t.Errorf("import call: %s", calls[1])
	}
	script, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the fake security recorded nothing: %v", err)
	}
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	unlock := "unlock-keychain -p keychain-password " + keychain
	partition := "set-key-partition-list -S apple-tool:,apple: -s -k keychain-password " + keychain
	if !strings.Contains(string(script), unlock) {
		t.Errorf("the keychain was never unlocked; a locked keychain refuses the import: %s", script)
	}
	if !strings.Contains(string(script), partition) {
		t.Errorf("partition list never set: %s", script)
	}
	// 顺序：解锁必须在 import 之前，而 import 是第二次调用
	if strings.Index(string(script), unlock) > strings.Index(string(script), partition) {
		t.Errorf("the unlock came after the partition list: %s", script)
	}
	// 钥匙串口令一次都不该出现在命令行参数里（ps 看得到）
	for _, call := range calls {
		if strings.Contains(call, "keychain-password") {
			t.Errorf("the keychain password reached a command line: %s", call)
		}
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
		Kind: iosmaterial.KindUploadKey, TeamID: testTeam,
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

// 指纹是装机现场唯一的核对判据：它必须与控制台登记那把公钥时算的值（sha256(公钥字节)）
// 一字不差。算错一端——对 base64 文本取摘要、或者拿私钥去算——运维比的就是两个永远不会
// 相等的字符串，而那要等第一次下发材料才看得出来，还容易被当成服务端的问题。
func TestMaterialKeyFingerprintIsTheValueTheConsoleRegisters(t *testing.T) {
	dir, pub := materialFixture(t)
	code, out := runRunner(t, func(string) string { return "" }, "material-key-fingerprint", "--signing-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	want := sha256.Sum256(pub)
	if strings.TrimSpace(out) != hex.EncodeToString(want[:]) {
		t.Fatalf("fingerprint %q, the console registers %s", strings.TrimSpace(out), hex.EncodeToString(want[:]))
	}
}

// 私钥不在就说不在：装机脚本靠这条退出码决定要不要把"算不出来"印出来
func TestMaterialKeyFingerprintSaysSoWhenThereIsNoKey(t *testing.T) {
	code, out := runRunner(t, func(string) string { return "" }, "material-key-fingerprint", "--signing-dir", signingDir(t))
	if code == 0 {
		t.Fatalf("a missing material key was reported as success: %s", out)
	}
	if !strings.Contains(out, materialKeyFileName) {
		t.Errorf("the error does not name the file that is missing: %s", out)
	}
}
