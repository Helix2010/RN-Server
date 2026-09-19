package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const password = "SUPER-SECRET-P12-PASSWORD"

func runTool(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf, strings.NewReader(stdin))
	return code, out.String(), errBuf.String()
}

// 一整条：生成密钥 → 加密一份证书 → 自己验一遍。
func TestKeygenEncryptVerify(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := runTool(t, "", "keygen", "--out", dir)
	if code != 0 {
		t.Fatalf("keygen: %d %s %s", code, out, errOut)
	}
	for _, role := range []string{"builder", "uploader"} {
		info, err := os.Stat(filepath.Join(dir, role+".x25519"))
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s 的私钥是 %04o，必须是 0600", role, info.Mode().Perm())
		}
	}
	// 私钥不许出现在任何一条输出里
	private, err := os.ReadFile(filepath.Join(dir, "builder.x25519"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, strings.TrimSpace(string(private))) {
		t.Fatal("keygen printed the private key")
	}

	p12 := filepath.Join(dir, "cert.p12")
	if err := os.WriteFile(p12, []byte("pretend this is a pkcs12"), 0o600); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(dir, "cert.box.json")
	code, out, errOut = runTool(t, password+"\n", "encrypt",
		"--pub", filepath.Join(dir, "builder.x25519.pub"), "--team", "J4JDFC8LCC",
		"--kind", "certificate", "--p12", p12, "--out", box)
	if code != 0 {
		t.Fatalf("encrypt: %d %s %s", code, out, errOut)
	}
	// 密文文件里不能有口令，也不能有明文的 .p12
	raw, err := os.ReadFile(box)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(password)) || bytes.Contains(raw, []byte("pretend this is a pkcs12")) ||
		bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte("pretend this is a pkcs12")))) {
		t.Fatal("the ciphertext file holds the secret in the clear")
	}

	code, out, errOut = runTool(t, "", "verify", "--key", filepath.Join(dir, "builder.x25519"), "--in", box)
	if code != 0 {
		t.Fatalf("verify: %d %s %s", code, out, errOut)
	}
	if !strings.Contains(out, "J4JDFC8LCC") || !strings.Contains(out, "certificate") {
		t.Errorf("verify 没说清解开的是什么：%s", out)
	}
	if strings.Contains(out, password) {
		t.Error("verify printed the password")
	}
}

// 上传 Key 是给上传账户那把密钥的：拿构建账户那把解不开。
func TestUploaderMaterialNeedsTheUploaderKey(t *testing.T) {
	dir := t.TempDir()
	if code, out, errOut := runTool(t, "", "keygen", "--out", dir); code != 0 {
		t.Fatalf("keygen: %d %s %s", code, out, errOut)
	}
	p8 := filepath.Join(dir, "AuthKey.p8")
	if err := os.WriteFile(p8, []byte("-----BEGIN PRIVATE KEY-----"), 0o600); err != nil {
		t.Fatal(err)
	}
	box := filepath.Join(dir, "upload.box.json")
	if code, out, errOut := runTool(t, "", "encrypt",
		"--pub", filepath.Join(dir, "uploader.x25519.pub"), "--team", "J4JDFC8LCC",
		"--kind", "upload-key", "--p8", p8, "--issuer", "3223da1d-14c5-46fc-80a1-41ecfb6e3c67",
		"--key-id", "8WQNTAY7MP", "--machine", "mch_YSX7-u_TPeImo0mQ2uUoYA", "--out", box); code != 0 {
		t.Fatalf("encrypt: %d %s %s", code, out, errOut)
	}
	if code, _, _ := runTool(t, "", "verify", "--key", filepath.Join(dir, "builder.x25519"), "--in", box); code == 0 {
		t.Fatal("the builder key opened an upload key; the two roles are not separated")
	}
	if code, out, errOut := runTool(t, "", "verify", "--key", filepath.Join(dir, "uploader.x25519"), "--in", box); code != 0 {
		t.Fatalf("the uploader key could not open its own material: %d %s %s", code, out, errOut)
	}
}

// 覆盖已有私钥 = 把已经发出去的材料全部作废，不许悄悄发生。
func TestKeygenRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runTool(t, "", "keygen", "--out", dir); code != 0 {
		t.Fatal("first keygen failed")
	}
	before, err := os.ReadFile(filepath.Join(dir, "builder.x25519"))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runTool(t, "", "keygen", "--out", dir); code == 0 {
		t.Fatalf("a second keygen overwrote the keys: %s", errOut)
	}
	after, err := os.ReadFile(filepath.Join(dir, "builder.x25519"))
	if err != nil || string(after) != string(before) {
		t.Fatal("the existing private key was changed")
	}
}

func TestEncryptRefusesAnEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runTool(t, "", "keygen", "--out", dir); code != 0 {
		t.Fatal("keygen failed")
	}
	p12 := filepath.Join(dir, "cert.p12")
	if err := os.WriteFile(p12, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runTool(t, "\n", "encrypt",
		"--pub", filepath.Join(dir, "builder.x25519.pub"), "--team", "J4JDFC8LCC",
		"--kind", "certificate", "--p12", p12, "--out", filepath.Join(dir, "out.json"))
	if code == 0 {
		t.Fatal("an empty password was accepted")
	}
	if !strings.Contains(errOut, "标准输入") {
		t.Errorf("错误没说清口令从哪来：%s", errOut)
	}
}
