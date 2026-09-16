package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/pins"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
)

func TestMain(m *testing.M) {
	keyBits = 2048
	os.Exit(m.Run())
}

type signerKeys struct {
	name string
	x    *ecdh.PrivateKey
	pin  pins.Signer
}

func newSigner(t *testing.T, name, role string) signerKeys {
	t.Helper()
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := pins.Entry(name, role, x.PublicKey().Bytes(), edPub)
	if err != nil {
		t.Fatal(err)
	}
	return signerKeys{name: name, x: x, pin: pin}
}

func writePins(t *testing.T, dir string, signers ...pins.Signer) string {
	t.Helper()
	raw, err := json.MarshalIndent(pins.File{Format: pins.Format, Signers: signers}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pins.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTool(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func readPassword(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") || strings.Count(string(raw), "\n") != 1 {
		t.Fatal("password file must be exactly one line")
	}
	return strings.TrimSuffix(string(raw), "\n")
}

// assertUploadOpens 检查上传文件：形状合法、每个 Box 用对应私钥打开、明文绑定了预期的身份。
func assertUploadOpens(t *testing.T, raw []byte, tenant, pkg, alias, password string, signers ...signerKeys) keystorebox.Plaintext {
	t.Helper()
	var upload keystorebox.Upload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&upload); err != nil {
		t.Fatal(err)
	}
	if err := upload.ValidateShape(); err != nil {
		t.Fatalf("upload shape: %v", err)
	}
	if upload.TenantSlug != tenant || upload.PackageName != pkg || upload.KeyAlias != alias || len(upload.Boxes) != len(signers) {
		t.Fatalf("upload header: %+v", upload)
	}
	var plain keystorebox.Plaintext
	for i, s := range signers {
		if upload.Boxes[i].RecipientSHA256 != s.pin.X25519PublicKeySHA256 {
			t.Fatalf("box %d is not in pin file order", i)
		}
		p, err := keystorebox.Open(upload.Boxes[i], s.x.Bytes())
		if err != nil {
			t.Fatalf("open box for %s: %v", s.name, err)
		}
		if p.TenantSlug != tenant || p.PackageName != pkg || p.KeyAlias != alias || p.CertificateSHA256 != upload.CertificateSHA256 ||
			len(p.Recipients) != len(signers) || p.StorePassword != password || p.KeyPassword != password || p.CreatedAt != upload.CreatedAt {
			t.Fatalf("plaintext does not bind the expected identity: %v", p)
		}
		plain = p
	}
	p12, err := plain.P12()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := pkcs12.FindKey(p12, password, alias)
	if err != nil || pkcs12.CertificateSHA256(entry) != upload.CertificateSHA256 {
		t.Fatalf("p12 inside the box: %v", err)
	}
	return plain
}

func TestCreateEndToEnd(t *testing.T) {
	work := t.TempDir()
	a, b := newSigner(t, "amos-signer-a", pins.RolePrimary), newSigner(t, "amos-signer-b", pins.RoleStandby)
	pinPath := writePins(t, work, a.pin, b.pin)
	out := filepath.Join(work, "anyfun-originals")

	code, stdout, stderr := runTool("create", "--pins", pinPath, "--tenant", "AnyFun", "--package", "com.anyfun.foundation",
		"--alias", "anyfun-release", "--out-dir", out)
	if code != 0 {
		t.Fatalf("create exit %d: %s", code, stderr)
	}
	if mode(t, out) != 0o700 {
		t.Fatalf("out dir mode %o", mode(t, out))
	}
	paths := map[string]string{
		"p12": filepath.Join(out, "anyfun-release.p12"), "password": filepath.Join(out, "anyfun-release.password"),
		"cert": filepath.Join(out, "certificate.pem"), "upload": filepath.Join(out, "keystore-upload.json"),
	}
	for name, p := range paths {
		if m := mode(t, p); m != 0o600 {
			t.Fatalf("%s mode %o", name, m)
		}
		if !strings.Contains(stdout, p) {
			t.Fatalf("stdout does not list %s", p)
		}
	}
	password := readPassword(t, paths["password"])
	p12, err := os.ReadFile(paths["p12"])
	if err != nil {
		t.Fatal(err)
	}
	entry, err := pkcs12.FindKey(p12, password, "anyfun-release")
	if err != nil {
		t.Fatalf("p12 does not open with the password file: %v", err)
	}
	certSHA := pkcs12.CertificateSHA256(entry)
	uploadRaw, err := os.ReadFile(paths["upload"])
	if err != nil {
		t.Fatal(err)
	}
	plain := assertUploadOpens(t, uploadRaw, "AnyFun", "com.anyfun.foundation", "anyfun-release", password, a, b)
	if plain.CertificateSHA256 != certSHA {
		t.Fatal("upload certificate fingerprint differs from the p12")
	}

	for _, want := range []string{certSHA, a.pin.X25519PublicKeySHA256, a.pin.Ed25519PublicKeySHA256, b.pin.X25519PublicKeySHA256,
		b.pin.Ed25519PublicKeySHA256, "signer confirm --tenant AnyFun", "com.anyfun.foundation"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	for _, forbidden := range []string{password, base64.StdEncoding.EncodeToString(p12), "curl", "x-admin-key", "BUILD_KEYSTORE_PASSPHRASE", "expectedVersion"} {
		if strings.Contains(stdout+stderr, forbidden) {
			t.Fatalf("output contains %q", forbidden[:min(len(forbidden), 12)])
		}
	}
	if strings.Contains(string(uploadRaw), password) || strings.Contains(string(uploadRaw), "expectedVersion") || strings.Contains(string(uploadRaw), "reason") {
		t.Fatal("upload file contains plaintext password or admin request fields")
	}

	t.Run("refuses an existing out dir", func(t *testing.T) {
		code, _, stderr := runTool("create", "--pins", pinPath, "--tenant", "AnyFun", "--package", "com.anyfun.foundation",
			"--alias", "anyfun-release", "--out-dir", out)
		if code != 1 || !strings.Contains(stderr, "已经存在") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	})

	t.Run("seal round trip from create outputs", func(t *testing.T) {
		c := newSigner(t, "amos-signer-c", pins.RoleStandby)
		newPins := filepath.Join(work, "pins-v2.json")
		raw, _ := json.Marshal(pins.File{Format: pins.Format, Signers: []pins.Signer{a.pin, c.pin}})
		if err := os.WriteFile(newPins, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		sealed := filepath.Join(work, "resealed.json")
		code, stdout, stderr := runTool("seal", "--pins", newPins, "--p12", paths["p12"], "--password-file", paths["password"],
			"--tenant", "AnyFun", "--package", "com.anyfun.foundation", "--out", sealed)
		if code != 0 {
			t.Fatalf("seal exit %d: %s", code, stderr)
		}
		if mode(t, sealed) != 0o600 {
			t.Fatalf("sealed mode %o", mode(t, sealed))
		}
		raw, err := os.ReadFile(sealed)
		if err != nil {
			t.Fatal(err)
		}
		assertUploadOpens(t, raw, "AnyFun", "com.anyfun.foundation", "anyfun-release", password, a, c)
		if !strings.Contains(stdout, certSHA) || strings.Contains(stdout+stderr, password) {
			t.Fatal("seal output lacks the fingerprint or leaks the password")
		}
		// --alias 与原件一致也可以
		code, _, stderr = runTool("seal", "--pins", newPins, "--p12", paths["p12"], "--password-file", paths["password"],
			"--tenant", "AnyFun", "--package", "com.anyfun.foundation", "--alias", "anyfun-release", "--out", filepath.Join(work, "resealed2.json"))
		if code != 0 {
			t.Fatalf("seal with matching alias: %s", stderr)
		}
		// 输出文件已存在
		code, _, _ = runTool("seal", "--pins", newPins, "--p12", paths["p12"], "--password-file", paths["password"],
			"--tenant", "AnyFun", "--package", "com.anyfun.foundation", "--out", sealed)
		if code != 1 {
			t.Fatal("seal overwrote an existing upload file")
		}
	})

	t.Run("seal rejections", func(t *testing.T) {
		wrong := filepath.Join(work, "wrong.password")
		if err := os.WriteFile(wrong, []byte(password+"0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		control := filepath.Join(work, "control.password")
		if err := os.WriteFile(control, []byte(password+"\nsecond-line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		escape := filepath.Join(work, "escape.password")
		if err := os.WriteFile(escape, []byte("abc\x1b[2Jdef\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		base := []string{"seal", "--pins", pinPath, "--p12", paths["p12"], "--tenant", "AnyFun", "--package", "com.anyfun.foundation"}
		cases := map[string][]string{
			"wrong password":  append(append([]string{}, base...), "--password-file", wrong, "--out", filepath.Join(work, "x1.json")),
			"alias mismatch":  append(append([]string{}, base...), "--password-file", paths["password"], "--alias", "other", "--out", filepath.Join(work, "x2.json")),
			"two lines":       append(append([]string{}, base...), "--password-file", control, "--out", filepath.Join(work, "x3.json")),
			"escape sequence": append(append([]string{}, base...), "--password-file", escape, "--out", filepath.Join(work, "x4.json")),
		}
		for name, args := range cases {
			code, stdout, stderr := runTool(args...)
			if code != 1 {
				t.Errorf("%s: exit %d", name, code)
			}
			if strings.Contains(stdout+stderr, password) || strings.Contains(stdout+stderr, "second-line") || strings.Contains(stdout+stderr, "\x1b") {
				t.Errorf("%s: output echoes the password file", name)
			}
			if _, err := os.Stat(args[len(args)-1]); err == nil {
				t.Errorf("%s: wrote an upload file anyway", name)
			}
		}
	})
}

func TestCreateRejectsBadInput(t *testing.T) {
	work := t.TempDir()
	a, b := newSigner(t, "amos-signer-a", pins.RolePrimary), newSigner(t, "amos-signer-b", pins.RoleStandby)
	good := writePins(t, work, a.pin, b.pin)
	tampered := b.pin
	tampered.X25519PublicKeySHA256 = a.pin.X25519PublicKeySHA256
	badDir := filepath.Join(work, "bad")
	if err := os.Mkdir(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mismatch := writePins(t, badDir, a.pin, tampered)

	valid := func(overrides ...string) []string {
		args := map[string]string{"--pins": good, "--tenant": "AnyFun", "--package": "com.anyfun.foundation", "--alias": "anyfun-release"}
		for i := 0; i+1 < len(overrides); i += 2 {
			args[overrides[i]] = overrides[i+1]
		}
		out := []string{"create"}
		for _, k := range []string{"--pins", "--tenant", "--package", "--alias"} {
			out = append(out, k, args[k])
		}
		return append(out, "--out-dir", filepath.Join(work, "out-"+strings.ReplaceAll(strings.Join(overrides, "_"), "/", "_")))
	}
	for name, args := range map[string][]string{
		"pin fingerprint mismatch": valid("--pins", mismatch),
		"missing pin file":         valid("--pins", filepath.Join(work, "nope.json")),
		"bad slug":                 valid("--tenant", "any fun"),
		"bad package":              valid("--package", "Com.Anyfun"),
		"bad alias":                valid("--alias", "my alias"),
	} {
		code, _, stderr := runTool(args...)
		if code != 1 || !strings.HasPrefix(stderr, "错误: ") {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
		if _, err := os.Stat(args[len(args)-1]); err == nil {
			t.Errorf("%s: created the out dir anyway", name)
		}
	}
}

func TestUsage(t *testing.T) {
	for name, args := range map[string][]string{
		"no args":        nil,
		"unknown":        {"generate"},
		"unknown flag":   {"create", "--agent-key", "x"},
		"missing flags":  {"create", "--tenant", "AnyFun"},
		"positional":     {"seal", "extra"},
		"seal no p12":    {"seal", "--pins", "p", "--password-file", "f", "--tenant", "AnyFun", "--package", "com.a.b"},
		"help is usage2": {"create", "-h"},
	} {
		code, stdout, stderr := runTool(args...)
		if code != 2 || !strings.Contains(stderr, "用法") || stdout != "" {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, stdout, stderr)
		}
	}
}
