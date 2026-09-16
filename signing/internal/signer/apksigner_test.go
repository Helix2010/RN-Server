package signer

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/apk"
	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/releasekey"
)

// 真实 apksigner verify --print-certs --verbose 的输出（线上 anyfun 包，2026-09-16）。
const realVerifyOutput = `Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
Signer #1 certificate DN: CN=AnyFun Release, O=AnyFun, C=CN
Signer #1 certificate SHA-256 digest: 1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694
Signer #1 certificate SHA-1 digest: b97130fe2837380b8c96957765a5445dd5031758
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 4096
`

func TestParseVerifyOutput(t *testing.T) {
	r, err := ParseVerifyOutput(realVerifyOutput)
	if err != nil {
		t.Fatal(err)
	}
	const cert = "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694"
	if !r.Verified || r.V1 || !r.V2 || !r.V3 || r.Signers != 1 || len(r.Certificates) != 1 || r.Certificates[0] != cert {
		t.Fatalf("parsed: %+v", r)
	}
	if err := CheckSigned(r, cert); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"not verified":        strings.Replace(realVerifyOutput, "Verifies\n", "DOES NOT VERIFY\n", 1),
		"no v3 line":          strings.Replace(realVerifyOutput, "Verified using v3 scheme (APK Signature Scheme v3): true\n", "", 1),
		"repeated v2":         realVerifyOutput + "Verified using v2 scheme (APK Signature Scheme v2): true\n",
		"count mismatch":      strings.Replace(realVerifyOutput, "Number of signers: 1", "Number of signers: 2", 1),
		"repeated count":      realVerifyOutput + "Number of signers: 1\n",
		"out of order signer": strings.Replace(realVerifyOutput, "Signer #1 certificate SHA-256", "Signer #2 certificate SHA-256", 1),
		"empty":               "",
	} {
		if _, err := ParseVerifyOutput(out); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, mutate := range map[string]func(*VerifyResult){
		"two signers":    func(r *VerifyResult) { r.Signers, r.Certificates = 2, []string{cert, cert} },
		"v3 missing":     func(r *VerifyResult) { r.V3 = false },
		"v2 missing":     func(r *VerifyResult) { r.V2 = false },
		"other cert":     func(r *VerifyResult) { r.Certificates = []string{strings.Repeat("0", 64)} },
		"not verified":   func(r *VerifyResult) { r.Verified = false },
		"no certificate": func(r *VerifyResult) { r.Certificates = nil },
	} {
		bad := r
		mutate(&bad)
		if err := CheckSigned(bad, cert); err == nil {
			t.Errorf("CheckSigned accepted %s", name)
		}
	}
}

// 口令只以文件出现：子进程参数里没有口令，环境为空（env -i），参数与设计第 18 条一致。
func TestApksignerArgumentsAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	script := filepath.Join(dir, "java")
	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + log + ".args\n" +
		"env > " + log + ".env\n" +
		"out=''; prev=''; for a in \"$@\"; do if [ \"$prev\" = --out ]; then out=\"$a\"; fi; prev=\"$a\"; last=\"$a\"; done\n" +
		"if [ -n \"$out\" ]; then cp \"$last\" \"$out\"; fi\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "SENTINEL-PASSWORD-e3b0c442"
	runtime := t.TempDir()
	passFile := filepath.Join(runtime, "store.pass")
	if err := os.WriteFile(passFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "in.apk")
	if err := os.WriteFile(in, []byte("apk"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JDK_JAVA_OPTIONS", "-Dinjected=yes")
	t.Setenv(EnvMachineToken, testToken)
	s := JavaAPKSigner{Java: script, Jar: "/opt/build-tools/lib/apksigner.jar"}
	p := SignParams{KeystorePath: filepath.Join(runtime, "keystore.p12"), KeyAlias: "anyfun-release", StorePasswordFile: passFile,
		KeyPasswordFile: passFile, MinSDK: 24, In: in, Out: filepath.Join(dir, "out.apk"), TmpDir: runtime}
	if err := s.Sign(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(log + ".args")
	env, _ := os.ReadFile(log + ".env")
	if strings.Contains(string(args), secret) || strings.Contains(string(env), secret) {
		t.Fatal("the password reached the child process arguments or environment")
	}
	for _, forbidden := range []string{"JDK_JAVA_OPTIONS", EnvMachineToken, "PATH=/usr"} {
		if strings.Contains(string(env), forbidden) {
			t.Fatalf("the child environment contains %s:\n%s", forbidden, env)
		}
	}
	want := []string{"-XX:-UsePerfData", "-Djava.io.tmpdir=" + runtime, "-jar", "/opt/build-tools/lib/apksigner.jar", "sign",
		"--ks", p.KeystorePath, "--ks-type", "PKCS12", "--ks-key-alias", "anyfun-release",
		"--ks-pass", "file:" + passFile, "--key-pass", "file:" + passFile,
		"--v1-signing-enabled", "false", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
		"--min-sdk-version", "24", "--out", p.Out, in}
	if got := strings.Split(strings.TrimSuffix(string(args), "\n"), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("arguments:\n got %q\nwant %q", got, want)
	}
	relative := p
	relative.KeystorePath = "keystore.p12"
	if err := s.Sign(context.Background(), relative); err == nil {
		t.Fatal("accepted a relative keystore path")
	}
}

func findJavaHome(t *testing.T) string {
	for _, candidate := range []string{os.Getenv("RN_SIGNING_JAVA_HOME"), os.Getenv("JAVA_HOME"), "/usr/lib/jvm/java-17-openjdk-amd64", "/usr/lib/jvm/default-java"} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(candidate, "bin", "java")); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// 集成测试：真 apksigner。RN_SIGNING_BUILD_TOOLS 指向 build-tools 目录（含 lib/apksigner.jar）。
// 设了 RN_SIGNING_TEST_APK 时，另外把线上 anyfun 包剥掉签名后用现场生成的 p12 真签一次。
func TestRealApksigner(t *testing.T) {
	tools := os.Getenv("RN_SIGNING_BUILD_TOOLS")
	if tools == "" {
		t.Skip("RN_SIGNING_BUILD_TOOLS is not set")
	}
	javaHome := findJavaHome(t)
	if javaHome == "" {
		t.Skip("no JDK found (set RN_SIGNING_JAVA_HOME)")
	}
	signer, err := NewJavaAPKSigner(javaHome, tools)
	if err != nil {
		t.Fatal(err)
	}
	key, err := releasekey.Generate(releasekey.Params{Alias: testAlias, CommonName: "Integration", KeyBits: 2048, ValidityYears: 30})
	if err != nil {
		t.Fatal(err)
	}
	material := keystoreMaterial{P12: key.PKCS12, Plain: keystorebox.Plaintext{KeyAlias: testAlias, StorePassword: key.Password, KeyPassword: key.Password,
		P12Base64: base64.StdEncoding.EncodeToString(key.PKCS12)}}
	runtime := t.TempDir()
	if err := os.Chmod(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := TrialSign(ctx, signer, runtime, material, 24, key.CertificateSHA256); err != nil {
		t.Fatalf("trial signing with the real apksigner: %v", err)
	}
	if err := TrialSign(ctx, signer, runtime, material, 24, strings.Repeat("0", 64)); err == nil {
		t.Fatal("trial signing accepted a different certificate")
	}
	if entries, _ := os.ReadDir(runtime); len(entries) != 0 {
		t.Fatalf("trial signing left %d entries in the runtime directory", len(entries))
	}

	unsigned, err := apktest.Build(apktest.Default())
	if err != nil {
		t.Fatal(err)
	}
	signAndVerify(t, signer, runtime, material, key, unsigned, "synthetic")

	if path := os.Getenv("RN_SIGNING_TEST_APK"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		stripped, err := apktest.StripSigningBlock(raw)
		if err != nil {
			t.Fatal(err)
		}
		signAndVerify(t, signer, runtime, material, key, stripped, "anyfun release")
	}
}

func signAndVerify(t *testing.T, signer JavaAPKSigner, runtime string, material keystoreMaterial, key releasekey.Result, unsigned []byte, label string) {
	t.Helper()
	ctx := context.Background()
	work := t.TempDir()
	in := filepath.Join(work, "unsigned.apk")
	out := filepath.Join(work, "signed.apk")
	if err := os.WriteFile(in, unsigned, 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := writeRuntimeFiles(runtime, material)
	if err != nil {
		t.Fatal(err)
	}
	err = signer.Sign(ctx, SignParams{KeystorePath: files.KeystorePath, KeyAlias: testAlias, StorePasswordFile: files.StorePasswordFile,
		KeyPasswordFile: files.KeyPasswordFile, MinSDK: 24, In: in, Out: out, TmpDir: files.Dir})
	if removeErr := files.Remove(); removeErr != nil {
		t.Fatal(removeErr)
	}
	if err != nil {
		t.Fatalf("%s: sign: %v", label, err)
	}
	result, err := signer.Verify(ctx, out, 24, "")
	if err != nil {
		t.Fatalf("%s: verify: %v", label, err)
	}
	if err := CheckSigned(result, key.CertificateSHA256); err != nil {
		t.Fatalf("%s: %v (%+v)", label, err, result)
	}
	if result.V1 || result.V4 {
		t.Fatalf("%s: unexpected schemes %+v", label, result)
	}
	parsed, err := apk.ParseFile(out, apk.DefaultLimits())
	if err != nil {
		t.Fatalf("%s: the signed package no longer parses: %v", label, err)
	}
	if !parsed.SigningBlock || parsed.MisalignedCount != 0 {
		t.Fatalf("%s: signed package facts: signingBlock=%v misaligned=%d", label, parsed.SigningBlock, parsed.MisalignedCount)
	}
	t.Logf("%s: signed %d bytes, certificate %s", label, parsed.Size, key.CertificateSHA256)
}
