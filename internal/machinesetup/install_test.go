package machinesetup

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	validCode  = "rne_CODEcodeCODEcodeCODEcodeCODEcodeCODEcode123"
	secretCode = "rne_SECRETcodeMUSTneverBEechoedANYWHEREatall"
)

func TestInstallScriptIsEmbedded(t *testing.T) {
	onDisk, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, InstallScript) || !bytes.HasPrefix(InstallScript, []byte("#!/usr/bin/env bash\n")) {
		t.Fatal("the embedded script is not install.sh")
	}
	if !bytes.Contains(InstallScript, []byte("\nset -euo pipefail\n")) {
		t.Fatal("install.sh must run with set -euo pipefail")
	}
	// curl … | bash：最后一行之前的东西必须全部是定义，main 放在最后才执行
	if !bytes.HasSuffix(InstallScript, []byte("\nmain \"$@\"\nexit\n")) {
		t.Fatal("install.sh must end with main \"$@\" followed by exit")
	}
}

func runScript(t *testing.T, args ...string) (int, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	// 与 curl … | bash -s -- 一样：脚本从 stdin 读
	cmd := exec.Command(bash, append([]string{"-s", "--"}, args...)...)
	cmd.Stdin = bytes.NewReader(InstallScript)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), out.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, out.String()
}

func TestInstallScriptSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	if out, err := exec.Command(bash, "-n", "install.sh").CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

// 参数不对以 2 退出，在碰任何东西、连任何地方之前；注册码不回显
func TestInstallScriptRejectsBadArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no arguments":          {},
		"missing code":          {"--server", "https://api.example.com"},
		"malformed code":        {"--server", "https://api.example.com", "--code", secretCode + "!"},
		"http to a public host": {"--server", "http://api.example.com", "--code", validCode},
		"server with a path":    {"--server", "https://api.example.com/v1", "--code", validCode},
		"loopback look-alike":   {"--server", "http://127.0.0.1.example.com", "--code", validCode},
		"short recovery sha":    {"--server", "https://api.example.com", "--code", validCode, "--recovery-sha256", "abcd"},
		"bad expect sha":        {"--server", "https://api.example.com", "--code", validCode, "--expect-sha256", strings.Repeat("g", 64)},
		"long instance":         {"--server", "https://api.example.com", "--code", validCode, "--instance", strings.Repeat("a", 23)},
		"relative jar":          {"--server", "https://api.example.com", "--code", validCode, "--apksigner-jar", "apksigner.jar"},
		"unknown flag":          {"--server", "https://api.example.com", "--code", validCode, "--token", secretCode},
		"flag without value":    {"--server", "https://api.example.com", "--code"},
	} {
		code, out := runScript(t, args...)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, code, out)
		}
		if strings.Contains(out, secretCode) {
			t.Errorf("%s: the code was echoed", name)
		}
	}
}

func TestInstallScriptNeedsRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	fingerprint := strings.Repeat("AB:", 31) + "AB"
	code, out := runScript(t, "--server", "https://api.example.com/", "--code", validCode,
		"--recovery-sha256", fingerprint, "--expect-sha256", strings.Repeat("0", 64), "--instance", "amos-signer-c")
	if code != 1 || !strings.Contains(out, "root") {
		t.Fatalf("exit %d, want 1 with a root message\n%s", code, out)
	}
}

// install.sh 按固定文件名找签名闸模板；模板改名时这里先失败，而不是装机时才失败
func TestInstallScriptFindsTheSignerTemplates(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "signer", "templates")
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		t.Skip("deploy/signer/templates is not in this tree yet")
	}
	for _, name := range []string{"rn-signer-@INSTANCE@.service", "rn-signer-@INSTANCE@-check.socket", "rn-signer-@INSTANCE@-check@.service", "rn-signer-@INSTANCE@.env"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("template %s: %v", name, err)
		}
	}
	for _, want := range []string{`"$unit.service" "$unit-check.socket" "$unit-check@.service"`, `"rn-signer-$INSTANCE.env"`} {
		if !bytes.Contains(InstallScript, []byte(want)) {
			t.Errorf("install.sh no longer renders %s", want)
		}
	}
}
