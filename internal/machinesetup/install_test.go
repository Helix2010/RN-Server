package machinesetup

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

// 以 root 执行的脚本里，python3 一律带 -I：否则 `python3 -` 把当前目录放进 sys.path，运维在 /tmp 里
// 执行时，本机任何用户放在那里的 json.py 会以 root 身份运行。
func TestScriptsRunPythonIsolated(t *testing.T) {
	pythonCall := regexp.MustCompile(`\bpython3\b`)
	for _, path := range []string{"install.sh", "install-macos.sh", "../../deploy/setup/build-bundles.sh", "../../deploy/amos/merge-env.sh"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		for i, line := range strings.Split(string(raw), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "#") || strings.HasPrefix(code, "need_commands ") {
				continue
			}
			for _, loc := range pythonCall.FindAllStringIndex(line, -1) {
				calls++
				if !strings.HasPrefix(line[loc[1]:], " -I ") {
					t.Errorf("%s:%d runs python3 without -I: %s", path, i+1, code)
				}
			}
		}
		if calls == 0 {
			t.Errorf("%s: no python3 call found; update this test", path)
		}
	}
}

// 脚本一开始就离开当前目录、收紧 umask、固定 PATH，并清掉继承来的环境与函数
func TestInstallScriptPinsDirectoryUmaskAndEnvironment(t *testing.T) {
	head, _, ok := bytes.Cut(InstallScript, []byte("\nreadonly "))
	if !ok {
		t.Fatal("install.sh has no readonly constants")
	}
	for _, want := range []string{"\nset -euo pipefail\n", "\ncd /\n", "\numask 077\n", "\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n", "compgen -e", "unset -f"} {
		if !bytes.Contains(head, []byte(want)) {
			t.Errorf("install.sh does not start with %q", strings.TrimSpace(want))
		}
	}
	if bytes.Contains(InstallScript, []byte("umask 022")) {
		t.Error("install.sh still widens the umask")
	}
}

// 行为上也核对一遍：当前目录里有 json.py、环境里有 PYTHONPATH，problem_code 照样只用标准库。
// 先证明这个 Python 不加防护时确实会导入当前目录的 json.py，否则“没导入”说明不了什么。
func TestInstallScriptPythonIgnoresTheCurrentDirectory(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not available")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "shadowed")
	if err := os.WriteFile(filepath.Join(dir, "json.py"), []byte("open("+strconv.Quote(marker)+", 'w').write('ran')\nraise SystemExit(0)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(t.TempDir(), "problem.json")
	if err := os.WriteFile(body, []byte(`{"code":"MACHINE_BUNDLE_UNAVAILABLE"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	control := exec.Command(python, "-", body)
	control.Dir = dir
	control.Stdin = strings.NewReader("import json\n")
	_ = control.Run()
	if _, err := os.Stat(marker); err != nil {
		t.Skipf("this python3 does not import json.py from the current directory, so the test would prove nothing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}

	// 去掉末尾的 main 调用，只定义函数，然后调 problem_code
	script, ok := bytes.CutSuffix(InstallScript, []byte("\nmain \"$@\"\nexit\n"))
	if !ok {
		t.Fatal("install.sh does not end with main")
	}
	script = append(script, []byte("\nproblem_code \"$1\"\n")...)
	cmd := exec.Command(bash, "-s", "--", body)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(script)
	cmd.Env = []string{"PATH=" + filepath.Dir(python) + ":/usr/bin:/bin", "PYTHONPATH=" + dir, "PYTHONSTARTUP=" + filepath.Join(dir, "json.py")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("problem_code failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("install.sh's python3 imported json.py from the current directory or PYTHONPATH")
	}
	if string(out) != "MACHINE_BUNDLE_UNAVAILABLE" {
		t.Fatalf("problem_code printed %q", out)
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
		"one-letter instance":   {"--server", "https://api.example.com", "--code", validCode, "--instance", "a"},
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

// ---- Mac 打包机的装机脚本 ----

func TestMacInstallScriptIsEmbedded(t *testing.T) {
	onDisk, err := os.ReadFile("install-macos.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, InstallMacOSScript) || !bytes.HasPrefix(InstallMacOSScript, []byte("#!/usr/bin/env bash\n")) {
		t.Fatal("the embedded script is not install-macos.sh")
	}
	if !bytes.Contains(InstallMacOSScript, []byte("\nset -euo pipefail\n")) {
		t.Fatal("install-macos.sh must run with set -euo pipefail")
	}
	// curl … | bash：最后一行之前全是定义，main 放在最后才执行
	if !bytes.HasSuffix(InstallMacOSScript, []byte("\nmain \"$@\"\nexit\n")) {
		t.Fatal("install-macos.sh must end with main \"$@\" followed by exit")
	}
	head, _, ok := bytes.Cut(InstallMacOSScript, []byte("\nreadonly "))
	if !ok {
		t.Fatal("install-macos.sh has no readonly constants")
	}
	for _, want := range []string{"\ncd /\n", "\numask 077\n", "compgen -e", "unset -f"} {
		if !bytes.Contains(head, []byte(want)) {
			t.Errorf("install-macos.sh does not start with %q", strings.TrimSpace(want))
		}
	}
	// PATH 收紧是对的，但收得太紧就把自己锁死了：node、pnpm、pod 只可能在 Homebrew 的两个
	// 目录里（macOS 不自带），而 preflight 的 need_commands 用 command -v 找它们。少了那两个
	// 目录，**任何一台 Mac 都过不了 preflight**，而报错说的是"缺少前提：命令 node"，人会一遍
	// 遍去装已经装好的东西。2026-09-19 装第一台机器时正是这个状态。
	//
	// 顺序也有讲究：系统目录在前，curl/git/tar 一律解析到系统那一份，Homebrew 被投毒也换不掉。
	if !bytes.Contains(head, []byte("\nPATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin\n")) {
		t.Error("install-macos.sh must put the system directories first and still include the Homebrew ones; " +
			"without them command -v can never find node/pnpm/pod and no Mac can pass preflight")
	}
}

// 首次装机是一次对服务端的信任：脚本、安装包与两把公钥都来自服务端。判据只有一个——
// 发布公钥的指纹——而它必须真的被用来比对，其余摘要必须来自**验过签的清单**。
//
// 这一条盯的是那条链子不能被抄近路：任何一处改回"直接采信 describe 响应里 bundle 那个
// 对象"，这台机器的信任根就变成了服务端说的话，而它手上有全部租户的签名材料。
func TestMacInstallScriptDerivesEverythingFromOneOutOfBandDigest(t *testing.T) {
	script := string(InstallMacOSScript)
	if !strings.Contains(script, "--release-key-sha256") {
		t.Error("install-macos.sh does not take --release-key-sha256")
	}
	// 另外两个不该再要人抄：多两次抄写只是多两次抄错的机会
	for _, gone := range []string{"--expect-sha256", "--allowed-signers-sha256"} {
		if strings.Contains(script, gone) {
			t.Errorf("install-macos.sh still asks the operator for %s", gone)
		}
	}
	if !strings.Contains(script, `printf '%s' "$RELEASE_KEY_SHA256" | grep -Eq '^[0-9a-f]{64}$'`) {
		t.Error("install-macos.sh does not validate the shape of --release-key-sha256")
	}
	// 链子的四环，少一环都不成立
	for _, step := range []string{
		// 1) 人给的指纹认出发布公钥
		`if [ "$got_key_sha" != "$RELEASE_KEY_SHA256" ]; then`,
		// 2) 用它验清单的离线签名。allowed_signers 当场生成，namespace 写死在命令行上：
		// 能从签名文件里读 namespace 的验签方等于没有 namespace
		`printf 'release-key %s\n' "$(cat "$WORK/release-key.pub")" > "$WORK/allowed_signers"`,
		`ssh-keygen -Y verify -f "$WORK/allowed_signers" -I release-key`,
		`-n rn-machine-bundles -s "$WORK/manifest.sig"`,
		// 签的是规范化字节，不是 JSON
		`"rn-machine-bundles-signature/v1",`,
		// 3) 清单要与**验过签的**那串字节里记的摘要对上，摘要才从清单里取
		`want_manifest="$(sed -n 's/^manifestSha256=//p' "$WORK/signed-bytes")"`,
		`if [ "$want_manifest" != "$got_manifest" ]; then`,
		`bundle = (manifest.get("bundles") or {}).get(want_bundle)`,
		// 4) 服务端自报的与已验签的不一致就停
		`sys.exit("服务端自报的归档摘要与已验签清单里的不一致，拒绝安装")`,
	} {
		if !strings.Contains(script, step) {
			t.Errorf("install-macos.sh is missing a link of the trust chain: %s", step)
		}
	}
	// 归档里那把公钥仍要与 describe 用过的那把一致：装到机器上的必须就是它
	if !strings.Contains(script, `[ "$key_sha" = "$RELEASE_KEY_SHA256" ]`) {
		t.Error("install-macos.sh does not re-check the release key it installs")
	}
}

// 这个脚本里不许再出现自己实现的密码学。
//
// 运维在执行前要把它从头读一遍、再与 CI 日志比对 shasum——那是整条链子的第一环，靠的是
// "能读完"。一段椭圆曲线运算没人读得动，比对摘要就只剩比对、没有"我知道我在跑什么"。
// 验签交给 macOS 自带的 ssh-keygen -Y verify，它比我们写的任何一版都更经得起看。
func TestMacInstallScriptRollsNoCryptoOfItsOwn(t *testing.T) {
	script := string(InstallMacOSScript)
	for _, smell := range []string{
		"def ed25519_verify", "ed25519_verify(", // 曾经内嵌过的那一版
		"xrecover", "on_curve", "def mul(", "2**255 - 19", // 曲线运算的痕迹
		"if s >= L:", // 连"拒非 canonical 的 S"也不该由我们来管
	} {
		if strings.Contains(script, smell) {
			t.Errorf("install-macos.sh rolls its own crypto again (%q); verification belongs to ssh-keygen -Y verify", smell)
		}
	}
	if !strings.Contains(script, "ssh-keygen -Y verify") {
		t.Error("install-macos.sh does not verify the manifest with ssh-keygen -Y verify")
	}
	// 它要在 preflight 里被要求，否则缺了会在验签那一步以"签名验不过"的样子出现
	if !strings.Contains(script, "need_commands curl python3 shasum openssl ssh-keygen") {
		t.Error("install-macos.sh does not require ssh-keygen and openssl up front")
	}
}

// 装机命令第二行让人把脚本的 sha256 与 CI 打印的值比对——那是整条信任链的第一环，也是
// "脚本里不自带密码学、所以你能把它从头读完"这个论证的落点：你得先确认跑的就是你读的。
//
// CI 不打印这个值的话，那一行就是一句**做不到的话**，而运维只会以为自己没找到。2026-09-19
// 之前正是这个状态：build-bundles.sh 只打印 install.sh（Linux 那个）的摘要。
func TestBundlesScriptPrintsTheMacInstallDigest(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/setup/build-bundles.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "sha256sum install-macos.sh") {
		t.Error("build-bundles.sh does not print the sha256 of install-macos.sh; " +
			"the second line of the install command tells the operator to compare against it")
	}
}

// CI 对「只改文档的提交」跳过部署（deploy-amos.yml 的 Decide whether this push needs a deploy）。
// 跳的理由不是省那几分钟：**每次部署都产出一份新的安装包，而它必须由平台管理员在离线机器上
// 重新签一次**。为一个改错别字的提交让人再走一遍离线签名，人就会开始嫌那道签名烦——而它是
// "服务端被攻破也换不出能过验的清单"的全部依据。
//
// 判据是一张白名单（docs/、仓库根的 *.md、两份 Mac 手册）。**有两个 .md 是会被打进安装包的**
// （deploy/signer/README.md、deploy/build-agent/README.md），它们改了必须部署。再往安装包里加
// .md 的人不会想到去看那份白名单，所以这里盯着：安装包里的 .md 一变，这条测试就要人回去确认。
func TestBundledMarkdownIsAccountedForInTheDeploySkipList(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/setup/build-bundles.sh")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"deploy/signer/README.md":      true,
		"deploy/build-agent/README.md": true,
	}
	found := map[string]bool{}
	for _, field := range strings.Fields(string(raw)) {
		trimmed := strings.Trim(field, `"'`)
		if !strings.HasSuffix(trimmed, ".md") {
			continue
		}
		if path, ok := strings.CutPrefix(trimmed, "$ROOT/"); ok {
			found[path] = true
		}
	}
	for path := range found {
		if !want[path] {
			t.Errorf("build-bundles.sh now packs %s into a bundle. "+
				"Check the docs whitelist in .github/workflows/deploy-amos.yml (Decide whether this push "+
				"needs a deploy): a file that ships inside a bundle must trigger a deploy, "+
				"otherwise the deployed bundle silently stops matching main", path)
		}
	}
	for path := range want {
		if !found[path] {
			t.Errorf("build-bundles.sh no longer packs %s; drop it from this test and re-check the CI whitelist", path)
		}
	}
}

// 机密不进命令行参数：注册码经 stdin 的 curl 配置或环境变量传，钥匙串口令不 echo。
func TestMacInstallScriptKeepsSecretsOutOfArgv(t *testing.T) {
	script := string(InstallMacOSScript)
	if !strings.Contains(script, `printf 'header = "x-enrollment-code: %s"\n' "$CODE" |`) {
		t.Error("install-macos.sh must pass the enrollment code to curl through a config on stdin")
	}
	if strings.Contains(script, `-H "x-enrollment-code: $CODE"`) || strings.Contains(script, "--code \"$CODE\" ") {
		t.Error("install-macos.sh puts the enrollment code in a command line")
	}
	if !strings.Contains(script, `RN_ENROLLMENT_CODE="$CODE" "$INSTALL_DIR/build-agent" enroll`) {
		t.Error("install-macos.sh must hand the enrollment code to enroll through the environment")
	}
	for _, line := range strings.Split(script, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "echo") && strings.Contains(code, "password") {
			t.Errorf("install-macos.sh echoes a password: %s", code)
		}
	}
}

// FileVault 没开就不装：这台机器上会放全部租户的 Distribution 私钥、上传 Key、
// 机器令牌与 deploy key。
func TestMacInstallScriptRefusesWithoutFileVault(t *testing.T) {
	script := string(InstallMacOSScript)
	if !strings.Contains(script, "fdesetup status") || !strings.Contains(script, "FileVault is On") {
		t.Error("install-macos.sh does not check FileVault")
	}
	index := strings.Index(script, "check_filevault() {")
	if index < 0 {
		t.Fatal("no check_filevault")
	}
	body := script[index:]
	if end := strings.Index(body, "\n# ---- 4."); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "die ") {
		t.Error("install-macos.sh only warns about FileVault; it must refuse to install")
	}
}
