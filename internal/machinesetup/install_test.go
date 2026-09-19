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

// macOS 的 sysadminctl 建用户**不建同名组**（主组是 staff），Linux 的 useradd 建。脚本里
// 有好几处 `install -g "$用户名"` 与 `chown "$用户:$用户"`，照搬 Linux 的习惯就会以
// `install: unknown group _rnbuildagent` 失败——装第一台机器时正是死在这里。那条报错不说
// 这是平台差异，人只会以为账户没建成，然后去查 sysadminctl。
func TestMacInstallScriptCreatesAGroupForEveryRoleAccount(t *testing.T) {
	script := string(InstallMacOSScript)
	for _, user := range []string{"AGENT_USER", "RUNNER_USER", "UPLOAD_USER"} {
		asGroup := strings.Contains(script, `-g "$`+user+`"`) ||
			strings.Contains(script, `"$`+user+`:$`+user+`"`)
		if !asGroup {
			continue
		}
		if !strings.Contains(script, `ensure_role_group "$`+user+`"`) {
			t.Errorf("install-macos.sh uses $%s as a group name but never creates that group; "+
				"macOS does not create one group per user the way Linux useradd does", user)
		}
	}
}

// 角色账户用 dscl 一条条写属性建，不用 sysadminctl。
//
// sysadminctl -addUser -roleAccount 在 macOS 15 上留下一条**空记录**——UniqueID、
// PrimaryGroupID、NFSHomeDirectory、UserShell 一个都没有——而且**返回 0**。脚本因此打着
// "已建角色账户"一路往下，三步之后在建目录时以 `install: unknown user _rnbuildagent` 失败，
// 指向完全错误的方向。装第一台机器时就是这么死的。
//
// 判据也必须是 getpwnam（`id`）能不能解析，不是 `dscl . -read` 有没有记录：那条空记录
// dscl 读得到、getpwnam 解析不了，两者会给出相反的答案。
func TestMacInstallScriptBuildsRoleAccountsWithDscl(t *testing.T) {
	script := string(InstallMacOSScript)
	// 禁的是**调用**，不是这个词：上面那段注释正要讲清楚为什么不用它
	if strings.Contains(script, "sysadminctl -addUser") {
		t.Error("install-macos.sh is back on sysadminctl -addUser; it returns 0 while leaving an empty " +
			"user record, which only surfaces three steps later as \"install: unknown user\"")
	}
	if !strings.Contains(script, `if id "$1" >/dev/null 2>&1; then`) {
		t.Error("ensure_role_account must decide with id (getpwnam), not with dscl -read")
	}
	// 没有这四个属性的记录就是一条 getpwnam 看不见的空壳
	for _, key := range []string{"UniqueID", "PrimaryGroupID", "NFSHomeDirectory", "UserShell"} {
		if !strings.Contains(script, `dscl . -create "/Users/$1" `+key) {
			t.Errorf("ensure_role_account does not set %s; without it getpwnam cannot resolve the account", key)
		}
	}
	// 建完必须验一次：dscl 的每一条都可能悄悄失败
	if !strings.Contains(script, `id "$1" >/dev/null 2>&1 || die "角色账户 $1 建完仍然解析不了`) {
		t.Error("ensure_role_account does not verify the account resolves after creating it")
	}
	// 组要先于账户建好，账户拿同名组的 gid 当主组（而不是 staff——每个本地用户都在那里面）
	if strings.Index(script, `ensure_role_group "$AGENT_USER"`) > strings.Index(script, `ensure_role_account "$AGENT_USER"`) {
		t.Error("groups must be created before the accounts that take their gid as a primary group")
	}
}

// 变量名后面紧跟中文时必须写成 ${var}。
//
// 这个脚本跑在 macOS 自带的 /bin/bash 上，而那是 **bash 3.2**（2006 年的 GPLv2 版本），
// 多字节处理比 bash 4/5 弱：`$uid、` 会被它把顿号的头一个字节算进变量名，于是去找一个
// 不存在的 `uid<byte>`，在 set -u 下当场 unbound variable。同样的写法在 Linux 的 bash 5
// 上完全正常——所以本地怎么测都测不出来。
//
// 这类错**只在报错路径上触发**，正是最需要那条消息的时候。装第一台机器时就是这样：建
// 账户失败的那条 die 自己先炸了，真正的原因一个字都没打出来。
func TestMacInstallScriptBracesVariablesBeforeNonASCII(t *testing.T) {
	unbraced := regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*|[0-9])[^\x00-\x7f]`)
	for i, line := range strings.Split(string(InstallMacOSScript), "\n") {
		if m := unbraced.FindString(line); m != "" {
			t.Errorf("install-macos.sh:%d writes %q; macOS ships bash 3.2, which folds the first byte "+
				"of the following multibyte character into the variable name and then dies with "+
				"\"unbound variable\" under set -u. Write ${...} instead.", i+1, m)
		}
	}
}

// 没替换的占位符要在解析参数时就拦住。
//
// 装第一台机器时把文档里的 `--code rne_…` 原样粘了上去：它以 rne_ 开头，于是过了当时那个
// 只看前缀的检查，一路走到第七步才以 `describe 返回 404` 失败——而那条报错说的是"注册码过期
// 或已用过就到控制台重发一个"，指向完全错误的方向，人会跑去重发一个同样用不了的码。
func TestMacInstallScriptRejectsUnsubstitutedPlaceholders(t *testing.T) {
	script := string(InstallMacOSScript)
	// 三个参数里任何一个还带着 …、< 或 > 都算没填
	if !strings.Contains(script, `case "$CODE$SERVER$RELEASE_KEY_SHA256" in`) {
		t.Error("parse_args does not look for unsubstituted placeholders in the three arguments")
	}
	// 注册码的形状要按服务端的口径查，光看 rne_ 前缀挡不住 rne_…
	if !strings.Contains(script, `'^rne_[A-Za-z0-9_-]{43}$'`) {
		t.Error("parse_args does not check the shape of --code; " +
			"a prefix-only check lets the documentation placeholder rne_… straight through")
	}
}

// describe 失败时要按状态码分开说，并把服务端写在 problem+json 里的原因带出来。
//
// 原来所有非 200 都套同一句"注册码过期或已用过就到控制台重发一个"。装第一台机器时撞上
// 503（安装包还没签），照着那句话去重发注册码，换来一模一样的 503——而真正要做的是去签
// 清单。这一步本来就不消耗注册码，那句话从一开始就不可能对。
func TestMacInstallScriptExplainsWhyDescribeFailed(t *testing.T) {
	script := string(InstallMacOSScript)
	for _, want := range []string{
		"503) die \"服务端上的安装包还没签",      // 去签，不是去重发码
		"404 | 410) die \"注册码过期或已经用过", // 这一种才是重发
		"000) die \"连不上",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("describe does not tell the operator what %q actually means", strings.TrimSuffix(want, ") die \""))
		}
	}
	if !strings.Contains(script, `服务端说：${detail}`) {
		t.Error("describe throws away the detail the server put in problem+json; " +
			"without it the operator only sees a status code")
	}
}

// 冒烟必须走生产那条路：由控制进程的账户发起 sudo，而不是以 root 直接切过去。
//
// build-runner 的 self-check 会核对任务根目录属于"调用 sudo 的那个人"（SUDO_UID），生产
// 路径里那个人正是 _rnbuildagent——目录也正属于它。以 root 跑的话 SUDO_UID 是 0，和目录
// 属主永远对不上，冒烟必失败，而它验的根本不是生产路径。装第一台机器时就死在这儿。
//
// 套两层还有个好处：这一下真的走了一遍 sudoers 里那条规则（root 切谁都不需要规则），失败
// 时说"检查 sudoers"才名副其实。
func TestMacInstallScriptSmokeTestsThroughTheControllerAccount(t *testing.T) {
	script := string(InstallMacOSScript)
	if !strings.Contains(script, `sudo -n -u "$AGENT_USER" sudo -n -u "$RUNNER_USER" "$INSTALL_DIR/build-runner" self-check`) {
		t.Error("the smoke test must reach build-runner the way production does — " +
			"controller account first, then sudo to the build user; running it straight from root " +
			"makes SUDO_UID 0 and self-check can never match the jobs root owner")
	}
	// build-runner 说了什么要带出来，别再自己猜原因
	if !strings.Contains(script, `自检失败。它说：`) {
		t.Error("the smoke test throws away what build-runner said and guesses the cause instead")
	}
}

// 无边界的生产者不能接 head：脚本开着 pipefail。
//
// `tr </dev/urandom | head -c 48` 里 head 取够就退出，tr 吃到 SIGPIPE（141），pipefail 把
// 管道的退出码变成 141，set -e 当场**静默**杀掉脚本——没有报错、没有 die，只是回到提示符。
// 装第一台机器时就是这样停在"签名区与上传区"下面一片空白。
//
// 别处那些 `printf … | grep -q` 不受影响：生产者只写几十字节，一次写进管道缓冲区就退出，
// 轮不到 SIGPIPE。区别在于生产者有没有边界，所以这里只盯 /dev/urandom。
func TestMacInstallScriptDoesNotPipeUrandomIntoHead(t *testing.T) {
	script := string(InstallMacOSScript)
	for _, line := range strings.Split(script, "\n") {
		// 跳注释：上面那段注释正要讲清楚为什么不能这么写
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "/dev/urandom") && strings.Contains(line, "| head") {
			t.Errorf("install-macos.sh pipes /dev/urandom into head (%q); "+
				"head exits first, tr takes SIGPIPE, and pipefail plus set -e kill the script "+
				"with no message at all", strings.TrimSpace(line))
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

// 装机最后那行 show-key 必须切到控制进程那个账户。build-agent 认的是"跑它的人得是状态
// 目录的属主"（cmd/build-agent/key.go 的 checkPrivate 用 geteuid），而装机脚本是 root：
// 以 root 跑 show-key 会以 "state must belong to the user running build-agent (uid 0)"
// 失败。真机上就这么发生过——失败信息还被 2>/dev/null 吃掉，屏幕上只剩下紧跟着的那句
// "核对上面这个出处公钥 sha256"，而上面什么都没有。
func TestMacInstallShowsTheFingerprintAsTheAgentAccount(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\nfinish() {\n")
	if start < 0 {
		t.Fatal("no finish() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	// 只看真正调用那个二进制的行（带引号的完整路径）；提示文字里给人抄的示例命令不算。
	calls := 0
	for _, line := range strings.Split(fn, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || !strings.Contains(line, `build-agent" show-key`) {
			continue
		}
		calls++
		if !strings.Contains(line, `sudo -n -u "$AGENT_USER"`) {
			t.Errorf("finish() runs show-key as root:\n  %s\nThe provenance key belongs to $AGENT_USER and "+
				"build-agent refuses to read a state directory it does not own, so this prints nothing — "+
				"while the very next line tells the operator to compare the fingerprint above", strings.TrimSpace(line))
		}
		if strings.Contains(line, "2>/dev/null") {
			t.Errorf("finish() throws away show-key's stderr:\n  %s\nWhen it fails there is nothing left "+
				"on screen to explain why the fingerprint is missing", strings.TrimSpace(line))
		}
	}
	if calls != 1 {
		t.Errorf("finish() calls show-key %d times; expected exactly one call to pin", calls)
	}
}

// 换过程序之后，上一次升级失败的记录就不再成立。只有"升级成功"才会删它
// （cmd/build-agent/upgrade），而装机脚本换二进制不走升级——真机上因此留下一条指向
// 已经装上的那一版的失败记录，控制台上一直挂着，看着像机器有毛病。
func TestMacInstallClearsAStaleUpgradeFailure(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\ninstall_programs() {\n")
	if start < 0 {
		t.Fatal("no install_programs() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	if !strings.Contains(fn, `rm -f "$AGENT_HOME/state/upgrade-failed.json"`) {
		t.Error("install_programs replaces the binaries but leaves state/upgrade-failed.json behind. " +
			"The console then reports a failed upgrade to a version this machine is already running, " +
			"and nothing ever clears it — only a successful self-upgrade does")
	}
}

// 两把材料私钥是**带外**的：内容从密码管理器取，装机时由人放到这台机器上的文件里。
// 脚本绝不能从服务端取它们——服务端只转发它读不懂的密文，那是整套设计的前提
// （ios-signing-material-distribution-2026-09-19 第 2 节）。
func TestMacInstallTakesMaterialKeysOnlyFromLocalFiles(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\ninstall_material_keys() {\n")
	if start < 0 {
		t.Fatal("no install_material_keys() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	for _, forbidden := range []string{"curl", "$SERVER", "describe", "machine-setup"} {
		if strings.Contains(fn, forbidden) {
			t.Errorf("install_material_keys mentions %q. A material private key must never come "+
				"from the server: the whole point is that a compromised server still cannot produce "+
				"usable signing material", forbidden)
		}
	}
	// 各归各的账户：构建那把给 _rnbuilder，上传那把给 _rnuploader。一把给两个账户等于
	// 拿到构建账户就同时拿到了上传能力
	if !strings.Contains(fn, `put_material_key "$MATERIAL_KEY_BUILDER" "$RUNNER_USER"`) ||
		!strings.Contains(fn, `put_material_key "$MATERIAL_KEY_UPLOADER" "$UPLOAD_USER"`) {
		t.Error("the two material keys are not installed under their own accounts")
	}
	// 指纹要打出来让人与控制台核对
	if !strings.Contains(fn, "material-key-fingerprint") {
		t.Error("install_material_keys does not print the fingerprints; a key placed on the wrong " +
			"machine would only show up as 'the material arrived but cannot be opened'")
	}
}

// 私钥文件必须是 0600、归对应账户。别人读得到就不是它独有的了。
func TestMacInstallPlacesMaterialKeysPrivately(t *testing.T) {
	body := string(InstallMacOSScript)
	start := strings.Index(body, "\nput_material_key() {\n")
	if start < 0 {
		t.Fatal("no put_material_key() in install-macos.sh")
	}
	fn := body[start:]
	if end := strings.Index(fn, "\n}\n"); end >= 0 {
		fn = fn[:end]
	}
	if !strings.Contains(fn, `install -o "$account" -g "$account" -m 0600`) {
		t.Error("a material key is not installed 0600 under its own account")
	}
}
