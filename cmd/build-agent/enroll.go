package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/signing/ident"
)

// build-agent enroll：新构建机用控制台发的一次性注册码换长期机器令牌。
//
//	build-agent enroll --server <API 源> --code rne_… --env-file /etc/rn-build-agent.env --state-dir /var/lib/rn-build-agent/state
//
// install.sh 以 root 调用它（设计「2. 新机器」第 5 步）：
//
//  1. env 文件里已经有令牌、状态目录里已经有出处密钥：已注册，什么都不改，注册码不用，退出 0。
//  2. POST /v1/machine-setup/describe：注册码必须属于一台构建机（不消耗注册码）。
//  3. 出处密钥：已有就复用（核对属主与权限），没有就生成。以 root 运行时密钥交给状态目录的属主
//     （rn-build-agent），常驻进程才读得到。
//  4. 先在 env 文件所在目录建好临时文件——写不进去就别消耗注册码。
//  5. POST /v1/machine-setup/enroll 交出处公钥，换回令牌；令牌**直接写进 env 文件**（0600，原子替换），
//     不经过屏幕、日志与命令行参数。已有 env 文件的其它键原样保留，缺的键按默认值补上。
//  6. 打印机器名、机器 id 与出处公钥完整 sha256（公开信息，控制台接受与签名闸 trust-builder 时核对）。

const (
	roleBuilder               = "builder"
	codeEnrollmentCodeInvalid = "ENROLLMENT_CODE_INVALID"
	envKeyServer              = "BUILD_AGENT_SERVER"
	envKeyMachineToken        = "BUILD_AGENT_MACHINE_TOKEN"
	envKeyStateDir            = "BUILD_AGENT_STATE_DIR"
	maxEnvFileBytes           = 1 << 20
)

var enrollmentCodePattern = regexp.MustCompile(`^rne_[A-Za-z0-9_-]{43}$`)

// envEntry 是 env 文件里的一个键。
type envEntry struct{ key, value string }

// envDefaults 是新 env 文件里服务端、令牌、状态目录之外的键，取值同 deploy/build-agent/rn-build-agent.env.example
// （TestEnrollDefaultsMatchTheEnvExample 守着两边一致）。
var envDefaults = []envEntry{
	{"BUILD_AGENT_REPO", "/var/lib/rn-build-agent/repos/rn-app.git"},
	{"BUILD_AGENT_WORKSPACE", "/var/lib/rn-build-jobs"},
	{"BUILD_AGENT_PLATFORMS", "android"},
	{"BUILD_AGENT_TIMEOUT_MINUTES", "45"},
	{"BUILD_AGENT_RUNNER", "/opt/rn-build-agent/build-runner"},
	{"BUILD_AGENT_RUNNER_USER", "builder"},
	{"LANG", "C.UTF-8"},
	{"ANDROID_HOME", "/opt/android-sdk"},
	{"ANDROID_SDK_ROOT", "/opt/android-sdk"},
	{"JAVA_HOME", "/usr/lib/jvm/java-17-openjdk-amd64"},
}

// legacyEnvKeys 是改造前的 env 里带机密的键：这种文件不合并，要先挪走（install.sh 把它留存进 legacy 目录）。
var legacyEnvKeys = []string{"BUILD_AGENT_TOKEN", "BUILD_KEYSTORE_PASSPHRASE"}

type enrollOptions struct {
	server   string
	code     string
	envFile  string
	stateDir string
}

// enrollment 是 enroll 的回答。它装着令牌：打印一律走 printsafe.go 的白名单。
type enrollment struct {
	MachineID string `json:"machineId"`
	Token     string `json:"token"`
	Status    string `json:"status"`
}

// enrollmentDescription 是 describe 的回答里构建机要用的字段；其余字段（安装包清单等）是给 install.sh 的。
type enrollmentDescription struct {
	MachineID string `json:"machineId"`
	Name      string `json:"name"`
	Role      string `json:"role"`
}

func enroll(args []string, stdout, stderr io.Writer) int {
	opts, ok := parseEnrollFlags(args, stderr)
	if !ok {
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	httpClient := &http.Client{Timeout: defaultHTTPRequestTimeout, CheckRedirect: refuseRedirects}
	if err := runEnroll(ctx, opts, httpClient, stdout); err != nil {
		fmt.Fprintln(stderr, "enroll failed:", err)
		return 1
	}
	return 0
}

func parseEnrollFlags(args []string, stderr io.Writer) (enrollOptions, bool) {
	set := flag.NewFlagSet("enroll", flag.ContinueOnError)
	set.SetOutput(stderr)
	var opts enrollOptions
	set.StringVar(&opts.server, "server", "", "the API origin, e.g. https://api.example.com")
	set.StringVar(&opts.code, "code", "", "the one-time enrollment code from the console (rne_…)")
	set.StringVar(&opts.envFile, "env-file", "/etc/rn-build-agent.env", "the env file the machine token is written into")
	set.StringVar(&opts.stateDir, "state-dir", "/var/lib/rn-build-agent/state", "the build agent state directory (provenance key)")
	if err := set.Parse(args); err != nil {
		return opts, false
	}
	if set.NArg() != 0 {
		fmt.Fprintln(stderr, "enroll takes no positional arguments")
		return opts, false
	}
	opts.server = strings.TrimRight(strings.TrimSpace(opts.server), "/")
	if err := checkEnrollServer(opts.server); err != nil {
		fmt.Fprintln(stderr, err)
		return opts, false
	}
	// 注册码格式不对时不回显它
	if !enrollmentCodePattern.MatchString(opts.code) {
		fmt.Fprintf(stderr, "--code must look like rne_ followed by 43 base64url characters (got %d characters)\n", len(opts.code))
		return opts, false
	}
	for name, path := range map[string]string{"--env-file": opts.envFile, "--state-dir": opts.stateDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			fmt.Fprintf(stderr, "%s must be a clean absolute path (got %q)\n", name, path)
			return opts, false
		}
	}
	return opts, true
}

// checkEnrollServer 要求一个纯粹的源：https，或者开发时的回环 http；不带路径、查询、用户信息。
// 它会原样写进 BUILD_AGENT_SERVER，常驻进程把令牌发给它。
func checkEnrollServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("--server must be an origin such as https://api.example.com (got %q)", server)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		// 与常驻进程的配置校验一致：只认这两种回环写法
		if host := u.Hostname(); host == "localhost" || host == "127.0.0.1" {
			return nil
		}
	}
	return fmt.Errorf("--server must be https, except for a loopback address in development (got %q)", server)
}

func runEnroll(ctx context.Context, opts enrollOptions, httpClient *http.Client, stdout io.Writer) error {
	syscall.Umask(0o077)
	lines, exists, err := readEnvFile(opts.envFile)
	if err != nil {
		return err
	}
	for _, key := range legacyEnvKeys {
		if value, ok := envValue(lines, key); ok && value != "" {
			return fmt.Errorf("%s still has %s from before the signing gate: move the old file aside (install.sh keeps it under /root/rn-build-agent-legacy-<date>/) and enroll again", opts.envFile, key)
		}
	}
	// 常驻进程按 env 文件里的状态目录找密钥：两边不一致，这次生成的密钥它就找不到
	if dir, ok := envValue(lines, envKeyStateDir); ok && dir != opts.stateDir {
		return fmt.Errorf("%s says %s=%s but --state-dir is %s; they must be the same directory", opts.envFile, envKeyStateDir, dir, opts.stateDir)
	}
	uid, gid, err := stateDirOwner(opts.stateDir)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(opts.stateDir, provenanceKeyFile)

	if token, _ := envValue(lines, envKeyMachineToken); token != "" {
		if !machineTokenPattern.MatchString(token) {
			return fmt.Errorf("%s has a %s that is not a machine token (%d characters); fix or empty it before enrolling", opts.envFile, envKeyMachineToken, len(token))
		}
		key, err := readKeyFileFor(keyPath, keyOwner(uid))
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s already has a machine token, but %s has no provenance key: this machine's identity is gone. Revoke it in the console, empty %s, and enroll a new machine", opts.envFile, opts.stateDir, envKeyMachineToken)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "already enrolled: %s has a machine token. Nothing was changed and the enrollment code was not used.\n", opts.envFile)
		fmt.Fprintf(stdout, "provenance public key sha256: %s\n", key.sha256)
		return nil
	}

	api := setupAPI{server: opts.server, http: httpClient}
	desc, err := api.describe(ctx, opts.code)
	if err != nil {
		return err
	}
	if desc.Role != roleBuilder {
		return fmt.Errorf("this enrollment code is for a %s, not a build machine; on a signing gate run signer enroll (install.sh picks the right one)", safeWord(desc.Role))
	}
	if !ident.ValidMachineName(desc.Name) || !ident.ValidServerIDWithPrefix(desc.MachineID, "mch") {
		return errors.New("the server described the machine with a malformed name or id")
	}

	key, created, err := ensureProvenanceKey(keyPath, uid, gid)
	if err != nil {
		return err
	}

	// 令牌到手之后才发现写不进 env 文件，注册码就白用了：临时文件先建好
	tmp, err := os.CreateTemp(filepath.Dir(opts.envFile), "."+filepath.Base(opts.envFile)+".enroll-*")
	if err != nil {
		return fmt.Errorf("cannot write next to %s: %w", opts.envFile, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	result, err := api.enroll(ctx, opts.code, key.publicBase64())
	if err != nil {
		return err
	}
	if result.MachineID != desc.MachineID {
		return fmt.Errorf("the server enrolled machine %s although the code described %s; the token was discarded — revoke both in the console", safeWord(result.MachineID), desc.MachineID)
	}
	if !machineTokenPattern.MatchString(result.Token) {
		return errors.New("the server returned a machine token of the wrong shape; the token was discarded — revoke this machine in the console and create a new one")
	}

	previousServer, _ := envValue(lines, envKeyServer)
	content := renderEnrolledEnv(lines, exists, opts, result.Token)
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("writing %s: %w", opts.envFile, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("writing %s: %w", opts.envFile, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", opts.envFile, err)
	}
	if err := os.Rename(tmp.Name(), opts.envFile); err != nil {
		return fmt.Errorf("replacing %s: %w", opts.envFile, err)
	}
	renamed = true
	if dir, err := os.Open(filepath.Dir(opts.envFile)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}

	fmt.Fprintf(stdout, "enrolled build machine %s (%s), status %s\n", desc.Name, desc.MachineID, safeWord(result.Status))
	fmt.Fprintf(stdout, "machine token written to %s (not shown)\n", opts.envFile)
	if previousServer != "" && previousServer != opts.server {
		fmt.Fprintf(stdout, "%s changed from %s to %s\n", envKeyServer, safeOrigin(previousServer), opts.server)
	}
	if created {
		fmt.Fprintln(stdout, "provenance key created in", opts.stateDir)
	} else {
		fmt.Fprintln(stdout, "existing provenance key reused from", opts.stateDir)
	}
	fmt.Fprintf(stdout, "provenance public key sha256: %s\n", key.sha256)
	fmt.Fprintf(stdout, "next: start rn-build-agent, accept %s in the console (compare the sha256 above),\n", desc.Name)
	fmt.Fprintf(stdout, "      then on every signing gate run: signer trust-builder --builder %s\n", desc.Name)
	return nil
}

// stateDirOwner 决定出处密钥属于谁。非 root 运行（开发、测试）时就是自己，目录没有就建；
// root 运行时是状态目录的属主，目录必须已经由 install.sh 建好、属于构建控制进程用户而不是 root。
func stateDirOwner(dir string) (int, int, error) {
	if os.Geteuid() != 0 {
		if err := ensureStateDir(dir, true); err != nil {
			return 0, 0, err
		}
		return -1, -1, nil
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, fmt.Errorf("%s does not exist: create it for the build agent user first (install -d -o rn-build-agent -g rn-build-agent -m 0700 %s)", dir, dir)
	}
	if err != nil {
		return 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("cannot read the owner of %s", dir)
	}
	if st.Uid == 0 {
		return 0, 0, fmt.Errorf("%s belongs to root; it must belong to the user the build agent runs as (rn-build-agent)", dir)
	}
	if err := checkPrivateFor(dir, info, true, int(st.Uid)); err != nil {
		return 0, 0, err
	}
	return int(st.Uid), int(st.Gid), nil
}

// keyOwner 把 stateDirOwner 的 -1（属于当前用户）换成真正的 uid。
func keyOwner(uid int) int {
	if uid < 0 {
		return os.Geteuid()
	}
	return uid
}

// ensureProvenanceKey 读出已有的出处密钥，没有就生成。uid 小于 0 表示属于当前用户。
func ensureProvenanceKey(path string, uid, gid int) (machineKey, bool, error) {
	key, err := readKeyFileFor(path, keyOwner(uid))
	if err == nil {
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return machineKey{}, false, err
	}
	key, err = createKeyFileFor(path, uid, gid)
	if err != nil {
		return machineKey{}, false, fmt.Errorf("cannot create the provenance key: %w", err)
	}
	return key, true, nil
}

// readEnvFile 读出 env 文件的各行。文件不在不是错误；符号链接、非普通文件、超过 1 MiB 是。
func readEnvFile(path string) ([]string, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s must be a regular file, not a symlink or anything else", path)
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxEnvFileBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(raw) > maxEnvFileBytes {
		return nil, false, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return []string{}, true, nil
	}
	return strings.Split(text, "\n"), true, nil
}

// envAssignment 认出 `KEY=value` 行（systemd EnvironmentFile 的写法，前导空白忽略），返回键与去掉引号的值。
func envAssignment(line string) (string, string, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" || trimmed[0] == '#' || trimmed[0] == ';' {
		return "", "", false
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// envValue 取一个键最后一次赋的值（systemd 里后面的赋值覆盖前面的）。
func envValue(lines []string, key string) (string, bool) {
	value, found := "", false
	for _, line := range lines {
		if k, v, ok := envAssignment(line); ok && k == key {
			value, found = v, true
		}
	}
	return value, found
}

// renderEnrolledEnv 写出注册后的 env 文件：服务端与令牌换成这次的（重复的赋值只留一行），其它已有的行
// 原样保留，缺的键按默认值补在末尾。没有旧文件时从默认值写起。
func renderEnrolledEnv(lines []string, exists bool, opts enrollOptions, token string) []byte {
	replace := map[string]string{envKeyServer: opts.server, envKeyMachineToken: token}
	var out []string
	if !exists {
		out = []string{
			"# /etc/rn-build-agent.env —— root:root 0600，由 build-agent enroll 写入。",
			"# 各键的含义见 /opt/rn-build-agent/rn-build-agent.env.example；令牌只在这个文件里，不要贴到任何地方。",
		}
	}
	done := map[string]bool{}
	for _, line := range lines {
		key, _, ok := envAssignment(line)
		if value, replaced := replace[key]; ok && replaced {
			if !done[key] {
				out = append(out, key+"="+value)
			}
			done[key] = true
			continue
		}
		if ok {
			done[key] = true
		}
		out = append(out, line)
	}
	all := append([]envEntry{{envKeyServer, opts.server}, {envKeyMachineToken, token}, {envKeyStateDir, opts.stateDir}}, envDefaults...)
	for _, entry := range all {
		if !done[entry.key] {
			out = append(out, entry.key+"="+entry.value)
			done[entry.key] = true
		}
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// safeWord 把服务端给的短字符串收成可以打印的样子：只留字母数字与 _-，最多 64 个字符。
func safeWord(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "(unprintable)"
	}
	return b.String()
}

// setupAPI 调 /v1/machine-setup：不带机器令牌，靠注册码。
type setupAPI struct {
	server string
	http   *http.Client
}

func (s setupAPI) describe(ctx context.Context, code string) (enrollmentDescription, error) {
	var out enrollmentDescription
	err := s.post(ctx, "/v1/machine-setup/describe", map[string]any{"code": code}, &out)
	return out, err
}

func (s setupAPI) enroll(ctx context.Context, code, ed25519PublicKey string) (enrollment, error) {
	var out enrollment
	err := s.post(ctx, "/v1/machine-setup/enroll", map[string]any{
		"code": code, "x25519PublicKey": nil, "ed25519PublicKey": ed25519PublicKey,
	}, &out)
	return out, err
}

// post 发 JSON、读回不超过 1 MiB 的 JSON。请求体里有注册码，错误信息里只带路径与服务端的回答。
func (s setupAPI) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, defaultHTTPRequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("content-type", "application/json")
	response, err := s.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxJSONResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%s: reading the response failed: %w", path, err)
	}
	if len(payload) > maxJSONResponseBytes {
		return fmt.Errorf("%s returned more than %d bytes", path, maxJSONResponseBytes)
	}
	if failedStatus(response.StatusCode) {
		err := newAPIError(path, response.StatusCode, payload)
		if errorCode(err) == codeEnrollmentCodeInvalid {
			return fmt.Errorf("%s: the enrollment code is not valid — it expires 60 minutes after it was issued, works once, and may have been mistyped; reissue it in the console (%s)", path, codeEnrollmentCodeInvalid)
		}
		return err
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("%s returned a body that is not the expected JSON", path)
	}
	return nil
}
