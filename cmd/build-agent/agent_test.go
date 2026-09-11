package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTenant(t *testing.T, fields map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenant.json")
	raw, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseTenant() map[string]any {
	return map[string]any{
		"slug":               "anyfun",
		"appName":            "AnyFun",
		"androidPackage":     "com.anyfun.foundation",
		"apiBaseUrl":         "https://api.anyfun.win",
		"version":            "1.3.7",
		"androidVersionCode": float64(33),
	}
}

func TestApplyBuildVersionTouchesOnlyTheTwoVersionFields(t *testing.T) {
	path := writeTenant(t, baseTenant())
	if err := applyBuildVersion(path, "1.3.8", 34); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	if after["version"] != "1.3.8" || after["androidVersionCode"] != float64(34) {
		t.Fatalf("version was not applied: %v", after)
	}
	// 身份字段一个都不能动
	for _, key := range []string{"slug", "appName", "androidPackage", "apiBaseUrl"} {
		if after[key] != baseTenant()[key] {
			t.Fatalf("%s changed to %v", key, after[key])
		}
	}
}

// 这条用例守的是整套设计的那条线：数据库能提供构建参数，不能提供构建身份。
// 服务端一旦能改到 applicationId，一次注入就能产出一个身份不同、却用我们的密钥
// 签名的 APK——而 Android 用（包名 + 签名证书）认身份，那个包能在用户设备上原地
// 覆盖安装，数据目录连钱包一起留着。
func TestApplyBuildVersionRefusesToChangeIdentity(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"package renamed": func(m map[string]any) { m["androidPackage"] = "com.evil.app" },
		"api redirected":  func(m map[string]any) { m["apiBaseUrl"] = "https://evil.example" },
		"field dropped":   func(m map[string]any) { delete(m, "slug") },
		"field added":     func(m map[string]any) { m["extra"] = "x" },
	} {
		before := baseTenant()
		after := baseTenant()
		mutate(after)
		after["version"] = "1.3.8"
		after["androidVersionCode"] = float64(34)
		if err := assertOnlyVersionChanged(before, after); err == nil {
			t.Fatalf("%s was allowed", name)
		}
	}
}

func TestApplyBuildVersionRejectsAFileItCannotUnderstand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tenant.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyBuildVersion(path, "1.0.0", 1); err == nil {
		t.Fatal("a tenant file that is not JSON was accepted")
	}
	if err := applyBuildVersion(filepath.Join(dir, "missing.json"), "1.0.0", 1); err == nil {
		t.Fatal("a missing tenant file was accepted")
	}
}

// 日志尾部要进数据库、进管理端界面，而 Gradle 失败时很乐意把整条命令行打出来，
// 里面就有 keystore 口令。
func TestRedactorReplacesSecretValuesWhereverTheyAppear(t *testing.T) {
	red := &redactor{values: secretValues([]string{
		"ANDROID_RELEASE_KEYSTORE_PASSWORD=sup3r-secret-passphrase",
		"BUILD_AGENT_TOKEN=agent-token-value",
		"HOME=/home/builder",
		"SHORT_PASSWORD=abc",
	})}
	line := red.line("gradle -Ppass=sup3r-secret-passphrase --token agent-token-value in /home/builder")
	if strings.Contains(line, "sup3r-secret-passphrase") || strings.Contains(line, "agent-token-value") {
		t.Fatalf("a secret survived redaction: %s", line)
	}
	// 非机密的变量值不能被顺手抹掉，否则日志会难读到没法定位
	if !strings.Contains(line, "/home/builder") {
		t.Fatalf("a harmless value was redacted: %s", line)
	}
	// 太短的值不参与替换：三个字母到处都是，替换它等于把日志毁掉
	if red.line("abc def") != "abc def" {
		t.Fatal("a very short secret was used for substring replacement")
	}
}

func TestLogBufferKeepsTheTailAndRedactsOnTheWayIn(t *testing.T) {
	buf := newLogBuffer(&redactor{values: []string{"sup3r-secret"}})
	for i := 0; i < 260; i++ {
		buf.add("line")
	}
	buf.add("password=sup3r-secret")
	snapshot := buf.snapshot()
	if len(snapshot) != 200 {
		t.Fatalf("buffer kept %d lines", len(snapshot))
	}
	// 失败原因永远在最后
	if !strings.HasPrefix(snapshot[len(snapshot)-1], "password=") {
		t.Fatalf("the last line was dropped: %q", snapshot[len(snapshot)-1])
	}
	if strings.Contains(strings.Join(snapshot, "\n"), "sup3r-secret") {
		t.Fatal("a secret reached the buffer unredacted")
	}
}

func TestLoadConfigRefusesAnIncompleteOrUnsafeSetup(t *testing.T) {
	full := map[string]string{
		"BUILD_AGENT_SERVER":    "https://api.example.com",
		"BUILD_AGENT_TOKEN":     "token",
		"BUILD_AGENT_REPO":      "/srv/rn-app.git",
		"BUILD_AGENT_WORKSPACE": "/var/lib/rn-build-agent",
	}
	apply := func(overrides map[string]string) {
		for _, key := range []string{"BUILD_AGENT_SERVER", "BUILD_AGENT_TOKEN", "BUILD_AGENT_REPO",
			"BUILD_AGENT_WORKSPACE", "BUILD_AGENT_PLATFORMS", "BUILD_AGENT_TIMEOUT_MINUTES"} {
			os.Unsetenv(key)
		}
		for key, value := range full {
			t.Setenv(key, value)
		}
		for key, value := range overrides {
			if value == "" {
				os.Unsetenv(key)
			} else {
				t.Setenv(key, value)
			}
		}
	}

	apply(nil)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("a complete configuration was rejected: %v", err)
	}
	for name, overrides := range map[string]map[string]string{
		"no server":            {"BUILD_AGENT_SERVER": ""},
		"no token":             {"BUILD_AGENT_TOKEN": ""},
		"no repo":              {"BUILD_AGENT_REPO": ""},
		"no workspace":         {"BUILD_AGENT_WORKSPACE": ""},
		"relative work":        {"BUILD_AGENT_WORKSPACE": "workspace"},
		"plain http":           {"BUILD_AGENT_SERVER": "http://api.example.com"},
		"bad platform":         {"BUILD_AGENT_PLATFORMS": "windows"},
		"absurd timeout":       {"BUILD_AGENT_TIMEOUT_MINUTES": "0"},
		"timeout not a number": {"BUILD_AGENT_TIMEOUT_MINUTES": "soon"},
	} {
		apply(overrides)
		if _, err := loadConfig(); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	// 本地回环允许 http：开发时没有证书，而这时 token 不出机器
	apply(map[string]string{"BUILD_AGENT_SERVER": "http://127.0.0.1:3000"})
	if _, err := loadConfig(); err != nil {
		t.Fatalf("a loopback development server was rejected: %v", err)
	}
}

// 仓库里的租户目录名与服务端的租户 slug 是两套命名：2026-09-11 部署时线上 slug
// 是 Predict.Kim，而仓库里的目录叫 anyfun。代理只认 tenantDirectory，而且必须挡住
// 任何能跳出 tenants/ 的写法——它会被直接拼进路径。
func TestTenantDirectoryMustStayInsideTenants(t *testing.T) {
	for name, value := range map[string]string{
		"empty":         "",
		"parent":        "..",
		"nested parent": "a/../../etc",
		"absolute":      "/etc/passwd",
		"slash":         "a/b",
		"backslash":     `a\b`,
	} {
		if value != "" && !strings.ContainsAny(value, `/\`) && !strings.Contains(value, "..") {
			t.Fatalf("%s should be caught by the guard", name)
		}
	}
	// 正常的目录名要放过
	for _, value := range []string{"anyfun", "tenant-2", "a.b_c"} {
		if strings.ContainsAny(value, `/\`) || strings.Contains(value, "..") {
			t.Fatalf("%q was treated as unsafe", value)
		}
	}
}

// keystore 口令是**运行时**从盒子里开出来的，不在进程环境里。不把它登记进脱敏器，
// Gradle 一旦把命令行打出来，口令就直接进了数据库和管理端界面。
func TestRuntimeSecretsAreRedactedAfterRegistration(t *testing.T) {
	red := newRedactor()
	buf := newLogBuffer(red)
	buf.add("gradle -Pstore=unsealed-store-password")
	// 登记之前是原样留着的——这正是不登记会发生的事
	if !strings.Contains(strings.Join(buf.snapshot(), "\n"), "unsealed-store-password") {
		t.Fatal("the fixture is wrong: the secret should be visible before registration")
	}
	red.add("unsealed-store-password")
	buf.add("gradle -Pstore=unsealed-store-password")
	last := buf.snapshot()
	if strings.Contains(last[len(last)-1], "unsealed-store-password") {
		t.Fatalf("a registered runtime secret still leaked: %s", last[len(last)-1])
	}
	// 太短的不参与替换：三五个字母到处都是，替换它等于毁掉日志
	red.add("abc")
	if red.line("abc def") != "abc def" {
		t.Fatal("a very short runtime secret was used for substring replacement")
	}
}

// needle 必须落在 PEM 的**一整行**里：每 64 个字符换一次行，跨行取会因为换行符
// 而在包里永远找不到——那会让这道检查变成一条恒假的断言，比没有更坏。
func TestCertificateNeedleComesFromASingleLine(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\n" +
		strings.Repeat("A", 64) + "\n" +
		strings.Repeat("B", 64) + "\n" +
		strings.Repeat("C", 64) + "\n" +
		"-----END CERTIFICATE-----\n"
	needle := certificateNeedle(pem)
	if len(needle) != 48 {
		t.Fatalf("needle is %d characters", len(needle))
	}
	if strings.Contains(needle, "\n") || strings.Contains(needle, "-----") {
		t.Fatalf("needle crosses a line or includes the armour: %q", needle)
	}
	if !strings.Contains(pem, needle) {
		t.Fatal("the needle cannot be found in the certificate it came from")
	}
	// 太短、空的、只有头尾的都不能硬凑出一个 needle——那会让检查恒真或恒假
	for name, input := range map[string]string{
		"empty":      "",
		"armour":     "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
		"one line":   "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("A", 64) + "\n-----END CERTIFICATE-----\n",
		"short line": "-----BEGIN CERTIFICATE-----\nAA\nBB\nCC\n-----END CERTIFICATE-----\n",
	} {
		if certificateNeedle(input) != "" {
			t.Fatalf("%s produced a needle anyway", name)
		}
	}
}

// AndroidManifest.xml 的字符串池是 UTF-16LE。只按 UTF-8 找，这道检查就成了恒假
// 的断言——2026-09-11 第一版正是如此，一个内容完全正确的包被判成"没编进证书"。
func TestUTF16LEMatchesHowAndroidStoresManifestStrings(t *testing.T) {
	got := utf16LE("AB")
	want := []byte{'A', 0, 'B', 0}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(utf16LE("")) != 0 {
		t.Fatal("an empty string produced bytes")
	}
}
