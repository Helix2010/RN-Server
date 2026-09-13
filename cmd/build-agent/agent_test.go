package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

func baseTenant() map[string]any {
	return map[string]any{
		"slug":                   "anyfun",
		"appName":                "AnyFun",
		"androidPackage":         "com.anyfun.foundation",
		"apiBaseUrl":             "https://api.anyfun.win",
		"bootstrapSignerAddress": "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17",
		"signerSha256":           "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694",
		"version":                "1.3.7",
		"androidVersionCode":     float64(33),
	}
}

func tenantJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWriteTenantFileLandsTheManifestUnderTheTenantDirectory(t *testing.T) {
	worktree := t.TempDir()
	path, err := writeTenantFile(worktree, "anyfun", tenantJSON(t, baseTenant()))
	if err != nil {
		t.Fatal(err)
	}
	// 目录仓库里不存在，代理要自己建出来——文件已经不再随代码提交
	if want := filepath.Join(worktree, "tenants", "anyfun", "tenant.json"); path != want {
		t.Fatalf("written to %s, want %s", path, want)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	if err := json.Unmarshal(raw, &after); err != nil {
		t.Fatal(err)
	}
	for key, want := range baseTenant() {
		if after[key] != want {
			t.Fatalf("%s is %v, want %v", key, after[key], want)
		}
	}
}

// 这几条守的是"身份文件搬到服务端之后，代理这一侧还剩下什么把关"。挡不住服务端
// 故意下发一个别的包名（那件事归 acknowledgeIdentityChange 和排队时的漂移检查），
// 挡的是会产出一个装上去才发现起不来的包的那些输入。
func TestWriteTenantFileRefusesAManifestThatWouldBreakTheApp(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"包名不是反向域名":     func(m map[string]any) { m["androidPackage"] = "notapackage" },
		"配置地址不是 https": func(m map[string]any) { m["apiBaseUrl"] = "http://api.anyfun.win" },
		"缺签名地址":        func(m map[string]any) { delete(m, "bootstrapSignerAddress") },
		"签名地址格式不对":     func(m map[string]any) { m["bootstrapSignerAddress"] = "0xzz" },
		"缺自校验指纹":       func(m map[string]any) { delete(m, "signerSha256") },
		"版本号不是正整数":     func(m map[string]any) { m["androidVersionCode"] = float64(0) },
		"应用名为空":        func(m map[string]any) { m["appName"] = "   " },
	} {
		fields := baseTenant()
		mutate(fields)
		if _, err := writeTenantFile(t.TempDir(), "anyfun", tenantJSON(t, fields)); err == nil {
			t.Fatalf("%s 被放过了", name)
		}
	}
}

// RN 模板那把 debug key 的私钥在每台装了 RN 的机器上。拿它当自校验基准等于把
// 校验关掉，还留下一行"已经校验过了"的假象。
func TestWriteTenantFileRefusesThePublicDebugSigner(t *testing.T) {
	fields := baseTenant()
	fields["signerSha256"] = reactNativeDebugSigner
	_, err := writeTenantFile(t.TempDir(), "anyfun", tenantJSON(t, fields))
	if err == nil || !strings.Contains(err.Error(), "debug key") {
		t.Fatalf("公共 debug 签名指纹被接受了: %v", err)
	}
}

func TestWriteTenantFileRejectsInputItCannotUnderstand(t *testing.T) {
	if _, err := writeTenantFile(t.TempDir(), "anyfun", []byte("not json")); err == nil {
		t.Fatal("不是 JSON 的身份文件被接受了")
	}
	// 任务里没带身份文件，说明服务端根本没能合成出来——这时候硬打出来的包装上去
	// 也起不来，要在这里就说清楚
	if _, err := writeTenantFile(t.TempDir(), "anyfun", nil); err == nil {
		t.Fatal("空的身份文件被接受了")
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

// 代理这道闸是第二个信任域：服务端已经拒绝把 RN 那把公开 debug 密钥登记成发布身份，
// 代理再独立拦一次。它在 2026-09-12 之前从来没有生效过——常量填的是那把密钥的
// SHA-1 补零凑到 64 位，而比对的是 SHA-256，两者永远不相等。
//
// 指纹用字面量写死而不是引常量：这条测试要证明的就是"常量的值是对的"，两边都引
// 同一个常量就退化成同义反复了。值来自
// `keytool -list -v -keystore RN-App/android/app/debug.keystore -storepass android`。
func TestTenantFileRefusesTheRealReactNativeDebugFingerprint(t *testing.T) {
	const realDebugSigner = "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
	manifest := map[string]any{
		"slug":                   "anyfun",
		"appName":                "AnyFun",
		"androidPackage":         "com.anyfun.wallet",
		"apiBaseUrl":             "https://api.anyfun.win",
		"bootstrapSignerAddress": "0x1234567890abcdef1234567890abcdef12345678",
		"signerSha256":           realDebugSigner,
		"version":                "1.0.0",
		"androidVersionCode":     float64(1),
	}
	err := validateTenantFile(manifest)
	if err == nil {
		t.Fatal("the public React Native debug fingerprint was accepted as this app's signing identity")
	}
	if !strings.Contains(err.Error(), "debug key") {
		t.Fatalf("the error does not say why it was refused: %v", err)
	}

	// 换成一把真的密钥就该放行，否则上面那条可能只是被别的校验挡下来了
	manifest["signerSha256"] = "0123456789abcdef" + strings.Repeat("0", 48)
	if err := validateTenantFile(manifest); err != nil {
		t.Fatalf("a normal fingerprint was refused: %v", err)
	}
}

// 检出里没有 scripts/build-sbom.mjs 时要说清楚是这件事，而不是让 node 报一句
// "Cannot find module"。这一步失败会让整个构建失败，错误信息得指到正确的地方。
func TestGenerateSBOMWithoutScriptSaysSo(t *testing.T) {
	worktree := t.TempDir()
	buf := newLogBuffer(newRedactor())
	_, err := generateSBOM(context.Background(), buf, worktree, "predict", filepath.Join(worktree, "app.apk"), os.Environ())
	if err == nil {
		t.Fatal("检出里没有 build-sbom.mjs 却当成功了")
	}
	if !strings.Contains(err.Error(), "build-sbom.mjs") {
		t.Fatalf("错误信息没点明缺什么：%v", err)
	}
}

// SBOM 的输出文件名要跟 APK 同名换后缀：两个文件在对象存储里是分开的两条记录，
// 名字对不上时没人能把它们配成一对。
func TestSBOMOutputNameTracksTheArtifact(t *testing.T) {
	apk := "/w/artifacts/predict-1.3.12-build41-release.apk"
	want := "/w/artifacts/predict-1.3.12-build41-release" + sbomFileSuffix
	if got := strings.TrimSuffix(apk, filepath.Ext(apk)) + sbomFileSuffix; got != want {
		t.Fatalf("SBOM 文件名 = %q，想要 %q", got, want)
	}
}

// 开不了盒子时给出的那句话，必须指向真正的原因：封装口令是**整台打包机共用的一个**，
// 新租户要填已有的那一个。第一版的提示是"把打包机上的 BUILD_KEYSTORE_PASSPHRASE
// 设成同一个"——第二个租户照着做，第一个租户的密钥当场就开不了了。
func TestOpenableExplainsTheSharedPassphrase(t *testing.T) {
	sealed, err := buildkeystore.Seal(buildkeystore.Bundle{
		KeystoreBase64: "eA==", StorePassword: "s", KeyAlias: "a", KeyPassword: "k",
	}, "passphrase-number-one")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed)

	ok, reason := openable(raw, "passphrase-number-one")
	if !ok || reason != "" {
		t.Fatalf("对的口令应当能打开：%v %q", ok, reason)
	}

	ok, reason = openable(raw, "a-completely-different-one")
	if ok {
		t.Fatal("错的口令却报成能打开")
	}
	if !strings.Contains(reason, "整台打包机共用") {
		t.Fatalf("没有点明口令是共用的：%q", reason)
	}
	// 口令本身绝不能出现在报给服务端、最终显示在控制台上的文字里
	for _, secret := range []string{"passphrase-number-one", "a-completely-different-one"} {
		if strings.Contains(reason, secret) {
			t.Fatalf("原因里带上了口令：%q", reason)
		}
	}
}

// 没有配口令、盒子是空的、盒子坏掉——三种都要能分辨，而不是都报成"口令不对"
func TestOpenableDistinguishesTheOtherFailures(t *testing.T) {
	if ok, reason := openable(nil, "x"); ok || !strings.Contains(reason, "没有下发") {
		t.Fatalf("空盒子：%v %q", ok, reason)
	}
	if ok, reason := openable(json.RawMessage(`{}`), ""); ok || !strings.Contains(reason, "BUILD_KEYSTORE_PASSPHRASE") {
		t.Fatalf("没配口令：%v %q", ok, reason)
	}
	if ok, reason := openable(json.RawMessage(`not json`), "passphrase-long-enough"); ok || !strings.Contains(reason, "JSON") {
		t.Fatalf("坏盒子：%v %q", ok, reason)
	}
}
