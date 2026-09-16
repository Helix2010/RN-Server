package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// 图标缺了要在花两分钟装依赖**之前**说，而且要说清楚缺哪几个、该放哪里。
// prebuild 报的是一句 ENOENT 加一串 @expo 的栈，看的人不知道那是租户资源没提交。
func TestMissingTenantIconsAreCaughtBeforeTheExpensiveSteps(t *testing.T) {
	worktree := t.TempDir()
	dir := filepath.Join(worktree, "assets", "tenants", "predict-kim")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := missingTenantIcons(worktree, "predict-kim")
	if len(missing) != 4 {
		t.Fatalf("一个都没有时应当报四个：%v", missing)
	}
	for _, name := range missing {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("png"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if left := missingTenantIcons(worktree, "predict-kim"); len(left) != 0 {
		t.Fatalf("补齐之后还报缺：%v", left)
	}
	// 别的租户目录不该影响判断
	if left := missingTenantIcons(worktree, "anyfun"); len(left) != 4 {
		t.Fatalf("另一个租户应当照样报缺：%v", left)
	}
}

// 图标由代理一张一张取下来，写进 app.config.ts 会去读的那个目录。老租户服务端不
// 下发，仓库里那份照旧生效——两种来源共存。
func TestFetchTenantIconsLandsThemWherePrebuildLooks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "image/png")
		_, _ = w.Write([]byte("png-" + filepath.Base(r.URL.Path)))
	}))
	defer server.Close()
	api := newClient(config{Server: server.URL, Token: "t"})

	worktree := t.TempDir()
	job := claimedJob{ID: "bld_x", TenantDirectory: "predict-kim",
		Icons: []string{"icon.png", "android-icon-foreground.png"}}
	written, err := fetchTenantIcons(context.Background(), api, job, worktree)
	if err != nil || written != 2 {
		t.Fatalf("取了 %d 张：%v", written, err)
	}
	got, err := os.ReadFile(filepath.Join(worktree, "assets", "tenants", "predict-kim", "icon.png"))
	if err != nil || string(got) != "png-icon.png" {
		t.Fatalf("图标没落到约定的路径上：%v %q", err, got)
	}

	// 一张都不下发时什么也不做，不去动仓库里已有的
	if n, err := fetchTenantIcons(context.Background(), api, claimedJob{ID: "bld_x"}, worktree); err != nil || n != 0 {
		t.Fatalf("空下发不该动任何东西：%d %v", n, err)
	}
}

// 文件名是服务端给的，但服务端和代理分属不同信任域，路径逃逸各自挡一次
func TestFetchTenantIconsRefusesNamesThatEscape(t *testing.T) {
	api := newClient(config{Server: "https://example.invalid", Token: "t"})
	worktree := t.TempDir()
	for _, name := range []string{"../outside.png", "sub/dir.png", "..", "a/../../b.png"} {
		job := claimedJob{ID: "bld_x", TenantDirectory: "predict-kim", Icons: []string{name}}
		if _, err := fetchTenantIcons(context.Background(), api, job, worktree); err == nil {
			t.Fatalf("%q 应当被拒", name)
		}
	}
}

// 硬杀之后留下的检出必须在下次启动时被清掉——连同裸库里那份登记。只删目录的话
// `git worktree list` 会一直列着一个指向不存在路径的条目；只 prune 的话磁盘照占。
// 真正的理由不是磁盘：那个目录里躺着本次构建解开的 .build-keystore.jks。
func TestPruneOrphanWorktreesRemovesTheCheckoutAndItsRegistration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("没有 git")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	bare := filepath.Join(root, "rn-app.git")
	workspace := filepath.Join(root, "workspace")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	git(source, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(source, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(source, "add", "README")
	git(source, "commit", "-qm", "first")
	git(root, "clone", "-q", "--bare", source, bare)
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}

	// 模拟一条跑到一半被杀掉的任务：检出还在，登记还在，里面还有解开的 keystore
	orphan := filepath.Join(workspace, "bld_orphan")
	git(workspace, "-C", bare, "worktree", "add", "--detach", orphan, "main")
	keystore := filepath.Join(orphan, ".build-keystore.jks")
	if err := os.WriteFile(keystore, []byte("not really a keystore"), 0o600); err != nil {
		t.Fatal(err)
	}

	pruneOrphanWorktrees(context.Background(), config{Workspace: workspace, Repo: bare})

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("检出还在：%v", err)
	}
	listed, err := exec.Command("git", "-C", bare, "worktree", "list").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(listed), "bld_orphan") {
		t.Fatalf("登记还挂在裸库上：\n%s", listed)
	}
}

// 重试要分清"现在不行"和"不行"。5xx 值得再试；4xx 是服务端的判断，重试一百次也是
// 同一个答案，只会把失败原因推迟几分钟才送到人眼前。
func TestUploadRetriesTransientFailuresButNotRejections(t *testing.T) {
	restore := retryBaseDelay
	retryBaseDelay = time.Millisecond
	defer func() { retryBaseDelay = restore }()
	attempts := map[string]int{}
	var mode string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/artifact-uploads"):
			attempts["ticket"]++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"artifact": map[string]any{"token": "tok"},
				"upload":   map[string]any{"method": "PUT", "url": "http://" + r.Host + "/put"},
			})
		case r.URL.Path == "/put":
			attempts["put"]++
			// 前两次装成网关抖动，第三次成功
			if attempts["put"] < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/release"):
			attempts["release"]++
			if mode == "reject" {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"code":"RELEASE_VERSION_NOT_INCREASING"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"release": map[string]any{"id": "rel_x"}})
		}
	}))
	defer server.Close()

	apk := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apk, []byte("apk"), 0o644); err != nil {
		t.Fatal(err)
	}
	api := newClient(config{Server: server.URL, Token: "t"})
	buf := newLogBuffer(newRedactor())

	release, err := api.uploadArtifact(context.Background(), "bld_1", apk, "", "", buf)
	if err != nil {
		t.Fatalf("两次 502 之后应该传上去：%v", err)
	}
	if release != "rel_x" || attempts["put"] != 3 {
		t.Fatalf("release=%q put 次数=%d", release, attempts["put"])
	}

	// 409 是拒绝，不许重试
	mode = "reject"
	attempts["release"] = 0
	if _, err = api.uploadArtifact(context.Background(), "bld_1", apk, "", "", buf); err == nil {
		t.Fatal("版本号没涨还是建出了发布记录")
	}
	if attempts["release"] != 1 {
		t.Fatalf("409 被重试了 %d 次", attempts["release"])
	}
}

// git ref 是**服务端从库里读出来下发的**，而它会被原样交给 git。
// 同一个函数里 TenantDirectory 已经这么挡过一次，理由一样：两端分属不同的
// 信任域，各自把住自己那一侧。
func TestValidateGitRef(t *testing.T) {
	for _, ok := range []string{
		"main", "release/2026-09", "v1.2.3", "feat/backup_recovery",
		"0123456789abcdef0123456789abcdef01234567",
	} {
		if err := validateGitRef(ok); err != nil {
			t.Fatalf("%q 是正常的 ref，不该被拒: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",                    // 空
		"--force",             // 选项注入：git 会把它当成 worktree add 的选项
		"-b",                  //
		"--upload-pack=sh -c", //
		"main;rm -rf /",       // 元字符
		"main branch",         // 空格
		"../../etc/passwd",    // 路径穿越
		"a..b",                // 区间语法，不是单个 committish
		"main\nrm -rf /",      // 换行
		"$(id)",               //
		"`id`",                //
	} {
		if err := validateGitRef(bad); err == nil {
			t.Fatalf("%q 应当被拒绝", bad)
		}
	}
}
