package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	path, err := writeTenantFile(testCheckout(t, worktree), "anyfun", tenantJSON(t, baseTenant()))
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
		if _, err := writeTenantFile(testCheckout(t, t.TempDir()), "anyfun", tenantJSON(t, fields)); err == nil {
			t.Fatalf("%s 被放过了", name)
		}
	}
}

// RN 模板那把 debug key 的私钥在每台装了 RN 的机器上。拿它当自校验基准等于把
// 校验关掉，还留下一行"已经校验过了"的假象。
func TestWriteTenantFileRefusesThePublicDebugSigner(t *testing.T) {
	fields := baseTenant()
	fields["signerSha256"] = reactNativeDebugSigner
	_, err := writeTenantFile(testCheckout(t, t.TempDir()), "anyfun", tenantJSON(t, fields))
	if err == nil || !strings.Contains(err.Error(), "debug key") {
		t.Fatalf("公共 debug 签名指纹被接受了: %v", err)
	}
}

func TestWriteTenantFileRejectsInputItCannotUnderstand(t *testing.T) {
	if _, err := writeTenantFile(testCheckout(t, t.TempDir()), "anyfun", []byte("not json")); err == nil {
		t.Fatal("不是 JSON 的身份文件被接受了")
	}
	// 任务里没带身份文件，说明服务端根本没能合成出来——这时候硬打出来的包装上去
	// 也起不来，要在这里就说清楚
	if _, err := writeTenantFile(testCheckout(t, t.TempDir()), "anyfun", nil); err == nil {
		t.Fatal("空的身份文件被接受了")
	}
}

// 日志尾部要进数据库、进管理端界面。控制进程环境里的机密（本机令牌）一旦出现在输出里，
// 上报前要被替换掉。
func TestRedactorReplacesSecretValuesWhereverTheyAppear(t *testing.T) {
	red := &redactor{values: secretValues([]string{
		"ANDROID_RELEASE_KEYSTORE_PASSWORD=sup3r-secret-passphrase",
		"BUILD_AGENT_MACHINE_TOKEN=agent-token-value",
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

// 图标缺了要在花两分钟装依赖**之前**说，而且要说清楚缺哪几个、该放哪里。
// prebuild 报的是一句 ENOENT 加一串 @expo 的栈，看的人不知道那是租户资源没提交。
func TestMissingTenantIconsAreCaughtBeforeTheExpensiveSteps(t *testing.T) {
	worktree := t.TempDir()
	dir := filepath.Join(worktree, "assets", "tenants", "predict-kim")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := missingTenantIcons(testCheckout(t, worktree), "predict-kim")
	if len(missing) != 4 {
		t.Fatalf("一个都没有时应当报四个：%v", missing)
	}
	for _, name := range missing {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("png"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if left := missingTenantIcons(testCheckout(t, worktree), "predict-kim"); len(left) != 0 {
		t.Fatalf("补齐之后还报缺：%v", left)
	}
	// 别的租户目录不该影响判断
	if left := missingTenantIcons(testCheckout(t, worktree), "anyfun"); len(left) != 4 {
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
	api := newClient(config{Server: server.URL, MachineToken: "rnm_test"})

	worktree := t.TempDir()
	job := claimedJob{ID: "bld_x", Attempt: 1, TenantDirectory: "predict-kim",
		Icons: []string{"icon.png", "android-icon-foreground.png"}}
	written, err := fetchTenantIcons(context.Background(), api, job, testCheckout(t, worktree))
	if err != nil || written != 2 {
		t.Fatalf("取了 %d 张：%v", written, err)
	}
	got, err := os.ReadFile(filepath.Join(worktree, "assets", "tenants", "predict-kim", "icon.png"))
	if err != nil || string(got) != "png-icon.png" {
		t.Fatalf("图标没落到约定的路径上：%v %q", err, got)
	}

	// 一张都不下发时什么也不做，不去动仓库里已有的
	if n, err := fetchTenantIcons(context.Background(), api, claimedJob{ID: "bld_x"}, testCheckout(t, worktree)); err != nil || n != 0 {
		t.Fatalf("空下发不该动任何东西：%d %v", n, err)
	}
}

// 文件名是服务端给的，但服务端和代理分属不同信任域，路径逃逸各自挡一次
func TestFetchTenantIconsRefusesNamesThatEscape(t *testing.T) {
	api := newClient(config{Server: "https://example.invalid", MachineToken: "rnm_test"})
	worktree := t.TempDir()
	for _, name := range []string{"../outside.png", "sub/dir.png", "..", "a/../../b.png"} {
		job := claimedJob{ID: "bld_x", TenantDirectory: "predict-kim", Icons: []string{name}}
		if _, err := fetchTenantIcons(context.Background(), api, job, testCheckout(t, worktree)); err == nil {
			t.Fatalf("%q 应当被拒", name)
		}
	}
}

func testCheckout(t *testing.T, dir string) *checkoutFS {
	t.Helper()
	fsys, err := openCheckoutFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fsys.Close() })
	return fsys
}
