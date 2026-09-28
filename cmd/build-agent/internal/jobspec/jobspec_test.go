package jobspec

import (
	"bytes"
	"strings"
	"testing"
)

func testLayout(t *testing.T) Layout {
	t.Helper()
	layout, err := NewLayout("/var/lib/rn-build-jobs", "bld_abcdEFGH1234")
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func testEnv(t *testing.T, layout Layout) []string {
	t.Helper()
	env, err := BuildEnv(layout, map[string]string{
		"PATH":                      "/usr/local/bin:/usr/bin:/bin",
		"JAVA_HOME":                 "/usr/lib/jvm/java-17-openjdk-amd64",
		"ANDROID_HOME":              "/opt/android-sdk",
		"BUILD_AGENT_MACHINE_TOKEN": "rnm_must-never-reach-the-runner",
		"SSH_AUTH_SOCK":             "/run/user/1000/agent",
	}, TaskEnv{Platform: PlatformAndroid, TenantDirectory: "anyfun", APIBaseURL: "https://api.anyfun.win", GoogleServices: true})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// 任务目录会被拼进路径：根目录与任务 id 的每一种逃逸写法都要挡住
func TestLayoutRefusesPathsThatEscape(t *testing.T) {
	for _, root := range []string{"", "relative/jobs", "/", "/var/lib/../etc", "/var/lib/jobs/", "/var/lib/./jobs"} {
		if _, err := NewLayout(root, "bld_abcd1234"); err == nil {
			t.Errorf("root %q was accepted", root)
		}
	}
	for _, id := range []string{"", "..", "../etc", "bld_ab/cd", "bld_..", "bld_abc", "BLD_abcd1234", "bld_abcd1234\n", "bld_abcd 1234"} {
		if _, err := NewLayout("/var/lib/rn-build-jobs", id); err == nil {
			t.Errorf("job id %q was accepted", id)
		}
	}
}

// 白名单之外的变量一个都不给：控制进程环境里的令牌、ssh agent 之类即使被传进来也要被丢掉
func TestBuildEnvKeepsOnlyTheAllowList(t *testing.T) {
	layout := testLayout(t)
	env := testEnv(t, layout)
	joined := strings.Join(env, "\n")
	for _, leaked := range []string{"BUILD_AGENT_MACHINE_TOKEN", "rnm_", "SSH_AUTH_SOCK"} {
		if strings.Contains(joined, leaked) {
			t.Fatalf("%s reached the runner environment:\n%s", leaked, joined)
		}
	}
	want := map[string]string{
		"HOME":                                  layout.Home(),
		"GRADLE_USER_HOME":                      layout.GradleUserHome(),
		"npm_config_store_dir":                  layout.PnpmStore(),
		"TMPDIR":                                layout.Tmp(),
		"EXPO_PUBLIC_TENANT":                    "anyfun",
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE": "./ota-certificate.pem",
		"EXPO_REQUIRE_OTA_SIGNING":              "1",
		"GOOGLE_SERVICES_JSON":                  "./google-services.json",
		"JAVA_HOME":                             "/usr/lib/jvm/java-17-openjdk-amd64",
	}
	for key, value := range want {
		if got := EnvValue(env, key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	// 删掉的开关不许回来
	if strings.Contains(joined, "GRADLE_DEPENDENCY_VERIFICATION") || strings.Contains(joined, "ANDROID_RELEASE_") {
		t.Fatal("a removed signing or verification switch is back in the environment")
	}
}

func TestCheckEnvRefusesAnythingOffTheList(t *testing.T) {
	layout := testLayout(t)
	good := testEnv(t, layout)
	if err := CheckEnv(layout, good, PlatformAndroid); err != nil {
		t.Fatalf("the built environment was refused: %v", err)
	}
	other, _ := NewLayout("/var/lib/rn-build-jobs", "bld_otherJOB9999")
	for name, env := range map[string][]string{
		"unknown key":                append(append([]string{}, good...), "LD_PRELOAD=/tmp/evil.so"),
		"token":                      append(append([]string{}, good...), "BUILD_AGENT_MACHINE_TOKEN=rnm_x"),
		"another job's gradle home":  replace(good, "GRADLE_USER_HOME", other.GradleUserHome()),
		"shared gradle home":         replace(good, "GRADLE_USER_HOME", "/var/cache/rn-build-agent/gradle"),
		"relative PATH entry":        replace(good, "PATH", "node_modules/.bin:/usr/bin"),
		"duplicate":                  append(append([]string{}, good...), "EXPO_REQUIRE_OTA_SIGNING=1"),
		"newline":                    replace(good, "EXPO_PUBLIC_TENANT", "anyfun\nLD_PRELOAD=x"),
		"missing HOME":               drop(good, "HOME"),
		"task value points into job": replace(good, "GOOGLE_SERVICES_JSON", layout.App()+"/google-services.json"),
		"removed switch":             append(append([]string{}, good...), "GRADLE_DEPENDENCY_VERIFICATION=0"),
	} {
		if err := CheckEnv(layout, env, PlatformAndroid); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func replace(env []string, key, value string) []string {
	out := drop(env, key)
	return append(out, key+"="+value)
}

func drop(env []string, key string) []string {
	var out []string
	for _, entry := range env {
		if !strings.HasPrefix(entry, key+"=") {
			out = append(out, entry)
		}
	}
	return out
}

func validSpec(t *testing.T, layout Layout) Spec {
	t.Helper()
	return Spec{
		Version: SpecVersion, JobID: layout.JobID, Kind: KindAPK, Platform: PlatformAndroid, TenantDirectory: "anyfun",
		AppVersion: "1.3.7", BuildNumber: 33, CommitSHA: strings.Repeat("a", 40), Env: testEnv(t, layout),
	}
}

func TestSpecRoundTripsAndRefusesUnknownFields(t *testing.T) {
	layout := testLayout(t)
	spec := validSpec(t, layout)
	raw, err := EncodeSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSpec(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(layout); err != nil {
		t.Fatalf("a valid spec was refused: %v", err)
	}
	withExtra := bytes.Replace(raw, []byte(`"v": 1,`), []byte(`"v": 1, "sealedKeystore": {},`), 1)
	if _, err := DecodeSpec(bytes.NewReader(withExtra)); err == nil {
		t.Fatal("a spec with an unknown field was accepted")
	}
	if _, err := DecodeSpec(bytes.NewReader(append(raw, []byte(`{}`)...))); err == nil {
		t.Fatal("a spec with trailing data was accepted")
	}
	if _, err := DecodeSpec(bytes.NewReader(bytes.Repeat([]byte(" "), MaxSpecSize+1))); err == nil {
		t.Fatal("an oversized spec was accepted")
	}
}

func TestSpecValidateRefusesMismatches(t *testing.T) {
	layout := testLayout(t)
	other, _ := NewLayout(layout.Root, "bld_otherJOB9999")
	for name, mutate := range map[string]func(*Spec){
		"wrong job":         func(s *Spec) { s.JobID = other.JobID },
		"kind":              func(s *Spec) { s.Kind = "shell" },
		"tenant escape":     func(s *Spec) { s.TenantDirectory = "../etc" },
		"commit":            func(s *Spec) { s.CommitSHA = "HEAD" },
		"apk with ota args": func(s *Spec) { s.OTA = &OTAArgs{} },
		"no platform":       func(s *Spec) { s.Platform = "" },
		"unknown platform":  func(s *Spec) { s.Platform = "harmony" },
		// 热更新包与平台无关，由 Android 那台机器构建
		"ota on ios": func(s *Spec) {
			s.Platform = PlatformIOS
			s.Kind = KindOTA
			s.OTA = &OTAArgs{Channel: "production", ApplyStrategy: "next_launch", RuntimeVersion: "1.3.7",
				APIBaseURL: "https://api.anyfun.win", ApplicationID: "dex-mobile"}
		},
		"ota without args": func(s *Spec) { s.Kind = KindOTA },
		"tenant env differs": func(s *Spec) {
			s.Env = replace(s.Env, "EXPO_PUBLIC_TENANT", "other")
		},
		"ota option injection": func(s *Spec) {
			s.Kind = KindOTA
			s.OTA = &OTAArgs{Channel: "--output-zip", ApplyStrategy: "next_launch", RuntimeVersion: "1.3.7",
				APIBaseURL: "https://api.anyfun.win", ApplicationID: "dex-mobile"}
		},
		// 租户与 Team 只属于 iOS 任务，而且要一起给：只有一个时执行进程既不能按租户取材料，也不该退回旧布局
		"tenant on android": func(s *Spec) { s.TenantID, s.AppleTeamID = "1000000001", "J4JDFC8LCC" },
		"tenant without team": func(s *Spec) {
			s.Platform, s.Env = PlatformIOS, testIOSEnv(t, layout)
			s.TenantID = "1000000001"
		},
		"tenant that is a path": func(s *Spec) {
			s.Platform, s.Env = PlatformIOS, testIOSEnv(t, layout)
			s.TenantID, s.AppleTeamID = "../1", "J4JDFC8LCC"
		},
		"team in lower case": func(s *Spec) {
			s.Platform, s.Env = PlatformIOS, testIOSEnv(t, layout)
			s.TenantID, s.AppleTeamID = "1000000001", "j4jdfc8lcc"
		},
	} {
		spec := validSpec(t, layout)
		mutate(&spec)
		if err := spec.Validate(layout); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// 按租户落盘的 iOS 任务带租户与 Team，照样过校验、照样能往返。
func TestIOSSpecCarriesTheTenant(t *testing.T) {
	layout := testLayout(t)
	spec := validSpec(t, layout)
	spec.Platform, spec.Env = PlatformIOS, testIOSEnv(t, layout)
	spec.TenantID, spec.AppleTeamID = "1000000001", "J4JDFC8LCC"
	if err := spec.Validate(layout); err != nil {
		t.Fatalf("a tenant's ios spec was refused: %v", err)
	}
	raw, err := EncodeSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSpec(bytes.NewReader(raw))
	if err != nil || decoded.TenantID != "1000000001" || decoded.AppleTeamID != "J4JDFC8LCC" {
		t.Fatalf("the tenant did not survive the round trip: %+v %v", decoded, err)
	}
}

func testIOSEnv(t *testing.T, layout Layout) []string {
	t.Helper()
	env, err := BuildEnv(layout, map[string]string{"PATH": "/usr/bin:/bin"}, TaskEnv{
		Platform: PlatformIOS, TenantDirectory: "anyfun", APIBaseURL: "https://api.anyfun.win",
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestResultIsCheckedPerKind(t *testing.T) {
	good := `{"v":1,"kind":"apk","nativeFingerprint":"` + strings.Repeat("ab", 20) + `"}`
	if _, err := DecodeResult(strings.NewReader(good), KindAPK, PlatformAndroid); err != nil {
		t.Fatalf("a valid result was refused: %v", err)
	}
	for name, doc := range map[string]string{
		"apk without fingerprint": `{"v":1,"kind":"apk"}`,
		"fingerprint not hex":     `{"v":1,"kind":"apk","nativeFingerprint":"$(id)"}`,
		"unknown field":           `{"v":1,"kind":"apk","nativeFingerprint":"` + strings.Repeat("ab", 20) + `","artifact":"/etc/passwd"}`,
		"kind mismatch":           `{"v":1,"kind":"ota"}`,
		// 上传标记只属于 iOS
		"android reports a toolchain": `{"v":1,"kind":"apk","nativeFingerprint":"` + strings.Repeat("ab", 20) + `","toolchain":"Xcode 16.2"}`,
	} {
		if _, err := DecodeResult(strings.NewReader(doc), KindAPK, PlatformAndroid); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// iOS 的安装包没有原生指纹：那套是签名闸复核未签名包用的，而 iOS 没有签名闸这一环。
func TestIOSResultCarriesNoNativeFingerprint(t *testing.T) {
	if _, err := DecodeResult(strings.NewReader(`{"v":1,"kind":"apk"}`), KindAPK, PlatformIOS); err != nil {
		t.Fatalf("a valid ios result was refused: %v", err)
	}
	// 结果里带的是工具链，不是"传上去了没有"：上传由控制进程交给另一个用户做，
	// 执行进程答不了那个问题
	parsed, err := DecodeResult(strings.NewReader(`{"v":1,"kind":"apk","toolchain":"Xcode 16.2 (16C5032a)"}`), KindAPK, PlatformIOS)
	if err != nil || parsed.Toolchain != "Xcode 16.2 (16C5032a)" {
		t.Fatalf("the toolchain must survive: %#v %v", parsed, err)
	}
	if _, err := DecodeResult(strings.NewReader(`{"v":1,"kind":"apk","uploadedToAppStoreConnect":true}`), KindAPK, PlatformIOS); err == nil {
		t.Fatal("the retired upload flag was accepted")
	}
	withFingerprint := `{"v":1,"kind":"apk","nativeFingerprint":"` + strings.Repeat("ab", 20) + `"}`
	if _, err := DecodeResult(strings.NewReader(withFingerprint), KindAPK, PlatformIOS); err == nil {
		t.Fatal("an ios result carrying a native fingerprint was accepted")
	}
}

// 机器级白名单按 GOOS 组装：RN_IOS_SIGNING_DIR 只在 macOS 上认。
//
// Linux 构建机上出现这个键只可能是配错了，而它是一条指向签名材料的路径——放行等于让
// 一台不该有签名材料的机器以为自己有。上传 Key 的两个标识（ASC_KEY_ID / ASC_ISSUER_ID）
// 已经随手工签名从白名单里删掉：执行进程跑第三方依赖，一把能上传 build 的 Key 就是
// 钥匙串里那些签名材料唯一缺的出口。
func TestMachineEnvKeysAreAssembledPerPlatform(t *testing.T) {
	android := machineEnvKeysFor(PlatformAndroid)
	ios := machineEnvKeysFor(PlatformIOS)
	for _, key := range android {
		if key == IOSSigningDirEnv {
			t.Fatalf("%s is accepted in an android job", IOSSigningDirEnv)
		}
	}
	found := false
	for _, key := range ios {
		if key == IOSSigningDirEnv {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s is not accepted in an ios job", IOSSigningDirEnv)
	}
	// Android 任务的环境里出现签名目录要当场拒收：同一台 Mac 上也不行
	layout := testLayout(t)
	env := append(testEnv(t, layout), IOSSigningDirEnv+"=/var/rn-build-signing")
	if err := CheckEnv(layout, env, PlatformAndroid); err == nil {
		t.Fatal("an android job was allowed to carry the signing directory")
	}
	if err := CheckEnv(layout, env, PlatformIOS); err != nil {
		t.Fatalf("an ios job was refused the signing directory: %v", err)
	}
	for _, keys := range [][]string{android, ios} {
		for _, key := range keys {
			if key == "ASC_KEY_ID" || key == "ASC_ISSUER_ID" {
				t.Fatalf("%s is still on the allow list; the build runner must hold no App Store Connect key", key)
			}
		}
	}
}

// 出网代理是机器级配置，任务环境必须带得过去。
//
// 任务环境是按白名单**重新构造**的，不继承控制进程的环境：不把这几个键放进来，机器上
// 配了代理也传不到构建进程里。而构建非出网不可——CocoaPods 装每一个 pod 都是去 clone
// 它的 git 源。2026-09-20 真机上 pod install 就卡在这儿：
// Failed to connect to github.com port 443 after 75017 ms。
func TestProxyVariablesReachTheBuild(t *testing.T) {
	layout := Layout{Root: "/var/rn-build-jobs", JobID: "bld_proxy0000001"}
	base := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + layout.Home(),
		"GRADLE_USER_HOME=" + layout.GradleUserHome(),
		"npm_config_store_dir=" + layout.PnpmStore(),
		"TMPDIR=" + layout.Tmp(),
		"ANDROID_USER_HOME=" + layout.AndroidUserHome(),
		"EXPO_PUBLIC_TENANT=anyfun",
		"EXPO_PUBLIC_API_BASE_URL=https://api.anyfun.win",
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=",
		"EXPO_REQUIRE_OTA_SIGNING=0",
	}
	// 大小写两套都要认：libcurl 只认小写的 http_proxy
	for _, entry := range []string{
		"HTTPS_PROXY=http://127.0.0.1:7890",
		"https_proxy=http://127.0.0.1:7890",
		"HTTP_PROXY=http://proxy.lan:3128",
		"http_proxy=socks5://127.0.0.1:1080",
		"ALL_PROXY=socks5h://proxy.lan:1080",
		"NO_PROXY=localhost,127.0.0.1,.lan",
		"no_proxy=*",
	} {
		if err := CheckEnv(layout, append(append([]string(nil), base...), entry), PlatformIOS); err != nil {
			t.Errorf("%s 被拒了：%v", entry, err)
		}
	}
}

// 代理地址里带账号口令就等于把那组凭据交给这次构建跑的第三方代码。
func TestProxyCredentialsAreRefused(t *testing.T) {
	layout := Layout{Root: "/var/rn-build-jobs", JobID: "bld_proxy0000002"}
	base := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + layout.Home(),
		"GRADLE_USER_HOME=" + layout.GradleUserHome(),
		"npm_config_store_dir=" + layout.PnpmStore(),
		"TMPDIR=" + layout.Tmp(),
		"ANDROID_USER_HOME=" + layout.AndroidUserHome(),
		"EXPO_PUBLIC_TENANT=anyfun",
		"EXPO_PUBLIC_API_BASE_URL=https://api.anyfun.win",
		"EXPO_UPDATES_CODE_SIGNING_CERTIFICATE=",
		"EXPO_REQUIRE_OTA_SIGNING=0",
	}
	for _, bad := range []string{
		"HTTPS_PROXY=http://user:pass@proxy.lan:3128",
		"HTTPS_PROXY=not-a-url",
		"HTTPS_PROXY=file:///etc/passwd",
		"HTTP_PROXY=http://proxy.lan:3128/some/path",
	} {
		err := CheckEnv(layout, append(append([]string(nil), base...), bad), PlatformIOS)
		if err == nil {
			t.Errorf("%s 被放过了", bad)
		}
	}
}
