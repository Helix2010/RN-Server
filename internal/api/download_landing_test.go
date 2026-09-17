package api

import (
	"strings"
	"testing"
)

// UA 猜设备：猜不出来时两个按钮都给。这个页面的失败模式应该是"多给一个按钮"，
// 不是"给错一个按钮"——给 iPhone 用户一个 APK 是我们修的正是这个毛病。
func TestDownloadLandingPlatformFallsBackToShowingBoth(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15": "ios",
		"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15":          "ios",
		"Mozilla/5.0 (iPod touch; CPU iPhone OS 15_8 like Mac OS X)":                  "ios",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36":                 "android",
		"Mozilla/5.0 (Linux; U; Android 13; zh-cn; MI 9) MicroMessenger/8.0":          "android",
		// iPadOS 13 起 Safari 默认发桌面 UA，认不出来；桌面浏览器同理
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15": "",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)":                            "",
		"": "",
	} {
		if got := downloadLandingPlatform(ua); got != want {
			t.Fatalf("%q → %q, want %q", ua, got, want)
		}
	}
}

// 没配安装入口时按钮置灰而不是消失、更不是 404：这个地址会被印在海报上。
func TestDownloadLandingTemplateGreysOutMissingEntryPoints(t *testing.T) {
	var out strings.Builder
	if err := downloadLandingTemplate.Execute(&out, map[string]any{
		"AppName": "AnyFun", "ShowIOS": true, "ShowAndroid": true,
		"IOSURL": "", "AndroidURL": "", "IOSHint": false,
	}); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, want := range []string{"iPhone / iPad 暂未开放", "Android 暂未开放"} {
		if !strings.Contains(page, want) {
			t.Fatalf("expected %q in the page: %s", want, page)
		}
	}
	if strings.Contains(page, "<a class=\"cta\"") {
		t.Fatalf("no link should be rendered when nothing is configured: %s", page)
	}
	// 页面不透出任何租户内部状态——与邀请落地页同一条纪律
	if strings.Contains(page, "tenant") || strings.Contains(page, "release") {
		t.Fatalf("the page must not leak tenant state: %s", page)
	}
}

func TestDownloadLandingTemplateRendersBothEntryPoints(t *testing.T) {
	var out strings.Builder
	if err := downloadLandingTemplate.Execute(&out, map[string]any{
		"AppName": "AnyFun", "ShowIOS": true, "ShowAndroid": true,
		"IOSURL":     "https://testflight.apple.com/join/ABCD1234",
		"AndroidURL": "https://api.example.com/v1/public/releases/latest/download?platform=android",
		"IOSHint":    true,
	}); err != nil {
		t.Fatal(err)
	}
	page := out.String()
	for _, want := range []string{
		`href="https://testflight.apple.com/join/ABCD1234"`,
		`platform=android`,
		"在 Safari 中打开",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("expected %q in the page: %s", want, page)
		}
	}
}

// installUrl 在 release.ios 那侧已经限死 https + Apple 的域名，这里是第二道：
// 模板把 href 当 URL 上下文处理，非 http(s) 的 scheme 会被换成 #ZgotmplZ。
func TestDownloadLandingTemplateNeutralisesHostileURLs(t *testing.T) {
	var out strings.Builder
	if err := downloadLandingTemplate.Execute(&out, map[string]any{
		"AppName": "AnyFun", "ShowIOS": true, "ShowAndroid": false,
		"IOSURL": "javascript:alert(1)", "AndroidURL": "", "IOSHint": false,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "javascript:") {
		t.Fatalf("a javascript: URL must not survive into the page: %s", out.String())
	}
}
