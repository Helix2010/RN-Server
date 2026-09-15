package api

import "testing"

// 没翻译的键不能当启动页标题用：compiledMessages 对没有内容的键返回键名本身，
// 那是管理端的缺失标记；直接铺到启动页上就是用户看到一行「launch.title」。
// 返回空串，App 才会退到它自己那个包的名字。
func TestResolveBrandingDropsUntranslatedLaunchCopy(t *testing.T) {
	config := map[string]any{
		"schemaVersion": 1, "version": 1, "enabled": true,
		"launch": map[string]any{
			"enabled": true, "minDisplayMs": 700,
			"animation":     map[string]any{"type": "fade_scale", "durationMs": 360},
			"defaultVisual": map[string]any{"light": map[string]any{}, "dark": map[string]any{}},
		},
	}
	cases := []struct {
		name     string
		messages map[string]string
		want     string
	}{
		{"有文案：照用", map[string]string{"launch.title": "某租户"}, "某租户"},
		{"值等于键名（没内容的缺失标记）", map[string]string{"launch.title": "launch.title"}, ""},
		{"键整个不存在", map[string]string{}, ""},
		{"空串", map[string]string{"launch.title": ""}, ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			launch := object(resolveBranding(config, "zh-CN", "zh-CN", item.messages)["launch"])
			if got, _ := launch["title"].(string); got != item.want {
				t.Fatalf("title = %q, want %q", got, item.want)
			}
			// 字段必须仍然在：App 的 schema 是 z.string() 非空，缺字段会让现网安装解析失败
			if _, ok := launch["title"]; !ok {
				t.Fatal("title 字段不能缺")
			}
		})
	}
}
