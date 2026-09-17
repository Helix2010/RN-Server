package api

import (
	"context"
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

/*
公开下载落地页 GET /app/download
（设计 docs/design/ios-testflight-distribution-2026-09-17.md §4.5.5）。

**存在的理由是一个二维码要同时管住两端。** 在这之前，海报和邀请页上的下载按钮固定
指向 /v1/public/releases/latest/download，而那条路由在没有 platform 参数时默认
android——iOS 用户扫码拿到的是一个 APK。iOS 的安装入口是 TestFlight 公开链接，
和 Android 的直装包不是同一类东西，也没法由同一条 302 兼顾。

所以物料上印的是这个地址，不是 TestFlight 链接本身：TF 链接换了（换测试组、
重开公开链接）不用重印二维码。

这个页面的两条纪律与邀请落地页一致：
  - 不显示任何租户内部状态（有没有配、配了什么、发到第几版）；
  - 该平台还没开放时按钮置灰并说明，**不返回 404**——这个地址会被印在海报上，
    印出去之后 404 的成本远高于一句"暂未开放"。
*/

// downloadLandingTemplate 内联模板，与 referral_landing.go 同一形状：这一个页面不值得
// 引入模板文件与静态资源管线。所有插值都走 html/template 的上下文转义。
//
// 注意 `.IOSURL` 与 `.AndroidURL` 落在 href 上：html/template 对 URL 上下文有单独的
// 转义规则（非 http/https 的 scheme 会被替换成 #ZgotmplZ），这是我们要的——installUrl
// 已经在 release.ios 那一侧限定了 https 与 Apple 的域名，这里是第二道。
var downloadLandingTemplate = template.Must(template.New("download").Parse(`<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>下载 {{.AppName}}</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#f4f7fb;color:#101828;padding:24px}
@media (prefers-color-scheme:dark){body{background:#0b1220;color:#f0f4fa}
  .card{background:#121c2d!important;border-color:#35445a!important}
  .hint{background:#1d2a3e!important}}
.card{max-width:420px;width:100%;background:#fff;border:1px solid #d5dde9;border-radius:14px;
      padding:28px;text-align:center;box-sizing:border-box}
h1{font-size:20px;margin:0 0 8px}
p{margin:0 0 20px;color:#5a687c}
a.cta,span.cta{display:block;border-radius:10px;padding:14px;font-weight:600;margin:0 0 12px}
a.cta{background:#3157d5;color:#fff;text-decoration:none}
span.cta{background:#e4e8ef;color:#98a2b3;cursor:not-allowed}
@media (prefers-color-scheme:dark){span.cta{background:#233047;color:#7d8aa0}}
.hint{font-size:13px;color:#5a687c;background:#eaf0f8;border-radius:10px;padding:12px;
      margin:8px 0 0;text-align:left}
</style></head>
<body><div class="card">
<h1>下载 {{.AppName}}</h1>
<p>选择你的设备。</p>
{{if .ShowIOS}}
  {{if .IOSURL}}<a class="cta" href="{{.IOSURL}}">iPhone / iPad 安装</a>
  {{else}}<span class="cta">iPhone / iPad 暂未开放</span>{{end}}
{{end}}
{{if .ShowAndroid}}
  {{if .AndroidURL}}<a class="cta" href="{{.AndroidURL}}">Android 下载</a>
  {{else}}<span class="cta">Android 暂未开放</span>{{end}}
{{end}}
{{if .IOSHint}}<p class="hint">iOS 需要先安装 TestFlight，按页面提示接受邀请即可。<br>
在微信 / 企业微信里打不开时，点右上角「…」选择「在 Safari 中打开」。</p>{{end}}
</div></body></html>`))

// downloadLandingPlatform 从 User-Agent 猜设备。猜不准是常态，所以猜不出来时两个
// 按钮都给——这个页面的失败模式应该是"多给一个按钮"，不是"给错一个按钮"。
//
// iPadOS 13 起的 Safari 默认发桌面 UA（含 Macintosh），所以 Mac 也归到"两个都给"
// 而不是 Android：给一个 Mac 用户看 TestFlight 按钮，比给他一个 APK 强。
func downloadLandingPlatform(userAgent string) string {
	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "android"):
		return "android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ipod"):
		return "ios"
	default:
		return ""
	}
}

func (s *server) downloadLandingPage(c *gin.Context) {
	ctx := c.Request.Context()
	tenant := tenantID(c)
	guess := downloadLandingPlatform(c.GetHeader("User-Agent"))
	showIOS := guess == "" || guess == "ios"
	showAndroid := guess == "" || guess == "android"

	// 平台没在 release.platforms 里开启，就连置灰的按钮都不要出现：那不是"还没发
	// 版"，是这个租户根本不做这个平台
	if showIOS {
		if enabled, err := s.platformEnabled(ctx, tenant, "ios"); err != nil || !enabled {
			showIOS = false
		}
	}
	if showAndroid {
		if enabled, err := s.platformEnabled(ctx, tenant, "android"); err != nil || !enabled {
			showAndroid = false
		}
	}
	// 两个都不开放时仍然渲染页面（会是一张只有标题的卡片）。见文件头：这个地址
	// 被印在物料上，任何情况下都不该是 404。
	if !showIOS && !showAndroid {
		showIOS, showAndroid = true, true
	}

	iosURL := ""
	if showIOS {
		iosURL = s.iosInstallURL(ctx, tenant)
	}
	androidURL := ""
	if showAndroid && s.hasPublicRelease(ctx, tenant, "android") {
		// 带上 platform：那条路由缺参数时默认 android，但依赖默认值等于把这个页面
		// 的正确性寄托在别处的一行兜底上
		androidURL = s.absoluteURL(c, "/v1/public/releases/latest/download?platform=android")
	}

	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = downloadLandingTemplate.Execute(c.Writer, map[string]any{
		"AppName":     s.tenantDisplayName(c),
		"ShowIOS":     showIOS,
		"ShowAndroid": showAndroid,
		"IOSURL":      iosURL,
		"AndroidURL":  androidURL,
		"IOSHint":     showIOS && iosURL != "",
	})
}

// hasPublicRelease 回答"这个平台现在有没有一版可以给匿名访客的包"。
//
// 只看 active。灰度包要凭安装凭证才可见，而这个页面上的访客多半还没装 App——
// 按灰度可见性算会让按钮对着一版他点进去拿不到的包。查不出来按"没有"算：
// 置灰一个其实可用的按钮，比给出一个 404 的下载链接好收场。
func (s *server) hasPublicRelease(ctx context.Context, tenant, platform string) bool {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM app_releases WHERE tenant_id=? AND platform=? AND status='active' ORDER BY build_number DESC LIMIT 1`,
		tenant, platform).Scan(&id)
	return err == nil && id != ""
}
