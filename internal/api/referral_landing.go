package api

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/Helix2010/RN-Server/internal/referral"
	"github.com/gin-gonic/gin"
)

/*
邀请落地页 GET /app/invite/:code（设计 §4.6）。

装了 App 且 Android 校验过域名归属时，系统直接唤起 App，走不到这里。
走到这里的是两类人：没装 App 的，和装了但系统还没校验通过的（安装时校验，
assetlinks.json 那会儿不在位就得等系统下次重试）。

页面只给三样东西：这个码有效、码本身、去哪儿下载。**不显示邀请人的任何信息**——
它和 codes/:code 读同一份数据、共用同一个限流计数器，返回内容也必须一样克制。
*/

// referralLandingTemplate 内联模板：这一个页面不值得引入模板文件与静态资源管线。
// 所有插值都走 html/template 的上下文转义。
var referralLandingTemplate = template.Must(template.New("invite").Parse(`<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.AppName}} 邀请</title>
<style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#f4f7fb;color:#101828;padding:24px}
@media (prefers-color-scheme:dark){body{background:#0b1220;color:#f0f4fa}
  .card{background:#121c2d!important;border-color:#35445a!important}
  .code{background:#1d2a3e!important}}
.card{max-width:420px;width:100%;background:#fff;border:1px solid #d5dde9;border-radius:14px;
      padding:28px;text-align:center;box-sizing:border-box}
h1{font-size:20px;margin:0 0 8px}
p{margin:0 0 20px;color:#5a687c}
.code{font:700 28px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:2px;
      background:#eaf0f8;border-radius:10px;padding:16px;margin:0 0 20px;word-break:break-all}
a.cta{display:block;background:#3157d5;color:#fff;text-decoration:none;border-radius:10px;
      padding:14px;font-weight:600}
</style></head>
<body><div class="card">
<h1>你收到一个邀请</h1>
<p>在 {{.AppName}} 里填写下面的邀请码即可绑定邀请人。</p>
<div class="code">{{.Code}}</div>
<a class="cta" href="{{.DownloadURL}}">下载 {{.AppName}}</a>
</div></body></html>`))

func (s *server) referralLandingPage(c *gin.Context) {
	valid, outcome := s.lookupInviteCode(c, c.Param("code"))
	if outcome != nil || !valid {
		// 码无效、格式不对、租户没开启邀请，一律同一个 404 页面：
		// 不区分"这个租户没开"和"这个码不存在"，免得把租户状态透出去
		s.referralLandingNotFound(c, outcome)
		return
	}
	// 展示用分段形态，提高抄写正确率；归一化会去掉连字符，粘回输入框也认
	code, _ := referral.Normalize(c.Param("code"))
	c.Header("Cache-Control", "no-store")
	c.Status(http.StatusOK)
	c.Header("Content-Type", "text/html; charset=utf-8")
	_ = referralLandingTemplate.Execute(c.Writer, map[string]string{
		"AppName":     s.tenantDisplayName(c),
		"Code":        referral.Format(code),
		"DownloadURL": "/v1/public/releases/latest/download",
	})
}

func (s *server) referralLandingNotFound(c *gin.Context, outcome *referralBindOutcome) {
	status := http.StatusNotFound
	// 限流命中要如实回 429，否则扫描器分不清"被限流"和"码不存在"，
	// 而正常用户会以为自己的码坏了
	if outcome != nil && outcome.Status == http.StatusTooManyRequests {
		status = http.StatusTooManyRequests
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(status, `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<meta name="robots" content="noindex"><title>邀请码无效</title></head>`+
		`<body style="font:16px/1.6 -apple-system,sans-serif;padding:40px;text-align:center">`+
		`<h1 style="font-size:20px">邀请码无效</h1>`+
		`<p style="color:#5a687c">请向邀请你的人重新确认这个链接。</p></body></html>`)
}

// tenantDisplayName 落地页标题里的应用名。取品牌配置里的应用名，取不到就用中性称呼——
// 这里不是"兜底换个值下发"，页面本身不携带任何需要它准确的语义。
func (s *server) tenantDisplayName(c *gin.Context) string {
	var raw []byte
	if err := s.db.QueryRowContext(c.Request.Context(),
		`SELECT config_value FROM app_configs WHERE config_key='mobile-bootstrap' AND tenant_id IN (?,0) ORDER BY (tenant_id=?) DESC LIMIT 1`,
		tenantID(c), tenantID(c)).Scan(&raw); err != nil {
		return "应用"
	}
	value := map[string]any{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "应用"
	}
	localization := object(value["localization"])
	messages := object(localization["messages"])
	fallback, _ := localization["fallbackLocale"].(string)
	if dictionary := object(messages[fallback]); dictionary != nil {
		if name, ok := dictionary["app.name"].(string); ok && name != "" {
			return name
		}
	}
	return "应用"
}
