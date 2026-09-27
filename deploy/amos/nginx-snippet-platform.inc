# 平台控制台（platform.anyfun.win）：静态站点 + 同源的管理接口转给 rn-server 的平台端
# （RN-Server 设计 service-and-console-split-2026-09-27 §3.4、§4.2）。产物在 /opt/rn-foundation/admin/platform，
# 由 RN-Admin 的 CI 用 `rn-foundation-apply admin platform` 换上。
#
# 平台控制台不属于任何租户：Host 原样转（不改写成某个 api.*），X-RN-Console-Host 为空（map 只认 console.*）。
# 平台端认这个域名靠配置 PLATFORM_CONSOLE_HOST，不靠请求头。
include /etc/nginx/conf.d/rn-foundation-snippet-console-static.inc;

# 只开管理接口。打包机、签名闸与新机器注册仍只走 api.*（机器配置里是它，装机命令也写它：MACHINE_API_ORIGIN），
# 这个域名上不给第二个入口。^~ 的理由同租户控制台
location ^~ /v1/admin/ {
    set $rn_service rn_platform;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
    gzip off;
    proxy_hide_header X-Frame-Options;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header Referrer-Policy;
}
location ^~ /v1/ {
    return 404;
}

# 统一登录的回调：认证中心固定回到 <控制台域名>/client/v1/oauth/login
location = /client/v1/oauth/login {
    set $rn_service rn_platform;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
    proxy_hide_header X-Frame-Options;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header Referrer-Policy;
}
