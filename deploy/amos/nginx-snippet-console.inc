# 租户控制台：静态站点 + 同源的 /v1/ 转给租户端。三个 console.* 的 root 都是同一份产物
# /opt/rn-foundation/admin/console（RN-Admin 设计 console-single-build-same-origin-2026-09-25）。
include /etc/nginx/conf.d/rn-foundation-snippet-console-static.inc;

# 控制台请求 API 走同源相对路径 /v1/...，这里转给 rn-server 的租户端。
#
# ^~ 必须有：静态片段里那条 ~* \.(js|css|png|...)$ 的正则 location 优先于普通前缀，不带 ^~ 的话
# /v1/.../xxx.png 会被它截走、按静态文件 404。
location ^~ /v1/ {
    # map 里没有这个控制台域名：不能转——Host 会原样是 console.*，后端虽然认得出租户，但拼出来的
    # 下载地址、新机器的安装命令都会变成控制台域名，构建机就被绑到了控制台上。直接报错，第一眼就能发现
    if ($rn_upstream_host = $host) {
        return 500;
    }
    set $rn_service rn_tenant;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
    # api.* 今天不压 JSON；gzip 会把强 ETag 改成弱 ETag。与跨域时代保持一致
    gzip off;
    # 后端自己也发这三个头；隐藏掉，由 server 级的 add_header ... always 统一给，免得每个响应各出现两次
    proxy_hide_header X-Frame-Options;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header Referrer-Policy;
}

# 统一登录的回调：认证中心固定把浏览器送回 <控制台域名>/client/v1/oauth/login，不能自定义
# （RN-Server 设计 tenant-console-accounts-and-sso-2026-09-25 §4.9）。与 /v1/ 一样转给租户端。
# 用 = 精确匹配：/client/ 下别的路径仍然落到下面的 SPA。
location = /client/v1/oauth/login {
    if ($rn_upstream_host = $host) {
        return 500;
    }
    set $rn_service rn_tenant;
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
    proxy_hide_header X-Frame-Options;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header Referrer-Policy;
}
