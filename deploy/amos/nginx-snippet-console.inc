# 控制台的公共部分：静态站点 + 同源的 /v1/ 转发。三个 console.* 的 root 都是同一份产物
# /opt/rn-foundation/admin/console（RN-Admin 设计 console-single-build-same-origin-2026-09-25）。
index index.html;

gzip on;
gzip_min_length 1k;
gzip_buffers 4 16k;
gzip_comp_level 6;
gzip_vary on;
gzip_types text/plain text/css text/xml text/javascript application/json
           application/javascript application/xml+rss application/xhtml+xml
           image/svg+xml;

add_header Referrer-Policy        "no-referrer" always;
add_header X-Content-Type-Options "nosniff"     always;
add_header X-Frame-Options        "SAMEORIGIN"  always;

# 控制台请求 API 走同源相对路径 /v1/...，这里转给 rn-server。
#
# ^~ 必须有：下面那条 ~* \.(js|css|png|...)$ 的正则 location 优先于普通前缀，不带 ^~ 的话
# /v1/.../xxx.png 会被它截走、按静态文件 404。
location ^~ /v1/ {
    # map 里没有这个控制台域名：不能转——Host 会原样是 console.*，后端虽然认得出租户，但拼出来的
    # 下载地址、新机器的安装命令都会变成控制台域名，构建机就被绑到了控制台上。直接报错，第一眼就能发现
    if ($rn_upstream_host = $host) {
        return 500;
    }
    include /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc;
    # api.* 今天不压 JSON；gzip 会把强 ETag 改成弱 ETag。与跨域时代保持一致
    gzip off;
    # 后端自己也发这三个头；隐藏掉，由 server 级的 add_header ... always 统一给，免得每个响应各出现两次
    proxy_hide_header X-Frame-Options;
    proxy_hide_header X-Content-Type-Options;
    proxy_hide_header Referrer-Policy;
}

location = /healthz {
    access_log off;
    add_header Content-Type text/plain;
    return 200 'ok';
}

# 带内容哈希的产物可以长缓存；index.html 不行，否则发版后用户停在旧壳子上
location ~* \.(?:js|css|png|jpg|jpeg|gif|ico|svg|woff2?)$ {
    expires 7d;
    add_header Cache-Control "public, max-age=604800, immutable";
    try_files $uri =404;
}

# index.html 必须每次回源问一次。原来这里什么缓存头都没发，只有 Last-Modified，
# 浏览器就会按启发式规则自己缓存（通常是"距上次修改时间的 10%"）——发版之后标签页
# 里还是旧壳子，它引用的是上一版的 hash 文件名，于是旧前端对着新服务端发请求。
# 真踩过：旧控制台多发了一个已经删掉的字段，服务端 DisallowUnknownFields 拒了整个
# 请求，而报错说的是"缺 reason"，根本看不出是版本不一致。
location / {
    try_files $uri $uri/ /index.html;
}

location = /index.html {
    add_header Cache-Control "no-cache, must-revalidate";
    expires -1;
}
