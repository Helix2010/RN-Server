# 两个控制台共用的部分：静态站点、统一账号登录页与它转给认证中心的接口。被 rn-foundation-snippet-console.inc
# （租户控制台）与 rn-foundation-snippet-platform.inc（平台控制台）include；转给 rn-server 的接口各在各的片段里
# （RN-Server 设计 service-and-console-split-2026-09-27 §3.4）。
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

# 统一账号的登录页放在控制台里（RN-Server 设计 platform-accounts-and-console-login-2026-09-27 §3.8）：
# 认证中心「挂在应用域名下」，/auth/v1/* 经 dev1 的内网入口（只放行 amos，只转 /auth/v1/* 与 userinfo）转给它，
# Host 原样——认证中心按 Host 认应用与登记的域名，没登录时把浏览器送回 https://<Host>/login?X-Auth-Token=…。
# RN 自己的 Cookie 都在 /v1/admin、/client/v1/oauth/login 下，不会带到这里
location ^~ /auth/v1/ {
    proxy_pass http://172.17.19.2:9098;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_connect_timeout 10s;
    proxy_read_timeout    30s;
}
# 口令登录接口限流（zone 在 rn-foundation.conf）：认证中心自己没有登录失败锁定
location = /auth/v1/login {
    limit_req zone=rn_cid_login burst=20 nodelay;
    limit_req_status 429;
    proxy_pass http://172.17.19.2:9098;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_connect_timeout 10s;
    proxy_read_timeout    30s;
}

# 控制台的统一账号登录页：同一份 SPA，但这一页经手统一账号口令，单独加严格的 CSP（只许同源脚本与请求，
# 不许被嵌进别的页面）。try_files 的第一个参数是文件：在本 location 里直接出 index.html，响应头就是下面这些；
# 写成最后一个参数会内部跳到 /index.html、换成那边的头。
# location 里只要有 add_header，外层的就不再继承，所以三个通用安全头在这里再写一遍
location = /login {
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'" always;
    add_header Cache-Control          "no-cache, must-revalidate" always;
    add_header Referrer-Policy        "no-referrer" always;
    add_header X-Content-Type-Options "nosniff"     always;
    add_header X-Frame-Options        "DENY"        always;
    try_files /index.html =404;
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
    # 这里有了 add_header，server 级的三个安全头就不再继承（nginx 的规则）：以前控制台的 HTML 一直没带
    # X-Frame-Options 等，可以被别的站点嵌进 iframe。补上
    add_header Referrer-Policy        "no-referrer" always;
    add_header X-Content-Type-Options "nosniff"     always;
    add_header X-Frame-Options        "SAMEORIGIN"  always;
    expires -1;
}
