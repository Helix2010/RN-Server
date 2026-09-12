# 控制台静态站点的公共部分。root 由各 server 块自己给——每个租户一份产物。
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

location / {
    try_files $uri $uri/ /index.html;
}
