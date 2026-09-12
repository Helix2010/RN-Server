# API 反代的公共部分。被 conf.d/rn-foundation.conf 里每个 api.* 的 server 块 include。
# 抽出来是因为域名按证书分组，一个 zone 一个 server 块，body 完全一样。

# 安装包直传走这条路径，512MB 的 APK 不能被 nginx 默认的 1m 卡掉。
# 0 = 不限制，上限由服务端的 ARTIFACT_MAX_SIZE_MB 管
client_max_body_size 0;
# 大文件边收边转发，不先落盘再转
proxy_request_buffering off;

location / {
    proxy_pass http://127.0.0.1:13080;

    # 租户是按 Host 头从 tenant_domain 认的，不能改写成上游地址
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_connect_timeout 60s;
    proxy_read_timeout   3600s;
    proxy_send_timeout   3600s;
}
