# 转发到 rn-server 的公共部分：api.* 的 `location /` 与 console.* 的 `location ^~ /v1/` 都 include 它，
# 两边的上传上限、超时、转发头必须一致，不各抄一份。装到 /etc/nginx/conf.d/rn-foundation-snippet-api-proxy.inc。

# 安装包直传走这条路径，512MB 的 APK 不能被 nginx 默认的 1m 卡掉。
# 0 = 不限制，上限由服务端的 ARTIFACT_MAX_SIZE_MB 管
client_max_body_size 0;
# 大文件边收边转发，不先落盘再转
proxy_request_buffering off;

proxy_pass http://127.0.0.1:13080;

# 租户是按 Host 头从 tenant_domain 认的，不能改写成上游地址。
# $rn_upstream_host 来自 rn-foundation.conf 顶上的 map：api.* 就是它自己；console.* 换成这个租户的 api.*，
# 后端看到的 Host 与控制台跨域的时代逐字节一致——拼下载地址、安装命令、SIWE 域名都还是 api.*
proxy_set_header Host              $rn_upstream_host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $rn_upstream_host;
# 统一登录用：控制台域名（api.* 上是空，等于不发）。见 rn-foundation.conf 顶上的 map $rn_console_host
proxy_set_header X-RN-Console-Host $rn_console_host;

proxy_http_version 1.1;
proxy_set_header Connection "";

proxy_connect_timeout 60s;
proxy_read_timeout   3600s;
proxy_send_timeout   3600s;
